// Zstandard stream scanner (RFC 8478).
//
// Skippable frames:
//   Magic_Number  u32 LE, 0x184D2A50 .. 0x184D2A5F (inclusive)
//   Frame_Size    u32 LE, unsigned payload length
//   payload       Frame_Size bytes
//
// All cursor/range math that can touch a 32-bit length is done in bigint, so a
// length with the high bit set (e.g. 0x80000000) can never move the cursor
// backwards.

export const SKIPPABLE_MAGIC_MIN = 0x184d2a50;
export const SKIPPABLE_MAGIC_MAX = 0x184d2a5f;
export const ZSTD_MAGIC = 0xfd2fb528;

const DID_SIZES = [0, 1, 2, 4] as const;
// FCS sizes when Single_Segment_flag is set / unset.
const FCS_SIZES_SS = [1, 2, 4, 8] as const;
const FCS_SIZES = [0, 2, 4, 8] as const;

export type FrameHeader = {
  singleSegment: boolean;
  checksum: boolean;
  dictionaryIdFlag: number;
  contentSizeFlag: number;
};

export function parseDescriptor(byte: number): FrameHeader {
  return {
    contentSizeFlag: byte >> 6,
    dictionaryIdFlag: byte & 3,
    checksum: Boolean(byte & 4),
    singleSegment: Boolean(byte & 32),
  };
}

export function readBlockHeader(data: Uint8Array) {
  if (data.length < 3) return null;
  const value = data[0] | (data[1] << 8) | (data[2] << 16);
  return { last: Boolean(value & 1), type: (value >> 1) & 3, size: value >> 3 };
}

/**
 * Read an unsigned 32-bit little-endian integer.
 *
 * The result is forced through `>>> 0` so values with the high bit set
 * (0x80000000 and above) stay positive instead of becoming negative.
 */
export function readUint32LE(data: ArrayLike<number>, offset = 0): number {
  return (
    (data[offset] |
      (data[offset + 1] << 8) |
      (data[offset + 2] << 16) |
      (data[offset + 3] << 24)) >>>
    0
  );
}

function readUint24LE(data: ArrayLike<number>, offset = 0): number {
  return (
    (data[offset] |
      (data[offset + 1] << 8) |
      (data[offset + 2] << 16)) >>>
    0
  );
}

/** Inclusive range check: every variant 0..15 is legal. */
export function isSkippableMagic(magic: number): boolean {
  return magic >= SKIPPABLE_MAGIC_MIN && magic <= SKIPPABLE_MAGIC_MAX;
}

export type ZstdScanErrorCode =
  | 'badMagic'
  | 'truncatedHeader'
  | 'truncatedPayload'
  | 'reservedBlockType';

export class ZstdScanError extends Error {
  readonly code: ZstdScanErrorCode;
  /** Absolute stream offset at which the error was detected. */
  readonly offset: bigint;

  constructor(code: ZstdScanErrorCode, message: string, offset: bigint) {
    super(message);
    this.name = 'ZstdScanError';
    this.code = code;
    this.offset = offset;
  }
}

export interface SkippableFrameEvent {
  type: 'skippable';
  /** Full 32-bit magic value, e.g. 0x184D2A5F. */
  magic: number;
  /** Low nibble of the magic, 0..15. */
  variant: number;
  /** Unsigned payload length parsed from the header. */
  length: number;
  /** Absolute offset of the frame's first magic byte. */
  start: bigint;
  /** Absolute offset immediately after the payload. */
  end: bigint;
  /** Present only when `streamPayload` is false. */
  payload?: Uint8Array;
}

export interface ZstdFrameEvent {
  type: 'zstd';
  magic: typeof ZSTD_MAGIC;
  start: bigint;
  end: bigint;
}

export type FrameEvent = SkippableFrameEvent | ZstdFrameEvent;

export interface ScanOptions {
  /**
   * When true (the default) skippable payloads are streamed past without being
   * buffered — only metadata is reported. When false the payload is
   * accumulated and attached to the event.
   */
  streamPayload?: boolean;
  /**
   * Total input length, if known. Frame end offsets computed from 32-bit
   * lengths are checked (in bigint) against this boundary while scanning, so
   * truncated payloads are detected as soon as the header is parsed.
   */
  knownLength?: bigint | number;
  onEvent?: (event: FrameEvent) => void;
}

type Phase =
  | 'magic'
  | 'skLen'
  | 'skPayload'
  | 'zDesc'
  | 'zWindow'
  | 'zDID'
  | 'zFCS'
  | 'zBlock'
  | 'zBlockPayload'
  | 'zChecksum';

/**
 * Incremental scanner: feed arbitrary chunk boundaries with `write()` and call
 * `end()` once the stream is finished.
 */
export class ZstdStreamScanner {
  readonly events: FrameEvent[] = [];

  private readonly streamPayload: boolean;
  private readonly knownLength: bigint | null;
  private readonly onEvent?: (event: FrameEvent) => void;

  /** Total bytes consumed so far (absolute stream offset). */
  private total = 0n;
  private phase: Phase = 'magic';
  /** Offset where the current frame's magic starts. */
  private frameStart = 0n;
  private header: number[] = [];
  private headerNeed = 4;

  // skippable frame state
  private skMagic = 0;
  private skLength = 0;
  private skEnd = 0n;

  // payload-phase state (skippable payload or zstd block payload)
  private remaining = 0;
  private chunks: Uint8Array[] | null = null;

  // zstd frame state
  private checksumFlag = false;
  private blockLast = false;

  constructor(options: ScanOptions = {}) {
    this.streamPayload = options.streamPayload ?? true;
    this.knownLength =
      options.knownLength === undefined ? null : BigInt(options.knownLength);
    this.onEvent = options.onEvent;
  }

  write(chunk: Uint8Array): void {
    let i = 0;
    while (i < chunk.length) {
      if (this.remaining > 0) {
        const take = Math.min(this.remaining, chunk.length - i);
        if (this.chunks !== null) {
          // Copy: the caller may reuse the chunk buffer.
          this.chunks.push(chunk.slice(i, i + take));
        }
        i += take;
        this.remaining -= take;
        this.total += BigInt(take);
        if (this.remaining === 0) this.payloadComplete();
        continue;
      }

      const take = Math.min(this.headerNeed, chunk.length - i);
      for (let j = 0; j < take; j++) this.header.push(chunk[i + j]);
      i += take;
      this.headerNeed -= take;
      this.total += BigInt(take);
      if (this.headerNeed === 0) this.headerComplete();
    }
  }

  /** Verify the stream ended on a frame boundary; throw otherwise. */
  end(): void {
    if (this.phase === 'magic' && this.header.length === 0) return;
    const code: ZstdScanErrorCode =
      this.phase === 'skPayload' ? 'truncatedPayload' : 'truncatedHeader';
    throw new ZstdScanError(
      code,
      `stream ended while expecting more bytes (phase=${this.phase})`,
      this.total,
    );
  }

  private emit(event: FrameEvent): void {
    this.events.push(event);
    this.onEvent?.(event);
  }

  private startFrame(): void {
    this.phase = 'magic';
    this.frameStart = this.total;
    this.header = [];
    this.headerNeed = 4;
  }

  private headerComplete(): void {
    switch (this.phase) {
      case 'magic':
        this.resolveMagic();
        return;
      case 'skLen':
        this.resolveSkLen();
        return;
      case 'zDesc':
        this.resolveZDesc();
        return;
      case 'zWindow':
        this.afterWindow();
        return;
      case 'zDID':
        this.enterFcs();
        return;
      case 'zFCS':
        this.enterBlock();
        return;
      case 'zBlock':
        this.resolveBlock();
        return;
      case 'zChecksum':
        this.zstdFrameComplete();
        return;
      default:
        throw new Error(`unexpected header phase: ${this.phase}`);
    }
  }

  private resolveMagic(): void {
    const magic = readUint32LE(this.header);
    this.header = [];

    if (isSkippableMagic(magic)) {
      this.skMagic = magic;
      this.phase = 'skLen';
      this.headerNeed = 4;
    } else if (magic === ZSTD_MAGIC) {
      this.phase = 'zDesc';
      this.headerNeed = 1;
    } else {
      throw new ZstdScanError(
        'badMagic',
        `unknown frame magic 0x${magic.toString(16).padStart(8, '0')} at offset ${this.frameStart}`,
        this.total,
      );
    }
  }

  private resolveSkLen(): void {
    // Unsigned LE: a high-bit length stays a positive number.
    const length = readUint32LE(this.header);
    this.header = [];
    this.skLength = length;
    // bigint range math: end = start + 8 + length, never a signed add.
    this.skEnd = this.frameStart + 8n + BigInt(length);
    if (this.knownLength !== null && this.skEnd > this.knownLength) {
      throw new ZstdScanError(
        'truncatedPayload',
        `skippable frame at ${this.frameStart} declares ${length} payload bytes but the input ends at ${this.knownLength}`,
        this.total,
      );
    }

    if (length === 0) {
      this.skippableFrameComplete(null);
      return;
    }
    this.phase = 'skPayload';
    this.remaining = length;
    this.chunks = this.streamPayload ? null : [];
  }

  private resolveZDesc(): void {
    const desc = this.header[0];
    this.header = [];
    this.checksumFlag = Boolean(desc & 0x04);
    const singleSegment = Boolean(desc & 0x20);
    const didFlag = desc & 0x03;
    const fcsFlag = (desc >> 6) & 0x03;

    const didSize = DID_SIZES[didFlag];
    const fcsSize = singleSegment
      ? FCS_SIZES_SS[fcsFlag]
      : FCS_SIZES[fcsFlag];

    this.pendingDidSize = didSize;
    this.pendingFcsSize = fcsSize;

    if (!singleSegment) {
      this.phase = 'zWindow';
      this.headerNeed = 1;
    } else {
      this.enterDid();
    }
  }

  private pendingDidSize = 0;
  private pendingFcsSize = 0;

  private afterWindow(): void {
    this.header = [];
    this.enterDid();
  }

  private enterDid(): void {
    if (this.pendingDidSize > 0) {
      this.phase = 'zDID';
      this.headerNeed = this.pendingDidSize;
    } else {
      this.enterFcs();
    }
  }

  private enterFcs(): void {
    this.header = [];
    if (this.pendingFcsSize > 0) {
      this.phase = 'zFCS';
      this.headerNeed = this.pendingFcsSize;
    } else {
      this.enterBlock();
    }
  }

  private enterBlock(): void {
    this.header = [];
    this.phase = 'zBlock';
    this.headerNeed = 3;
  }

  private resolveBlock(): void {
    const value = readUint24LE(this.header);
    this.header = [];
    this.blockLast = Boolean(value & 1);
    const blockType = (value >> 1) & 3;
    const blockSize = value >>> 3;

    if (blockType === 3) {
      throw new ZstdScanError(
        'reservedBlockType',
        `reserved block type at offset ${this.total}`,
        this.total,
      );
    }
    // An RLE block regenerates `blockSize` bytes but stores exactly one.
    const payloadSize = blockType === 1 ? 1 : blockSize;
    if (payloadSize === 0) {
      this.blockPayloadComplete();
      return;
    }
    this.phase = 'zBlockPayload';
    this.remaining = payloadSize;
    this.chunks = null;
  }

  private payloadComplete(): void {
    if (this.phase === 'skPayload') {
      const collected = this.streamPayload ? null : concatChunks(this.chunks);
      this.skippableFrameComplete(collected);
    } else {
      this.blockPayloadComplete();
    }
  }

  private blockPayloadComplete(): void {
    this.remaining = 0;
    this.chunks = null;
    if (this.blockLast) {
      if (this.checksumFlag) {
        this.phase = 'zChecksum';
        this.headerNeed = 4;
      } else {
        this.zstdFrameComplete();
      }
    } else {
      this.enterBlock();
    }
  }

  private skippableFrameComplete(payload: Uint8Array | null): void {
    const event: SkippableFrameEvent = {
      type: 'skippable',
      magic: this.skMagic,
      variant: this.skMagic & 0x0f,
      length: this.skLength,
      start: this.frameStart,
      end: this.skEnd,
    };
    if (payload !== null) event.payload = payload;
    this.emit(event);
    this.startFrame();
  }

  private zstdFrameComplete(): void {
    this.emit({
      type: 'zstd',
      magic: ZSTD_MAGIC,
      start: this.frameStart,
      end: this.total,
    });
    this.startFrame();
  }
}

function concatChunks(chunks: Uint8Array[] | null): Uint8Array {
  if (chunks === null || chunks.length === 0) return new Uint8Array(0);
  if (chunks.length === 1) return chunks[0];
  const total = chunks.reduce((n, c) => n + c.length, 0);
  const out = new Uint8Array(total);
  let off = 0;
  for (const c of chunks) {
    out.set(c, off);
    off += c.length;
  }
  return out;
}

/** One-shot scan of a complete buffer; returns every frame event in order. */
export function scanZstdStream(
  input: Uint8Array,
  options: Omit<ScanOptions, 'knownLength'> = {},
): FrameEvent[] {
  const scanner = new ZstdStreamScanner({
    ...options,
    knownLength: BigInt(input.length),
  });
  scanner.write(input);
  scanner.end();
  return scanner.events;
}
