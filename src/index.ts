// Zstandard framing core.
//
// Skippable frames are defined in RFC 8478 §3.3:
//
//   Magic_Number : 4 bytes LE, 0x184D2A50 .. 0x184D2A5F (both ends included)
//   Frame_Size   : 4 bytes LE unsigned
//   [Frame_Size bytes of payload]
//
// Frame_Size must always be read as an *unsigned* little-endian 32-bit
// integer; the old scanner used |0, which turned sizes with the high bit
// set into negative numbers and walked the cursor backwards.

export const ZSTD_MAGIC = 0x28b52ffd;
export const SKIPPABLE_MAGIC_MIN = 0x184d2a50;
export const SKIPPABLE_MAGIC_MAX = 0x184d2a5f;
export const SKIPPABLE_HEADER_SIZE = 8;

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

/** Read 4 bytes as an UNSIGNED little-endian 32-bit integer. */
export function readUInt32LE(data: Uint8Array, offset = 0): number {
  return (
    (data[offset] |
      (data[offset + 1] << 8) |
      (data[offset + 2] << 16) |
      (data[offset + 3] << 24)) >>>
    0
  );
}

/** True for every magic in the complete skippable range, both ends included. */
export function isSkippableMagic(magic: number): boolean {
  return magic >= SKIPPABLE_MAGIC_MIN && magic <= SKIPPABLE_MAGIC_MAX;
}

/** Absolute byte range [start, end); end is exclusive. */
export interface ByteRange {
  /** Absolute offset of the first magic byte. */
  start: number;
  /** Absolute offset just past the last payload byte. */
  end: number;
}

export interface SkippableFrameEvent {
  /** Magic number actually found (0x184D2A50 .. 0x184D2A5F). */
  magic: number;
  /** Which of the 16 skippable variants this frame is (0..15). */
  variant: number;
  /** Unsigned payload length. */
  length: number;
  /** Absolute range of the whole frame (header + payload). */
  range: ByteRange;
  /** Absolute range of the header bytes. */
  headerRange: ByteRange;
  /** Absolute range of the payload (start === end for length 0). */
  payloadRange: ByteRange;
}

export class ScannerError extends Error {
  readonly code: string;
  readonly offset: number;
  constructor(code: string, message: string, offset: bigint) {
    super(message);
    this.name = 'ScannerError';
    this.code = code;
    this.offset = Number(offset);
  }
}

export class InvalidMagicError extends ScannerError {
  readonly actual: number;
  constructor(actual: number, offset: bigint) {
    super(
      'invalid_magic',
      `invalid frame magic 0x${actual.toString(16).padStart(8, '0')} at offset ${offset}`,
      offset,
    );
    this.name = 'InvalidMagicError';
    this.actual = actual >>> 0;
  }
}

export class TruncatedFrameError extends ScannerError {
  /** 'skippable_header' | 'skippable_payload' | 'zstd_frame' */
  readonly kind: string;
  constructor(kind: string, offset: bigint, expectedEnd?: bigint) {
    const what =
      kind === 'skippable_header'
        ? 'truncated skippable frame header'
        : kind === 'skippable_payload'
          ? `truncated skippable frame payload (expected end at byte ${expectedEnd ?? '?'})`
          : 'truncated zstd frame';
    super(kind, `${what} at offset ${offset}`, offset);
    this.name = 'TruncatedFrameError';
    this.kind = kind;
  }
}

function buildSkippableEvent(
  magic: number,
  length: number,
  headerStart: bigint,
): SkippableFrameEvent {
  // End is computed in bigint so a declared length near 2^32-1 can never
  // overflow; the result is then checked against the input boundary.
  const headerEnd = headerStart + BigInt(SKIPPABLE_HEADER_SIZE);
  const end = headerEnd + BigInt(length);
  return {
    magic: magic >>> 0,
    variant: (magic - SKIPPABLE_MAGIC_MIN) & 0xf,
    length,
    range: { start: Number(headerStart), end: Number(end) },
    headerRange: { start: Number(headerStart), end: Number(headerEnd) },
    payloadRange: { start: Number(headerEnd), end: Number(end) },
  };
}

export interface ReadSkippableHeaderResult {
  event: SkippableFrameEvent;
  /** Absolute offset of the first byte after the payload. */
  end: number;
}

/**
 * Validate a single skippable frame header against a complete buffer.
 *
 * Reads the length unsigned, validates the full inclusive magic range and
 * checks the bigint-computed end against the input boundary.
 */
export function readSkippableHeader(
  data: Uint8Array,
  offset: number = 0,
): ReadSkippableHeaderResult {
  const start = BigInt(offset);
  if (start + BigInt(SKIPPABLE_HEADER_SIZE) > BigInt(data.length)) {
    throw new TruncatedFrameError('skippable_header', BigInt(data.length));
  }
  const magic = readUInt32LE(data, offset);
  if (!isSkippableMagic(magic)) {
    throw new InvalidMagicError(magic, start);
  }
  const length = readUInt32LE(data, offset + 4);
  const event = buildSkippableEvent(magic, length, start);
  const end = BigInt(event.range.end);
  if (end > BigInt(data.length)) {
    // The header itself is well formed; report it before failing the
    // boundary check so callers know exactly which frame is short.
    throw new TruncatedFrameError(
      'skippable_payload',
      BigInt(data.length),
      end,
    );
  }
  return { event, end: Number(end) };
}

export interface SkippableScannerHandlers {
  /** Fired once per fully headed skippable frame. */
  onSkippable?: (event: SkippableFrameEvent) => void;
  /** Raw bytes of every ordinary (non-skippable) zstd frame. */
  onData?: (chunk: Uint8Array, offset: number) => void;
  /**
   * Called with payload slices of skippable frames. The scanner itself never
   * accumulates payload bytes; payload is streamed straight through here
   * (zero-copy views of the caller's chunks).
   */
  onPayload?: (chunk: Uint8Array, range: ByteRange) => void;
  /**
   * Stream skippable payload through `onPayload` instead of silently
   * dropping it. Defaults to false: payload is skipped without caching.
   */
  streamPayload?: boolean;
}

type State =
  | 'magic'
  | 'skLength'
  | 'skPayload'
  | 'desc'
  | 'fixedHeader'
  | 'blockHeader'
  | 'blockPayload'
  | 'rlePayload'
  | 'checksum';

const DICT_ID_SIZE = [0, 1, 2, 4];

/**
 * Incremental scanner for a stream of zstd frames (skippable and ordinary
 * frames may be freely interleaved). Only frame/block headers are parsed;
 * ordinary frame content is passed through untouched.
 *
 * Skippable payload is never cached: at most the 8 header bytes are buffered
 * across chunk boundaries.
 */
export class SkippableScanner {
  private readonly onSkippable?: (event: SkippableFrameEvent) => void;
  private readonly onData?: (chunk: Uint8Array, offset: number) => void;
  private readonly onPayload?: (chunk: Uint8Array, range: ByteRange) => void;
  private readonly streamPayload: boolean;

  private state: State = 'magic';
  private pending = new Uint8Array(8);
  private pendingLen = 0;
  private pendingNeed = 4;
  private pos = 0n;

  // Current skippable frame.
  private skEnd = 0n;

  // Current ordinary zstd frame.
  private contentChecksum = false;
  private dictIdSize = 0;
  private contentSizeSize = 0;
  private fixedRemaining = 0;
  private blockRemaining = 0;
  private pendingLastBlock = false;

  constructor(handlers: SkippableScannerHandlers = {}) {
    this.onSkippable = handlers.onSkippable;
    this.onData = handlers.onData;
    this.onPayload = handlers.onPayload;
    this.streamPayload = handlers.streamPayload ?? false;
  }

  /** Absolute number of bytes consumed so far. */
  get bytesRead(): number {
    return Number(this.pos);
  }

  write(chunk: Uint8Array): void {
    let i = 0;
    const n = chunk.length;
    const forward = (len: number) => {
      if (len > 0 && this.onData) this.onData(chunk.subarray(i, i + len), Number(this.pos));
      this.pos += BigInt(len);
      i += len;
    };
    const streamPayload = (len: number, payloadOffset: bigint) => {
      if (len > 0 && this.streamPayload && this.onPayload) {
        this.onPayload(chunk.subarray(i, i + len), {
          start: Number(payloadOffset),
          end: Number(payloadOffset + BigInt(len)),
        });
      }
      this.pos += BigInt(len);
      i += len;
    };

    while (i < n) {
      switch (this.state) {
        case 'magic': {
          const take = Math.min(this.pendingNeed - this.pendingLen, n - i);
          this.pending.set(chunk.subarray(i, i + take), this.pendingLen);
          this.pendingLen += take;
          i += take;
          this.pos += BigInt(take);
          if (this.pendingLen < this.pendingNeed) return;
          const magic = readUInt32LE(this.pending, 0);
          this.pendingLen = 0;
          this.pendingNeed = 4;
          if (isSkippableMagic(magic)) {
            // Header so far; length follows.
            this.pending[0] = magic & 0xff;
            this.pending[1] = (magic >>> 8) & 0xff;
            this.pending[2] = (magic >>> 16) & 0xff;
            this.pending[3] = magic >>> 24;
            this.pendingLen = 4;
            this.pendingNeed = SKIPPABLE_HEADER_SIZE;
            this.state = 'skLength';
          } else if (magic === ZSTD_MAGIC) {
            // Ordinary frame: replay the 4 magic bytes just consumed,
            // then parse the descriptor next. Use a fresh copy: `pending`
            // may already hold bytes belonging to a later frame.
            if (this.onData) {
              this.onData(
                Uint8Array.from(this.pending.subarray(0, 4)),
                Number(this.pos - 4n),
              );
            }
            this.state = 'desc';
            this.pendingNeed = 1;
          } else {
            throw new InvalidMagicError(magic, this.pos - 4n);
          }
          break;
        }

        case 'skLength': {
          const take = Math.min(this.pendingNeed - this.pendingLen, n - i);
          this.pending.set(chunk.subarray(i, i + take), this.pendingLen);
          this.pendingLen += take;
          i += take;
          this.pos += BigInt(take);
          if (this.pendingLen < SKIPPABLE_HEADER_SIZE) return;
          const magic = readUInt32LE(this.pending, 0);
          const length = readUInt32LE(this.pending, 4); // unsigned LE
          const headerStart = this.pos - BigInt(SKIPPABLE_HEADER_SIZE);
          const event = buildSkippableEvent(magic, length, headerStart);
          this.skEnd = BigInt(event.range.end);
          this.pending.fill(0, 0, SKIPPABLE_HEADER_SIZE);
          this.pendingLen = 0;
          this.pendingNeed = 4;
          this.onSkippable?.(event);
          if (length === 0) {
            // No payload to consume: next frame starts immediately.
            this.state = 'magic';
          } else {
            this.state = 'skPayload';
          }
          break;
        }

        case 'skPayload': {
          const remaining = Number(this.skEnd - this.pos);
          const take = Math.min(remaining, n - i);
          if (take > 0) {
            const payloadOffset =
              this.skEnd - BigInt(remaining);
            streamPayload(take, payloadOffset);
          }
          if (this.pos === this.skEnd) {
            this.state = 'magic';
            this.pendingNeed = 4;
          }
          break;
        }

        case 'desc': {
          const take = Math.min(1 - this.pendingLen, n - i);
          if (take > 0 && this.onData) {
            this.onData(chunk.subarray(i, i + take), Number(this.pos));
          }
          this.pending.set(chunk.subarray(i, i + take), this.pendingLen);
          this.pendingLen += take;
          i += take;
          this.pos += BigInt(take);
          if (this.pendingLen < 1) return;
          const header = parseDescriptor(this.pending[0]);
          this.contentChecksum = header.checksum;
          this.dictIdSize = DICT_ID_SIZE[header.dictionaryIdFlag];
          if (header.singleSegment) {
            // RFC 8478: single-segment FCS field sizes are {1,1,2,4}
            // bytes for flags {0,1,2,3}.
            this.contentSizeSize = [1, 1, 2, 4][header.contentSizeFlag] ?? 1;
          } else {
            // RFC 8478: non-single-segment sizes are {0,2,4,8}.
            this.contentSizeSize = [0, 2, 4, 8][header.contentSizeFlag] ?? 0;
          }
          this.fixedRemaining = this.dictIdSize + this.contentSizeSize;
          this.pendingLen = 0;
          this.pendingNeed = 4;
          this.state =
            this.fixedRemaining > 0 ? 'fixedHeader' : 'blockHeader';
          if (this.fixedRemaining === 0) this.pendingNeed = 3;
          break;
        }

        case 'fixedHeader': {
          const take = Math.min(this.fixedRemaining, n - i);
          forward(take);
          this.fixedRemaining -= take;
          if (this.fixedRemaining > 0) return;
          this.state = 'blockHeader';
          this.pendingNeed = 3;
          break;
        }

        case 'blockHeader': {
          const take = Math.min(3 - this.pendingLen, n - i);
          if (take > 0 && this.onData) {
            this.onData(chunk.subarray(i, i + take), Number(this.pos));
          }
          this.pending.set(chunk.subarray(i, i + take), this.pendingLen);
          this.pendingLen += take;
          i += take;
          this.pos += BigInt(take);
          if (this.pendingLen < 3) return;
          const bh = readBlockHeader(this.pending.subarray(0, 3))!;
          this.pendingLen = 0;
          this.pendingLastBlock = bh.last;
          if (bh.type === 3) {
            throw new ScannerError(
              'reserved_block_type',
              `reserved block type at offset ${this.pos - 3n}`,
              this.pos - 3n,
            );
          }
          if (bh.type === 1) {
            // RLE blocks store exactly one content byte regardless of size.
            this.blockRemaining = 1;
            this.state = 'rlePayload';
          } else if (bh.size === 0) {
            // Zero-length RAW/compressed block: no payload bytes.
            this.afterBlock(bh.last);
          } else {
            this.blockRemaining = bh.size;
            this.state = 'blockPayload';
          }
          break;
        }

        case 'rlePayload':
        case 'blockPayload': {
          const take = Math.min(this.blockRemaining, n - i);
          forward(take);
          this.blockRemaining -= take;
          if (this.blockRemaining > 0) return;
          this.afterBlock(this.pendingLastBlock);
          break;
        }

        case 'checksum': {
          const take = Math.min(4 - this.pendingLen, n - i);
          if (take > 0 && this.onData) {
            this.onData(chunk.subarray(i, i + take), Number(this.pos));
          }
          this.pendingLen += take;
          i += take;
          this.pos += BigInt(take);
          if (this.pendingLen < 4) return;
          this.pendingLen = 0;
          this.state = 'magic';
          this.pendingNeed = 4;
          break;
        }
      }
    }
  }

  private afterBlock(last: boolean): void {
    if (last) {
      this.state = this.contentChecksum ? 'checksum' : 'magic';
      this.pendingLen = 0;
      this.pendingNeed = 4;
    } else {
      this.state = 'blockHeader';
      this.pendingLen = 0;
      this.pendingNeed = 3;
    }
  }

  /** Call after the final chunk to detect a frame cut off mid-stream. */
  finish(): void {
    if (this.state === 'magic' && this.pendingLen === 0) return;
    if (this.state === 'skLength') {
      throw new TruncatedFrameError('skippable_header', this.pos);
    }
    if (this.state === 'skPayload') {
      throw new TruncatedFrameError('skippable_payload', this.pos, this.skEnd);
    }
    if (this.state === 'magic') {
      // Fewer than 4 bytes of a new frame: type is not yet knowable.
      throw new TruncatedFrameError('frame_header', this.pos);
    }
    throw new TruncatedFrameError('zstd_frame', this.pos);
  }
}

export interface ScanSkippableOptions {
  /** Also invoke onPayload for payload bytes (kept out of the event). */
  includePayload?: boolean;
  onSkippable?: (event: SkippableFrameEvent) => void;
  onData?: (chunk: Uint8Array, offset: number) => void;
  onPayload?: (chunk: Uint8Array, range: ByteRange) => void;
}

/**
 * One-shot scan of a complete buffer. Walks the stream frame by frame
 * (skippable and ordinary frames may interleave) and returns all skippable
 * frame events. Payload is never cached in the returned events.
 */
export function scanSkippableFrames(
  data: Uint8Array,
  options: ScanSkippableOptions = {},
): SkippableFrameEvent[] {
  const events: SkippableFrameEvent[] = [];
  const scanner = new SkippableScanner({
    streamPayload: options.includePayload ?? false,
    onSkippable: (event) => {
      events.push(event);
      options.onSkippable?.(event);
    },
    onData: options.onData,
    onPayload: options.onPayload,
  });
  scanner.write(data);
  scanner.finish();
  return events;
}
