import { describe, expect, it } from 'vitest';
import {
  isSkippableMagic,
  parseDescriptor,
  readUint32LE,
  scanZstdStream,
  SKIPPABLE_MAGIC_MAX,
  SKIPPABLE_MAGIC_MIN,
  ZSTD_MAGIC,
  ZstdScanError,
  ZstdStreamScanner,
  type FrameEvent,
} from '../src/index.js';

const u32le = (value: number) =>
  Uint8Array.from([value & 0xff, (value >>> 8) & 0xff, (value >>> 16) & 0xff, (value >>> 24) & 0xff]);

const u24le = (value: number) =>
  Uint8Array.from([value & 0xff, (value >>> 8) & 0xff, (value >>> 16) & 0xff]);

/** skippable frame: magic variant 0..15 + payload. */
function skippable(variant: number, payload: Uint8Array | number[]): Uint8Array {
  const body = payload instanceof Uint8Array ? payload : Uint8Array.from(payload);
  return concat([u32le(SKIPPABLE_MAGIC_MIN + variant), u32le(body.length), body]);
}

/**
 * Minimal standard zstd frame: Single_Segment (FCS_Flag=0 => 1-byte FCS),
 * no checksum, no dictionary ID. Raw_Block is type 0.
 */
function zstdFrame(
  blocks: { last: boolean; type: number; size: number; data?: number[] }[],
  contentSize = 0,
): Uint8Array {
  const parts: Uint8Array[] = [
    u32le(ZSTD_MAGIC),
    Uint8Array.from([0x20]), // FHD: Single_Segment only
    Uint8Array.from([contentSize]), // 1-byte Frame_Content_Size
  ];
  for (const b of blocks) {
    const header = (b.size << 3) | ((b.type & 3) << 1) | (b.last ? 1 : 0);
    parts.push(u24le(header));
    if (b.data) parts.push(Uint8Array.from(b.data));
  }
  return concat(parts);
}

function concat(parts: Uint8Array[]): Uint8Array {
  const total = parts.reduce((n, p) => n + p.length, 0);
  const out = new Uint8Array(total);
  let off = 0;
  for (const p of parts) {
    out.set(p, off);
    off += p.length;
  }
  return out;
}

function skippableEvents(events: FrameEvent[]) {
  return events.filter((e): e is Extract<FrameEvent, { type: 'skippable' }> => e.type === 'skippable');
}

it('parses flags', () => expect(parseDescriptor(32).singleSegment).toBe(true));

describe('readUint32LE', () => {
  it('reads unsigned little-endian values, high bit stays positive', () => {
    expect(readUint32LE(u32le(0))).toBe(0);
    expect(readUint32LE(u32le(1))).toBe(1);
    expect(readUint32LE(u32le(0x7fffffff))).toBe(0x7fffffff);
    expect(readUint32LE(u32le(0x80000000))).toBe(0x80000000);
    expect(readUint32LE(u32le(0xffffffff))).toBe(0xffffffff);
  });

  it('reads bytes in little-endian order', () => {
    expect(readUint32LE(Uint8Array.from([0x78, 0x56, 0x34, 0x12]))).toBe(0x12345678);
  });
});

describe('skippable magic range', () => {
  it('accepts both ends of the inclusive range', () => {
    expect(isSkippableMagic(SKIPPABLE_MAGIC_MIN)).toBe(true); // 0x184D2A50
    expect(isSkippableMagic(SKIPPABLE_MAGIC_MAX)).toBe(true); // 0x184D2A5F
    expect(isSkippableMagic(SKIPPABLE_MAGIC_MAX - 1)).toBe(true);
  });

  it('rejects values just outside the range', () => {
    expect(isSkippableMagic(SKIPPABLE_MAGIC_MIN - 1)).toBe(false);
    expect(isSkippableMagic(SKIPPABLE_MAGIC_MAX + 1)).toBe(false);
    expect(isSkippableMagic(ZSTD_MAGIC)).toBe(false);
  });

  it('reports every variant at the range endpoints', () => {
    const first = skippable(0, [1, 2, 3]);
    const last = skippable(15, [4, 5, 6, 7]);
    const events = scanZstdStream(concat([first, last]));
    const sk = skippableEvents(events);
    expect(sk[0].magic).toBe(0x184d2a50);
    expect(sk[0].variant).toBe(0);
    expect(sk[1].magic).toBe(0x184d2a5f);
    expect(sk[1].variant).toBe(15);
  });
});

describe('length and absolute range', () => {
  it('handles length 0 without consuming payload bytes', () => {
    const events = scanZstdStream(skippable(7, []));
    expect(events).toHaveLength(1);
    expect(events[0]).toMatchObject({ type: 'skippable', variant: 7, length: 0 });
    expect(events[0].start).toBe(0n);
    expect(events[0].end).toBe(8n);
  });

  it('reports correct length and bigint absolute range', () => {
    const payload = Uint8Array.from([10, 20, 30]);
    const events = scanZstdStream(skippable(3, payload));
    expect(events[0].start).toBe(0n);
    expect(events[0].end).toBe(11n);
    expect((events[0] as any).length).toBe(3);
  });

  it('does not treat a high-bit length as negative or rewind the cursor', () => {
    // Header only: length 0x80000000 with no payload present.
    const header = concat([u32le(SKIPPABLE_MAGIC_MIN + 2), u32le(0x80000000)]);
    let caught: ZstdScanError | undefined;
    try {
      scanZstdStream(header);
    } catch (e) {
      caught = e as ZstdScanError;
    }
    // A signed read would produce -2^31 and point the cursor backwards.
    expect(caught).toBeInstanceOf(ZstdScanError);
    expect(caught?.code).toBe('truncatedPayload');
    expect(caught?.offset).toBe(8n);

    // Length 0xFFFFFFFF must also remain positive.
    const maxHeader = concat([u32le(SKIPPABLE_MAGIC_MAX), u32le(0xffffffff)]);
    try {
      scanZstdStream(maxHeader);
      throw new Error('expected truncation error');
    } catch (e) {
      expect((e as ZstdScanError).code).toBe('truncatedPayload');
    }
  });

  it('treats a high-bit length as forward skip with a matching known length', () => {
    // Declare 0x80000000 payload bytes; the declared end equals the known
    // total, so the header passes the boundary check and the scanner simply
    // skips the (not fully fed) payload forwards.
    const header = concat([u32le(SKIPPABLE_MAGIC_MIN), u32le(0x80000000)]);
    const scanner = new ZstdStreamScanner({ knownLength: 0x80000008n });
    scanner.write(header);
    scanner.write(Uint8Array.from([0xaa]));
    expect(scanner.events).toHaveLength(0);
  });
});

describe('truncation', () => {
  it('detects a truncated header at every suffix length', () => {
    const frame = skippable(1, [9, 9]);
    for (let n = 0; n < 8; n++) {
      const partial = frame.subarray(0, n);
      if (n === 0) {
        expect(scanZstdStream(partial)).toEqual([]);
        continue;
      }
      try {
        scanZstdStream(partial);
        throw new Error(`expected error for ${n}-byte input`);
      } catch (e) {
        expect((e as ZstdScanError).code).toBe('truncatedHeader');
      }
    }
  });

  it('detects a truncated payload and reports the declared end', () => {
    const frame = skippable(4, [1, 2, 3, 4]);
    const partial = frame.subarray(0, 10); // 2 of 4 payload bytes missing
    try {
      scanZstdStream(partial);
      throw new Error('expected truncation error');
    } catch (e) {
      expect((e as ZstdScanError).code).toBe('truncatedPayload');
    }
  });

  it('rejects unknown magic', () => {
    const bad = concat([u32le(0x184d2a60), u32le(0)]);
    try {
      scanZstdStream(bad);
      throw new Error('expected bad magic');
    } catch (e) {
      expect((e as ZstdScanError).code).toBe('badMagic');
    }
  });
});

describe('streaming', () => {
  it('skips payload without caching by default', () => {
    const events = scanZstdStream(skippable(1, [7, 8, 9]));
    expect('payload' in events[0]).toBe(false);
  });

  it('caches payload when streamPayload is false', () => {
    const events = scanZstdStream(skippable(1, [7, 8, 9]), { streamPayload: false });
    const sk = skippableEvents(events)[0];
    expect(Array.from(sk.payload!)).toEqual([7, 8, 9]);
  });

  it('reassembles payload split across many tiny chunks', () => {
    const bytes = Uint8Array.from({ length: 100 }, (_, i) => i % 256);
    const frame = skippable(5, bytes);
    const scanner = new ZstdStreamScanner({ streamPayload: false, knownLength: BigInt(frame.length) });
    for (const b of frame) scanner.write(Uint8Array.from([b]));
    scanner.end();
    const sk = skippableEvents(scanner.events)[0];
    expect(Array.from(sk.payload!)).toEqual(Array.from(bytes));
    expect(sk.start).toBe(0n);
    expect(sk.end).toBe(BigInt(frame.length));
  });
});

describe('alternating skippable and zstd frames', () => {
  it('finds the next frame exactly after skipping', () => {
    const a = skippable(0, [1, 1, 1]); // 11 bytes, range [0,11)
    const b = zstdFrame([{ last: true, type: 0, size: 0 }]); // 4+1+1+3 = 9 bytes
    const c = skippable(15, []); // 8 bytes
    const stream = concat([a, b, c]);

    const events = scanZstdStream(stream);
    expect(events.map((e) => e.type)).toEqual(['skippable', 'zstd', 'skippable']);

    expect(events[0].start).toBe(0n);
    expect(events[0].end).toBe(11n);

    expect(events[1].start).toBe(11n);
    expect(events[1].end).toBe(20n);

    // Next frame starts exactly where the zstd frame ended.
    expect(events[2].start).toBe(20n);
    expect(events[2].end).toBe(28n);
  });

  it('handles real zstd blocks (raw and multi-block)', () => {
    const z = zstdFrame([
      { last: false, type: 0, size: 3, data: [1, 2, 3] }, // Raw_Block
      { last: true, type: 1, size: 10, data: [0x55] }, // RLE: one stored byte
    ]);
    const after = skippable(2, [0]);
    const events = scanZstdStream(concat([z, after]));
    expect(events[0].type).toBe('zstd');
    // 4 magic + 1 desc + 1 FCS + (3+3) block headers + (3+1) payloads = 16
    expect(events[0].end).toBe(16n);
    expect(events[1].start).toBe(16n);
    expect(events[1].end).toBe(25n);
  });

  it('parses the same stream correctly one byte at a time', () => {
    const stream = concat([
      skippable(13, [5, 6]),
      zstdFrame([{ last: true, type: 0, size: 0 }]),
      skippable(0, []),
    ]);
    const scanner = new ZstdStreamScanner({ knownLength: BigInt(stream.length) });
    for (const b of stream) scanner.write(Uint8Array.from([b]));
    scanner.end();
    expect(scanner.events.map((e) => [e.type, e.start.toString(), e.end.toString()])).toEqual([
      ['skippable', '0', '10'],
      ['zstd', '10', '19'],
      ['skippable', '19', '27'],
    ]);
  });

  it('invokes onEvent callbacks in stream order', () => {
    const seen: FrameEvent[] = [];
    const scanner = new ZstdStreamScanner({ onEvent: (e) => seen.push(e) });
    scanner.write(skippable(0, []));
    scanner.write(zstdFrame([{ last: true, type: 0, size: 0 }]));
    scanner.end();
    expect(seen.map((e) => e.type)).toEqual(['skippable', 'zstd']);
    expect(scanner.events).toEqual(seen);
  });
});
