import { describe, expect, it } from 'vitest';
import {
  InvalidMagicError,
  SKIPPABLE_MAGIC_MIN,
  SKIPPABLE_MAGIC_MAX,
  ZSTD_MAGIC,
  SkippableScanner,
  TruncatedFrameError,
  readSkippableHeader,
  readUInt32LE,
  scanSkippableFrames,
  type SkippableFrameEvent,
} from '../src/index.js';

const ZSTD_MAGIC_BYTES = [0xfd, 0x2f, 0xb5, 0x28];

function u32le(value: number): number[] {
  return [value & 0xff, (value >>> 8) & 0xff, (value >>> 16) & 0xff, value >>> 24];
}

function skippable(variant: number, payload: Uint8Array | number[] = []): Uint8Array {
  const body = payload instanceof Uint8Array ? payload : Uint8Array.from(payload);
  const out = new Uint8Array(8 + body.length);
  out.set(u32le(SKIPPABLE_MAGIC_MIN + variant), 0);
  out.set(u32le(body.length >>> 0), 4);
  out.set(body, 8);
  return out;
}

/**
 * Minimal ordinary zstd frame, RAW block:
 *   magic | descriptor(single_segment, no checksum) | FCS=0 | block(last, raw, size=0)
 * 9 bytes total.
 */
function zstdEmptyFrame(): Uint8Array {
  return Uint8Array.from([...ZSTD_MAGIC_BYTES, 0x20, 0x00, 0x01, 0x00, 0x00]);
}

/** Ordinary zstd frame carrying `content` in a single last RAW block. */
function zstdRawFrame(content: number[]): Uint8Array {
  const blockHeader = (content.length << 3) | 0b000 | 0b1; // raw type 0, last
  const out = new Uint8Array(4 + 2 + 3 + content.length);
  let o = 0;
  out.set(ZSTD_MAGIC_BYTES, o);
  o += 4;
  out[o++] = 0x20; // Frame_Header_Descriptor: single segment, FCS flag 0
  out[o++] = content.length; // 1-byte FCS (single-segment form)
  out[o++] = blockHeader & 0xff;
  out[o++] = (blockHeader >>> 8) & 0xff;
  out[o++] = (blockHeader >>> 16) & 0xff;
  out.set(content, o);
  return out;
}

function concat(...parts: Uint8Array[]): Uint8Array {
  const total = parts.reduce((s, p) => s + p.length, 0);
  const out = new Uint8Array(total);
  let o = 0;
  for (const p of parts) {
    out.set(p, o);
    o += p.length;
  }
  return out;
}

describe('readUInt32LE', () => {
  it('reads high-bit-set values as unsigned', () => {
    expect(readUInt32LE(Uint8Array.from([0, 0, 0, 0x80]))).toBe(0x80000000);
    expect(readUInt32LE(Uint8Array.from([0xff, 0xff, 0xff, 0xff]))).toBe(0xffffffff);
    expect(readUInt32LE(Uint8Array.from([1, 0, 0, 0x80]))).toBe(0x80000001);
  });
});

describe('skippable magic range', () => {
  it.each([0, 1, 14, 15])('accepts variant %i at the range ends', (variant) => {
    const magic = SKIPPABLE_MAGIC_MIN + variant;
    const data = skippable(variant);
    const { event } = readSkippableHeader(data);
    expect(event.magic).toBe(magic);
    expect(event.variant).toBe(variant);
  });

  it('rejects the value just below the range', () => {
    const data = new Uint8Array(8);
    data.set(u32le(SKIPPABLE_MAGIC_MIN - 1), 0);
    expect(() => readSkippableHeader(data)).toThrow(InvalidMagicError);
  });

  it('accepts 0x184D2A5F and rejects 0x184D2A60 (last legal value included)', () => {
    expect(readSkippableHeader(skippable(15)).event.magic).toBe(SKIPPABLE_MAGIC_MAX);
    const data = new Uint8Array(8);
    data.set(u32le(SKIPPABLE_MAGIC_MAX + 1), 0);
    expect(() => readSkippableHeader(data)).toThrow(InvalidMagicError);
  });

  it('rejects the ordinary zstd magic as skippable', () => {
    const data = new Uint8Array(8);
    data.set(u32le(ZSTD_MAGIC), 0);
    expect(() => readSkippableHeader(data)).toThrow(InvalidMagicError);
  });
});

describe('length handling', () => {
  it('accepts length 0 with an empty, exact absolute range', () => {
    const { event, end } = readSkippableHeader(skippable(0));
    expect(event.length).toBe(0);
    expect(event.headerRange).toEqual({ start: 0, end: 8 });
    expect(event.payloadRange).toEqual({ start: 8, end: 8 });
    expect(event.range).toEqual({ start: 0, end: 8 });
    expect(end).toBe(8);
  });

  it('reads high-bit-set lengths unsigned and never moves the cursor backwards', () => {
    const length = 0x80000000;
    const data = new Uint8Array(8);
    data.set(u32le(SKIPPABLE_MAGIC_MIN + 3), 0);
    data.set(u32le(length), 4);

    const events: SkippableFrameEvent[] = [];
    // Header is valid; the (absent) payload is what is truncated.
    expect(() =>
      scanSkippableFrames(data, { onSkippable: (e) => events.push(e) }),
    ).toThrow(TruncatedFrameError);

    expect(events).toHaveLength(1);
    expect(events[0].length).toBe(length);
    expect(events[0].range.end).toBeGreaterThan(events[0].range.start);
    expect(events[0].range.end).toBe(0x80000008);
  });

  it('accepts maximum length 0xFFFFFFFF in the event range', () => {
    const data = new Uint8Array(8);
    data.set(u32le(SKIPPABLE_MAGIC_MIN), 0);
    data.set(u32le(0xffffffff), 4);
    const events: SkippableFrameEvent[] = [];
    expect(() => scanSkippableFrames(data, { onSkippable: (e) => events.push(e) })).toThrow(
      TruncatedFrameError,
    );
    expect(events[0].length).toBe(0xffffffff);
    expect(events[0].range.end).toBe(0x100000007);
  });
});

describe('truncation', () => {
  it('throws on a truncated skippable header (1..7 bytes)', () => {
    const full = skippable(2, [1, 2, 3]);
    for (let cut = 1; cut < 8; cut++) {
      let threw = false;
      try {
        readSkippableHeader(full.subarray(0, cut));
      } catch (e) {
        threw = true;
        expect(e).toBeInstanceOf(TruncatedFrameError);
        expect((e as TruncatedFrameError).kind).toBe('skippable_header');
      }
      expect(threw).toBe(true);
    }
  });

  it('throws on truncated payload and reports the expected end', () => {
    const full = skippable(1, [0xaa, 0xbb, 0xcc, 0xdd]);
    const cut = full.subarray(0, 10); // 2 of 4 payload bytes missing
    let threw = false;
    try {
      readSkippableHeader(cut);
    } catch (e) {
      threw = true;
      expect(e).toBeInstanceOf(TruncatedFrameError);
      const t = e as TruncatedFrameError;
      expect(t.kind).toBe('skippable_payload');
      expect(t.offset).toBe(10);
    }
    expect(threw).toBe(true);
  });
});

describe('interleaved skippable and ordinary frames', () => {
  it('walks skippable / zstd / skippable and lands on the exact next frame start', () => {
    const a = skippable(0, [10, 20, 30]); // 11 bytes
    const z = zstdEmptyFrame(); // 9 bytes
    const b = skippable(15, [99]); // 9 bytes
    const stream = concat(a, z, b);

    const events = scanSkippableFrames(stream);
    expect(events.map((e) => e.variant)).toEqual([0, 15]);

    expect(events[0].range).toEqual({ start: 0, end: 11 });
    expect(events[0].length).toBe(3);
    expect(events[0].payloadRange).toEqual({ start: 8, end: 11 });

    // Next frame (ordinary) starts exactly at byte 11.
    expect(events[1].headerRange.start).toBe(20);
    expect(events[1].range).toEqual({ start: 20, end: 29 });
    expect(events[1].length).toBe(1);
    expect(events[1].payloadRange).toEqual({ start: 28, end: 29 });
  });

  it('passes ordinary frame bytes through unchanged at correct offsets', () => {
    const a = skippable(5, new Array(4).fill(0x55));
    const content = [7, 8, 9, 10];
    const z = zstdRawFrame(content);
    const b = skippable(0);
    const stream = concat(a, z, b);

    const received: { bytes: number[]; offset: number }[] = [];
    scanSkippableFrames(stream, {
      onData: (chunk, offset) => received.push({ bytes: [...chunk], offset }),
    });
    const passthrough = concat(...received.map((r) => Uint8Array.from(r.bytes)));
    expect([...passthrough]).toEqual([...z]);
    expect(received[0].offset).toBe(12); // right after first skippable (8+4)
  });

  it('handles two consecutive skippable frames with no gap', () => {
    const stream = concat(skippable(0, [1]), skippable(14, [2, 3]));
    const events = scanSkippableFrames(stream);
    expect(events.map((e) => e.range.end)).toEqual([9, 19]);
    expect(events[1].range.start).toBe(9);
  });

  it('handles ordinary frames back to back', () => {
    const stream = concat(zstdEmptyFrame(), zstdEmptyFrame());
    const received: number[] = [];
    const events = scanSkippableFrames(stream, {
      onData: (c) => received.push(...c),
    });
    expect(events).toEqual([]);
    expect(received.length).toBe(18);
  });
});

describe('streaming SkippableScanner', () => {
  const stream = concat(
    skippable(0, new Array(5).fill(0xab)),
    zstdRawFrame([1, 2, 3]),
    skippable(15),
  );

  it('parses correctly when chunks arrive one byte at a time', () => {
    const events: SkippableFrameEvent[] = [];
    const scanner = new SkippableScanner({ onSkippable: (e) => events.push(e) });
    for (let i = 0; i < stream.length; i++) {
      scanner.write(stream.subarray(i, i + 1));
    }
    scanner.finish();
    expect(events.map((e) => e.variant)).toEqual([0, 15]);
    expect(events[0].range).toEqual({ start: 0, end: 13 });
    expect(events[1].range.start).toBe(25);
    expect(scanner.bytesRead).toBe(stream.length);
  });

  it('never caches payload: streamPayload=false drops payload bytes', () => {
    const payloads: number[] = [];
    const scanner = new SkippableScanner({
      streamPayload: false,
      onPayload: (c) => payloads.push(...c),
    });
    scanner.write(stream);
    scanner.finish();
    expect(payloads).toEqual([]);
  });

  it('streams payload slices at absolute ranges when enabled', () => {
    const pieces: { bytes: number[]; start: number; end: number }[] = [];
    const scanner = new SkippableScanner({
      streamPayload: true,
      onPayload: (c, range) =>
        pieces.push({ bytes: [...c], start: range.start, end: range.end }),
    });
    // Split in the middle of the first payload.
    scanner.write(stream.subarray(0, 10));
    scanner.write(stream.subarray(10));
    scanner.finish();

    const first = pieces.filter((p) => p.start >= 8 && p.end <= 13);
    expect(concat(...first.map((p) => Uint8Array.from(p.bytes)))).toEqual(
      Uint8Array.from([0xab, 0xab, 0xab, 0xab, 0xab]),
    );
    expect(first[0].start).toBe(8);
    const lastEnd = first[first.length - 1].end;
    expect(lastEnd).toBe(13); // next frame starts here
  });

  it('reports truncated header at finish()', () => {
    const scanner = new SkippableScanner();
    scanner.write(skippable(0).subarray(0, 5));
    let kind = '';
    try {
      scanner.finish();
    } catch (e) {
      expect(e).toBeInstanceOf(TruncatedFrameError);
      kind = (e as TruncatedFrameError).kind;
    }
    expect(kind).toBe('skippable_header');
  });

  it('reports truncated payload at finish()', () => {
    const scanner = new SkippableScanner();
    scanner.write(skippable(0, [1, 2, 3, 4]).subarray(0, 10));
    expect(() => scanner.finish()).toThrow(TruncatedFrameError);
  });

  it('reports truncated ordinary frame at finish()', () => {
    const scanner = new SkippableScanner();
    scanner.write(zstdEmptyFrame().subarray(0, 6));
    expect(() => scanner.finish()).toThrow(TruncatedFrameError);
  });

  it('replays zstd magic correctly when the previous skippable frame arrived in another chunk', () => {
    // Regression: the magic replay used the shared pending buffer, which
    // still held the previous frame's length bytes.
    const head = skippable(15); // zero-length
    const z = zstdEmptyFrame();
    const received: { bytes: Uint8Array; offset: number }[] = [];
    const scanner = new SkippableScanner({
      onData: (bytes, offset) => received.push({ bytes, offset }),
    });
    scanner.write(head);
    scanner.write(z);
    scanner.finish();
    const all = concat(...received.map((r) => r.bytes));
    expect([...all]).toEqual([...z]);
    expect(received[0].offset).toBe(8);
  });

  it('rejects an out-of-range magic mid-stream', () => {
    const bad = new Uint8Array(8);
    bad.set(u32le(SKIPPABLE_MAGIC_MAX + 1), 0);
    const scanner = new SkippableScanner();
    expect(() => scanner.write(bad)).toThrow(InvalidMagicError);
  });
});
