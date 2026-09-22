# Zstandard framing core

TypeScript library for Zstandard frame processing, including a scanner for
[skippable frames](https://www.rfc-editor.org/rfc/rfc8478#section-3.3).

Run `npm install`, then `npm test` and `npm run build`.

## Skippable frame scanning

- Lengths are read as **unsigned** little-endian 32-bit values (`readUInt32LE`),
  so a high bit set never produces a negative cursor offset.
- Magic validation covers the complete inclusive range
  `0x184D2A50 .. 0x184D2A5F` (`isSkippableMagic`).
- Frame `end` offsets are computed with `bigint` and checked against the input
  boundary (`readSkippableHeader`, `scanSkippableFrames`).
- `SkippableScanner` is a streaming parser: skippable payload is skipped
  without buffering (only up to 8 header bytes are cached across chunks), or
  streamed via `onPayload` when `streamPayload: true`. Ordinary zstd frames are
  walked by headers (FCS/dictionary/block headers, RLE size handling, trailing
  checksum) and their bytes are passed through `onData` unchanged.
- Each skippable event reports the magic, `variant` (0..15), unsigned `length`
  and absolute ranges — `range`, `headerRange`, `payloadRange`
  (`{start, end}`, `end` exclusive).
