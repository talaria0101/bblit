#!/usr/bin/env python3
"""Bugs Bunny: Lost in Time - BZE container parser (layout verified on all 167 files).

A .BZE is a tiled container. All integers little-endian.

  Sector 0 (2048 bytes) = directory:
      u32[3] at +0:  1, N, 1          (constants; N = record count)
      N records:    [u32 raw_size, u32 aligned_size, u32 chunk_id]
                    chunk_id 0 = terminator, still a real chunk
  Then one 2048-aligned TILE per record, in record order, starting at
  byte 0x800:

      tile k = file[ 0x800 + sum(aligned_size[0..k]) : + aligned_size[k] ]

      tile header: 0x0b, chunk type byte, then type-specific fields
      payload = raw_size bytes (the rest of the tile is padding)

Invariants checked across the disc (167 files, 946 tiles):
  - every tile starts with 0x0b
  - tiles start at 0x800 and 0x800 + sum(aligned_size) == file size exactly
  - aligned_size == align2048(raw_size)
Chunk id semantics from BUGS.EXE: 3 = speech (XA-ADPCM), 4 = music
(XA-ADPCM), 2 and 5..10 = level data (textures/tables).
"""
import struct, sys, os

def directory(d):
    n = struct.unpack_from('<I', d, 4)[0]
    recs = []
    pos = 12
    for _ in range(n):
        raw, aligned, cid = struct.unpack_from('<III', d, pos)
        recs.append((cid, raw, aligned))
        pos += 12
    return recs

def tiles(d):
    """Yield (chunk_id, tile_offset, payload_offset, raw_size, aligned_size)."""
    off = 0x800
    for cid, raw, aligned in directory(d):
        yield cid, off, off + 8, raw, aligned
        off += aligned

def report(path):
    d = open(path, 'rb').read()
    print(f'== {os.path.basename(path)} ({len(d)} bytes)')
    for cid, toff, poff, raw, aligned in tiles(d):
        print(f'  id={cid:<3} tile={toff:#9x} payload={poff:#9x} raw={raw:#9x} aligned={aligned:#9x}')

def extract(path, outdir):
    d = open(path, 'rb').read()
    base = os.path.splitext(os.path.basename(path))[0]
    os.makedirs(outdir, exist_ok=True)
    for cid, toff, poff, raw, aligned in tiles(d):
        name = f'{base}.chunk{cid:02d}.bin'
        with open(os.path.join(outdir, name), 'wb') as f:
            f.write(d[poff:poff+raw])
        print(f'  id={cid:<3} raw={raw:#9x} -> {name}')

if __name__ == '__main__':
    if len(sys.argv) >= 3 and sys.argv[1] == '-x':
        extract(sys.argv[2], sys.argv[3])
    else:
        for p in sys.argv[1:]:
            report(p)
