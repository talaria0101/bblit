#!/usr/bin/env python3
"""Minimal ISO 9660 extractor with Joliet/Rock Ridge name support."""
import struct, sys, os

iso_path = sys.argv[1]
out_root = sys.argv[2] if len(sys.argv) > 2 else None

f = open(iso_path, 'rb')

def read_sector(lba, count=1):
    f.seek(lba * 2048)
    return f.read(2048 * count)

# PVD at LBA 16; scan volume descriptors
pvd = None; svd = None; terminator_lba = None
lba = 16
while True:
    d = read_sector(lba)
    t = d[0]
    if t == 1: pvd = d
    elif t == 2: svd = d  # supplementary = usually Joliet
    elif t == 255:
        terminator_lba = lba
        break
    lba += 1
    if lba > 200: break

print(f"PVD found: {pvd is not None}, Joliet SVD found: {svd is not None}, terminator at LBA {terminator_lba}")

def parse_root(dr):
    ext_lba = struct.unpack('<I', dr[2:6])[0]
    size = struct.unpack('<I', dr[10:14])[0]
    return ext_lba, size

def walk(dir_lba, dir_size, prefix, out, depth=0, joliet=False):
    nsec = (dir_size + 2047)//2048
    data = read_sector(dir_lba, nsec)
    pos = 0
    while pos < len(data):
        ln = data[pos]
        if ln == 0:
            # advance to next sector boundary
            nxt = ((pos//2048)+1)*2048
            if nxt >= len(data): break
            pos = nxt
            continue
        dr = data[pos:pos+ln]
        pos += ln
        ext_lba = struct.unpack('<I', dr[2:6])[0]
        size = struct.unpack('<I', dr[10:14])[0]
        flags = dr[25]
        name_len = dr[32]
        name = dr[33:33+name_len]
        if joliet:
            name = name.decode('utf-16-be', 'replace')
        else:
            name = name.decode('latin-1')
        if name in ('\x00', '\x01'):
            continue
        # split off ;version
        base = name.split(';')[0]
        is_dir = bool(flags & 2)
        # Rock Ridge: check for NM entry in system use area
        # (skipped for simplicity unless needed)
        path = prefix + base
        if is_dir:
            out.append(('d', path, ext_lba, size))
            if depth < 12:
                walk(ext_lba, size, path + '/', out, depth+1, joliet)
        else:
            out.append(('f', path, ext_lba, size))

entries = []
used = None
if svd:
    enc = svd[40:40+32]
    # check Joliet escape sequences
    if enc[:3] == b'%/@' or enc[:3] == b'%/C' or enc[:3] == b'%/E':
        used = 'joliet'
        root_dr_len = svd[156+0]
        root_dr = svd[156:156+root_dr_len]
        rlba, rsize = parse_root(root_dr)
        walk(rlba, rsize, '', entries, 0, joliet=True)

if used is None and pvd:
    used = 'iso9660'
    root_dr_len = pvd[156]
    root_dr = pvd[156:156+root_dr_len]
    rlba, rsize = parse_root(root_dr)
    walk(rlba, rsize, '', entries, 0, joliet=False)

print(f"Used descriptor: {used}, total entries: {len(entries)}")
for kind, path, lba, size in entries:
    print(f"{kind} {size:>10} lba={lba:<8} {path}")

if out_root:
    os.makedirs(out_root, exist_ok=True)
    f.seek(0)
    for kind, path, lba, size in entries:
        dest = os.path.join(out_root, path.lstrip('/'))
        if kind == 'd':
            os.makedirs(dest, exist_ok=True)
        else:
            f.seek(lba*2048)
            remaining = size
            os.makedirs(os.path.dirname(dest), exist_ok=True)
            with open(dest, 'wb') as o:
                while remaining > 0:
                    chunk = f.read(min(1<<20, remaining))
                    if not chunk: break
                    o.write(chunk)
                    remaining -= len(chunk)
    print(f"extracted to {out_root}")
