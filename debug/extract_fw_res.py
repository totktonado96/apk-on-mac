#!/usr/bin/env python3
# extract_fw_res.py -- pull ONE file (default: /system/framework/framework-res.apk)
# out of the local Android emulator system image, WITHOUT booting anything:
# GPT -> super partition (liblp dynamic partitions) -> logical partition ->
# ext4 -> path walk -> extent read. Read-only.
#
# WHY: the framework ANSWER differential (debug/fwprobe.sh) reads platform
# theme/style values from a framework resource table. apktool's bundled
# ~/Library/apktool/framework/1.apk is API 36 while the checked-in golden is
# the API-30 AVD, and INTERNAL resource ids shift between levels -- so a
# level-matched table is needed for exact-parity work. The API-30 image on
# this box carries the real one; this extracts it:
#
#   python3 debug/extract_fw_res.py \
#     android-emulator/android-sdk/system-images/android-30/google_apis/arm64-v8a/system.img \
#     system/framework/framework-res.apk /tmp/framework-res-api30.apk
#   MACAPK_FW_RES_APK=/tmp/framework-res-api30.apk  # then gates the probe run
#
# PROVENANCE WARNING: the extracted apk is a Google-built binary from the SDK
# system image. LOCAL DIAGNOSTIC USE ONLY -- never commit or redistribute it.
# See docs/framework-res-table_2026-08-08.md.
#
# Struct layouts: GPT (UEFI spec), liblp (AOSP system/core/fs_mgr/liblp
# metadata_format.h: geometry magic 0x616c4467, header magic 0x414C5030,
# LpMetadataPartition 52 B, LpMetadataExtent 24 B), ext4 (kernel docs; extent
# magic 0xF30A). Verified 2026-08-08 against the android-30 google_apis image.
import struct, sys

IMG, TARGET_PATH, OUT = sys.argv[1], sys.argv[2], sys.argv[3]
TARGET = TARGET_PATH.strip("/").split("/")
f = open(IMG, "rb")

def rd(off, n):
    f.seek(off)
    return f.read(n)

# ---- GPT ----
hdr = rd(512, 92)
assert hdr[:8] == b"EFI PART"
(part_lba,) = struct.unpack_from("<Q", hdr, 72)
(nparts,) = struct.unpack_from("<I", hdr, 80)
(psize,) = struct.unpack_from("<I", hdr, 84)
gpt = {}
for i in range(nparts):
    e = rd(part_lba * 512 + i * psize, psize)
    first, last = struct.unpack_from("<QQ", e, 32)
    if first == 0 and last == 0:
        continue
    name = e[56:56 + 72].decode("utf-16le").rstrip("\x00")
    gpt[name] = (first * 512, (last - first + 1) * 512)
print("gpt:", gpt)
super_off = gpt["super"][0]

# ---- liblp geometry + metadata ----
geo = rd(super_off + 4096, 58)
(gmagic,) = struct.unpack_from("<I", geo, 0)
assert gmagic == 0x616C4467, hex(gmagic)
(meta_max, slots, lbs) = struct.unpack_from("<III", geo, 40)
meta_off = super_off + 4096 + 4096 * 2   # reserved + 2 geometry copies
m = rd(meta_off, meta_max)
(magic, major, minor, hsize) = struct.unpack_from("<IHHI", m, 0)
assert magic == 0x414C5030, hex(magic)
(tables_size,) = struct.unpack_from("<I", m, 44)
# table descriptors at offset 80: partitions, extents, groups, block_devices
po, pn, pes = struct.unpack_from("<III", m, 80)
eo, en, ees = struct.unpack_from("<III", m, 92)
tables = meta_off + hsize
parts = []
for i in range(pn):
    p = rd(tables + po + i * pes, pes)
    name = p[:36].split(b"\x00")[0].decode()
    attrs, fei, ne, gi = struct.unpack_from("<IIII", p, 36)
    parts.append((name, fei, ne))
print("lp partitions:", parts)
extents = []
for i in range(en):
    e = rd(tables + eo + i * ees, ees)
    ns, tt = struct.unpack_from("<QI", e, 0)
    td, ts = struct.unpack_from("<QI", e, 12)
    extents.append((ns, tt, td, ts))

def logical_reader(name):
    for pname, fei, ne in parts:
        if pname == name:
            segs = []   # (logical_byte_off, super_byte_off, byte_len)
            lo = 0
            for ns, tt, td, ts in extents[fei:fei + ne]:
                assert tt == 0, "non-linear extent"
                segs.append((lo, super_off + td * 512, ns * 512))
                lo += ns * 512
            def r(off, n):
                out = b""
                while n > 0:
                    for slo, soff, slen in segs:
                        if slo <= off < slo + slen:
                            take = min(n, slo + slen - off)
                            out += rd(soff + (off - slo), take)
                            off += take
                            n -= take
                            break
                    else:
                        out += b"\x00" * n
                        n = 0
                return out
            return r, lo
    return None, 0

# ---- ext4 on a reader ----
def ext4(r):
    sb = r(1024, 1024)
    (magic,) = struct.unpack_from("<H", sb, 0x38)
    if magic != 0xEF53:
        return None
    (log_block,) = struct.unpack_from("<I", sb, 0x18)
    bs = 1024 << log_block
    (ipg,) = struct.unpack_from("<I", sb, 0x28)
    (isz,) = struct.unpack_from("<H", sb, 0x58)
    (feat,) = struct.unpack_from("<I", sb, 0x60)
    (dsz,) = struct.unpack_from("<H", sb, 0xFE)
    if not (feat & 0x80) or dsz == 0:
        dsz = 32
    gd = 2048 if bs == 1024 else bs
    return dict(r=r, bs=bs, ipg=ipg, isz=isz, gd=gd, dsz=dsz)

def inode(fs, num):
    grp = (num - 1) // fs["ipg"]
    idx = (num - 1) % fs["ipg"]
    d = fs["r"](fs["gd"] + grp * fs["dsz"], fs["dsz"])
    (it_lo,) = struct.unpack_from("<I", d, 8)
    it_hi = struct.unpack_from("<I", d, 40)[0] if fs["dsz"] >= 64 else 0
    return fs["r"]((it_lo | (it_hi << 32)) * fs["bs"] + idx * fs["isz"], fs["isz"])

def blocks(fs, ino):
    (size_lo,) = struct.unpack_from("<I", ino, 4)
    (size_hi,) = struct.unpack_from("<I", ino, 108)
    (flags,) = struct.unpack_from("<I", ino, 32)
    out = []
    assert flags & 0x80000, "no extents"
    def walk(node):
        magic, entries, mx, depth = struct.unpack_from("<HHHH", node, 0)
        assert magic == 0xF30A
        for i in range(entries):
            e = node[12 + i * 12:24 + i * 12]
            (lblk,) = struct.unpack_from("<I", e, 0)
            if depth == 0:
                ln, hi, lo = struct.unpack_from("<HHI", e, 4)
                out.append((lblk, (hi << 32) | lo, ln & 0x7FFF))
            else:
                lo, hi = struct.unpack_from("<IH", e, 4)
                walk(fs["r"](((hi << 32) | lo) * fs["bs"], fs["bs"]))
    walk(ino[40:100])
    return (size_lo | (size_hi << 32)), out

def lookup(fs, dino, want):
    size, exts = blocks(fs, dino)
    for lblk, phys, ln in exts:
        for b in range(ln):
            blk = fs["r"]((phys + b) * fs["bs"], fs["bs"])
            off = 0
            while off + 8 <= len(blk):
                inum, rl, nl, ft = struct.unpack_from("<IHBB", blk, off)
                if rl < 8:
                    break
                if inum and nl:
                    if blk[off + 8:off + 8 + nl].decode("utf-8", "replace") == want:
                        return inum
                off += rl
    return None

def read_file(fs, ino):
    size, exts = blocks(fs, ino)
    data = bytearray(size)
    for lblk, phys, ln in exts:
        chunk = fs["r"](phys * fs["bs"], ln * fs["bs"])
        start = lblk * fs["bs"]
        end = min(start + len(chunk), size)
        data[start:end] = chunk[:end - start]
    return bytes(data)

for cand in ("system", "system_a"):
    r, sz = logical_reader(cand)
    if r is None:
        continue
    fs = ext4(r)
    if not fs:
        print(cand, "not ext4")
        continue
    print(cand, "ext4 bs=", fs["bs"], "size=", sz)
    for prefix in (TARGET, TARGET[1:] if TARGET[0] == "system" else None):
        if prefix is None:
            continue
        cur, ok = 2, True
        for comp in prefix:
            nxt = lookup(fs, inode(fs, cur), comp)
            if nxt is None:
                ok = False
                break
            cur = nxt
        if ok:
            data = read_file(fs, inode(fs, cur))
            open(OUT, "wb").write(data)
            print(f"EXTRACTED {len(data)} bytes -> {OUT}")
            sys.exit(0)
print("NOT FOUND")
