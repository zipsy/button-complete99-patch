#!/usr/bin/env python3
"""Patch B.U.T.T.O.N.exe: Steam achievement COMPLETE_99 -> COMPLETE_99%.

Usage: python3 patch_complete99.py <original exe>
The input is never modified; the result is written as <stem>-patched.exe
next to it, and its MD5 is checked against the known-good patched build.
"""
import hashlib
import struct
import sys

ORIG_MD5 = "613a292a7ecb478abcd6556a92b7ac64"
PATCHED_MD5 = "3aa028ce0b8d84a4be0c3a0c5c616dce"

if len(sys.argv) != 2:
    sys.exit("usage: python3 patch_complete99.py <original exe>")
src = sys.argv[1]
try:
    with open(src, "rb") as f:
        data = bytearray(f.read())
except OSError as e:
    sys.exit(f"cannot read {src}: {e}")

md5 = hashlib.md5(data).hexdigest()
if md5 == PATCHED_MD5:
    sys.exit(f"input {src} is already the PATCHED build (md5 {md5}) - give the ORIGINAL exe")
if md5 != ORIG_MD5:
    sys.exit(f"input {src} md5 {md5} != expected original {ORIG_MD5} - refusing to patch")

# ---- constants, verified against the pristine original ----
US_FILE = 0x2D4FC
US_SIZE = 0xAC9C
C99_FILE = 0x37728
GUID_FILE = 0x38198
META_RVA, META_SIZE = 0x1E1A8, 0x1CE08
CLI_META_SIZE_FI = 0x214
TEXT_HDR_FI = 0x178
TEXT_VS_FI = TEXT_HDR_FI + 8
TEXT_SIZE_FI = TEXT_HDR_FI + 16
SEC1_RAWOFF_FI = 0x178 + 40 + 20
SEC2_RAWOFF_FI = 0x178 + 80 + 20
ORIG_TEXT_VS = 0x390B4
ORIG_TEXT_SIZE = 0x39200
ORIG_RSRC = 0x39400
ORIG_RELOC = 0x3DA00
ORIG_LEN = 252928
ORIG_SIZEOFIMG = 0x3B0AE
SIZEOFIMG_FI = 0x80 + 0x28

assert len(data) == ORIG_LEN
assert data[C99_FILE] == 0x17
assert data[C99_FILE + 1:C99_FILE + 23] == "COMPLETE_99".encode("utf-16-le")
assert data[TEXT_HDR_FI:TEXT_HDR_FI + 6] == b".text\x00"
assert struct.unpack_from("<I", data, TEXT_SIZE_FI)[0] == ORIG_TEXT_SIZE
assert struct.unpack_from("<I", data, SEC1_RAWOFF_FI)[0] == ORIG_RSRC
assert struct.unpack_from("<I", data, SEC2_RAWOFF_FI)[0] == ORIG_RELOC
assert struct.unpack_from("<I", data, SIZEOFIMG_FI)[0] == ORIG_SIZEOFIMG
assert data[GUID_FILE - 4:GUID_FILE] == b"\x00\x00\x00\x00"
assert struct.unpack_from("<II", data, 0x210) == (META_RVA, META_SIZE)

NEW = "COMPLETE_99%".encode("utf-16-le")
entry = struct.pack("B", len(NEW) + 1) + NEW
entry += b"\x00" * (-len(entry) % 4)
assert len(entry) == 0x1C
SHIFT = 0x200
BLOCK = entry + b"\x00" * (SHIFT - len(entry))
HEAP_SHIFT = len(entry)
NEW_TOKEN = struct.pack("<I", 0x70000000 | US_SIZE)
OLD_TOKEN = struct.pack("<I", 0x70000000 | (C99_FILE - US_FILE))

# 1) retarget the single ldstr operand for COMPLETE_99
n = 0
p = 0
while True:
    p = data.find(b"\x72" + OLD_TOKEN, p)
    if p < 0:
        break
    data[p + 1:p + 5] = NEW_TOKEN
    n += 1
    print(f"ldstr retargeted at file 0x{p:X}")
if n == 0:
    sys.exit("no ldstr reference to COMPLETE_99 found - aborting")

# 2) BSJB stream directory: #US grows by the entry, #GUID/#Blob shift by the block
BSJB = data.find(b"BSJB", 0x1C300)
vlen = struct.unpack_from("<I", data, BSJB + 12)[0]
flags, nst = struct.unpack_from("<HH", data, BSJB + 16 + vlen)
t = BSJB + 16 + vlen + 4
for _ in range(nst):
    ro, sz = struct.unpack_from("<II", data, t)
    q = t + 8
    nm = b""
    while data[q]:
        nm += bytes([data[q]])
        q += 1
    L = len(nm) + 1
    L += -L % 4
    name = nm.decode()
    if name == "#US":
        struct.pack_into("<I", data, t + 4, sz + HEAP_SHIFT)
    elif name in ("#GUID", "#Blob"):
        struct.pack_into("<I", data, t, ro + SHIFT)
    t += 8 + L

# 3) COR20 metadata size and NT Header SizeOfImage both must cover the growth
struct.pack_into("<I", data, CLI_META_SIZE_FI, META_SIZE + SHIFT)
struct.pack_into("<I", data, SIZEOFIMG_FI, ORIG_SIZEOFIMG + SHIFT)

# 4) PE sections: .text grows, .rsrc/.reloc shift by the full block
struct.pack_into("<I", data, TEXT_SIZE_FI, ORIG_TEXT_SIZE + SHIFT)
assert struct.unpack_from("<I", data, TEXT_VS_FI)[0] == ORIG_TEXT_VS
struct.pack_into("<I", data, TEXT_VS_FI, ORIG_TEXT_VS + SHIFT)
struct.pack_into("<I", data, SEC1_RAWOFF_FI, ORIG_RSRC + SHIFT)
struct.pack_into("<I", data, SEC2_RAWOFF_FI, ORIG_RELOC + SHIFT)

# 5) physically insert the 0x200-aligned block at the end of the #US heap
data[GUID_FILE:GUID_FILE] = BLOCK

# 6) legacy Framework-CLR pointers into the assembly trailer (file 0x100/0x128
# DataDirectory entries, PIMAGE_INFO@0x200, IMAGE_SECURITY + import-stub records)
LEGACY_PTRS = {
    0x100: 0x3B054,
    0x128: 0x3AFB0,
    0x200: 0x3B090,
    0x391C4: 0x3AFCC,
    0x391C8: 0x391CC,
    0x39254: 0x3B07C,
    0x39260: 0x3B09E,
    0x3927C: 0x3B090,
}
for fi, want in sorted(LEGACY_PTRS.items()):
    po = fi + SHIFT if fi >= GUID_FILE else fi
    assert struct.unpack_from("<I", data, po)[0] == want
    struct.pack_into("<I", data, po, want + SHIFT)

# ---- post-patch verification before writing ----
assert data.count(OLD_TOKEN) == 0
assert data.count(NEW_TOKEN) == 1
assert len(data) == ORIG_LEN + SHIFT
mrva, msze = struct.unpack_from("<II", data, 0x210)
si = struct.unpack_from("<I", data, SIZEOFIMG_FI)[0]
assert mrva + msze <= si
assert mrva + msze <= 0x2000 + struct.unpack_from("<I", data, TEXT_VS_FI)[0]
assert data[0x39492:0x3949D] == b"_CorExeMain"
assert data[0x393CC:0x393D0] == b"RSDS"

stem = src[:-4] if src.lower().endswith(".exe") else src
dst = stem + "-patched.exe"
with open(dst, "wb") as f:
    f.write(data)

out_md5 = hashlib.md5(data).hexdigest()
ok = out_md5 == PATCHED_MD5
print(f"OK" if ok else "MISMATCH", f"{dst} md5 {out_md5} (expected {PATCHED_MD5})")
if not ok:
    sys.exit(1)
