#!/usr/bin/env python3
"""Step 3 — Decode the 29-entry constant pool and recover the flag.

Each entry in the aux blob is individually encrypted with an offset-seeded
PCG keystream.  Handler 0x180007790 inside the binary dispatches on the
decrypted first byte (the "type tag") and applies a type-specific decoder
for the remainder of the entry.

The flag lives in entries 1..15, encoded as VARINTs (tag 0xb1).  Each
integer is one ASCII codepoint of the flag.
"""
from __future__ import annotations

import json
import os
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _common import (
    AUX_OFFSET_TABLE_RVA, AUX_LENGTH_TABLE_RVA,
    MASK32, NEG_GOLDEN, PCG_MUL_A, PCG_ADD_A, PCG_MUL_B,
    STRING_ROT_MIX,
    data_path, load_image, read_u32,
)

# -----------------------------------------------------------------------------
# Load inputs
# -----------------------------------------------------------------------------
with open(data_path("snap.json")) as fh:
    snap = json.load(fh)
SEED_7EC = snap["seed_7ec"]
SEED_13C = snap["seed_13c"]

with open(data_path("aux.bin"), "rb") as fh:
    aux = fh.read()

_pe, image = load_image()
offsets = [read_u32(image, AUX_OFFSET_TABLE_RVA + i * 4) for i in range(29)]
lengths = [read_u32(image, AUX_LENGTH_TABLE_RVA + i * 4) for i in range(29)]


# -----------------------------------------------------------------------------
# Per-entry decryption primitives
# -----------------------------------------------------------------------------
def pcg_tag(off: int) -> tuple[int, int]:
    """Decrypt the 1-byte type tag at aux[off].

    Mirrors the prelude of handler 0x180007790.  Returns (decrypted_tag,
    final_state) so callers can chain if needed.
    """
    ecx = (off * NEG_GOLDEN) & MASK32
    ecx ^= SEED_13C; ecx &= MASK32
    eax = (ecx >> 16) ^ ecx
    ecx = (eax * PCG_MUL_A) & MASK32
    ecx ^= SEED_7EC; ecx &= MASK32
    eax = (ecx >> 16) ^ ecx
    ecx = (eax * PCG_MUL_B) & MASK32
    ks  = (((ecx >> 16) & 0xff) ^ (ecx & 0xff)) & 0xff
    return aux[off] ^ ks, ecx


def decode_varint(off: int) -> int:
    """VARINT (LEB128) decoder for tag 0xb1.

    Each byte uses an independent PCG stream seeded by (off+1+i) * 0x9e3779b9.
    The low 7 bits of each decrypted byte accumulate into the result; the
    high bit marks "continue".
    """
    ebp = off + 1
    pos = off + 1
    result = 0
    shift  = 0
    for _ in range(16):  # safety cap
        ecx = (ebp * NEG_GOLDEN) & MASK32
        ebp += 1
        ecx ^= SEED_13C; ecx &= MASK32
        eax = (ecx >> 16) ^ ecx
        ecx = (eax * PCG_MUL_A) & MASK32
        ecx ^= SEED_7EC; ecx &= MASK32
        eax = (ecx >> 16) ^ ecx
        ecx = (eax * PCG_MUL_B) & MASK32
        ks  = (((ecx >> 16) & 0xff) ^ (ecx & 0xff)) & 0xff
        if pos >= len(aux):
            break
        b = aux[pos] ^ ks
        pos += 1
        result |= (b & 0x7f) << shift
        shift += 7
        if not (b & 0x80):
            break
    # Handler ends with PyLong_FromLong which is signed.  Sign-extend.
    if result & 0x80000000:
        result -= 0x100000000
    return result


def decode_string(off: int, length: int) -> bytes:
    """String decoder for tag 0x16.

    For each byte of the payload:
      1. Generate PCG keystream byte with ESI seeded at
         (0x9e3779b9 - off*0x61c88647) and decrementing by 0x61c88647.
      2. XOR the ciphertext byte at aux[off + 1 + i] with the keystream.
      3. Rotate-right-3 the result.
      4. XOR with ((off * 0x6b43a9b1) XOR (length * 0x9e3779b9)) indexed by
         (i mod 4) * 8.
    """
    r15 = ((off * STRING_ROT_MIX) ^ (length * NEG_GOLDEN)) & MASK32
    esi = (NEG_GOLDEN - (off * 0x61c88647)) & MASK32
    out = bytearray(length)
    for i in range(length):
        ecx = esi & MASK32
        ecx ^= SEED_13C; ecx &= MASK32
        esi = (esi - 0x61c88647) & MASK32
        eax = (ecx >> 16) ^ ecx
        ecx = (eax * PCG_MUL_A) & MASK32
        ecx ^= SEED_7EC; ecx &= MASK32
        eax = (ecx >> 16) ^ ecx
        ecx = (eax * PCG_MUL_B) & MASK32
        ks  = (((ecx >> 16) & 0xff) ^ (ecx & 0xff)) & 0xff
        pos = off + 1 + i
        if pos >= len(aux):
            break
        b   = aux[pos] ^ ks
        rot = ((b >> 3) | ((b & 7) << 5)) & 0xff
        out[i] = rot ^ ((r15 >> ((i % 4) * 8)) & 0xff)
    return bytes(out)


# -----------------------------------------------------------------------------
# Walk the constant pool
# -----------------------------------------------------------------------------
TAG_NAMES = {0x75: "None", 0xdc: "True", 0xd0: "False"}
flag_chars: list[int] = []

print(f"{'idx':>3s} {'off':>4s} {'len':>3s} {'tag':>4s}  value")
for i in range(29):
    off, ln = offsets[i], lengths[i]
    if ln == 0 or off + ln > len(aux):
        print(f" {i:2d} {off:4d} {ln:3d}   --   (empty/OOR)")
        continue
    tag, _ = pcg_tag(off)
    if tag in TAG_NAMES:
        print(f" {i:2d} {off:4d} {ln:3d}  {tag:02x}   {TAG_NAMES[tag]}")
    elif tag == 0xb1:
        val = decode_varint(off)
        desc = f"int={val}"
        if 0 <= val < 256 and 32 <= val < 127:
            desc += f"  -> {chr(val)!r}"
            if 1 <= i <= 15:
                flag_chars.append(val)
        print(f" {i:2d} {off:4d} {ln:3d}  b1   {desc}")
    elif tag == 0x16:
        body = decode_string(off, ln - 1)
        try:
            text = body.decode("utf-8")
            desc = repr(text)
        except UnicodeDecodeError:
            desc = "hex=" + body.hex()
        print(f" {i:2d} {off:4d} {ln:3d}  16   str {desc}")
    else:
        print(f" {i:2d} {off:4d} {ln:3d}  {tag:02x}   (unhandled tag)")


if len(flag_chars) == 15:
    flag = bytes(flag_chars).decode("ascii")
    print(f"\nFLAG: {flag}")
else:
    print(f"\n[!] expected 15 flag characters, got {len(flag_chars)}")
