#!/usr/bin/env python3
"""Step 1 — Decrypt and inflate the VM bytecode.

Reads 0x180 bytes of ciphertext from RVA 0x4a970, applies two PCG passes
(using seeds recovered by step 0), zlib-inflates the result, and writes
534 bytes of raw VM bytecode to data/bc.bin.
"""
from __future__ import annotations

import json
import os
import sys
import zlib

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _common import (
    BYTECODE_SRC_RVA, MASK32, PCG_MUL_A, PCG_ADD_A, PCG_MUL_B, PCG_ADD_B,
    BC_PASS1_SEED_TWEAK, BC_PASS1_MIX,
    BC_PASS2_K848_TWEAK, BC_PASS2_MIX,
    data_path, load_image,
)

# Load runtime state and binary ----------------------------------------------
with open(data_path("snap.json")) as fh:
    snap = json.load(fh)
seed_7ec = snap["seed_7ec"]
seed_13c = snap["seed_13c"]
k_828    = snap["k_828"]
k_848    = snap["k_848"]

_pe, image = load_image()
src = bytearray(image[BYTECODE_SRC_RVA:BYTECODE_SRC_RVA + 0x180])
assert len(src) == 0x180


def pass1(buf: bytearray) -> None:
    """PCG pass 1 — 2 bytes per iteration, seeded by (seed_7ec, seed_13c)."""
    r9  = seed_7ec
    ecx = (seed_13c ^ BC_PASS1_SEED_TWEAK) & MASK32
    for i in range(0, 0x180, 2):
        for off in (0, 1):
            eax = (r9 ^ ecx ^ BC_PASS1_MIX) & MASK32
            ecx = ((eax * PCG_MUL_A) + PCG_ADD_A) & MASK32
            ks  = ((ecx >> 16) ^ (ecx & 0xff)) & 0xff
            buf[i + off] ^= ks


def pass2(buf: bytearray) -> None:
    """PCG pass 2 — 2 bytes per iteration, seeded by (k_828, k_848)."""
    r8  = (k_848 ^ BC_PASS2_K848_TWEAK) & MASK32
    ecx = ((r8 >> 3) ^ k_828 ^ BC_PASS2_MIX) & MASK32
    for i in range(0, 0x180, 2):
        for off in (0, 1):
            ecx = (ecx ^ r8) & MASK32
            eax = ((ecx * PCG_MUL_B) + PCG_ADD_B) & MASK32
            ecx = ((eax >> 13) ^ eax) & MASK32
            buf[i + off] ^= ecx & 0xff


pass1(src)
pass2(src)

# After pass 2 the buffer is a standard zlib stream (starts with 78 da).
if not src.startswith(b"\x78\xda"):
    print(f"[!] warning: unexpected header after pass 2: {bytes(src[:4]).hex()}")

bytecode = zlib.decompress(bytes(src), wbits=15)
out = data_path("bc.bin")
with open(out, "wb") as fh:
    fh.write(bytecode)

print(f"Decrypted {len(bytecode)} bytes of VM bytecode (expected 534).")
print(f"First instruction: {bytecode[0]:#04x} {bytecode[1]:02x} {bytecode[2]:02x} {bytecode[3]:02x}"
      f" (expected `d1 20 00 00` = JUMP_ABS 0x20)")
print(f"\nWrote {out}")
