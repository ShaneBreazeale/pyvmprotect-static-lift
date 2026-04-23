#!/usr/bin/env python3
"""Step 2 — Decrypt and inflate the encrypted constant pool ("aux blob").

Reads 0xd7 bytes of ciphertext from RVA 0x4a430, applies two PCG passes
(with aux-specific mix constants), zlib-inflates the result, and writes
204 bytes of aux-blob ciphertext to data/aux.bin.

Note that the aux blob is itself encrypted per-entry; step 3 decodes each
entry individually using offset-seeded PCG.
"""
from __future__ import annotations

import json
import os
import sys
import zlib

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _common import (
    AUX_SRC_RVA, MASK32, PCG_MUL_A, PCG_ADD_A, PCG_MUL_B, PCG_ADD_B,
    AUX_PASS1_SEED_TWEAK, AUX_PASS1_MIX,
    AUX_PASS2_K848_TWEAK, AUX_PASS2_MIX,
    data_path, load_image,
)

with open(data_path("snap.json")) as fh:
    snap = json.load(fh)
seed_7ec = snap["seed_7ec"]
seed_13c = snap["seed_13c"]
k_828    = snap["k_828"]
k_848    = snap["k_848"]

_pe, image = load_image()
src = bytearray(image[AUX_SRC_RVA:AUX_SRC_RVA + 0xd7])
assert len(src) == 0xd7


def pass1(buf: bytearray) -> None:
    """PCG pass 1 — 1 byte per iteration.  Constants differ from bytecode pass 1."""
    r10 = seed_7ec
    ecx = (seed_13c ^ AUX_PASS1_SEED_TWEAK) & MASK32
    for i in range(0xd7):
        eax = (r10 ^ ecx ^ AUX_PASS1_MIX) & MASK32
        ecx = ((eax * PCG_MUL_A) + PCG_ADD_A) & MASK32
        ks  = ((ecx >> 16) ^ (ecx & 0xff)) & 0xff
        buf[i] ^= ks


def pass2(buf: bytearray) -> None:
    """PCG pass 2 — 1 byte per iteration.  Constants differ from bytecode pass 2."""
    r9  = (k_848 ^ AUX_PASS2_K848_TWEAK) & MASK32
    ecx = ((r9 >> 3) ^ k_828 ^ AUX_PASS2_MIX) & MASK32
    for i in range(0xd7):
        ecx = (ecx ^ r9) & MASK32
        eax = ((ecx * PCG_MUL_B) + PCG_ADD_B) & MASK32
        ecx = ((eax >> 13) ^ eax) & MASK32
        buf[i] ^= ecx & 0xff


pass1(src)
pass2(src)

if not src.startswith(b"\x78\xda"):
    print(f"[!] warning: unexpected header after pass 2: {bytes(src[:4]).hex()}")

aux = zlib.decompress(bytes(src), wbits=15)
out = data_path("aux.bin")
with open(out, "wb") as fh:
    fh.write(aux)

print(f"Decrypted {len(aux)} bytes of aux blob (expected 204).")
print(f"First 16 bytes (still per-entry encrypted): {aux[:16].hex()}")
print(f"\nWrote {out}")
