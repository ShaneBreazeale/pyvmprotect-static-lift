#!/usr/bin/env python3
"""Bonus — Decrypt the 209 anti-debug / vendor-detection strings.

These are the strings referenced by the string decryptor at 0x180007530.
Each entry has a length word at RVA 0x4a6a0 + i*2 and an offset word at
RVA 0x49960 + i*2, both indexing into the ciphertext base at RVA 0x49b10.

No relation to the flag — the flag characters live in the aux blob, not
here — but this script is a useful sanity check that seed_7ec and
seed_13c are correct, and the decoded pool is a fun look at what the
vendor runtime is fingerprinting (Frida, x64dbg, VirtualBox, Qemu, ...).
"""
from __future__ import annotations

import json
import os
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _common import (
    MASK32, PCG_MUL_A, PCG_ADD_A,
    data_path, load_image,
)

with open(data_path("snap.json")) as fh:
    snap = json.load(fh)
SEED_7EC = snap["seed_7ec"]
SEED_13C = snap["seed_13c"]

_pe, image = load_image()

LEN_TBL = 0x4a6a0
OFF_TBL = 0x49960
CT_BASE = 0x49b10
N = 0xd1                         # 209 strings
STATE_STEP = 0x7083d9a1          # per-entry running-state delta


def decrypt(ct: bytes, r8_init: int) -> bytes:
    """One entry's decryption — matches the loop at 0x1800075c0."""
    r8 = (-r8_init) & MASK32
    out = bytearray(len(ct))
    for j in range(len(ct)):
        eax = SEED_13C
        ecx = SEED_7EC
        eax ^= r8; eax &= MASK32
        ecx ^= eax; ecx &= MASK32
        r8 = (r8 + PCG_ADD_A) & MASK32
        state = ecx
        state ^= (state >> 16)
        state = (state * 0x9e3779b9) & MASK32      # -0x61c88647
        out[j] = ct[j] ^ ((state >> 16) & 0xff) ^ (state & 0xff)
    return bytes(out)


lines: list[str] = []
r8_state = 0
for i in range(N):
    length = struct.unpack_from("<H", image, LEN_TBL + 2 * i)[0]
    offset = struct.unpack_from("<H", image, OFF_TBL + 2 * i)[0]
    if length == 0:
        lines.append(f"[{i:03d}] (empty)")
    else:
        ct = image[CT_BASE + offset:CT_BASE + offset + length]
        pt = decrypt(ct, r8_state)
        try:
            text = pt.decode("utf-8")
            lines.append(f"[{i:03d}] len={length:3d}  {text!r}")
        except UnicodeDecodeError:
            lines.append(f"[{i:03d}] len={length:3d}  hex={pt.hex()}")
    r8_state = (r8_state + STATE_STEP) & MASK32

out = data_path("strings.txt")
with open(out, "w") as fh:
    fh.write("\n".join(lines) + "\n")

# Pretty sampling for the console.
print("\n".join(lines[:10]))
print("...")
print("\n".join(lines[120:135]))
print(f"\nWrote {out}  ({len(lines)} strings total)")
