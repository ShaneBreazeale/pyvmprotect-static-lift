#!/usr/bin/env python3
"""Step 5 (bonus) — Disassemble the VM bytecode.

Reads the bytecode from data/bc.bin and the opcode classification from
data/opcodes.json, then prints a block-by-block disassembly using the
23-entry basic-block table at RVA 0x4a5e0 inside the image.
"""
from __future__ import annotations

import json
import os
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _common import data_path, load_image

with open(data_path("bc.bin"), "rb") as fh:
    bc = fh.read()
with open(data_path("opcodes.json")) as fh:
    ops = json.load(fh)

# Basic-block table (23 entries, each 8 bytes: offset, block-tag)
_pe, image = load_image()
BB_TABLE = 0x4a5e0
block_starts = [struct.unpack_from("<II", image, BB_TABLE + i * 8)[0]
                for i in range(23)]
block_tags   = [struct.unpack_from("<II", image, BB_TABLE + i * 8)[1]
                for i in range(23)]
block_starts.append(len(bc))

# Manual size hints for jump-family opcodes.  The classifier spots most
# operand sizes automatically but jump handlers write to pc without an
# intermediate LEA, so we patch the known ones here.
MANUAL = {
    "0xd1": 3,  "0x9c": 3,  "0x9d": 3,  "0x46": 3,
    "0x8b": 3,  "0xe0": 3,
}
for k, n in MANUAL.items():
    if k in ops and ops[k]["opsz"] != n:
        ops[k]["opsz"] = n

def dec_u24(b: bytes, o: int) -> int:
    return b[o] | (b[o + 1] << 8) | (b[o + 2] << 16)

out_lines: list[str] = []
for i in range(23):
    start, end = block_starts[i], block_starts[i + 1]
    out_lines.append(
        f"\n=== Block {i:2d}  pc={start:#06x}..{end:#06x}  tag={block_tags[i]:#010x} ===")
    pc = start
    while pc < end:
        op = bc[pc]
        info = ops.get(f"0x{op:02x}", {"name": f"UNK_{op:02x}", "opsz": 0})
        opsz = info["opsz"]
        if pc + 1 + opsz > end:
            opsz = 0
        operand = 0
        if   opsz == 1: operand = bc[pc + 1]
        elif opsz == 2: operand = struct.unpack_from("<H", bc, pc + 1)[0]
        elif opsz == 3: operand = dec_u24(bc, pc + 1)
        elif opsz == 4: operand = struct.unpack_from("<I", bc, pc + 1)[0]
        operand_s = f"{operand:#08x}" if opsz else ""
        out_lines.append(f"  {pc:#06x}  {op:02x}  {operand_s:>10s}  {info['name']}")
        pc += 1 + opsz

text = "\n".join(out_lines).lstrip("\n")
out = data_path("dis.txt")
with open(out, "w") as fh:
    fh.write(text + "\n")

print(text)
print(f"\nWrote {out}")
