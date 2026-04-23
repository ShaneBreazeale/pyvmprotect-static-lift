#!/usr/bin/env python3
"""Step 4 (bonus) — Classify every VM opcode handler.

Each raw opcode byte b is dispatched via:

    idx1   = sbox_A[b]                    # stack-resident identity at load time
    idx2   = sbox_B[idx1]
    slot   = pc_xor ^ idx2
    hdlr   = handler_tbl[slot * 8] ^ xor_key

Rather than reverse the indirection, this script reads the snapshot captured
in step 0 and then walks every unique handler entry point with capstone,
tracking two live-register sets:

  * vm_regs  — registers that currently hold [0x180053128] (a table of
               Python C-API function pointers used by the VM)
  * pc_regs  — registers that currently hold the VM program counter
               (loaded from [RCX+0x10] or similar)

Any `CALL qword [vm_reg + K]` or `MOV r, [vm_reg + K]` maps K to a named
slot (PyNumber_Add, PyObject_RichCompare, etc.).  Any byte read indexed by
`pc_reg` gives the handler's operand size.

Output: data/opcodes.json with {"0xNN": {"name": "COMPARE_OP", "opsz": 3}}.
"""
from __future__ import annotations

import json
import os
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _common import (
    IMAGE_BASE, FN_DEFAULT_HDLR, data_path, load_image,
)

import capstone
from capstone.x86 import X86_OP_MEM, X86_OP_REG, X86_OP_IMM, X86_REG_RIP

pe, image = load_image()
md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
md.detail = True

# sbox_B + handler table were captured in step 0.
with open(data_path("snap.json")) as fh:
    snap = json.load(fh)
sbox_b = bytes.fromhex(snap["sb"])
ht_ptrs = struct.unpack("<256Q", bytes.fromhex(snap["ht"]))

unique_handlers = sorted({p for p in ht_ptrs if p and p != FN_DEFAULT_HDLR})

# Each raw byte maps to a handler via sbox_B[raw].
h_to_ops: dict[int, list[int]] = {}
for raw in range(256):
    h = ht_ptrs[sbox_b[raw]]
    if h == FN_DEFAULT_HDLR:
        continue
    h_to_ops.setdefault(h, []).append(raw)

# ---------- function boundaries --------------------------------------------
for s in pe.sections:
    if s.Name.decode().strip("\x00 ") == ".pdata":
        pdata = s.get_data()
        break

pdata_end: dict[int, int] = {}
for i in range(len(pdata) // 12):
    start_rva, end_rva, _ = struct.unpack_from("<III", pdata, i * 12)
    pdata_end[IMAGE_BASE + start_rva] = IMAGE_BASE + end_rva

handler_end: dict[int, int] = {}
ordered = sorted(unique_handlers)
for i, h in enumerate(ordered):
    bounds = [h + 0x100]
    if h in pdata_end:
        bounds.append(pdata_end[h])
    if i + 1 < len(ordered):
        bounds.append(ordered[i + 1])
    handler_end[h] = min(bounds)

# ---------- dispatch-table slot names --------------------------------------
VM_SLOTS = {
    0x00: "Add",       0x08: "Sub",       0x10: "Mul",       0x18: "TrueDiv",
    0x20: "FloorDiv",  0x28: "Pow",       0x30: "Mod",       0x38: "MatMul",
    0x40: "Lsh",       0x48: "Rsh",       0x50: "And",       0x58: "Or",
    0x60: "Xor",       0x68: "Inv",       0x70: "Neg",       0x78: "GetItem",
    0x80: "Call",      0x88: "Call2",     0x90: "GetAttr",   0x98: "SetAttr",
    0xa0: "GetItem2",  0xa8: "SetItem",   0xb0: "SeqContains", 0xb8: "IsTrue",
    0xc0: "IsInst",    0xc8: "RichCompare", 0xd0: "Format",  0xd8: "GetIter",
    0xe0: "IterNext",  0xe8: "ListNew",   0xf0: "TupleNew",  0xf8: "DictNew",
    0x100: "Str",      0x108: "Repr",     0x110: "Slice",
}

PC_CONTAINER_REGS = {capstone.x86.X86_REG_RCX,
                     capstone.x86.X86_REG_RBX,
                     capstone.x86.X86_REG_RDI}

# ---------- IAT name resolution --------------------------------------------
IAT_NAMES: dict[int, str] = {}
for entry in pe.DIRECTORY_ENTRY_IMPORT:
    for imp in entry.imports:
        if imp.name:
            IAT_NAMES[imp.address] = imp.name.decode()

VM_TABLE_ADDR = 0x180053128


def resolve_abs(ins) -> int | None:
    for op in ins.operands:
        if op.type == X86_OP_MEM and op.mem.base == X86_REG_RIP:
            return ins.address + ins.size + op.mem.disp
    return None


def analyse(h: int) -> dict:
    """Return a feature dict for handler `h`."""
    end = handler_end[h]
    blob = bytes(image[h - IMAGE_BASE:end - IMAGE_BASE])
    info = {
        "iat":         [],
        "vm_slots":    [],
        "pc_adv":      0,     # handler does LEA r, [pc + k]; MOV [pc_container+0x10], r
        "bc_read_max": -1,    # max byte offset read relative to pc
        "pc_write_adv":False,
        "pc_write_jmp":False,
        "cmp":         [],
    }
    vm_regs: set[int] = set()
    pc_regs: set[int] = set()
    adv_regs: set[int] = set()

    for ins in md.disasm(blob, h):
        opstr = ins.op_str.lower()

        # IAT calls
        target = resolve_abs(ins)
        if ins.mnemonic == "call" and target in IAT_NAMES:
            info["iat"].append(IAT_NAMES[target])

        # Track vm_table pointer flow and VM-slot accesses.
        if ins.mnemonic == "mov" and len(ins.operands) == 2:
            dst, src = ins.operands
            # Record VM slot reads before we touch the destination.
            if (src.type == X86_OP_MEM
                    and src.mem.base in vm_regs
                    and src.mem.disp in VM_SLOTS):
                info["vm_slots"].append(VM_SLOTS[src.mem.disp])
            if dst.type == X86_OP_REG:
                d = dst.reg
                vm_regs.discard(d); pc_regs.discard(d); adv_regs.discard(d)
                if src.type == X86_OP_MEM:
                    if resolve_abs(ins) == VM_TABLE_ADDR:
                        vm_regs.add(d)
                    elif src.mem.disp == 0x10 and src.mem.base in PC_CONTAINER_REGS:
                        pc_regs.add(d)
            if dst.type == X86_OP_MEM and src.type == X86_OP_REG:
                if dst.mem.disp == 0x10 and dst.mem.base in PC_CONTAINER_REGS:
                    if src.reg in adv_regs:
                        info["pc_write_adv"] = True
                    else:
                        info["pc_write_jmp"] = True

        if ins.mnemonic == "call" and len(ins.operands) == 1:
            op = ins.operands[0]
            if (op.type == X86_OP_MEM
                    and op.mem.base in vm_regs
                    and op.mem.disp in VM_SLOTS):
                info["vm_slots"].append(VM_SLOTS[op.mem.disp])

        # Byte reads via `byte ptr [pc_reg + K]` or `byte ptr [x + pc_reg + K]`
        for op in ins.operands:
            if op.type == X86_OP_MEM:
                m = op.mem
                if (m.base in pc_regs or m.index in pc_regs):
                    if ins.mnemonic in ("movzx", "movsx", "mov") and 0 <= m.disp <= 8:
                        info["bc_read_max"] = max(info["bc_read_max"], m.disp)

        # LEA r, [pc_reg + K]
        if ins.mnemonic == "lea" and len(ins.operands) == 2:
            dst, src = ins.operands
            if dst.type == X86_OP_REG:
                d = dst.reg
                vm_regs.discard(d); pc_regs.discard(d); adv_regs.discard(d)
                if (src.type == X86_OP_MEM
                        and src.mem.base in pc_regs
                        and 0 < src.mem.disp <= 8):
                    info["pc_adv"] = max(info["pc_adv"], src.mem.disp)
                    adv_regs.add(d)

        if ins.mnemonic == "cmp":
            for op in ins.operands:
                if op.type == X86_OP_IMM and 0 < op.imm < 0x200:
                    info["cmp"].append(op.imm)

    return info


PRIORITY = [
    ("RichCompare", "COMPARE_OP"),
    ("SeqContains", "CONTAINS_OP"),
    ("GetIter",     "GET_ITER"),
    ("IterNext",    "FOR_ITER"),
    ("ListNew",     "BUILD_LIST"),
    ("TupleNew",    "BUILD_TUPLE"),
    ("DictNew",     "BUILD_MAP"),
    ("Str",         "CONV_STR"),
    ("Repr",        "CONV_REPR"),
    ("Slice",       "BUILD_SLICE"),
    ("Format",      "FORMAT_VALUE"),
    ("IsInst",      "IS_INSTANCE"),
    ("IsTrue",      "TO_BOOL"),
    ("Call2",       "CALL_FN_KW"),
    ("Call",        "CALL_FN"),
    ("SetAttr",     "STORE_ATTR"),
    ("GetAttr",     "LOAD_ATTR"),
    ("SetItem",     "STORE_SUBSCR"),
    ("GetItem2",    "BINARY_SUBSCR2"),
    ("GetItem",     "BINARY_SUBSCR"),
    ("TrueDiv",     "BINARY_TRUEDIV"),
    ("FloorDiv",    "BINARY_FLOORDIV"),
    ("Pow",         "BINARY_POW"),
    ("Mod",         "BINARY_MOD"),
    ("MatMul",      "BINARY_MATMUL"),
    ("Lsh",         "BINARY_LSH"),
    ("Rsh",         "BINARY_RSH"),
    ("And",         "BINARY_AND"),
    ("Or",          "BINARY_OR"),
    ("Xor",         "BINARY_XOR"),
    ("Inv",         "UNARY_INV"),
    ("Neg",         "UNARY_NEG"),
    ("Mul",         "BINARY_MUL"),
    ("Sub",         "BINARY_SUB"),
    ("Add",         "BINARY_ADD"),
]


def classify(info, primary: int) -> str:
    slots = list(dict.fromkeys(info["vm_slots"]))
    apis  = info["iat"]
    sz    = info["pc_adv"] if info["pc_adv"] > 0 else (
        info["bc_read_max"] + 1 if info["bc_read_max"] >= 0 else 0)
    for sn, name in PRIORITY:
        if sn in slots:
            return f"{name}({sz})" if sz else name
    if "PyImport_ImportModuleLevel" in apis: return f"IMPORT_NAME({sz})"
    if "PyImport_AddModule"         in apis: return f"IMPORT_FROM({sz})"
    if "PyUnicode_Join"             in apis: return "BUILD_STRING"
    if "PyUnicode_Concat"           in apis: return "STRING_CONCAT"
    if "PyBytes_FromStringAndSize"  in apis: return "LOAD_BYTES"
    if "PyObject_RichCompareBool"   in apis: return f"COMPARE_BOOL({sz})"
    if "PyDict_SetItemString"       in apis: return f"STORE_NAME({sz})"
    if "PyDict_GetItemString"       in apis: return f"LOAD_NAME({sz})"
    if "PyDict_SetItem"             in apis: return f"STORE_KEY({sz})"
    if "PyDict_GetItem"             in apis: return f"LOAD_KEY({sz})"
    if "PyLong_FromLong" in apis or "PyLong_FromLongLong" in apis: return f"LOAD_INT({sz})"
    if "PyFloat_FromDouble"         in apis: return f"LOAD_FLOAT({sz})"
    if "PyList_SetItem"             in apis: return f"LIST_APPEND({sz})"
    if "PyTuple_SetItem"            in apis: return f"TUPLE_SET({sz})"
    # Manual fallbacks for opcodes whose semantics involve XOR-masked handler
    # pointers that this lightweight classifier doesn't track.
    MANUAL_NAMES = {
        0xe7: "LOAD_NAME",
        0x6f: "STORE_GLOBAL",
        0xd1: "JUMP_ABS",
        0x9c: "POP_JUMP_IF_FALSE",
        0x9d: "POP_JUMP_IF_TRUE",
        0x46: "JUMP_IF",
        0xe0: "COMPARE_OP",
        0xcd: "NOP",
        0x76: "DUP_TOP",
        0xed: "POP_TOP",
    }
    if primary in MANUAL_NAMES:
        name = MANUAL_NAMES[primary]
        if sz == 0 and primary in (0xe7, 0x6f, 0xd1, 0x9c, 0x9d, 0x46, 0xe0):
            sz = 3
        return f"{name}({sz})" if sz else name
    return f"UNKNOWN({sz})"


opcode_table: dict[str, dict] = {}
for h in unique_handlers:
    info = analyse(h)
    ops = h_to_ops.get(h, [])
    primary = ops[0] if ops else 0
    name = classify(info, primary)
    sz = info["pc_adv"] if info["pc_adv"] > 0 else (
        info["bc_read_max"] + 1 if info["bc_read_max"] >= 0 else 0)
    for op in ops:
        opcode_table[f"0x{op:02x}"] = {"name": name, "opsz": sz, "handler": f"{h:#x}"}

out = data_path("opcodes.json")
with open(out, "w") as fh:
    json.dump(opcode_table, fh, indent=2, sort_keys=True)

print(f"Classified {len(unique_handlers)} unique handlers over {len(opcode_table)} raw opcodes.")
print(f"Compare op lives at handler 0x18000e7f0 (raw byte 0xe0): "
      f"{opcode_table.get('0xe0', {}).get('name')}")
print(f"\nWrote {out}")
