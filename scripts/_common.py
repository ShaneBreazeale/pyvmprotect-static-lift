"""Shared constants and helpers for the PyVMProtect static-lift pipeline.

Every path in this pipeline is expressed relative to the repository root, so
the scripts can be invoked from any working directory.
"""
from __future__ import annotations

import os
import struct

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), os.pardir))
BINARY = os.path.join(ROOT, "crackmev3.pyd")
DATA = os.path.join(ROOT, "data")

# Image base and known RVAs ---------------------------------------------------
IMAGE_BASE = 0x180000000

# Encrypted source blobs inside .71sy2
BYTECODE_SRC_RVA = 0x4a970       # 0x180 bytes, two-pass PCG + zlib -> 534 B bytecode
AUX_SRC_RVA      = 0x4a430       # 0xd7 bytes, two-pass PCG + zlib -> 204 B aux

# 29-entry constant-pool index
AUX_OFFSET_TABLE_RVA = 0x4a870   # dword per entry, offset into aux blob
AUX_LENGTH_TABLE_RVA = 0x4a530   # dword per entry, includes the 1-byte tag

# Globals populated at runtime (absolute VAs)
G_SEED_7EC       = 0x1800537ec   # PCG seed 1 (set by 0x180007260)
G_SEED_13C       = 0x18005313c   # PCG seed 2
G_K_828          = 0x180053828   # aux / bytecode pass-2 seed
G_K_848          = 0x180053848   # aux / bytecode pass-2 seed
G_SBOX_B_PTR     = 0x1800537f8   # 256-byte S-box (alloc'd in 0x180013670)
G_HANDLER_TBL    = 0x180053830   # 256 x qword handler pointers
G_XOR_KEY        = 0x180053810   # XOR mask applied to handler pointers
G_BC_PTR         = 0x180053808   # decrypted bytecode buffer
G_AUX_PTR        = 0x180053838   # decrypted aux blob buffer

# Key functions (absolute VAs)
FN_PYINIT        = 0x1800150f0
FN_REAL_ENTRY    = 0x180014cf0   # _ttokwy5gsm
FN_VM            = 0x180013c30   # VM interpreter
FN_VM_LOOP       = 0x180014270   # dispatch loop head
FN_VM_SETUP      = 0x180013670   # builds sbox_B + handler_tbl
FN_DEFAULT_HDLR  = 0x180013640   # "invalid opcode" stub
FN_NAME_DECRYPT  = 0x180007790   # on-demand constant-pool fetcher
FN_SEED_CHAIN    = 0x180015373   # start of 117-handler init chain in PyInit
FN_SEED_CHAIN_END = 0x180015674  # end of chain, seeds settled
FN_K828_K848     = 0x1800073a0   # derives k_828/k_848 from .424um
FN_PYINIT_DECRYPT = 0x180015893  # bytecode + aux decrypt section
FN_PYINIT_DECRYPT_END = 0x180015c00
FN_COOKIE_CHECK  = 0x180018d40
TRAMP_JMP_RAX    = 0x180034750
TRAMP_JMP_RAX_2  = 0x180034770

# Mixing constants discovered during analysis
MASK32 = 0xFFFFFFFF
NEG_GOLDEN = 0x9e3779b9          # == -0x61c88647 in 32-bit two's complement
PCG_MUL_A = 0x45d9f3b
PCG_ADD_A = 0x27d4eb2d
PCG_MUL_B = 0x27d4eb2d
PCG_ADD_B = 0x165667b1

BC_PASS1_SEED_TWEAK = 0xaeb27f1a   # XOR on seed_13c for bytecode pass 1
BC_PASS1_MIX        = 0x56951cea
BC_PASS2_K848_TWEAK = 0xa96ae315   # XOR on k_848 for bytecode pass 2
BC_PASS2_MIX        = 0xac6d77ca

AUX_PASS1_SEED_TWEAK = 0x787b5c5c  # XOR on seed_13c for aux pass 1
AUX_PASS1_MIX        = 0xad27fd3c
AUX_PASS2_K848_TWEAK = 0x52d802c3  # XOR on k_848 for aux pass 2
AUX_PASS2_MIX        = 0x7986b27c

STRING_ROT_MIX       = 0x6b43a9b1  # offset multiplier for 0x16 string tag


def ensure_data_dir() -> None:
    os.makedirs(DATA, exist_ok=True)


def data_path(name: str) -> str:
    return os.path.join(DATA, name)


def load_image() -> tuple["pefile.PE", bytes]:
    import pefile
    pe = pefile.PE(BINARY)
    return pe, bytes(pe.get_memory_mapped_image())


def read_u32(image: bytes, rva: int) -> int:
    return struct.unpack_from("<I", image, rva)[0]


def rva(va: int) -> int:
    return va - IMAGE_BASE
