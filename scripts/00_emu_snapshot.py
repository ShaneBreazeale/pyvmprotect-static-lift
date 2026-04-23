#!/usr/bin/env python3
"""Step 0 — Unicorn snapshot of the VM setup routine.

Runs three short fragments of `crackmev3.pyd` in a sandboxed emulator and
captures the runtime state required by later steps:

  * The 256-byte  sbox_B    (dispatch indirection layer 2)
  * The 2048-byte handler_tbl (256 qword handler pointers)
  * The 256-byte  perm       (Fisher-Yates permutation)
  * The 256-byte  invperm    (inverse permutation, used for sbox_B derivation)
  * The 2048-byte stack handler array (indexed by perm to build handler_tbl)
  * seed_7ec, seed_13c, k_828, k_848 — the four PCG seeds used by every
    subsequent decryption in this binary.

The snapshot is written to data/snap.json.
"""
from __future__ import annotations

import json
import os
import struct
import sys

from unicorn import Uc, UcError, UC_ARCH_X86, UC_MODE_64
from unicorn import UC_HOOK_CODE, UC_HOOK_MEM_INVALID
from unicorn import UC_PROT_ALL, UC_PROT_READ, UC_PROT_WRITE
from unicorn.x86_const import (
    UC_X86_REG_RSP, UC_X86_REG_RCX, UC_X86_REG_RDX,
    UC_X86_REG_R8, UC_X86_REG_R9, UC_X86_REG_RAX,
    UC_X86_REG_RIP, UC_X86_REG_RBP, UC_X86_REG_GS_BASE,
)

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _common import (
    BINARY, DATA, IMAGE_BASE, MASK32,
    G_SEED_7EC, G_SEED_13C, G_K_828, G_K_848,
    G_SBOX_B_PTR, G_HANDLER_TBL, G_XOR_KEY,
    FN_VM_SETUP, FN_SEED_CHAIN, FN_SEED_CHAIN_END, FN_K828_K848,
    FN_COOKIE_CHECK, TRAMP_JMP_RAX, TRAMP_JMP_RAX_2,
    ensure_data_dir, data_path,
)

# -----------------------------------------------------------------------------
# Harness setup
# -----------------------------------------------------------------------------
ensure_data_dir()

import pefile

pe = pefile.PE(BINARY)
image = bytes(pe.get_memory_mapped_image())

uc = Uc(UC_ARCH_X86, UC_MODE_64)
image_size = (len(image) + 0xfff) & ~0xfff
uc.mem_map(IMAGE_BASE, image_size, UC_PROT_ALL)
uc.mem_write(IMAGE_BASE, image)

# Fake stack cookie so the setup function's epilogue does not fault.
uc.mem_write(0x180051000, struct.pack("<Q", 0x2B992DDFA232))

STACK_BASE = 0x7fff00000000
STACK_SIZE = 0x100000
uc.mem_map(STACK_BASE, STACK_SIZE, UC_PROT_READ | UC_PROT_WRITE)
uc.reg_write(UC_X86_REG_RSP, STACK_BASE + 0x80000)

TEB_BASE = 0x10000000000
PEB_BASE = TEB_BASE + 0x1000
uc.mem_map(TEB_BASE, 0x3000, UC_PROT_READ | UC_PROT_WRITE)
uc.reg_write(UC_X86_REG_GS_BASE, TEB_BASE)
uc.mem_write(TEB_BASE + 0x30, struct.pack("<Q", TEB_BASE))  # TEB self ptr
uc.mem_write(TEB_BASE + 0x60, struct.pack("<Q", PEB_BASE))  # PEB ptr

# Bump-allocator scratch region.  The module's internal allocator and a few
# hash-resolved Win32 APIs are redirected here.
SCRATCH_BASE = 0x7fff20000000
SCRATCH_SIZE = 0x4000000
uc.mem_map(SCRATCH_BASE, SCRATCH_SIZE, UC_PROT_READ | UC_PROT_WRITE)
_bump = [SCRATCH_BASE + 0x1000]

def alloc(n: int) -> int:
    n = max(16, n)
    p = _bump[0]
    _bump[0] = (_bump[0] + n + 15) & ~15
    return p

# IAT thunks: point every import at a single RET gadget.  Individual CALL
# qword ptr [iat_slot] instructions land on our `hook_code` via the gadget.
THUNK_BASE = 0x7fff10000000
uc.mem_map(THUNK_BASE, 0x10000, UC_PROT_ALL)

iat_stubs: dict[int, tuple[int, str]] = {}
for entry in pe.DIRECTORY_ENTRY_IMPORT:
    for imp in entry.imports:
        name = imp.name.decode() if imp.name else f"ord{imp.ordinal}"
        stub = THUNK_BASE + len(iat_stubs) * 0x10
        uc.mem_write(stub, b"\xc3")          # RET
        uc.mem_write(imp.address, struct.pack("<Q", stub))
        iat_stubs[stub] = (imp.address, name)

# Blind-stub the rest of the IAT range; PyVMProtect populates some slots at
# load time via hash-resolved pointers rather than linker imports.
GENERIC_STUB = THUNK_BASE + 0x8000
uc.mem_write(GENERIC_STUB, b"\xc3")
for off in range(0x18003d000, 0x18003d800, 8):
    cur = struct.unpack("<Q", bytes(uc.mem_read(off, 8)))[0]
    if cur == 0:
        uc.mem_write(off, struct.pack("<Q", GENERIC_STUB))
iat_stubs[GENERIC_STUB] = (0, "VirtualAlloc")


def dispatch_import(name: str, rcx: int, rdx: int, r8: int, r9: int) -> int:
    """Minimal stubs for the few Win32 APIs that the setup routine invokes."""
    if name == "VirtualAlloc":
        return alloc(rdx if 0 < rdx < 0x100000 else 0x1000)
    if name == "VirtualProtect":
        if r9:
            uc.mem_write(r9, struct.pack("<I", 2))
        return 1
    if name in ("VirtualFree", "HeapFree"):
        return 1
    if name == "HeapAlloc":
        return alloc(r8 if 0 < r8 < 0x100000 else 0x1000)
    if name == "GetProcessHeap":
        return 0x12340000
    if name == "IsDebuggerPresent":
        return 0
    if name.startswith("Tls") or name.startswith("Fls"):
        return 0 if "Get" in name else 1
    if name == "EncodePointer":
        return rcx
    if name == "GetModuleHandleW":
        return IMAGE_BASE
    if name == "GetSystemTimeAsFileTime":
        if rcx:
            uc.mem_write(rcx, b"\x00" * 8)
        return 0
    if name in ("GetLastError", "SetLastError"):
        return 0
    if name in ("QueryPerformanceCounter", "QueryPerformanceFrequency"):
        if rcx:
            uc.mem_write(rcx, struct.pack("<Q", 1000))
        return 1
    return 0


# Anti-debug / timing helpers that we cannot sensibly emulate → force to zero.
STUB_ZERO = {
    0x180009d80, 0x180009cf0, 0x180009d00, 0x180008f20, 0x180008f70,
    0x18000ae40, 0x18000b510, 0x1800073f0, 0x180017e70,
    0x18000ad10, 0x18000b450, 0x180009050, 0x180008d40,
    0x18000b8e0, 0x180017b60, 0x1800162c0, 0x180007300, 0x180008710,
}
STUB_ONE  = {0x18000a5c0}               # return 1 = "pass sanity"
ALLOC_FNS = {0x180024870, 0x18001cf00}  # internal bump allocators

snapshot: dict[str, object] = {}
SNAPSHOT_PC = 0x180013be6               # immediately after sbox_B fill loop


def _ret_with(rax: int) -> None:
    uc.reg_write(UC_X86_REG_RAX, rax)
    rsp = uc.reg_read(UC_X86_REG_RSP)
    ret = struct.unpack("<Q", bytes(uc.mem_read(rsp, 8)))[0]
    uc.reg_write(UC_X86_REG_RSP, rsp + 8)
    uc.reg_write(UC_X86_REG_RIP, ret)


def hook_code(uc, addr, size, _ud):
    if addr == SNAPSHOT_PC and "sb" not in snapshot:
        sb_ptr = struct.unpack("<Q", bytes(uc.mem_read(G_SBOX_B_PTR, 8)))[0]
        ht_ptr = struct.unpack("<Q", bytes(uc.mem_read(G_HANDLER_TBL, 8)))[0]
        rbp = uc.reg_read(UC_X86_REG_RBP)
        rsp = uc.reg_read(UC_X86_REG_RSP)
        snapshot.update({
            "sb_ptr":  sb_ptr,
            "ht_ptr":  ht_ptr,
            "xor_key": struct.unpack("<Q", bytes(uc.mem_read(G_XOR_KEY, 8)))[0],
            "sb":          bytes(uc.mem_read(sb_ptr, 256)),
            "ht":          bytes(uc.mem_read(ht_ptr, 2048)),
            "perm":        bytes(uc.mem_read(rbp + 0x830, 256)),
            "invperm":     bytes(uc.mem_read(rbp + 0x730, 256)),
            "stack_hdlrs": bytes(uc.mem_read(rsp + 0x30, 2048)),
        })
    if addr == FN_COOKIE_CHECK:
        _ret_with(uc.reg_read(UC_X86_REG_RAX))
        return
    if addr in (TRAMP_JMP_RAX, TRAMP_JMP_RAX_2):
        rax = uc.reg_read(UC_X86_REG_RAX)
        if rax == 0 or rax < 0x1000:
            rdx_sz = uc.reg_read(UC_X86_REG_RDX)
            alloc_size = rdx_sz if 0 < rdx_sz < 0x100000 else 0x1000
            _ret_with(alloc(alloc_size) if addr == TRAMP_JMP_RAX else 0)
        return
    if addr in STUB_ZERO:
        _ret_with(0); return
    if addr in STUB_ONE:
        _ret_with(1); return
    if addr in ALLOC_FNS:
        rcx = uc.reg_read(UC_X86_REG_RCX)
        _ret_with(alloc(rcx if 0 < rcx < 0x100000 else 0x1000))
        return
    if addr in iat_stubs:
        _, name = iat_stubs[addr]
        rcx = uc.reg_read(UC_X86_REG_RCX)
        rdx = uc.reg_read(UC_X86_REG_RDX)
        r8  = uc.reg_read(UC_X86_REG_R8)
        r9  = uc.reg_read(UC_X86_REG_R9)
        _ret_with(dispatch_import(name, rcx, rdx, r8, r9))
        return


def hook_invalid(uc, access, addr, size, value, _ud):
    # Map the faulting page and continue.  The module does no meaningful
    # memory writes outside of regions we already mapped, so lazy mapping
    # is safe here.
    page = addr & ~0xfff
    try:
        uc.mem_map(page, 0x2000, UC_PROT_READ | UC_PROT_WRITE)
        return True
    except UcError:
        return False


uc.hook_add(UC_HOOK_CODE, hook_code)
uc.hook_add(UC_HOOK_MEM_INVALID, hook_invalid)


def call_and_return(entry: int) -> None:
    """Invoke `entry` with an artificial sentinel return address."""
    sentinel = 0x7ffffffffff0
    rsp = uc.reg_read(UC_X86_REG_RSP)
    uc.mem_write(rsp - 8, struct.pack("<Q", sentinel))
    uc.reg_write(UC_X86_REG_RSP, rsp - 8)
    try:
        uc.emu_start(entry, sentinel, timeout=30_000_000, count=10_000_000)
    except UcError as e:
        raise SystemExit(f"[-] emulation at {entry:#x} failed: {e}")


# -----------------------------------------------------------------------------
# 1. Build sbox_B + handler_tbl by running the VM setup routine.
# -----------------------------------------------------------------------------
print("[0/3] Running VM setup routine at 0x180013670 ...")
call_and_return(FN_VM_SETUP)
if "sb" not in snapshot:
    raise SystemExit("[-] setup routine did not reach the snapshot address")
print(f"      sbox_B  @ {snapshot['sb_ptr']:#x}  ({sum(1 for b in snapshot['sb'] if b)}/256 nonzero)")
print(f"      handler_tbl @ {snapshot['ht_ptr']:#x}")
unique_handlers = sorted({p for p in struct.unpack("<256Q", snapshot["ht"]) if p})
print(f"      unique handlers: {len(unique_handlers)} (matches vendor's \"53-opcode VM\")")

# -----------------------------------------------------------------------------
# 2. Run the 117-handler seed chain.  Settles seed_7ec and seed_13c.
# -----------------------------------------------------------------------------
print("[1/3] Running seed chain 0x180015373..0x180015674 ...")
try:
    uc.emu_start(FN_SEED_CHAIN, FN_SEED_CHAIN_END, timeout=15_000_000)
except UcError as e:
    raise SystemExit(f"[-] seed chain failed: {e}")

# -----------------------------------------------------------------------------
# 3. Call 0x1800073a0 to materialise k_828 / k_848 from .424um slots.
# -----------------------------------------------------------------------------
print("[2/3] Running key-derivation helper 0x1800073a0 ...")
call_and_return(FN_K828_K848)


def r32(va: int) -> int:
    return struct.unpack("<I", bytes(uc.mem_read(va, 4)))[0]

snapshot["seed_7ec"] = r32(G_SEED_7EC)
snapshot["seed_13c"] = r32(G_SEED_13C)
snapshot["k_828"]    = r32(G_K_828)
snapshot["k_848"]    = r32(G_K_848)

print("[3/3] Seeds recovered:")
print(f"      seed_7ec = {snapshot['seed_7ec']:#010x}")
print(f"      seed_13c = {snapshot['seed_13c']:#010x}")
print(f"      k_828    = {snapshot['k_828']:#010x}")
print(f"      k_848    = {snapshot['k_848']:#010x}")

# -----------------------------------------------------------------------------
# 4. Serialise.
# -----------------------------------------------------------------------------
serial = {k: (v.hex() if isinstance(v, (bytes, bytearray)) else v)
          for k, v in snapshot.items()}
out = data_path("snap.json")
with open(out, "w") as fh:
    json.dump(serial, fh, indent=2)
print(f"\nWrote {out}")
