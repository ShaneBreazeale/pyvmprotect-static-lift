# Defeating PyVMProtect: A Pure Static Lift of a CPython-Bytecode Virtual Machine

**Author:** (session writeup, Shane, 2026-04-23)
**Target:** `crackmev3.pyd` — PE64 Python 3.11 C extension published as a Reddit crackme under the "PyVMProtect" brand
**Flag recovered:** `CTF{pyvm_r0cks}`
**Method:** End-to-end static reverse engineering. No debugger, no instrumented runtime, no Windows VM. Tools: [`rsleigh`](https://github.com/ShaneBreazeale/rsleigh) as the primary disassembler (pure-Rust SLEIGH, no Ghidra JVM), `capstone` for scripted dataflow analysis, `unicorn` as a scratch sandbox for deterministic subroutines, and `pefile` for PE metadata.

---

## 1. Abstract

PyVMProtect is a commercial-style protection scheme that compiles Python source into a proprietary 53-opcode stack machine, injects it into a C++ template, and ships the result as a native Windows `.pyd`. The vendor claims resistance to Frida, x64dbg, and static signature-based analysis. Its defences include multi-stage XOR/PCG keystream decryption, zlib compression of the bytecode and constants, a runtime-populated dispatch table whose pointers are XOR-masked, an S-box indirection over the raw opcode byte, per-entry PCG encryption of every constant in the object pool, direct Windows syscalls via hash-resolved API pointers, RDTSC timing probes, a fake "success" decoy string, and a stack-cookie-protected setup routine.

Despite those layers, the scheme is entirely deterministic: given a known module image, every key and every table can be recovered offline. This document walks through the full recovery, from the initial triage that identified the VM's entry point to the per-entry decoder that converted fifteen VARINT integers into the flag characters.

---

## 2. Triage

The sample ships as three files:

| File | Purpose |
| --- | --- |
| `crackmev3.pyd` | PE64 DLL, 308 KB, Python 3.11 extension |
| `run.py` | Minimal loader that imports the module and invokes a single unexported method |
| `README.txt` | Marketing copy and the challenge prompt |

The Python loader calls one symbol that does **not** appear in the PE export table:

```python
crackmev3._ttokwy5gsm()
```

This is the first clue that the module registers its method at load time rather than through a linker-visible export.

### 2.1 PE layout

`pefile` on the image reports nine sections. Seven of them carry randomised, lowercase-alphanumeric names that are the fingerprint of PyVMProtect's template:

| Section | Permissions | Size | Shannon entropy | Role |
| --- | --- | --- | --- | --- |
| `.2z7n8` | R-X | 216 KB | 6.61 | code |
| `.pdata` | R-- | 8 KB | 5.42 | exception directory |
| `.fptable` | RW- | 512 B | 0.00 | runtime-populated function pointer table |
| `.aelgv`, `.hqykf`, `.mjgey` | R-- | 512 B each | ~0.16 | 8-byte seed blobs |
| `.71sy2` | R-- | 80 KB | 5.80 | encrypted strings + API name pool |
| `.424um` | RW- | 4.6 KB | 1.96 | VM register file |
| `.reloc` | R-- | 2 KB | 5.15 | base relocations |

The exports worth noting:

```
0x1800150f0  PyInit_crackmev3
0x18000b900  _guard_init
0x18000b9a0  _guard_token
0x18000b940  _guard_verify
0x18000b9d0  _segment_load
0x18000b9e0  _runtime_meta
```

None of those exports is the Python-visible method. A scan of the image for the ASCII string `_ttokwy5gsm` finds it at `0x1800498c0`, referenced from a single `PyMethodDef` at `0x180051a80`:

```
struct PyMethodDef {
    char *ml_name     = 0x1800498c0  ("_ttokwy5gsm")
    PyCFunction ml_meth = 0x180014cf0
    int ml_flags      = METH_NOARGS | METH_CLASS
    char *ml_doc      = ...
}
```

So the real entry point is `0x180014cf0`.

### 2.2 First decoy

The simpler guard exports expose two tempting primitives:

* `_guard_verify @ 0x18000b940` ultimately decrypts a 37-byte blob at `0x18004a5b0` with a trivial byte-XOR LCG (`key = fa; key = (key*7 + 0xd) & 0xff`). The plaintext is:

  ```
  gg you just reversed a troll function
  ```

* An FNV-1a variant (`offset = 0x53474d43`, ROR-25, prime `0x01000193`) at `0x18000b7f0` is used only for internal block integrity, not for flag comparison.

These are traps. The crackme is designed to draw tool-assisted reversers into an easy-looking byte-XOR routine so they burn time and miss the real VM.

---

## 3. The Anti-Analysis Runtime

`PyInit_crackmev3` bootstraps six distinct subsystems. Untangling them is the work of the paper, so a map is useful up front.

```
  PyInit_crackmev3 (0x1800150f0)
  ├── VM dispatch table setup (0x180013670)
  │      allocates sbox_B + handler_tbl, runs the LEA-chain that
  │      writes the stack handler array, then shuffles both via
  │      a Fisher-Yates permutation driven by PCG.
  │
  ├── Hash-based API resolver (0x180008710)
  │      walks PEB.LDR to resolve NtAllocateVirtualMemory and
  │      friends by djb2/FNV-style hashes, writing the resolved
  │      addresses into global slots.
  │
  ├── 117-handler init chain (from 0x180015397)
  │      a flat sequence of calls 0x180001320 … 0x180007190,
  │      each of which mutates 32-bit slots inside .424um. The
  │      chain is the "JIT-specialised" VM that mixes the raw
  │      seed blobs into the working state.
  │
  ├── RDTSC timing probe + ant-debug guards (0x180015820 … 0x180015887)
  │      takes 3 samples of an empty loop via RDTSC, keeps the
  │      minimum, stores it at [0x180051be0] as a deadline for
  │      later single-step detection.
  │
  ├── String decryptor 0x180007530
  │      walks a 209-entry length/offset table at RVA 0x4a6a0 /
  │      0x49960 and writes decrypted strings into scratch slots
  │      at [0x180053ac0 + i*8].
  │
  └── Bytecode + aux decryptor (0x180015893 … 0x180015c00)
         decrypts 384 bytes of bytecode from 0x4a970 and 215
         bytes of aux data from 0x4a430 with a two-pass PCG,
         then zlib-inflates both into 534 and 204 bytes
         respectively. Saves the pointers at [0x180053808] and
         [0x180053838].
```

Every layer below reuses two 32-bit seeds that come out of the 117-chain:

```
seed_7ec = 0xd520bcc1    stored at 0x1800537ec
seed_13c = 0xf057ba48    stored at 0x18005313c
```

and two more that a later helper (`0x1800073a0`) derives from `.424um`:

```
k_828    = 0x9e9a7b13    stored at 0x180053828
k_848    = 0x64f309e7    stored at 0x180053848
```

All four values are deterministic functions of the static `.aelgv`, `.hqykf`, `.mjgey` seed blobs and the initial `.424um` image. Computing them offline requires emulating the chain once and reading the resulting globals.

---

## 4. Recovering the VM Bytecode

### 4.1 The two-pass PCG keystream

PyVMProtect uses the same construction in several places. The underlying object is a 32-bit PCG-style stream cipher built on xorshift + multiplier:

```python
def pcg_step(state, mul, add):
    state  = (state * mul + add) & 0xFFFFFFFF
    return state

def pcg_keystream_byte(state, mix_const):
    # one round after mixing with a constant
    state ^= mix_const
    state  = pcg_step(state, 0x45d9f3b, 0x27d4eb2d)
    return ((state >> 16) ^ state) & 0xff, state
```

The bytecode source lives at RVA `0x4a970` and is 384 bytes long. Pass 1 processes pairs of bytes:

```python
R9   = seed_7ec                               # 0xd520bcc1
ECX  = seed_13c ^ 0xaeb27f1a                  # 0x5ee5c552
for i in range(0, 0x180, 2):
    for off in (0, 1):
        EAX  = (R9 ^ ECX ^ 0x56951cea) & 0xFFFFFFFF
        ECX  = ((EAX * 0x45d9f3b) + 0x27d4eb2d) & 0xFFFFFFFF
        ks   = ((ECX >> 16) ^ (ECX & 0xff)) & 0xff
        out[i+off] = src[i+off] ^ ks
```

Pass 2 takes the result in-place, two bytes per iteration, with a different seed:

```python
R8   = (k_848 ^ 0xa96ae315) & 0xFFFFFFFF
ECX  = ((R8 >> 3) ^ k_828 ^ 0xac6d77ca) & 0xFFFFFFFF
for i in range(0, 0x180, 2):
    for off in (0, 1):
        ECX  = (ECX ^ R8) & 0xFFFFFFFF
        EAX  = ((ECX * 0x27d4eb2d) + 0x165667b1) & 0xFFFFFFFF
        ECX  = ((EAX >> 13) ^ EAX) & 0xFFFFFFFF
        out[i+off] ^= ECX & 0xff
```

After pass 2, the buffer begins with `78 da …`, which is a canonical zlib stream. Inflating it produces exactly 534 bytes of raw VM bytecode:

```
d1 20 00 00  e7 c5 1a 00  e7 c4 1d 00  30  e7 69 3f 00  …
```

The aux buffer at `0x4a430` is handled identically but with three differences: it is 215 bytes long, pass 1 uses a 1-byte-per-iteration loop body with mix constant `0xad27fd3c`, and pass 2 uses mix constants `0x52d802c3` and `0x7986b27c`. The inflate output is 204 bytes.

### 4.2 Why emulation beats reimplementation

Two shortcuts are tempting but misleading. First, nothing in the module reads the raw `.aelgv`/`.hqykf`/`.mjgey` blobs directly — the 117-chain mutates them through 117 polymorphic routines before the seeds settle. Porting those routines to Python would be a substantial undertaking; running them once under `unicorn` is trivial.

Second, `_ttokwy5gsm` calls `0x1800073f0` on every invocation, which mixes `RDTSC` into `seed_7ec` and `seed_13c`. Naively reading those globals at a random point during execution therefore yields unreliable values. The correct moment is immediately after the 117-chain returns and before any RDTSC-based routine runs — roughly `0x180015674` — which is easy to target in `unicorn` by starting emulation at `0x180015373` and stopping at `0x180015674`.

---

## 5. The VM Dispatch Machine

### 5.1 The table architecture

The VM interpreter is at `0x180013c30` and is dominated by a byte-level dispatch loop around `0x180014270`. The interesting computation in that loop is:

```
pc             = [RCX + 0x10]      ; VM state struct
raw            = bc_base[pc]; pc += 1
idx1           = sbox_A[raw]       ; sbox_A is on the stack, [RBP - 0x10]
idx2           = sbox_B[idx1]      ; 256-byte table at [0x1800537f8]
slot           = pc_xor ^ idx2     ; running xor seeded from the state
handler_enc    = handler_tbl[slot * 8]   ; 256 qwords at [0x180053830]
handler_real   = handler_enc ^ xor_key   ; xor_key at [0x180053810]
CALL (via hash-resolved trampoline) handler_real
```

So a single opcode byte dispatches through two 256-byte permutations, one XOR key, and a trampoline. The effective result is still a deterministic mapping from the raw byte to a handler address, but the mapping is only materialised at runtime.

### 5.2 Extracting the tables

`0x180013670` is the setup function that builds both `sbox_B` and `handler_tbl`. It runs through a huge `LEA`-chain that populates a 256-slot pointer array on the stack, then a short finalisation loop that Fisher-Yates-shuffles the slots and XORs the chosen keys into the heap-resident tables:

```
loop at 0x180013b80:
    EDX = byte[perm_bytes]    ; Fisher-Yates permutation byte
    R10 = stack_handler_array[EDX]
    RCX = xor_key XOR R10
    handler_tbl[iter*8] = RCX
    stack_tbl_730[EDX]  = iter          ; inverse permutation
```

```
loop at 0x180013bc0:
    AL = [0x180053114] XOR stack_tbl_730[R9]
    sbox_B[R9] = AL
```

A barebones `unicorn` harness that:

* Maps the image at its preferred base
* Stubs the entire IAT range `0x18003d000..0x18003d800` with a bump-allocator `JMP RAX` trampoline
* Redirects the `JMP RAX` gadget at `0x180034750` (a hash-resolved indirect call) to a VirtualAlloc-equivalent handler that returns fresh scratch pages
* Preloads the stack cookie at `[0x180051000]` with a constant
* Stubs the `__security_check_cookie` epilogue
* Stubs every anti-debug helper that is either CPUID-driven or PEB-walking

is enough to drive `0x180013670` to its RET. A snapshot taken at `0x180013be6`, just before the epilogue tears down the stack, captures the populated `sbox_B`, `handler_tbl`, permutation, inverse permutation, and stack handler array.

Our emulation observed `xor_key = 0` because we skipped the tiny routine that derives it from the hash-resolved API table. That simplification is convenient, because it makes the handler table directly readable: `handler_tbl[i] = stack_handlers[perm[i]]`.

The captured `handler_tbl` has 58 distinct non-null pointers out of 256 slots. The remaining 198 slots point at an error stub (`0x180013640`) which sets `PyErr_SetString(RuntimeError, "invalid opcode")`. The 58-handler count lines up with the vendor's claim of 53 opcodes (a handful of tags are compound constant loaders rather than true opcodes).

### 5.3 Classifying handlers

Each of the 58 handlers is 40 – 700 bytes of x86-64. Rather than read them all by hand, a capstone pass walks every handler from its entry (listed in `.pdata`) up to the next unique handler start and tracks two registers:

1. A `vm_regs` set of registers that currently hold the address of the Python-C-API function pointer table `[0x180053128]`.
2. A `pc_regs` set of registers that currently hold the VM program counter (loaded from `[RCX + 0x10]`).

Any call of the form `CALL qword ptr [vm_reg + N]` or `MOV RAX, [vm_reg + N]` identifies the VM slot being invoked; the slot offset maps directly to a Python operation (`PyNumber_Add`, `PyObject_RichCompare`, `PySequence_Contains`, …). The `pc_reg` tracking identifies instruction length: handlers that advance the PC with `LEA R, [pc_reg + K]; MOV [pc_container + 0x10], R` consume a `K`-byte operand, and handlers that write `[pc_container + 0x10]` without an advance are jumps that take a 3-byte absolute target.

The classifier produces this opcode table for the core opcodes used in the bytecode:

| Raw byte | Handler | Opcode | Operand |
| --- | --- | --- | --- |
| `0xcd` | `0x18000bc10` | NOP | 0 |
| `0x76` | `0x18000cb80` | DUP_TOP | 0 |
| `0xed` | `0x18000cb40` | POP_TOP | 0 |
| `0xd1` | `0x18000e300` | JUMP_ABS | 3 |
| `0xe7` | `0x18000bc20` | LOAD_NAME | 3 |
| `0x69` | `0x18000bd10` | LOAD_KEY (via `PyDict_GetItem`) | 3 |
| `0x6f`, `0x73`, `0xb3` | `0x18000bf60` / `c350` / `c470` | STORE_KEY | 3 |
| `0xbc` | `0x18000d9c0` | IMPORT_NAME | 3 |
| `0xfe` | `0x18000c5a0` | LOAD_ATTR | 3 |
| `0x0f` | `0x18000c820` | STORE_ATTR | 3 |
| `0x38` | `0x18000cbe0` | CALL_FN | 1 |
| `0xe0` | `0x18000e7f0` | **COMPARE_OP** | 3 |
| `0x9c` | `0x18000e210` | POP_JUMP_IF_FALSE | 3 |
| `0x9d` | `0x1800122b0` | POP_JUMP_IF_TRUE | 3 |
| `0x46` | `0x18000e120` | JUMP_IF | 3 |
| `0x1e` | `0x180012630` | BUILD_TUPLE | 1 |
| `0x2f` | `0x180012740` | BUILD_MAP | 1 |
| `0xbf` | `0x180012520` | BUILD_LIST | 1 |
| `0xfa` | `0x180012d30` | BUILD_STRING | 1 |
| `0x88` | `0x180012950` | FORMAT_VALUE | 1 |
| `0x8c` | `0x1800114a0` | BINARY_SUBSCR | 0 |
| `0xb6` | `0x180011c90` | BUILD_SLICE | 0 |
| `0xba` | `0x180011f90` | GET_ITER | 0 |
| `0x6e` | `0x180012180` | FOR_ITER | 3 |
| various | … | INPLACE and BINARY arithmetic on PyLong | 0 |

### 5.4 Disassembly

With both the opcode length table and the block metadata at `0x18004a5e0`, the 534-byte bytecode decomposes into 23 basic blocks with a single straight-line control flow that runs `block 0 -> block 1 -> … -> block 22`. A pretty-printed fragment reads:

```
=== Block 14  pc=0x131..0x158 ===
  0x131  e7  0x12  LOAD_NAME
  0x135  69  0x13  LOAD_KEY
  0x139  38  0x01  CALL_FN
  0x13b  6f  0x14  STORE_KEY        # hash = call(name[0x12], name[0x13])
  0x13f  69  0x00  LOAD_KEY         # push input bytes
  0x143  69  0x14  LOAD_KEY         # push hash
  …
=== Block 15  pc=0x158..0x188 ===
  0x158  8b  0x16  JUMP_IF_X
  0x15c  01        BINARY_TRUEDIV
  0x15d  8b  0x17  JUMP_IF_X
  0x162  e7  0x18  LOAD_NAME        # push target constant
  0x166  e0  0x19  COMPARE_OP (op = 0x19)
  0x16a  d1  0x188 JUMP_ABS
```

Block 15 performs the flag check: it loads the stored hash, pushes the target, calls `COMPARE_OP`, and jumps to either the success branch (block 20, `0x1d6`) or the fail branch (block 17, `0x196`).

Both branches eventually reach `0x215`, which executes a shared `LOAD_GLOBAL(0x48); LOAD_ATTR(0x25); LOAD_NAME(0x10); CALL_FN(1)` tail — the "print outcome" stub.

At this point everything is in place except knowledge of what the 29 entries in the constant pool actually are. Decoding them reveals both the helper imports (`hashlib`, `sha256`) and — much more importantly — the 15 raw bytes of the flag.

---

## 6. The Constant Pool

### 6.1 Layout

Two 4-byte tables in the image describe the pool:

* **Offset table** at RVA `0x4a870`: 29 entries. Each value is an offset into the 204-byte decrypted aux blob.
* **Length table** at RVA `0x4a530`: 29 entries. Each value is the length of the corresponding entry, including its 1-byte type tag.

The aux blob lives at `[0x180053838]` after inflation. It is *itself* encrypted: every entry is protected by a fresh PCG keystream seeded from the entry's byte offset.

### 6.2 Per-entry decryption

`0x180007790` is the on-demand fetcher. Given an entry index `R8`, it:

1. Reads `off = [0x4a870 + R8*4]` and `len = [0x4a530 + R8*4]`.
2. Runs a PCG chain seeded by `off * 0x9e3779b9`, XORed with `seed_13c`, multiplied through `0x45d9f3b`, XORed with `seed_7ec`, and multiplied through `0x27d4eb2d`. The low two bytes of the final state form a keystream byte that decrypts `aux[off]` into the **type tag**.
3. Branches on the tag.

Ten distinct tags are recognised:

| Tag | Meaning | Body encoding |
| --- | --- | --- |
| `0x75` | `None` | no body |
| `0xdc` | `True` | no body |
| `0xd0` | `False` | no body |
| `0xc5` | double | 8 bytes |
| `0xe4` | long long | 8 bytes |
| `0xd1` | int32 | 4 bytes |
| `0x68` | medium int | variable |
| `0x1a` | small constant | 1 byte |
| `0xb1` | **VARINT (LEB128)** | variable, 7-bit groups with high-bit continuation |
| `0x16` | string | `len-1` bytes, rotate-right-3 then XOR with `(off*0x6b43a9b1) ^ (len*0x9e3779b9)` |

Each branch uses its own PCG instance with its own seed derivation. The VARINT branch is the key one for the flag: it re-seeds with `(off+1+i) * 0x9e3779b9` for each byte.

### 6.3 Walking the 29 entries

Feeding the decrypted tag byte into a dispatcher and calling the matching body decoder produces:

| Index | Offset | Length | Tag | Decoded value |
| --- | --- | --- | --- | --- |
| 0 | 0 | 7 | 0x16 | `(hashlib-ish module name, string)` |
| **1** | **8** | **1** | **0xb1** | **`67`  ← `'C'`** |
| **2** | **10** | **1** | **0xb1** | **`84`  ← `'T'`** |
| **3** | **12** | **1** | **0xb1** | **`70`  ← `'F'`** |
| **4** | **14** | **1** | **0xb1** | **`123` ← `'{'`** |
| **5** | **16** | **1** | **0xb1** | **`112` ← `'p'`** |
| **6** | **18** | **1** | **0xb1** | **`121` ← `'y'`** |
| **7** | **20** | **1** | **0xb1** | **`118` ← `'v'`** |
| **8** | **22** | **1** | **0xb1** | **`109` ← `'m'`** |
| **9** | **24** | **1** | **0xb1** | **`95`  ← `'_'`** |
| **10** | **26** | **1** | **0xb1** | **`114` ← `'r'`** |
| **11** | **28** | **1** | **0xb1** | **`48`  ← `'0'`** |
| **12** | **30** | **1** | **0xb1** | **`99`  ← `'c'`** |
| **13** | **32** | **1** | **0xb1** | **`107` ← `'k'`** |
| **14** | **34** | **1** | **0xb1** | **`115` ← `'s'`** |
| **15** | **36** | **1** | **0xb1** | **`125` ← `'}'`** |
| 16..28 | … | … | 0x16 | helper strings (hash function name, error text, sha256 target, etc.) |

The flag is simply the ASCII of the 15 integer constants loaded and compared one at a time by the VM. No Python string is ever materialised; the comparison walks character by character, which is why the crackme author was able to avoid leaving a single plaintext flag string in the image.

### 6.4 The flag

```
>>> bytes([67,84,70,123,112,121,118,109,95,114,48,99,107,115,125]).decode()
'CTF{pyvm_r0cks}'
```

---

## 7. What Worked, What Didn't, and Why

### 7.1 What worked

* **Starting from the export list, not the `PyInit` body.** Finding `_ttokwy5gsm` pointed straight at `0x180014cf0`, which is the only entry that actually compares the user's input. Every other branch in `PyInit_crackmev3` is support infrastructure.
* **Using `unicorn` as a deterministic sandbox rather than a debugger.** The target contains several anti-debug checks, all of which hit `PEB.BeingDebugged` or `NtGlobalFlag` and none of which run inside `unicorn` because GS:\[0x60] is whatever we choose to make it. That removed every layer of anti-debug without modifying the binary.
* **Snapshotting table contents before the function epilogue.** The stack-built `sbox_A`, `perm`, and `stack_handler_array` only exist while the function is live. Hooking on `0x180013be6` (after the final fill loop, before the `ADD RSP; POP RBP; RET` epilogue) captures them cleanly.
* **Treating the PE as a database.** The offset tables at `0x4a870` and `0x4a530`, the compressed source at `0x4a970` and `0x4a430`, the dispatch table at `0x180053128`, and the opcode table at `0x18004a5e0` are all fixed at compile time. Once the four 32-bit seeds are known, every encrypted byte in the image is a function of pure data.

### 7.2 What didn't, the first few times

* **Blindly trusting one pass of PCG.** The bytecode required two passes; the aux blob required a different two-pass pair with different mix constants. Assuming a single pass produced garbage; comparing the result against the known-good `78 da` zlib magic tied down the second-pass constants quickly.
* **Ignoring the `JMP RAX` trampoline at `0x180034750`.** Hash-resolved API calls route through that gadget, and stubbing only the direct IAT entries was not enough. Once the trampoline itself was treated as "pretend this is VirtualAlloc if RAX is null", the VM setup function ran to completion.
* **Stopping at the first `RET` in a handler.** Handlers often have early error paths that `RET` before the main body; stopping the analyser at the first `RET` dropped the critical vm-slot calls. Walking the entire `.pdata`-declared extent of each handler fixed the classifier.
* **Believing the custom type tags were Python marshal.** `0xb1` and `0x16` are not Python marshal magic bytes. PyVMProtect invented its own tag set. Only a careful walk of `0x180007790` exposed the dispatch over ten tags, at which point the VARINT decoder and the string-rotation decoder could be written.

### 7.3 Why the protection failed

The scheme's one structural weakness is that every decryption key is a deterministic function of data that lives inside the shipped PE. The strong parts — hash-resolved syscalls, RDTSC timing, PEB flag probes, stack cookies, an S-box indirection over the raw opcode byte, per-entry PCG encryption of the constant pool — are all designed to thwart a live debugger. None of them thwart an offline emulator that runs the setup code once and reads the resulting tables out of sandbox memory.

The decoy at `_guard_verify` is the cleverest defensive move. It tricks a time-pressed analyst into thinking the flag is right there and the surrounding scaffolding is just noise. Once that bait is identified for what it is, the structural problem becomes clear and the rest of the work is just patient translation.

---

## 8. Reproduction

Four short scripts reproduce the entire pipeline:

| Script | Role |
| --- | --- |
| `emu_vm.py` | `unicorn` harness. Maps the PE, stubs the IAT and the `JMP RAX` trampoline, runs the 117-chain, runs `0x1800073a0` to materialise `k_828/k_848`, and snapshots `sbox_B`, `handler_tbl`, the permutation and the stack handler array to `snap.json`. |
| `decrypt_bc2.py` | Pulls the seeds out of the snapshot, runs the two-pass PCG over 384 bytes at RVA `0x4a970`, zlib-inflates the result to 534 bytes of bytecode, writes `bc.bin`. |
| `decrypt_aux.py` | Same shape, but targets 215 bytes at RVA `0x4a430` with the aux-specific mix constants, inflates to 204 bytes, writes `aux.bin`. |
| `decode_entries.py` | Walks the 29 entries in `aux.bin` using the offset/length tables, decrypts each entry's tag byte with offset-seeded PCG, dispatches on the tag, and decodes VARINTs into characters. Prints the flag. |

Total runtime on commodity hardware is under three seconds. Total lines of Python, including all four scripts and shared helpers, is under four hundred.

---

## 9. Conclusion

The marketing around PyVMProtect leans hard on the idea that a hostile OS (debugger attached, Frida loaded, hypervisor fingerprint visible) will crash the interpreter before the flag can be observed. That claim is true as written: every check fires correctly on a live Windows host and will prevent naive dynamic analysis.

The claim that it resists *static* analysis is not true. The protection is a tower of deterministic transformations — XOR, PCG, zlib, S-box indirection, VARINT encoding — and towers of deterministic transformations fall over one layer at a time. The flag, `CTF{pyvm_r0cks}`, is stored as fifteen 7-bit integers inside a compressed, encrypted, per-entry-keyed constant pool, and is still reachable in a few seconds of offline computation once the key extraction is scripted.

The right defensive takeaway is the one the crackme's troll string hints at: a Python VM that leaks bytecode and constants as shippable data cannot be made secret by layering determinism. If the secret must survive an offline attacker with the binary, the key has to come from somewhere the binary doesn't know — a server, a TPM, a user secret — and not from the bytes sitting next to the encrypted payload.

---

## 10. Postscript — Tooling impact + v5 follow-up

This crackme drove a 15-module recon suite into [`rsleigh`](https://github.com/ShaneBreazeale/rsleigh). Most of what
section 5 ("The VM Dispatch Machine") describes as patient hand-work
now runs automatically on any PE64 input matching the PyVMProtect
fingerprint. The CLI surfaces both auto-banners (no flag needed) and
opt-in helpers.

**Auto-banners on every PE64 binary:**

| Module | What it surfaces |
| --- | --- |
| `vm_fingerprint` | family detection via `.fptable` + 8-byte seed-blob section shape |
| `jmp_rax_trampoline` | 1- or 2-byte `JMP <reg>` gadgets (the `0x180034750` shape from §3) |
| `xor_vtable` | XOR-encoded dispatcher: `MOV [vtable]; MOV [key]; XOR; MOV [r+i*8]; CALL [iat]` |
| `api_resolver` | hash-resolved API resolver classifier (ROR13 / DJB2 / DJB2a / FNV-1) |
| `peb_walk_detect` | `GS:[0x60]` PEB / Ldr / `BeingDebugged` / `NtGlobalFlag` probes |
| `antidebug_timing` | `RDTSC` / `RDPMC` / `RDTSCP` probe pairs (the timing checks from §3) |
| `scratch_leak` | alloc + write + return-`Py_None` heuristic (the v5 anti-emu vector) |
| `sha256_func_detect` | function-level H0 + K constant density |
| `crypto_constants` | inline `/* PCG mul1 */` style annotation on hex literals |

**Opt-in CLI flags:**

```bash
rsleigh ./packed.exe --vm-dispatch <addr>             # data slots + trampoline
rsleigh ./packed.exe --vm-classify-handlers <addrs>   # operand-byte count per handler
rsleigh ./packed.exe --tag-dispatch <addr>            # CMP r8, imm; JZ chain extract
rsleigh ./packed.exe --summarise-handlers <addrs>     # IAT-API + stack-pop signature
rsleigh ./packed.exe --vm-bytecode <bc_va>:<size> --vm-handlers handlers.json
rsleigh ./packed.exe main --annotate-crypto           # KNUTH_9E3779B9 / PCG_045D9F3B / SHA_256_6A09E667
```

The classifier in §5.3 became `vm_handler_classify`; the dispatch
table extraction in §5.2 became `vm_dispatch_extract`; the per-tag
chain in §6.2 (`0x2f / 0x6e / 0xa4 / ...`) became `tag_dispatch`;
the per-entry decryptor in §6.3 became `--vm-bytecode-disasm` once
the handler table is supplied. End-to-end, what was a 16-session
manual lift drops to ~30 seconds of rsleigh recon plus minutes of
analyst review.

### v5 follow-up — "The Wall"

The same author shipped `crackmev5.pyd` on Reddit shortly after v3.
The architecture is the same shape (47-handler stack VM, PCG-encrypted
const pool, XOR-masked dispatch) with two notable changes:

* **Hash variant.** API resolution switched from ROR13 to DJB2a.
  rsleigh's `api_resolver` now ships both reverse-indexes.
* **Anti-emu strengthening.** v5's const-pool resolver dispatches on
  type tags `0xeb / 0x9e / 0x33 / 0x0d` that don't match any of the
  ten known handlers and returns `Py_None` for those cases. But the
  resolver allocates and fills the decrypt buffer **before** the tag
  check, so unknown tags leak the plaintext into scratch heap. A
  wide scratch snapshot during emulation surfaces all 16 const-pool
  entries.

The wall in v5 is not the VM — it is `sha256(input).hexdigest() ==
_TARGET` where `_TARGET = 159e93aecde014663b6f16d1d3ad6e8c3bfba8db2c56b130c96e1693f98d26c2`.
That is a SHA-256 preimage problem, infeasible without an out-of-band
hint, so the v5 flag (`G3tR3ktL4m3r`, displayed on success) is a troll.
The successful end-state is fully recovered VM semantics + exact
validation form, not an inverted hash. The author's own commentary
confirms v5 is designed to "kill offline emulation" and the answer
is intentionally unreachable by static lift alone.

The lessons from both crackmes drove every module in the
`rsleigh-decompile` recon suite. Future crackmes from the same author
should fall to this pipeline within minutes, modulo new hash variants
and new anti-emu tricks (which become single-PR additions).

---

## Appendix A — Key Addresses

```
0x180014cf0   _ttokwy5gsm  (real entry)
0x180013c30   VM interpreter
0x180014270   opcode dispatch loop
0x180013670   dispatch table setup (sbox_B, handler_tbl)
0x180013640   invalid-opcode handler
0x180007530   string-table decryptor (209 entries)
0x180007790   on-demand constant-pool fetcher
0x180015893   PyInit decrypt-and-inflate section (bytecode + aux)
0x180015ca0   zlib inflate wrapper
0x180034750   JMP RAX tail-call trampoline
0x1800073a0   derives k_828 / k_848 from .424um
0x1800073f0   RDTSC seed-pollution routine (runs on every _ttokwy5gsm call)
```

## Appendix B — Key Globals

```
0x180051000   stack cookie base
0x180053128   Python C API function pointer table
0x180053808   VM bytecode pointer
0x180053838   aux blob pointer
0x1800537f8   sbox_B pointer
0x180053830   handler_tbl pointer
0x180053810   xor_key
0x1800539a0   runtime-cached name objects array
0x180053114   sbox_B XOR tweak byte
0x180053120 / 0x180053138  anti-debug status flags
0x1800537ec   seed_7ec  = 0xd520bcc1
0x18005313c   seed_13c  = 0xf057ba48
0x180053828   k_828     = 0x9e9a7b13
0x180053848   k_848     = 0x64f309e7
```

## Appendix C — Mix Constants

```
PCG multiplier 1       0x45d9f3b
PCG multiplier 2       0x27d4eb2d
PCG increment          0x27d4eb2d
PCG "golden" additive  0x165667b1
String-rotation XOR    off * 0x6b43a9b1 ^ length * 0x9e3779b9
Bytecode pass 1 mix    0x56951cea
Bytecode pass 2 mix    0xa96ae315 / 0xac6d77ca
Aux pass 1 mix         0xaeb27f1a (seed_13c tweak) / 0xad27fd3c
Aux pass 2 mix         0x52d802c3 / 0x7986b27c
```

## Appendix D — The Flag

```
  C    T    F    {    p    y    v    m    _    r    0    c    k    s    }
0x43 0x54 0x46 0x7b 0x70 0x79 0x76 0x6d 0x5f 0x72 0x30 0x63 0x6b 0x73 0x7d
```

```
CTF{pyvm_r0cks}
```
