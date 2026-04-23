# PyVMProtect Static Lift — `crackmev3.pyd`

Full static reverse-engineering of a PyVMProtect-obfuscated Python crackme. Recovers the flag `CTF{pyvm_r0cks}` from the binary in under three seconds without a debugger, instrumented runtime, or Windows VM.

See [`WHITEPAPER.md`](WHITEPAPER.md) for the complete technical writeup.

## Target

`crackmev3.pyd` — PE64 Python 3.11 C extension. A Reddit crackme released under the "PyVMProtect" brand that compiles Python source into a proprietary 53-opcode stack machine. Ships with:

- Two-pass PCG keystream + zlib compression on bytecode and aux blob
- Runtime-populated dispatch table with XOR-masked handler pointers
- S-box indirection over the raw opcode byte
- Per-entry PCG encryption of every constant pool entry
- Direct Windows syscalls via hash-resolved API pointers
- RDTSC timing probes, PEB-based debugger detection, stack cookies
- A fake "success" decoy string to burn the time of casual reversers

None of those defences work against an offline emulator that runs the setup code once and reads the resulting tables out of sandbox memory.

## Quick start

```bash
pip install -r requirements.txt
./solve.sh
```

Expected tail of output:

```
FLAG: CTF{pyvm_r0cks}
```

## Pipeline

| Step | Script | Purpose |
| --- | --- | --- |
| 0 | `scripts/00_emu_snapshot.py` | Unicorn harness. Runs init chain + setup routine; snapshots `sbox_B`, `handler_tbl`, permutation tables, seed values. Writes `data/snap.json`. |
| 1 | `scripts/01_decrypt_bytecode.py` | Two-pass PCG + zlib inflate on 384 bytes at RVA `0x4a970`. Writes `data/bc.bin` (534 bytes of VM bytecode). |
| 2 | `scripts/02_decrypt_aux.py` | Two-pass PCG + zlib inflate on 215 bytes at RVA `0x4a430`. Writes `data/aux.bin` (204 bytes of encrypted constant pool). |
| 3 | `scripts/03_decode_entries.py` | Walks the 29-entry constant pool, per-entry PCG decryption, VARINT / string dispatch. **Prints the flag.** |
| 4 (bonus) | `scripts/04_classify_opcodes.py` | Classifies all 58 VM handler functions via capstone dataflow. Writes `data/opcodes.json`. |
| 5 (bonus) | `scripts/05_disassemble.py` | Disassembles `bc.bin` into 23 basic blocks using the classified opcodes. |
| bonus | `scripts/bonus_decrypt_strings.py` | Decrypts the 209 anti-debug strings (tool names, VM vendor strings, etc.) to show what the runtime is fingerprinting. |

## Artifacts produced

- `data/snap.json` — runtime state captured from the VM setup routine
- `data/bc.bin` — 534 bytes of VM bytecode
- `data/aux.bin` — 204 bytes of encrypted constant pool
- `data/opcodes.json` — opcode → handler classification table
- `data/dis.txt` — human-readable disassembly of the bytecode
- `data/strings.txt` — decrypted anti-debug string pool

## Requirements

- Python ≥ 3.9
- `pefile`, `unicorn`, `capstone` (see `requirements.txt`)
- No Windows, no debugger, no network

## Repository layout

```
.
├── README.md
├── WHITEPAPER.md              full technical writeup
├── requirements.txt
├── solve.sh                   runs steps 0..3 end to end
├── crackmev3.pyd              target binary (Windows PE64)
├── run.py                     vendor's Python loader (not needed for static lift)
├── README.txt                 vendor's challenge prompt
├── scripts/
│   ├── 00_emu_snapshot.py
│   ├── 01_decrypt_bytecode.py
│   ├── 02_decrypt_aux.py
│   ├── 03_decode_entries.py
│   ├── 04_classify_opcodes.py
│   ├── 05_disassemble.py
│   └── bonus_decrypt_strings.py
└── data/                      artifacts land here (gitignored except .gitkeep)
```

## License

MIT. The target binary is the original author's. Scripts are provided for educational reverse-engineering research.
