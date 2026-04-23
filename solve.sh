#!/usr/bin/env bash
# End-to-end solver for the PyVMProtect crackme.
# Runs the four pipeline stages that produce the flag.
set -euo pipefail

cd "$(dirname "$0")"

# Prefer a project-local virtualenv if one exists (e.g. .venv/ created via
# `python3 -m venv .venv && .venv/bin/pip install -r requirements.txt`).
if [ -x ".venv/bin/python" ]; then
    PY=".venv/bin/python"
elif command -v python3 >/dev/null 2>&1; then
    PY="python3"
else
    PY="python"
fi

echo "==> step 0: snapshot runtime state (unicorn)"
"$PY" scripts/00_emu_snapshot.py

echo
echo "==> step 1: decrypt VM bytecode"
"$PY" scripts/01_decrypt_bytecode.py

echo
echo "==> step 2: decrypt aux blob"
"$PY" scripts/02_decrypt_aux.py

echo
echo "==> step 3: decode constant pool + recover flag"
"$PY" scripts/03_decode_entries.py
