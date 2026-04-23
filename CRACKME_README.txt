PyVMProtect: C++ Stack-Machine VM for Python Code Protection

What it does:
Compiles Python code into a proprietary 53-opcode instruction set, injects it into a C++ template, and outputs a native Windows .pyd. Defeats dynamic analysis through direct system calls (bypassing IAT hooking), JIT string decryption on the C-stack, and immediate memory erasure with SecureZeroMemory.

Why it's different:
Nuitka and PyArmor expose strings/logic to the CPython C-API—vulnerable to Frida and x64dbg. PyVMProtect assumes a hostile OS: starves the heap, uses polymorphic randomized opcodes per build, and breaks static signatures entirely.

Who it's for:
Enterprises protecting high-value Python logic (financial algorithms, anti-cheat, SaaS backends). Public beta for security researchers to battle-test.

The Challenge:
Compiled a password-checking script into a .pyd. Extract the hidden flag (CTF{...}) through reverse engineering—guessing doesn't count.


⚠️ WARNING: This .pyd will trigger AV/SmartScreen heuristics (not malware, unsigned). Run only in a sandbox/hypervisor.
Feedback welcome. Post your methodology if you crack it.