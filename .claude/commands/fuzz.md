# RAPTOR Binary Fuzzer

**Sanity check:** If input doesn't look like binary executable, STOP and tell user the correct tool.
- /fuzz is for: Binary executables
- Not for: URLs (use /web) or source code (use /scan)

Run: `python3 raptor.py fuzz --binary <path> --duration <seconds>`
