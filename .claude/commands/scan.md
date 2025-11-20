# RAPTOR Code Scanner

**Sanity check:** If input doesn't look like local source code, STOP and tell user the correct tool.
- /scan is for: Local directories, source code
- Not for: URLs (use /web) or binaries (use /fuzz)

Run: `python3 raptor.py scan --repo <path>`
