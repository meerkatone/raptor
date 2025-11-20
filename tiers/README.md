# RAPTOR Tiers Structure

## Purpose

Organize knowledge and capabilities with progressive disclosure:
- **Core (CLAUDE.md):** Always loaded - decision logic only
- **Personas:** Available on-demand - expert methodologies
- **Specialists:** Reserved for future - custom sub-agents
- **Reference:** Reserved for future - deep dives and detailed guides

---

## Current Structure

```
tiers/
├── personas/                # Expert methodologies (AVAILABLE, not auto-loaded)
│   ├── security_researcher.md   (~500t, load on request)
│   ├── exploit_developer.md     (~400t, load on request)
│   ├── crash_analyst.md         (~450t, load on request)
│   └── README.md
│
├── specialists/             # Sub-agents (RESERVED for future)
│   └── README.md            # Currently: Defer to Python packages/
│
└── reference/               # RESERVED for future deep dives
    └── (empty - add when needed)
```

---

## Usage Pattern

### Personas (Available Now)

**Load explicitly when needed:**
```
"Use security researcher persona to analyze this"
"Exploit developer: create PoC"
"Crash analyst: is this exploitable?"
```

**Token cost:** 0 until invoked, 400-500 when loaded

### Specialists (Future)

**Reserved for custom domain specialists that don't exist in Python:**
- API testing approaches
- Mobile app security
- Cloud infrastructure patterns

**Currently:** All specialists implemented in Python (packages/)
**Check availability:** System can detect Python vs custom specialists

### Reference (Future)

**Reserved for detailed guides:**
- Complete attack methodologies
- Tool orchestration examples
- Failure recovery mappings

**Add when users request deep background knowledge.**

---

## Token Budget

**Current usage:**
- Core (CLAUDE.md): ~800 tokens (always loaded)
- Personas: 0 tokens (load on explicit request only)
- Specialists: 0 tokens (Python handles, or future custom)
- Reference: 0 tokens (empty, reserved)

**Typical session:** 800 tokens (core only)
**With persona:** 800 + 500 = 1,300 tokens (when requested)

**Capacity remaining:** ~2,700 tokens for future expansion

---

## Design Philosophy

**Start minimal:**
- Only CLAUDE.md always loaded
- Everything else on-demand

**Expand when needed:**
- Users ask for methodologies → Personas exist
- Users ask for custom approaches → Add specialists
- Users ask for deep explanations → Add reference files

**Defer to Python:**
- Python already handles execution
- Don't duplicate what exists
- Tiers provide decision-making, not execution

---

## File Naming Conventions

**Personas:** `[role].md` (security_researcher.md, exploit_developer.md)
**Specialists:** `[domain].md` (api_tester.md, mobile_scanner.md)
**Reference:** `[topic].md` (attack_methodologies.md, tool_guide.md)

All lowercase with underscores.
