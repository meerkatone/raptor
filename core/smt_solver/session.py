"""Solver construction with a default timeout.

The harness caps solver queries at 5 s by default so a pathological
encoding from one finding can't stall an entire validation pass. Override
per-call via ``new_solver(timeout_ms=...)``.
"""
from __future__ import annotations

from contextlib import contextmanager
from typing import Any, Iterator

from .availability import z3

DEFAULT_TIMEOUT_MS = 5000

# Z3 stores the timeout as an unsigned 32-bit value internally;
# anything larger silently wraps. Cap at 2^31 - 1 ms (~24.8 days)
# which is comfortably bigger than any sane cap and safely below
# the wraparound boundary on every Z3 build.
_MAX_TIMEOUT_MS = 2 ** 31 - 1


def new_solver(timeout_ms: int = DEFAULT_TIMEOUT_MS) -> Any:
    """Return a fresh ``z3.Solver()`` with the given timeout applied.

    Caller-supplied ``timeout_ms`` is clamped to ``[1, _MAX_TIMEOUT_MS]``.

    Pre-fix:
      * `timeout_ms=0` was forwarded verbatim. Z3 interprets `timeout=0`
        as "no timeout" — exactly the OPPOSITE of what a caller passing
        0 (intent: "fail immediately") expects. A zero-timeout query
        then ran to completion, blowing the harness's 5s overall budget
        on a single pathological encoding.
      * Negative values: Z3 silently coerces via unsigned cast so
        `timeout_ms=-1` became 4294967295 (~49 days) — effectively
        no timeout, same harm.
      * Values > 2^32 ms: wrap around to small numbers (4_294_967_300
        becomes 4 ms).

    Clamp to a sensible range so each of those pathological inputs
    becomes a usable per-call timeout.
    """
    if timeout_ms < 1:
        timeout_ms = 1
    elif timeout_ms > _MAX_TIMEOUT_MS:
        timeout_ms = _MAX_TIMEOUT_MS
    s = z3.Solver()
    s.set("timeout", timeout_ms)
    return s


@contextmanager
def scoped(solver: Any) -> Iterator[Any]:
    """Push an assertion scope on ``solver`` for the duration of the block.

    On exit (normal or exception), pops the scope — assertions added
    inside are removed, assertions from before remain. Lets domain
    encoders try hypothesis constraints and roll back cheaply without
    discarding the surrounding solver state.
    """
    solver.push()
    try:
        yield solver
    finally:
        solver.pop()
