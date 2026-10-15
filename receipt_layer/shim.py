"""Thin wrapper: wrap callables so every call issues a signed receipt.

This is the integration point — an agent framework wraps its tools once
and gets receipts for free.
"""
from __future__ import annotations

import functools

from .receipts import ReceiptLog


def wrap(fn, log: ReceiptLog, tool_name: str | None = None,
         run_id: str | None = None):
    """Wrap fn so each invocation appends a signed receipt to log.

    The recorded args shape is {"args": [...], "kwargs": {...}} — build
    claims with gate.make_claim(tool_name, *args, **kwargs) to match it.
    Failed calls are recorded as evidence (result={"error": ...}) and the
    exception is re-raised. run_id binds issued receipts to one agent run.
    """
    name = tool_name or getattr(fn, "__name__", "tool")

    @functools.wraps(fn)
    def wrapper(*args, **kwargs):
        call = {"args": list(args), "kwargs": dict(kwargs)}
        try:
            result = fn(*args, **kwargs)
        except Exception as exc:
            log.issue(name, call, {"error": type(exc).__name__,
                                   "message": str(exc)}, run_id=run_id)
            raise
        log.issue(name, call, {"ok": True, "result": result}, run_id=run_id)
        return result

    return wrapper
