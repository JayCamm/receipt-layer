"""LangGraph integration (soft import — langchain is NOT a dependency).

`@wrap_tool_call` middleware is LangGraph's purpose-built seat for
cross-cutting concerns (the docs name caching, logging, retries,
validation); receipts belong in it. One decorator covers every tool
call in a `create_agent`-built agent.

Usage:
    from receipt_layer import ReceiptLog, Ed25519Signer
    from receipt_layer.integrations.langgraph import (
        make_receipt_middleware, make_gate_hook,
    )

    signer = Ed25519Signer.generate()
    log = ReceiptLog(signer, "receipts.jsonl", default_run_id="run-1")
    mw = make_receipt_middleware(log, run_id="run-1")
    agent = create_agent(model, tools, middleware=[mw])

    # Gate adapter: claim_fn builds the explicit claim list from state.
    # (v1 stays out of claim-from-prose extraction by design.)
    hook = make_gate_hook(gate, lambda state: [...])
"""
from __future__ import annotations


def _norm_args(tool_call: dict) -> dict:
    """Normalize a LangGraph tool_call's args to the claim shape.

    LangGraph tool_call["args"] is the tool's kwargs dict; we record it
    as {"args": [], "kwargs": {...}} so gate.make_claim(tool, **kwargs)
    matches what the middleware recorded.
    """
    return {"args": [], "kwargs": dict(tool_call.get("args") or {})}


def make_receipt_middleware(log, run_id: str | None = None, *, name: str = "receipt_middleware"):
    """Build a @wrap_tool_call middleware issuing a signed receipt per call.

    Every tool invocation appends a receipt (tool_name, args_hash,
    result_hash) to `log`, bound to `run_id`. Failed calls are recorded
    as evidence (result={"error": ...}) and the exception is re-raised,
    matching the stdlib shim's behavior.
    """
    try:
        from langchain.agents.middleware import wrap_tool_call
    except ImportError as exc:
        raise ImportError(
            "receipt_layer LangGraph integration needs the 'langchain' "
            "package: pip install langchain"
        ) from exc

    @wrap_tool_call(name=name)
    def _middleware(request, handler):
        tc = request.tool_call
        tool_name = tc["name"]
        try:
            response = handler(request)
        except Exception as exc:
            log.issue(
                tool_name, _norm_args(tc),
                {"error": type(exc).__name__, "message": str(exc)},
                run_id=run_id,
            )
            raise
        content = getattr(response, "content", None)
        status = getattr(response, "status", "ok")
        log.issue(
            tool_name, _norm_args(tc),
            {"ok": status != "error", "result": content},
            run_id=run_id,
        )
        return response

    return _middleware


def make_gate_hook(gate, claim_fn):
    """After-agent-style hook: build claims from state, run the gate.

    claim_fn(state) -> list of claim dicts (see gate.make_claim).
    Returns a hook(state) -> GateResult. Wire it wherever a completion
    decision is made (e.g. after the agent loop, before reporting done).
    v1 deliberately does not extract claims from prose.
    """
    def hook(state):
        return gate.check(claim_fn(state))
    return hook
