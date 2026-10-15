# receipt-layer

**Completion-evidence harness ("receipt layer") — v1.**

## The problem

False completion — agents saying "done" when the work never happened — is 45–48% of agent failures (Advani 2026, ~9,876 trajectories). LLM judges detect it at near-chance (AUROC ≤ 0.65) because they read confident closing phrases, not verified state.

## The mechanism

Don't read the prose. Check the receipts.

Every tool call issues a signed receipt (`tool_name`, `args_hash`, `result_hash`, `timestamp`, `seq`, `run_id`) into an append-only log. When the agent claims completion, the `CompletionGate` verifies the claim against the receipts **without reading any prose**:

1. Every claimed action has ≥1 valid receipt with matching `tool_name` + `args_hash`.
2. Every receipt signature verifies under the signer's algorithm (tamper-evident).
3. The log itself is gap-free (append-only invariant): sequence numbers run 1..N with no deletions.
4. No receipt is consumed twice — replay protection keyed on `(run_id, seq)` and **persisted** to the log, so a second gate instance on the same log still holds replays.
5. When the gate is bound to a `run_id`, receipts from any other run evidence nothing (`wrong_run`).

Verdict is `PASS` or `HOLD`, with machine-readable counter-evidence (which claim failed, why).

## Threat model (v1, honest)

**What v1 defends against:**
- The agent's *story* diverging from its *actions* (false "done", selective amnesia, invented tool calls). This is the 45–48% failure class.
- Receipt tampering (any byte flip invalidates the Ed25519/HMAC signature).
- Receipt deletion (gap detection on load and on check).
- Cross-run replay (run_id binding: a receipt from run A evidences nothing in run B).
- Cross-instance replay (consumed markers persisted as signed log lines; a fresh gate on the same log still holds).
- Key compromise of the *verifier*: with Ed25519 (the default), the verifier holds only the public key and cannot forge receipts.

**What v1 does NOT defend against:**
- A compromised tool implementation (garbage in, signed garbage out — the receipt attests the call happened, not that the tool is honest).
- A stolen signer private key (then the attacker can mint receipts; protect the signer as a secret).
- File-level deletion of the log itself (out of scope; use append-only storage).
- Correctness of conclusions (see "Honest boundary" below).

**Key separation:** the Ed25519 private seed lives in the tool-execution layer (framework middleware). The agent LLM only ever sees receipt strings. The `CompletionGate` takes a `Verifier` (public key only). HMAC mode remains for the single-trust-domain case (signer and verifier in the same backend) and for reading v0 logs.

## Layout

```
receipt-layer/
├── pyproject.toml
├── README.md
├── design_v1.md
├── receipt_layer/
│   ├── __init__.py
│   ├── _ed25519.py    # vendored pure-Python Ed25519 (RFC 8032), stdlib only
│   ├── signers.py     # Signer/Verifier protocol; HMACSigner, Ed25519Signer
│   ├── receipts.py    # Receipt v1 (run_id, alg), ReceiptLog (+JSONL, replay markers)
│   ├── gate.py        # CompletionGate (run binding, persisted replay), GateResult
│   ├── shim.py        # wrap(): thin wrapper auto-issuing receipts on every call
│   └── integrations/
│       └── langgraph.py  # @wrap_tool_call middleware + gate hook (soft import)
└── tests/
    ├── test_harness.py  # A1/A2/A3, run in hmac AND ed25519 modes
    └── test_v1.py       # V1–V4 frozen acceptance
```

## Quickstart

```python
from receipt_layer import ReceiptLog, CompletionGate, make_claim, Ed25519Signer

signer = Ed25519Signer.generate()          # private seed stays in the tool layer
log = ReceiptLog(signer, "receipts.jsonl", default_run_id="run-1")

from receipt_layer import wrap
search = wrap(lambda q: f"results for {q}", log, "search", run_id="run-1")
search("grokking")                         # receipt issued automatically

gate = CompletionGate(log, verifier=signer.verifier, run_id="run-1")
result = gate.check([make_claim("search", "grokking")])
print(result.verdict)                      # PASS
print(result.to_dict())                    # machine-readable
```

LangGraph:

```python
from receipt_layer.integrations.langgraph import make_receipt_middleware, make_gate_hook

mw = make_receipt_middleware(log, run_id="run-1")
agent = create_agent(model, tools, middleware=[mw])
# ... run the agent ...
hook = make_gate_hook(gate, lambda state: claims_from(state))
print(hook(state).verdict)                 # PASS or HOLD, no prose read
```

## Frozen acceptance criteria

v0 (written before v0 implementation):
- **A1 — 20 injected false-"done" cases → HOLD on all 20.**
- **A2 — 20 legit completions → PASS on all 20, zero false holds.**
- **A3 — byte-flip tamper → `verify()` False (3/3).**

v1 (from design_v1.md, written before v1 implementation):
- **V1 — signatures:** RFC 8032 §7.1 test vectors 3/3 pass for the vendored Ed25519; receipt signed under key A fails verification under key B (gate HOLD `bad_signature`); A1/A2/A3 regression green in **both** hmac and ed25519 modes.
- **V2 — run binding:** receipt under run_id "a" presented to a gate bound to "b" → HOLD `wrong_run`; same-run → PASS; unbound gate → PASS (v0 behavior); second gate instance on the same persisted log re-checking consumed receipts → HOLD `replayed`; tampered consumed-marker refused at load.
- **V3 — LangGraph:** 3 tool calls through the middleware (no LLM; middleware driven directly) → all valid Ed25519 receipts with correct `tool_name`/`args_hash`/`run_id`; gate over executed calls → PASS; one forged claim → HOLD; `make_gate_hook` adapter returns PASS on a fresh gate.
- **V4 — honest boundary documented** (this README).

## Acceptance results

| Suite | Result |
|---|---|
| A1 (20 false-"done" → HOLD) | **20/20 HOLD** (hmac + ed25519) |
| A2 (20 legit → PASS) | **20/20 PASS, 0 false holds** (hmac + ed25519) |
| A3 (byte-flip tamper) | **3/3 False** (hmac + ed25519) |
| V1 (RFC 8032, cross-key, regression) | **3/3 vectors, cross-key HOLD, regression green** |
| V2 (wrong_run, persisted replay) | **HOLD wrong_run, HOLD replayed (2nd instance), marker tamper refused** |
| V3 (LangGraph middleware) | **3/3 valid receipts, gate PASS, forged HOLD, hook OK** |
| V4 (docs) | **this README** |

Run: `python tests/test_harness.py` then `python tests/test_v1.py` (stdlib only; V3 needs `langchain` installed and skips gracefully without it; also runs under pytest).

## Perf (measured, not estimated)

Vendored pure-Python Ed25519 (this machine, 20 ops each, two runs):

| Op | ms/op |
|---|---|
| sign | ~290–330 |
| verify | ~420–500 |
| HMAC sign (comparison) | ~0.003 |

The design doc estimated ~50/100–200 ms; actuals are ~3–5× slower. At agent tool-call frequency (seconds per call dominated by LLM latency) this is acceptable for v1, but it is the reason the `Signer`/`Verifier` protocol exists: inject `cryptography` or `nacl` backends for production throughput. The pure-Python module is a correctness baseline and a zero-dependency default, not a performance choice.

## Honest boundary (unchanged from v0)

The gate verifies that claimed actions **happened** with the claimed arguments. It does **not** check that a tool's *result* supports the agent's *conclusion* — e.g., calling `search("x")`, getting "no results", and claiming "found the answer" still passes, because the call is evidenced. v1 deliberately stays out of claim-from-prose extraction (Justin decision 2026-10-15): the gate takes explicit claim lists, and the framework hook takes a caller-supplied `claim_fn`. Result-aware claim checking is a different instrument.

## Remaining gaps (honest)

1. **Timestamps not enforced.** Receipts carry timestamps; the gate doesn't check freshness or monotonicity. Clock games out of scope.
2. **No defense against compromised tools.** Signed garbage is still garbage (see threat model).
3. **Log file itself is trusted storage.** Deletion of the whole log, or of consumed-markers by a writer with file access, is out of scope — same trust assumption as v0's file.
4. **OpenAI Agents SDK adapter designed, not built** (see design_v1.md §3).
5. **Pure-Python Ed25519 is slow** (~286/420 ms per op) — inject a native backend for production.
6. **Selective claiming allowed by design.** Claims need valid evidence; they don't need to account for every receipt. What the gate polices is the log's integrity and the claims' evidence, not the shape of the claim.
