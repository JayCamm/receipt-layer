# receipt-layer v1 — design (draft, 2026-10-15)

**Goal:** close the two deployment gaps named in the README: (1) key management — the
secret holder can forge; (2) cross-instance replay. Plus the one framework integration
that turns the library into something a team would actually deploy.

**Not in scope:** claim extraction from natural prose (README gap 7 stands — the gate
verifies calls happened, not that results support conclusions). v1 wires the gate to an
explicit claim list; a framework `after_agent` hook adapter takes the claim list from a
caller-supplied function. Natural-language claim extraction is the next research step,
not this one.

---

## 1. Key separation: Ed25519 signer/verifier split

**Threat model (honest):** v0's HMAC is fine when signer and verifier share a trust
domain (both run in the operator's backend; the agent LLM only ever sees receipt
strings, never the secret). It breaks when verification must be public or the key must
cross a trust boundary. v1 makes asymmetric the default because a team deploying agents
is exactly that case.

- **Signer** holds the Ed25519 private key. It lives in the tool-execution layer — the
  framework middleware that issues receipts. The agent (LLM) never touches it.
- **Verifier** holds only the public key. The `CompletionGate` verifies with the public
  key; forging would require the private key.
- **Implementation, zero-dependency:** vendor a compact pure-Python Ed25519 module
  (~150–200 lines, standard reference construction, SHA-512 based) as
  `receipt_layer/_ed25519.py`. Pure-Python signing ~50ms, verification ~100–200ms per
  op — acceptable at agent tool-call frequency; measured and documented in tests.
- **Escape hatch:** define a small `Signer`/`Verifier` protocol. Ship `HMACSigner`
  (v0 behavior, single-trust-domain mode) and `Ed25519Signer`; any backend
  implementing the interface (e.g. `cryptography`, `nacl` for production speed) can be
  injected. HMAC mode stays for the single-process case and for v0 log compatibility.

## 2. run_id binding + persistent replay state

- `Receipt` gains `run_id: str`, covered by the signature (v1 log format versioned;
  v0 logs verify in HMAC-compat mode only).
- `ReceiptLog.issue(tool_name, args, result, run_id=...)`.
- `CompletionGate(log, public_key, run_id=...)`:
  - receipts with a different `run_id` → HOLD, reason `wrong_run` (this is the
    cross-instance replay fix: a receipt from run A evidences nothing in run B);
  - replay protection keyed on `(run_id, seq)` and persisted to the JSONL log, so a
    second gate instance on the same log still holds replays (v0's in-memory consumed
    set did not).

## 3. Framework integration: LangGraph first

**Choice:** LangGraph's `@wrap_tool_call` middleware (`langchain.agents.middleware`) is
the purpose-built seat for cross-cutting concerns — the docs name exactly this class
(caching, logging, retries, validation); receipts belong in it. One decorator covers
every tool call in a `create_agent`-built agent. (OpenAI Agents SDK is the designed
second adapter: `RunHooks.on_tool_start/on_tool_end` for issuance plus an
`OutputGuardrail` for the gate — async-only, straightforward, not built in v1.)

- New module `receipt_layer/integrations/langgraph.py`, **soft import** (no hard
  dependency on langgraph):
  ```python
  @wrap_tool_call
  def receipt_middleware(request, handler):
      response = handler(request)
      log.issue(request.tool_call["name"], request.tool_call["args"],
                <result from response>, run_id=run_id)
      return response
  ```
  Attach: `create_agent(model, tools, middleware=[receipt_middleware(log, run_id=...)])`.
- Gate adapter: an `after_agent`-style hook taking `claim_fn(state) -> list[claim]`,
  running `gate.check(claim_fn(state))`. Claim construction stays caller-supplied.
- **Test without an LLM:** drive tool calls through a `ToolNode` with the middleware
  attached directly (no model invocation needed). Every call issues a valid
  Ed25519-signed receipt; `gate.check` over claims built from the executed calls
  → PASS; a forged claim → HOLD.

## 4. Frozen v1 acceptance (written before implementation)

- **V1 — signatures:** RFC 8032 test vectors pass for the vendored Ed25519 module;
  receipt signed under key A fails verification under key B; A1/A2/A3 regression
  still green in both HMAC and Ed25519 modes.
- **V2 — run binding:** receipt issued under run_id "a", presented to a gate bound to
  run_id "b" → HOLD `wrong_run`; same receipt checked by a *second* gate instance on
  the same persisted log → HOLD `replayed`.
- **V3 — LangGraph:** N tool calls through a middleware-wrapped `ToolNode` all issue
  valid Ed25519 receipts with correct tool_name/args_hash; gate over the executed
  calls → PASS; one injected forged claim → HOLD.
- **V4 — honest boundary documented:** no prose claim extraction shipped; README
  updated with the v1 threat model, the perf numbers, and the remaining gap.

## 5. Open questions for Justin (one-word decisions)

1. LangGraph first — yes, or name a different framework?
2. Ship Ed25519 as default with HMAC compat mode — or HMAC-only with process
   separation documented?
3. Scope check: v1 stays out of claim-from-prose extraction. Agree?
