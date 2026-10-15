"""CompletionGate: verify completion claims against receipts. Reads no prose.

v1 changes vs v0:
- Optional run binding: CompletionGate(log, verifier=None, run_id=...).
  When bound, a receipt from a different run evidences nothing -> HOLD
  `wrong_run`. This is the cross-instance replay fix.
- Replay protection keyed on (run_id, seq) and persisted: the gate asks
  the log (log.is_consumed / log.mark_consumed), so a second gate
  instance loading the same persisted log still holds replays. v0 kept
  the consumed set in gate memory only.
- Verification goes through an explicit Verifier (Ed25519 public key by
  default). If omitted, the log's own verifier is used (v0-compat).

Documented semantics (unchanged from v0):
- The *log* must be gap-free (append-only invariant). Claims need valid,
  unconsumed, matching receipts. Selectively claiming a subset of real
  work is legitimate and passes.
"""
from __future__ import annotations

from .receipts import Receipt, ReceiptLog, _digest
from .signers import Verifier


def make_claim(tool_name: str, *args, **kwargs) -> dict:
    """Build a claim dict in the exact args shape the shim records.

    Alternatively pass {"tool_name": ..., "args_hash": ...} directly.
    """
    return {
        "tool_name": tool_name,
        "args": {"args": list(args), "kwargs": dict(kwargs)},
    }


class GateResult:
    """Machine-readable verdict: PASS or HOLD plus counter-evidence."""

    def __init__(self, verdict: str, failures: list[dict]):
        if verdict not in ("PASS", "HOLD"):
            raise ValueError("verdict must be PASS or HOLD")
        self.verdict = verdict
        self.failures = failures

    @property
    def passed(self) -> bool:
        return self.verdict == "PASS"

    def to_dict(self) -> dict:
        return {"verdict": self.verdict, "failures": self.failures}

    def __bool__(self) -> bool:
        return self.passed

    def __repr__(self) -> str:
        return f"GateResult({self.verdict}, {len(self.failures)} failures)"


class CompletionGate:
    """Checks that claimed actions are evidenced by valid, un-replayed receipts."""

    def __init__(self, log: ReceiptLog, verifier: Verifier | None = None,
                 run_id: str | None = None):
        self._log = log
        # Key separation: prefer an explicitly passed verifier (public key
        # only). Fall back to the log's verifier for v0-compat.
        self._verifier = verifier if verifier is not None else log.verifier
        self._run_id = run_id

    def _claim_key(self, claim: dict) -> tuple:
        args_hash = claim.get("args_hash")
        if args_hash is None:
            args_hash = _digest(claim.get("args"))
        return (claim["tool_name"], args_hash)

    def _verify(self, receipt: Receipt) -> bool:
        if not receipt.signature:
            return False
        payload = (receipt.legacy_payload()
                   if self._log.is_legacy(receipt)
                   else receipt.payload())
        return self._verifier.verify(payload, receipt.signature)

    def check(self, claims: list[dict]) -> GateResult:
        failures: list[dict] = []
        if not claims:
            return GateResult("HOLD", [{
                "claim_index": None,
                "reason": "empty_claim",
                "detail": "completion claim lists no actions; nothing evidenced",
            }])

        # Log integrity first: a broken evidence chain poisons everything.
        ok, detail = self._log.check_integrity()
        if not ok:
            return GateResult("HOLD", [{
                "claim_index": None,
                "tool_name": None,
                "reason": "log_gap",
                "detail": f"receipt log is not gap-free ({detail}); "
                          "a receipt may have been deleted",
            }])

        # Index receipts whose signatures verify, by (tool_name, args_hash).
        # When run-bound, only same-run receipts can evidence claims.
        index: dict[tuple, list[Receipt]] = {}
        other_run_index: dict[tuple, list[Receipt]] = {}
        for receipt in self._log:
            if not self._verify(receipt):
                continue
            key = (receipt.tool_name, receipt.args_hash)
            if self._run_id is None or receipt.run_id == self._run_id:
                index.setdefault(key, []).append(receipt)
            else:
                other_run_index.setdefault(key, []).append(receipt)

        matched: list[Receipt] = []  # receipts evidencing claims, in claim order
        for i, claim in enumerate(claims):
            try:
                key = self._claim_key(claim)
                tool_name = claim["tool_name"]
            except (KeyError, TypeError, AttributeError):
                failures.append({
                    "claim_index": i,
                    "tool_name": None,
                    "reason": "malformed_claim",
                    "detail": "claim must be a dict with tool_name and args (or args_hash)",
                })
                continue
            candidates = [r for r in index.get(key, []) if r not in matched]
            if not candidates:
                if key in other_run_index:
                    failures.append({
                        "claim_index": i,
                        "tool_name": tool_name,
                        "reason": "wrong_run",
                        "detail": (
                            f"a receipt matches tool+args but belongs to run "
                            f"{other_run_index[key][0].run_id!r}, not "
                            f"{self._run_id!r}: a receipt from another run "
                            "evidences nothing here"
                        ),
                    })
                    continue
                # Distinguish "nothing like this happened" from "evidence tampered".
                tampered_exists = any(
                    (r.tool_name, r.args_hash) == key and r not in matched
                    for r in self._log
                )
                failures.append({
                    "claim_index": i,
                    "tool_name": tool_name,
                    "reason": "bad_signature" if tampered_exists else "no_receipt",
                    "detail": (
                        "a receipt matches tool+args but its signature is invalid"
                        if tampered_exists else
                        "no receipt in the log matches tool_name+args_hash"
                    ),
                })
                continue
            matched.append(candidates[0])

        # Replay: no receipt may evidence two claims. Consumed state lives
        # in the log (persisted), keyed on (run_id, seq).
        if not failures:
            for receipt in matched:
                if self._log.is_consumed(receipt.run_id, receipt.seq):
                    failures.append({
                        "claim_index": None,
                        "tool_name": receipt.tool_name,
                        "reason": "replayed",
                        "detail": f"receipt seq {receipt.seq} (run "
                                  f"{receipt.run_id!r}) was already consumed "
                                  "by an earlier check",
                    })

        if failures:
            return GateResult("HOLD", failures)
        for receipt in matched:
            self._log.mark_consumed(receipt.run_id, receipt.seq)
        return GateResult("PASS", [])
