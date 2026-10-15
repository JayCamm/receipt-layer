"""Signed, tamper-evident receipts for tool calls. Standard library only.

v1 changes vs v0:
- Receipts carry `alg` (signature algorithm) and `run_id`, both covered by
  the signature. v0 log lines (no `alg` key) still verify in HMAC-compat
  mode against the legacy payload.
- Replay protection is persisted: on a passing check the gate appends
  signed "consumed" markers to the JSONL log, so a second gate instance
  loading the same log still holds replays. v0's in-memory-only set did not.
"""
from __future__ import annotations

import dataclasses
import hashlib
import json
import os
import time
from dataclasses import dataclass

from .signers import HMACSigner, Signer, Verifier


def _canonical(obj) -> bytes:
    """Deterministic byte serialization for hashing/signing."""
    try:
        return json.dumps(
            obj, sort_keys=True, separators=(",", ":"),
            ensure_ascii=True, default=str,
        ).encode("utf-8")
    except (TypeError, ValueError):
        return repr(obj).encode("utf-8")


def _digest(obj) -> str:
    return hashlib.sha256(_canonical(obj)).hexdigest()


@dataclass(frozen=True)
class Receipt:
    """Evidence that one tool call happened.

    The signature covers every other field, including `alg` and `run_id`:
    flipping any byte invalidates it. `run_id` binds the receipt to one
    agent run — a receipt from run A evidences nothing in run B.
    """
    tool_name: str
    args_hash: str
    result_hash: str
    timestamp: float
    seq: int
    signature: str = ""
    run_id: str = ""
    alg: str = "hmac-sha256"

    def payload(self) -> bytes:
        return _canonical({
            "alg": self.alg,
            "tool_name": self.tool_name,
            "args_hash": self.args_hash,
            "result_hash": self.result_hash,
            "timestamp": self.timestamp,
            "seq": self.seq,
            "run_id": self.run_id,
        })

    def legacy_payload(self) -> bytes:
        """v0 payload shape (no alg/run_id), for verifying old log lines."""
        return _canonical({
            "tool_name": self.tool_name,
            "args_hash": self.args_hash,
            "result_hash": self.result_hash,
            "timestamp": self.timestamp,
            "seq": self.seq,
        })

    def signed(self, signature: str) -> "Receipt":
        return dataclasses.replace(self, signature=signature)


def _marker_payload(run_id: str, seq: int) -> bytes:
    return _canonical({"_marker": "consumed", "run_id": run_id, "seq": seq})


class ReceiptLog:
    """Append-only log of signed receipts, with optional JSONL persistence.

    `signer` is a Signer (or raw HMAC secret bytes for v0-compat). The log
    verifies with `signer.verifier`; for Ed25519 that holds only the public
    key material, so a log opened for verification cannot issue receipts.
    """

    def __init__(self, signer, path: str | None = None,
                 default_run_id: str | None = None):
        if isinstance(signer, (bytes, bytearray)):
            signer = HMACSigner(bytes(signer))
        if not isinstance(signer, Signer):
            raise ValueError("signer must be a Signer (or HMAC secret bytes)")
        self._signer: Signer = signer
        self._receipts: list[Receipt] = []
        self._consumed: set[tuple[str, int]] = set()  # (run_id, seq)
        self._legacy_seqs: set[int] = set()  # seqs of v0-format lines
        self._path = path
        self._default_run_id = default_run_id or ""
        if path and os.path.exists(path):
            self._load()

    @property
    def verifier(self) -> Verifier:
        return self._signer.verifier

    @property
    def alg(self) -> str:
        return self._signer.alg

    def issue(self, tool_name: str, args=None, result=None,
              run_id: str | None = None) -> Receipt:
        """Record one tool call. Returns the signed receipt."""
        unsigned = Receipt(
            tool_name=tool_name,
            args_hash=_digest(args),
            result_hash=_digest(result),
            timestamp=time.time(),
            seq=len(self._receipts) + 1,
            run_id=self._default_run_id if run_id is None else run_id,
            alg=self._signer.alg,
        )
        receipt = unsigned.signed(self._signer.sign(unsigned.payload()))
        self._receipts.append(receipt)
        if self._path:
            with open(self._path, "a", encoding="utf-8") as f:
                f.write(json.dumps(dataclasses.asdict(receipt)) + "\n")
        return receipt

    def verify(self, receipt: Receipt) -> bool:
        """True iff the receipt's signature is valid.

        v0 log lines (no `alg` key in JSON) are verified against the legacy
        payload shape; everything else against the v1 payload.
        """
        if not receipt.signature:
            return False
        payload = (receipt.legacy_payload()
                   if receipt.seq in self._legacy_seqs
                   else receipt.payload())
        return self._signer.verifier.verify(payload, receipt.signature)

    def is_legacy(self, receipt: Receipt) -> bool:
        """True if this receipt came from a v0-format log line."""
        return receipt.seq in self._legacy_seqs

    def mark_consumed(self, run_id: str, seq: int) -> None:
        """Record that receipt (run_id, seq) evidenced a passing check.

        Persisted to the JSONL log as a signed marker so a second gate
        instance loading the same log still holds replays.
        """
        key = (run_id, seq)
        if key in self._consumed:
            return
        self._consumed.add(key)
        if self._path:
            marker = {
                "_marker": "consumed",
                "run_id": run_id,
                "seq": seq,
                "sig": self._signer.sign(_marker_payload(run_id, seq)),
            }
            with open(self._path, "a", encoding="utf-8") as f:
                f.write(json.dumps(marker) + "\n")

    def is_consumed(self, run_id: str, seq: int) -> bool:
        return (run_id, seq) in self._consumed

    def _load(self) -> None:
        assert self._path is not None
        verifier = self._signer.verifier
        with open(self._path, encoding="utf-8") as f:
            for lineno, line in enumerate(f, 1):
                line = line.strip()
                if not line:
                    continue
                data = json.loads(line)
                if data.get("_marker") == "consumed":
                    # Signed replay marker.
                    sig = data.get("sig", "")
                    if not verifier.verify(
                        _marker_payload(data.get("run_id", ""), data.get("seq", 0)),
                        sig,
                    ):
                        raise ValueError(
                            f"receipt log failed verification at line {lineno}: "
                            "consumed-marker signature invalid"
                        )
                    self._consumed.add((data.get("run_id", ""), data.get("seq", 0)))
                    continue
                legacy = "alg" not in data
                receipt = Receipt(**data)
                if legacy:
                    # v0 line: verify against the legacy payload shape.
                    if not receipt.signature or not verifier.verify(
                        receipt.legacy_payload(), receipt.signature
                    ):
                        raise ValueError(
                            f"receipt log failed verification at line {lineno} "
                            f"(seq {data.get('seq')!r}): signature invalid"
                        )
                    self._legacy_seqs.add(receipt.seq)
                elif not self.verify(receipt):
                    raise ValueError(
                        f"receipt log failed verification at line {lineno} "
                        f"(seq {data.get('seq')!r}): signature invalid"
                    )
                self._receipts.append(receipt)
        ok, detail = self.check_integrity()
        if not ok:
            raise ValueError(f"receipt log failed integrity check on load: {detail}")

    def check_integrity(self) -> tuple[bool, str]:
        """The log must be gap-free: receipt seqs exactly 1..N."""
        seqs = sorted(r.seq for r in self._receipts)
        expected = list(range(1, len(seqs) + 1))
        if seqs != expected:
            return False, f"seqs {seqs} are not contiguous 1..{len(seqs)}"
        return True, "ok"

    def __len__(self) -> int:
        return len(self._receipts)

    def __iter__(self):
        return iter(self._receipts)

    def __getitem__(self, i):
        return self._receipts[i]
