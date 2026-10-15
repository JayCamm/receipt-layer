"""Frozen v1 acceptance tests for receipt-layer v1.

V1: RFC 8032 vectors pass; cross-key rejection; A1/A2/A3 regression in both modes.
V2: run_id binding (wrong_run); cross-instance replay via persisted markers.
V3: LangGraph middleware integration (no LLM; middleware driven directly).
V4: README documents v1 threat model, perf numbers, remaining gaps (manual).

Run:  python tests/test_v1.py      (also runs under pytest)
V3 needs langchain installed; it skips gracefully without it.
"""
import os
import sys
import tempfile
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from receipt_layer import (  # noqa: E402
    ReceiptLog, CompletionGate, make_claim,
    Ed25519Signer, Ed25519Verifier, HMACSigner,
)
from receipt_layer.receipts import _digest  # noqa: E402


def _ed_log(path=None, run_id=None):
    signer = Ed25519Signer.generate()
    return signer, ReceiptLog(signer, path, default_run_id=run_id)


# ---------------------------------------------------------------- V1 ---
def test_V1_signatures():
    # RFC 8032 section 7.1 vectors (also asserted here, not just in /tmp).
    from receipt_layer import _ed25519 as e
    vectors = [
        ("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
         "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
         "",
         "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155"
         "5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"),
        ("4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
         "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
         "72",
         "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da"
         "085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00"),
        ("c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7",
         "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025",
         "af82",
         "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac"
         "18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a"),
    ]
    for i, (seed_h, pub_h, msg_h, sig_h) in enumerate(vectors, 1):
        sk, pk = bytes.fromhex(seed_h), bytes.fromhex(pub_h)
        m, sig = bytes.fromhex(msg_h), bytes.fromhex(sig_h)
        assert e.publickey(sk) == pk, f"RFC8032 v{i}: pubkey"
        assert e.signature(m, sk, pk) == sig, f"RFC8032 v{i}: sig"
        assert e.checkvalid(sig, m, pk), f"RFC8032 v{i}: verify"
    print("V1: RFC 8032 3/3 vectors pass")

    # Cross-key: receipt signed under key A fails verification under key B.
    a = Ed25519Signer.generate()
    b = Ed25519Signer.generate()
    log_a = ReceiptLog(a)
    r = log_a.issue("t", {"args": [1], "kwargs": {}}, "ok")
    assert log_a.verify(r) is True
    assert b.verifier.verify(r.payload(), r.signature) is False
    # And the gate with B's verifier holds a claim evidenced only by A's receipt.
    log_b = ReceiptLog(b)
    log_b._receipts.append(r)
    gate_b = CompletionGate(log_b, verifier=b.verifier)
    res = gate_b.check([{"tool_name": "t", "args_hash": r.args_hash}])
    assert res.verdict == "HOLD", f"V1 cross-key: {res.to_dict()}"
    assert res.failures[0]["reason"] == "bad_signature"
    print("V1: cross-key rejection OK (gate HOLD bad_signature)")

    # A1/A2/A3 regression in both modes is asserted by test_harness.py;
    # spot-check one of each here so V1 is self-contained.
    import subprocess
    out = subprocess.run(
        [sys.executable, "tests/test_harness.py"], capture_output=True, text=True,
        cwd=os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        timeout=600,
    )
    assert "ALL ACCEPTANCE TESTS PASSED (hmac + ed25519)" in out.stdout, out.stdout[-500:]
    print("V1: A1/A2/A3 regression green in hmac + ed25519 modes")


# ---------------------------------------------------------------- V2 ---
def test_V2_run_binding():
    signer = Ed25519Signer.generate()

    # Gate bound to a different run: the receipt evidences nothing here.
    log = ReceiptLog(signer, default_run_id="a")
    log.issue("search", {"args": ["x"], "kwargs": {}}, "ok")  # run_id="a"
    gate_b = CompletionGate(log, verifier=signer.verifier, run_id="b")
    res = gate_b.check([make_claim("search", "x")])
    assert res.verdict == "HOLD", f"V2 wrong_run: {res.to_dict()}"
    assert res.failures[0]["reason"] == "wrong_run", res.failures

    # Unbound gate (v0 behavior): passes regardless of run. Fresh log so
    # nothing is consumed yet (consumed state is per-log in v1).
    log2 = ReceiptLog(signer, default_run_id="a")
    log2.issue("search", {"args": ["x"], "kwargs": {}}, "ok")
    gate_free = CompletionGate(log2, verifier=signer.verifier)
    assert gate_free.check([make_claim("search", "x")]).passed

    # Same run: passes (and consumes).
    gate_a = CompletionGate(log, verifier=signer.verifier, run_id="a")
    assert gate_a.check([make_claim("search", "x")]).passed
    print("V2: wrong_run HOLD + unbound PASS + same-run PASS")


def test_V2_cross_instance_replay():
    with tempfile.TemporaryDirectory() as tmp:
        path = os.path.join(tmp, "log.jsonl")
        signer = Ed25519Signer.generate()

        # Instance 1: issue, check (PASS consumes + persists marker).
        log1 = ReceiptLog(signer, path, default_run_id="r")
        log1.issue("a", {"args": [1], "kwargs": {}}, "ok")
        gate1 = CompletionGate(log1, verifier=signer.verifier, run_id="r")
        assert gate1.check([make_claim("a", 1)]).passed

        # Instance 2: fresh objects, same persisted log.
        log2 = ReceiptLog(signer, path, default_run_id="r")
        assert len(log2) == 1  # receipts reloaded
        gate2 = CompletionGate(log2, verifier=signer.verifier, run_id="r")
        res = gate2.check([make_claim("a", 1)])
        assert res.verdict == "HOLD", f"V2 replay: {res.to_dict()}"
        assert res.failures[0]["reason"] == "replayed", res.failures
    print("V2: second gate instance on persisted log HOLD replayed")

    # Tampered consumed-marker is refused at load (not silently dropped).
    with tempfile.TemporaryDirectory() as tmp:
        path = os.path.join(tmp, "log.jsonl")
        signer = Ed25519Signer.generate()
        log1 = ReceiptLog(signer, path, default_run_id="r")
        log1.issue("a", {"args": [1], "kwargs": {}}, "ok")
        CompletionGate(log1, verifier=signer.verifier, run_id="r").check(
            [make_claim("a", 1)])
        with open(path, encoding="utf-8") as f:
            lines = f.readlines()
        import json
        assert any(json.loads(l).get("_marker") == "consumed" for l in lines)
        # Flip the marker signature.
        out = []
        for l in lines:
            d = json.loads(l)
            if d.get("_marker") == "consumed":
                d["sig"] = ("0" if d["sig"][0] != "0" else "1") + d["sig"][1:]
            out.append(json.dumps(d) + "\n")
        with open(path, "w", encoding="utf-8") as f:
            f.writelines(out)
        try:
            ReceiptLog(signer, path, default_run_id="r")
        except ValueError:
            pass
        else:
            raise AssertionError("V2: tampered consumed-marker loaded without error")
    print("V2: tampered consumed-marker refused at load")


# ---------------------------------------------------------------- V3 ---
def test_V3_langgraph():
    try:
        from langchain.agents.middleware import wrap_tool_call  # noqa
        from langgraph.prebuilt.tool_node import ToolCallRequest
        from langchain_core.tools import tool
        from langchain_core.messages import ToolMessage
    except ImportError:
        print("V3: SKIPPED (langchain not installed)")
        return

    from receipt_layer.integrations.langgraph import (
        make_receipt_middleware, make_gate_hook,
    )

    signer = Ed25519Signer.generate()
    log = ReceiptLog(signer, default_run_id="lg-run")
    mw = make_receipt_middleware(log, run_id="lg-run")

    @tool
    def search(q: str) -> str:
        """Search for q."""
        return "result:" + q

    @tool
    def fetch(url: str) -> str:
        """Fetch a URL."""
        return "page:" + url

    tools = {"search": search, "fetch": fetch}
    queries = [("search", {"q": "a"}), ("fetch", {"url": "u1"}), ("search", {"q": "b"})]

    for i, (tname, targs) in enumerate(queries):
        req = ToolCallRequest(
            tool_call={"name": tname, "args": targs, "id": f"call-{i}",
                       "type": "tool_call"},
            tool=tools[tname],
            state={},
            runtime=None,
        )

        def handler(r, _tools=tools):
            t = _tools[r.tool_call["name"]]
            out = t.invoke(r.tool_call["args"])
            return ToolMessage(content=str(out),
                               tool_call_id=r.tool_call["id"],
                               name=r.tool_call["name"])

        resp = mw.wrap_tool_call(req, handler)
        assert isinstance(resp, ToolMessage), type(resp)

    # Every call issued a valid Ed25519 receipt with correct fields.
    assert len(log) == 3, len(log)
    for r, (tname, targs) in zip(log, queries):
        assert r.tool_name == tname, (r.tool_name, tname)
        assert r.alg == "ed25519", r.alg
        assert r.run_id == "lg-run", r.run_id
        assert r.args_hash == _digest({"args": [], "kwargs": targs}), "args_hash"
        assert log.verify(r), "signature"

    # Gate over the executed calls -> PASS.
    gate = CompletionGate(log, verifier=signer.verifier, run_id="lg-run")
    claims = [make_claim(tname, **targs) for tname, targs in queries]
    res = gate.check(claims)
    assert res.passed, f"V3 gate: {res.to_dict()}"

    # One forged claim -> HOLD.
    res2 = gate.check([make_claim("search", q="zzz")])
    assert res2.verdict == "HOLD"

    # Gate hook adapter: claim_fn(state) -> GateResult.
    hook = make_gate_hook(gate, lambda state: [make_claim("search", q="a")])
    # (fresh log/gate for the hook so nothing is consumed)
    signer2 = Ed25519Signer.generate()
    log2 = ReceiptLog(signer2, default_run_id="x")
    log2.issue("search", {"args": [], "kwargs": {"q": "a"}}, "ok")
    gate2 = CompletionGate(log2, verifier=signer2.verifier, run_id="x")
    hook2 = make_gate_hook(gate2, lambda state: [make_claim("search", q="a")])
    assert hook2({}).passed
    print("V3: 3 tool calls via middleware -> valid Ed25519 receipts; "
          "gate PASS; forged claim HOLD; hook adapter OK")


# ---------------------------------------------------------------- V4 ---
def test_V4_readme_documents_v1():
    readme = open(os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        "README.md"), encoding="utf-8").read()
    for needle in ("threat model", "Ed25519", "run_id", "wrong_run",
                   "replayed", "claim-from-prose", "perf"):
        assert needle.lower() in readme.lower(), f"V4: README missing {needle!r}"
    print("V4: README documents threat model, perf, and the prose boundary")


def _perf():
    signer = Ed25519Signer.generate()
    payload = b"x" * 200
    t0 = time.perf_counter()
    sigs = [signer.sign(payload) for _ in range(20)]
    t1 = time.perf_counter()
    v = signer.verifier
    oks = [v.verify(payload, s) for s in sigs]
    t2 = time.perf_counter()
    assert all(oks)
    sign_ms = (t1 - t0) / 20 * 1000
    verify_ms = (t2 - t1) / 20 * 1000
    print(f"PERF: Ed25519 pure-python sign {sign_ms:.1f} ms/op, "
          f"verify {verify_ms:.1f} ms/op (20 ops each)")
    return sign_ms, verify_ms


if __name__ == "__main__":
    test_V1_signatures()
    test_V2_run_binding()
    test_V2_cross_instance_replay()
    test_V3_langgraph()
    test_V4_readme_documents_v1()
    _perf()
    print("ALL V1 ACCEPTANCE TESTS PASSED")
