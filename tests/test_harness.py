"""Frozen acceptance tests for the receipt layer. Standard library only.

Run:  python tests/test_harness.py      (also runs under pytest)
"""
import dataclasses
import json
import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from receipt_layer import (  # noqa: E402
    Receipt, ReceiptLog, CompletionGate, make_claim, wrap,
)

SECRET = b"test-secret-32-bytes-000000000000"
OTHER_SECRET = b"other-secret-32-bytes-0000000000"

# Backend selection: "hmac" (v0-compat) or "ed25519". The v1 acceptance
# requires A1/A2/A3 green in both modes.
_BACKEND = "hmac"
_ED_KEYS = {}  # mode -> (signer, other_signer), built lazily


def _ed_keypair(which):
    from receipt_layer import Ed25519Signer
    if which not in _ED_KEYS:
        _ED_KEYS[which] = (Ed25519Signer.generate(), Ed25519Signer.generate())
    return _ED_KEYS[which][0 if which == "main" else 1]


def make_log(path=None):
    from receipt_layer import ReceiptLog as _RL
    if _BACKEND == "ed25519":
        return _RL(_ed_keypair("main"), path)
    return _RL(SECRET, path)


def make_other_log():
    from receipt_layer import ReceiptLog as _RL
    if _BACKEND == "ed25519":
        return _RL(_ed_keypair("other"))
    return _RL(OTHER_SECRET)


BAD_SIG = {"hmac": "f" * 64, "ed25519": "f" * 128}


def bad_sig():
    return BAD_SIG[_BACKEND]


def do(log, tool, *a, **k):
    """Issue a receipt with the exact args shape make_claim() produces."""
    return log.issue(tool, {"args": list(a), "kwargs": dict(k)}, "ok")


def expect_hold(label, result, reason=None):
    assert result.verdict == "HOLD", f"{label}: expected HOLD, got {result}"
    if reason is not None:
        reasons = [f["reason"] for f in result.failures]
        assert reason in reasons, f"{label}: expected reason {reason}, got {reasons}"
    return result


def expect_pass(label, result):
    assert result.verdict == "PASS", \
        f"{label}: expected PASS, got {result.to_dict()}"
    return result


# ---------------------------------------------------------------- A1 ---
def test_A1_false_done_must_hold():
    held = 0

    # F1: claim with no receipt at all (empty log)
    log = make_log()
    gate = CompletionGate(log)
    expect_hold("F1 empty-log", gate.check([make_claim("search", "x")]), "no_receipt")
    held += 1

    # F2: receipt exists for different args
    log = make_log(); gate = CompletionGate(log)
    do(log, "search", "x")
    expect_hold("F2 wrong-args", gate.check([make_claim("search", "y")]), "no_receipt")
    held += 1

    # F3: receipt exists for different tool
    log = make_log(); gate = CompletionGate(log)
    do(log, "search", "x")
    expect_hold("F3 wrong-tool", gate.check([make_claim("lookup", "x")]), "no_receipt")
    held += 1

    # F4: hand-forged receipt (random signature) inserted into the log
    log = make_log(); gate = CompletionGate(log)
    forged = Receipt(tool_name="search", args_hash="a" * 64, result_hash="b" * 64,
                     timestamp=1.0, seq=1, signature=bad_sig())
    log._receipts.append(forged)
    expect_hold("F4 forged-signature",
                gate.check([{"tool_name": "search", "args_hash": "a" * 64}]),
                "bad_signature")
    held += 1

    # F5: receipt signed with a different key
    log = make_log(); gate = CompletionGate(log)
    other = make_other_log()
    r = other.issue("search", {"args": ["x"], "kwargs": {}}, "ok")
    log._receipts.append(r)
    expect_hold("F5 wrong-key", gate.check([make_claim("search", "x")]), "bad_signature")
    held += 1

    # F6: tampered result_hash (one byte flipped)
    log = make_log(); gate = CompletionGate(log)
    r = do(log, "search", "x")
    bad = dataclasses.replace(r, result_hash=("0" if r.result_hash[0] != "0" else "1")
                              + r.result_hash[1:])
    log._receipts[-1] = bad
    expect_hold("F6 tampered-result", gate.check([make_claim("search", "x")]),
                "bad_signature")
    held += 1

    # F7: tampered args_hash, claim references the tampered hash directly
    log = make_log(); gate = CompletionGate(log)
    r = do(log, "search", "x")
    bad = dataclasses.replace(r, args_hash="0" * 64)
    log._receipts[-1] = bad
    expect_hold("F7 tampered-args",
                gate.check([{"tool_name": "search", "args_hash": "0" * 64}]),
                "bad_signature")
    held += 1

    # F8: tampered tool_name
    log = make_log(); gate = CompletionGate(log)
    r = do(log, "search", "x")
    bad = dataclasses.replace(r, tool_name="evil")
    log._receipts[-1] = bad
    expect_hold("F8 tampered-tool",
                gate.check([{"tool_name": "evil", "args_hash": r.args_hash}]),
                "bad_signature")
    held += 1

    # F9: tampered seq number (1 -> 99). Breaks the append-only invariant,
    # so log-integrity fires before signature checking.
    log = make_log(); gate = CompletionGate(log)
    r = do(log, "search", "x")
    bad = dataclasses.replace(r, seq=99)
    log._receipts[-1] = bad
    expect_hold("F9 tampered-seq", gate.check([make_claim("search", "x")]),
                "log_gap")
    held += 1

    # F10: receipt deleted from the log (seq 3 of 1..4 removed) — the log
    # is no longer gap-free, so the evidence chain is broken
    log = make_log(); gate = CompletionGate(log)
    for i in (1, 2, 3, 4):
        do(log, "t", i=i)
    del log._receipts[2]  # remove seq 3
    expect_hold("F10 deleted-receipt",
                gate.check([make_claim("t", i=1), make_claim("t", i=2),
                            make_claim("t", i=4)]),
                "log_gap")
    held += 1

    # F11: deletion variant — seq 2 of 1..3 removed
    log = make_log(); gate = CompletionGate(log)
    for i in (1, 2, 3):
        do(log, "t", i=i)
    del log._receipts[1]  # remove seq 2
    expect_hold("F11 deleted-receipt-2",
                gate.check([make_claim("t", i=1), make_claim("t", i=3)]),
                "log_gap")
    held += 1

    # F12: replay across checks — same claims checked twice
    log = make_log(); gate = CompletionGate(log)
    do(log, "a", 1); do(log, "b", 2)
    claims = [make_claim("a", 1), make_claim("b", 2)]
    expect_pass("F12 first-check", gate.check(claims))
    expect_hold("F12 replay", gate.check(claims), "replayed")
    held += 1

    # F13: same action claimed twice, only one receipt exists
    log = make_log(); gate = CompletionGate(log)
    do(log, "a", 1)
    expect_hold("F13 double-claim",
                gate.check([make_claim("a", 1), make_claim("a", 1)]),
                "no_receipt")
    held += 1

    # F14: second task reuses first task's receipts (same gate session)
    log = make_log(); gate = CompletionGate(log)
    do(log, "a", 1)
    expect_pass("F14 task1", gate.check([make_claim("a", 1)]))
    expect_hold("F14 task2-reuse", gate.check([make_claim("a", 1)]), "replayed")
    held += 1

    # F15: empty claim list
    log = make_log(); gate = CompletionGate(log)
    do(log, "a", 1)
    expect_hold("F15 empty-claim", gate.check([]), "empty_claim")
    held += 1

    # F16: type-confused args (int 5 vs str "5" hash differently)
    log = make_log(); gate = CompletionGate(log)
    do(log, "t", n=5)
    expect_hold("F16 type-confusion", gate.check([make_claim("t", n="5")]),
                "no_receipt")
    held += 1

    # F17: two valid claims plus one bogus
    log = make_log(); gate = CompletionGate(log)
    do(log, "a", 1); do(log, "b", 2)
    expect_hold("F17 one-bogus",
                gate.check([make_claim("a", 1), make_claim("b", 2),
                            make_claim("c", 3)]),
                "no_receipt")
    held += 1

    # F18: receipt with empty signature inserted
    log = make_log(); gate = CompletionGate(log)
    r = do(log, "search", "x")
    bad = dataclasses.replace(r, signature="")
    log._receipts[-1] = bad
    expect_hold("F18 empty-signature", gate.check([make_claim("search", "x")]),
                "bad_signature")
    held += 1

    # F19: on-disk log tampered (args_hash flipped inside valid JSON)
    with tempfile.TemporaryDirectory() as tmp:
        path = os.path.join(tmp, "log.jsonl")
        log = make_log(path)
        do(log, "a", 1); do(log, "b", 2)
        with open(path, encoding="utf-8") as f:
            lines = f.readlines()
        data = json.loads(lines[0])
        data["args_hash"] = ("0" if data["args_hash"][0] != "0" else "1") \
            + data["args_hash"][1:]
        lines[0] = json.dumps(data) + "\n"
        with open(path, "w", encoding="utf-8") as f:
            f.writelines(lines)
        try:
            make_log(path)
        except ValueError:
            held += 1  # F19: tampered log refused at load
        else:
            raise AssertionError("F19 on-disk-tamper: tampered log loaded without error")

    # F20: claim by raw args_hash that matches nothing
    log = make_log(); gate = CompletionGate(log)
    do(log, "a", 1)
    expect_hold("F20 bad-args-hash",
                gate.check([{"tool_name": "a", "args_hash": "0" * 64}]),
                "no_receipt")
    held += 1

    assert held == 20, f"A1: held {held}/20"
    print(f"A1: {held}/20 false-done cases -> HOLD")


def test_A2_legit_must_pass():
    passed = 0

    def fresh2():
        log = make_log()
        return log, CompletionGate(log)

    # L1: single action
    log, gate = fresh2(); do(log, "search", "x")
    expect_pass("L1 single", gate.check([make_claim("search", "x")])); passed += 1

    # L2: three-step chain, distinct tools
    log, gate = fresh2()
    do(log, "search", "q"); do(log, "fetch", "u"); do(log, "summarize", "t")
    expect_pass("L2 chain", gate.check([make_claim("search", "q"),
                                        make_claim("fetch", "u"),
                                        make_claim("summarize", "t")])); passed += 1

    # L3: retry x3, claimed x3
    log, gate = fresh2()
    for _ in range(3):
        do(log, "fetch", "u")
    expect_pass("L3 retry-x3", gate.check([make_claim("fetch", "u")] * 3)); passed += 1

    # L4: retry x3, claimed once (extra receipts are fine)
    log, gate = fresh2()
    for _ in range(3):
        do(log, "fetch", "u")
    expect_pass("L4 retry-claimed-once", gate.check([make_claim("fetch", "u")])); passed += 1

    # L5: interleaved tools A,B,A,B
    log, gate = fresh2()
    do(log, "a", 1); do(log, "b", 1); do(log, "a", 2); do(log, "b", 2)
    expect_pass("L5 interleaved", gate.check([make_claim("a", 1), make_claim("b", 1),
                                              make_claim("a", 2), make_claim("b", 2)])); passed += 1

    # L6-L8: empty/None results
    for lbl, res in (("L6 empty-dict", {}), ("L7 none", None), ("L8 empty-list", [])):
        log, gate = fresh2()
        log.issue("t", {"args": ["x"], "kwargs": {}}, res)
        expect_pass(lbl, gate.check([make_claim("t", "x")])); passed += 1

    # L9: nested args
    log, gate = fresh2()
    do(log, "t", spec={"a": {"b": [1, 2, {"c": 3}]}})
    expect_pass("L9 nested", gate.check([make_claim("t", spec={"a": {"b": [1, 2, {"c": 3}]}})])); passed += 1

    # L10: unicode args and result
    log, gate = fresh2()
    log.issue("t", {"args": ["héllo→"], "kwargs": {}}, "wörld✓")
    expect_pass("L10 unicode", gate.check([make_claim("t", "héllo→")])); passed += 1

    # L11: float args
    log, gate = fresh2(); do(log, "t", x=0.1 + 0.2)
    expect_pass("L11 float", gate.check([make_claim("t", x=0.1 + 0.2)])); passed += 1

    # L12: bool/None args
    log, gate = fresh2(); do(log, "t", flag=True, missing=None)
    expect_pass("L12 bool-none", gate.check([make_claim("t", flag=True, missing=None)])); passed += 1

    # L13: 1KB string arg
    log, gate = fresh2(); big = "z" * 1024; do(log, "t", big)
    expect_pass("L13 big-arg", gate.check([make_claim("t", big)])); passed += 1

    # L14: 50-step chain
    log, gate = fresh2()
    claims = []
    for i in range(50):
        do(log, "step", i=i)
        claims.append(make_claim("step", i=i))
    expect_pass("L14 long-chain", gate.check(claims)); passed += 1

    # L15: kwargs only
    log, gate = fresh2(); do(log, "t", q="x", n=2)
    expect_pass("L15 kwargs", gate.check([make_claim("t", q="x", n=2)])); passed += 1

    # L16: positional only
    log, gate = fresh2(); do(log, "t", "a", "b")
    expect_pass("L16 positional", gate.check([make_claim("t", "a", "b")])); passed += 1

    # L17: mixed args + kwargs
    log, gate = fresh2(); do(log, "t", "a", n=2)
    expect_pass("L17 mixed", gate.check([make_claim("t", "a", n=2)])); passed += 1

    # L18: shim — tool raises once, then succeeds; claim only the success
    log, gate = fresh2()
    calls = {"n": 0}

    def flaky(q):
        calls["n"] += 1
        if calls["n"] == 1:
            raise RuntimeError("boom")
        return "fine"

    flaky_wrapped = wrap(flaky, log, "flaky")
    try:
        flaky_wrapped("q")
    except RuntimeError:
        pass
    flaky_wrapped("q")
    assert len(log) == 2  # error receipt + success receipt both recorded
    expect_pass("L18 shim-error-then-success", gate.check([make_claim("flaky", "q")]))
    passed += 1

    # L19: same tool, different args — disambiguated by args_hash
    log, gate = fresh2()
    do(log, "search", "x"); do(log, "search", "y"); do(log, "search", "z")
    expect_pass("L19 disambiguation",
                gate.check([make_claim("search", "z"), make_claim("search", "x")])); passed += 1

    # L20: claim by raw args_hash
    log, gate = fresh2()
    r = do(log, "search", "x")
    expect_pass("L20 raw-args-hash",
                gate.check([{"tool_name": "search", "args_hash": r.args_hash}])); passed += 1

    assert passed == 20, f"A2: passed {passed}/20"
    print(f"A2: {passed}/20 legit completions -> PASS, 0 false holds")


def test_A3_tamper():
    log = make_log()
    r = do(log, "search", "x")
    assert log.verify(r) is True, "A3: valid receipt must verify"

    def flip(s):
        return ("0" if s[0] != "0" else "1") + s[1:]

    n = 0
    assert log.verify(dataclasses.replace(r, result_hash=flip(r.result_hash))) is False, \
        "A3: flipped result_hash must not verify"
    n += 1
    assert log.verify(dataclasses.replace(r, signature=flip(r.signature))) is False, \
        "A3: flipped signature must not verify"
    n += 1
    assert log.verify(dataclasses.replace(r, tool_name="searchX")) is False, \
        "A3: flipped tool_name must not verify"
    n += 1
    print(f"A3: {n}/3 byte-flip tamper cases -> verify() False")


def run_all():
    test_A1_false_done_must_hold()
    test_A2_legit_must_pass()
    test_A3_tamper()


if __name__ == "__main__":
    for mode in ("hmac", "ed25519"):
        globals()["_BACKEND"] = mode
        print(f"--- backend: {mode} ---")
        run_all()
    print("ALL ACCEPTANCE TESTS PASSED (hmac + ed25519)")
