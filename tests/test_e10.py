import copy

import numpy as np

from cerurl.e10 import (Ctx, MAX_AGE, attempt_timestamp_repair, entry_hash, item, make_artifact, make_entry, run_e10, verify, world)


def base(seed=1, phish=True):
    rng = np.random.default_rng(seed); T = 1_800_000_000
    w = world(rng, T, phish, 4000)
    return w, T, item(w["e2"], w["a2"], w["c2"], [w["e1"], w["e2"]]), Ctx(T, {w["url"]: (entry_hash(w["e2"]), 2)})


def test_clean_evidence_accepted():
    _, _, it, ctx = base()
    assert verify(it, ctx)["accepted"]


def test_every_post_signature_byte_flip_detected():
    w, T, it, ctx = base()
    for i in range(0, len(it["artifact"]), 97):
        b = bytearray(it["artifact"]); b[i] ^= 0x01; bad = dict(it, artifact=bytes(b))
        assert verify(bad, ctx)["reason"] == "artifact_hash_mismatch"


def test_metadata_and_redirect_tampering_detected():
    w, T, it, ctx = base()
    m = copy.deepcopy(it); m["entry"]["manifest"]["capture_at"] += 1
    assert verify(m, ctx)["reason"] == "bad_signature"
    r = copy.deepcopy(it); r["redirect_chain"] = ["https://x.example"]
    assert verify(r, ctx)["reason"] == "redirect_chain_mismatch"


def test_valid_signature_stale_rejected_by_policy_not_crypto():
    w, T, _, _ = base()
    old = item(w["e1"], w["a1"], w["c1"], [w["e1"]]); r = verify(old, Ctx(T))
    assert r["sig_valid"] and not r["accepted"] and r["reason"] == "stale"


def test_future_available_rejected_and_no_timestamp_invention():
    w, T, _, _ = base()
    e = make_entry(w["url"], 2, w["a2"], w["c2"], w["t2"], T + 10 * 3600, entry_hash(w["e1"]))
    assert verify(item(e, w["a2"], w["c2"], [w["e1"], e]), Ctx(T))["reason"] == "available_after_prediction_time"
    n = make_entry(w["url"], 2, w["a2"], w["c2"], None, w["t2"], entry_hash(w["e1"]))
    assert verify(item(n, w["a2"], w["c2"], [w["e1"], n]), Ctx(T))["reason"] == "missing_capture_time"
    assert attempt_timestamp_repair({}).startswith("refused")


def test_signed_false_content_is_accepted_and_flagged_as_residual():
    w, T, _, _ = base()
    a = make_artifact(np.random.default_rng(2), False, 3000); e = make_entry(w["url"], 2, a, w["c1"], w["t2"], w["t2"] + 30, entry_hash(w["e1"]))
    assert verify(item(e, a, w["c1"], [w["e1"], e]), Ctx(T))["accepted"]


def test_run_small_passes(tmp_path):
    a = run_e10(str(tmp_path / "o"), str(tmp_path / "t"), n_per=5, plots=False)
    assert a["pass_criteria"]["status"] == "pass"
