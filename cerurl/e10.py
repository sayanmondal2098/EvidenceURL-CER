"""E10: evidence replay, staleness and storage tampering.

Explicit integrity model (all claims are conditional on it):
  * every evidence item has a manifest {url, version, artifact_sha256, artifact_len, capture_at,
    available_at, timestamp_source, redirect_chain_sha256, collector_id, prev};
  * the collector signs the canonical manifest with HMAC-SHA256 under a per-collector key that the
    verifier holds (symmetric stand-in for a public-key signature: it proves *who vouched for the
    manifest*, not that remote content was truthful);
  * manifests of one URL form a hash chain (``prev`` = hash of the previous signed entry); the
    verifier may hold an anchored head (hash, version) learned out of band;
  * artifact bytes and the redirect chain are stored outside the manifest and bound only by hashes.

Verifier order (first failing check is the reason): unsigned -> bad signature -> artifact hash ->
redirect-chain hash -> log link/head consistency -> missing / non-collector timestamp -> availability
after prediction time -> staleness (policy max age) -> superseded by a known newer version.
A capture timestamp is never invented: a missing capture_at, or one whose source is not the collector
clock, makes the evidence ineligible for freshness-sensitive use; editing it breaks the signature.

Not detectable inside this model (reported as residual, never as detections): a collector that signs
false content, and a replayed old snapshot inside the freshness window when no newer version is known.
"""
from __future__ import annotations

import copy
import hashlib
import hmac
import json
import time
from pathlib import Path

import numpy as np

from .core import Case, Observation, certify, quarantine_root_groups
from .repair import RepairConfig, repair

MAX_AGE = 24 * 3600
SKEW = 300
KEYS = {"collA": b"collector-A-secret-key-material-00001", "collB": b"collector-B-secret-key-material-00002"}
ATTACKER_KEY = b"attacker-controlled-key-material-0003"
PHISH, BENIGN = b"PHISH-KIT-LOGIN-FORM", b"CORPORATE-FAQ-PAGE"
N_PER = 150


def canon(o) -> bytes: return json.dumps(o, sort_keys=True, separators=(",", ":")).encode()
def sha(b: bytes) -> str: return hashlib.sha256(b).hexdigest()
def sign(key: bytes, manifest: dict) -> str: return hmac.new(key, canon(manifest), hashlib.sha256).hexdigest()
def entry_hash(e: dict) -> str: return sha(canon(e["manifest"]) + e["sig"].encode())
def evidence_value(art: bytes) -> float: return 0.9 if PHISH in art else 0.1


def make_artifact(rng, phish: bool, size: int) -> bytes:
    return (PHISH if phish else BENIGN) + b"|" + rng.bytes(max(size, 64))


def make_entry(url, version, art, chain, capture_at, available_at, prev, signer="collA", key=None, source="collector_clock"):
    m = dict(url=url, version=version, artifact_sha256=sha(art), artifact_len=len(art), capture_at=capture_at, available_at=available_at,
             timestamp_source=source, redirect_chain_sha256=sha(canon(chain)), collector_id=signer, prev=prev)
    return dict(manifest=m, sig=sign(key or KEYS[signer], m), signer=signer)


class Ctx:
    def __init__(self, T, anchored=None, keys=KEYS, max_age=MAX_AGE, skew=SKEW):
        self.T, self.anchored, self.keys, self.max_age, self.skew = T, anchored, keys, max_age, skew


def verify(item: dict, ctx: Ctx) -> dict:
    e = item["entry"]; m = e["manifest"]; art = item["artifact"]
    def res(ok, why, sv): return dict(accepted=ok, reason=why, sig_valid=sv)
    if not e.get("sig"): return res(False, "unsigned", False)
    key = ctx.keys.get(e.get("signer"))
    if key is None or not hmac.compare_digest(sign(key, m), e["sig"]): return res(False, "bad_signature", False)
    if sha(art) != m["artifact_sha256"] or len(art) != m["artifact_len"]: return res(False, "artifact_hash_mismatch", True)
    if sha(canon(item["redirect_chain"])) != m["redirect_chain_sha256"]: return res(False, "redirect_chain_mismatch", True)
    log = item["log"]; prev = "GENESIS"
    for i, le in enumerate(log):
        k = ctx.keys.get(le.get("signer"))
        if not le.get("sig") or k is None or not hmac.compare_digest(sign(k, le["manifest"]), le["sig"]): return res(False, "log_entry_bad_signature", True)
        if le["manifest"]["prev"] != prev or le["manifest"]["version"] != i + 1: return res(False, "log_broken_link", True)
        prev = entry_hash(le)
    if entry_hash(e) not in {entry_hash(x) for x in log}: return res(False, "entry_not_in_log", True)
    anc = (ctx.anchored or {}).get(m["url"])
    if anc and prev != anc[0]: return res(False, "log_truncated_or_forked", True)
    if m["capture_at"] is None: return res(False, "missing_capture_time", True)
    if m["timestamp_source"] != "collector_clock": return res(False, "untrusted_timestamp_source", True)
    if m["available_at"] > ctx.T + ctx.skew: return res(False, "available_after_prediction_time", True)
    if m["capture_at"] > ctx.T + ctx.skew: return res(False, "capture_after_prediction_time", True)
    if ctx.T - m["capture_at"] > ctx.max_age: return res(False, "stale", True)
    if anc and m["version"] < anc[1]: return res(False, "superseded", True)
    return res(True, "ok", True)


def attempt_timestamp_repair(item: dict) -> str:
    """Refuses to fabricate capture times from created_date, receipt time, or neighbours."""
    return "refused: capture_at is not derivable from any non-collector field"


# ---- worlds / scenarios ---------------------------------------------------------------------------
def world(rng, T, state_now_phish: bool, size: int):
    url = f"https://site{int(rng.integers(1 << 30))}.example/login"; chain1 = [url, url + "/home"]
    a1 = make_artifact(rng, False, size); t1 = T - int(rng.integers(2 * MAX_AGE, 6 * MAX_AGE))
    e1 = make_entry(url, 1, a1, chain1, t1, t1 + 30, "GENESIS")
    chain2 = [url, "https://cdn.evil.example/kit"] if state_now_phish else chain1
    a2 = make_artifact(rng, state_now_phish, size); t2 = T - int(rng.integers(60, 3600))
    e2 = make_entry(url, 2, a2, chain2, t2, t2 + 30, entry_hash(e1))
    return dict(url=url, e1=e1, a1=a1, c1=chain1, t1=t1, e2=e2, a2=a2, c2=chain2, t2=t2, T=T)


def item(entry, art, chain, log): return dict(entry=copy.deepcopy(entry), artifact=art, redirect_chain=copy.deepcopy(chain), log=copy.deepcopy(log))


def scenario_items(rng):
    S = {}  # name -> (class, expectation, builder(rng,T,size)->(item, ctx, truth_phish))
    T0 = 1_800_000_000
    def add(name, cls, expect, fn): S[name] = (cls, expect, fn)
    def fresh(rng, T, size, phish=None):
        phish = bool(rng.random() < .5) if phish is None else phish
        w = world(rng, T, phish, size); return w, phish
    def legit(rng, T, size, skew=0, empty_chain=False):
        w, ph = fresh(rng, T, size); e, a, c = w["e2"], w["a2"], w["c2"]
        if empty_chain:
            c = []; e = make_entry(w["url"], 2, a, c, w["t2"], w["t2"] + 30, entry_hash(w["e1"]))
        if skew:
            e = make_entry(w["url"], 2, a, c, w["t2"], T + skew, entry_hash(w["e1"]))
        return item(e, a, c, [w["e1"], e]), Ctx(T, {w["url"]: (entry_hash(e), 2)}), ph
    add("legit_fresh", "legit", "accept", lambda r, T, s: legit(r, T, s))
    add("legit_clock_skew_within_tolerance", "legit", "accept", lambda r, T, s: legit(r, T, s, skew=SKEW - 60))
    add("legit_empty_redirect_chain", "legit", "accept", lambda r, T, s: legit(r, T, s, empty_chain=True))
    def unsigned(r, T, s):
        w, ph = fresh(r, T, s); it = item(w["e2"], w["a2"], w["c2"], [w["e1"], w["e2"]]); it["entry"]["sig"] = None
        return it, Ctx(T), ph
    add("unsigned_otherwise_valid", "unsigned", "reject", unsigned)
    def wrongkey(r, T, s):
        w, ph = fresh(r, T, True); a = make_artifact(r, False, s); e = make_entry(w["url"], 2, a, w["c1"], w["t2"], w["t2"] + 30, entry_hash(w["e1"]), key=ATTACKER_KEY)
        return item(e, a, w["c1"], [w["e1"], e]), Ctx(T), True
    add("signed_with_attacker_key", "post_signature", "reject", wrongkey)
    def stale_age(r, T, s):
        w, _ = fresh(r, T, s); return item(w["e1"], w["a1"], w["c1"], [w["e1"]]), Ctx(T), True
    add("signed_stale_replay_old_benign", "stale", "reject", stale_age)
    def stale_super(r, T, s):
        w, _ = fresh(r, T, s); T2 = w["t1"] + int(r.integers(3600, MAX_AGE - 3600)); w2 = dict(w); 
        e1 = make_entry(w["url"], 1, w["a1"], w["c1"], T2 - 600, T2 - 570, "GENESIS"); e2 = make_entry(w["url"], 2, w["a2"], w["c2"], T2 - 60, T2 - 30, entry_hash(e1))
        return item(e1, w["a1"], w["c1"], [e1, e2]), Ctx(T2, {w["url"]: (entry_hash(e2), 2)}), True
    add("signed_replay_in_window_newer_version_known", "stale", "reject", stale_super)
    def stale_unknown(r, T, s):
        w, _ = fresh(r, T, s); T2 = w["t1"] + int(r.integers(3600, MAX_AGE - 3600))
        e1 = make_entry(w["url"], 1, w["a1"], w["c1"], T2 - 600, T2 - 570, "GENESIS")
        return item(e1, w["a1"], w["c1"], [e1]), Ctx(T2, {w["url"]: (entry_hash(e1), 1)}), True
    add("signed_replay_in_window_no_newer_known", "residual", "residual_accept", stale_unknown)
    def future(r, T, s):
        w, ph = fresh(r, T, s); e = make_entry(w["url"], 2, w["a2"], w["c2"], w["t2"], T + int(r.integers(2 * SKEW, 7 * 86400)), entry_hash(w["e1"]))
        return item(e, w["a2"], w["c2"], [w["e1"], e]), Ctx(T), ph
    add("signed_feed_available_after_prediction_time", "policy", "reject", future)
    def missing_ts(r, T, s):
        w, ph = fresh(r, T, s); e = make_entry(w["url"], 2, w["a2"], w["c2"], None, w["t2"] + 30, entry_hash(w["e1"]))
        return item(e, w["a2"], w["c2"], [w["e1"], e]), Ctx(T), ph
    add("signed_missing_capture_time", "policy", "reject", missing_ts)
    def inferred_ts(r, T, s):
        w, ph = fresh(r, T, s); e = make_entry(w["url"], 2, w["a2"], w["c2"], T - 100, T - 100, entry_hash(w["e1"]), source="inferred_from_created_date")
        return item(e, w["a2"], w["c2"], [w["e1"], e]), Ctx(T), ph
    add("resigned_with_inferred_timestamp", "policy", "reject", inferred_ts)
    def invented_ts(r, T, s):
        w, ph = fresh(r, T, s); e = make_entry(w["url"], 2, w["a2"], w["c2"], None, w["t2"] + 30, entry_hash(w["e1"])); it = item(e, w["a2"], w["c2"], [w["e1"], e])
        it["entry"]["manifest"]["capture_at"] = T - 10  # unsigned post-hoc "repair"
        return it, Ctx(T), ph
    add("capture_time_invented_after_signing", "post_signature", "reject", invented_ts)
    def bytes_mut(kind):
        def f(r, T, s):
            w, _ = fresh(r, T, s, phish=True); a = w["a2"] if True else None; it = item(w["e2"], a, w["c2"], [w["e1"], w["e2"]]); b = bytearray(a)
            if kind == "flip": i = int(r.integers(len(b))); b[i] ^= 1 << int(r.integers(8))
            elif kind == "truncate": b = b[:-int(r.integers(1, 20))]
            elif kind == "append": b += r.bytes(int(r.integers(1, 20)))
            else: b = bytearray(make_artifact(r, False, s))  # swap phishing bytes for a benign page
            it["artifact"] = bytes(b); return it, Ctx(T, {w["url"]: (entry_hash(w["e2"]), 2)}), True
        return f
    for k in ("flip", "truncate", "append", "swap_to_benign"): add(f"post_signature_bytes_{k}", "post_signature", "reject", bytes_mut(k))
    def meta_mut(field):
        def f(r, T, s):
            w, ph = fresh(r, T, s); e = copy.deepcopy(w["e2"]); m = e["manifest"]
            if field == "capture_at": m["capture_at"] = T - 5
            elif field == "available_at": m["available_at"] = m["available_at"] - 1000
            elif field == "url": m["url"] = m["url"] + "?x"
            else: m["version"] = 1
            return item(e, w["a2"], w["c2"], [w["e1"], w["e2"]]), Ctx(T), ph
        return f
    for k in ("capture_at", "available_at", "url", "version"): add(f"post_signature_metadata_{k}", "post_signature", "reject", meta_mut(k))
    def chain_swap(update_hash):
        def f(r, T, s):
            w, _ = fresh(r, T, s, phish=True); newc = [w["url"], w["url"] + "/home"]
            if update_hash: e = copy.deepcopy(w["e2"]); e["manifest"]["redirect_chain_sha256"] = sha(canon(newc))
            else: e = w["e2"]
            return item(e, w["a2"], newc, [w["e1"], w["e2"]]), Ctx(T), True
        return f
    add("redirect_chain_replaced_manifest_untouched", "post_signature", "reject", chain_swap(False))
    add("redirect_chain_and_hash_replaced", "post_signature", "reject", chain_swap(True))
    def log_mut(kind):
        def f(r, T, s):
            w, ph = fresh(r, T, s); e3 = make_entry(w["url"], 3, w["a2"], w["c2"], w["t2"] + 10, w["t2"] + 40, entry_hash(w["e2"])); full = [w["e1"], w["e2"], e3]
            if kind == "truncate_tail": log = full[:2]
            elif kind == "delete_middle": log = [w["e1"], e3]
            else: log = [w["e2"], w["e1"], e3]
            return item(e3, w["a2"], w["c2"], log), Ctx(T, {w["url"]: (entry_hash(e3), 3)}), ph
        return f
    for k in ("truncate_tail", "delete_middle", "reorder"): add(f"manifest_log_{k}", "post_signature", "reject", log_mut(k))
    def false_content(r, T, s):
        w, _ = fresh(r, T, s, phish=True); a = make_artifact(r, False, s); e = make_entry(w["url"], 2, a, w["c1"], w["t2"], w["t2"] + 30, entry_hash(w["e1"]))
        return item(e, a, w["c1"], [w["e1"], e]), Ctx(T, {w["url"]: (entry_hash(e), 2)}), True
    add("signed_false_content_by_compromised_collector", "residual", "residual_accept", false_content)
    return S, T0


# ---- decision impact via core certificate / repair -----------------------------------------------------
def decide(ev_value, accepted, truth_phish, rng):
    honest = 0.9 if truth_phish else 0.1; P = np.array([[0.7, 0.3], [0.0, 1.0]])
    others = [Observation(0, float(np.clip(honest + rng.normal(0, .03), 0, 1)), 0.2 / 3, frozenset({f"s{i}"}), f"o{i}") for i in range(3)]
    obs = others + [Observation(0, ev_value, 0.8, frozenset({"collA"}), "ev"), Observation(1, honest, 1.0, frozenset({"s1"}), "n1")]
    cands = [Observation(0, honest, 0.0, frozenset({f"c{i}"}), f"cand{i}") for i in range(2)]
    case = Case("e10", P, obs, 0, int(truth_phish), cands, {c.obs_id: 1.0 for c in cands})
    repaired = False
    if not accepted:
        case = quarantine_root_groups(case, {"collA"}); case.candidates = cands; case.candidate_costs = {c.obs_id: 1.0 for c in cands}
        rep = certify(case, 1)
        if not rep["certified"]:
            out = repair(case, "counterfactual", RepairConfig(budget=1, max_steps=2, acquisition_budget=2.0)); repaired = bool(out["actions"]); return out["final"]["verdict"], repaired
    return certify(case, 1)["verdict"], repaired


def wrong(v, truth_phish): return (truth_phish and v == "benign") or ((not truth_phish) and v == "malicious")


def pct(a, q): return float(np.percentile(a, q)) if len(a) else None


def run_e10(out_dir="results/E10", table_dir="tables", n_per=N_PER, seed=20261010, plots=True) -> dict:
    t0 = time.perf_counter(); out = Path(out_dir); out.mkdir(parents=True, exist_ok=True); tables = Path(table_dir); tables.mkdir(parents=True, exist_ok=True)
    rng = np.random.default_rng(seed); S, T0 = scenario_items(rng); rows = []; lat = []; inval = []
    for name, (cls, expect, fn) in S.items():
        for i in range(n_per):
            size = int(np.clip(rng.lognormal(10, 1.2), 2_000, 1_500_000)); T = T0 + int(rng.integers(0, 86400 * 30))
            it, ctx, truth = fn(rng, T, size)
            ta = time.perf_counter(); v = verify(it, ctx); ms = (time.perf_counter() - ta) * 1000; lat.append((ms, size))
            ev = evidence_value(it["artifact"]) if it["artifact"] is not None else 0.1
            dn, _ = decide(ev, True, truth, np.random.default_rng(seed + i))
            dv, rep = decide(ev, v["accepted"], truth, np.random.default_rng(seed + i))
            di, _ = decide(0.9 if truth else 0.1, True, truth, np.random.default_rng(seed + i))
            # certificate invalidation: certificate issued on the clean evidence, then the tampered item is read
            if cls == "post_signature":
                cert_digest = sha(canon(it["entry"]["manifest"])); ts = time.perf_counter(); r2 = verify(it, ctx)
                inval.append(dict(scenario=name, ms=(time.perf_counter() - ts) * 1000, invalidated=not r2["accepted"]))
            rows.append(dict(scenario=name, cls=cls, expect=expect, i=i, size=size, accepted=v["accepted"], reason=v["reason"], sig_valid=v["sig_valid"], ms=ms,
                             naive_wrong=wrong(dn, truth), verified_wrong=wrong(dv, truth), naive_degraded=dn != di, verified_degraded=dv != di, repair_triggered=rep, verdict_naive=dn, verdict_verified=dv))
    import pandas as pd
    df = pd.DataFrame(rows); df.to_csv(out / "verification_results.csv", index=False)
    summ = []
    for name, g in df.groupby("scenario", sort=False):
        cls, exp = g.cls.iloc[0], g.expect.iloc[0]
        summ.append(dict(scenario=name, cls=cls, expect=exp, n=len(g), rejected=float((~g.accepted).mean()), accepted=float(g.accepted.mean()), sig_valid=float(g.sig_valid.mean()),
                         naive_wrong=float(g.naive_wrong.mean()), verified_wrong=float(g.verified_wrong.mean()), repair_triggered=float(g.repair_triggered.mean()),
                         p50_ms=pct(g.ms, 50), p95_ms=pct(g.ms, 95), top_reason=g.reason.mode().iloc[0]))
    sm = pd.DataFrame(summ); sm.to_csv(out / "scenario_summary.csv", index=False)
    post = df[df.cls == "post_signature"]; legit = df[df.cls == "legit"]; stale = df[df.cls.isin(["stale"]) | (df.scenario == "signed_replay_in_window_no_newer_known")]
    reject_expected = df[df.expect == "reject"]; resid = df[df.expect == "residual_accept"]
    policy_only = df[(df.cls.isin(["stale", "policy"])) & df.sig_valid & ~df.accepted]
    bytes_df = df[df.scenario.str.startswith("post_signature_bytes")]
    lat_a = np.array([x[0] for x in lat]); sizes = np.array([x[1] for x in lat])
    buckets = {n: dict(p50_ms=pct(lat_a[m], 50), p95_ms=pct(lat_a[m], 95), n=int(m.sum())) for n, m in (("<10KB", sizes < 10_000), ("10KB-200KB", (sizes >= 10_000) & (sizes < 200_000)), (">=200KB", sizes >= 200_000))}
    iv = pd.DataFrame(inval); sched = {}
    for D in (60, 900, 3600):
        d = D - (rng.uniform(0, D, 20000)) ; sched[f"audit_every_{D}s"] = dict(mean_s=float(d.mean()), p95_s=float(np.percentile(d, 95)))
    audit = dict(audit_version="E10-1", world_type="controlled_synthetic", seed=seed, items=len(df), scenarios=len(S), items_per_scenario=n_per,
                 integrity_model=dict(signature="HMAC-SHA256 over canonical manifest, per-collector key held by verifier (symmetric stand-in)", binds="manifest metadata + artifact hash + redirect-chain hash + hash-chained prior entry", does_not_prove="truthfulness of remote content at signing time", policy=dict(max_age_seconds=MAX_AGE, availability_skew_seconds=SKEW, trusted_timestamp_source="collector_clock")),
                 detection=dict(post_signature_detection_rate=float((~post.accepted).mean()), post_signature_byte_changes=dict(n=len(bytes_df), detected=int((~bytes_df.accepted).sum())),
                                false_reject_rate_legit=float((~legit.accepted).mean()), false_accept_rate_expected_reject=float(reject_expected.accepted.mean()),
                                stale_acceptance_rate=dict(all_stale=float(stale.accepted.mean()), by_scenario={k: float(g.accepted.mean()) for k, g in stale.groupby("scenario")}),
                                signature_valid_but_rejected_by_policy=int(len(policy_only)), residual_accepted=dict(n=len(resid), accepted=int(resid.accepted.sum()), scenarios=sorted(resid.scenario.unique().tolist())),
                                invented_timestamp_repairs_accepted=int(df[df.scenario.isin(["signed_missing_capture_time", "resigned_with_inferred_timestamp", "capture_time_invented_after_signing"]) & df.accepted].shape[0])),
                 decision_impact=dict(naive_wrong_verdict_rate_on_expected_reject=float(reject_expected.naive_wrong.mean()), verified_wrong_verdict_rate_on_expected_reject=float(reject_expected.verified_wrong.mean()),
                                      residual_verified_wrong_rate=float(resid.verified_wrong.mean()), residual_verified_degraded_rate=float(resid.verified_degraded.mean()), naive_degraded_vs_honest_evidence=float(reject_expected.naive_degraded.mean()), verified_degraded_vs_honest_evidence=float(reject_expected.verified_degraded.mean()),
                                      repair_decisions_triggered=int(df.repair_triggered.sum()), repair_rate_on_rejections=float(df[~df.accepted].repair_triggered.mean())),
                 latency_ms=dict(p50=pct(lat_a, 50), p95=pct(lat_a, 95), by_artifact_size=buckets),
                 time_to_certificate_invalidation=dict(read_time_verification_ms=dict(p50=pct(iv.ms, 50), p95=pct(iv.ms, 95), invalidated_fraction=float(iv.invalidated.mean())), periodic_audit_simulated=sched, note="read-time rows are measured wall-clock; periodic-audit rows are a simulated clock with uniform tamper times"),
                 timestamp_repair_policy=attempt_timestamp_repair({}), runtime_seconds=round(time.perf_counter() - t0, 1))
    ok = bool((~post.accepted).all()) and bool((~bytes_df.accepted).all()) and bool(legit.accepted.all()) and audit["detection"]["invented_timestamp_repairs_accepted"] == 0 and bool((~reject_expected.accepted).all()) and bool(resid.accepted.all())
    audit["pass_criteria"] = dict(all_post_signature_changes_detected=bool((~post.accepted).all()), no_false_rejects=bool(legit.accepted.all()), no_invented_timestamp_accepted=audit["detection"]["invented_timestamp_repairs_accepted"] == 0,
                                  residual_cases_reported_not_claimed_detected=bool(resid.accepted.all()), signature_not_treated_as_truth=audit["detection"]["signature_valid_but_rejected_by_policy"] > 0 and audit["detection"]["residual_accepted"]["accepted"] > 0, status="pass" if ok else "HALT_DOWNSTREAM_CERTIFICATION")
    audit["limitations"] = ["Controlled synthetic evidence; no real screenshots/HTML or live sites.", "HMAC with a verifier-held key is a symmetric stand-in; key compromise/transparency-log trust are outside the model.", "Evidence value is a synthetic marker classifier, not a phishing detector.",
                            "Replay inside the freshness window with no newer known version, and false content signed by a compromised collector, are undetectable here and are reported as residual acceptances."]
    (out / "audit.json").write_text(json.dumps(audit, indent=2, sort_keys=True, default=str), encoding="utf-8")
    if not ok: raise AssertionError("E10 integrity expectations failed; plots withheld: " + json.dumps(audit["pass_criteria"]))
    tex = [r"\begin{tabular}{llrrr}", r"scenario & class & rejected & naive wrong & verified wrong \\", r"\hline"]
    tex += [f"{r.scenario.replace('_', ' ')} & {r.cls} & {r.rejected:.2f} & {r.naive_wrong:.2f} & {r.verified_wrong:.2f} \\\\" for r in sm.itertuples()] + [r"\end{tabular}"]
    (tables / "e10_tamper.tex").write_text("\n".join(tex) + "\n", encoding="utf-8")
    if plots:
        import matplotlib; matplotlib.use("Agg")
        import matplotlib.pyplot as plt
        fig, ax = plt.subplots(1, 2, figsize=(14, 6), gridspec_kw=dict(width_ratios=[2, 1]))
        y = np.arange(len(sm)); ax[0].barh(y - .2, sm.rejected, .4, label="rejected"); ax[0].barh(y + .2, sm.verified_wrong, .4, label="wrong verdict after verification")
        ax[0].set_yticks(y); ax[0].set_yticklabels(sm.scenario, fontsize=6); ax[0].legend(fontsize=7); ax[0].set_xlabel("fraction of items")
        ax[1].bar(list(buckets), [b["p95_ms"] for b in buckets.values()]); ax[1].set_ylabel("p95 verify ms"); fig.tight_layout(); fig.savefig(out / "tamper_detection.png", dpi=120); plt.close(fig)
    return audit
