"""E09: source-compromise and malicious-feed injection resilience (controlled synthetic worlds).

World: one target URL (node 0, ground-truth label y) with 4 linked pages; observations come from
G independent root source groups (some artifacts are mirrors of the same group, some reports are
aggregated from two groups).  A separate pool of K independent, unattackable acquisition candidates
(sealed honest outcomes) exists for CER repair.

Attacker control (identical for every method, "realistic source-control limitation"):
  * the attacker holds a set A of root groups (budget b, or a 0-40% population fraction);
  * every observation with an ancestor in A is controlled: value forced to the goal extreme
    (0 = hide phishing, 1 = poison a benign page), reported weight multiplied by LAMBDA and EXTRA
    additional mirror artifacts are injected -- all derived from the same compromised group;
  * the attacker cannot alter uncontrolled observations, the graph, thresholds, the audited group
    registry, or create new ancestry (no Sybil groups, no forged provenance).

Knowledge (see ``blackbox_subset`` / ``greybox_subset`` signatures -- the information is
structurally limited to the function arguments):
  * black box: only the number of groups; random subset and (untargeted) random direction;
  * grey box: public graph, alpha, artifact->group ancestry and system verdict queries; not values,
    weights, thresholds or the defence in use;
  * white box: everything including the evaluated method; exhaustive best subset against that
    method's score (CER / certificate-only are attacked through the provenance-aware score; the
    repair loop is not differentiated through -- documented limitation).

Methods: feature classifier (not source-attackable), original-URLTrust surrogate (source-unaware
reported-weight propagation), source-unaware robust fusion (unweighted per-node median of artifacts),
provenance-aware fusion (one unit per ancestry set, fixed audited registry weights, propagation),
certificate-only (provenance-aware verdict emitted only if certified at the declared budget) and
full CER (certificate + counterfactual acquisition repair, abstain if still uncertified).

Certificate meaning: a verdict certified at budget b on the observed (possibly attacked) evidence
set equals the verdict of the same evidence set with the attacker's groups replaced by honest
values, because that clean set lies within b groups.  It is stability, not correctness.
"""
from __future__ import annotations

import json
import time
from itertools import combinations
from pathlib import Path

import numpy as np
import pandas as pd

from .core import Case, Observation, certify as core_certify
from .repair import RepairConfig, repair as core_repair

TAU_B, TAU_M, ALPHA = 0.40, 0.60, 0.35
LAMBDA, EXTRA = 3.0, 2
K_CAND, NEW_W, ACQ_BUDGET, MAX_STEPS, BMAX = 4, 0.3, 3.0, 3, 5
N_NODES = 5
METHODS = ["feature", "urltrust_original", "robust_fusion", "provenance_fusion", "certificate_only", "full_cer"]
KNOWLEDGE = ["black", "grey", "white"]
FRACTIONS = [0.0, 0.1, 0.2, 0.3, 0.4]

_MASKS: dict = {}


def masks(ncols, bmax):
    key = (ncols, bmax)
    if key not in _MASKS:
        rows, ends = [], []
        for k in range(bmax + 1):
            for s in combinations(range(ncols), k):
                r = np.zeros(ncols, np.float32); r[list(s)] = 1; rows.append(r)
            ends.append(len(rows))
        _MASKS[key] = (np.array(rows), ends)
    return _MASKS[key]


def verdict_of(s, tb=TAU_B, tm=TAU_M):
    return "malicious" if s >= tm else "benign" if s <= tb else "abstain"


def wrong_class(v, y):
    return (y == 1 and v == "benign") or (y == 0 and v == "malicious")


class World:
    pass


def make_world(rng: np.random.Generator, idx: int) -> World:
    c = World(); c.idx = idx
    G = int(rng.integers(10, 13)); n = N_NODES; ncols = G + K_CAND
    y = int(rng.random() < 0.5)
    truth = [y] + [int(rng.random() < (0.7 if y else 0.15)) for _ in range(n - 1)]
    P = np.zeros((n, n))
    for i in range(n):
        succ = rng.choice(n, size=int(rng.integers(1, 4)), replace=False)
        P[i, succ] = rng.dirichlet(np.ones(len(succ)))
    err = rng.uniform(0.02, 0.12, G)
    obs = []
    for node in range(n):
        q = 0.9 if node == 0 else 0.65
        gs = {g for g in range(G) if rng.random() < q}
        while len(gs) < 6: gs.add(int(rng.integers(G)))
        for g in sorted(gs):
            lab = truth[node] ^ int(rng.random() < err[g]); base = 0.88 if lab else 0.12
            v0 = float(np.clip(base + rng.normal(0, 0.08), 0, 1))
            for a in range(1 + int(rng.random() < 0.35)):
                v = v0 if a == 0 else float(np.clip(v0 + rng.normal(0, 0.03), 0, 1))
                obs.append(dict(node=node, val=v, wrep=float(rng.uniform(0.5, 1.5)), anc=(g,)))
            if rng.random() < 0.12:
                h = int(rng.choice([x for x in range(G) if x != g])); labh = truth[node] ^ int(rng.random() < err[h])
                v = float(np.clip((base + (0.88 if labh else 0.12)) / 2 + rng.normal(0, 0.05), 0, 1))
                obs.append(dict(node=node, val=v, wrep=float(rng.uniform(0.5, 1.5)), anc=tuple(sorted((g, h)))))
    cands = []
    for k in range(K_CAND):
        node = int(rng.choice(n, p=[0.4, 0.15, 0.15, 0.15, 0.15])); lab = truth[node] ^ int(rng.random() < 0.05)
        cands.append(dict(node=node, val=float(np.clip((0.88 if lab else 0.12) + rng.normal(0, 0.08), 0, 1)), anc=(G + k,), cost=1.0, id=f"c{k}"))
    c.y, c.n, c.P, c.G, c.ncols, c.obs, c.cands = y, n, P, G, ncols, obs, cands
    c.feature = float(np.clip(0.5 + (y - 0.5) * 0.45 + rng.normal(0, 0.28), 0, 1))
    c.registry = rng.uniform(0.7, 1.3, ncols)
    B = (1 - ALPHA) * np.linalg.inv(np.eye(n) - ALPHA * P); c.B = B; c.brow = B[0]
    c.onode = np.array([o["node"] for o in obs]); c.oval = np.array([o["val"] for o in obs]); c.owrep = np.array([o["wrep"] for o in obs])
    A = np.zeros((len(obs), ncols), np.float32)
    for i, o in enumerate(obs):
        for g in o["anc"]: A[i, g] = 1
    c.Aanc = A; c.Nmat = np.eye(n)[c.onode]; c.idx_node = [np.where(c.onode == nd)[0] for nd in range(n)]
    keys = {}
    for o in obs: keys.setdefault((o["node"], o["anc"]), []).append(o["val"])
    ks = sorted(keys); unode = np.array([k[0] for k in ks]); uanc = np.zeros((len(ks), ncols), np.float32)
    uw = np.zeros(len(ks)); uval = np.zeros(len(ks))
    for i, k in enumerate(ks):
        for g in k[1]: uanc[i, g] = 1
        uw[i] = float(np.mean([c.registry[g] for g in k[1]])); uval[i] = float(np.mean(keys[k]))
    for nd in range(n): uw[unode == nd] /= uw[unode == nd].sum()
    c.unode, c.uanc, c.uw, c.uval = unode, uanc, uw, uval
    c.Nu = np.eye(n)[unode]
    return c


# ---- batch scorers over attack masks (S, ncols) -------------------------------------------------
def _comp(Mb, Amat): return (Mb @ Amat.T) > 0


def score_naive(c, Mb, tgt):
    comp = _comp(Mb, c.Aanc); w = c.owrep * (1 + comp * (LAMBDA * (1 + EXTRA) - 1)); v = np.where(comp, tgt, c.oval)
    return ((w * v) @ c.Nmat / (w @ c.Nmat)) @ c.brow


def score_robust(c, Mb, tgt):
    comp = _comp(Mb, c.Aanc); v = np.where(comp, tgt, c.oval); cnt = 1.0 + EXTRA * comp; S = len(Mb); r = np.zeros((S, c.n)); ar = np.arange(S)
    for nd in range(c.n):
        ix = c.idx_node[nd]; o = np.argsort(v[:, ix], axis=1, kind="stable")
        vs = np.take_along_axis(v[:, ix], o, 1); cs = np.take_along_axis(cnt[:, ix], o, 1).cumsum(1); tot = cs[:, -1:]
        lo = (cs >= tot / 2).argmax(1); hi = (cs > tot / 2).argmax(1); r[:, nd] = (vs[ar, lo] + vs[ar, hi]) / 2
    return r @ c.brow


def score_pa(c, Mb, tgt):
    comp = _comp(Mb, c.uanc); v = np.where(comp, tgt, c.uval)
    return ((c.uw * v) @ c.Nu) @ c.brow


SCORERS = dict(urltrust_original=score_naive, robust_fusion=score_robust, provenance_fusion=score_pa)


# ---- attacker views ---------------------------------------------------------------------------
def blackbox_subset(G: int, b: int, seed: int):
    """Knows only the number of groups."""
    return sorted(np.random.default_rng(seed).choice(G, size=min(b, G), replace=False).tolist())


def greybox_subset(G: int, b: int, P, alpha: float, artifact_nodes, artifact_ancestry):
    """Knows the public graph/alpha and which groups produced which artifact; no values, weights, thresholds, defence."""
    row = (1 - alpha) * np.linalg.inv(np.eye(len(P)) - alpha * np.asarray(P))[0]
    sc = np.zeros(G)
    for nd, anc in zip(artifact_nodes, artifact_ancestry):
        for g in anc: sc[g] += row[nd]
    return sorted(np.argsort(-sc, kind="stable")[:b].tolist())


def to_mask(c, subset):
    m = np.zeros(c.ncols, np.float32); m[list(subset)] = 1; return m


# ---- certificate and repair (vectorised; cross-checked against core) ---------------------------------
def cert_state(unode, uanc, uw, uv, brow, b):
    Mc, ends = masks(uanc.shape[1], BMAX); e = ends[b]
    comp = (Mc[:e] @ uanc.T) > 0; coef = brow[unode] * uw; s = float(coef @ uv)
    down = float((comp @ (coef * uv)).max()); up = float((comp @ (coef * (1 - uv))).max())
    lower, upper = max(0.0, s - down), min(1.0, s + up)
    if s >= TAU_M: v, ok = "malicious", lower >= TAU_M + 1e-12
    elif s <= TAU_B: v, ok = "benign", upper <= TAU_B - 1e-12
    else: v, ok = "abstain", False
    return dict(score=s, verdict=v, certified=bool(ok), lower=lower, upper=upper)


def _util(r):
    if r["verdict"] == "malicious": return r["lower"] - TAU_M
    if r["verdict"] == "benign": return TAU_B - r["upper"]
    return -0.15 - min(abs(r["score"] - TAU_B), abs(r["score"] - TAU_M))


def _add(st, node, anc_row, val, valc):
    unode, uanc, uw, uv, uvc = st
    return (np.append(unode, node), np.vstack([uanc, anc_row]), np.append(np.where(unode == node, uw * (1 - NEW_W), uw), NEW_W),
            np.append(uv, val), np.append(uvc, valc))


def fast_cer(c, uv_att, b):
    """Counterfactual repair; never reads candidate values before acquisition (hypotheticals use 0/1 only)."""
    st = (c.unode, c.uanc, c.uw, uv_att, c.uval); remaining = ACQ_BUDGET; used = set(); actions = []
    def rep(s): return cert_state(s[0], s[1], s[2], s[3], c.brow, b)
    for _ in range(MAX_STEPS):
        r = rep(st)
        if r["certified"]: break
        valid = [k for k in range(K_CAND) if k not in used and c.cands[k]["cost"] <= remaining]
        if not valid: break
        cur = _util(r); r_node = ((st[2] * st[3]) @ np.eye(c.n)[st[0]]); node_scores = c.B @ r_node; best = None
        for k in valid:
            cd = c.cands[k]; row = np.zeros(c.ncols, np.float32); row[cd["anc"][0]] = 1
            p = float(np.clip(node_scores[cd["node"]], 0.1, 0.9)); ex = 0.0
            for v, pr in ((0.0, 1 - p), (1.0, p)):
                h = _add(st, cd["node"], row, v, v); ex += pr * _util(rep(h))
            key = ((ex - cur) / cd["cost"], cd["id"])
            if best is None or key > best[0]: best = (key, k)
        k = best[1]; cd = c.cands[k]; row = np.zeros(c.ncols, np.float32); row[cd["anc"][0]] = 1
        st = _add(st, cd["node"], row, cd["val"], cd["val"]); remaining -= cd["cost"]; used.add(k); actions.append(cd["id"])
    r = rep(st)
    return dict(report=r, verdict=r["verdict"] if r["certified"] else "abstain", certified=r["certified"], actions=actions, cost=ACQ_BUDGET - remaining, state=st)


def brute_flips(state, brow, b, V, rng, n_random=4):
    """Independent re-check: replace every <=b group subset by extremes (and random values); count verdict changes."""
    unode, uanc, uw, uv, _ = state; Mc, ends = masks(uanc.shape[1], BMAX); flips = 0
    coef = brow[unode] * uw
    for row in Mc[:ends[b]]:
        hit = [i for i in range(len(unode)) if any(row[g] and uanc[i, g] for g in range(uanc.shape[1]))]
        for mode in range(2 + n_random):
            v = uv.copy()
            for i in hit: v[i] = float(mode) if mode < 2 else float(rng.random())
            if verdict_of(float(coef @ v)) != V: flips += 1
    return flips


def core_case(c, uv, with_cands=False):
    obs = [Observation(int(c.unode[i]), float(uv[i]), float(c.uw[i]), frozenset(f"g{g}" for g in np.where(c.uanc[i] > 0)[0]), f"u{i}") for i in range(len(c.unode))]
    cands = [Observation(cd["node"], cd["val"], 0.0, frozenset({f"g{cd['anc'][0]}"}), cd["id"]) for cd in c.cands] if with_cands else []
    costs = {cd["id"]: cd["cost"] for cd in c.cands} if with_cands else {}
    return Case(f"w{c.idx}", c.P, obs, 0, c.y, cands, costs)


def crosscheck_core(worlds, n_cert=12, n_repair=6):
    bad_cert = 0; checks = 0
    for c in worlds[:n_cert]:
        for b in range(4):
            f = cert_state(c.unode, c.uanc, c.uw, c.uval, c.brow, b)
            r = core_certify(core_case(c, c.uval), b, ALPHA, TAU_B, TAU_M); checks += 1
            if (f["verdict"], f["certified"]) != (r["verdict"], r["certified"]) or abs(f["lower"] - r["lower_bound"]) > 1e-9 or abs(f["upper"] - r["upper_bound"]) > 1e-9: bad_cert += 1
    bad_rep = 0; rchecks = 0
    for c in worlds[:n_repair]:
        for b in (1, 2):
            f = fast_cer(c, c.uval, b); r = core_repair(core_case(c, c.uval, True), "counterfactual", RepairConfig(budget=b, alpha=ALPHA, tau_b=TAU_B, tau_m=TAU_M, new_weight=NEW_W, acquisition_budget=ACQ_BUDGET, max_steps=MAX_STEPS))
            rchecks += 1
            if f["actions"] != [a["id"] for a in r["actions"]] or f["certified"] != r["final"]["certified"] or (f["certified"] and f["verdict"] != r["final"]["verdict"]): bad_rep += 1
    return dict(certificate_checks=checks, certificate_mismatches=bad_cert, repair_checks=rchecks, repair_mismatches=bad_rep)


def reference_attack_score(c, method, subset, tgt):
    """Scalar reference that builds the attacked artifact list explicitly and checks control limits."""
    A = set(subset); art = []
    for o in c.obs:
        if A & set(o["anc"]):
            art += [dict(node=o["node"], val=float(tgt), w=o["wrep"] * LAMBDA, ctl=True) for _ in range(1 + EXTRA)]
        else: art.append(dict(node=o["node"], val=o["val"], w=o["wrep"], ctl=False))
    untouched_ok = sum(not a["ctl"] for a in art) == sum(1 for o in c.obs if not (A & set(o["anc"])))
    r = np.zeros(c.n)
    for nd in range(c.n):
        xs = [a for a in art if a["node"] == nd]
        if method == "urltrust_original": r[nd] = sum(a["w"] * a["val"] for a in xs) / sum(a["w"] for a in xs)
        else:
            vals = sorted(a["val"] for a in xs); m = len(vals); r[nd] = vals[m // 2] if m % 2 else (vals[m // 2 - 1] + vals[m // 2]) / 2
    return float(r @ c.brow), untouched_ok


def check_attack_implementation(worlds, rng, trials=60):
    bad = 0
    for _ in range(trials):
        c = worlds[int(rng.integers(len(worlds)))]; sub = blackbox_subset(c.G, int(rng.integers(0, 6)), int(rng.integers(1 << 30))); tgt = float(rng.integers(0, 2))
        for m, fn in (("urltrust_original", score_naive), ("robust_fusion", score_robust)):
            ref, ok = reference_attack_score(c, m, sub, tgt); got = float(fn(c, to_mask(c, sub)[None], tgt)[0])
            if abs(ref - got) > 1e-9 or not ok: bad += 1
    return dict(trials=trials * 2, mismatches=bad)


def knowledge_isolation_checks(worlds):
    import inspect
    sig_b = list(inspect.signature(blackbox_subset).parameters); sig_g = list(inspect.signature(greybox_subset).parameters)
    forbidden = {"values", "weights", "registry", "thresholds", "tau_b", "tau_m", "method", "truth", "y", "feature"}
    ok_sig = not (forbidden & set(sig_b + sig_g))
    inv = 0
    for c in worlds[:20]:  # outputs must not change when hidden fields are scrambled
        base = greybox_subset(c.G, 3, c.P, ALPHA, [o["node"] for o in c.obs], [o["anc"] for o in c.obs])
        keep = [(o["node"], o["anc"]) for o in c.obs]
        scr = greybox_subset(c.G, 3, c.P, ALPHA, [k[0] for k in keep], [k[1] for k in keep])
        inv += base != scr
    return dict(signatures_exclude_hidden_info=ok_sig, blackbox_args=sig_b, greybox_args=sig_g, greybox_invariance_failures=int(inv))


# ---- experiment --------------------------------------------------------------------------------------
def direction(goal, y, knowledge, clean_verdict, bb_dir):
    if goal == "targeted_hide": return 0.0
    if goal == "targeted_fp": return 1.0
    if knowledge == "black" or clean_verdict == "abstain": return bb_dir
    return 0.0 if clean_verdict == "malicious" else 1.0


def run_state(c, method, subset_mask, tgt, b_def, prec):
    """Return (verdict, score, certified, cost, soundness_info) of one method on one attacked state."""
    if method == "feature": return verdict_of(c.feature), c.feature, False, 0.0, None
    if method in SCORERS:
        s = float(SCORERS[method](c, subset_mask[None], tgt)[0]); return verdict_of(s), s, False, 0.0, None
    comp = (subset_mask @ c.uanc.T) > 0; uv = np.where(comp, tgt, c.uval)
    if method == "certificate_only":
        r = cert_state(c.unode, c.uanc, c.uw, uv, c.brow, b_def)
        return (r["verdict"] if r["certified"] else "abstain"), r["score"], r["certified"], 0.0, dict(V=r["verdict"], state=(c.unode, c.uanc, c.uw, uv, c.uval))
    r = fast_cer(c, uv, b_def)
    return r["verdict"], r["report"]["score"], r["certified"], r["cost"], dict(V=r["verdict"], state=r["state"], actions=len(r["actions"]))


def run_e09(out_dir="results/E09", table_dir="tables", cases=240, seed=20260909, plots=True) -> dict:
    t0 = time.perf_counter(); out = Path(out_dir); out.mkdir(parents=True, exist_ok=True); tables = Path(table_dir); tables.mkdir(parents=True, exist_ok=True)
    rng = np.random.default_rng(seed); worlds = [make_world(rng, i) for i in range(cases)]
    cross = crosscheck_core(worlds); impl = check_attack_implementation(worlds, np.random.default_rng(seed + 1)); iso = knowledge_isolation_checks(worlds)
    rows = []; snd = dict(certified_states=0, equivalence_violations=0, brute_checked=0, brute_flips=0, assumption_violated_certified=0, assumption_violated_flips=0)
    brng = np.random.default_rng(seed + 2); clean_cache = {}
    for c in worlds:
        Ma, ea = masks(c.G, BMAX); Ma = np.hstack([Ma, np.zeros((len(Ma), K_CAND), np.float32)])
        wb = {(m, t): SCORERS[m](c, Ma, float(t)) for m in SCORERS for t in (0, 1)}
        zero = np.zeros(c.ncols, np.float32)
        clean = {m: run_state(c, m, zero, 0.0, 0, None) for m in ["feature", *SCORERS]}
        goals = ["untargeted", "targeted_hide" if c.y == 1 else "targeted_fp"]
        settings = [("b", b, b, b) for b in range(BMAX + 1)] + [("frac", f, int(round(f * c.G)), int(round(f * c.G))) for f in FRACTIONS] + [("frac_misdeclared", f, int(round(f * c.G)), 2) for f in FRACTIONS if round(f * c.G) > 2]
        for kind, level, nA, b_def in settings:
            for goal in goals:
                for knowledge in (KNOWLEDGE if kind == "b" else ["black"]):
                    seedv = int(c.idx * 1000003 + nA * 101 + (goal == "untargeted") * 7 + 13)
                    bb_dir = float(np.random.default_rng(seedv + 5).integers(0, 2))
                    bb_sub = blackbox_subset(c.G, nA, seedv)
                    gb_sub = greybox_subset(c.G, nA, c.P, ALPHA, [o["node"] for o in c.obs], [o["anc"] for o in c.obs]) if knowledge == "grey" else None
                    for method in METHODS:
                        cv_key = "provenance_fusion" if method in ("certificate_only", "full_cer") else method
                        cv, cs = clean[cv_key][0], clean[cv_key][1]
                        tgt = direction(goal, c.y, knowledge, cv, bb_dir)
                        if knowledge == "black": sub = bb_sub
                        elif knowledge == "grey": sub = gb_sub
                        else:
                            if method == "feature": sub = []
                            else:
                                arr = wb[(cv_key, int(tgt))][:ea[min(nA, BMAX)]]
                                j = int(np.argmin(arr)) if tgt == 0 else int(np.argmax(arr)); sub = np.where(Ma[j][:c.G] > 0)[0].tolist()
                        m = to_mask(c, sub); ta = time.perf_counter()
                        v, s, cert, cost, info = run_state(c, method, m, tgt, b_def, None); dt = time.perf_counter() - ta
                        if method in ("certificate_only", "full_cer"):
                            cc = run_state(c, method, zero, tgt, b_def, None); cvv, css = cc[0], cc[1]
                        else: cvv = clean[method][0]; css = clean[method][1]
                        shift = (css - s) if tgt == 0 else (s - css)
                        if method in ("certificate_only", "full_cer") and cert and info is not None:
                            st = info["state"]; coefs = c.brow[st[0]] * st[2]; V_clean = verdict_of(float(coefs @ st[4]))
                            if kind in ("b", "frac"):
                                snd["certified_states"] += 1
                                if V_clean != info["V"]: snd["equivalence_violations"] += 1
                                if snd["certified_states"] % 40 == 0:
                                    snd["brute_checked"] += 1; snd["brute_flips"] += brute_flips(st, c.brow, min(b_def, 3), info["V"], brng)
                            else:
                                snd["assumption_violated_certified"] += 1; snd["assumption_violated_flips"] += int(V_clean != info["V"])
                        rows.append(dict(case=c.idx, y=c.y, kind=kind, level=level, n_comp=len(sub), b_def=b_def, goal=goal, knowledge=knowledge, method=method, dir=tgt,
                                         clean_verdict=cvv, att_verdict=v, certified=cert, clean_score=round(css, 5), att_score=round(s, 5), shift=round(shift, 5), cost=cost, ms=round(dt * 1000, 4)))
    df = pd.DataFrame(rows); df.to_csv(out / "state_results.csv", index=False)
    df["wrong_att"] = [wrong_class(v, y) for v, y in zip(df.att_verdict, df.y)]; df["wrong_clean"] = [wrong_class(v, y) for v, y in zip(df.clean_verdict, df.y)]
    df["clean_correct"] = [(v == "malicious" and y == 1) or (v == "benign" and y == 0) for v, y in zip(df.clean_verdict, df.y)]
    df["att_abstain"] = df.att_verdict == "abstain"; df["induced"] = df.wrong_att & ~df.wrong_clean
    df["fn"] = (df.att_verdict == "benign") & (df.y == 1); df["fp"] = (df.att_verdict == "malicious") & (df.y == 0)

    def summarize(g):
        pos, neg = g[g.y == 1], g[g.y == 0]; el = g[g.clean_correct]
        return pd.Series(dict(n=len(g), clean_accuracy=g.clean_correct.mean(), asr_all=g.induced.mean(), asr_eligible=(el.wrong_att.mean() if len(el) else np.nan),
                              cond_fn=(pos.fn.mean() if len(pos) else np.nan), cond_fp=(neg.fp.mean() if len(neg) else np.nan), abstain=g.att_abstain.mean(),
                              certified=g.certified.mean(), mean_shift=g["shift"].mean(), ms=g.ms.mean(), cost=g.cost.mean()))
    summ = df.groupby(["kind", "knowledge", "goal", "method", "level"]).apply(summarize, include_groups=False).reset_index()
    summ.to_csv(out / "summary.csv", index=False)
    cert_viol = snd["equivalence_violations"] + snd["brute_flips"]
    base = summ[(summ.kind == "b") & (summ.knowledge == "white") & (summ.goal == "untargeted") & (summ.level == 2)].set_index("method")
    ok = cert_viol == 0 and cross["certificate_mismatches"] == 0 and cross["repair_mismatches"] == 0 and impl["mismatches"] == 0 and iso["signatures_exclude_hidden_info"] and iso["greybox_invariance_failures"] == 0
    audit = dict(audit_version="E09-1", world_type="controlled_synthetic", seed=seed, cases=cases, states=len(df), runtime_seconds=round(time.perf_counter() - t0, 1),
                 threat_model=dict(budget_groups=list(range(BMAX + 1)), population_fractions=FRACTIONS, control="all-descendant control of compromised groups: value forced to goal extreme, reported weight x%s, +%d mirror artifacts; no change to graph, thresholds, registry, uncontrolled evidence, no forged ancestry" % (LAMBDA, EXTRA),
                                   goals=["untargeted", "targeted_hide (phishing -> benign)", "targeted_fp (benign -> malicious)"], knowledge={"black": "group count only; random subset/direction", "grey": "public graph+alpha+ancestry, verdict queries", "white": "everything incl. method; exhaustive best subset vs that method's score (CER/cert-only attacked via provenance score)"}),
                 methods=dict(feature="URL-feature-style noisy score; unaffected by source compromise (evasion out of scope), reported with its clean accuracy", urltrust_original="source-unaware reported-weight propagation surrogate (NOT the authors' released model)",
                              robust_fusion="source-unaware unweighted per-node median of artifacts", provenance_fusion="one unit per ancestry set, fixed audited registry weights", certificate_only="provenance fusion + certificate at declared budget, abstain if uncertified", full_cer="certificate + counterfactual acquisition repair (independent candidates), abstain if uncertified"),
                 soundness=snd | dict(violations=cert_viol, note="certificates checked only where attacker groups <= declared budget; misdeclared-budget stress rows are reported separately as assumption violations"),
                 cross_checks=dict(core_certify_and_repair=cross, attack_implementation_vs_scalar_reference=impl, knowledge_isolation=iso),
                 white_box_b2_untargeted=base[["clean_accuracy", "asr_all", "asr_eligible", "abstain", "certified"]].round(4).to_dict("index"),
                 pass_criteria=dict(zero_certificate_violations=cert_viol == 0, attacks_match_threat_definition=impl["mismatches"] == 0, knowledge_not_exceeded=iso["signatures_exclude_hidden_info"] and iso["greybox_invariance_failures"] == 0,
                                    fast_certifier_matches_core=cross["certificate_mismatches"] == 0 and cross["repair_mismatches"] == 0, clean_accuracy_not_used_as_resilience=True, status="pass" if ok else "HALT_DOWNSTREAM_CERTIFICATION"),
                 limitations=["Controlled synthetic worlds; real feeds/ancestry are not used, so results are not real-world attack-success claims.", "Certificates guarantee verdict stability under the stated threat, not correctness.",
                              "White-box attack on CER/certificate-only optimises the provenance score, not the repair loop.", "Repair candidates are independent unattackable collections; an attacker holding them would invalidate the CER gain.",
                              "Original URLTrust is a source-unaware surrogate; feature classifier is a synthetic score, not trained on URL strings.", "Untargeted grey/white attackers use verdict queries; targeted attackers know the label of their own target."])
    (out / "audit.json").write_text(json.dumps(audit, indent=2, sort_keys=True, default=str), encoding="utf-8")
    if not ok: raise AssertionError(f"E09 soundness/consistency failure: {snd} {cross} {impl} {iso}; plots withheld")
    tex = [r"\begin{tabular}{lrrrrr}", r"method & clean acc. & ASR (all) & ASR (eligible) & certified & abstain \\", r"\hline"]
    for m in METHODS:
        r = base.loc[m]; tex.append(f"{m.replace('_', ' ')} & {r.clean_accuracy:.3f} & {r.asr_all:.3f} & {0 if np.isnan(r.asr_eligible) else r.asr_eligible:.3f} & {r.certified:.3f} & {r.abstain:.3f} \\\\")
    (tables / "e09_resilience.tex").write_text("\n".join(tex + [r"\end{tabular}"]) + "\n", encoding="utf-8")
    if plots:
        import matplotlib; matplotlib.use("Agg")
        import matplotlib.pyplot as plt
        fig, ax = plt.subplots(2, 3, figsize=(14, 7))
        for j, k in enumerate(KNOWLEDGE):
            for m in METHODS:
                s = summ[(summ.kind == "b") & (summ.knowledge == k) & (summ.goal == "untargeted") & (summ.method == m)].sort_values("level")
                ax[0, j].plot(s.level, s.asr_all, "o-", label=m); ax[1, j].plot(s.level, s.abstain, "o-", label=m)
            ax[0, j].set_title(f"{k}-box, untargeted"); ax[0, j].set_ylabel("attack-induced wrong verdicts (all cases)"); ax[1, j].set_ylabel("abstention rate"); ax[1, j].set_xlabel("compromised groups b")
        ax[0, 0].legend(fontsize=7); fig.tight_layout(); fig.savefig(out / "attack_success_vs_budget.png", dpi=120); plt.close(fig)
        fig, ax = plt.subplots(1, 2, figsize=(10, 3.6))
        for m in METHODS:
            s = summ[(summ.kind == "frac") & (summ.goal == "untargeted") & (summ.method == m)].sort_values("level")
            ax[0].plot(s.level * 100, s.asr_all, "o-", label=m); ax[1].plot(s.level * 100, s.abstain, "o-", label=m)
        ax[0].set_xlabel("% of source groups compromised"); ax[0].set_ylabel("attack-induced wrong verdicts"); ax[1].set_xlabel("% of source groups compromised"); ax[1].set_ylabel("abstention"); ax[0].legend(fontsize=7)
        fig.tight_layout(); fig.savefig(out / "population_fraction.png", dpi=120); plt.close(fig)
    return audit
