"""E06: exact fixed-graph decision certificate and exhaustive soundness check.

The validator is independent of ``core.py``: it solves the propagation with
exact rational arithmetic, perturbs the observation values directly for every
attack subset, and re-applies the decision rule.  ``core.certify`` is only the
system under test.

Model (all assumptions are attached to the audit):
  * fixed row-stochastic P (dangling vertices are absorbing self-loops),
  * fixed intrinsic weights, per-node weights sum to one, influence in [0,1],
  * score = e_t^T (1-a)(I-aP)^-1 r with r_i = sum_o w_o v_o, a in [0,1),
  * attacker controls <= b ancestor groups and every observation having ANY
    controlled ancestor (all-descendant control) is set arbitrarily in [0,1];
    the score is linear in each value so the extremes 0 / 1 are optimal
    (re-checked with random interior perturbations),
  * decision: score >= tau_m malicious, score <= tau_b benign, else abstain;
    "flip" = any change of the original actionable verdict (including to abstain).
"""
from __future__ import annotations

import csv
import json
import random
import time
from fractions import Fraction as F
from itertools import combinations
from math import gcd
from pathlib import Path

import numpy as np

from .core import Case, Observation, certify, score_and_coefficients, worst_damage_safe_bound

ALPHAS = [F(0), F(1, 5), F(7, 20), F(4, 5), F(99, 100)]
TOL = 1e-9
MAX_GROUPS = 15
FULL_ENUM_GROUPS = 10  # exhaustive over all subset sizes up to here; else sizes <= CAP
CAP = 4


def exact_target_row(P, alpha, t):
    """Row t of B=(1-a)(I-aP)^-1 as Fractions via Gauss-Jordan on (I-aP)^T y=(1-a)e_t."""
    n = len(P)
    A = [[(F(1) if i == j else F(0)) - alpha * P[j][i] for j in range(n)] + [(1 - alpha) if i == t else F(0)] for i in range(n)]
    for c in range(n):
        p = next(r for r in range(c, n) if A[r][c] != 0)
        A[c], A[p] = A[p], A[c]
        piv = A[c][c]; A[c] = [x / piv for x in A[c]]
        for r in range(n):
            if r != c and A[r][c] != 0:
                f = A[r][c]; A[r] = [x - f * y for x, y in zip(A[r], A[c])]
    return [A[i][n] for i in range(n)]


def make_instance(rng: random.Random, idx: int) -> dict:
    alpha = ALPHAS[idx % len(ALPHAS)]
    n = rng.randint(2, 6)
    consensus = idx % 2 == 1  # many near-unanimous, mostly disjoint-ancestry cases so that certification at b>=1 is actually exercised
    if consensus: n = max(n, 3)
    P = []
    for i in range(n):
        mode = rng.random()
        if mode < 0.2: row = [F(1) if j == i else F(0) for j in range(n)]  # dangling -> absorbing
        else:
            cuts = sorted(rng.randint(0, 4) for _ in range(n - 1)); parts = [b - a for a, b in zip([0] + cuts, cuts + [4])]
            row = [F(x, 4) for x in parts]
        P.append(row)
    G = rng.randint(2, MAX_GROUPS); obs = []
    high = rng.random() < 0.5
    for node in range(n):
        k = rng.randint(4, 8) if consensus else rng.randint(1, 4)
        d = 12 if consensus else 4
        for _ in range(100):
            if consensus:
                w = [0] * k
                for _u in range(d): w[rng.randrange(k)] += 1
                break
            cuts = sorted(rng.randint(0, d) for _ in range(k - 1)); w = [b - a for a, b in zip([0] + cuts, cuts + [d])]
            if rng.random() > 0.25: break
            if sum(w) == d: break
        for wi in w:
            if consensus:
                anc = rng.sample(range(G), 1 if rng.random() < 0.85 else min(G, 2))
                v = (4 if high else 0) if rng.random() < 0.92 else rng.randint(0, 4)
            else:
                anc = rng.sample(range(G), 1 if rng.random() < 0.6 else min(G, rng.randint(2, 3))); v = rng.randint(0, 4)
            obs.append(dict(node=node, v=v, w=F(wi, d), anc=tuple(sorted(anc))))
    target = rng.randrange(n)
    row = exact_target_row(P, alpha, target)
    coef = [row[o["node"]] * o["w"] for o in obs]
    assert sum(coef) == 1
    L = 1
    for c in coef: L = L * c.denominator // gcd(L, c.denominator)
    cint = [int(c * L) for c in coef]
    S0 = sum(ci * o["v"] for ci, o in zip(cint, obs)); s0 = F(S0, 4 * L)
    tau_b, tau_m = F(rng.randint(1, 4), 10), F(rng.randint(6, 9), 10)
    if consensus: tau_b, tau_m = F(rng.randint(1, 3), 10), F(rng.randint(4, 6), 10)
    tie = idx % 7 == 0
    if tie:
        if rng.random() < 0.5 and s0 > 0: tau_m = s0; tau_b = min(tau_b, tau_m - F(1, 100))
        elif s0 < 1: tau_b = s0; tau_m = max(tau_m, tau_b + F(1, 100))
        tau_b, tau_m = max(F(0), tau_b), min(F(1), tau_m)
        if not tau_b < tau_m: tau_b, tau_m = F(3, 10), F(7, 10); tie = False
    return dict(idx=idx, alpha=alpha, n=n, P=P, obs=obs, target=target, cint=cint, L=L, S0=S0, tau_b=tau_b, tau_m=tau_m, tie=tie)


def to_case(inst: dict, strip_overlap: bool = False) -> Case:
    P = np.array([[float(x) for x in r] for r in inst["P"]])
    obs = [Observation(o["node"], o["v"] / 4, float(o["w"]), frozenset({f"g{o['anc'][0]}"} if strip_overlap else {f"g{a}" for a in o["anc"]}), f"o{i}")
           for i, o in enumerate(inst["obs"])]
    return Case(f"e06_{inst['idx']:05d}", P, obs, inst["target"], None, [], {}, "controlled_synthetic", {})


def verdict(S, inst):
    scale = 4 * inst["L"]
    if S >= inst["tau_m"] * scale: return "malicious"
    if S <= inst["tau_b"] * scale: return "benign"
    return "abstain"


def enumerate_attacks(inst):
    """All subsets up to kmax: per size, list of (S_down, S_up, subset); recomputed from perturbed values."""
    groups = sorted({a for o in inst["obs"] for a in o["anc"]}); G = len(groups)
    kmax = G if G <= FULL_ENUM_GROUPS else CAP
    masks = [sum(1 << groups.index(a) for a in o["anc"]) for o in inst["obs"]]
    by_size = {}
    for k in range(kmax + 1):
        rows = []
        for sub in combinations(range(G), k):
            m = sum(1 << g for g in sub)
            down = sum(c * (0 if mk & m else o["v"]) for c, o, mk in zip(inst["cint"], inst["obs"], masks))
            up = sum(c * (4 if mk & m else o["v"]) for c, o, mk in zip(inst["cint"], inst["obs"], masks))
            rows.append((down, up, tuple(f"g{groups[g]}" for g in sub)))
        by_size[k] = rows
    return groups, kmax, by_size


def check_instance(inst: dict, mutant: str | None = None, rng: random.Random | None = None) -> dict:
    t0 = time.perf_counter()
    groups, kmax, by_size = enumerate_attacks(inst); enum_s = time.perf_counter() - t0
    scale = 4 * inst["L"]; v0 = verdict(inst["S0"], inst); s0 = float(F(inst["S0"], scale))
    case = to_case(inst, strip_overlap=(mutant == "first_ancestor_only"))
    # exact cumulative extrema and first flip
    cum_min, cum_max, min_cost, witness = {}, {}, None, None
    lo, hi = inst["S0"], inst["S0"]
    for k in range(kmax + 1):
        for down, up, sub in by_size[k]:
            lo, hi = min(lo, down), max(hi, up)
            if min_cost is None and k > 0 and v0 != "abstain":
                for name, S in (("down", down), ("up", up)):
                    if verdict(S, inst) != v0: min_cost, witness = k, (sub, name, verdict(S, inst)); break
        cum_min[k], cum_max[k] = lo, hi
    out = dict(case_id=case.case_id, groups=len(groups), nodes=inst["n"], alpha=str(inst["alpha"]), tau_b=str(inst["tau_b"]), tau_m=str(inst["tau_m"]),
               score=s0, exact_verdict=v0, kmax_enumerated=kmax, exact_min_attack_cost=min_cost, witness_groups=list(witness[0]) if witness else None,
               witness_direction=witness[1] if witness else None, witness_flipped_to=witness[2] if witness else None)
    viol, cert_lb = [], None
    b_list = list(range(0, min(kmax, CAP) + 1))
    stats = dict(certified_calls=0, checks=0, exact_damage_mismatch=0, fallback_not_conservative=0, analytic_mismatch=0, bound_not_enclosing=0, float_tie_disagreement=0)
    s_core, coeffs, _ = score_and_coefficients(case, float(inst["alpha"]))
    if abs(s_core - s0) > TOL: viol.append(dict(kind="score_mismatch", core=s_core, exact=s0))
    for b in b_list:
        use_b = max(b - 1, 0) if mutant == "budget_minus_one" else b
        c = certify(case, use_b, float(inst["alpha"]), float(inst["tau_b"]), float(inst["tau_m"]))
        stats["checks"] += 1
        d_ex, u_ex = s0 - float(F(cum_min[b], scale)), float(F(cum_max[b], scale)) - s0
        if mutant is None:
            if abs(c["down_damage"] - d_ex) > TOL or abs(c["up_damage"] - u_ex) > TOL:
                stats["exact_damage_mismatch"] += 1; viol.append(dict(kind="damage_mismatch", budget=b, core=[c["down_damage"], c["up_damage"]], exact=[d_ex, u_ex]))
            fd, fu, *_ = worst_damage_safe_bound(case.observations, coeffs, b, exact_max_groups=0)
            if fd < d_ex - TOL or fu < u_ex - TOL:
                stats["fallback_not_conservative"] += 1; viol.append(dict(kind="fallback_bound_below_exact", budget=b, fallback=[fd, fu], exact=[d_ex, u_ex]))
            if c["lower_bound"] > s0 - d_ex + TOL or c["upper_bound"] < s0 + u_ex - TOL:
                stats["bound_not_enclosing"] += 1; viol.append(dict(kind="bounds_do_not_enclose_attacked_score", budget=b))
            # analytic group coverage: sum of b largest per-group contributions (upper bound; equality when ancestries are disjoint)
            per = {g: sum(float(ci) * o["v"] / 4 for ci, o in zip(coeffs, inst["obs"]) if int(g[1:]) in o["anc"]) for g in (f"g{x}" for x in groups)}
            ana = sum(sorted(per.values(), reverse=True)[:b])
            disjoint = all(len(o["anc"]) == 1 for o in inst["obs"])
            if ana < d_ex - TOL or (disjoint and abs(min(ana, sum(float(ci) * o["v"] / 4 for ci, o in zip(coeffs, inst["obs"]))) - d_ex) > TOL):
                stats["analytic_mismatch"] += 1; viol.append(dict(kind="group_coverage_analytic_mismatch", budget=b, analytic=ana, exact=d_ex, disjoint=disjoint))
        if c["verdict"] != v0 and c["certified"]:
            stats["float_tie_disagreement"] += 1; viol.append(dict(kind="certified_with_wrong_verdict", budget=b, core=c["verdict"], exact=v0))
        if c["certified"]:
            stats["certified_calls"] += 1
            for down, up, sub in (r for k in range(b + 1) for r in by_size[k]):
                for name, S in (("down", down), ("up", up)):
                    if verdict(S, inst) != v0:
                        viol.append(dict(kind="certified_but_flipped", budget=b, subset=list(sub), direction=name, attacked_score=float(F(S, scale)), original=v0, attacked=verdict(S, inst)))
        elif cert_lb is None: cert_lb = b
    out["certificate_cost_lower_bound"] = cert_lb if cert_lb is not None else f">{b_list[-1]}"
    out["certified_budgets"] = [b for b in b_list if b < (cert_lb if cert_lb is not None else 10 ** 9)]
    if mutant is None and rng is not None and v0 != "abstain":
        # linearity check: random interior perturbations of a random subset never beat the 0/1 extremes
        for _ in range(6):
            k = rng.randint(1, min(kmax, 3)); sub = rng.sample(groups, min(k, len(groups))); m = set(sub)
            vals = [F(rng.randint(0, 4), 4) if set(o["anc"]) & m else F(o["v"], 4) for o in inst["obs"]]
            S = sum(c * v * 4 for c, v in zip(inst["cint"], vals))
            if S < min(r[0] for kk in range(min(kmax, k) + 1) for r in by_size[kk]) or S > max(r[1] for kk in range(min(kmax, k) + 1) for r in by_size[kk]):
                viol.append(dict(kind="interior_perturbation_beats_extremes", subset=sub))
    out.update(violations=viol, stats=stats, enum_seconds=round(enum_s, 5))
    if min_cost is not None and cert_lb is not None and cert_lb > min_cost: out["lb_exceeds_exact"] = True
    return out


def _coverage(insts):
    cov = dict(cases=len(insts), alpha0=0, alpha_ge_099=0, ties=0, abstain=0, zero_weight_obs=0, overlap_multi_ancestor=0, shared_ancestor_across_nodes=0, dangling_absorbing=0, groups_min=99, groups_max=0)
    for i in insts:
        cov["alpha0"] += i["alpha"] == 0; cov["alpha_ge_099"] += i["alpha"] >= F(99, 100); cov["ties"] += i["tie"]
        cov["zero_weight_obs"] += any(o["w"] == 0 for o in i["obs"]); cov["overlap_multi_ancestor"] += any(len(o["anc"]) > 1 for o in i["obs"])
        by = {}
        for o in i["obs"]:
            for a in o["anc"]: by.setdefault(a, set()).add(o["node"])
        cov["shared_ancestor_across_nodes"] += any(len(v) > 1 for v in by.values())
        cov["dangling_absorbing"] += any(r[k] == 1 for k, r in enumerate(i["P"]))
        g = len(by); cov["groups_min"] = min(cov["groups_min"], g); cov["groups_max"] = max(cov["groups_max"], g)
        cov["abstain"] += verdict(i["S0"], i) == "abstain"
    return cov


def _csv(path, rows, cols):
    with path.open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=cols, extrasaction="ignore"); w.writeheader()
        for r in rows: w.writerow({c: json.dumps(r[c]) if isinstance(r.get(c), (list, dict)) else r.get(c) for c in cols})


def run_e06(out_dir: str = "results/E06", table_dir: str = "tables", n_cases: int = 1200, seed: int = 20260606, plots: bool = True) -> dict:
    out = Path(out_dir); tables = Path(table_dir); out.mkdir(parents=True, exist_ok=True); tables.mkdir(parents=True, exist_ok=True)
    t0 = time.perf_counter(); rng = random.Random(seed)
    insts = [make_instance(rng, i) for i in range(n_cases)]
    rows = [check_instance(i, rng=rng) for i in insts]
    runtime = time.perf_counter() - t0
    violations = [dict(case_id=r["case_id"], **v) for r in rows for v in r["violations"]]
    # detector controls: deliberately unsound certifiers must be caught, else the validator is too weak
    mut = {}
    for name in ("budget_minus_one", "first_ancestor_only"):
        mrows = [check_instance(i, mutant=name) for i in insts[: min(n_cases, 400)]]
        mut[name] = sum(len(r["violations"]) for r in mrows)
    detector_ok = all(v > 0 for v in mut.values())
    cov = _coverage(insts)
    agg = {k: sum(r["stats"][k] for r in rows) for k in rows[0]["stats"]} if rows else {}
    certified_by_budget = {b: sum(b in r["certified_budgets"] for r in rows) for b in range(CAP + 1)}
    gap = [r for r in rows if r["exact_min_attack_cost"] is not None and isinstance(r["certificate_cost_lower_bound"], int)]
    tight = sum(r["certificate_cost_lower_bound"] == r["exact_min_attack_cost"] for r in gap)
    ok = not violations and detector_ok
    audit = dict(
        audit_version="E06-1", world_type="controlled_synthetic", seed=seed, cases=n_cases, runtime_seconds=round(runtime, 3),
        assumptions=["fixed row-stochastic P; dangling vertices modelled as absorbing self-loops", "fixed intrinsic weights, per-node sum one, weights/values in [0,1]",
                     "attacker controls <= b ancestor groups with all-descendant control; controlled values arbitrary in [0,1] (0/1 extremes optimal by linearity, interior values sampled)",
                     "graph, weights, ancestry, thresholds unchanged; no graph-perturbation budget (graph_l1_budget=0)", "supported: 2..15 source groups; exhaustive over all sizes when <=10 groups, sizes <=4 above",
                     "flip = any change of original actionable verdict, abstention included; abstain verdicts are never certifiable"],
        coverage=cov, checks_per_budget=agg, certified_cases_by_budget=certified_by_budget,
        min_attack_cost=dict(cases_with_exact_cost=sum(r["exact_min_attack_cost"] is not None for r in rows), cases_with_cost_and_cert_lb=len(gap), cert_lb_equals_exact=tight,
                             cert_lb_never_exceeds_exact=not any(r.get("lb_exceeds_exact") for r in rows)),
        soundness=dict(violations=len(violations), kinds=sorted({v["kind"] for v in violations}), first_violations=violations[:20]),
        detector_controls=dict(mutant_violations=mut, detected=detector_ok),
        pass_criteria=dict(zero_violations=not violations, detector_controls_fire=detector_ok, status="pass" if ok else "HALT_DOWNSTREAM_CERTIFICATION"),
        limitations=["Controlled synthetic instances, not real provenance.", "Certificate semantics are restricted to the stated threat model; no claim under changed graph, weights or ancestry.",
                     "Exactness for >10 groups is limited to attack sizes <=4; larger costs are reported as lower bounds."])
    (out / "audit.json").write_text(json.dumps(audit, indent=2, sort_keys=True, default=str), encoding="utf-8")
    (out / "violations.jsonl").write_text("".join(json.dumps(v, default=str) + "\n" for v in violations), encoding="utf-8")
    if not ok:
        raise AssertionError(f"E06 soundness check failed ({len(violations)} violations, detector_ok={detector_ok}); downstream certification tables and plots withheld")
    _csv(out / "per_case_min_attack_cost.csv", rows, ["case_id", "groups", "nodes", "alpha", "tau_b", "tau_m", "score", "exact_verdict", "kmax_enumerated", "exact_min_attack_cost", "certificate_cost_lower_bound", "certified_budgets", "witness_direction", "witness_flipped_to"])
    _csv(out / "attack_witnesses.csv", [r for r in rows if r["witness_groups"]], ["case_id", "exact_verdict", "exact_min_attack_cost", "witness_groups", "witness_direction", "witness_flipped_to"])
    tex = [r"\begin{tabular}{lr}", r"Quantity & value \\", r"\hline", f"cases & {n_cases} \\\\", f"soundness violations & {len(violations)} \\\\"]
    tex += [f"certified at b={b} & {c} \\\\" for b, c in certified_by_budget.items()] + [f"lower bound = exact cost & {tight}/{len(gap)} \\\\", r"\end{tabular}"]
    (tables / "e06_soundness.tex").write_text("\n".join(tex) + "\n", encoding="utf-8")
    if plots:
        import matplotlib; matplotlib.use("Agg")
        import matplotlib.pyplot as plt
        fig, ax = plt.subplots(1, 2, figsize=(9, 3.5))
        ax[0].bar(list(certified_by_budget), list(certified_by_budget.values())); ax[0].set_xlabel("attack budget b"); ax[0].set_ylabel("cases certified (0 violations)")
        pts = [(r["exact_min_attack_cost"], r["certificate_cost_lower_bound"]) for r in gap]
        ax[1].scatter(*zip(*pts) if pts else ([], []), alpha=0.3, s=10); ax[1].plot([0, CAP + 1], [0, CAP + 1], "k--", lw=0.8)
        ax[1].set_xlabel("exact min attack cost"); ax[1].set_ylabel("certificate lower bound"); fig.tight_layout(); fig.savefig(out / "soundness_summary.png", dpi=130); plt.close(fig)
    return audit
