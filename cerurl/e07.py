"""E07: scaling exact certificates with integer / linear programming.

Per direction (down: attacker sets controlled values to 0, up: to 1) the
maximum-damage descendant-coverage problem is the binary program

    max  sum_o g_o y_o          g_o = c_o * v_o (down) or c_o * (1 - v_o) (up)
    s.t. sum_g cost_g x_g <= b
         y_o <= sum_{g in anc(o)} x_g          (o controlled only via a compromised ancestor)
         y_o >= x_g   for g in anc(o)          (all-descendant control / shared-ancestor consistency)
         x in {0,1}^G, 0 <= y_o <= 1

Certificate rule (direction aware): malicious needs s - D_down >= tau_m + eps,
benign needs s + D_up <= tau_b - eps, abstain is never certified.  Only
*upper bounds on damage* may certify:
  * ``milp``   : HiGHS dual bound (equals the optimum when solved to optimality; still a valid
                 bound after a timeout),
  * ``lp``     : LP relaxation,
  * ``knap``   : fractional knapsack over single-group contributions (valid for any overlap).
The greedy attack is a *lower* bound on damage (an optimistic attack) and is reported
only as empirical robustness, never as a guarantee.
"""
from __future__ import annotations

import csv
import json
import random
import time
from itertools import combinations
from pathlib import Path

import numpy as np
from scipy import sparse
from scipy.optimize import Bounds, LinearConstraint, milp

EPS = 1e-9
SIZES = (20, 50, 100, 500)
BUDGETS = (0, 1, 2, 3, 4, 5)
OVERLAPS = {"low": 1, "medium": 3, "high": 6}
DENSITIES = {"sparse": 0.08, "dense": 0.6}
ENUM_MAX_GROUPS = 20


def make_case(seed: int, G: int, overlap: str, density: str, costed: bool) -> dict:
    rng = np.random.default_rng(seed)
    n = 30; m = max(2 * G, n)
    P = (rng.random((n, n)) < DENSITIES[density]) * rng.random((n, n))
    for i in range(n):
        if P[i].sum() == 0: P[i, i] = 1.0  # dangling vertex -> absorbing
    P /= P.sum(axis=1, keepdims=True)
    alpha = float(rng.choice([0.0, 0.35, 0.8, 0.95]))
    B = (1 - alpha) * np.linalg.inv(np.eye(n) - alpha * P)
    node = np.concatenate([np.arange(n), rng.integers(0, n, m - n)])
    raw = rng.random(m) + 0.05; w = raw / np.bincount(node, raw, n)[node]
    c = B[int(rng.integers(n)), node] * w
    c = c / c.sum()
    high = rng.random() < 0.5
    v = np.where(rng.random(m) < 0.9, 1.0 if high else 0.0, rng.random(m))
    k = OVERLAPS[overlap]
    rows, cols = [], []
    for o in range(m):
        a = rng.choice(G, size=int(rng.integers(1, k + 1)), replace=False)
        rows += [o] * len(a); cols += list(a)
    M = sparse.csr_matrix((np.ones(len(rows)), (rows, cols)), shape=(m, G))  # obs x group
    cost = rng.integers(1, 3, G).astype(float) if costed else np.ones(G)
    s = float(c @ v)
    return dict(seed=seed, G=G, m=m, overlap=overlap, density=density, costed=costed, alpha=alpha, c=c, v=v, M=M, cost=cost, s=s,
                tau_b=float(rng.choice([0.2, 0.3, 0.4])), tau_m=float(rng.choice([0.5, 0.6, 0.7])))


def gains(case, direction):
    return case["c"] * (case["v"] if direction == "down" else 1 - case["v"])


def solve_milp(case, direction, b, integer=True, time_limit=10.0):
    """Returns dict(primal, dual_bound, status, seconds). dual_bound is a valid upper bound on max damage."""
    g = gains(case, direction); G, m, M = case["G"], case["m"], case["M"].tocoo()
    t0 = time.perf_counter()
    if b == 0 or g.sum() == 0:
        return dict(primal=0.0, bound=0.0, status="optimal", seconds=0.0, nodes=0, vars=G + m)
    cobj = np.concatenate([np.zeros(G), -g])
    cover = sparse.hstack([-case["M"], sparse.identity(m)]).tocsr()  # y_o - sum x <= 0
    link = sparse.hstack([sparse.csr_matrix((M.col * 0 + 1.0, (np.arange(M.nnz), M.col)), shape=(M.nnz, G)),
                          sparse.csr_matrix((-np.ones(M.nnz), (np.arange(M.nnz), M.row)), shape=(M.nnz, m))]).tocsr()  # x_g - y_o <= 0
    budget_row = sparse.csr_matrix(np.concatenate([case["cost"], np.zeros(m)])[None, :])
    cons = [LinearConstraint(budget_row, -np.inf, b), LinearConstraint(cover, -np.inf, 0), LinearConstraint(link, -np.inf, 0)]
    integrality = np.concatenate([np.ones(G) if integer else np.zeros(G), np.zeros(m)])
    res = milp(cobj, constraints=cons, integrality=integrality, bounds=Bounds(0, 1),
               options=dict(time_limit=time_limit, mip_rel_gap=0.0, disp=False))
    sec = time.perf_counter() - t0
    status = {0: "optimal", 1: "timeout"}.get(res.status, f"failed_{res.status}")
    primal = float(-res.fun) if res.x is not None and res.fun is not None else None
    dual = getattr(res, "mip_dual_bound", None)
    if status == "optimal" and not integer: bound = primal
    elif dual is not None and np.isfinite(dual): bound = float(-dual)
    elif status == "optimal": bound = primal
    else: bound = None  # no valid bound -> caller must treat as unknown
    return dict(primal=primal, bound=bound, status=status, seconds=sec, nodes=getattr(res, "mip_node_count", None), vars=G + m)


def knapsack_bound(case, direction, b):
    """Fractional knapsack on single-group contributions: valid upper bound for any overlap pattern."""
    g = gains(case, direction); contrib = case["M"].T @ g
    order = np.argsort(-contrib / case["cost"]); left, tot = float(b), 0.0
    for j in order:
        take = min(1.0, left / case["cost"][j]); tot += take * contrib[j]; left -= take * case["cost"][j]
        if left <= 0: break
    return float(min(tot, g.sum()))


def greedy_attack(case, direction, b):
    """Optimistic LOWER bound on damage (a concrete attack); empirical only."""
    g = gains(case, direction); M = case["M"].tocsc(); covered = np.zeros(case["m"], bool); left, dmg = float(b), 0.0
    while True:
        best, bj = 0.0, -1
        for j in range(case["G"]):
            if case["cost"][j] > left: continue
            rows = M.indices[M.indptr[j]:M.indptr[j + 1]]; gain = g[rows][~covered[rows]].sum() / case["cost"][j]
            if gain > best + 1e-15: best, bj = gain, j
        if bj < 0: break
        rows = M.indices[M.indptr[bj]:M.indptr[bj + 1]]; dmg += g[rows][~covered[rows]].sum(); covered[rows] = True; left -= case["cost"][bj]
    return float(dmg)


def enumerate_damage(case, direction, b):
    g = gains(case, direction); G = case["G"]; M = case["M"].tocsc()
    cov = [np.zeros(case["m"], bool) for _ in range(G)]
    for j in range(G): cov[j][M.indices[M.indptr[j]:M.indptr[j + 1]]] = True
    best = 0.0
    for k in range(1, b + 1):
        for sub in combinations(range(G), k):
            if case["cost"][list(sub)].sum() > b: continue
            mask = np.logical_or.reduce([cov[j] for j in sub]); best = max(best, float(g[mask].sum()))
    return best


def decide(case, down, up):
    s = case["s"]
    if s >= case["tau_m"]: return "malicious", s - down >= case["tau_m"] + EPS
    if s <= case["tau_b"]: return "benign", s + up <= case["tau_b"] - EPS
    return "abstain", False


def certified(case, down, up):
    if down is None or up is None: return False
    return decide(case, down, up)[1]


def rss_mb():
    """Peak process working set (MB): psutil if present, else the Windows API; None if unavailable."""
    try:
        import psutil; m = psutil.Process().memory_info(); return getattr(m, "peak_wset", m.rss) / 1e6
    except Exception:
        pass
    try:
        import ctypes
        from ctypes import wintypes
        class PMC(ctypes.Structure):
            _fields_ = [("cb", wintypes.DWORD), ("PageFaultCount", wintypes.DWORD), ("PeakWorkingSetSize", ctypes.c_size_t), ("WorkingSetSize", ctypes.c_size_t),
                        ("QuotaPeakPagedPoolUsage", ctypes.c_size_t), ("QuotaPagedPoolUsage", ctypes.c_size_t), ("QuotaPeakNonPagedPoolUsage", ctypes.c_size_t),
                        ("QuotaNonPagedPoolUsage", ctypes.c_size_t), ("PagefileUsage", ctypes.c_size_t), ("PeakPagefileUsage", ctypes.c_size_t)]
        pmc = PMC(); pmc.cb = ctypes.sizeof(PMC)
        k32 = ctypes.WinDLL("kernel32", use_last_error=True)
        k32.GetCurrentProcess.restype = wintypes.HANDLE
        k32.K32GetProcessMemoryInfo.argtypes = [wintypes.HANDLE, ctypes.POINTER(PMC), wintypes.DWORD]
        k32.K32GetProcessMemoryInfo.restype = wintypes.BOOL
        if k32.K32GetProcessMemoryInfo(k32.GetCurrentProcess(), ctypes.byref(pmc), pmc.cb): return pmc.PeakWorkingSetSize / 1e6
    except Exception:
        pass
    return None


def run_case(case, b, time_limit):
    out = dict(seed=case["seed"], G=case["G"], m=case["m"], overlap=case["overlap"], density=case["density"], costed=case["costed"], alpha=case["alpha"], b=b,
               score=case["s"], verdict=decide(case, 0, 0)[0])
    res = {d: solve_milp(case, d, b, True, time_limit) for d in ("down", "up")}
    lp = {d: solve_milp(case, d, b, False, time_limit) for d in ("down", "up")}
    kn = {d: knapsack_bound(case, d, b) for d in ("down", "up")}
    gr = {d: greedy_attack(case, d, b) for d in ("down", "up")}
    en = {d: enumerate_damage(case, d, b) for d in ("down", "up")} if case["G"] <= ENUM_MAX_GROUPS else None
    lpb = {d: lp[d]["bound"] for d in lp}
    out.update(milp_status="timeout" if any(r["status"] == "timeout" for r in res.values()) else ("optimal" if all(r["status"] == "optimal" for r in res.values()) else "failed"),
               milp_seconds=round(sum(r["seconds"] for r in res.values()), 4), lp_seconds=round(sum(r["seconds"] for r in lp.values()), 4),
               milp_down=res["down"]["primal"], milp_up=res["up"]["primal"], milp_bound_down=res["down"]["bound"], milp_bound_up=res["up"]["bound"],
               gap_down=None if res["down"]["bound"] is None or res["down"]["primal"] is None else res["down"]["bound"] - res["down"]["primal"],
               gap_up=None if res["up"]["bound"] is None or res["up"]["primal"] is None else res["up"]["bound"] - res["up"]["primal"],
               lp_down=lpb["down"], lp_up=lpb["up"], knap_down=kn["down"], knap_up=kn["up"], greedy_down=gr["down"], greedy_up=gr["up"],
               enum_down=en["down"] if en else None, enum_up=en["up"] if en else None, rss_mb=rss_mb())
    ex_d = en["down"] if en else res["down"]["primal"]; ex_u = en["up"] if en else res["up"]["primal"]
    out["reference"] = "enumeration" if en else "milp_primal"
    exact_ok = res["down"]["status"] == "optimal" and res["up"]["status"] == "optimal" or en is not None
    out["cert_exact"] = bool(exact_ok and certified(case, ex_d, ex_u))
    out["cert_milp"] = certified(case, res["down"]["bound"] + 1e-7 if res["down"]["bound"] is not None else None, res["up"]["bound"] + 1e-7 if res["up"]["bound"] is not None else None)
    out["cert_lp"] = certified(case, lpb["down"] + 1e-7 if lpb["down"] is not None else None, lpb["up"] + 1e-7 if lpb["up"] is not None else None)
    out["cert_knap"] = certified(case, kn["down"] + 1e-7, kn["up"] + 1e-7)
    out["empirically_robust_greedy"] = out["verdict"] != "abstain" and not (decide(case, gr["down"], gr["up"])[1] is False)
    viol = []
    tol = 1e-7
    for name, d, u in (("milp", res["down"]["bound"], res["up"]["bound"]), ("lp", lpb["down"], lpb["up"]), ("knap", kn["down"], kn["up"])):
        if d is not None and d < ex_d - tol or u is not None and u < ex_u - tol: viol.append(f"{name}_bound_below_exact")
    for name in ("milp", "lp", "knap"):
        if out[f"cert_{name}"] and not (exact_ok and certified(case, ex_d, ex_u)) and exact_ok: viol.append(f"{name}_certified_but_exact_not")
    if gr["down"] > ex_d + tol or gr["up"] > ex_u + tol: viol.append("greedy_attack_exceeds_exact")
    if en and (abs(en["down"] - res["down"]["primal"]) > 1e-7 and res["down"]["status"] == "optimal" or abs(en["up"] - res["up"]["primal"]) > 1e-7 and res["up"]["status"] == "optimal"): viol.append("milp_disagrees_with_enumeration")
    out["violations"] = viol
    return out


def _csv(path, rows, cols):
    with path.open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=cols, extrasaction="ignore"); w.writeheader(); w.writerows(rows)


def run_e07(out_dir="results/E07", table_dir="tables", sizes=SIZES, budgets=BUDGETS, reps=2, time_limit=10.0, seed=20260707, plots=True) -> dict:
    out = Path(out_dir); tables = Path(table_dir); out.mkdir(parents=True, exist_ok=True); tables.mkdir(parents=True, exist_ok=True)
    t0 = time.perf_counter(); rows, archive = [], {}; k = 0
    for G in sizes:
        for ov in OVERLAPS:
            for dn in DENSITIES:
                for r in range(reps):
                    k += 1; case = make_case(seed + k, G, ov, dn, costed=(r == 1))
                    key = f"case{k}"
                    archive[f"{key}_c"] = case["c"]; archive[f"{key}_v"] = case["v"]; archive[f"{key}_cost"] = case["cost"]
                    coo = case["M"].tocoo(); archive[f"{key}_rows"] = coo.row; archive[f"{key}_cols"] = coo.col
                    for b in budgets: rows.append(run_case(case, b, time_limit))
    np.savez_compressed(out / "solver_inputs.npz", **archive)
    with (out / "solver_outputs.jsonl").open("w", encoding="utf-8") as f:
        for r in rows: f.write(json.dumps(r) + "\n")
    cols = [c for c in rows[0] if c != "violations"] + ["violations"]
    _csv(out / "results.csv", [{**r, "violations": "|".join(r["violations"])} for r in rows], cols)
    viol = [dict(seed=r["seed"], G=r["G"], b=r["b"], kinds=r["violations"]) for r in rows if r["violations"]]
    checkable = [r for r in rows if r["reference"] == "enumeration" or r["milp_status"] == "optimal"]
    def stat(name):
        cert = [r for r in checkable if r["cert_exact"]]
        return dict(certified=sum(r[f"cert_{name}"] for r in checkable), false_unprotected=sum(r["cert_exact"] and not r[f"cert_{name}"] for r in checkable),
                    false_unprotected_rate=round(sum(not r[f"cert_{name}"] for r in cert) / len(cert), 4) if cert else None,
                    unsound=sum(r[f"cert_{name}"] and not r["cert_exact"] for r in checkable))
    by_size = {}
    for G in sizes:
        rs = [r for r in rows if r["G"] == G]
        by_size[G] = dict(cases=len(rs), timed_out=sum(r["milp_status"] == "timeout" for r in rs), fraction_timed_out=round(sum(r["milp_status"] == "timeout" for r in rs) / len(rs), 4),
                          median_milp_seconds=round(float(np.median([r["milp_seconds"] for r in rs])), 4), max_milp_seconds=round(max(r["milp_seconds"] for r in rs), 4),
                          certified_by_milp_bound=sum(r["cert_milp"] for r in rs), certified_by_lp=sum(r["cert_lp"] for r in rs), certified_by_knapsack=sum(r["cert_knap"] for r in rs),
                          greedy_empirically_robust_but_not_milp_certified=sum(r["empirically_robust_greedy"] and not r["cert_milp"] for r in rs),
                          max_rss_mb=max([r["rss_mb"] for r in rows if r["rss_mb"] and r["G"] == G], default=None))
    gaps = [max(r["gap_down"] or 0, r["gap_up"] or 0) for r in rows if r["gap_down"] is not None]
    ok = not viol
    audit = dict(audit_version="E07-1", world_type="controlled_synthetic", seed=seed, time_limit_seconds=time_limit, cases=len(rows),
                 sizes=list(sizes), budgets=list(budgets), solver="scipy.optimize.milp (HiGHS), mip_rel_gap=0; no licensed solver used",
                 formulation="binary program with cover, shared-ancestor consistency (y>=x), cost budget; see module docstring",
                 reference_for_soundness="exhaustive enumeration when G<=20, otherwise proven-optimal MILP; timed-out instances are excluded from the exact reference but still checked for bound validity only where a reference exists",
                 soundness=dict(violations=len(viol), first=viol[:20]), certifier_comparison={n: stat(n) for n in ("milp", "lp", "knap")},
                 by_size=by_size, max_optimality_gap=max(gaps) if gaps else None, enumeration_cases=sum(r["reference"] == "enumeration" for r in rows),
                 timeout_policy="a timeout may certify only through HiGHS's dual bound; if no valid bound exists the case is unknown/not certified", runtime_seconds=round(time.perf_counter() - t0, 2),
                 pass_criteria=dict(all_conservative_certificates_sound=ok, status="pass" if ok else "HALT_DOWNSTREAM_CERTIFICATION"),
                 limitations=["Controlled synthetic instances; propagation coefficients come from a random fixed graph.", "Greedy attack is an optimistic lower bound and never a guarantee.",
                              "Instances with G>20 are checked against the MILP optimum, not independent enumeration.", "Memory is the process peak working set (cumulative over the run, so not per-case); null when unavailable."])
    (out / "audit.json").write_text(json.dumps(audit, indent=2, sort_keys=True), encoding="utf-8")
    if not ok: raise AssertionError(f"E07 soundness violations: {viol[:3]}; plots withheld")
    tex = [r"\begin{tabular}{rrrrr}", r"G & timed out & median s & MILP cert. & knapsack cert. \\", r"\hline"]
    tex += [f"{G} & {v['fraction_timed_out']} & {v['median_milp_seconds']} & {v['certified_by_milp_bound']} & {v['certified_by_knapsack']} \\\\" for G, v in by_size.items()] + [r"\end{tabular}"]
    (tables / "e07_scaling.tex").write_text("\n".join(tex) + "\n", encoding="utf-8")
    if plots:
        import matplotlib; matplotlib.use("Agg")
        import matplotlib.pyplot as plt
        fig, ax = plt.subplots(1, 3, figsize=(13, 3.6))
        for name, lab in (("milp", "MILP bound"), ("lp", "LP relaxation"), ("knap", "knapsack")):
            ax[0].plot(list(budgets), [sum(r[f"cert_{name}"] for r in rows if r["b"] == b) for b in budgets], "o-", label=lab)
        ax[0].plot(list(budgets), [sum(r["cert_exact"] for r in rows if r["b"] == b) for b in budgets], "k--", label="exact reference"); ax[0].set_xlabel("b"); ax[0].set_ylabel("certified cases"); ax[0].legend(fontsize=7)
        pts = [(r["milp_down"], r["knap_down"], r["lp_down"]) for r in rows if r["milp_down"] is not None and r["milp_down"] > 0]
        if pts:
            a = np.array(pts); ax[1].scatter(a[:, 0], a[:, 1], s=8, alpha=.4, label="knapsack"); ax[1].scatter(a[:, 0], a[:, 2], s=8, alpha=.4, label="LP")
            mx = a.max(); ax[1].plot([0, mx], [0, mx], "k--", lw=.8)
        ax[1].set_xlabel("exact max damage (down)"); ax[1].set_ylabel("upper bound"); ax[1].legend(fontsize=7)
        ax[2].bar([str(G) for G in sizes], [by_size[G]["median_milp_seconds"] for G in sizes]); ax[2].set_ylabel("median MILP s"); ax[2].set_xlabel("ancestor groups")
        fig.tight_layout(); fig.savefig(out / "bound_tightness.png", dpi=130); plt.close(fig)
    return audit
