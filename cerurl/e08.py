"""E08: joint source + typed-graph attacks and the joint certificate.

Joint bound under validation (proof sketch in ``PROOF``):
  Let P be the clean row-stochastic matrix, Q any nonnegative row-stochastic matrix with
  max_i ||Q_i - P_i||_1 <= eps, B_X = (1-a)(I-aX)^-1, x_X(r) = B_X r.
  Then for r, r' in [0,1]^n and the target t
      |x_Q(r')_t - x_P(r)_t|  <=  |x_P(r')_t - x_P(r)_t|  +  a*eps / (2(1-a)).
  Matrix norm: Delta = Q-P is measured in the induced infinity norm (maximum absolute row sum,
  i.e. the row-wise l1 norm); B_Q is row stochastic so ||B_Q||_inf = 1; each Delta row sums to
  zero so |Delta_i y| <= (||Delta_i||_1 / 2) * range(y) <= ||Delta_i||_1 / 2 for y in [0,1]^n.
  Normalisation: propagation matrices are row stochastic (dangling pages are absorbing
  self-loops).  Regime: a in [0,1) for the proof; the certificate is *asserted* only for
  a <= ALPHA_ASSERT_MAX (numeric validation grid below) and is vacuous once a*eps/(2(1-a)) >= 1.
  Everything outside this domain abstains.

Graph snapshots are always recomputed from the typed edge list after every perturbation; a
fixed-graph certificate (eps = 0) is never applied to a changing graph.  The first term is the
E06 source-damage bound evaluated on the clean graph, so source and graph budgets add.

Typed graph model: each edge is ``hyperlink`` (insert / remove / reweight, bounded step m),
``redirect`` (mass may move only to a node of the same site as the original target) or
``structural`` (immutable).  Ops are applied to the row after renormalising it to total one, so a
single op changes the row by at most 2m in l1, and k ops by at most 2km.  Semantics-preserving
edits (edge splitting, row rescaling, zero-weight edges, node relabelling) leave Q unchanged and
cost no budget; this is checked numerically.
"""
from __future__ import annotations

import csv
import json
import random
import time
from collections import namedtuple
from itertools import combinations
from pathlib import Path

import numpy as np

from .core import Case, Observation, certify

HYPER, REDIR, STRUCT = "hyperlink", "redirect", "structural"
ALPHA_ASSERT_MAX = 0.95
ALPHAS = [0.0, 0.15, 0.3, 0.35, 0.5, 0.7, 0.9, 0.97]
BMAX, KMAX, M_STEP, POOL = 3, 3, 0.1, 22
TOL = 1e-9
Op = namedtuple("Op", "kind i j j2 amount")

PROOF = ("x_Q-x_P = (a/(1-a)) B_Q (Q-P) x_P because (I-aQ)^-1-(I-aP)^-1=(I-aQ)^-1 a (Q-P) (I-aP)^-1; "
         "B_Q row stochastic, Q-P rows sum to zero => |(Q-P)_i y| <= ||(Q-P)_i||_1/2 * range(y); range(x_P)<=1.")


class OpRejected(Exception):
    pass


def matrix(edges, n):
    P = np.zeros((n, n))
    for i, j, w, _ in edges:
        P[i, j] += w
    s = P.sum(1)
    for i in range(n):
        if s[i] <= 1e-15:
            P[i] = 0; P[i, i] = 1
        else:
            P[i] /= s[i]
    return P


def target_row(alpha, Q, t):
    n = len(Q)
    e = np.zeros(n); e[t] = 1 - alpha
    return np.linalg.solve((np.eye(n) - alpha * Q).T, e)


def _wt(edges, i, j, typ):
    return sum(w for a, b, w, ty in edges if a == i and b == j and ty == typ)


def _sub(edges, i, j, typ, d):
    out = []
    for a, b, w, ty in edges:
        if a == i and b == j and ty == typ and d > 0:
            take = min(w, d); d -= take; w -= take
            if w <= 1e-15: continue
        out.append((a, b, w, ty))
    return out


def apply_op(edges, site, open_nodes, op: Op):
    """Return a new typed edge list; raise OpRejected for anything outside the permitted types."""
    k, i, j, j2, m = op
    if not 0 < m < 1: raise OpRejected("bad_amount")
    tot = sum(w for a, _, w, _ in edges if a == i)
    if tot <= 0: raise OpRejected("empty_row")
    edges = [(a, b, w / tot, t) if a == i else (a, b, w, t) for a, b, w, t in edges]
    hw = _wt(edges, i, j, HYPER)
    if k == "insert_link":
        if hw > 0: raise OpRejected("edge_exists")
        if not (site[i] == site[j] or j in open_nodes): raise OpRejected("relation_type_forbids_link")
        return edges + [(i, j, m, HYPER)]
    if k == "reweight_up":
        if hw <= 0: raise OpRejected("no_hyperlink")
        return edges + [(i, j, m, HYPER)]
    if k == "reweight_down":
        if hw <= 0: raise OpRejected("no_hyperlink")
        return _sub(edges, i, j, HYPER, min(m, hw))
    if k == "remove_link":
        if hw <= 0: raise OpRejected("no_hyperlink")
        if hw > m + 1e-12: raise OpRejected("edge_too_heavy_for_budget")
        return _sub(edges, i, j, HYPER, hw)
    if k == "redirect":
        rw = _wt(edges, i, j, REDIR)
        if rw <= 0: raise OpRejected("not_a_redirect_edge")
        if j2 == j or site[j2] != site[j]: raise OpRejected("redirect_leaves_site")
        d = min(m, rw)
        return _sub(edges, i, j, REDIR, d) + [(i, j2, d, REDIR)]
    raise OpRejected("unknown_op")


def candidate_ops(edges, n, site, open_nodes, m):
    out = []
    for i in range(n):
        for j in range(n):
            for k in ("insert_link", "reweight_up", "reweight_down", "remove_link"):
                try: apply_op(edges, site, open_nodes, Op(k, i, j, None, m)); out.append(Op(k, i, j, None, m))
                except OpRejected: pass
            for j2 in range(n):
                try: apply_op(edges, site, open_nodes, Op("redirect", i, j, j2, m)); out.append(Op("redirect", i, j, j2, m))
                except OpRejected: pass
    return out


def semantic_variants(edges, n, rng):
    """Semantics-preserving edits: split an edge, rescale a row, add a zero-weight edge."""
    out = []
    e = edges[rng.randrange(len(edges))]
    out.append([x for x in edges if x is not e] + [(e[0], e[1], e[2] / 2, e[3]), (e[0], e[1], e[2] / 2, e[3])])
    i = rng.randrange(n); c = rng.uniform(.3, 3)
    out.append([(a, b, w * c, t) if a == i else (a, b, w, t) for a, b, w, t in edges])
    out.append(edges + [(rng.randrange(n), rng.randrange(n), 0.0, HYPER)])
    return out


def typing_violations(clean, final, site, open_nodes):
    """Independent re-check that the realised graph respects relation types."""
    bad = []
    pairs = lambda es, ty: {(a, b) for a, b, w, t in es if t == ty and w > 1e-12}
    if pairs(clean, STRUCT) != pairs(final, STRUCT): bad.append("structural_changed")
    for a, b in pairs(final, HYPER) - pairs(clean, HYPER):
        if not (site[a] == site[b] or b in open_nodes): bad.append("illegal_link")
    cr = pairs(clean, REDIR)
    for a, b in pairs(final, REDIR) - cr:
        if not any(a == x and site[b] == site[y] for x, y in cr): bad.append("illegal_redirect")
    return bad


def make_case(rng: random.Random, idx: int) -> dict:
    alpha = ALPHAS[idx % len(ALPHAS)]
    n = rng.randint(4, 6); site = [i // 2 for i in range(n)]; open_nodes = {rng.randrange(n)}
    edges = []
    for i in range(n):
        if rng.random() < 0.1:
            edges.append((i, i, 1.0, STRUCT)); continue
        targets = rng.sample(range(n), rng.randint(2, 3)); ws = [rng.randint(1, 4) for _ in targets]; z = sum(ws)
        for pos, (j, w) in enumerate(zip(targets, ws)):
            typ = HYPER if pos == 0 else rng.choice([HYPER, REDIR, STRUCT])
            edges.append((i, j, w / z, typ))
    G = rng.randint(6, 8); obs = []
    level = {i: rng.random() < 0.5 for i in range(n)}
    target = rng.randrange(n); level[target] = rng.random() < 0.6
    for node in range(n):
        k = rng.randint(4, 8); w = [0] * k
        for _ in range(12): w[rng.randrange(k)] += 1
        for wi in w:
            anc = tuple(sorted(rng.sample(range(G), 1 if rng.random() < 0.85 else 2)))
            v = (0.95 if level[node] else 0.05) if rng.random() < 0.92 else rng.choice([0.05, 0.5, 0.95])
            obs.append(dict(node=node, v=v, w=wi / 12, anc=anc))
    return dict(idx=idx, alpha=alpha, n=n, site=site, open=open_nodes, edges=edges, obs=obs, target=target, G=G,
                tau_b=rng.choice([0.15, 0.25, 0.35]), tau_m=rng.choice([0.45, 0.55, 0.65]))


def to_core(spec) -> Case:
    P = matrix(spec["edges"], spec["n"])
    obs = [Observation(o["node"], o["v"], o["w"], frozenset(f"g{a}" for a in o["anc"]), f"o{i}") for i, o in enumerate(spec["obs"])]
    return Case(f"e08_{spec['idx']:04d}", P, obs, spec["target"], None, [], {}, "controlled_synthetic", {})


def verdict_of(s, tb, tm):
    return "malicious" if s >= tm else "benign" if s <= tb else "abstain"


class Evaluator:
    """Independent attacked-score evaluator over all <=BMAX source-group subsets."""

    def __init__(self, spec):
        self.spec = spec; self.G = spec["G"]
        self.node = np.array([o["node"] for o in spec["obs"]]); self.w = np.array([o["w"] for o in spec["obs"]]); self.v = np.array([o["v"] for o in spec["obs"]])
        A = np.zeros((len(spec["obs"]), self.G))
        for r, o in enumerate(spec["obs"]):
            for a in o["anc"]: A[r, a] = 1
        subs = [s for k in range(BMAX + 1) for s in combinations(range(self.G), k)]
        X = np.zeros((len(subs), self.G))
        for r, s in enumerate(subs): X[r, list(s)] = 1
        self.subsets = subs; self.M = ((X @ A.T) > 0).astype(float)
        self.end = [sum(len(s) <= b for s in subs) for b in range(BMAX + 1)]

    def coeff(self, Q):
        return target_row(self.spec["alpha"], Q, self.spec["target"])[self.node] * self.w

    def score(self, Q):
        return float(self.coeff(Q) @ self.v)

    def worst(self, Q):
        c = self.coeff(Q); cv = c * self.v; s = float(cv.sum())
        dn = self.M @ cv; up = self.M @ (c - cv)
        return s, [s - dn[:e].max() for e in self.end], [s + up[:e].max() for e in self.end], dn, up


def search_case(spec, ev: Evaluator, verdict, m=M_STEP, pool=POOL, kmax=KMAX):
    """Exhaustive typed-op search over a pool of the strongest single ops, all source subsets <=BMAX."""
    n, edges, site, op_ = spec["n"], spec["edges"], spec["site"], spec["open"]
    P = matrix(edges, n)
    def key(res):  # smaller is more damaging
        return res[1] if verdict == "malicious" else [-u for u in res[2]]
    best = {j: [(np.inf, None, None)] * (BMAX + 1) for j in range(kmax + 1)}
    stats = dict(sequences=0, rejected=0, cost_cap_violations=0, typing_violations=0)
    def consider(j, Q, ops, res):
        kv = key(res); idx = res[3] if verdict == "malicious" else res[4]
        for b in range(BMAX + 1):
            if kv[b] < best[j][b][0]:
                sl = idx[:ev.end[b]]
                best[j][b] = (kv[b], ops, ev.subsets[int(np.argmax(sl))])
    res0 = ev.worst(P); consider(0, P, (), res0)
    cands = candidate_ops(edges, n, site, op_, m)
    scored = []
    for op in cands:
        Q = matrix(apply_op(edges, site, op_, op), n); r = ev.worst(Q); scored.append((key(r)[BMAX], op))
    scored.sort(key=lambda t: t[0]); pool_ops = [o for _, o in scored[:pool]]
    for j in range(1, kmax + 1):
        for combo in combinations(pool_ops, j):
            stats["sequences"] += 1
            cur = edges
            try:
                for op in combo: cur = apply_op(cur, site, op_, op)
            except OpRejected:
                stats["rejected"] += 1; continue
            Q = matrix(cur, n)
            if np.abs(Q - P).sum(1).max() > 2 * j * m + TOL: stats["cost_cap_violations"] += 1
            if typing_violations(edges, cur, site, op_): stats["typing_violations"] += 1
            consider(j, Q, combo, ev.worst(Q))
    cum = {}
    for k in range(kmax + 1):
        cum[k] = []
        for b in range(BMAX + 1):
            c = min((best[j][b] for j in range(k + 1)), key=lambda t: t[0])
            cum[k].append(c)
    return cum, stats, len(cands)


def regime_gate(alpha, eps, tau_b, tau_m, Q=None, P=None):
    """Reasons for which the joint certificate must abstain (empty list = inside the validation domain)."""
    why = []
    if not 0 <= alpha <= ALPHA_ASSERT_MAX: why.append("alpha_outside_validated_domain")
    if not 0 <= eps <= 2: why.append("edge_budget_outside_[0,2]")
    elif 0 <= alpha < 1 and alpha * eps / (2 * (1 - alpha)) >= 1: why.append("graph_term_vacuous")
    if not 0 <= tau_b < tau_m <= 1: why.append("bad_thresholds")
    if Q is not None:
        Q = np.asarray(Q, float)
        if (Q < -1e-12).any() or not np.allclose(Q.sum(1), 1, atol=1e-9): why.append("Q_not_row_stochastic")
        if P is not None and np.abs(Q - np.asarray(P)).sum(1).max() > eps + 1e-9: why.append("Q_outside_l1_ball")
    return why


def joint_certificate(spec, case, b, k, m=M_STEP):
    eps = min(2.0, 2 * k * m)
    why = regime_gate(spec["alpha"], eps, spec["tau_b"], spec["tau_m"])
    if "alpha_outside_validated_domain" in why or "bad_thresholds" in why or "edge_budget_outside_[0,2]" in why:
        return dict(status="abstain_unknown_regime", certified=False, reasons=why, eps=eps)
    c = certify(case, b, spec["alpha"], spec["tau_b"], spec["tau_m"], graph_l1_budget=eps)
    st = "certified" if c["certified"] else ("abstain_vacuous_graph_term" if why else "not_certified")
    return dict(status=st, certified=bool(c["certified"]) and not why, lower=c["lower_bound"], upper=c["upper_bound"], verdict=c["verdict"], eps=eps, reasons=why)


def property_checks(trials=6000, seed=808):
    """Numeric validation of the joint bound over random and extremal (P, Q, r, source attack)."""
    rng = random.Random(seed); nrng = np.random.default_rng(seed)
    grid = [0.0, 0.1, 0.35, 0.5, 0.8, 0.95, 0.99]
    viol = 0; worst_ratio = 0.0; cnt = dict(random=0, extremal=0, pure_graph=0)
    for tno in range(trials):
        n = rng.randint(2, 8); a = rng.choice(grid); eps = rng.choice([0.05, 0.2, 0.5, 1.0, 2.0])
        P = nrng.dirichlet(np.ones(n) * rng.choice([.3, 1.0]), n)
        for i in range(n):
            if rng.random() < .15: P[i] = 0; P[i, i] = 1
        r = nrng.random(n) if tno % 2 else nrng.integers(0, 2, n).astype(float)
        x = (1 - a) * np.linalg.solve(np.eye(n) - a * P, r)
        mode = "extremal" if tno % 3 == 0 else "random"
        Q = P.copy()
        for i in range(n):
            R = np.zeros(n)
            if mode == "extremal": R[int(np.argmax(x) if rng.random() < .5 else np.argmin(x))] = 1
            else: R = nrng.dirichlet(np.ones(n))
            d = np.abs(R - P[i]).sum()
            lam = 1.0 if d <= eps else eps / d
            Q[i] = P[i] + lam * (R - P[i])
        if tno % 5 == 0: Q = P.copy(); Q[0] = (1 - min(1, eps / 2)) * P[0] + min(1, eps / 2) * (np.eye(n)[n - 1]); mode = "random"
        e_real = np.abs(Q - P).sum(1).max(); assert e_real <= eps + 1e-9 and (Q >= -1e-12).all() and np.allclose(Q.sum(1), 1)
        gp = a * eps / (2 * (1 - a))
        t = rng.randrange(n)
        yP = target_row(a, P, t); yQ = target_row(a, Q, t)
        k_obs = rng.randint(1, 6); nodes = [rng.randrange(n) for _ in range(k_obs)]
        # source attack: perturb the prior r through one controlled node's mass, extremes 0/1
        S = rng.random() < 0.5
        r2 = r.copy()
        if S:
            for nd in nodes: r2[nd] = float(rng.randint(0, 1))
        else: cnt["pure_graph"] += 1
        sP = yP @ r; src = abs(yP @ r2 - sP); sQ = yQ @ r2
        ratio = (abs(sQ - sP) - src) / gp if gp > 1e-12 else 0.0
        worst_ratio = max(worst_ratio, ratio, 0.0)
        if abs(sQ - sP) > src + gp + TOL: viol += 1
        cnt[mode] += 1
    # negative control: substochastic Q breaks the bound and must be rejected by the gate
    P = np.eye(2); Q = np.zeros((2, 2)); a = 0.2; eps = 1.0
    gp = a * eps / (2 * (1 - a)); dev = abs(target_row(a, Q, 0) @ np.ones(2) - target_row(a, P, 0) @ np.ones(2))
    neg = dict(deviation=float(dev), bound=gp, bound_violated=bool(dev > gp), gate_rejects=bool(regime_gate(a, eps, .3, .7, Q, P)))
    return dict(trials=trials, assertion_violations=viol, max_observed_over_bound=round(worst_ratio, 6), modes=cnt, alpha_grid=grid, negative_control_non_stochastic_Q=neg)


def semantic_checks(specs, rng):
    n_chk = 0; bad = 0
    for sp in specs:
        P = matrix(sp["edges"], sp["n"]); ev = Evaluator(sp); s0 = ev.score(P)
        for var in semantic_variants(sp["edges"], sp["n"], rng):
            n_chk += 1; Q = matrix(var, sp["n"])
            if np.abs(Q - P).max() > 1e-12 or abs(ev.score(Q) - s0) > 1e-12: bad += 1
        perm = list(range(sp["n"])); rng.shuffle(perm); inv = {a: b for b, a in enumerate(perm)}
        Qp = np.zeros_like(P)
        for i in range(sp["n"]):
            for j in range(sp["n"]): Qp[inv[i], inv[j]] = P[i, j]
        y = target_row(sp["alpha"], Qp, inv[sp["target"]]); r = np.zeros(sp["n"])
        for o in sp["obs"]: r[inv[o["node"]]] += o["w"] * o["v"]
        n_chk += 1
        if abs(float(y @ r) - s0) > 1e-9: bad += 1
    return dict(checks=n_chk, violations=bad)


def typed_rejection_controls():
    edges = [(0, 1, .5, HYPER), (0, 2, .5, REDIR), (1, 1, 1.0, STRUCT), (2, 2, 1.0, STRUCT)]
    site = [0, 0, 1]; cases = [Op("insert_link", 1, 2, None, .1), Op("reweight_down", 1, 1, None, .1), Op("redirect", 0, 1, 0, .1),
                               Op("redirect", 0, 2, 0, .1), Op("remove_link", 0, 1, None, .1), Op("insert_link", 0, 1, None, .1)]
    out = []
    for op in cases:
        try: apply_op(edges, site, set(), op); out.append((op.kind, "accepted"))
        except OpRejected as e: out.append((op.kind, str(e)))
    return out


def run_e08(out_dir="results/E08", table_dir="tables", cases=96, seed=20260808, random_trials=40, prop_trials=6000, plots=True) -> dict:
    t0 = time.perf_counter(); out = Path(out_dir); out.mkdir(parents=True, exist_ok=True); tables = Path(table_dir); tables.mkdir(parents=True, exist_ok=True)
    rng = random.Random(seed); specs = [make_case(rng, i) for i in range(cases)]
    prop = property_checks(prop_trials, seed + 1); sem = semantic_checks(specs[:40], random.Random(seed + 2)); ctrl = typed_rejection_controls()
    rows, wit = [], []
    counters = dict(certificates_asserted=0, flips_of_certified=0, bound_violations=0, cost_cap_violations=0, typing_violations=0, random_trials=0,
                    random_bound_violations=0, random_flips_of_certified=0, unknown_regime_cases=0, unknown_regime_certified=0, fixed_certificate_misapplied_flips=0,
                    fixed_certificates_considered=0, sequences=0, rejected_sequences=0)
    runtime = dict(attack_seconds=0.0, certify_seconds=0.0)
    nrng = random.Random(seed + 3)
    for sp in specs:
        case = to_core(sp); ev = Evaluator(sp); P = matrix(sp["edges"], sp["n"]); s0 = ev.score(P); verdict = verdict_of(s0, sp["tau_b"], sp["tau_m"])
        indomain = sp["alpha"] <= ALPHA_ASSERT_MAX
        cum = None
        if verdict != "abstain":
            ta = time.perf_counter(); cum, st, ncand = search_case(sp, ev, verdict); runtime["attack_seconds"] += time.perf_counter() - ta
            counters["cost_cap_violations"] += st["cost_cap_violations"]; counters["typing_violations"] += st["typing_violations"]
            counters["sequences"] += st["sequences"]; counters["rejected_sequences"] += st["rejected"]
        if not indomain: counters["unknown_regime_cases"] += 1
        cands = candidate_ops(sp["edges"], sp["n"], sp["site"], sp["open"], M_STEP)
        certs = {}
        for b in range(BMAX + 1):
            for k in range(KMAX + 1):
                tc = time.perf_counter(); c = joint_certificate(sp, case, b, k); runtime["certify_seconds"] += time.perf_counter() - tc; certs[(b, k)] = c
                worst = flip = None; slack = None; witness = None
                if cum is not None:
                    val, ops, subset = cum[k][b]; worst = val if verdict == "malicious" else -val
                    flip = bool(worst < sp["tau_m"] - TOL) if verdict == "malicious" else bool(worst > sp["tau_b"] + TOL)
                    witness = (ops, subset)
                    if c.get("certified"):
                        counters["certificates_asserted"] += 1
                        if flip: counters["flips_of_certified"] += 1; wit.append(dict(case=case.case_id, b=b, k=k, kind="VIOLATION", ops=str(ops), subset=str(subset), worst=worst))
                        lo, up = c["lower"], c["upper"]
                        if worst < lo - TOL if verdict == "malicious" else worst > up + TOL: counters["bound_violations"] += 1
                    if "lower" in c: slack = (worst - c["lower"]) if verdict == "malicious" else (c["upper"] - worst)
                    if k >= 1 and indomain:
                        fx = certs.get((b, 0))
                        if fx and fx.get("certified"):
                            counters["fixed_certificates_considered"] += 1
                            if flip: counters["fixed_certificate_misapplied_flips"] += 1
                    if flip and len(wit) < 400 and not c.get("certified") and (b, k) in ((1, 0), (0, 1), (1, 1), (2, 2), (3, 3)):
                        wit.append(dict(case=case.case_id, b=b, k=k, kind="attack_flip", ops=str(ops), subset=str(subset), worst=round(worst, 6)))
                if not indomain and c.get("certified"): counters["unknown_regime_certified"] += 1
                rows.append(dict(case=case.case_id, alpha=sp["alpha"], in_domain=indomain, verdict=verdict, score=round(s0, 6), b=b, k=k, status=c["status"], certified=bool(c.get("certified")),
                                 lower=c.get("lower"), upper=c.get("upper"), eps=c["eps"], attack_worst_score=None if worst is None else round(worst, 6), attack_flips=flip,
                                 bound_slack=None if slack is None else round(slack, 6)))
        if verdict != "abstain" and indomain:
            cl = certs[(BMAX, KMAX)]
            for _ in range(random_trials):
                j = nrng.randint(1, KMAX); cur = sp["edges"]; ok = True
                for _o in range(j):
                    op = nrng.choice(cands)
                    try: cur = apply_op(cur, sp["site"], sp["open"], op._replace(amount=nrng.uniform(.01, M_STEP)))
                    except OpRejected: ok = False; break
                if not ok: continue
                Q = matrix(cur, sp["n"]); subset = set(nrng.sample(range(sp["G"]), nrng.randint(0, BMAX)))
                c = ev.coeff(Q); v2 = ev.v.copy()
                for r_, o in enumerate(sp["obs"]):
                    if subset.intersection(o["anc"]): v2[r_] = nrng.choice([0.0, 1.0, nrng.random()])
                s_att = float(c @ v2); counters["random_trials"] += 1
                if "lower" in cl and not (cl["lower"] - TOL <= s_att <= cl["upper"] + TOL): counters["random_bound_violations"] += 1
                if cl.get("certified") and verdict_of(s_att, sp["tau_b"], sp["tau_m"]) != verdict and (s_att < sp["tau_m"] - TOL if verdict == "malicious" else s_att > sp["tau_b"] + TOL):
                    counters["random_flips_of_certified"] += 1
    sound_fail = (counters["flips_of_certified"] + counters["bound_violations"] + counters["random_bound_violations"] + counters["random_flips_of_certified"]
                  + counters["cost_cap_violations"] + counters["typing_violations"] + counters["unknown_regime_certified"] + prop["assertion_violations"] + sem["violations"])
    gate_ok = all(r[1] != "accepted" for r in ctrl) and prop["negative_control_non_stochastic_Q"]["gate_rejects"]
    ok = sound_fail == 0 and gate_ok
    def agg(pred):
        sel = [r for r in rows if r["in_domain"] and r["verdict"] != "abstain" and pred(r)]
        n = len(sel)
        return dict(n=n, certified=sum(r["certified"] for r in sel), flips=sum(bool(r["attack_flips"]) for r in sel),
                    coverage=round(sum(r["certified"] for r in sel) / n, 4) if n else None,
                    empirical_robust=round(sum(not r["attack_flips"] for r in sel) / n, 4) if n else None,
                    mean_slack=round(float(np.mean([r["bound_slack"] for r in sel if r["bound_slack"] is not None])), 4) if any(r["bound_slack"] is not None for r in sel) else None)
    cells = {(b, k): agg(lambda r, b=b, k=k: r["b"] == b and r["k"] == k) for b in range(BMAX + 1) for k in range(KMAX + 1)}
    compare = dict(pure_source={b: cells[(b, 0)] for b in range(1, BMAX + 1)}, pure_graph={k: cells[(0, k)] for k in range(1, KMAX + 1)}, joint={f"b={b},k={k}": cells[(b, k)] for b in range(1, BMAX + 1) for k in range(1, KMAX + 1)})
    by_alpha = {a: agg(lambda r, a=a: r["alpha"] == a and r["b"] == 2 and r["k"] == 2) for a in ALPHAS if a <= ALPHA_ASSERT_MAX}
    audit = dict(audit_version="E08-1", world_type="controlled_synthetic", seed=seed, cases=cases, actionable_cases=sum(1 for r in rows if r["b"] == 0 and r["k"] == 0 and r["verdict"] != "abstain"),
                 budgets=dict(source_groups=list(range(BMAX + 1)), edge_ops=list(range(KMAX + 1)), op_step_m=M_STEP, edge_l1_budget="eps = min(2, 2*k*m)"),
                 validation_domain=dict(proof="a in [0,1); P,Q nonnegative row stochastic; max row l1(Q-P)<=eps; values in [0,1]; fixed weights/ancestry; ancestor-group all-descendant control",
                                        matrix_norm="induced infinity norm (max row l1) of Q-P; B_Q row stochastic", normalisation="row stochastic with absorbing dangling rows",
                                        asserted_alpha_range=[0, ALPHA_ASSERT_MAX], numeric_validation_alphas=prop["alpha_grid"], proof_sketch=PROOF,
                                        abstains_when=["alpha>0.95", "eps outside [0,2]", "graph term a*eps/(2(1-a))>=1", "ops outside relation types", "non-stochastic or out-of-ball Q"]),
                 soundness=counters, property_tests=prop, semantic_preserving_checks=sem, typed_rejection_controls=ctrl, compare_pure_vs_joint=compare, by_alpha_at_b2_k2=by_alpha,
                 runtime={k: round(v, 2) for k, v in runtime.items()} | dict(total_seconds=round(time.perf_counter() - t0, 2)),
                 pass_criteria=dict(zero_soundness_violations=sound_fail == 0, unknown_regimes_abstain=counters["unknown_regime_certified"] == 0, typed_controls_reject=gate_ok,
                                    status="pass" if ok else "HALT_DOWNSTREAM_CERTIFICATION"),
                 limitations=["Adversarial search is exhaustive over a pool of the 22 strongest single typed ops (k<=3, step m=0.1, all source subsets <=3) plus random continuous trials: it is a lower bound on true damage.",
                              "Controlled synthetic graphs; no real web graph is used.", "Source corruption is endpoint (0/1) all-descendant control; weights, ancestry and thresholds are fixed.",
                              "Fixed-graph certificates are NOT valid on a changing graph; the count of fixed certificates that flip under graph attack is reported."])
    (out / "audit.json").write_text(json.dumps(audit, indent=2, sort_keys=True, default=str), encoding="utf-8")
    if not ok: raise AssertionError(f"E08 soundness failure: {counters}; property={prop['assertion_violations']} semantic={sem['violations']}; plots withheld")
    for name, data in (("cells.csv", rows), ("attack_witnesses.csv", wit)):
        if data:
            with (out / name).open("w", newline="", encoding="utf-8") as f:
                w = csv.DictWriter(f, fieldnames=list(data[0].keys()) if name == "cells.csv" else sorted({k for d in data for k in d})); w.writeheader(); w.writerows(data)
    tex = [r"\begin{tabular}{rrrrr}", r"$b$ & $k$ & certified & empirical robust & flips \\", r"\hline"]
    tex += [f"{b} & {k} & {c['coverage']} & {c['empirical_robust']} & {c['flips']} \\\\" for (b, k), c in cells.items()] + [r"\end{tabular}"]
    (tables / "e08_joint.tex").write_text("\n".join(tex) + "\n", encoding="utf-8")
    if plots:
        import matplotlib; matplotlib.use("Agg")
        import matplotlib.pyplot as plt
        fig, ax = plt.subplots(1, 3, figsize=(14, 3.8))
        for a_, key, title in ((ax[0], "coverage", "certified coverage"), (ax[1], "empirical_robust", "empirical robust (attack search)"), (ax[2], "mean_slack", "mean bound slack")):
            Z = np.array([[cells[(b, k)][key] or 0 for k in range(KMAX + 1)] for b in range(BMAX + 1)], float)
            im = a_.imshow(Z, origin="lower", cmap="viridis"); a_.set_xlabel("edge budget k (typed ops)"); a_.set_ylabel("source budget b (groups)"); a_.set_title(title)
            a_.set_xticks(range(KMAX + 1)); a_.set_yticks(range(BMAX + 1)); fig.colorbar(im, ax=a_, fraction=.046)
            for b in range(BMAX + 1):
                for k in range(KMAX + 1): a_.text(k, b, f"{Z[b, k]:.2f}", ha="center", va="center", color="w", fontsize=8)
        fig.tight_layout(); fig.savefig(out / "heatmaps.png", dpi=130); plt.close(fig)
    return audit
