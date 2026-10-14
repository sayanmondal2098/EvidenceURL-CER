"""Fixed-graph provenance-aware URL-risk propagation and *sound* certificates.

Threat model: attacker controls <= b *root source groups*, changing every
observation derived from any controlled group arbitrarily within [0, 1].
Weights, source ancestry, graph and decision thresholds remain unchanged.

Certificate extends to uncertain row-stochastic graph Q if every row satisfies
||P[i]-Q[i]||_1 <= graph_l1_budget. Bounds are conservative in that case.
No claims are made under changed ancestry, weight poisoning, forged sources,
invalid provenance, unbounded adversaries, or adaptive model retraining.
"""
from __future__ import annotations
from dataclasses import dataclass, field
from itertools import combinations
from typing import FrozenSet, Sequence
import numpy as np


@dataclass(frozen=True)
class Observation:
    node: int
    value: float
    weight: float
    ancestors: FrozenSet[str]
    obs_id: str = ""
    kind: str = "controlled"

    def __post_init__(self):
        if not 0 <= self.value <= 1 or not 0 <= self.weight <= 1:
            raise ValueError("values and weights must be in [0,1]")
        if not self.ancestors:
            raise ValueError("observation requires a known, nonempty root-source ancestry")


@dataclass
class Case:
    case_id: str
    P: np.ndarray
    observations: list[Observation]
    target: int
    truth: int | None = None
    candidates: list[Observation] = field(default_factory=list)
    candidate_costs: dict[str, float] = field(default_factory=dict)
    world_type: str = "controlled_synthetic"
    metadata: dict = field(default_factory=dict)


def transition(P) -> np.ndarray:
    """Validate a nonnegative row-stochastic *incoming-mixing* matrix."""
    P = np.asarray(P, dtype=float)
    if P.ndim != 2 or P.shape[0] != P.shape[1] or not len(P):
        raise ValueError("P must be a nonempty square matrix")
    if not np.all(np.isfinite(P)) or (P < -1e-12).any():
        raise ValueError("P must be finite and nonnegative")
    if not np.allclose(P.sum(axis=1), 1, atol=1e-9):
        raise ValueError("Each row of P must sum to one, including dangling rows")
    return P


def validate_observations(obs: Sequence[Observation], n: int):
    if not obs:
        raise ValueError("No observations")
    weights = np.zeros(n)
    for o in obs:
        if not 0 <= o.node < n:
            raise ValueError(f"Invalid node index {o.node}")
        weights[o.node] += o.weight
    if not np.allclose(weights, 1, atol=1e-9):
        raise ValueError(f"Per-node observation weights must sum to one: {weights}")


def fundamental(P, alpha: float) -> np.ndarray:
    """B = (1-alpha)(I-alpha P)^-1; row stochastic if P is row stochastic."""
    P = transition(P)
    if not 0 <= alpha < 1:
        raise ValueError("alpha must be in [0,1)")
    n = len(P)
    return (1-alpha)*np.linalg.solve(np.eye(n)-alpha*P, np.eye(n))


def prior(obs: Sequence[Observation], n: int) -> np.ndarray:
    validate_observations(obs, n)
    r = np.zeros(n)
    for o in obs:
        r[o.node] += o.weight*o.value
    return r


def score_and_coefficients(case: Case, alpha: float = 0.35):
    P = transition(case.P)
    n = len(P)
    if not 0 <= case.target < n:
        raise ValueError("Invalid target")
    r = prior(case.observations, n)
    B = fundamental(P, alpha)
    score = float(B[case.target] @ r)
    coefficients = np.array([B[case.target, o.node]*o.weight for o in case.observations])
    if not np.isclose(coefficients.sum(), 1):
        raise AssertionError("Influence weights do not sum to one")
    return score, coefficients, B @ r


def worst_damage(obs: Sequence[Observation], coeffs: Sequence[float], budget: int,
                 direction: str, max_groups: int = 24):
    """Exact exhaustive maximum directional damage for <=budget root groups.

    For large m deliberately raises instead of silently calling a heuristic a certificate.
    """
    if not isinstance(budget, int) or budget < 0 or direction not in ('down', 'up'):
        raise ValueError("budget must be nonnegative integer and direction down/up")
    groups = sorted(set().union(*(o.ancestors for o in obs)))
    if len(groups) > max_groups:
        raise ValueError(f"Exact enumerator accepts at most {max_groups} groups; use a proven upper bound")
    c = np.asarray(coeffs, dtype=float)
    if len(c) != len(obs) or (c < -1e-12).any():
        raise ValueError("Invalid influence coefficients")
    best_loss, best_subset = 0.0, ()
    for k in range(min(budget, len(groups)) + 1):
        for subset in combinations(groups, k):
            A = set(subset)
            loss = sum(float(ci)*(o.value if direction=='down' else 1-o.value)
                       for o, ci in zip(obs,c) if A.intersection(o.ancestors))
            if loss > best_loss + 1e-12:
                best_loss, best_subset = loss, subset
    return float(best_loss), list(best_subset)


def worst_damage_safe_bound(obs: Sequence[Observation], coeffs: Sequence[float], budget: int,
                           exact_max_groups: int=24):
    """Return both direction bounds. Conservative fallback when group count is large.

    Fallback: sum of b largest upper bounds for individual group impact, capped
    by total directional damage. Valid even when observations have multiple ancestors.
    """
    groups = sorted(set().union(*(o.ancestors for o in obs)))
    if len(groups) <= exact_max_groups:
        d,g = worst_damage(obs, coeffs, budget, 'down', exact_max_groups)
        u,h = worst_damage(obs, coeffs, budget, 'up', exact_max_groups)
        return d,u,g,h,'exact'
    d_all = sum(c*o.value for c,o in zip(coeffs,obs))
    u_all = sum(c*(1-o.value) for c,o in zip(coeffs,obs))
    def upper(direction):
        contributions=[]
        for group in groups:
            val = sum(float(c)*(o.value if direction=='down' else 1-o.value)
                      for c,o in zip(coeffs,obs) if group in o.ancestors)
            contributions.append(val)
        return min(d_all if direction=='down' else u_all,
                   sum(sorted(contributions,reverse=True)[:budget]))
    return float(upper('down')),float(upper('up')),[],[],'conservative_union_bound'


def certify(case: Case, budget: int=1, alpha: float=0.35,
            tau_b: float=0.40, tau_m: float=0.60, graph_l1_budget: float=0.0):
    """Certify current *actionable* verdict against root-source corruption.

    Tie convention: score >= tau_m => malicious, <= tau_b => benign; other abstain.
    Bounds are derived with weak inclusive inequalities, with numeric tolerance.
    graph_l1_budget in [0,2] is a certified rowwise L1 upper bound, not an inferred guess.
    """
    if not 0 <= tau_b < tau_m <= 1:
        raise ValueError('Require 0 <= tau_b < tau_m <= 1')
    if not 0 <= graph_l1_budget <= 2:
        raise ValueError('graph_l1_budget must be in [0,2]')
    s,coeffs,_ = score_and_coefficients(case,alpha)
    down,up,dgroups,ugroups,method=worst_damage_safe_bound(case.observations,coeffs,budget)
    # ||r_Q-r_P||∞ <= 0 under graph-only perturbation. For fixed r∈[0,1]^n:
    # ||x_Q-x_P||∞ <= alpha*eps/(2*(1-alpha)) because TV bound of row perturbation.
    gp = min(1., alpha*graph_l1_budget/(2*(1-alpha)))
    lower=max(0.,s-down-gp)
    upper=min(1.,s+up+gp)
    if s >= tau_m:
        verdict='malicious'; ok=(lower>=tau_m+1e-12)
    elif s <= tau_b:
        verdict='benign'; ok=(upper<=tau_b-1e-12)
    else:
        verdict='abstain'; ok=False
    return dict(case_id=case.case_id, verdict=verdict, score=float(s), truth=case.truth,
                certified=bool(ok), budget=budget, alpha=alpha, tau_b=tau_b, tau_m=tau_m,
                lower_bound=float(lower), upper_bound=float(upper), down_damage=down,
                up_damage=up, graph_deviation_bound=gp, max_graph_row_l1=graph_l1_budget,
                down_worst_groups=dgroups, up_worst_groups=ugroups, cert_method=method,
                world_type=case.world_type, note='Only valid for stated root-group and graph perturbation threat model')


def flip_attack(case: Case, groups: Sequence[str], direction: str) -> Case:
    """Endpoint root-group compromise on a DEEP COPIED case, graph held fixed."""
    if direction not in ('down','up'): raise ValueError('direction must be down/up')
    attacked=[]; A=set(groups)
    for o in case.observations:
        v=(0.0 if direction=='down' else 1.0) if A.intersection(o.ancestors) else o.value
        attacked.append(Observation(o.node,v,o.weight,o.ancestors,o.obs_id,o.kind))
    return Case(case.case_id,case.P.copy(),attacked,case.target,case.truth,
                list(case.candidates),dict(case.candidate_costs),case.world_type,dict(case.metadata))


def add_observation(case: Case, candidate: Observation, new_weight: float=0.3):
    """Append evidence. Existing weights for the candidate's node scaled by (1-w).

    Independent acquisition assumes candidate's root ancestry is accurate and existing
    values/weights are immutable except the specified deterministic rescaling.
    """
    if not 0 < new_weight < 1: raise ValueError('new_weight must be (0,1)')
    if candidate.node>=len(case.P): raise ValueError('candidate node missing')
    scaled=[]
    for o in case.observations:
        weight=o.weight*(1-new_weight) if o.node==candidate.node else o.weight
        scaled.append(Observation(o.node,o.value,weight,o.ancestors,o.obs_id,o.kind))
    scaled.append(Observation(candidate.node,candidate.value,new_weight,candidate.ancestors,
                              candidate.obs_id,candidate.kind))
    return Case(case.case_id,case.P.copy(),scaled,case.target,case.truth,
                [c for c in case.candidates if c.obs_id != candidate.obs_id],
                dict(case.candidate_costs),case.world_type,dict(case.metadata))


def quarantine_root_groups(case: Case, compromised_groups: Sequence[str]) -> Case:
    """Remove observations derived from externally CONFIRMED invalid root groups.

    A verification failure must come from independent evidence; do not infer it
    from disagreement with the detector's present prediction. No proof is
    generated if a node is left without observations.
    """
    compromised=set(compromised_groups)
    if not compromised: return case
    n=len(case.P)
    remaining=[o for o in case.observations if not (o.ancestors & compromised)]
    for node in range(n):
        group=[o for o in remaining if o.node==node]
        if not group:
            raise ValueError('No admissible evidence for node: abstain/collect before recertifying')
    normalized=[]
    for node in range(n):
        denom=sum(o.weight for o in remaining if o.node==node)
        if denom<=0: raise ValueError('Zero effective evidence weight')
        for o in remaining:
            if o.node==node:
                normalized.append(Observation(o.node,o.value,o.weight/denom,o.ancestors,o.obs_id,o.kind))
    meta=dict(case.metadata)
    meta.setdefault('quarantined_confirmed_roots',[])
    meta['quarantined_confirmed_roots']=sorted(set(meta['quarantined_confirmed_roots'])|compromised)
    return Case(case.case_id,case.P.copy(),normalized,case.target,case.truth,
                list(case.candidates),dict(case.candidate_costs),case.world_type,meta)


def minimum_flip_groups(case: Case, alpha: float=.35, tau_b:float=.40,
                        tau_m:float=.60, max_groups:int=16):
    """Exact smallest root-group count reversing an actionable verdict.

    Applies only for a fixed graph, fixed weights, and bounded root-group
    observation replacement. Raises on large group sets rather than guessing.
    """
    s,coeff,_=score_and_coefficients(case,alpha)
    verdict='malicious' if s>=tau_m else 'benign' if s<=tau_b else 'abstain'
    if verdict=='abstain':
        return {'verdict':verdict,'minimum_groups_to_flip':None,'witness':None}
    groups=set().union(*(o.ancestors for o in case.observations))
    if len(groups)>max_groups:
        raise ValueError(f'Exact minimum search supports up to {max_groups} groups')
    direction='down' if verdict=='malicious' else 'up'
    for b in range(len(groups)+1):
        damage,witness=worst_damage(case.observations,coeff,b,direction,max_groups)
        extreme=s-damage if direction=='down' else s+damage
        flips=extreme<tau_m-1e-12 if direction=='down' else extreme>tau_b+1e-12
        if flips:
            return {'verdict':verdict,'initial_score':float(s),'minimum_groups_to_flip':b,
                    'witness':witness,'direction':direction,'adversarial_endpoint':float(extreme)}
    return {'verdict':verdict,'minimum_groups_to_flip':None,'witness':None}
