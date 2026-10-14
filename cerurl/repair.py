"""Counterfactual acquisition policies. Crucially, action selection never reads
candidate.value. That value is a sealed oracle outcome revealed only after action.
"""
from __future__ import annotations
from dataclasses import dataclass
import numpy as np
from .core import Case, Observation, add_observation, certify, score_and_coefficients


@dataclass
class RepairConfig:
    budget: int = 1
    alpha: float = .35
    tau_b: float = .40
    tau_m: float = .60
    new_weight: float = .3
    acquisition_budget: float = 3.0
    max_steps: int = 3


def _utility(report):
    """Surrogate combining robust decision margin and actionable coverage.

    This is a heuristic policy objective, NOT a proven optimal decision repair.
    """
    v=report['verdict']
    if v=='malicious': return report['lower_bound']-report['tau_m']
    if v=='benign': return report['tau_b']-report['upper_bound']
    return -0.15 - min(abs(report['score']-report['tau_b']),
                       abs(report['score']-report['tau_m']))


def select_action(case: Case, policy: str, cfg: RepairConfig,
                  remaining: float, rng: np.random.Generator):
    valid=[c for c in case.candidates if case.candidate_costs[c.obs_id] <= remaining]
    if not valid: return None
    if policy=='random':
        return valid[int(rng.integers(len(valid)))]
    if policy=='cheapest':
        return min(valid,key=lambda c:(case.candidate_costs[c.obs_id],c.obs_id))
    if policy=='uncertainty':
        # Without looking at hidden candidate outcomes, target the least certain node.
        _,_,scores=score_and_coefficients(case,cfg.alpha)
        return min(valid,key=lambda c:(abs(float(scores[c.node])-.5),case.candidate_costs[c.obs_id]))
    if policy!='counterfactual': raise ValueError('Unknown repair policy '+policy)
    score,_,node_scores=score_and_coefficients(case,cfg.alpha)
    current=certify(case,cfg.budget,cfg.alpha,cfg.tau_b,cfg.tau_m)
    current_util=_utility(current)
    ranked=[]
    for cand in valid:
        # Hypothetical outcomes only. Never access cand.value until execution.
        p=float(np.clip(node_scores[cand.node],.10,.90))
        outcomes=[]
        for v,prob in ((0.,1-p),(1.,p)):
            hypothetical=Observation(cand.node,v,0.,cand.ancestors,cand.obs_id,cand.kind)
            altered=add_observation(case,hypothetical,cfg.new_weight)
            report=certify(altered,cfg.budget,cfg.alpha,cfg.tau_b,cfg.tau_m)
            outcomes.append(prob*_utility(report))
        expected=sum(outcomes)
        cost=case.candidate_costs[cand.obs_id]
        ranked.append(((expected-current_util)/cost,cand.obs_id,cand))
    return max(ranked,key=lambda x:(x[0],x[1]))[2]


def repair(case: Case, policy: str='counterfactual',cfg: RepairConfig|None=None,seed: int=7):
    cfg=cfg or RepairConfig()
    rng=np.random.default_rng(seed)
    current=case
    initial=certify(current,cfg.budget,cfg.alpha,cfg.tau_b,cfg.tau_m)
    remaining=cfg.acquisition_budget
    actions=[]
    for step in range(cfg.max_steps):
        report=certify(current,cfg.budget,cfg.alpha,cfg.tau_b,cfg.tau_m)
        if report['certified']:break
        candidate=select_action(current,policy,cfg,remaining,rng)
        if candidate is None:break
        cost=current.candidate_costs[candidate.obs_id]
        # SEALED ORACLE: access the pre-generated value ONLY AFTER selecting action.
        current=add_observation(current,candidate,cfg.new_weight)
        remaining-=cost
        result=certify(current,cfg.budget,cfg.alpha,cfg.tau_b,cfg.tau_m)
        actions.append({'step':step+1,'id':candidate.obs_id,'source_roots':sorted(candidate.ancestors),
                        'node':candidate.node,'revealed_value':candidate.value,
                        'cost':cost,'result_verdict':result['verdict'],
                        'result_certified':result['certified']})
    final=certify(current,cfg.budget,cfg.alpha,cfg.tau_b,cfg.tau_m)
    truth=current.truth
    return {'case_id':case.case_id,'policy':policy,'truth':truth,'initial':initial,
            'final':final,'actions':actions,'total_cost':cfg.acquisition_budget-remaining,
            'num_actions':len(actions),'correct_before':
            initial['verdict']==('malicious' if truth==1 else 'benign') if truth is not None else None,
            'correct_after':final['verdict']==('malicious' if truth==1 else 'benign') if truth is not None else None,
            'world_type':case.world_type}
