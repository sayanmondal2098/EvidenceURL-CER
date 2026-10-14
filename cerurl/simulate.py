"""Explicitly CONTROLLED SYNTHETIC cases, never real web measurements."""
from __future__ import annotations
import json
from dataclasses import asdict
from pathlib import Path
import numpy as np
from .core import Case, Observation


def generate_case(case_number: int, seed: int=42, n_nodes: int=3,
                  n_groups: int=6, shared_probability: float=0.28) -> Case:
    if n_nodes < 1 or n_groups < 3:
        raise ValueError('n_nodes>=1, n_groups>=3')
    rng=np.random.default_rng(np.random.SeedSequence([seed,case_number]))
    target_truth=int(rng.random()<0.50)
    node_truth=np.array([target_truth]+[int(rng.random()<0.60) if target_truth else
                                       int(rng.random()<0.40) for _ in range(n_nodes-1)])
    # Explicit incoming-mixing matrix. Row i mixes node i and its neighbors.
    raw=rng.uniform(0.0,0.22,(n_nodes,n_nodes)); np.fill_diagonal(raw,1.5)
    P=raw/raw.sum(axis=1,keepdims=True)
    observations=[]
    # Correlated upstream feed 'shared_x' can be inherited by several apparently
    # distinct collectors. It IS an attacker-controllable ROOT group.
    for node in range(n_nodes):
        for j in range(n_groups):
            source=f'c{j}'
            ancestors={source}
            if j in (1,2) and rng.random()<shared_probability:
                ancestors.add('upstream_shared')
            # probability of correct observation; varying source quality
            quality=float(rng.uniform(.67,.96))
            if j==0: quality=0.95
            truth=int(node_truth[node]); reported=truth if rng.random()<quality else (1-truth)
            # Moderately informative continuous observations in [0,1]
            value=float(np.clip(rng.normal(.85 if reported else .15,.10),0,1))
            observations.append(Observation(node,value,1/n_groups,frozenset(ancestors),
                                            f'o{node}_{j}','simulated_measurement'))
    # Candidate pool is pre-collected by *simulator only*, not visible to selector:
    # candidate value is sealed until execute action. This ensures no oracle leakage.
    candidates=[];costs={}
    for j in range(7):
        node=0 if j<5 else int(rng.integers(1,n_nodes)) if n_nodes>1 else 0
        ancestors=frozenset({f'independent_candidate_{j}'}) if j < 5 else frozenset({f'c{j% n_groups}'})
        quality=float(rng.uniform(.68,.97))
        observed=int(node_truth[node]) if rng.random()<quality else 1-int(node_truth[node])
        value=float(np.clip(rng.normal(.85 if observed else .15,.10),0,1))
        obs_id=f'candidate_{j}'
        candidates.append(Observation(node,value,0.,ancestors,obs_id,'simulated_sealed_oracle'))
        costs[obs_id]=float([1.0,1.25,1.5,1.75,2.0,0.75,0.9][j])
    return Case(f'synth_{seed}_{case_number:06d}',P,observations,0,target_truth,
                candidates,costs,'controlled_synthetic',
                {'generator_seed':seed,'case_number':case_number,'node_truth':node_truth.tolist(),
                 'unseen_candidate_values_are_sealed':True})


def obs_to_dict(o: Observation) -> dict:
    return {'node':o.node,'value':o.value,'weight':o.weight,
            'ancestors':sorted(o.ancestors),'obs_id':o.obs_id,'kind':o.kind}


def obs_from_dict(v: dict) -> Observation:
    return Observation(int(v['node']),float(v['value']),float(v['weight']),
                       frozenset(v['ancestors']),v.get('obs_id',''),v.get('kind','controlled'))


def case_to_dict(c: Case) -> dict:
    return {'case_id':c.case_id,'P':np.asarray(c.P).tolist(),
            'observations':[obs_to_dict(o) for o in c.observations],
            'target':c.target,'truth':c.truth,'candidates':[obs_to_dict(o) for o in c.candidates],
            'candidate_costs':c.candidate_costs,'world_type':c.world_type,'metadata':c.metadata}


def case_from_dict(v: dict) -> Case:
    return Case(v['case_id'],np.asarray(v['P'],dtype=float),
                [obs_from_dict(o) for o in v['observations']],int(v['target']),v.get('truth'),
                [obs_from_dict(o) for o in v.get('candidates',[])],
                v.get('candidate_costs',{}),v.get('world_type','unknown'),v.get('metadata',{}))


def generate_dataset(path: str | Path, n_cases: int=250, seed: int=42,
                     n_groups: int=6, shared_probability: float=.28) -> dict:
    p=Path(path);p.parent.mkdir(parents=True,exist_ok=True)
    with p.open('w',encoding='utf-8') as f:
        for i in range(n_cases):
            f.write(json.dumps(case_to_dict(generate_case(i,seed,n_groups=n_groups,
                            shared_probability=shared_probability)))+'\n')
    manifest={'dataset':'CER-URLBench controlled simulator','world_type':'controlled_synthetic',
              'n_cases':n_cases,'seed':seed,'n_groups':n_groups,
              'shared_probability':shared_probability,
              'warning':'Not real URLs, real provenance, or zero-day performance'}
    p.with_suffix('.manifest.json').write_text(json.dumps(manifest,indent=2),encoding='utf-8')
    return manifest


def load_cases(path: str | Path):
    with Path(path).open(encoding='utf-8') as f:
        for line in f:
            if line.strip(): yield case_from_dict(json.loads(line))
