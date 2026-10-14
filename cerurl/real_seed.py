"""Controlled perturbations anchored on real held-out URLs and labels.

NOTE: Generated collector observations are SIMULATED. The real anchor is
only the URL and its original held-out label/lexical model prediction.
Never call this genuine evidence acquisition or zero-day validation.
"""
import json
from pathlib import Path
import numpy as np
import pandas as pd
from .simulate import generate_case,case_to_dict
from .core import Observation


def anchors_to_controlled(holdout_csv: str,output_jsonl: str,n: int=500,seed:int=23):
    df=pd.read_csv(holdout_csv)
    expected={'url','host','label','prob_phishing'}
    if not expected.issubset(df.columns): raise ValueError(f'Missing {expected-set(df.columns)}')
    df=df.dropna(subset=list(expected))
    if len(df)>n:df=df.sample(n=n,random_state=seed)
    out=Path(output_jsonl);out.parent.mkdir(parents=True,exist_ok=True)
    with out.open('w',encoding='utf-8') as f:
        for i,(_,row) in enumerate(df.iterrows()):
            c=generate_case(i,seed=seed)
            c.truth=int(row['label'])
            # Use *real held-out model probability* as one intrinsic observation.
            # Other simulated values are generated conditionally on held-out truth.
            rng=np.random.default_rng(np.random.SeedSequence([seed,i,13579]))
            altered=[]
            for o in c.observations:
                if o.node==0 and o.obs_id=='o0_0':
                    # Stable measured lexical prediction; not a separate independent witness.
                    altered.append(Observation(o.node,float(row['prob_phishing']),o.weight,
                                               frozenset({'lexical_model'}),o.obs_id,'heldout_model_score'))
                else:
                    v=float(np.clip(rng.normal(.80 if c.truth else .20,.16),0,1))
                    altered.append(Observation(o.node,v,o.weight,o.ancestors,o.obs_id,
                                               'simulated_conditioned_on_real_label'))
            c.observations=altered
            new=[]
            for o in c.candidates:
                val=float(np.clip(rng.normal(.84 if c.truth else .16,.18),0,1))
                new.append(Observation(o.node,val,o.weight,o.ancestors,o.obs_id,'simulated_oracle'))
            c.candidates=new
            c.world_type='synthetic_perturbation_on_anchor_label'
            c.metadata.update({'anchor_url':str(row['url']),'anchor_host':str(row['host']),
                               'heldout_lexical_probability':float(row['prob_phishing']),
                               'MUST_NOT_CLAIM_REAL_PROVENANCE':True})
            f.write(json.dumps(case_to_dict(c))+'\n')
    return {'n_cases':len(df),'output':str(out),
            'world_type':'synthetic_perturbation_on_anchor_label',
            'warning':'Anchor URLs, labels and model predictions come from the supplied holdout CSV; provenance/evidence is synthetic. If the CSV is a synthetic smoke fixture, everything is synthetic.'}
