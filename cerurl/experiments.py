"""Controlled benchmark: certification, attack verification, repair policies.

All generated results are labeled CONTROLLED_SYNTHETIC. No reported real-world
phishing accuracy, zero-day claims, or fake sensor provenance.
"""
from __future__ import annotations
import json,csv
from collections import Counter
from itertools import combinations
from pathlib import Path
import numpy as np
from .core import certify,flip_attack,score_and_coefficients,Case
from .simulate import load_cases
from .repair import repair,RepairConfig
from .metrics import evaluate_repair


def run_attack_audit(cases: list[Case], budgets=(0,1,2), alpha=.35):
    """Search all group subsets and both binary extreme attacks for small cases.

    Empirically verifies the *certified* guarantee on these held-out examples;
    it does not replace a general proof, nor test adaptive weight corruption.
    """
    reports=[]
    for budget in budgets:
        n_cert=violations=flips=attacks=0
        for case in cases:
            cert=certify(case,budget=budget,alpha=alpha)
            if cert['certified']:n_cert+=1
            groups=sorted(set().union(*(o.ancestors for o in case.observations)))
            for k in range(min(budget,len(groups))+1):
                for subset in combinations(groups,k):
                    for direction in ('down','up'):
                        modified=flip_attack(case,subset,direction)
                        now=certify(modified,budget=0,alpha=alpha)
                        attacks+=1
                        changed=now['verdict']!=cert['verdict']
                        flips+=changed
                        violations+=int(cert['certified'] and changed)
        reports.append({'source_budget':budget,'n_cases':len(cases),'n_attack_trials':attacks,
                        'certified_coverage':n_cert/len(cases) if cases else None,
                        'attack_flip_fraction_over_trials':flips/attacks if attacks else None,
                        'certificate_violations':violations,
                        'guarantee_tested':'fixed P and weights, bounded root-group observations'})
    return reports


def run_benchmark(dataset_path: str,output_dir: str,seed:int=7,
                  policies=('counterfactual','random','uncertainty','cheapest'),
                  budgets=(0,1,2), max_cases:int|None=None):
    cases=list(load_cases(dataset_path))
    if max_cases: cases=cases[:max_cases]
    out=Path(output_dir);out.mkdir(parents=True,exist_ok=True)
    report={'dataset':str(dataset_path),'world_type':'controlled_synthetic',
            'n_cases':len(cases),'policies':list(policies),'budgets':list(budgets),
            'seed':seed,'configuration':{'alpha':.35,'tau_b':.4,'tau_m':.6,
                   'acquisition_budget':3.0,'new_weight':.30,'max_steps':3}}
    detailed=[]
    for budget in budgets:
        for policy in policies:
            cfg=RepairConfig(budget=int(budget))
            rows=[repair(c,policy,cfg,seed=seed+i) for i,c in enumerate(cases)]
            for r in rows:
                detailed.append({'budget':budget,**r})
            report[f'budget_{budget}_{policy}']=evaluate_repair(rows)
    with (out/'repair_trials.jsonl').open('w',encoding='utf-8') as f:
        for row in detailed:f.write(json.dumps(row)+'\n')
    attack_audit=run_attack_audit(cases,budgets)
    report['attack_audit']=attack_audit
    (out/'benchmark_report.json').write_text(json.dumps(report,indent=2),encoding='utf-8')
    _save_summary(report,out)
    try:_plots(report,out)
    except ImportError:pass
    return report


def _save_summary(report,out):
    rows=[]
    for budget in report['budgets']:
        for policy in report['policies']:
            result=report[f'budget_{budget}_{policy}']
            rows.append({'budget':budget,'policy':policy,
                         'certified_before':result['before']['certified_coverage'],
                         'certified_after':result['after']['certified_coverage'],
                         'selective_accuracy_after':result['after'].get('selective_accuracy'),
                         'coverage_after':result['after']['coverage'],
                         'corrections':result['corrected_cases'],
                         'degradations':result['degraded_cases'],
                         'mean_cost':result['mean_acquisition_cost']})
    with (out/'results.csv').open('w',newline='',encoding='utf-8') as f:
        w=csv.DictWriter(f,fieldnames=list(rows[0]));w.writeheader();w.writerows(rows)


def _plots(report,out):
    import matplotlib
    matplotlib.use('Agg')
    import matplotlib.pyplot as plt
    fig,ax=plt.subplots(figsize=(8,5))
    for policy in report['policies']:
        x=list(report['budgets']);y=[report[f'budget_{b}_{policy}']['after']['certified_coverage'] for b in x]
        ax.plot(x,y,marker='o',label=policy)
    ax.set(xlabel='Compromised root-source groups',ylabel='Certified decision coverage',
           title='Controlled-synthetic CER benchmark; not field performance',ylim=(0,1))
    ax.legend();fig.tight_layout();fig.savefig(out/'certified_coverage.png',dpi=175);plt.close(fig)
    fig,ax=plt.subplots(figsize=(8,5))
    for policy in report['policies']:
        x=[report[f'budget_{b}_{policy}']['mean_acquisition_cost'] for b in report['budgets']]
        y=[report[f'budget_{b}_{policy}']['after']['certified_coverage'] for b in report['budgets']]
        ax.scatter(x,y,label=policy)
        for xx,yy,b in zip(x,y,report['budgets']):ax.annotate(str(b),(xx,yy))
    ax.set(xlabel='Mean evidence-acquisition cost',ylabel='Certified decision coverage',
           title='Repair cost vs robust coverage (labels = compromise budget)',ylim=(0,1))
    ax.legend();fig.tight_layout();fig.savefig(out/'cost_vs_certification.png',dpi=175);plt.close(fig)
