"""Operational and scientific metrics with abstention handled explicitly."""
from __future__ import annotations
import math
import numpy as np
from sklearn.metrics import accuracy_score,precision_recall_fscore_support,confusion_matrix


def evaluate_repair(rows):
    if not rows: return {}
    n=len(rows)
    initially=[r['initial'] for r in rows]; finally_=[r['final'] for r in rows]
    def evaluate(stage):
        decided=[i for i,r in enumerate(stage) if r['verdict']!='abstain']
        certified=[i for i,r in enumerate(stage) if r['certified']]
        valid=[i for i in decided if rows[i]['truth'] is not None]
        true=np.array([rows[i]['truth'] for i in valid],dtype=int)
        pred=np.array([int(stage[i]['verdict']=='malicious') for i in valid],dtype=int)
        quality={}
        if len(true):
            pr,re,f1,_=precision_recall_fscore_support(true,pred,average='binary',zero_division=0)
            quality={'selective_accuracy':float(accuracy_score(true,pred)),
                     'selective_precision':float(pr),'selective_recall':float(re),
                     'selective_f1':float(f1),
                     'confusion_matrix_0benign_1phishing':confusion_matrix(true,pred,labels=[0,1]).tolist()}
        return {'coverage':len(decided)/n,'certified_coverage':len(certified)/n,
                'abstention_rate':1-len(decided)/n,**quality}
    corrected=sum(not r['correct_before'] and r['correct_after'] for r in rows)
    degraded=sum(r['correct_before'] and not r['correct_after'] for r in rows)
    return {'n_cases':n,'before':evaluate(initially),'after':evaluate(finally_),
            'corrected_cases':corrected,'degraded_cases':degraded,
            'corrected_fraction_all_cases':corrected/n,'degraded_fraction_all_cases':degraded/n,
            'mean_actions':float(np.mean([r['num_actions'] for r in rows])),
            'mean_acquisition_cost':float(np.mean([r['total_cost'] for r in rows])),
            'warning':'Controlled synthetic outcomes; not field phishing detection or true zero-day scores'}
