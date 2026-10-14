"""Real public URL-label ingestion and honest URL-only baseline.

UCI PhiUSIIL dataset ID 967 labels: 1=legitimate, 0=phishing.
CER labels: 0=benign, 1=phishing. NEVER learn from target-derived
or post-crawl features by accident; baseline trains on raw URL string only.
"""
from __future__ import annotations
import hashlib,json,re
from pathlib import Path
from urllib.parse import urlsplit
import numpy as np
import pandas as pd
from joblib import dump,load
from sklearn.model_selection import GroupShuffleSplit
from sklearn.pipeline import Pipeline
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (accuracy_score,precision_score,recall_score,f1_score,
                             roc_auc_score,average_precision_score,confusion_matrix,brier_score_loss)


def download_uci(output_path: str | Path):
    """Optional internet download performed on USER machine, never simulated."""
    try: from ucimlrepo import fetch_ucirepo
    except ImportError as exc:
        raise RuntimeError('Install optional dependency: pip install -e ".[uci]"') from exc
    ds=fetch_ucirepo(id=967)
    X=ds.data.features; y=ds.data.targets
    if 'URL' not in X.columns or y is None or y.empty:
        raise ValueError('Unexpected UCI schema; inspect upstream changes')
    labels=pd.to_numeric(y.iloc[:,0],errors='raise').astype(int)
    if not set(labels.unique()).issubset({0,1}): raise ValueError('Unexpected labels')
    p=Path(output_path);p.parent.mkdir(parents=True,exist_ok=True)
    pd.DataFrame({'url':X['URL'].astype(str),'original_label':labels,
                  'label':(labels==0).astype(int), 'source_dataset':'PhiUSIIL_UCI_967'}).to_csv(p,index=False)
    return {'path':str(p),'rows':len(labels),'phishing':int((labels==0).sum()),
            'benign':int((labels==1).sum()),'label_mapping':'original 0=phishing, 1=benign; CER 1=phishing'}


def read_url_csv(path: str | Path, source: str='cer') -> tuple[pd.DataFrame,dict]:
    path=Path(path); df=pd.read_csv(path,low_memory=False)
    columns={str(c).lower():c for c in df.columns}
    url_col=columns.get('url')
    if url_col is None: raise ValueError('CSV missing URL/url column')
    if source=='uci':
        # For an official raw UCI CSV, Label is the UCI convention.
        label_col=columns.get('original_label',columns.get('label'))
        if label_col is None: raise ValueError('UCI CSV missing original_label/label')
        # A prepared file from download_uci has both original_label and mapped label.
        labels=pd.to_numeric(df[label_col],errors='coerce').map({0:1,1:0})
    elif source=='cer':
        label_col=columns.get('label')
        if label_col is None: raise ValueError('CER CSV missing label column')
        labels=pd.to_numeric(df[label_col],errors='coerce')
    else: raise ValueError('source must be uci or cer')
    data=pd.DataFrame({'url':df[url_col].astype('string').str.strip(),'label':labels})
    before=len(data)
    data=data.dropna(subset=['url','label'])
    data=data[data['url'].str.len().between(7,4096)]
    data=data[data['label'].isin([0,1])].copy()
    data['label']=data['label'].astype(int)
    # Conflicted URL assertions cannot be silently resolved using test-label information.
    conflicts=data.groupby('url')['label'].nunique()
    conflict_urls=set(conflicts[conflicts>1].index)
    data=data[~data['url'].isin(conflict_urls)].drop_duplicates('url')
    data=data.reset_index(drop=True)
    data['host']=data['url'].map(hostname)
    data=data[data['host']!=''].copy()
    return data, {'raw_rows':before,'retained_rows':len(data),'conflicted_urls_dropped':len(conflict_urls),
                  'dropped_rows':before-len(data),'label_convention':'CER 1=phishing, 0=benign'}


def hostname(url: str) -> str:
    try:
        v=str(url).strip()
        if not re.match(r'^https?://',v,re.IGNORECASE): v='http://'+v
        return (urlsplit(v).hostname or '').lower().removeprefix('www.')
    except ValueError: return ''


def sha256_file(path: str | Path):
    h=hashlib.sha256()
    with open(path,'rb') as f:
        for b in iter(lambda:f.read(1024*1024),b''): h.update(b)
    return h.hexdigest()


def split_by_host(df: pd.DataFrame, seed: int=42):
    # Group on observed hostname, not full registrable domain. No temporal proof.
    gss=GroupShuffleSplit(n_splits=1,test_size=.2,random_state=seed)
    trv_idx,te_idx=next(gss.split(df,df.label,df.host))
    trv=df.iloc[trv_idx].copy();test=df.iloc[te_idx].copy()
    gss2=GroupShuffleSplit(n_splits=1,test_size=.25,random_state=seed+1)
    tr_idx,va_idx=next(gss2.split(trv,trv.label,trv.host))
    train=trv.iloc[tr_idx].copy(); val=trv.iloc[va_idx].copy()
    if set(train.host)&set(val.host) or set(train.host)&set(test.host) or set(val.host)&set(test.host):
        raise AssertionError('Hostname leakage across splits')
    if any(part.label.nunique()!=2 for part in (train,val,test)):
        raise ValueError('Class missing from grouped partition; use a larger source dataset')
    return train,val,test


def classifier_metrics(y,p):
    pred=(np.asarray(p)>=.5).astype(int); y=np.asarray(y).astype(int)
    result={'count':len(y),'accuracy':float(accuracy_score(y,pred)),
            'precision_phishing':float(precision_score(y,pred,zero_division=0)),
            'recall_phishing':float(recall_score(y,pred,zero_division=0)),
            'f1_phishing':float(f1_score(y,pred,zero_division=0)),
            'auprc':float(average_precision_score(y,p)),
            'brier':float(brier_score_loss(y,p)),
            'confusion_matrix_rows_true_0benign_1phishing':confusion_matrix(y,pred,labels=[0,1]).tolist()}
    if len(set(y))==2: result['auroc']=float(roc_auc_score(y,p))
    return result


def train_lexical(csv_path: str,output_dir: str,source: str='cer',
                  sample: int|None=None,seed:int=42):
    df,audit=read_url_csv(csv_path,source)
    if sample and len(df)>sample:
        # Bounded quickstart subset; do not call this temporally representative.
        df=df.sample(n=sample,random_state=seed)
    train,val,test=split_by_host(df,seed)
    model=Pipeline([
        ('tfidf',TfidfVectorizer(analyzer='char',ngram_range=(2,4),min_df=2,
                                max_features=70000,sublinear_tf=True)),
        ('classifier',LogisticRegression(max_iter=700,solver='liblinear',class_weight='balanced',random_state=seed))
    ])
    model.fit(train.url.astype(str),train.label)
    pval=model.predict_proba(val.url.astype(str))[:,1]
    ptest=model.predict_proba(test.url.astype(str))[:,1]
    out=Path(output_dir);out.mkdir(parents=True,exist_ok=True)
    dump(model,out/'url_lexical_model.joblib')
    pd.DataFrame({'url':test.url,'host':test.host,'label':test.label,
                  'prob_phishing':ptest,'partition':'test'}).to_csv(out/'holdout_predictions.csv',index=False)
    metrics={'dataset_path':str(csv_path),'dataset_sha256':sha256_file(csv_path),
             'source':source,'seed':seed,'split':'group-disjoint observed hostname (NOT temporal)',
             'audit':audit,'n_total':len(df),'n_train':len(train),'n_validation':len(val),
             'n_test':len(test),'validation':classifier_metrics(val.label,pval),
             'test':classifier_metrics(test.label,ptest),
             'limitation':'URL-only baseline; no collector provenance; not proof of zero-day performance'}
    (out/'training_report.json').write_text(json.dumps(metrics,indent=2),encoding='utf-8')
    return metrics


def score_url(model_path: str,url: str):
    model=load(model_path)
    return {'url':url,'probability_phishing':float(model.predict_proba([url])[0,1]),
            'model_kind':'URL lexical only','provenance_verified':False,
            'certificate_available':False}
