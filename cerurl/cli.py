"""Command-line interface. Run ``cerurl --help``."""
from __future__ import annotations
import argparse,json
from pathlib import Path
from .simulate import generate_dataset,load_cases
from .public_data import download_uci,train_lexical,score_url
from .experiments import run_benchmark,run_attack_audit
from .core import certify,quarantine_root_groups,minimum_flip_groups
from .real_seed import anchors_to_controlled
from .html_artifacts import extract_manifest
from .feeds import import_snapshot
from .repair import repair,RepairConfig
from .curation import curate_e01


def main(argv=None):
    p=argparse.ArgumentParser(prog='cerurl',description='EvidenceURL-CER research prototype')
    cmd=p.add_subparsers(dest='command',required=True)
    d=cmd.add_parser('download-uci',help='Download real UCI PhiUSIIL dataset, requires internet and [uci]')
    d.add_argument('--out',default='data/raw/phiusiil.csv')
    d=cmd.add_parser('generate',help='Generate labelled CONTROLLED-SYNTHETIC provenance cases')
    d.add_argument('--out',default='data/controlled_cases.jsonl');d.add_argument('--cases',type=int,default=250)
    d.add_argument('--seed',type=int,default=42);d.add_argument('--groups',type=int,default=6)
    d.add_argument('--shared-prob',type=float,default=.28)
    d=cmd.add_parser('benchmark',help='Run fixed-graph certificate, attack and repair experiments')
    d.add_argument('--data',default='data/controlled_cases.jsonl');d.add_argument('--out',default='results/demo')
    d.add_argument('--seed',type=int,default=7);d.add_argument('--max-cases',type=int)
    d.add_argument('--budgets',default='0,1,2')
    d=cmd.add_parser('train',help='Train URL-only phishing baseline from real local URL/label CSV')
    d.add_argument('--csv',required=True);d.add_argument('--out',default='results/url_model')
    d.add_argument('--source',choices=['cer','uci'],default='cer')
    d.add_argument('--sample',type=int);d.add_argument('--seed',type=int,default=42)
    d=cmd.add_parser('predict',help='Classify raw URL (NO evidence or resilience certification)')
    d.add_argument('--model',required=True);d.add_argument('--url',required=True)
    d=cmd.add_parser('ingest-feed',help='Import an already-downloaded PhishTank/URLhaus/Tranco CSV snapshot')
    d.add_argument('--source',required=True,choices=['phishtank','urlhaus','tranco'])
    d.add_argument('--csv',required=True);d.add_argument('--out',required=True)
    d=cmd.add_parser('extract-html',help='Safely parse LOCAL HTML artifacts (not verified collection)')
    d.add_argument('--manifest',required=True,help='CSV columns url,html_path')
    d.add_argument('--root',required=True,help='Local directory with HTML files')
    d.add_argument('--out',default='results/html_artifacts.jsonl')
    d=cmd.add_parser('seed-from-holdout',help='Create SYNTHETIC provenance cases anchored on real holdout URL predictions')
    d.add_argument('--holdout',required=True);d.add_argument('--out',default='data/controlled_on_real_urls.jsonl')
    d.add_argument('--n',type=int,default=500);d.add_argument('--seed',type=int,default=23)
    d=cmd.add_parser('quarantine',help='Simulate removal of independently confirmed compromised source roots')
    d.add_argument('--data',default='data/controlled_cases.jsonl');d.add_argument('--index',type=int,default=0)
    d.add_argument('--roots',required=True,help='Comma-separated externally VERIFIED compromised roots')
    d=cmd.add_parser('inspect',help='Inspect synthetic trust/certificate and repair case')
    d.add_argument('--data',default='data/controlled_cases.jsonl');d.add_argument('--index',type=int,default=0)
    d.add_argument('--budget',type=int,default=1);d.add_argument('--policy',default='counterfactual')
    d=cmd.add_parser('curate-e01',help='Fail-closed URLTrust/source provenance curation and leakage audit')
    d.add_argument('--index',help='Local URLTrust index (.sqlite/.db/.csv/.json/.jsonl); absent produces an explicit no-data audit')
    d.add_argument('--html-root',help='Local HTML archive root; only paths declared in the index are read')
    d.add_argument('--out',default='results/E01')
    d.add_argument('--tables',default='tables')
    d.add_argument('--decisions',help='Optional CSV with url,decision_at for post-decision graph-edge checks')
    d.add_argument('--source-schema',choices=['auto','urltrust','phiusiil','cer_binary'],default='auto',help='Documented input label convention; auto only recognises these schemas')
    args=p.parse_args(argv)
    if args.command=='download-uci': result=download_uci(args.out)
    elif args.command=='generate':
        result=generate_dataset(args.out,args.cases,args.seed,args.groups,args.shared_prob)
    elif args.command=='benchmark':
        budgets=tuple(int(x) for x in args.budgets.split(','))
        result=run_benchmark(args.data,args.out,args.seed,budgets=budgets,max_cases=args.max_cases)
        # print concise summary; full JSON written to disk
        result={'cases':result['n_cases'],'out':args.out,'attack_audit':result['attack_audit'],
                'policies':result['policies'],'budgets':result['budgets']}
    elif args.command=='train': result=train_lexical(args.csv,args.out,args.source,args.sample,args.seed)
    elif args.command=='predict':result=score_url(args.model,args.url)
    elif args.command=='ingest-feed': result=import_snapshot(args.source,args.csv,args.out)
    elif args.command=='extract-html': result=extract_manifest(args.manifest,args.root,args.out)
    elif args.command=='seed-from-holdout': result=anchors_to_controlled(args.holdout,args.out,args.n,args.seed)
    elif args.command=='quarantine':
        c=list(load_cases(args.data))[args.index]
        before=certify(c)
        q=quarantine_root_groups(c,args.roots.split(','))
        result={'before':before,'after':certify(q),'quarantined':args.roots.split(',')}
    elif args.command=='inspect':
        cases=list(load_cases(args.data)); c=cases[args.index]
        result={'case_id':c.case_id,'before':certify(c,args.budget),
                'exact_min_flip':minimum_flip_groups(c),
                'repair':repair(c,args.policy,RepairConfig(budget=args.budget))}
    elif args.command=='curate-e01':
        result=curate_e01(args.index,args.html_root,args.out,args.tables,args.decisions,args.source_schema)
        result={'out':args.out,'tables':args.tables,'flow':result['flow'],
                'pass_criteria':result['pass_criteria'],'controls':result['controls']}
    print(json.dumps(result,indent=2))
    return 0

if __name__=='__main__':main()
