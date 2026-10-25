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
from .e01_sources import audit_acquired_sources
from .e05 import run_e05
from .e06 import run_e06
from .e07 import run_e07
from .e08 import run_e08
from .e09 import run_e09
from .e10 import run_e10
from .e11 import run_e11
from .e12 import run_e12
from .e13 import DEFAULT_BUDGETS, run_e13
from .e02 import prepare_e02
from .e03 import prepare_e03
from .e04 import prepare_e04
from .sources import write_source_registry
from .acquire import acquire_sources


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
    d=cmd.add_parser('audit-e01-sources',help='E01 audit over receipt-backed acquired snapshots under data/raw')
    d.add_argument('--raw-dir',default='data/raw')
    d.add_argument('--out',default='results/E01')
    d.add_argument('--tables',default='tables')
    d.add_argument('--psl',help='Public Suffix List file (default: data/raw/public_suffix_list/public_suffix_list.dat)')
    d=cmd.add_parser('run-e05',help='E05 shared-upstream provenance graph vs naive independence (controlled topologies)')
    d.add_argument('--out',default='results/E05')
    d.add_argument('--tables',default='tables')
    d=cmd.add_parser('run-e06',help='E06 exact certificate vs exhaustive enumeration soundness check')
    d.add_argument('--out',default='results/E06')
    d.add_argument('--tables',default='tables')
    d.add_argument('--cases',type=int,default=1200)
    d.add_argument('--seed',type=int,default=20260606)
    d=cmd.add_parser('run-e07',help='E07 MILP/LP/knapsack certificate scaling and soundness')
    d.add_argument('--out',default='results/E07')
    d.add_argument('--tables',default='tables')
    d.add_argument('--sizes',default='20,50,100,500')
    d.add_argument('--budgets',default='0,1,2,3,4,5')
    d.add_argument('--reps',type=int,default=2)
    d.add_argument('--time-limit',type=float,default=10.0)
    d=cmd.add_parser('run-e08',help='E08 joint source + typed-graph attacks and joint certificate')
    d.add_argument('--out',default='results/E08')
    d.add_argument('--tables',default='tables')
    d.add_argument('--cases',type=int,default=96)
    d.add_argument('--seed',type=int,default=20260808)
    d=cmd.add_parser('run-e09',help='E09 source-compromise and malicious-feed injection resilience')
    d.add_argument('--out',default='results/E09')
    d.add_argument('--tables',default='tables')
    d.add_argument('--cases',type=int,default=240)
    d.add_argument('--seed',type=int,default=20260909)
    d=cmd.add_parser('run-e10',help='E10 evidence replay, staleness and storage tampering')
    d.add_argument('--out',default='results/E10')
    d.add_argument('--tables',default='tables')
    d.add_argument('--n-per',type=int,default=150)
    d.add_argument('--seed',type=int,default=20261010)
    d=cmd.add_parser('run-e11',help='E11 isolated HTTP cloaking sites, acquisition policies and ground-truth audit')
    d.add_argument('--out',default='results/E11')
    d.add_argument('--tables',default='tables')
    d.add_argument('--n-per',type=int,default=20,help='Replicates per controlled scenario')
    d.add_argument('--seed',type=int,default=20261111)
    d.add_argument('--budgets',default='1,3,5',help='Common attempt budgets, including the first observation')
    d.add_argument('--no-plots',action='store_true')
    d=cmd.add_parser('run-e12',help='E12 admissible counterfactual challenges and attack localization')
    d.add_argument('--out',default='results/E12')
    d.add_argument('--tables',default='tables')
    d.add_argument('--cases',type=int,default=120)
    d.add_argument('--seed',type=int,default=20261212)
    d=cmd.add_parser('run-e13',help='E13 matched-budget repair policy comparison')
    d.add_argument('--out',default='results/E13')
    d.add_argument('--tables',default='tables')
    d.add_argument('--cases',type=int,default=40)
    d.add_argument('--repeats',type=int,default=3)
    d.add_argument('--seed',type=int,default=20261313)
    d.add_argument('--budgets',default=','.join(map(str,DEFAULT_BUDGETS)))
    d=cmd.add_parser('prepare-e02',help='Create an honest frozen-URLTrust reproduction preflight package')
    d.add_argument('--out',default='results/E02')
    d.add_argument('--audit',default='results/E01/audit.json')
    d=cmd.add_parser('source-registry',help='Write prospective source intake registry; does not download data')
    d.add_argument('--json-out',default='data/source_registry.json')
    d.add_argument('--markdown-out',default='docs/SOURCE_ACQUISITION_REGISTRY.md')
    d=cmd.add_parser('acquire-sources',help='One-plan downloader for explicitly authorised source artifacts')
    d.add_argument('--plan',required=True,help='JSON acquisition plan; see data/source_acquisition_plan.example.json')
    d.add_argument('--out',default='data/acquired')
    d.add_argument('--dry-run',action='store_true')
    d.add_argument('--only',help='Comma-separated source IDs to acquire; leaves other plan entries untouched')
    d.add_argument('--log',default='data/logs/source_acquisition.jsonl',help='Append a URL-free JSONL run log here; pass an empty string to disable')
    d.add_argument('--quiet',action='store_true',help='Suppress live acquisition progress messages on the terminal')
    d=cmd.add_parser('prepare-e04',help='Create assurance/maliciousness separation audit artifacts')
    d.add_argument('--out',default='results/E04')
    d.add_argument('--audit',default='results/E01/audit.json')
    d.add_argument('--authoritative-dir',help='Pinned authoritative URLTrust source checkout; required before any E02 model can run')
    d=cmd.add_parser('prepare-e03',help='Create a fail-closed temporal/domain-disjoint evaluation package')
    d.add_argument('--out',default='results/E03')
    d.add_argument('--audit',default='results/E01/audit.json')
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
    elif args.command=='audit-e01-sources':
        result=audit_acquired_sources(args.raw_dir,args.out,args.tables,args.psl)
        result={'out':args.out,'tables':args.tables,'flow':result['flow'],
                'pass_criteria':result['pass_criteria'],'controls':result['controls']}
    elif args.command=='run-e05':
        a=run_e05(args.out,args.tables); result={'out':args.out,'pass_criteria':a['pass_criteria'],'controls':a['controls']}
    elif args.command=='run-e06':
        a=run_e06(args.out,args.tables,args.cases,args.seed)
        result={'out':args.out,'cases':a['cases'],'runtime_seconds':a['runtime_seconds'],'soundness':{k:a['soundness'][k] for k in ('violations','kinds')},'pass_criteria':a['pass_criteria']}
    elif args.command=='run-e07':
        a=run_e07(args.out,args.tables,tuple(int(x) for x in args.sizes.split(',')),tuple(int(x) for x in args.budgets.split(',')),args.reps,args.time_limit)
        result={'out':args.out,'cases':a['cases'],'runtime_seconds':a['runtime_seconds'],'soundness':a['soundness']['violations'],'certifier_comparison':a['certifier_comparison'],'by_size':a['by_size'],'pass_criteria':a['pass_criteria']}
    elif args.command=='run-e08':
        a=run_e08(args.out,args.tables,args.cases,args.seed)
        result={'out':args.out,'cases':a['cases'],'actionable_cases':a['actionable_cases'],'runtime':a['runtime'],'soundness':a['soundness'],'property_tests':a['property_tests'],'semantic_preserving_checks':a['semantic_preserving_checks'],'pass_criteria':a['pass_criteria']}
    elif args.command=='run-e09':
        a=run_e09(args.out,args.tables,args.cases,args.seed)
        result={'out':args.out,'cases':a['cases'],'states':a['states'],'runtime_seconds':a['runtime_seconds'],'soundness':a['soundness'],'cross_checks':a['cross_checks'],'white_box_b2_untargeted':a['white_box_b2_untargeted'],'pass_criteria':a['pass_criteria']}
    elif args.command=='run-e10':
        a=run_e10(args.out,args.tables,args.n_per,args.seed)
        result={'out':args.out,'items':a['items'],'runtime_seconds':a['runtime_seconds'],'detection':a['detection'],'decision_impact':a['decision_impact'],'latency_ms':a['latency_ms'],'time_to_certificate_invalidation':a['time_to_certificate_invalidation'],'pass_criteria':a['pass_criteria']}
    elif args.command=='run-e11':
        a=run_e11(args.out,args.tables,args.n_per,args.seed,tuple(int(x) for x in args.budgets.split(',')),plots=not args.no_plots)
        result={'out':args.out,'sites':a['sites'],'policy_trials':a['policy_trials'],
                'runtime_seconds':a['runtime_seconds'],'summary':a['summary'],'pass_criteria':a['pass_criteria']}
    elif args.command=='run-e12':
        a=run_e12(args.out,args.tables,args.cases,args.seed)
        result={'out':args.out,'cases':a['cases'],'exact_cases':a['exact_cases'],
                'heuristic_cases':a['heuristic_cases'],'summary':a['summary'],
                'pass_criteria':a['pass_criteria']}
    elif args.command=='run-e13':
        a=run_e13(args.out,args.tables,args.cases,args.repeats,args.seed,
                  tuple(int(x) for x in args.budgets.split(',')))
        result={'out':args.out,'cases_per_repeat':a['cases_per_repeat'],
                'repeats':a['repeats'],'trial_count':a['trial_count'],
                'runtime_seconds':a['runtime_seconds'],'efficacy':a['efficacy'],
                'pass_criteria':a['pass_criteria']}
    elif args.command=='prepare-e02': result=prepare_e02(args.out,args.audit,args.authoritative_dir)
    elif args.command=='prepare-e03': result=prepare_e03(args.out,args.audit)
    elif args.command=='prepare-e04': result=prepare_e04(args.out,args.audit)
    elif args.command=='source-registry': result=write_source_registry(args.json_out,args.markdown_out)
    elif args.command=='acquire-sources': result=acquire_sources(args.plan,args.out,args.dry_run,set(args.only.split(',')) if args.only else None,args.log,not args.quiet)
    print(json.dumps(result,indent=2))
    return 0

if __name__=='__main__':main()
