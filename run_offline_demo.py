"""Zero-download end-to-end CER demo. All data is controlled synthetic."""
from pathlib import Path
from cerurl.simulate import generate_dataset
from cerurl.experiments import run_benchmark

if __name__=='__main__':
    root=Path(__file__).resolve().parent
    data=root/'data'/'demo_from_scratch.jsonl'
    out=root/'results'/'demo_from_scratch'
    print('Generating controlled synthetic data, NOT authentic URL observations')
    generate_dataset(data,n_cases=80,seed=42)
    report=run_benchmark(str(data),str(out),budgets=(0,1,2),max_cases=40)
    print('Synthetic cases:', report['n_cases'])
    print('Attack-audit certificate violations:', [r['certificate_violations'] for r in report['attack_audit']])
    print('Output directory:',out)
