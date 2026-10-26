"""Run the quick synthetic demo or the complete offline E01-E20 workflow."""
from __future__ import annotations

import argparse
import logging
from pathlib import Path

from cerurl.e20 import run_full_pipeline
from cerurl.experiments import run_benchmark
from cerurl.simulate import generate_dataset


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--full-pipeline",
        action="store_true",
        help="Run every E01-E20 step offline instead of the quick synthetic demo",
    )
    parser.add_argument(
        "--out-root",
        default="results/full_pipeline",
        help="Fresh output directory used with --full-pipeline",
    )
    parser.add_argument(
        "--seed-runs",
        type=int,
        default=5,
        help="E20 replay seeds (0 for archive-only or at least 5)",
    )
    args = parser.parse_args()
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")

    if args.full_pipeline:
        logging.info("Starting offline E01-E20 pipeline; no live feeds will be downloaded")
        audit = run_full_pipeline(args.out_root, seed_runs=args.seed_runs)
        logging.info(
            "Pipeline status=%s completed=%d/%d blocked_or_partial=%s failed=%s",
            audit["status"],
            audit["completed_count"],
            audit["experiment_count"],
            audit["blocked_or_partial_experiments"],
            audit["failed_experiments"],
        )
        logging.info("Pipeline output: %s", audit["output_root"])
        logging.info("Detailed progress: %s", Path(audit["output_root"]) / "logs")
        return 1 if audit["failed_experiments"] else 0

    root = Path(__file__).resolve().parent
    data = root / "data" / "demo_from_scratch.jsonl"
    out = root / "results" / "demo_from_scratch"
    logging.info("Generating controlled synthetic cases, not authentic URL observations")
    generate_dataset(data, n_cases=80, seed=42)
    report = run_benchmark(str(data), str(out), budgets=(0, 1, 2), max_cases=40)
    logging.info("Synthetic cases: %d", report["n_cases"])
    logging.info(
        "Attack-audit certificate violations: %s",
        [row["certificate_violations"] for row in report["attack_audit"]],
    )
    logging.info("Quick-demo output: %s", out)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
