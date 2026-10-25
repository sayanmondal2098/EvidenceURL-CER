# E20 reproducibility report

- Overall status: **pass_with_limitations**
- No live network access or mutable feed downloads were performed.
- E01-E19 archived experiments inventoried: 19.
- Archived statuses: `{"BASELINE_NOT_REPRODUCIBLE": 1, "NOT_RUN_INPUTS_MISSING": 1, "NOT_RUN_TEMPORAL_ELIGIBILITY_BLOCKED": 1, "PARTIAL_CONTROLLED_INVARIANT_ONLY": 1, "pass": 14, "pass_with_flagged_data_quality_findings": 1}`.
- Acquired source snapshot hashes verified: `True`.
- E20 confirmatory synthetic seeds: `[20262020, 20263029, 20264038, 20265047, 20266056]`.
- External train/calibration/test split: **not frozen**; no split was inferred.
- Campaign-level cluster inference: **unavailable**; controlled case clusters only.

## Confirmatory E20 replay comparisons

| Hypothesis | Contrast | Effect | 95% CI | Holm-adjusted p | Status |
|---|---|---:|---:|---:|---|
| E20-H1 | E13 CER-guided minus random final actual loss at B=3 | -0.9 | [-1.3833333333333333, -0.49166666666666664] | 0.00019998000199980003 | evaluated_controlled_only |
| E20-H2 | E18 graph minus no-graph all-case accuracy | 0.0 | [0.0, 0.0] | 1.0 | evaluated_controlled_only |

## Archived primary hypotheses

| ID | Status | Observed result | Uncertainty |
|---|---|---|---|
| H1 | descriptive_controlled | shared_five: 5 naive vs 1 source-aware witnesses; flip budget 3 vs 1 | No inferential CI: one deterministic controlled topology; no campaigns. |
| H2 | bounded_exhaustive_software_check | 0 violations across 5724 attack checks | No statistical CI; finite controlled instances and the stated exactness limits apply, not a universal real-world guarantee. |
| H3 | archived_single_seed_exploratory | Archived E13 summary contains matched policies and paired trial rows; 42 policy-budget summary rows are available. | Not treated as confirmatory: archived run is one seed with three repeats; campaign/source-group cluster identifiers are unavailable. |
| H4 | NOT_RUN_INPUTS_MISSING | No effect size reported because prospective ledgers are missing. | No CI or p-value; E16 correctly reported no performance metrics. |
| H5 | archived_controlled_no_increment_observed | {"accuracy_denominator": "all paired cases; abstentions count as incorrect for this graph-increment comparison", "assessment": "graph incremental value is supported in this synthetic design only if the paired interval excludes zero; no field-performance implication follows", "bootstrap_95_ci": [0.0, 0.0], "fusion": "within-source aggregation followed by per-node median across source groups, then graph propagation", "graph_fusion_all_case_accuracy": 0.8958333333333334, "interval_excludes_zero": false, "no_graph_fusion_all_case_accuracy": 0.8958333333333334, "paired_accuracy_delta_graph_minus_no_graph": 0.0} | Archived per-case bootstrap interval is controlled-synthetic only and not campaign-clustered; interval is not evidence of field benefit. |
| H6 | archived_controlled_correctness_check | scales=4; maximum recorded update error=2.466915560717098e-13 | Deterministic numeric equality check, not a population CI. |

## Reproduction instructions

Run `python -m cerurl.cli run-e20` from the repository root. The command hash-verifies local archived results and acquired release receipts, reruns the preregistered controlled E06/E13/E18 seed subset offline, and regenerates E20 summary tables, effect plots, report, and manifest. It does not replay original external source acquisition or recreate unavailable field splits. For restricted or missing inputs, see `issues.csv`, `source_license_manifest.json`, and `frozen_manifest.json`.

Archived figure files are hash-linked in `artifact_manifest.csv`; the E20 hypothesis figure is regenerated from the E20 seed-replay CSVs. Earlier experiment figures are not claimed regenerated unless their experiment runner is explicitly rerun from its archived raw inputs.

## Limitations and ethics

No E20 result is a field performance estimate. Several source terms do not constitute redistribution clearance. No real campaign identifiers exist for the controlled replays, and archived runs often have fewer than five independent seeds. E02/E03 remain blocked, E16 has missing prospective ledgers, and the original URLTrust implementation is not pinned locally. No raw acquired URLs or feed data are copied into E20.
