# Preregistered E01–E20 Experimental Protocol (template to freeze before execution)

## Hypotheses

H1: dependency-aware certificates reduce false robustness claims relative to independent-report assumptions.
H2: exact fixed-graph certificates have zero empirical soundness violations under the explicitly bounded group-control model on exhaustively searchable instances.
H3: at matched acquisition budgets, certificate-guided repair improves certified risk-coverage and verified corrections relative to random, uncertainty and diversity baselines.
H4: benefits persist for first-seen phishing campaigns with out-of-time data and real acquisition costs, with abstentions accounted for.

No hypothesis is an achieved result. Freeze selected hypotheses and tests with a dated registration commit **before** observing final test results.

## Release modes

- **Historical:** local `index.sql`, offline HTML, verified external metadata. Accurate source and label semantics, but usually no authenticated collector ancestry. Enables baseline and restricted-case studies only.
- **Prospective:** timestamped snapshot receipt, independent source collection, attestable provenance where actually supported. Enables active decision repair and real source-corruption studies.
- **Controlled:** deliberately generated observations with known attack/control sets, local `.test` sites, seeded action-outcome menus. Enables exhaustive and isolated attacks, not a substitute for field effectiveness.

## Key independent variables

- Group-compromise budget b ∈ {0,1,2,3,4,5}, plus a *separate* fractional model for large populations.
- Graph edge attack budget e ∈ {0,1,2,5,10} subject to edge validity and semantic type.
- Acquisition budget B ∈ {0,1,2,3,5,10} observations and separately currency/latency costs.
- Observational setting: same upstream feed / independent feeds / cloned collector / independent ASN and device / cloaked site / timestamp-expired evidence.
- Evaluation period: development, calibration, future test; additional OOD source.
- Verdict policy: calibrated malicious, calibrated benign, abstain; threshold preregistered on calibration partition.

## Strong baselines

B0 lexical and content-only logistic regression or XGBoost; B1 frozen original URLTrust; B2 provenance-unaware robust fusion; B3 provenance-group-aware fusion; B4 certificate-only (no repair); B5 random repair; B6 uncertainty sampling; B7 disagreement sampling; B8 provenance-diversity heuristic; B9 expected-risk greedy without certificate; B10 EvidenceURL-CER full. Add graph-robust baseline URL2Path/PGNNCert/GNNGuard where code and assumptions permit. If a model is unavailable, mark explicitly rather than reimplement an undocumented approximation under the original name.

## Core metrics and denominator semantics

- `CERT_COVERAGE_b` = count of *correct and incorrect* issued decisions carrying a sound b-budget certificate / total tested URLs; separately show certified *accuracy* among those decisions.
- `ATTACK_FLIP_RATE_b` = successful decision flip / attacked cases for fixed attack budget, with tie/abstention outcomes also separately counted.
- `REPAIR_CORRECTION` = initially wrong issued decisions that become correct / initially wrong issued decisions receiving repair attempts.
- `REPAIR_DEGRADATION` = initially correct decisions that become wrong / initially correct decisions receiving repair attempts.
- `SELECTIVE_RISK` = erroneous issued decisions / all issued decisions, at each coverage; no silent exclusion of abstention.
- `COST_PER_CORRECTION` = total acquisition costs / number of genuine decision corrections, with undefined/NA if zero corrections.
- `TTR` time until trustworthy (soundly certified) verdict or abstention; plot right-censored curves for unresolved instances.

Do not report only accuracy on decided cases without coverage. Confusion matrices must reveal abstained count.

## Statistical reporting

Five independent seeds minimum for stochastic attacks or actions, with more in small cohorts. Use 95% cluster bootstrap confidence intervals based on campaign/domain/source groups and a prespecified block design. Use paired permutation or cluster bootstrap contrasts for preregistered method pairs; Holm correction for primary multiple comparisons. For cost/latency, show median, p95, and confidence intervals. Provide absolute effect sizes and confidence intervals. No artificial claims of significance from simulated pseudo-replication.

## Per-experiment required artifacts

`results/E##_name/config.json`, `raw_runs.jsonl`, `metrics.csv`, `figures/*.pdf`, `tables/*.tex`, `analysis.md`, `run_manifest.json`, `stderr.log` (as appropriate). All outputs identify whether they use historical, prospective, controlled or synthetic data. Any missing dataset yields `run_status=NOT_RUN`, and a blocker description.

## Core final plots and tables

Fig 1 cohort/split flow; Fig 2 source dependency graph; Fig 3 threat model and CER loop; Fig 4 soundness vs source budgets; Fig 5 attack flip probability vs budget; Fig 6 certified coverage vs attack cost; Fig 7 repair correction/degradation vs acquisitions; Fig 8 risk-coverage; Fig 9 first-seen AUPRC by month; Fig 10 latency and cost distributions; Fig 11 graph robustness vs joint budgets; Fig 12 attack/counterfactual case studies. Tables: dataset sizes, source provenance, threat assumptions, complete baseline comparisons, full ablations, timing and memory, error taxonomy, statistical hypothesis tests.

## Ethics and disclosure

Do not package sensitive live phishing URLs, login forms with personal information, malware payloads or restricted datasets in a public release. Prefer sanitized URL hashes, controlled examples and replayable fingerprints. Obtain institutional approval and source licensing permissions for any active collection.
