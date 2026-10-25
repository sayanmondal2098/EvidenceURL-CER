# EvidenceURL-CER | Executable Research Prototype

**Title:** Certified Counterfactual Evidence Repair for Adversarially Resilient Malicious-URL Intelligence.

A runnable Python reference implementation of (i) an optional real public-data URL-only phishing baseline; (ii) a controlled simulated multi-source provenance benchmark; (iii) exact small-root-group robustness certification of a **fixed nonnegative graph mixing model**; (iv) a conservative row-L1 graph-perturbation certificate; (v) an honest counterfactual evidence-acquisition baseline and comparators; and (vi) repeatable evaluation, audit logs, plots and tests.

> **Research integrity:** This code is an executable *prototype*, not a completed verified production phishing detector. The included multi-collector/attack dataset is artificial and marked `controlled_synthetic`. No real sensor origin, attestation, historical timestamp, field zero-day detection, or measured TPR is claimed. The URLTrust-style operator is a simplified incoming-mixing formulation, **not the original frozen URLTrust implementation**. Integrating that original implementation remains a separate experiment.

## Quick start (NO dataset and NO internet required)

Requires Python 3.10+:

```bash
python -m venv .venv
# Windows: .venv\\Scripts\\activate
# Linux/macOS: source .venv/bin/activate
python -m pip install -e '.[test]'
pytest -q
cerurl generate --out data/controlled_cases.jsonl --cases 250 --seed 42
cerurl inspect --data data/controlled_cases.jsonl --index 0 --budget 1
cerurl benchmark --data data/controlled_cases.jsonl --out results/controlled_demo --max-cases 60 --budgets 0,1,2
```

Main outputs: `results/controlled_demo/benchmark_report.json`, `repair_trials.jsonl`, `results.csv`, `certified_coverage.png`, `cost_vs_certification.png`.

To evaluate more cases, omit `--max-cases`. Runtime grows with number of source groups and attack budgets; exhaustive attack checks are exponential and explicitly restricted to small synthetic cases.

## Real public dataset (optional, requires INTERNET on YOUR computer)

Official repository: https://archive.ics.uci.edu/dataset/967/phiusiil+phishing+url+dataset

PhiUSIIL dataset UCI ID 967, 235,795 observations, 54 features. **Original labels: `1 = legitimate`, `0 = phishing`. Our CER labels: `0 = benign`, `1 = phishing`.** Original dataset citation: A. Prasad and S. Chandra, *PhiUSIIL: A diverse security profile empowered phishing URL detection framework based on similarity index and incremental learning*, Computers & Security, 2024, https://doi.org/10.1016/j.cose.2023.103545. Dataset CC BY 4.0; preserve attribution.

```bash
python -m pip install -e '.[uci,test]'
cerurl download-uci --out data/raw/phiusiil.csv
# Prepared download contains CER-mapped label already:
cerurl train --csv data/raw/phiusiil.csv --source cer --out results/real_url_baseline --sample 20000
cerurl predict --model results/real_url_baseline/url_lexical_model.joblib --url 'https://example.org/path'
```

For the **raw official UCI CSV** with column `URL` and original `label`, use `--source uci` to invert labels. `--source cer` assumes your CSV already contains CER labels. The `download-uci` command produces BOTH `original_label` and correctly mapped `label`, so choose `--source cer` for that file.

For a smoke check without any download, train on `examples/SMOKE_SYNTHETIC_URLS.csv`. The `.test` URLs and labels are **artificial**; their metrics establish only software functionality and must never appear as empirical detection results.

**Baseline validity:** training uses raw URL strings ONLY, via character TF-IDF and logistic regression; split groups by observed hostname to reduce duplicate-site leakage. This is **NOT temporal** or source-separated zero-day evaluation, and is **NOT** an attested or provenance-rich phishing system. `label`, `original_label`, `Domain` statistics and any future post-hoc labels are excluded from training features.

## Connect a real holdout to a controlled attack simulator

```bash
cerurl seed-from-holdout --holdout results/real_url_baseline/holdout_predictions.csv --out data/synthetic_on_real_urls.jsonl --n 300 
```
and then run the benchmark:
```bash
cerurl benchmark --data data/synthetic_on_real_urls.jsonl --out results/synthetic_on_real_url_anchors --max-cases 40
```

ONLY the anchor URL, its supplied held-out label and URL-only model prediction come from the input holdout (which itself may be synthetic). Collector observations, source identities, provenance roots and repair outcomes are **simulated from the labels**, and are labelled `synthetic_perturbation_on_anchor_label`. Never use these results as a real sensor or zero-day robustness result.

## Safely inspect LOCAL HTML captures

Create a CSV with `url,html_path`, relative to a local HTML root. Example:

```bash
cerurl extract-html --manifest examples/html_manifest.csv --root examples/html --out results/local_html.jsonl
```

This parses file bytes without visiting external links, running JavaScript, or executing downloads. Its output includes SHA-256, links, scripts, iframe references, form actions, and password-input presence. It explicitly leaves capture time `null` and source verification `false` unless independently established. A local HTML record is **not independent witness evidence** and is not fed into resilience certification automatically.

## E01 provenance curation and leakage audit

For a locally supplied URLTrust-style index (CSV, JSON/JSONL, or SQLite table) and its separately archived HTML directory:

```bash
cerurl curate-e01 --index database/index.sqlite --html-root database --out results/E01 --tables tables
```

The adapter also recognises the local prepared PhiUSIIL release and verifies
that its `label` is the exact inverse of `original_label` before any row is
included:

```bash
cerurl curate-e01 --index data/raw/phiusiil.csv --source-schema phiusiil --out results/E01 --tables tables
```

The command produces normalized `tables/urls.csv`, `tables/observations.jsonl`,
source/provenance and URL-graph tables, plus `results/E01/audit.json`, a complete
inclusion/exclusion ledger, duplicate/conflict report, and sanitized sample
ledger. `result=0` maps only to `benign` and `result=1` only to `phishing`.
It never treats `created_date` as HTML capture time, never treats unavailable
HTML as benign, and blocks first-seen evaluation when historical availability
metadata is absent.  The built-in assertion controls demonstrate detection of
train/test URL overlap, post-decision evidence, and two feeds mirroring one
upstream source.  It does not import external threat feeds; those require a
separately retained, authorised snapshot and provenance record before they can
be added to an E01 run.

For the receipt-backed snapshots under `data/raw` (PhiUSIIL, PhishTank, OpenPhish,
Phishing.Database, URLhaus; popularity lists as context only; Public Suffix List for
eTLD+1), run `cerurl audit-e01-sources`. Artifacts whose bytes do not match their
receipt hash are not ingested. Output is the same E01 file set plus
`results/E01/etld_plus_one_counts.csv`.

## E05 shared-upstream source graph

`cerurl run-e05` builds controlled provenance topologies (shared source, independent, partial overlap, bad-data cycle, unknown ancestry, same operator, copied reports), compares "N reports = N witnesses" with source-aware independence, and writes `results/E05` (audit, summary/group/compromise CSVs, plots) and `tables/e05_independence.tex`. Cycles are flagged and collapsed; unknown ancestry is pooled into one attack unit, never counted as independent.

## E06 exact certificate and exhaustive soundness

`cerurl run-e06 [--cases 1200 --seed 20260606]` validates `core.certify` against an independent exact (rational-arithmetic) enumeration of every attack subset (2-15 groups; ties, abstention, overlap, shared ancestors, zero weights, dangling vertices, alpha 0 and 0.99). It writes `results/E06` (`audit.json`, `per_case_min_attack_cost.csv`, `attack_witnesses.csv`, `violations.jsonl`, `soundness_summary.png`) and `tables/e06_soundness.tex`. If any certified case is actually flipped, or the built-in unsound-certifier controls are not detected, the command raises and **withholds the tables and plots**.

## E07 scaling via integer and linear programming

`cerurl run-e07 [--sizes 20,50,100,500 --budgets 0,1,2,3,4,5 --reps 2 --time-limit 10]` formulates maximum descendant-coverage damage as a binary program (HiGHS via `scipy.optimize.milp`) and compares it with exhaustive enumeration (G<=20), the LP relaxation and a fractional-knapsack bound. Only upper bounds on damage can certify; the greedy attack is reported as empirical robustness only, and a timed-out solve certifies only through its valid dual bound, otherwise the case is unknown. Writes `results/E07` (`audit.json`, `results.csv`, `solver_inputs.npz`, `solver_outputs.jsonl`, `bound_tightness.png`) and `tables/e07_scaling.tex`; any unsound certificate raises and withholds plots.

## E08 joint source and typed-graph attacks

`cerurl run-e08 [--cases 96 --seed 20260808]` adds typed graph perturbations (hyperlink insert/remove/reweight, redirects confined to the original target's site, immutable structural edges, and zero-cost semantics-preserving edits) with a second edge budget `k` (ops of step 0.1, so row-l1 `eps = min(2, 2k*0.1)`), recomputes the graph snapshot after every perturbation, and compares pure-source, pure-graph and joint attacks (exhaustive over the 22 strongest typed ops, k<=3, all source subsets b<=3, plus random continuous trials). The joint bound is the E06 source damage plus `alpha*eps/(2(1-alpha))` (induced infinity norm, row-stochastic normalisation, proof in the `e08.py` docstring); it abstains for alpha>0.95, vacuous graph terms, or out-of-type/non-stochastic graphs. Writes `results/E08` (`audit.json`, `cells.csv`, `attack_witnesses.csv`, `heatmaps.png`) and `tables/e08_joint.tex`; any soundness failure raises and withholds plots.

## Run every experiment (step by step)

Run from the project root. On Windows replace `cerurl` with `.\venv\Scripts\python.exe -m cerurl.cli` if the console script is not on PATH.

```bash
# 0. Setup and unit tests
python -m venv venv && venv\Scripts\activate        # Linux/macOS: source venv/bin/activate
python -m pip install -e ".[test]"
pytest -q

# 1. Acquire authorised snapshots (needs internet; keeps hashed receipts under data/raw)
cerurl source-registry
cerurl acquire-sources --plan data/source_acquisition_plan.json --out data/raw --dry-run   # review first
cerurl acquire-sources --plan data/source_acquisition_plan.json --out data/raw
#    (Public Suffix List for eTLD+1: data/raw/public_suffix_list/public_suffix_list.dat + .receipt.json)

# E01 provenance and leakage audit
cerurl audit-e01-sources --raw-dir data/raw --out results/E01 --tables tables        # ~2 min
#    URLTrust index + HTML archive, if you have them:
#    cerurl curate-e01 --index database/index.sqlite --html-root database --out results/E01 --tables tables

# E02 frozen-URLTrust reproduction preflight (needs E01; stays blocked without the pinned authoritative checkout)
cerurl prepare-e02 --out results/E02 --audit results/E01/audit.json [--authoritative-dir PATH]

# E03 temporal / domain-disjoint evaluation gate (fail-closed without authenticated times)
cerurl prepare-e03 --out results/E03 --audit results/E01/audit.json

# E04 assurance vs maliciousness separation audit
cerurl prepare-e04 --out results/E04 --audit results/E01/audit.json

# E05 shared-upstream source graph (controlled topologies)
cerurl run-e05 --out results/E05 --tables tables

# E06 exact certificate soundness (halts downstream plots on any violation)
cerurl run-e06 --out results/E06 --tables tables

# E07 MILP / LP scaling of exact certificates (~30 s)
cerurl run-e07 --out results/E07 --tables tables
# E08 joint source + typed-graph attacks (~20 s)
cerurl run-e08 --out results/E08 --tables tables

# Controlled benchmark / repair demo (feeds the certification plots in "Quick start")
cerurl generate --out data/controlled_cases.jsonl --cases 250 --seed 42
cerurl benchmark --data data/controlled_cases.jsonl --out results/controlled_demo --max-cases 60 --budgets 0,1,2

# Optional real URL-only baseline (see sections above)
cerurl download-uci --out data/raw/phiusiil.csv
cerurl train --csv data/raw/phiusiil.csv --source cer --out results/real_url_baseline --sample 20000
```

E09-E20 are protocol items in `docs/EXPERIMENT_PROMPTS_E01_E20.md` and have no runnable command yet. Run order matters: E01 first (E02-E04 read `results/E01/audit.json`); run E06 before generating or publishing any certification plot from `benchmark`.

## Confirmed compromised-source quarantine

```bash
cerurl quarantine --data data/controlled_cases.jsonl --index 0 --roots c0
```

Source quarantine requires **external proof** that a root was compromised, such as an actual signature failure or formally validated provenance issue. Mere disagreement with a prediction is not proof. If all evidence for any node is removed, certification fails closed rather than silently inventing a benign observation.

## Formal model and exact guarantee

Let observation `o` for node `i` have risk `z_o ∈ [0,1]`, fixed weight `w_o>=0`, and upstream provenance root ancestors `A(o)`. For each node, its observation weights sum to one. Let `P` be a fixed row-stochastic incoming-mixing matrix and `alpha ∈ [0,1)`. Define

```
r_i = Σ_{o.node=i} w_o z_o
x = (1-alpha) r + alpha P x
x = B r,  B=(1-alpha)(I-alpha P)^(-1)
```

The score for target `u` is `x_u=Σ_o c_o z_o`, where `c_o=B[u,o.node]*w_o>=0` and `Σ c_o=1`. Under compromise of a set of at most `b` root groups, the attacker may alter ALL observations descended from ANY compromised root, each to an arbitrary value in `[0,1]`, but may not alter the roots, graph, weights, labels, or thresholds. Thus the **exact** worst-case downward damage is

```
D_down(b) = max_{|S| <= b} Σ_{o:A(o) intersects S} c_o z_o
```

and the upward damage substitutes `(1-z_o)`. Exhaustive enumeration establishes exactness for small root group sets; for larger groups the code computes a **safe, conservative union upper bound** instead of falsely asserting exactness. A decision is certified if its entire reachable interval stays inside its original actionable class region (`>=tau_m` for malicious, `<=tau_b` for benign). Scores between the thresholds abstain.

**Graph extension:** If graph changes satisfy `max_i ||Q_i-P_i||_1 <= eps`, with both `P,Q` row-stochastic, the extra conservative score-change allowance is `alpha*eps/(2*(1-alpha))`. This follows the fixed-point contraction and total-variation bound for `x in [0,1]^n`. Certification requires the supplied eps to actually bound the possible graph perturbations. It is NOT sufficient to specify an arbitrary guessed eps.

**Minimum attack:** `cerurl inspect` also uses exact enumeration to estimate the smallest root-group budget needed to change an actionable verdict on a small graph. This applies ONLY to the fixed-input threat model.

## Active evidence repair

Repair actions are pre-generated but their **observed values are sealed** until acquisition. Policy comparison:

* `counterfactual`: evaluate hypothetical observations at values zero and one, estimate current node conditional probability (using the existing score), and rank actions by expected robust-decision surrogate improvement per cost.
* `random`: uniformly sample feasible available actions.
* `uncertainty`: inspect an uncertain node.
* `cheapest`: select the least expensive admissible action.

All policies use identical test cases and action inventories. The counterfactual policy is a **heuristic, not proven optimal**. The model intentionally permits no improvement, degraded decisions, and abstention. The benchmark records each of these outcomes and never hides negative results. Actual live re-collection and truthful fresh independent source provenance remain future work.

## Files

```text
cerurl/core.py         fixed-graph exact/conservative source and graph certificates
cerurl/simulate.py     transparent controlled provenance generator
cerurl/repair.py       policy baselines and sealed-oracle action execution
cerurl/experiments.py  adversarial enumeration, benchmark, reports and charts
cerurl/metrics.py      certified coverage, abstentions, corrections/degradations
cerurl/public_data.py  official UCI downloader, label validation, URL-only ML baseline
cerurl/real_seed.py    synthetic perturbations anchored on real held-out labels
cerurl/html_artifacts.py read-only local HTML extraction (no live crawling)
cerurl/cli.py          CLI commands
examples/              .test fixture only; NO real malware
results/controlled_demo/ actually executed controlled example reports

tests/                  formal-assumption regression and leakage tests
docs/                   companion detailed experiment prompts and methods
```

## Experimental limitations and honesty checklist

- Grouped by full observed **hostname** (not eTLD+1). True campaign/domain-disjoint and strict chronological splits need additional verified metadata.
- Certificate soundness assumes accurate upstream ancestry; fabricated root independence invalidates it.
- Signatures and hashes prove integrity/authorship, not truthful webpage content. This prototype does **not** implement TPM/TEE, real signing, append-only logs, or live trusted provenance.
- Correlated-source compromise is explicitly represented in the simulator; source-group units are not equal to individual URL reports.
- The small graph uses a stylized incoming-mixing operator and synthetic node relationships. No automatic maliciousness inheritance from arbitrary hyperlinks is justified.
- Real first-seen/zero-day claims need prospectively collected, time-stamped, nonleaky phishing samples and a held-out evaluator. The UCI dataset does not satisfy that design alone.
- E01-E20 full research protocol is in docs. This code implements a **runnable MVP for selected experiments**, not all twenty real-world field experiments.
- The packaged figures are **controlled synthetic illustrations**. Do not put them in the journal as real phishing detection results.

## License

Code: MIT (see LICENSE). UCI dataset stays with its own license and attribution. No external real dataset is redistributed here.

## Optional import of additional public feed snapshots

Download and retain an **authorised feed snapshot** according to the source's usage terms, then import locally. The code does not fetch live suspicious URLs:

```bash
cerurl ingest-feed --source phishtank --csv data/raw/phishtank_verified.csv --out data/phishtank_records.jsonl
cerurl ingest-feed --source urlhaus --csv data/raw/urlhaus.csv --out data/urlhaus_records.jsonl
cerurl ingest-feed --source tranco --csv data/raw/tranco.csv --out data/tranco_candidates.jsonl
```

- PhishTank verified records are labelled `phishing`; pending records remain `unknown`.
- URLhaus records are `malware_distribution`, **not automatically phishing**.
- Tranco records remain `benign_candidate_unverified`, **not known benign**.
- Local ingest time is separate from source-reported verification/submission time; no genuine HTML capture time is invented.
- Snapshot records cannot directly substitute for independent collector observations in a certification experiment.

## One-command authorised source acquisition

The source registry and [example acquisition plan](data/source_acquisition_plan.example.json) cover PhiUSIIL, PhishTank, PhishingEval, Common Crawl, Tranco, and PhiShark 2026. Copy the example to a private local plan, pin the intended release/crawl URLs, record the applicable terms, and obtain any required access approval. Then acquire every enabled source with one command:

```bash
cerurl acquire-sources --plan data/source_acquisition_plan.json --out data/acquired
```

Use `--dry-run` first. Each download receives a SHA-256 receipt containing its retrieval time, source/release identifiers, selected response headers, and terms reference. The command refuses any source lacking explicit authorisation; it also refuses PhiShark without a local approval/DUA receipt and provider-issued URL. It only downloads artifact bytesâ€”it does not open URLs from feeds, extract archives, or execute archived HTML. Live `[acquire]` status messages are printed to the terminal (use `--quiet` to suppress them). Every invocation also appends a URL-free JSONL run log to `data/logs/source_acquisition.jsonl`, with statuses, receipts/hashes where available, and refusals. Use `--log path/to/log.jsonl` to choose another location.

The supplied plan registers only the already prepared `data/raw/phiusiil.csv` under the receipt system. The official UCI ZIP archive is intentionally not acquired unless a future plan explicitly requests it.

PhishingEval is handled as distinct Zenodo dataset artifacts, not as the GitHub source ZIP. The active plan downloads its core target-list, phishing, archived/benign HTML, and controlled-perturbation bundles (about 3.4 GB total) with published MD5 verification; the much larger `merge277` and `visible_dataset2` archives stay disabled until explicitly enabled in the plan.
