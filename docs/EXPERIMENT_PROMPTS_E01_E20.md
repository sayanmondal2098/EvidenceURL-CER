# Twenty Execution-Ready Research Prompts for EvidenceURL-CER

These prompts are intended for sequential use with a coding/research agent. **Copy the master prompt first**, then one experiment prompt below. If executing independently, supply `protocols/`, `schemas/` and the corresponding real, permitted datasets. A prompt is not evidence that its associated experiment has run. In each experiment, use immutable manifests, real data only when present, deterministic seeds, exact denominators, honest `NOT_RUN` status and a frozen non-leaking train/calibration/test split. All URLs used in attack-generation should be offline or on authorised `.test` infrastructure.

---

## E01. Audit CER-URLBench provenance, data quality and leakage

**Agent prompt:** You are a cybersecurity data-curation scientist. Ingest the locally supplied URLTrust `index` dataset (`result=0` benign, `1` phishing; HTML in `database/`), plus only actually acquired/authorised PhishTank and other snapshots. Parse source assertions into `urls.csv`, raw observations into `observations.jsonl`, and independent source groups into provenance tables. Record hashes, timestamp semantics, capture failures, missingness, authority and external access terms. Identify duplicate canonical URLs, conflicting time-varying labels, duplicate/similar HTML hashes, same-domain/campaign contamination, feed mirroring and graph edges originating after test decision times. Never infer `capture_at` from SQL `created_date`, or label unavailable HTML as benign. Implement a precise audit report detailing flow from raw rows to decided cases. Compute summary counts by label, source, month, eTLD+1, campaign, capture availability, and independent source ancestry, separately by cohort.

**Controls/outputs:** Run an assertion test where a URL appears in both train/test groups, where a timestamp follows decision time, and where two feeds mirror one source; these must be flagged. Deliver `results/E01/audit.json`, `tables/dataset_characteristics.tex`, inclusion/exclusion ledger, duplicate conflicts, and a manually inspectable `sample_ledger.csv` with sanitized IDs. **Pass:** zero silent label flips and zero unflagged leakage. Lack of reliable time metadata must explicitly prevent first-seen evaluation.

## E02. Frozen URLTrust reproduction against feature-only baselines

**Agent prompt:** You are reproducing the original URLTrust model and testing its inferential contribution. Load the authoritative URLTrust implementation without modifying algorithms or parameters, and build adapters to the audited local URLs, HTML and graph edges. Construct URL lexical, HTML-content and hyperlink features *only* where observed and permitted. Compare feature-only logistic regression, XGBoost, graph-free URLTrust ablation, and frozen full URLTrust using identical partitions and labels. Document exact edge semantics and dangling-node policy; never propagate a phishing label across a plain hyperlink without explicit model semantics. Fit all preprocessors only on training data. Calibrate thresholds using calibration partition, then lock before test evaluation.

**Outputs:** clean confusion matrices, AUPRC, AUROC, recall at fixed FPR, F1, MCC, Brier, ECE, graph size/edge counts, cold-start coverage, runtime and mean/cluster confidence intervals. Compare original reported results to reproduced results only when the data/conditions really match. Deliver source hash, environment file, full hyperparameter manifest and baseline scripts in `results/E02/`. **Pass:** reproducible end-to-end metrics with no held-out graph leakage; if original code is unavailable, report `BASELINE_NOT_REPRODUCIBLE`, not simulated values.

## E03. Causal temporal and domain/campaign-disjoint generalisation

**Agent prompt:** You are building a first-seen phishing evaluation that cannot use future information. Freeze test months prospectively or use historical archived snapshots only when evidence-availability timestamps are authenticated. Partition by past training window, later calibration, future untouched test; optionally add 7/14/30-day gaps. Group by eTLD+1 and known campaigns, and run an independent infrastructure-disjoint stress test. For every test verdict at t, replay only graph nodes/edges/evidence available by t. Train URLTrust and baseline models with the same eligible data; measure performance of first-seen URL and first-seen campaign separately. Explicitly report how many historical records lack provable availability time and cannot qualify for zero-day inference.

**Outputs:** monthly AUPRC/AUROC/TPR@FPR, cold-start confusion matrix with abstentions, distribution shifts, coverage, first-seen sample counts, stratified errors and blocked-leakage count. Compare random split **only as a diagnostic**, not the main result. **Pass:** queryable audit log proving no test features arrived after the decision timestamp and no disallowed group overlap.

## E04. Separate trustworthy evidence from website trustworthiness

**Agent prompt:** You are assessing whether cryptographic/collection assurance and maliciousness are independently measurable. Define URL maliciousness estimate P(u) separately from evidence assurance Q(o) and certificate budget K(u); prohibit their collapse into a single uncalibrated percentage. On controlled observations and any genuine cryptographically signed datasets, perturb content while preserving authentic collector records, and perturb provenance while preserving identical observed content. Compare binary signatures, verified collection hashes, freshness metrics and cross-vantage consistency. Test whether strong evidence verification can correctly support a malicious verdict and whether an unsigned but informative observation is treated as lower-assurance rather than automatically benign.

**Outputs:** conditional P/Q distributions, cross-tab of benign/malicious vs low/high Q, failure cases, attestation-availability counts, calibration and decision risk. **Pass:** no equation interprets signature validity as website benignness, and all unverifiable claims remain distinguishable from verified evidence.

## E05. Shared-upstream source graph versus naïve independent feeds

**Agent prompt:** Build a provenance DAG/hypergraph for observed and controlled reports, with `derived_from`, `mirrors_feed`, `collected_by`, `aggregated_from`, and same-operator edges. Identify attack units at independently controlled ancestor groups and compute descendant closure. Create controlled topologies: five different feed labels all deriving from one source, five truly independent feeds, partial overlap, cycles erroneously introduced by bad data, and unknown ancestors. Compare assumption of N reports = N independent witnesses against source-aware independence. Audit group assignments and show exactly which descendant observations are corrupted when each ancestor is compromised.

**Outputs:** source graph plots, independent group counts, ancestor-reachability tests, graph connectivity, per-URL robustness score inflation under naïve assumptions. **Pass:** source counts do not increase when reports are copied, cycles are rejected/flagged, and unknown dependencies are not silently treated as independent.

## E06. Exact fixed-graph decision certificate and exhaustive soundness

**Agent prompt:** Implement and independently validate the exact restricted certificate from the companion manuscript. State fixed normalized nonnegative row-stochastic propagation, fixed intrinsic fusion weights, evidence influence bounded in [0,1], and explicit ancestor-group compromise with all-descendant control. For small graphs/provenance DAGs (2–15 source groups), enumerate every attack subset within budget b and calculate maximal directional decision-score decrease/increase. Compare exact enumeration against analytic/group-coverage result and conservative bounds. Include ties, abstention thresholds, overlap, zero-weight groups, shared ancestors, damping α=0 and near 1, dangling vertices. No result may count as certified if actual perturbation flips it under the permitted budget.

**Outputs:** exact tables for per-URL certified minimal attack cost (or lower bound where exact infeasible), attack witnesses, unit/property tests, empirical soundness-violation count with assumptions attached, runtime. **Pass:** zero violations across exhaustive supported instances; if violated, halt all downstream certification plots pending correction.

## E07. Scaling exact certificates via integer and linear programming

**Agent prompt:** Formulate the maximum-damage descendant-coverage problem as a binary integer program, with shared-ancestor consistency, source cost budgets, and a direction-aware URL decision margin. Implement an exact solver or compare a licensed solver when available; implement a relaxed LP/greedy conservative upper bound on adversarial damage. Never report an optimistic approximate attack as a valid robustness guarantee. Evaluate b=0..5 and 20/50/100/500 ancestor groups with varied overlap and sparse/dense dependency graphs. Compare enumeration/exact solution/relaxation at identical cases and quantify certificate tightness and false-unprotected rate.

**Outputs:** solver input/output archives, optimality gaps, memory, CPU time, fraction timed out, guaranteed vs empirical robustness, bound-tightness plots. **Pass:** all conservative certificates are sound on exact-checkable instances; timeouts yield unknown or safe non-certification, never a guessed proof.

## E08. Joint source and graph attacks with certificate guarantees

**Agent prompt:** Add typed graph perturbations: insertion/removal/reweighting of hyperlink edges, constrained redirect changes and semantics-preserving graph modifications. Define a second graph budget and respect web relation types. Verify the manuscript's joint perturbation bound under its assumptions by numeric property tests and constrained adversarial search; document the matrix norm, normalization and α regime. Compare pure source corruption, pure graph corruption, and joint attacks. Recompute graph snapshot under each perturbation, never apply a fixed-graph certificate to a changing graph without an additional valid bound.

**Outputs:** 2D heatmap of certified coverage over (source budget, edge budget), soundness counters, attack flips, certified vs empirical bounds and attack runtime. **Pass:** every asserted joint certificate has a separately documented proof/validation domain; unknown regimes abstain.

## E09. Source-compromise and malicious-feed injection resilience

**Agent prompt:** Using controlled ground-truth source ancestry and optional prospective independent collections, compromise b=0..5 upstream groups (and a separately defined 0%–40% population fraction). Attack labels/reports, observation values, source weights and multiple descendant artifacts, maintaining realistic source-control limitations. Compare feature classifier, original URLTrust, source-unaware robust fusion, provenance-aware fusion, certificate-only, and full CER. Run both untargeted and targeted attack settings, including compromised benign-source groups that hide phishing and poisoned malicious reports that cause benign-site false positives. Ensure attacker is not granted knowledge unavailable in the declared white/grey/black-box setting.

**Outputs:** attack success rates at equal budgets, score shifts, conditional false negatives/positives, certified coverage, abstention, and time/cost. **Pass:** real attack successes match the threat definition; high clean-set accuracy alone is not treated as resilience.

## E10. Evidence replay, staleness, and storage tampering

**Agent prompt:** Construct time-versioned evidence manifests. Replay an old benign screenshot/HTML snapshot after a controlled website changes to a phishing state, tamper with saved artifact bytes, alter metadata timestamps, replace redirect chains, and submit feed entries whose availability dates are later than the prediction time. Separate tests for unsigned evidence, correctly signed but stale evidence, and signed evidence whose bytes were subsequently changed. Do not treat a valid signature as proof of truthful remote content.

**Outputs:** detection rate and false reject/accept rate, stale-acceptance rate, repair decisions triggered, p50/p95 verification latency, time to certificate invalidation. **Pass:** all post-signature byte changes detected in the explicit hash/signature model; signature-valid stale observations may still be rejected by policy, and no invented capture timestamp repairs them.

## E11. Multi-vantage cloaking with controlled website behaviour

**Agent prompt:** Build isolated `.test` websites serving distinct harmless and phishing-*simulated* content to selected browser user agents, network vantages and observation times; no real victim credentials or external attack targets. Schedule adversarial cloaking rules so two correlated collectors see benign templates while independent mobile/network collectors see a simulated credential-harvesting marker. Record true site state, collection condition, hashes, redirects, and source ancestors. Compare one-vantage, fixed three-vantage, random new vantage, diversity heuristic and CER challenge policy. Account for website outages as missing evidence, not benign proof.

**Outputs:** cloaking exposure rate, true contradiction discoveries, repair successes, decision changes, time-to-evidence, false positives and cost. **Pass:** all apparent gains are measured against actual controlled ground truth and source availability, not model-generated labels.

## E12. Counterfactual challenge quality and minimal decision-flip evidence

**Agent prompt:** For each incorrectly decided/fragile URL, derive counterfactual challenges identifying which source group, evidence type, or graph relation would need to change to reverse the verdict. For small controlled cases solve exact minimal-change counterfactuals; for larger cases use a constrained heuristic with an admissibility check. Compare counterfactual sets against random, gradient attribution, feature importance and disagreement. Measure overlap with real injected attack ground truth and number of attempts needed to expose the compromise. Disallow direct access to the held-out attack seed and true unobserved action outcome during challenge selection.

**Outputs:** challenge validity, precision/recall of vulnerable groups, minimality gap, top-k attack localization, runtime, false counterfactual claims. **Pass:** identified counterfactuals are feasible under the model; only exact or provably bounded cases receive corresponding guarantees. ==== RETRY

## E13. Repair action selection against matched-budget baselines

**Agent prompt:** Implement repair policies: NO-REPAIR, RANDOM, UNCERTAINTY, DISAGREEMENT, INDEPENDENT-DIVERSITY, EXPECTED-RISK GREEDY, and certificate-guided EvidenceURL-CER. Each method receives the *same* action menu, acquisition prices, possible outcomes distribution, and maximum attempts; no policy sees future outcomes or labels. For candidate actions like independent network vantage, second DNS measurement, archived HTML comparison, redirect inspection, source provenance verification or signed feed lookup, learn or specify estimated observation outcomes only from training/calibration. Run budgets B={0,1,2,3,5,10} and repeat seeds.

**Outputs:** cumulative expected/actual adversarial loss, certified coverage gains, action count, latency, money cost, per-policy chosen-action distributions, unresolved counts. **Pass:** improvements survive paired matched-budget comparison and remain when the extra evidence contradicts initial verdicts.

## E14. Corrected vs degraded decisions and safe abstention

**Agent prompt:** Evaluate the *consequences* of active repair rather than merely measuring how frequently a score changes. Partition test URLs into initially correct/wrong/abstained states using independently adjudicated labels not visible to policy. After each action count transitions: wrong->correct, correct->wrong, wrong->abstain, correct->abstain, abstain->correct, abstain->wrong, unchanged. Calibrate security release policy on calibration data and freeze it. Compare no-repair, static extra scanning and CER. Plot selective risk vs coverage, calibration curves before/after, and mean operational utility for multiple false-negative/false-positive/abstention costs.

**Outputs:** all-transition confusion table, repair corrections/degradations, abstain fraction, corrected cost, paired CIs and condition-specific error analysis. **Pass:** all denominator and coverage choices explicit; never label a merely more confident same verdict as a corrected error.

## E15. Certificate strengthening and dynamic invalidation following repair

**Agent prompt:** After each new evidence observation, rebuild ancestor dependencies, recompute the URLTrust score and directional certificate, and compare pre/post certified source-group budgets. Implement policy to invalidate certificates on freshness expiration, upstream independence loss, newly discovered mirrors and changes to the relevant graph snapshot. Include controlled cases where a new supporting report shares the old compromised ancestor, where a truly independent contradictory report correctly weakens confidence, and where an independent supporting observation strengthens the bound. Test incremental recalculation against full recomputation.

**Outputs:** per-action certificate transition matrix, median certified-budget gain, valid vs invalid updates, stale-certificate retention rate (target zero in covered cases), incremental speedup and certificate agreement with full rebuild. **Pass:** no certificate is preserved when its proof inputs change outside the allowed incremental update rules.

## E16. Prospective first-seen phishing and source-separated external validation

**Agent prompt:** Collect or consume legally permitted phishing-feed snapshots prospectively with exact receipt time and never reveal future verified labels or test domain/campaign information before scoring. Evaluate URLs/campaigns with no training-period identity match, separate first-seen-by-feed from genuinely novel campaign, and include independent screened benign pages. Hold out an external source/domain/period. Compare frozen URLTrust, feature-only modern baseline, provenance-aware fusion, certificate-only, and full CER at equal evidence cost. Clearly distinguish no signal because the site is inaccessible from model false negatives. PhishLumos and URL2Path are related work, not automatically reproducible baselines without code/data.

**Outputs:** first-seen AUPRC, TPR at specified FPR, selective risk vs coverage, time-to-verdict, latency, action cost, campaign-group CIs and error taxonomy. **Pass:** first-seen qualification is based on data accessible at prediction time, not merely current feed absence.

## E17. Longitudinal drift, source expiry and certificate stability

**Agent prompt:** Replay monthly/weekly prospective evidence revisions or controlled site-state transitions, including domain migration, DNS changes, certificate rotation, page cleanup, redirect mutation, source reputation changes and silent source withdrawal. Distinguish actual malicious->benign remediation from model error using independently verified temporal labels. Freeze incremental update schedule and freshness TTL by modality based on training/calibration. Compare static trust, periodic full refresh, freshness-only and CER repair triggers. Test graph snapshot invalidation and certificate regeneration under changed topology.

**Outputs:** time-dependent AUPRC, accuracy/coverage by evidence age, alert/recheck delay, unnecessary repair rate, certificate expiry correctness, time-to-correction and longitudinal cost. **Pass:** no claim about drift from a single dated snapshot; when genuine longitudinal data absent, restrict claims to controlled simulations.

## E18. Critical ablation, sensitivity, and assumption violations

**Agent prompt:** Run systematic ablation: remove source ancestry, remove directional certificates, replace counterfactual policy with random, remove URLTrust graph, remove freshness, remove abstention, remove action-cost term, remove calibration, and disable source-group caps. Keep training/evaluation fixed and budgets matched. Sweep α in graph propagation, evidence fusion weights, attack budget, provenance uncertainty, action cost multiplier, and percentage of correlated reports. Separately run assumption-stress cases violating fixed weights, independent source claims, or graph normalization; **invalidate** theoretical certificates where assumptions fail, even if empirical accuracy remains high.

**Outputs:** complete ablation table and factorial interactions, confidence intervals, sensitivity surfaces and proof-assumption audit. **Pass:** explicitly assess whether URLTrust's graph contributes incremental value after robust provenance fusion, rather than automatically claiming it does.

## E19. Scale, latency, incremental graph repair and storage cost

**Agent prompt:** Benchmark ingestion, provenance-ancestor closure, certificate exact/relaxed solving, full URLTrust propagation, incremental trust recomputation, action selection, storage writes and proof-checking. Scale to feasible sizes (10^3, 10^4, 10^5 and if possible 10^6 observed URLs) while reporting actual hardware, graph degree, ancestor-group distribution, workload source (real/controlled), and memory. Evaluate p50/p95/p99 latency per stage, runtime/memory vs b and action budget, cost per protected URL and network/collector overhead. Use profiler traces and algorithmic complexity approximations; if hardware is insufficient mark limits.

**Outputs:** scalability plots, exact vs approximate certificate costs and gaps, incremental recomputation speedups, bottleneck analysis and deployment requirements. **Pass:** demonstrate correctness equality of incremental/full computation on test cases and avoid extrapolating million-node measurements that were not run.

## E20. Reproducibility, preregistered analysis and final scientific report

**Agent prompt:** Freeze the dataset release, source licence manifest, train/calibration/test splits, model versions, acquisition policies, attack budgets and primary hypotheses. Create a one-command reproducibility runner (never re-download mutable live feeds by default) that reconstructs E01–E19 summaries from archived permitted data. Run five or more seeds for stochastic settings, cluster-bootstrap 95% intervals over independent campaigns/source groups, paired contrasts and Holm correction for preregistered primary comparisons. Provide executable scripts that regenerate every figure and table from raw result JSONL; maintain permanent issue logs for missing datasets and failed attacks. Populate the journal's Experimental Setup and Results sections from **executed** data only; append threats to validity, ethical restrictions and code/data availability statement.

**Outputs:** a final manifest linking every figure and number to run IDs and hashes, hypothesis table with observed effect sizes and uncertainty, limitations, reproducibility status, per-experiment PASS/FAIL/NOT_RUN, and publication-ready LaTeX tables/figures. **Pass:** an independent reviewer can reproduce results from released permitted artifacts, or receives precise instructions for restricted-data evaluation; no fabricated confidence intervals or result claims.

---

## Suggested execution order and stop gates

1. Foundation: E01->E02->E03; first publish an honest data availability report.
2. Formal core: E05->E06->E07->E08; **do not proceed with certified claims** until E06 proof/model tests pass.
3. Robustness: E04->E09->E10->E11->E12, using controlled attacks where provenance truth is known.
4. Repair: E13->E14->E15; require matched-budget positive result without unacceptable repair degradation.
5. External generalisation and delivery: E16->E17->E18->E19->E20.

## Minimum defensible submission result

Demonstrate sound certificate conditions, external validity on an unseen campaign cohort, a controlled provenance-corruption benchmark, statistically supported repair benefit at matched acquisition budgets, ablation showing the contribution of the graph, and transparent handling of abstentions and missing evidence. If some hypothesis fails, publish the negative result transparently; do not change the test protocol after seeing results.
