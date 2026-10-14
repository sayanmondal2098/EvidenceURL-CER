# CER-URLBench Normalised Data Dictionary v0.1

A production implementation can use Parquet for scale. This offline scaffold writes CSV/JSONL and a data-quality report. Missing information must stay null: null is not zero, benign, valid, or independent.

## A. `urls.csv` (one source assertion per URL per source record)

- `url_id` stable SHA-256 of canonical display URL; no plaintext re-identification in public releases.
- `url`, `host`; `registrable_domain` null until PSL-derived; `source_record_id` raw stable source row ID.
- `source_dataset`, `cohort`, `world_type` (`observed`, `controlled`, `synthetic_perturbation`).
- `label_class` (`benign`, `phishing`, `malware_distribution`, `unknown`), `label_status` (`source_asserted`, `verified_feed`, `analyst_reviewed`, `pending`, `conflicted`).
- `label_event_at` when label was submitted/verified/reviewed (source semantics specified separately).
- `label_available_at` when research system obtained that label (use actual snapshot acquisition time); do not backdate.
- `record_ingested_at` local import time; `source_created_date` original raw `created_date`, unrelated to HTML capture time.
- `html_relative_path`, `html_sha256` with missing HTML recorded as null; `capture_at` **null unless authentic HTML capture time is supplied**.
- `campaign_id` optional ground-truth grouping, not inferred from a test label at prediction time; `review_basis` provenance for benign.

`urls.csv` may contain duplicate URL IDs from independent labels. Conflicts must be flagged rather than dropped; retain original source assertions for label reconciliation.

## B. `observations.jsonl` (one measurement per artifact per vantage)

Required in future collector implementation: `observation_id`, `url_id`, `observed_at`, `ingested_at`, `vantage_group_id`, `collector_id`, `collector_build`, `modality` (`html`, `redirect`, `dns`, `tls`, `http`, `screenshot`, `feed_report`, `graph_edge`), `artifact_sha256`, `artifact_uri`, `quality_status`, `signature_verified` (nullable), `attestation_status` (nullable), `source_group_ids` (array), `parent_observation_ids` (array), `capture_error`, `world_type`, `source_snapshot_id`. Fields describing an unperformed attestation must remain null, not `verified`.

## C. `source_groups.csv` / `provenance_edges.csv`

`source_group_id,operator_id,independence_claim,independence_basis,first_valid_at,last_valid_at` and `parent_id,child_id,relation,valid_from,valid_until`. `relation` includes `derived_from`, `collected_by`, `mirrors_feed`, `hosted_by`, `aggregated_from`. These are *provenance* edges, not URLTrust hyperlinks.

## D. `url_graph_edges.csv`

`edge_id,source_url_id,target_url_id,relation_type,observed_at,available_at,observer_group_id,source_observation_id,evidence_sha256,semantic_weight,quality_status,world_type`. `relation_type` must distinguish hyperlink, redirect, shared_resource, same_ip, shared_certificate and related campaign. No cross-class propagation without explicit relation semantics.

## E. `attack_runs.jsonl`

`run_id,case_id,model_version,graph_snapshot_id,attack_type,attack_budget_units,attacker_controlled_groups,attacked_observation_ids,attacked_edge_ids,attack_origin,world_type,seed,decision_before,decision_after,certificate_before,certificate_after,flip_success,attack_runtime_ms`.

## F. `repair_actions.jsonl`

`repair_run_id,case_id,action_id,action_type,source_group_requested,selection_policy,predicted_gain,action_cost,selection_time_ms,observed_outcome,observed_at,decision_before,decision_after,certificate_before,certificate_after,label_reference,repair_status,world_type`.

## G. `splits.csv`

`url_id,split_name,split_version,grouping_id,first_eligible_at,grouping_rules,embargo_days`. **Never** create a temporal split from `record_ingested_at` of a single historical import. Quarantine records lacking reliable historical acquisition times.

## H. `metric_runs.jsonl`

`experiment_id,run_id,dataset_release,split_version,method,attack_budget,seed,n_test,n_decided,n_abstained,metric_name,metric_value,unit,confidence_interval,analysis_version`. Include cohort counts and per-budget certified coverage to prevent cherry-picking.

## Leakage invariants

1. If feature `available_at` > decision timestamp, exclude it and log violation.
2. If raw evidence `observed_at` > decision timestamp, exclude it and log violation.
3. Never join future label verification times into contemporaneous features.
4. Never pretend labels/HTML extracted from the *same* source are independent evidence witnesses.
5. Separate graph-provenance ancestry from URL hyperlink graph; otherwise certificates overcount attack sources.
6. Keep candidate benign status distinct from confirmed benign.
7. Record every perturbation action and seed; do not overwrite clean artifacts in place.
