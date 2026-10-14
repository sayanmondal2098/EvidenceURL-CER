"""E03 temporal and group-disjoint evaluation gate.

No temporal score is emitted unless every evaluated feature has an authenticated
availability time no later than its decision time and every prohibited grouping
is disjoint across frozen partitions.
"""
from __future__ import annotations

import csv
import json
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path


def _write_json(path: Path, value: dict):
    path.parent.mkdir(parents=True,exist_ok=True)
    path.write_text(json.dumps(value,indent=2,sort_keys=True)+"\n",encoding="utf-8")


def validate_replay(decisions: list[dict], features: list[dict]) -> list[dict]:
    """Return every temporal-leakage/missing-time violation for a replay.

    Timestamps are expected to be ISO-8601 UTC strings.  Missing availability
    is a blocker, not an assumed pre-decision observation.
    """
    by_url=defaultdict(list)
    for f in features: by_url[f.get("url_id")].append(f)
    findings=[]
    for d in decisions:
        uid=d.get("url_id"); at=d.get("decision_at")
        if not at:
            findings.append({"kind":"missing_decision_time","url_id":uid,"severity":"error"}); continue
        for f in by_url.get(uid,[]):
            available=f.get("available_at")
            if not available:
                findings.append({"kind":"missing_feature_availability_time","url_id":uid,"feature_id":f.get("feature_id"),"severity":"error"})
            elif available>at:
                findings.append({"kind":"feature_after_decision","url_id":uid,"feature_id":f.get("feature_id"),"decision_at":at,"available_at":available,"severity":"error"})
    return findings


def validate_group_disjoint(rows: list[dict], grouping_fields=("etld_plus_one","campaign_id","infrastructure_id")) -> list[dict]:
    """Flag a grouping value occurring in more than one frozen partition."""
    findings=[]
    for field in grouping_fields:
        seen=defaultdict(set)
        for row in rows:
            value=row.get(field); split=row.get("split_name")
            if value and split: seen[value].add(split)
        findings.extend({"kind":"disallowed_group_overlap","grouping":field,"group_value":value,"splits":sorted(splits),"severity":"error"} for value,splits in seen.items() if len(splits)>1)
    return findings


def _controls() -> dict:
    future=validate_replay([{"url_id":"u","decision_at":"2024-02-01T00:00:00Z"}],[{"url_id":"u","feature_id":"f","available_at":"2024-02-02T00:00:00Z"}])
    overlap=validate_group_disjoint([{"etld_plus_one":"example.test","campaign_id":None,"infrastructure_id":None,"split_name":"train"},{"etld_plus_one":"example.test","campaign_id":None,"infrastructure_id":None,"split_name":"test"}])
    checks={"future_feature_flagged":bool(future),"group_overlap_flagged":bool(overlap)}
    if not all(checks.values()): raise AssertionError(checks)
    return {"executed":True,"checks":checks,"passed":True}


def prepare_e03(out_dir: str="results/E03", audit_path: str="results/E01/audit.json") -> dict:
    out=Path(out_dir); out.mkdir(parents=True,exist_ok=True)
    source=Path(audit_path); audit=json.loads(source.read_text(encoding="utf-8")) if source.is_file() else None
    n=int(audit.get("flow",{}).get("included_assertions",0)) if audit else 0
    first_seen=audit.get("timestamp_semantics",{}).get("first_seen_evaluation",{}) if audit else {}
    blockers=[]
    if not audit: blockers.append("E01_audit_not_found")
    if not first_seen.get("evaluable",False): blockers.append("all_historical_records_lack_authenticated_availability_time")
    if audit and audit.get("missingness",{}).get("missing_etld_plus_one",0)>0: blockers.append("eTLD_plus_one_unavailable_without_public_suffix_list")
    blockers.extend(["campaign_ids_not_supplied","no_frozen_temporal_train_calibration_test_split","no_authoritative_URLTrust_reproduction_for_matched_baseline"])
    status="NOT_RUN_TEMPORAL_ELIGIBILITY_BLOCKED"
    ledger=[{"cohort":"phiusiil_uci_967" if audit else "unknown","records":n,"eligibility":"excluded","reason":";".join(blockers),"first_seen_qualified_records":0,"test_cases":0}]
    with (out/"temporal_eligibility_ledger.csv").open("w",newline="",encoding="utf-8") as f:
        writer=csv.DictWriter(f,fieldnames=list(ledger[0])); writer.writeheader(); writer.writerows(ledger)
    # There are no valid test decisions to replay; an empty, schema-defined log
    # truthfully states that no claim of no-leakage was evaluated.
    (out/"feature_replay_audit.jsonl").write_text("",encoding="utf-8")
    (out/"metrics.csv").write_text("month,mode,metric,value,denominator,status\n",encoding="utf-8")
    (out/"cold_start_confusion_matrix.csv").write_text("split,true_label,prediction,count,status\n",encoding="utf-8")
    (out/"stratified_errors.csv").write_text("stratum,error_type,count,status\n",encoding="utf-8")
    (out/"random_split_diagnostic.csv").write_text("mode,status,reason\nrandom_split,NOT_RUN,diagnostic_only_and_no_valid_temporal_cohort\n",encoding="utf-8")
    controls=_controls()
    manifest={"experiment":"E03","run_at":datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00","Z"),"run_status":status,"source_audit":str(source),"historical_records_lacking_provable_availability_time":n,"first_seen_qualified_records":0,"test_cases":0,"blocked_leakage_count":0,"replay_audit_rows":0,"controls":controls,"grouping":{"eTLD_plus_one":"unavailable","campaign":"not_supplied","infrastructure":"not_supplied"},"required_before_run":["authenticated source/evidence availability times","frozen past-train/later-calibration/future-test split","Public Suffix List-derived eTLD+1","campaign/infrastructure group IDs","pinned authoritative URLTrust implementation and matched baselines"],"blockers":blockers}
    _write_json(out/"run_manifest.json",manifest)
    _write_json(out/"config.json",{"experiment":"E03","status":status,"random_split":"diagnostic_only_never_primary","temporal_rule":"feature.available_at <= decision_at for every replayed feature","group_rule":"no eTLD+1/campaign/infrastructure value may span frozen partitions","gap_days":[0,7,14,30]})
    (out/"analysis.md").write_text("# E03 status\n\nNo first-seen evaluation was run. PhiUSIIL supplies static URL labels but no authenticated label/evidence availability timestamps, HTML captures, graph evidence, campaign IDs, or infrastructure IDs. Therefore all records are excluded from temporal denominators and all requested metrics remain unreported.\n",encoding="utf-8")
    return {"out":str(out),"run_status":status,"historical_records_blocked":n,"controls":controls}
