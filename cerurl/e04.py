"""E04 assurance/risk separation audit.

P(u), Q(o), and K(u) are represented in different fields and are deliberately
never combined into a percentage or used as each other's proxy.
"""
from __future__ import annotations

import csv
import json
from datetime import datetime, timezone
from pathlib import Path


def _json(path: Path, value):
    path.parent.mkdir(parents=True,exist_ok=True)
    path.write_text(json.dumps(value,indent=2,sort_keys=True)+"\n",encoding="utf-8")


def controlled_cases() -> list[dict]:
    """Harmless synthetic invariant cases, not website observations or metrics."""
    return [
        {"case_id":"verified_malicious","world_type":"controlled_synthetic","P_maliciousness":0.95,"Q_assurance":{"hash":"verified","signature":"verified","trusted_time":"simulated_verified","vantage":"one"},"K_certificate_budget":None,"content_fingerprint":"a","expected":"malicious_estimate_allowed_with_strong_Q"},
        {"case_id":"verified_benign","world_type":"controlled_synthetic","P_maliciousness":0.05,"Q_assurance":{"hash":"verified","signature":"verified","trusted_time":"simulated_verified","vantage":"one"},"K_certificate_budget":None,"content_fingerprint":"b","expected":"signature_does_not_mean_benign"},
        {"case_id":"unsigned_informative","world_type":"controlled_synthetic","P_maliciousness":0.88,"Q_assurance":{"hash":"observed_unverified","signature":"absent","trusted_time":"unknown","vantage":"one"},"K_certificate_budget":None,"content_fingerprint":"c","expected":"unsigned_informative_not_benign"},
        {"case_id":"same_content_different_provenance","world_type":"controlled_synthetic","P_maliciousness":0.88,"Q_assurance":{"hash":"verified","signature":"invalid","trusted_time":"unknown","vantage":"one"},"K_certificate_budget":None,"content_fingerprint":"c","expected":"Q_changes_without_changing_P"},
        {"case_id":"tampered_artifact","world_type":"controlled_synthetic","P_maliciousness":0.90,"Q_assurance":{"hash":"mismatch","signature":"invalid","trusted_time":"unknown","vantage":"one"},"K_certificate_budget":None,"content_fingerprint":"d","expected":"integrity_failure_does_not_imply_benign"},
    ]


def validate_separation(cases: list[dict]) -> dict:
    by_id={c["case_id"]:c for c in cases}
    unsigned=by_id["unsigned_informative"]
    changed=by_id["same_content_different_provenance"]
    checks={
        "verified_evidence_can_support_malicious_estimate":by_id["verified_malicious"]["P_maliciousness"]>=.5 and by_id["verified_malicious"]["Q_assurance"]["signature"]=="verified",
        "verified_signature_not_interpreted_as_benign":by_id["verified_benign"]["P_maliciousness"]<.5 and by_id["verified_benign"]["Q_assurance"]["signature"]=="verified",
        "unsigned_informative_not_benign":unsigned["P_maliciousness"]>=.5 and unsigned["Q_assurance"]["signature"]=="absent",
        "provenance_perturbation_preserves_P":unsigned["content_fingerprint"]==changed["content_fingerprint"] and unsigned["P_maliciousness"]==changed["P_maliciousness"] and unsigned["Q_assurance"]!=changed["Q_assurance"],
        "no_assurance_scalar":all(not isinstance(c["Q_assurance"],(float,int)) and "K_certificate_budget" in c for c in cases),
    }
    if not all(checks.values()): raise AssertionError(checks)
    return {"executed":True,"checks":checks,"passed":True}


def prepare_e04(out_dir: str="results/E04", audit_path: str="results/E01/audit.json") -> dict:
    out=Path(out_dir); out.mkdir(parents=True,exist_ok=True)
    audit_file=Path(audit_path); audit=json.loads(audit_file.read_text(encoding="utf-8")) if audit_file.is_file() else {}
    n=int(audit.get("flow",{}).get("included_assertions",0)); cases=controlled_cases(); controls=validate_separation(cases)
    with (out/"controlled_assurance_cases.jsonl").open("w",encoding="utf-8") as f:
        for case in cases: f.write(json.dumps(case,sort_keys=True)+"\n")
    schema={"P(u)":{"meaning":"estimated maliciousness probability/risk; never inferred from signature or hash status","range":"[0,1] when a calibrated maliciousness model exists","available_for_phiusiil":"label only; no E04 model score was run"},"Q(o)":{"meaning":"structured evidence assurance attributes (integrity, signature, trusted time, provenance/vantage), not website trustworthiness","representation":"named categorical components; no uncalibrated scalar"},"K(u)":{"meaning":"source/graph certificate budget under an explicit certified threat model","available_for_phiusiil":"not available; no evidence/graph provenance"},"prohibited_inference":"signature_verified => benign or low P(u)"}
    _json(out/"assurance_schema.json",schema)
    with (out/"conditional_pq_distribution.csv").open("w",newline="",encoding="utf-8") as f:
        w=csv.DictWriter(f,fieldnames=["world_type","P_band","Q_signature","count","interpretation"]); w.writeheader()
        for c in cases: w.writerow({"world_type":"controlled_synthetic","P_band":"high" if c["P_maliciousness"]>=.5 else "low","Q_signature":c["Q_assurance"]["signature"],"count":1,"interpretation":c["expected"]})
    with (out/"pq_crosstab.csv").open("w",newline="",encoding="utf-8") as f:
        w=csv.DictWriter(f,fieldnames=["P_band","Q_level","count","world_type"]); w.writeheader()
        for c in cases:
            level="high" if c["Q_assurance"]["signature"]=="verified" and c["Q_assurance"]["hash"]=="verified" else "low_or_unknown"
            w.writerow({"P_band":"malicious_estimate" if c["P_maliciousness"]>=.5 else "benign_estimate","Q_level":level,"count":1,"world_type":"controlled_synthetic"})
    with (out/"attestation_availability.csv").open("w",newline="",encoding="utf-8") as f:
        w=csv.DictWriter(f,fieldnames=["cohort","records","signature_verified","hash_verified","trusted_time","attestation_status","interpretation"]); w.writeheader(); w.writerow({"cohort":"phiusiil_uci_967","records":n,"signature_verified":0,"hash_verified":0,"trusted_time":0,"attestation_status":0,"interpretation":"URL/label-only data; absence of assurance is not benign evidence"})
    with (out/"failure_cases.csv").open("w",newline="",encoding="utf-8") as f:
        w=csv.DictWriter(f,fieldnames=["case_id","failure_or_invariant","world_type"]); w.writeheader()
        for c in cases[1:]: w.writerow({"case_id":c["case_id"],"failure_or_invariant":c["expected"],"world_type":"controlled_synthetic"})
    (out/"calibration_and_decision_risk.csv").write_text("cohort,calibration,decision_risk,status\nphiusiil_uci_967,NOT_EVALUATED,NOT_EVALUATED,no_P_model_or_assurance_ground_truth\n",encoding="utf-8")
    manifest={"experiment":"E04","run_at":datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00","Z"),"run_status":"PARTIAL_CONTROLLED_INVARIANT_ONLY","real_attested_observations":0,"phiusiil_records_without_attestation":n,"controls":controls,"prohibited_inference":"signature validity is assurance of artifact provenance/integrity only, never website benignness","limitations":["No genuine cryptographically signed collector dataset is locally available.","Controlled cases validate representation/invariants only and are not empirical maliciousness or calibration results.","K is not available for the PhiUSIIL URL/label-only cohort."]}
    _json(out/"run_manifest.json",manifest)
    (out/"analysis.md").write_text("# E04 status\n\nP(u), Q(o), and K(u) are distinct fields. Controlled invariants show that verified evidence can accompany a high maliciousness estimate and that unsigned evidence remains informative rather than benign. No real attestation or calibration claim is made.\n",encoding="utf-8")
    return {"out":str(out),"run_status":manifest["run_status"],"controls":controls,"unattested_records":n}
