"""E02 frozen-reproduction preflight.

This module intentionally creates a NOT_RUN package when the original URLTrust
source and a compatible audited graph/HTML cohort are not supplied.  It never
uses the project's simplified graph operator as a substitute for URLTrust.
"""
from __future__ import annotations

import csv
import hashlib
import importlib.metadata
import json
from datetime import datetime, timezone
from pathlib import Path


def _sha256(path: Path) -> str:
    digest=hashlib.sha256()
    with path.open("rb") as f:
        for block in iter(lambda:f.read(1024*1024),b""): digest.update(block)
    return digest.hexdigest()


def _write_json(path: Path, value: dict):
    path.parent.mkdir(parents=True,exist_ok=True)
    path.write_text(json.dumps(value,indent=2,sort_keys=True)+"\n",encoding="utf-8")


def _environment() -> str:
    packages=("numpy","pandas","scikit-learn","scipy","matplotlib","joblib","xgboost")
    lines=[]
    for package in packages:
        try: lines.append(f"{package}=={importlib.metadata.version(package)}")
        except importlib.metadata.PackageNotFoundError: lines.append(f"{package}==NOT_INSTALLED")
    return "\n".join(lines)+"\n"


def prepare_e02(out_dir: str="results/E02", audit_path: str="results/E01/audit.json", authoritative_dir: str | None=None) -> dict:
    """Write an honest E02 package and per-mode blocker records.

    An authoritative directory is accepted only as an explicit future handoff;
    this preflight does not attempt to identify or alter its implementation.
    """
    out=Path(out_dir); out.mkdir(parents=True,exist_ok=True)
    audit_file=Path(audit_path)
    audit=json.loads(audit_file.read_text(encoding="utf-8")) if audit_file.is_file() else None
    candidate=Path(authoritative_dir) if authoritative_dir else None
    original_present=bool(candidate and candidate.is_dir() and any(candidate.iterdir()))
    html_available=bool(audit and audit.get("missingness",{}).get("html_unavailable",0)==0 and audit.get("flow",{}).get("included_assertions",0)>0)
    graph_edges=int(audit.get("flow",{}).get("graph_edges",0)) if audit else 0
    reasons=[]
    if not original_present: reasons.append("authoritative_URLTrust_source_not_supplied_or_pinned")
    if not audit: reasons.append("E01_audit_not_found")
    elif audit.get("flow",{}).get("included_assertions",0)==0: reasons.append("no_audited_URLTrust_assertions")
    if not html_available: reasons.append("no_permitted_HTML_content_cohort")
    if graph_edges==0: reasons.append("no_audited_URLTrust_graph_edges")
    if audit and audit.get("timestamp_semantics",{}).get("first_seen_evaluation",{}).get("evaluable") is False: reasons.append("no_reliable_historical_availability_time")
    # A common, frozen partition is a prerequisite for every comparison.
    reasons.append("no_frozen_E02_train_calibration_test_split_manifest")
    status="BASELINE_NOT_REPRODUCIBLE"
    modes={
        "url_lexical_logistic": {"family":"feature-only logistic regression","features":"canonical URL character TF-IDF only","hyperparameters":{"ngram_range":[2,4],"min_df":2,"max_features":70000,"sublinear_tf":True,"solver":"liblinear","class_weight":"balanced","max_iter":700},"status":"NOT_RUN_COMMON_E02_PARTITION_MISSING"},
        "html_content_logistic": {"family":"feature-only logistic regression","features":"HTML text only where locally captured and permitted","hyperparameters":None,"status":"NOT_RUN_NO_PERMITTED_HTML"},
        "xgboost": {"family":"feature-only XGBoost","features":"to be frozen after the common feature schema is available","hyperparameters":None,"status":"NOT_RUN_HYPERPARAMETERS_NOT_SUPPLIED"},
        "urltrust_graph_free_ablation": {"family":"frozen original URLTrust with graph component disabled","features":"authoritative implementation-defined","hyperparameters":None,"status":"NOT_RUN_AUTHORITATIVE_URLTRUST_MISSING"},
        "urltrust_full_frozen": {"family":"frozen original URLTrust","features":"authoritative implementation-defined; no label propagation across plain hyperlinks without documented semantics","hyperparameters":None,"status":"NOT_RUN_AUTHORITATIVE_URLTRUST_MISSING"},
    }
    for name,mode in modes.items():
        _write_json(out/"model_modes"/name/"mode.json",{**mode,"run_status":status,"blockers":reasons,"leakage_guard":{"fit_preprocessors_on":"training_only","calibrate_on":"calibration_only","test_threshold":"locked_before_test","heldout_graph_edges":"must be excluded unless original URLTrust semantics explicitly permits them","dangling_node_policy":"must be read from authoritative implementation; no substitute policy"}})
    source_hashes=[]
    for p in (audit_file,Path("data/raw/phiusiil.csv"),Path("tables/urls.csv"),Path("tables/observations.jsonl"),Path("tables/url_graph_edges.csv")):
        if p.is_file(): source_hashes.append({"path":str(p),"sha256":_sha256(p),"bytes":p.stat().st_size})
    _write_json(out/"hyperparameters.json",{"status":status,"policy":"A null field means the original setting was not supplied; it must not be invented.","modes":modes})
    _write_json(out/"config.json",{"experiment":"E02","run_status":status,"partition_policy":"one frozen train/calibration/test manifest shared by every mode","calibration_policy":"calibrate only on calibration; lock threshold before test","graph_policy":"plain hyperlinks are not label-propagation edges without authoritative URLTrust semantics","mode_names":list(modes)})
    _write_json(out/"run_manifest.json",{"experiment":"E02","run_at":datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00","Z"),"run_status":status,"source_hashes":source_hashes,"authoritative_urltrust":{"requested_path":str(candidate) if candidate else None,"present":original_present,"sha256":None,"policy":"No URLTrust-like local implementation may be substituted for the authoritative source."},"adapters":{"url_lexical":{"available":bool(audit)},"html_content":{"available":html_available},"hyperlink_graph":{"edge_count":graph_edges,"available":graph_edges>0}},"same_partition_required":True,"blockers":reasons})
    (out/"environment.txt").write_text(_environment(),encoding="utf-8")
    (out/"metrics.csv").write_text("mode,split,metric,value,status\n",encoding="utf-8")
    (out/"raw_runs.jsonl").write_text(json.dumps({"experiment":"E02","run_status":status,"blockers":reasons},sort_keys=True)+"\n",encoding="utf-8")
    (out/"baseline_scripts"/"README.md").parent.mkdir(parents=True,exist_ok=True)
    (out/"baseline_scripts"/"README.md").write_text("# E02 model modes\n\nThese mode records are intentionally NOT_RUN. Training requires a pinned authoritative URLTrust checkout, a frozen common split, and audited HTML/graph inputs. Do not replace missing URLTrust with this repository's simplified CER graph operator.\n",encoding="utf-8")
    (out/"baseline_scripts"/"run_mode.py").write_text('''"""Guarded E02 mode launcher; it refuses an unfrozen comparison."""\nimport json, sys\nfrom pathlib import Path\nmode=Path(sys.argv[1]).resolve() if len(sys.argv)==2 else None\nif not mode or not mode.is_file(): raise SystemExit("usage: run_mode.py path/to/mode.json")\nrecord=json.loads(mode.read_text(encoding="utf-8"))\nif record.get("status", "").startswith("NOT_RUN") or record.get("run_status") != "RUN_READY":\n    raise SystemExit("REFUSED: "+record.get("status", "mode is not frozen/runnable"))\nraise SystemExit("A RUN_READY adapter has not been supplied by this package.")\n''',encoding="utf-8")
    (out/"baseline_scripts"/"validate_manifest.py").write_text('''"""Minimal E02 manifest validator; does not train models."""\nimport json, sys\nfrom pathlib import Path\np=Path(sys.argv[1] if len(sys.argv)==2 else "../run_manifest.json")\nr=json.loads(p.read_text(encoding="utf-8"))\nrequired={"experiment","run_status","source_hashes","adapters","same_partition_required"}\nmissing=required-set(r)\nif missing: raise SystemExit("invalid manifest; missing "+repr(sorted(missing)))\nprint(r["run_status"])\n''',encoding="utf-8")
    (out/"analysis.md").write_text("# E02 status\n\n`BASELINE_NOT_REPRODUCIBLE`: the authoritative URLTrust implementation is absent, and the audited PhiUSIIL cohort has neither permitted HTML nor graph edges. No model metrics, confusion matrices, thresholds, confidence intervals, or reproduction claims were generated.\n",encoding="utf-8")
    (out/"stderr.log").write_text("No model execution attempted: BASELINE_NOT_REPRODUCIBLE.\n",encoding="utf-8")
    return {"out":str(out),"run_status":status,"blockers":reasons,"model_modes":list(modes)}
