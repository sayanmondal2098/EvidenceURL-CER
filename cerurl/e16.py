"""E16: prospective first-seen evaluation over locally supplied frozen outputs.

This module never fetches or visits URLs. Prediction outputs, snapshot receipt
events, and independently adjudicated labels are separate input ledgers.
"""
from __future__ import annotations

import csv
import hashlib
import json
import math
import random
import re
import time
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from sklearn.metrics import average_precision_score


SYSTEMS = (
    "urltrust_frozen",
    "feature_only",
    "provenance_fusion",
    "certificate_only",
    "full_cer",
)
PARTITIONS = ("train", "calibration", "test", "external")
METRIC_COHORTS = (
    "test_all",
    "external_all",
    "test_first_seen",
    "external_first_seen",
    "test_first_seen_strict_novel",
    "external_first_seen_strict_novel",
)
CSV_SCHEMAS = {
    "cohorts": (
        "case_id", "partition", "decision_at", "source_id", "domain_id",
        "campaign_id", "infrastructure_id",
    ),
    "predictions": (
        "case_id", "system", "probability_phishing", "access_status",
        "signal_count", "evidence_cost", "latency_ms",
    ),
    "labels": (
        "case_id", "label", "verified_at", "adjudication_source",
        "independent", "benign_screened",
    ),
    "feed_events": (
        "case_id", "feed_source", "snapshot_received_at",
        "snapshot_path", "snapshot_sha256",
    ),
}


def _parse_time(value: str, field: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError(f"{field} must be an ISO-8601 timestamp: {value!r}") from exc
    if parsed.tzinfo is None:
        raise ValueError(f"{field} must include a timezone: {value!r}")
    return parsed.astimezone(timezone.utc)


def _truth(value: str, field: str) -> bool:
    normalized = value.strip().lower()
    if normalized in ("1", "true", "yes"):
        return True
    if normalized in ("0", "false", "no"):
        return False
    raise ValueError(f"{field} must be one of 0/1, true/false, or yes/no")


def _read_rows(path: Path, schema: tuple[str, ...]) -> list[dict[str, str]]:
    if not path.is_file():
        raise FileNotFoundError(path)
    with path.open(newline="", encoding="utf-8-sig") as stream:
        reader = csv.DictReader(stream)
        missing = set(schema) - set(reader.fieldnames or ())
        if missing:
            raise ValueError(f"{path} is missing columns: {sorted(missing)}")
        return [
            {key: (row.get(key) or "").strip() for key in schema}
            for row in reader
        ]


def _required(value: str, field: str) -> str:
    if not value:
        raise ValueError(f"{field} must not be blank")
    if "://" in value:
        raise ValueError(f"{field} must be an opaque ID, not a URL")
    return value


def _finite_nonnegative(value: str, field: str) -> float:
    try:
        number = float(value)
    except ValueError as exc:
        raise ValueError(f"{field} must be numeric") from exc
    if not math.isfinite(number) or number < 0:
        raise ValueError(f"{field} must be finite and nonnegative")
    return number


def _load_cohorts(path: Path) -> dict[str, dict[str, Any]]:
    result: dict[str, dict[str, Any]] = {}
    for row in _read_rows(path, CSV_SCHEMAS["cohorts"]):
        case_id = _required(row["case_id"], "case_id")
        if case_id in result:
            raise ValueError(f"Duplicate cohort case_id: {case_id}")
        if row["partition"] not in PARTITIONS:
            raise ValueError(f"Invalid partition for {case_id}: {row['partition']!r}")
        _required(row["source_id"], "source_id")
        _required(row["domain_id"], "domain_id")
        result[case_id] = {
            **row,
            "decision": _parse_time(row["decision_at"], "decision_at"),
        }
    if not result:
        raise ValueError("cohorts ledger is empty")
    return result


def _load_predictions(
    path: Path, cohorts: dict[str, dict[str, Any]],
) -> dict[tuple[str, str], dict[str, Any]]:
    result: dict[tuple[str, str], dict[str, Any]] = {}
    eval_ids = {case_id for case_id, row in cohorts.items() if row["partition"] != "train"}
    with path.open(newline="", encoding="utf-8-sig") as stream:
        headers = set(csv.DictReader(stream).fieldnames or ())
    leaked = headers & {"label", "ground_truth", "verified_at", "adjudication_source"}
    if leaked:
        raise ValueError(f"Prediction ledger contains outcome columns: {sorted(leaked)}")
    for row in _read_rows(path, CSV_SCHEMAS["predictions"]):
        case_id = _required(row["case_id"], "prediction case_id")
        system = row["system"]
        if case_id not in eval_ids:
            raise ValueError(f"Prediction row refers to non-evaluation case: {case_id}")
        if system not in SYSTEMS:
            raise ValueError(f"Unknown model system: {system!r}")
        key = (case_id, system)
        if key in result:
            raise ValueError(f"Duplicate prediction row: {case_id}/{system}")
        if row["access_status"] not in ("available", "inaccessible"):
            raise ValueError(f"Invalid access_status for {case_id}/{system}")
        signals = int(row["signal_count"])
        if signals < 0:
            raise ValueError(f"signal_count must be nonnegative for {case_id}/{system}")
        score_text = row["probability_phishing"]
        score = None if not score_text else float(score_text)
        if row["access_status"] == "inaccessible":
            if score is not None or signals != 0:
                raise ValueError(
                    f"Inaccessible prediction must have blank score and zero signals: {case_id}/{system}"
                )
        elif score is None or not math.isfinite(score) or not 0 <= score <= 1 or signals == 0:
            raise ValueError(
                f"Available prediction needs a score in [0,1] and at least one signal: {case_id}/{system}"
            )
        result[key] = {
            "case_id": case_id,
            "system": system,
            "score": score,
            "access_status": row["access_status"],
            "signal_count": signals,
            "evidence_cost": _finite_nonnegative(row["evidence_cost"], "evidence_cost"),
            "latency_ms": _finite_nonnegative(row["latency_ms"], "latency_ms"),
        }

    for case_id in eval_ids:
        rows = [result.get((case_id, system)) for system in SYSTEMS]
        if any(item is None for item in rows):
            missing = [system for system, item in zip(SYSTEMS, rows) if item is None]
            raise ValueError(f"Missing system predictions for {case_id}: {missing}")
        costs = [item["evidence_cost"] for item in rows if item is not None]
        if max(costs) - min(costs) > 1e-9:
            raise ValueError(f"Evidence costs are not matched for case {case_id}")
    return result


def _load_labels(path: Path, cohorts: dict[str, dict[str, Any]]) -> dict[str, dict[str, Any]]:
    eval_ids = {case_id for case_id, row in cohorts.items() if row["partition"] != "train"}
    result: dict[str, dict[str, Any]] = {}
    for row in _read_rows(path, CSV_SCHEMAS["labels"]):
        case_id = _required(row["case_id"], "label case_id")
        if case_id not in eval_ids:
            raise ValueError(f"Label row refers to non-evaluation case: {case_id}")
        if case_id in result:
            raise ValueError(f"Duplicate label row: {case_id}")
        label = int(row["label"])
        if label not in (0, 1):
            raise ValueError(f"label must be 0=benign or 1=phishing for {case_id}")
        verified_at = _parse_time(row["verified_at"], "verified_at")
        if verified_at < cohorts[case_id]["decision"]:
            raise ValueError(f"Ground truth predates scoring for {case_id}")
        if not _truth(row["independent"], "independent"):
            raise ValueError(f"Ground-truth adjudication is not independent for {case_id}")
        benign_screened = _truth(row["benign_screened"], "benign_screened")
        if label == 0 and not benign_screened:
            raise ValueError(f"Benign case lacks independent screening: {case_id}")
        result[case_id] = {
            "label": label,
            "verified_at": verified_at,
            "adjudication_source": _required(row["adjudication_source"], "adjudication_source"),
        }
    missing = eval_ids - set(result)
    extra = set(result) - eval_ids
    if missing or extra:
        raise ValueError(
            f"Label ledger must cover every non-training case and no others; "
            f"missing={len(missing)}, extra={len(extra)}"
        )
    return result


def _load_feed_events(path: Path, cohorts: dict[str, dict[str, Any]]) -> dict[str, datetime]:
    first_seen: dict[str, datetime] = {}
    verified_snapshots: dict[Path, str] = {}
    for row in _read_rows(path, CSV_SCHEMAS["feed_events"]):
        case_id = _required(row["case_id"], "feed event case_id")
        if case_id not in cohorts:
            raise ValueError(f"Feed event refers to unknown case: {case_id}")
        _required(row["feed_source"], "feed_source")
        received_at = _parse_time(row["snapshot_received_at"], "snapshot_received_at")
        expected_hash = row["snapshot_sha256"].lower()
        if not re.fullmatch(r"[0-9a-f]{64}", expected_hash):
            raise ValueError(f"Invalid snapshot SHA-256 for feed event {case_id}")
        snapshot = Path(row["snapshot_path"])
        if not snapshot.is_absolute():
            snapshot = path.parent / snapshot
        snapshot = snapshot.resolve()
        if snapshot not in verified_snapshots:
            if not snapshot.is_file():
                raise FileNotFoundError(f"Snapshot artifact is missing: {snapshot}")
            verified_snapshots[snapshot] = _sha256(snapshot)
        if verified_snapshots[snapshot] != expected_hash:
            raise ValueError(f"Snapshot SHA-256 mismatch for feed event {case_id}")
        if case_id not in first_seen or received_at < first_seen[case_id]:
            first_seen[case_id] = received_at
    return first_seen


def _feed_sources(path: Path) -> dict[str, set[str]]:
    result: dict[str, set[str]] = defaultdict(set)
    for row in _read_rows(path, CSV_SCHEMAS["feed_events"]):
        result[row["case_id"]].add(row["feed_source"])
    return result


def _validate_external_holdout(cohorts: dict[str, dict[str, Any]]) -> dict[str, Any]:
    by_partition: dict[str, list[dict[str, Any]]] = {
        name: [row for row in cohorts.values() if row["partition"] == name]
        for name in PARTITIONS
    }
    missing = [name for name, rows in by_partition.items() if not rows]
    if missing:
        return {"valid": False, "reason": "missing_partitions", "missing": missing}

    chronology = all(
        max(row["decision"] for row in by_partition[left])
        <= min(row["decision"] for row in by_partition[right])
        for left, right in zip(PARTITIONS, PARTITIONS[1:])
    )
    external = by_partition["external"]
    rest = [row for name in PARTITIONS if name != "external" for row in by_partition[name]]
    fields = ("source_id", "domain_id")
    overlap = {
        field: sorted(
            {row[field] for row in external if row[field]}
            & {row[field] for row in rest if row[field]}
        )
        for field in fields
    }
    disjoint = all(not values for values in overlap.values())
    return {
        "valid": chronology and disjoint,
        "chronological_partitions": chronology,
        "external_source_domain_disjoint": disjoint,
        "external_group_overlap_counts": {field: len(values) for field, values in overlap.items()},
        "external_periods": sorted({row["decision"].strftime("%Y-%m") for row in external}),
    }


def _eligible_cases(
    cohorts: dict[str, dict[str, Any]], first_seen: dict[str, datetime],
) -> dict[str, dict[str, Any]]:
    training = [row for row in cohorts.values() if row["partition"] == "train"]
    train_domains = {row["domain_id"] for row in training if row["domain_id"]}
    train_campaigns = {row["campaign_id"] for row in training if row["campaign_id"]}
    train_infra = {row["infrastructure_id"] for row in training if row["infrastructure_id"]}
    training_end = max(row["decision"] for row in training)
    result = {}
    for case_id, row in cohorts.items():
        if row["partition"] == "train":
            continue
        seen_at = first_seen.get(case_id)
        feed_first_seen = bool(
            seen_at is not None and training_end < seen_at <= row["decision"]
        )
        domain_novel = bool(row["domain_id"] and row["domain_id"] not in train_domains)
        campaign_novel = bool(
            row["campaign_id"] and row["campaign_id"] not in train_campaigns
        )
        infra_novel = bool(
            row["infrastructure_id"] and row["infrastructure_id"] not in train_infra
        )
        result[case_id] = {
            "case_id": case_id,
            "partition": row["partition"],
            "first_seen_by_feed": feed_first_seen,
            "first_seen_at": seen_at.isoformat().replace("+00:00", "Z") if seen_at else "",
            "training_domain_novel": domain_novel,
            "training_campaign_novel": campaign_novel,
            "training_infrastructure_novel": infra_novel,
            "strict_novel": domain_novel and campaign_novel and infra_novel,
        }
    return result


def _operating_threshold(rows: list[tuple[float, int]], max_fpr: float) -> float:
    negatives = sum(label == 0 for _, label in rows)
    positives = sum(label == 1 for _, label in rows)
    if not negatives or not positives:
        raise ValueError("Calibration requires accessible phishing and screened benign cases")
    candidates = sorted({0.0, 1.0, *(score for score, _ in rows)})
    eligible = []
    for threshold in candidates:
        fp = sum(score >= threshold and label == 0 for score, label in rows)
        tp = sum(score >= threshold and label == 1 for score, label in rows)
        fpr = fp / negatives
        if fpr <= max_fpr:
            eligible.append((tp, -threshold, threshold))
    return max(eligible)[2] if eligible else math.nextafter(1.0, math.inf)


def _average_precision(rows: list[tuple[float, int]]) -> float | None:
    if not rows or len({label for _, label in rows}) < 2:
        return None
    return float(average_precision_score(
        [label for _, label in rows], [score for score, _ in rows],
    ))


def _tpr_fpr(rows: list[tuple[float, int]], threshold: float) -> tuple[float | None, float | None]:
    positives = sum(label == 1 for _, label in rows)
    negatives = sum(label == 0 for _, label in rows)
    if not positives or not negatives:
        return None, None
    tp = sum(score >= threshold and label == 1 for score, label in rows)
    fp = sum(score >= threshold and label == 0 for score, label in rows)
    return tp / positives, fp / negatives


def _campaign_bootstrap(
    rows: list[tuple[float, int, str]], metric: str, seed: int, samples: int,
) -> tuple[float | None, float | None]:
    groups: dict[str, list[tuple[float, int]]] = defaultdict(list)
    for score, label, campaign in rows:
        if campaign:
            groups[campaign].append((score, label))
    if len(groups) < 2:
        return None, None
    names = sorted(groups)
    rng = random.Random(seed)
    estimates: list[float] = []
    for _ in range(samples):
        selected = [rng.choice(names) for _ in names]
        replicate = [row for group in selected for row in groups[group]]
        if metric == "auprc":
            value = _average_precision(replicate)
        else:
            value, _ = _tpr_fpr(replicate, metric)
        if value is not None:
            estimates.append(value)
    if not estimates:
        return None, None
    estimates.sort()
    return estimates[int(0.025 * (len(estimates) - 1))], estimates[
        int(0.975 * (len(estimates) - 1))
    ]


def _write_csv(path: Path, rows: list[dict[str, Any]], columns: tuple[str, ...] | None = None) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fields = list(columns or (rows[0].keys() if rows else ()))
    with path.open("w", newline="", encoding="utf-8") as stream:
        writer = csv.DictWriter(stream, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)


def run_e16(
    out_dir: str = "results/E16",
    table_dir: str = "tables",
    cohort_path: str = "data/E16/cohorts.csv",
    prediction_path: str = "data/E16/predictions.csv",
    label_path: str = "data/E16/labels.csv",
    feed_events_path: str = "data/E16/feed_events.csv",
    max_fpr: float = 0.01,
    bootstrap_samples: int = 500,
    seed: int = 20261616,
) -> dict[str, Any]:
    """Evaluate frozen, locally supplied model scores without URL retrieval.

    Calibration labels select operating thresholds. Labels for test and
    external cases are joined only after each prediction row is frozen.
    """
    if not math.isfinite(max_fpr) or not 0 < max_fpr < 1:
        raise ValueError("max_fpr must be strictly between 0 and 1")
    if type(bootstrap_samples) is not int or bootstrap_samples < 1:
        raise ValueError("bootstrap_samples must be a positive integer")
    started = time.perf_counter()
    out, tables = Path(out_dir), Path(table_dir)
    out.mkdir(parents=True, exist_ok=True)
    tables.mkdir(parents=True, exist_ok=True)
    inputs = {
        "cohorts": Path(cohort_path),
        "predictions": Path(prediction_path),
        "labels": Path(label_path),
        "feed_events": Path(feed_events_path),
    }
    absent = [str(path) for path in inputs.values() if not path.is_file()]
    if absent:
        audit = {
            "experiment": "E16",
            "status": "NOT_RUN_INPUTS_MISSING",
            "missing_inputs": absent,
            "metrics_reported": False,
            "pass_criteria": {"status": "blocked", "reason": "prospective ledgers are not present"},
            "runtime_seconds": time.perf_counter() - started,
        }
        _write_csv(out / "metrics.csv", [], (
            "system", "cohort", "metric", "value", "denominator", "status",
        ))
        _write_csv(out / "selective_risk_coverage.csv", [], (
            "system", "cohort", "confidence_threshold", "coverage", "selective_risk",
            "decided", "denominator",
        ))
        _write_csv(out / "error_taxonomy.csv", [], (
            "system", "cohort", "error_type", "count", "denominator",
        ))
        _write_csv(out / "eligibility.csv", [], (
            "case_id", "partition", "first_seen_by_feed", "first_seen_at",
            "training_domain_novel", "training_campaign_novel",
            "training_infrastructure_novel", "strict_novel",
        ))
        (out / "audit.json").write_text(json.dumps(audit, indent=2) + "\n", encoding="utf-8")
        _write_manifest(out)
        return audit

    cohorts = _load_cohorts(inputs["cohorts"])
    predictions = _load_predictions(inputs["predictions"], cohorts)
    labels = _load_labels(inputs["labels"], cohorts)
    feed_first_seen = _load_feed_events(inputs["feed_events"], cohorts)
    feeds_by_case = _feed_sources(inputs["feed_events"])
    holdout = _validate_external_holdout(cohorts)
    eligible = _eligible_cases(cohorts, feed_first_seen)
    for case_id, label in labels.items():
        label_source = label["adjudication_source"]
        if label_source == cohorts[case_id]["source_id"] or label_source in feeds_by_case[case_id]:
            raise ValueError(f"Adjudication source is not independent for {case_id}")

    calibration_cases = [
        case_id for case_id, row in cohorts.items() if row["partition"] == "calibration"
    ]
    thresholds = {}
    for system in SYSTEMS:
        calibration = [
            (predictions[(case_id, system)]["score"], labels[case_id]["label"])
            for case_id in calibration_cases
            if predictions[(case_id, system)]["score"] is not None
        ]
        thresholds[system] = _operating_threshold(calibration, max_fpr)

    metrics: list[dict[str, Any]] = []
    curves: list[dict[str, Any]] = []
    taxonomy: list[dict[str, Any]] = []
    all_test = {
        name: [case_id for case_id, row in cohorts.items() if row["partition"] == name]
        for name in ("test", "external")
    }
    groups = {
        "test_all": all_test["test"],
        "external_all": all_test["external"],
        "test_first_seen": [
            case_id for case_id in all_test["test"] if eligible[case_id]["first_seen_by_feed"]
        ],
        "external_first_seen": [
            case_id for case_id in all_test["external"] if eligible[case_id]["first_seen_by_feed"]
        ],
        "test_first_seen_strict_novel": [
            case_id for case_id in all_test["test"]
            if eligible[case_id]["first_seen_by_feed"] and eligible[case_id]["strict_novel"]
        ],
        "external_first_seen_strict_novel": [
            case_id for case_id in all_test["external"]
            if eligible[case_id]["first_seen_by_feed"] and eligible[case_id]["strict_novel"]
        ],
    }

    for cohort_name, case_ids in groups.items():
        for system_index, system in enumerate(SYSTEMS):
            available = [
                (case_id, predictions[(case_id, system)])
                for case_id in case_ids
                if predictions[(case_id, system)]["score"] is not None
            ]
            scored = [(item["score"], labels[case_id]["label"]) for case_id, item in available]
            positives = sum(label == 1 for _, label in scored)
            negatives = sum(label == 0 for _, label in scored)
            ap = _average_precision(scored)
            tpr, fpr = _tpr_fpr(scored, thresholds[system])
            campaign_rows = [
                (item["score"], labels[case_id]["label"], cohorts[case_id]["campaign_id"])
                for case_id, item in available
            ]
            campaign_ci_rows = [row for row in campaign_rows if row[2]]
            ap_low, ap_high = _campaign_bootstrap(
                campaign_ci_rows, "auprc", seed + system_index, bootstrap_samples,
            )
            tpr_low, tpr_high = _campaign_bootstrap(
                campaign_ci_rows, thresholds[system], seed + 100 + system_index, bootstrap_samples,
            )
            inaccessible = sum(
                predictions[(case_id, system)]["access_status"] == "inaccessible"
                for case_id in case_ids
            )
            cost = (
                sum(predictions[(case_id, system)]["evidence_cost"] for case_id in case_ids)
                / len(case_ids) if case_ids else None
            )
            latency = (
                sum(predictions[(case_id, system)]["latency_ms"] for case_id in case_ids)
                / len(case_ids) if case_ids else None
            )
            entries = (
                ("auprc", ap, len(scored), "ok" if ap is not None else "insufficient_class_variation"),
                ("tpr_at_calibrated_fpr", tpr, positives, "ok" if tpr is not None else "insufficient_class_variation"),
                ("fpr_at_calibrated_threshold", fpr, negatives, "ok" if fpr is not None else "insufficient_class_variation"),
                ("campaign_bootstrap_auprc_ci_low", ap_low, len(campaign_ci_rows), "ok" if ap_low is not None else "insufficient_campaign_groups"),
                ("campaign_bootstrap_auprc_ci_high", ap_high, len(campaign_ci_rows), "ok" if ap_high is not None else "insufficient_campaign_groups"),
                ("campaign_bootstrap_tpr_ci_low", tpr_low, len(campaign_ci_rows), "ok" if tpr_low is not None else "insufficient_campaign_groups"),
                ("campaign_bootstrap_tpr_ci_high", tpr_high, len(campaign_ci_rows), "ok" if tpr_high is not None else "insufficient_campaign_groups"),
                ("campaign_group_count", len({row[2] for row in campaign_ci_rows}), len(scored), "ok"),
                ("campaign_ci_included_cases", len(campaign_ci_rows), len(scored), "campaign_id_required"),
                ("calibrated_threshold", thresholds[system], len(calibration_cases), "calibration_only"),
                ("inaccessible_no_signal_count", inaccessible, len(case_ids), "not_a_false_negative"),
                ("mean_evidence_cost", cost, len(case_ids), "ok" if cost is not None else "empty_cohort"),
                ("mean_latency_ms", latency, len(case_ids), "ok" if latency is not None else "empty_cohort"),
            )
            for metric, value, denominator, status in entries:
                metrics.append({
                    "system": system, "cohort": cohort_name, "metric": metric,
                    "value": value, "denominator": denominator, "status": status,
                })

            for error_type in (
                "true_positive", "true_negative", "false_positive", "false_negative",
                "inaccessible_no_signal",
            ):
                count = 0
                for case_id in case_ids:
                    item = predictions[(case_id, system)]
                    label = labels[case_id]["label"]
                    if item["access_status"] == "inaccessible":
                        count += int(error_type == "inaccessible_no_signal")
                    elif error_type == "true_positive":
                        count += int(item["score"] >= thresholds[system] and label == 1)
                    elif error_type == "true_negative":
                        count += int(item["score"] < thresholds[system] and label == 0)
                    elif error_type == "false_positive":
                        count += int(item["score"] >= thresholds[system] and label == 0)
                    elif error_type == "false_negative":
                        count += int(item["score"] < thresholds[system] and label == 1)
                taxonomy.append({
                    "system": system, "cohort": cohort_name, "error_type": error_type,
                    "count": count, "denominator": len(case_ids),
                })

            for confidence in (0.0, 0.2, 0.4, 0.6, 0.8, 1.0):
                decided = [
                    (case_id, item) for case_id, item in available
                    if abs(item["score"] - 0.5) * 2 >= confidence
                ]
                errors = sum(
                    int((item["score"] >= 0.5) != bool(labels[case_id]["label"]))
                    for case_id, item in decided
                )
                curves.append({
                    "system": system,
                    "cohort": cohort_name,
                    "confidence_threshold": confidence,
                    "coverage": len(decided) / len(case_ids) if case_ids else None,
                    "selective_risk": errors / len(decided) if decided else None,
                    "decided": len(decided),
                    "denominator": len(case_ids),
                })

    _write_csv(out / "metrics.csv", metrics)
    _write_csv(out / "selective_risk_coverage.csv", curves)
    _write_csv(out / "error_taxonomy.csv", taxonomy)
    eligibility_rows = list(eligible.values())
    _write_csv(out / "eligibility.csv", eligibility_rows, tuple(eligibility_rows[0].keys()))
    input_hashes = {name: _sha256(path) for name, path in inputs.items()}
    equal_cost = True
    first_seen_test = sum(
        eligible[case_id]["first_seen_by_feed"] for case_id in all_test["test"]
    )
    first_seen_external = sum(
        eligible[case_id]["first_seen_by_feed"] for case_id in all_test["external"]
    )
    strict_novel_test = sum(
        eligible[case_id]["first_seen_by_feed"] and eligible[case_id]["strict_novel"]
        for case_id in all_test["test"]
    )
    strict_novel_external = sum(
        eligible[case_id]["first_seen_by_feed"] and eligible[case_id]["strict_novel"]
        for case_id in all_test["external"]
    )
    required_first_seen_cohorts = {
        "test_first_seen", "external_first_seen",
        "test_first_seen_strict_novel", "external_first_seen_strict_novel",
    }
    first_seen_ap_rows = [
        row for row in metrics
        if row["metric"] == "auprc" and row["cohort"] in required_first_seen_cohorts
    ]
    first_seen_metrics_estimable = (
        len(first_seen_ap_rows) == len(SYSTEMS) * len(required_first_seen_cohorts)
        and all(row["status"] == "ok" for row in first_seen_ap_rows)
    )
    passed = (
        holdout["valid"] and first_seen_test > 0 and first_seen_external > 0
        and strict_novel_test > 0 and strict_novel_external > 0
        and first_seen_metrics_estimable
    )
    audit = {
        "experiment": "E16",
        "status": "pass" if passed else "fail",
        "metrics_reported": True,
        "input_sha256": input_hashes,
        "systems": list(SYSTEMS),
        "fpr_target": max_fpr,
        "thresholds_selected_from_calibration_only": thresholds,
        "case_counts": dict(Counter(row["partition"] for row in cohorts.values())),
        "first_seen_feed_cases": sum(row["first_seen_by_feed"] for row in eligible.values()),
        "first_seen_test_cases": first_seen_test,
        "first_seen_external_cases": first_seen_external,
        "strict_novel_first_seen_test_cases": strict_novel_test,
        "strict_novel_first_seen_external_cases": strict_novel_external,
        "strict_novel_first_seen_cases": sum(
            row["first_seen_by_feed"] and row["strict_novel"] for row in eligible.values()
        ),
        "external_holdout": holdout,
        "equal_evidence_cost_per_case": equal_cost,
        "first_seen_rule": (
            "positive feed listing with a receipt timestamp strictly after training cutoff "
            "and no later than the decision; source snapshot bytes are SHA-256 verified; "
            "absence from a current feed is never used"
        ),
        "ground_truth_rule": (
            "separate independent adjudication ledger; verified no earlier than the decision; "
            "benign labels require independent screening"
        ),
        "no_signal_rule": (
            "inaccessible cases require blank model score and zero signals; reported separately "
            "and included in coverage denominator, not counted as false negatives"
        ),
        "metrics": {
            "first_seen_auprc": "average precision over accessible first-seen cases; denominator and class counts in metrics.csv",
            "tpr_at_fpr": "threshold selected on calibration cases to maximize TPR subject to requested FPR; evaluated on test/external",
            "selective_risk": "incorrect decisions among accessible cases above each confidence threshold; coverage denominator includes all cases",
            "campaign_ci": f"percentile bootstrap over campaign IDs, {bootstrap_samples} replicates; unavailable below two groups",
            "cost_latency": "mean supplied per-case evidence cost and end-to-end latency; all systems must match evidence cost exactly within 1e-9",
        },
        "related_work": {
            "PhishLumos": "not reproduced; code/data availability and protocol were not independently established",
            "URL2Path": "not reproduced; code/data availability and protocol were not independently established",
        },
        "pass_criteria": {
            "prospective_group_temporal_holdout": holdout["valid"],
            "source_domain_period_external_holdout": holdout["valid"],
            "first_seen_based_on_receipt_time_not_absence": True,
            "independent_post_decision_labels": True,
            "snapshot_hashes_verified": True,
            "matched_evidence_costs": equal_cost,
            "all_required_systems_scored": True,
            "first_seen_test_and_external_metrics_estimable": first_seen_metrics_estimable,
            "status": "pass" if passed else "fail",
        },
        "runtime_seconds": time.perf_counter() - started,
    }
    (out / "audit.json").write_text(json.dumps(audit, indent=2, allow_nan=False) + "\n", encoding="utf-8")
    _write_manifest(out)
    return audit


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _write_manifest(out: Path) -> None:
    files = [
        path for path in out.rglob("*")
        if path.is_file() and path.name != "manifest_sha256.json"
    ]
    manifest = {
        str(path.relative_to(out)): _sha256(path)
        for path in sorted(files)
    }
    (out / "manifest_sha256.json").write_text(
        json.dumps(manifest, indent=2) + "\n", encoding="utf-8",
    )
