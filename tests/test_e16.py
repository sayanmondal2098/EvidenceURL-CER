import csv
import hashlib
import json
from datetime import datetime, timedelta, timezone

import pytest

from cerurl.e16 import SYSTEMS, _operating_threshold, run_e16


def _timestamp(value):
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _write_csv(path, columns, rows):
    with path.open("w", newline="", encoding="utf-8") as stream:
        writer = csv.DictWriter(stream, fieldnames=columns)
        writer.writeheader()
        writer.writerows(rows)


def _ledgers(tmp_path):
    start = datetime(2025, 1, 1, tzinfo=timezone.utc)
    snapshot_bytes = b"retained authorised feed snapshot bytes"
    (tmp_path / "feed_snapshot.bin").write_bytes(snapshot_bytes)
    snapshot_hash = hashlib.sha256(snapshot_bytes).hexdigest()
    cohorts, predictions, labels, feed_events = [], [], [], []
    partitions = ("train", "calibration", "test", "external")
    for partition_index, partition in enumerate(partitions):
        for index in range(4):
            case_id = f"case-{partition}-{index}"
            decision = start + timedelta(days=partition_index * 30 + index)
            external = partition == "external"
            cohorts.append({
                "case_id": case_id,
                "partition": partition,
                "decision_at": _timestamp(decision),
                "source_id": f"external-feed" if external else "main-feed",
                "domain_id": (
                    f"domain-{partition}-{index}" if external or partition != "train"
                    else f"domain-train-{index}"
                ),
                "campaign_id": f"campaign-{partition}-{index}",
                "infrastructure_id": f"infra-{partition}-{index}",
            })
            if partition == "train":
                continue
            label = index % 2
            labels.append({
                "case_id": case_id,
                "label": label,
                "verified_at": _timestamp(decision + timedelta(days=2)),
                "adjudication_source": "independent-screening-lab",
                "independent": "true",
                "benign_screened": "true" if label == 0 else "false",
            })
            for system_index, system in enumerate(SYSTEMS):
                inaccessible = system == "feature_only" and partition == "test" and index == 0
                score = 0.9 if label else 0.1
                predictions.append({
                    "case_id": case_id,
                    "system": system,
                    "probability_phishing": "" if inaccessible else score,
                    "access_status": "inaccessible" if inaccessible else "available",
                    "signal_count": 0 if inaccessible else 2,
                    "evidence_cost": 1.0,
                    "latency_ms": 2.0 + system_index,
                })
            if partition in ("test", "external"):
                event_at = decision + timedelta(hours=1) if index == 3 else decision - timedelta(hours=1)
                feed_events.append({
                    "case_id": case_id,
                    "feed_source": "prospective-feed",
                    "snapshot_received_at": _timestamp(event_at),
                    "snapshot_path": "feed_snapshot.bin",
                    "snapshot_sha256": snapshot_hash,
                })

    paths = {
        "cohorts": tmp_path / "cohorts.csv",
        "predictions": tmp_path / "predictions.csv",
        "labels": tmp_path / "labels.csv",
        "feed_events": tmp_path / "feed_events.csv",
    }
    _write_csv(paths["cohorts"], (
        "case_id", "partition", "decision_at", "source_id", "domain_id",
        "campaign_id", "infrastructure_id",
    ), cohorts)
    _write_csv(paths["predictions"], (
        "case_id", "system", "probability_phishing", "access_status",
        "signal_count", "evidence_cost", "latency_ms",
    ), predictions)
    _write_csv(paths["labels"], (
        "case_id", "label", "verified_at", "adjudication_source",
        "independent", "benign_screened",
    ), labels)
    _write_csv(paths["feed_events"], (
        "case_id", "feed_source", "snapshot_received_at", "snapshot_path",
        "snapshot_sha256",
    ), feed_events)
    return paths


def _run(tmp_path, paths):
    return run_e16(
        tmp_path / "results", tmp_path / "tables",
        paths["cohorts"], paths["predictions"], paths["labels"],
        paths["feed_events"], bootstrap_samples=25,
    )


def test_e16_separates_prospective_feed_novelty_and_inaccessible_cases(tmp_path):
    paths = _ledgers(tmp_path)
    audit = _run(tmp_path, paths)
    assert audit["status"] == "pass"
    assert audit["pass_criteria"]["first_seen_based_on_receipt_time_not_absence"]
    assert audit["first_seen_feed_cases"] == 6
    assert audit["strict_novel_first_seen_cases"] == 6

    eligibility = list(csv.DictReader((tmp_path / "results" / "eligibility.csv").open()))
    test_future = next(row for row in eligibility if row["case_id"] == "case-test-3")
    assert test_future["first_seen_by_feed"] == "False"
    metrics = list(csv.DictReader((tmp_path / "results" / "metrics.csv").open()))
    auprc = next(row for row in metrics if row["system"] == "full_cer"
                  and row["cohort"] == "test_first_seen_strict_novel"
                  and row["metric"] == "auprc")
    assert float(auprc["value"]) == 1.0
    no_signal = next(row for row in metrics if row["system"] == "feature_only"
                     and row["cohort"] == "test_all"
                     and row["metric"] == "inaccessible_no_signal_count")
    assert no_signal["value"] == "1"
    taxonomy = list(csv.DictReader((tmp_path / "results" / "error_taxonomy.csv").open()))
    false_negatives = next(row for row in taxonomy if row["system"] == "feature_only"
                           and row["cohort"] == "test_all"
                           and row["error_type"] == "false_negative")
    assert false_negatives["count"] == "0"
    manifest = json.loads((tmp_path / "results" / "manifest_sha256.json").read_text())
    assert {"audit.json", "metrics.csv", "selective_risk_coverage.csv",
            "error_taxonomy.csv", "eligibility.csv"} <= set(manifest)


def test_e16_missing_prospective_inputs_is_explicitly_blocked(tmp_path):
    audit = run_e16(
        tmp_path / "results", tmp_path / "tables",
        tmp_path / "missing-cohorts.csv", tmp_path / "missing-predictions.csv",
        tmp_path / "missing-labels.csv", tmp_path / "missing-feed-events.csv",
    )
    assert audit["status"] == "NOT_RUN_INPUTS_MISSING"
    assert audit["metrics_reported"] is False
    assert (tmp_path / "results" / "manifest_sha256.json").is_file()


def test_e16_rejects_prediction_ledger_with_outcome_fields(tmp_path):
    paths = _ledgers(tmp_path)
    with paths["predictions"].open(newline="", encoding="utf-8") as stream:
        rows = list(csv.DictReader(stream))
    for row in rows:
        row["label"] = "0"
    _write_csv(paths["predictions"], (
        "case_id", "system", "probability_phishing", "access_status",
        "signal_count", "evidence_cost", "latency_ms", "label",
    ), rows)
    with pytest.raises(ValueError, match="outcome columns"):
        _run(tmp_path, paths)


def test_e16_rejects_unmatched_evidence_costs(tmp_path):
    paths = _ledgers(tmp_path)
    with paths["predictions"].open(newline="", encoding="utf-8") as stream:
        rows = list(csv.DictReader(stream))
    rows[0]["evidence_cost"] = "3.0"
    _write_csv(paths["predictions"], (
        "case_id", "system", "probability_phishing", "access_status",
        "signal_count", "evidence_cost", "latency_ms",
    ), rows)
    with pytest.raises(ValueError, match="not matched"):
        _run(tmp_path, paths)


def test_e16_verifies_retained_snapshot_bytes_against_receipt(tmp_path):
    paths = _ledgers(tmp_path)
    with paths["feed_events"].open(newline="", encoding="utf-8") as stream:
        rows = list(csv.DictReader(stream))
    rows[0]["snapshot_sha256"] = "0" * 64
    _write_csv(paths["feed_events"], (
        "case_id", "feed_source", "snapshot_received_at", "snapshot_path",
        "snapshot_sha256",
    ), rows)
    with pytest.raises(ValueError, match="SHA-256 mismatch"):
        _run(tmp_path, paths)


def test_e16_threshold_uses_above_one_when_no_calibration_point_meets_fpr():
    threshold = _operating_threshold([(1.0, 0), (0.0, 1)], max_fpr=0.01)
    assert threshold > 1.0


def test_e16_marks_external_source_domain_overlap_as_failed(tmp_path):
    paths = _ledgers(tmp_path)
    with paths["cohorts"].open(newline="", encoding="utf-8") as stream:
        rows = list(csv.DictReader(stream))
    rows[-1]["source_id"] = "main-feed"
    _write_csv(paths["cohorts"], (
        "case_id", "partition", "decision_at", "source_id", "domain_id",
        "campaign_id", "infrastructure_id",
    ), rows)
    audit = _run(tmp_path, paths)
    assert audit["status"] == "fail"
    assert not audit["pass_criteria"]["source_domain_period_external_holdout"]
