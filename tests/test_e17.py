import csv
import hashlib
import json

import pytest

from cerurl.e17 import (
    POLICIES, _calibrate_ttls, _case_plans, _policy_run,
    _sealed_monthly_observations, run_e17,
)


def test_e17_runs_controlled_longitudinal_comparison_and_writes_hashes(tmp_path):
    audit = run_e17(
        tmp_path / "out", tmp_path / "tables",
        cases=16, months=8, seed=17, calibration_seed=71,
    )
    assert audit["status"] == "pass"
    assert audit["field_drift_claim"] is False
    assert audit["world_type"] == "controlled_synthetic_longitudinal"
    assert audit["stale_certificate_retained_count"] == 0
    assert audit["certificate_expiry_correctness"] == 1.0
    assert set(audit["policies"]) == set(POLICIES)

    out = tmp_path / "out"
    monthly = list(csv.DictReader((out / "monthly.csv").open()))
    assert len(monthly) == 16 * 8 * len(POLICIES)
    assert {row["policy"] for row in monthly} == set(POLICIES)
    manifest = json.loads((out / "manifest_sha256.json").read_text())
    assert {
        "audit.json", "monthly.csv", "metrics.csv", "summary.csv",
        "calibration_ttl.csv",
    } <= set(manifest)
    for relative, expected in manifest.items():
        assert hashlib.sha256((out / relative).read_bytes()).hexdigest() == expected
    assert (tmp_path / "tables" / "e17_longitudinal.tex").is_file()


def test_e17_cer_rebuilds_certificate_after_graph_snapshot_change():
    plan = _case_plans(8, 11, 8)[0]
    ttls, _ = _calibrate_ttls(71, samples=100)
    outcomes = _sealed_monthly_observations(plan, 8, 91)
    rows = _policy_run(plan, outcomes, 8, ttls, periodic_interval=3)
    static_change = next(
        row for row in rows
        if row["policy"] == "static_trust" and row["graph_snapshot_changed"]
    )
    cer_change = next(
        row for row in rows
        if row["policy"] == "cer_repair" and row["graph_snapshot_changed"]
    )
    assert not static_change["certificate_valid"]
    assert cer_change["certificate_invalidated"]
    assert cer_change["invalidation_reason"] == "graph_snapshot_changed"
    assert cer_change["action_count"] > 0
    assert cer_change["certificate_valid"]


def test_e17_calibration_ttls_are_seeded_and_per_modality():
    left, rows = _calibrate_ttls(123, samples=80)
    right, _ = _calibrate_ttls(123, samples=80)
    assert left == right
    assert set(left) == {"feed", "dns", "tls", "html", "redirect", "reputation"}
    assert len(rows) == len(left) * 7


@pytest.mark.parametrize(
    ("cases", "months", "periodic_interval"),
    [(7, 12, 3), (8, 3, 3), (8, 12, 0)],
)
def test_e17_rejects_invalid_run_parameters(tmp_path, cases, months, periodic_interval):
    with pytest.raises(ValueError):
        run_e17(
            tmp_path / "out", tmp_path / "tables", cases=cases,
            months=months, periodic_interval=periodic_interval,
        )
