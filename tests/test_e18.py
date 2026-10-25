import csv
import hashlib
import json

import pytest

from cerurl.e18 import (
    ABLATIONS, FACTORS, SWEEP, _assumption_stress,
    _make_case, _sensitivity, run_e18,
)


def test_e18_run_writes_complete_controlled_outputs_and_manifest(tmp_path):
    audit = run_e18(
        tmp_path / "out", tmp_path / "tables",
        cases=12, seed=18, bootstrap_samples=100,
    )
    assert audit["status"] == "pass"
    assert audit["world_type"] == "controlled_synthetic"
    assert audit["field_performance_claim"] is False
    assert audit["pass_criteria"]["all_requested_ablation_axes_present"]
    assert audit["pass_criteria"]["full_factorial_interactions_reported"]
    assert audit["pass_criteria"]["sensitivity_axes_reported"]
    assert audit["pass_criteria"]["assumption_violations_invalidate_proofs"]
    assert audit["pass_criteria"]["graph_increment_assessed_after_source_fusion"]
    out = tmp_path / "out"
    ablations = list(csv.DictReader((out / "ablation.csv").open()))
    assert {row["ablation"] for row in ablations} == set(ABLATIONS)
    interactions = list(csv.DictReader((out / "factorial_interactions.csv").open()))
    assert len(interactions) == len(FACTORS) * (len(FACTORS) - 1)
    sensitivity = list(csv.DictReader((out / "sensitivity.csv").open()))
    assert {row["dimension"] for row in sensitivity} == set(SWEEP)
    manifest = json.loads((out / "manifest_sha256.json").read_text())
    for relative, expected in manifest.items():
        assert hashlib.sha256((out / relative).read_bytes()).hexdigest() == expected
    assert (tmp_path / "tables" / "e18_ablations.tex").is_file()


def test_e18_assumption_violations_are_fail_closed():
    case, label = _make_case(1, "stress-case")
    rows = _assumption_stress([(case, label)])
    assert {row["violation"] for row in rows} == {
        "fixed_weights_changed", "independence_claims_merged",
        "graph_normalization_broken",
    }
    assert all(row["certificate_status"] == "invalidated" for row in rows)


def test_e18_sensitivity_reports_cost_and_requested_axes():
    cases = [_make_case(index, f"sens-{index}") for index in range(12)]
    rows = _sensitivity(cases, seed=37)
    assert {row["dimension"] for row in rows} == set(SWEEP)
    cost_rows = [row for row in rows if row["dimension"] == "action_cost_multiplier"]
    assert len(cost_rows) == len(SWEEP["action_cost_multiplier"])
    assert any(row["mean_action_cost"] > 0 for row in cost_rows)
    uncertainty_rows = [
        row for row in rows if row["dimension"] == "provenance_uncertainty"
        and row["value"] > 0
    ]
    assert all(row["certificate_coverage"] == 0 for row in uncertainty_rows)


@pytest.mark.parametrize(("cases", "bootstrap_samples"), [(11, 100), (12, 99)])
def test_e18_rejects_invalid_parameters(tmp_path, cases, bootstrap_samples):
    with pytest.raises(ValueError):
        run_e18(
            tmp_path / "out", tmp_path / "tables",
            cases=cases, bootstrap_samples=bootstrap_samples,
        )
