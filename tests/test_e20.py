import hashlib
import json

import pytest

from cerurl.e20 import _cluster_bootstrap, _holm, run_e20


def test_e20_holm_adjustment_is_monotone_and_preserves_missing_tests():
    adjusted = _holm({"one": 0.01, "two": 0.04, "missing": None})
    assert adjusted == {"one": 0.02, "two": 0.04, "missing": None}


def test_e20_cluster_bootstrap_is_repeatable():
    values = [1.0, 3.0, 2.0, 4.0]
    clusters = ["a", "a", "b", "c"]
    assert _cluster_bootstrap(values, clusters, seed=20) == _cluster_bootstrap(
        values, clusters, seed=20,
    )


def test_e20_archive_only_run_is_explicitly_partial_and_offline(tmp_path):
    out = tmp_path / "out"
    tables = tmp_path / "tables"
    audit = run_e20(str(out), str(tables), seed_runs=0)

    assert audit["status"] == "partial_or_blocked"
    assert audit["network_accessed"] is False
    assert audit["mutable_feeds_redownloaded"] is False
    assert audit["archived_experiments"] == 19
    assert audit["seed_replays"]["seed_values"] == []
    assert audit["data_release_hash_verification_pass"]
    assert not audit["confirmatory_hypotheses"][0]["paired_observations"]

    experiment_rows = (out / "experiment_status.csv").read_text(encoding="utf-8")
    assert "E16" in experiment_rows
    assert "NOT_RUN_INPUTS_MISSING" in experiment_rows
    assert "E02" in experiment_rows
    assert "BASELINE_NOT_REPRODUCIBLE" in experiment_rows
    assert "E05" in experiment_rows
    assert "ARCHIVED_OUTPUTS_PRESENT_STATUS_UNSPECIFIED" not in experiment_rows
    assert (out / "paper_sections.tex").is_file()
    assert (out / "source_license_manifest.json").is_file()
    assert (out / "issue_log.jsonl").is_file()
    assert (tables / "e20_hypotheses.tex").is_file()

    manifest = json.loads((out / "manifest_sha256.json").read_text())
    assert len(manifest) == audit["manifest_entry_count"]
    for relative, digest in manifest.items():
        assert hashlib.sha256((out / relative).read_bytes()).hexdigest() == digest


@pytest.mark.parametrize("seed_runs", [-1, 1, 4])
def test_e20_rejects_invalid_seed_run_count(tmp_path, seed_runs):
    with pytest.raises(ValueError):
        run_e20(str(tmp_path / "out"), str(tmp_path / "tables"), seed_runs=seed_runs)
