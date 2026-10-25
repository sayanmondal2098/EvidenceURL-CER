import csv
import hashlib
import json

import pytest

from cerurl.e19 import run_e19


def test_e19_small_run_reports_incremental_agreement_and_hashed_outputs(tmp_path):
    out = tmp_path / "out"
    tables = tmp_path / "tables"
    audit = run_e19(
        str(out), str(tables), sizes=(64,), seed=19, repeats=3,
        certificate_time_limit=1.0,
    )

    assert audit["status"] == "pass"
    assert audit["workload_source"].startswith("controlled_synthetic")
    assert audit["incremental_correctness"]["all_updates_match_full_recomputation"]
    assert audit["completed_sizes"] == [64]
    assert audit["deployment_limits"]["network_collector_overhead"].startswith("not measured")

    incremental = list(csv.DictReader((out / "incremental_checks.csv").open()))
    assert len(incremental) == 1
    assert incremental[0]["equivalent"] == "True"
    assert float(incremental[0]["max_abs_error"]) <= 1e-9

    latencies = list(csv.DictReader((out / "stage_latency.csv").open()))
    assert {"p50_ms", "p95_ms", "p99_ms"} <= set(latencies[0])
    assert {row["stage"] for row in latencies} >= {
        "ingestion", "ancestor_closure", "full_propagation",
        "incremental_trust_update", "storage_write",
    }
    manifest = json.loads((out / "manifest_sha256.json").read_text())
    for relative, digest in manifest.items():
        assert hashlib.sha256((out / relative).read_bytes()).hexdigest() == digest
    assert (out / "scalability.png").is_file()
    assert (out / "certificate_costs.png").is_file()
    assert (tables / "e19_scale_summary.csv").is_file()


@pytest.mark.parametrize(
    ("sizes", "repeats"),
    [
        ((), 3),
        ((64, 64), 3),
        ((32,), 3),
        ((64,), 2),
    ],
)
def test_e19_rejects_invalid_parameters(tmp_path, sizes, repeats):
    with pytest.raises(ValueError):
        run_e19(
            str(tmp_path / "out"), str(tmp_path / "tables"),
            sizes=sizes, repeats=repeats,
        )
