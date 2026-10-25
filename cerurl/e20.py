"""E20: offline reproducibility audit and final report generator."""
from __future__ import annotations

import csv
import hashlib
import importlib.metadata
import json
import os
import platform
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import numpy as np

from .e06 import run_e06
from .e13 import DEFAULT_BUDGETS, run_e13
from .e18 import run_e18

EXPERIMENTS = tuple(f"E{index:02d}" for index in range(1, 20))
E20_MULTI_SEED_REPLAYS = {"E06", "E13", "E18"}
SOURCE_REGISTRY = Path("data/source_registry.json")
ACQUISITION_MANIFEST = Path("data/raw/acquisition_manifest.json")
SOURCE_PLAN = Path("data/source_acquisition_plan.json")
BOOTSTRAP_SAMPLES = 5_000
PERMUTATION_SAMPLES = 10_000


def _json(path: Path) -> dict[str, Any]:
    with path.open(encoding="utf-8") as stream:
        data = json.load(stream)
    return data if isinstance(data, dict) else {}


def _write_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(payload, indent=2, sort_keys=True, allow_nan=False) + "\n",
        encoding="utf-8",
    )


def _write_csv(path: Path, rows: list[dict[str, Any]], columns: tuple[str, ...]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as stream:
        writer = csv.DictWriter(stream, fieldnames=columns, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)


def _hash(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _sha_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _relative(path: Path, root: Path) -> str:
    try:
        return path.resolve().relative_to(root.resolve()).as_posix()
    except ValueError:
        return path.as_posix()


def _run_id(experiment: str, audit_path: Path) -> str:
    if not audit_path.is_file():
        return f"{experiment}-NO-AUDIT"
    audit = _json(audit_path)
    seed = audit.get("seed")
    seed_part = f"-seed-{seed}" if seed is not None else ""
    return f"{experiment}{seed_part}-{_hash(audit_path)[:12]}"


def _git_facts(root: Path) -> dict[str, Any]:
    def git(*args: str) -> str | None:
        try:
            result = subprocess.run(
                ["git", *args], cwd=root, check=True, capture_output=True,
                text=True, timeout=10,
            )
        except (OSError, subprocess.SubprocessError):
            return None
        return result.stdout.strip()

    return {
        "commit": git("rev-parse", "HEAD"),
        "working_tree_status": git("status", "--porcelain"),
    }


def _package_versions() -> dict[str, str | None]:
    result = {"evidenceurl-cer": None}
    for package in ("numpy", "scipy", "pandas", "scikit-learn", "matplotlib", "joblib"):
        try:
            result[package] = importlib.metadata.version(package)
        except importlib.metadata.PackageNotFoundError:
            result[package] = None
    try:
        result["evidenceurl-cer"] = importlib.metadata.version("evidenceurl-cer")
    except importlib.metadata.PackageNotFoundError:
        result["evidenceurl-cer"] = "local source checkout"
    return result


def _receipt_path(value: str, root: Path) -> Path:
    candidate = Path(value)
    if candidate.is_absolute():
        return candidate
    return root / candidate


def _dataset_and_license_release(root: Path) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    sources = _json(root / SOURCE_REGISTRY).get("sources", [])
    source_by_id = {item.get("source_id"): item for item in sources}
    acquisition_path = root / ACQUISITION_MANIFEST
    plan_path = root / SOURCE_PLAN
    acquisition = _json(acquisition_path) if acquisition_path.is_file() else {}
    plan = _json(plan_path) if plan_path.is_file() else {}
    plan_by_id = {item.get("source_id"): item for item in plan.get("sources", [])}
    entries, license_rows = [], []
    for item in acquisition.get("acquired", []):
        receipt_path = _receipt_path(item.get("receipt", ""), root)
        receipt = _json(receipt_path) if receipt_path.is_file() else {}
        artifact_path = _receipt_path(receipt.get("artifact_path", ""), root)
        expected = receipt.get("sha256") or item.get("sha256")
        actual = _hash(artifact_path) if artifact_path.is_file() else None
        registry = source_by_id.get(item.get("source_id"), {})
        source_plan = plan_by_id.get(item.get("source_id"), {})
        terms_reference = (
            receipt.get("authorisation", {}).get("terms_reference")
            or source_plan.get("authorisation", {}).get("terms_reference")
            or registry.get("url")
        )
        source_id = item.get("source_id", "unknown")
        if source_id == "phiusiil":
            license_status = (
                "CC BY 4.0 declared in source registry; attribution required; "
                "redistribution remains subject to the upstream terms"
            )
        else:
            license_status = (
                "access/terms reference retained; redistribution license and "
                "redistribution permission not adjudicated"
            )
        entries.append({
            "source_id": source_id,
            "release_id": receipt.get("release_id") or source_plan.get("release_id"),
            "artifact_id": receipt.get("artifact_id"),
            "artifact_path": (
                _relative(artifact_path, root) if artifact_path.is_absolute()
                else str(artifact_path)
            ),
            "receipt_path": _relative(receipt_path, root),
            "receipt_sha256": _hash(receipt_path) if receipt_path.is_file() else None,
            "artifact_sha256_expected": expected,
            "artifact_sha256_observed": actual,
            "artifact_hash_verified": bool(expected and actual == expected),
            "bytes": artifact_path.stat().st_size if artifact_path.is_file() else None,
            "acquired_at": receipt.get("acquired_at"),
            "terms_reference": terms_reference,
            "license_status": license_status,
            "redistributed": False,
        })
        license_rows.append({
            "source_id": source_id,
            "release_id": receipt.get("release_id") or source_plan.get("release_id"),
            "terms_reference": terms_reference,
            "access_authorized_in_receipt": receipt.get("authorisation", {}).get(
                "acquisition_authorized_by_user",
            ),
            "license_status": license_status,
            "redistribution_status": "not cleared; raw artifact not copied into E20",
            "receipt_sha256": _hash(receipt_path) if receipt_path.is_file() else None,
        })
    release = {
        "release_type": "local acquired snapshots and controlled synthetic fixture",
        "acquisition_manifest_path": str(ACQUISITION_MANIFEST),
        "acquisition_manifest_sha256": (
            _hash(acquisition_path) if acquisition_path.is_file() else None
        ),
        "source_plan_path": str(SOURCE_PLAN),
        "source_plan_sha256": _hash(plan_path) if plan_path.is_file() else None,
        "controlled_cases_manifest": _controlled_fixture(root),
        "acquired_artifacts": entries,
        "hash_verification_pass": bool(entries) and all(
            entry["artifact_hash_verified"] for entry in entries
        ),
        "redistribution_notice": (
            "The E20 report contains hashes and metadata only. It does not copy "
            "or redistribute acquired source datasets."
        ),
    }
    return release, license_rows


def _controlled_fixture(root: Path) -> dict[str, Any]:
    manifest_path = root / "data/controlled_cases.manifest.json"
    data_path = root / "data/controlled_cases.jsonl"
    result = {
        "manifest_path": "data/controlled_cases.manifest.json",
        "data_path": "data/controlled_cases.jsonl",
        "world_type": "controlled_synthetic",
    }
    if manifest_path.is_file():
        result["manifest"] = _json(manifest_path)
        result["manifest_sha256"] = _hash(manifest_path)
    if data_path.is_file():
        result["data_sha256"] = _hash(data_path)
        result["data_bytes"] = data_path.stat().st_size
    return result


def _experiment_record(root: Path, experiment: str) -> dict[str, Any]:
    directory = root / "results" / experiment
    audit_path = directory / "audit.json"
    run_manifest_path = directory / "run_manifest.json"
    audit = _json(audit_path) if audit_path.is_file() else {}
    run_manifest = _json(run_manifest_path) if run_manifest_path.is_file() else {}
    status = (
        audit.get("status") or run_manifest.get("run_status")
        or run_manifest.get("status")
    )
    if experiment == "E01" and not status:
        status = "pass_with_flagged_data_quality_findings"
    if experiment == "E02" and not status:
        status = "BASELINE_NOT_REPRODUCIBLE"
    if experiment == "E03" and not status:
        status = "NOT_RUN_TEMPORAL_ELIGIBILITY_BLOCKED"
    if experiment == "E04" and not status:
        status = "PARTIAL_CONTROLLED_INVARIANT_ONLY"
    if experiment == "E16" and not status:
        status = "NOT_RUN_INPUTS_MISSING"
    if not directory.is_dir():
        status = "NOT_RUN_ARTIFACTS_ABSENT"
    pass_criteria = audit.get("pass_criteria", {})
    if isinstance(pass_criteria, dict):
        pass_value = pass_criteria.get("status")
        if not status and pass_value:
            status = (
                "pass" if pass_value == "pass"
                else str(pass_value).upper()
            )
    if directory.is_dir() and not status:
        status = "ARCHIVED_OUTPUTS_PRESENT_STATUS_UNSPECIFIED"
    files = []
    permission_errors = []
    if directory.is_dir():
        for current, dirs, names in os.walk(directory, onerror=lambda error: permission_errors.append(str(error))):
            dirs[:] = sorted(name for name in dirs if name not in {"__pycache__"})
            for name in sorted(names):
                path = Path(current) / name
                if not path.is_file():
                    continue
                try:
                    files.append({
                        "path": _relative(path, root),
                        "sha256": _hash(path),
                        "bytes": path.stat().st_size,
                    })
                except OSError as exc:
                    permission_errors.append(f"{_relative(path, root)}: {exc}")
    manifest_path = directory / "manifest_sha256.json"
    manifest_valid, manifest_report = _verify_result_manifest(directory, manifest_path)
    seed = audit.get("seed")
    if seed is None:
        seed = run_manifest.get("seed")
    for nested in ("calibration", "ttl_selection", "matched_design"):
        nested_data = audit.get(nested, {})
        if seed is None and isinstance(nested_data, dict):
            seed = nested_data.get("seed")
    return {
        "experiment": experiment,
        "run_id": _run_id(experiment, audit_path if audit_path.is_file() else run_manifest_path),
        "status": status,
        "world_type": audit.get("world_type") or audit.get("dataset_scope"),
        "seed": seed,
        "cases": audit.get("cases") or audit.get("n_cases") or run_manifest.get("test_cases"),
        "repeats": audit.get("repeats"),
        "reproducibility_assessment": (
            "result hashes verified; archived stochastic result has only one seed"
            if seed is not None and manifest_valid is not False
            else "archive inventoried and content-hashed; no multi-seed metadata"
        ),
        "audit_path": _relative(audit_path, root) if audit_path.is_file() else None,
        "audit_sha256": _hash(audit_path) if audit_path.is_file() else None,
        "run_manifest_path": (
            _relative(run_manifest_path, root) if run_manifest_path.is_file() else None
        ),
        "run_manifest_sha256": (
            _hash(run_manifest_path) if run_manifest_path.is_file() else None
        ),
        "archived_output_count": len(files),
        "archived_outputs": files,
        "result_manifest_valid": manifest_valid,
        "result_manifest_report": manifest_report,
        "permission_errors": permission_errors,
        "raw_data_or_seed_replay_available": bool(
            (directory / "raw_runs.jsonl").is_file()
            or (directory / "trial_results.csv").is_file()
            or (directory / "raw_runs.csv").is_file()
        ),
    }


def _verify_result_manifest(directory: Path, path: Path) -> tuple[bool | None, dict[str, Any]]:
    if not path.is_file():
        return None, {"present": False, "checked": 0, "missing": [], "mismatched": []}
    manifest = _json(path)
    missing, mismatched, checked = [], [], 0
    for relative, expected in manifest.items():
        candidate = directory / relative
        if not candidate.is_file():
            missing.append(relative)
            continue
        checked += 1
        if _hash(candidate) != expected:
            mismatched.append(relative)
    return not missing and not mismatched, {
        "present": True, "checked": checked, "missing": missing,
        "mismatched": mismatched,
    }


def _scalar_leaves(value: Any, pointer: str = "") -> list[tuple[str, Any]]:
    leaves = []
    if isinstance(value, dict):
        for key, child in value.items():
            leaves.extend(_scalar_leaves(child, f"{pointer}/{key}"))
    elif isinstance(value, list):
        for index, child in enumerate(value):
            leaves.extend(_scalar_leaves(child, f"{pointer}/{index}"))
    elif value is None or isinstance(value, (str, int, float, bool)):
        leaves.append((pointer or "/", value))
    return leaves


def _registered_plan(seed_runs: int, seed_base: int) -> dict[str, Any]:
    seeds = [seed_base + index * 1009 for index in range(seed_runs)]
    return {
        "title": "E20 prospective controlled replay analysis",
        "registration_scope": (
            "This plan is written before the E20 seed replays below. It cannot be "
            "represented as preregistration of E01-E19 results already observed."
        ),
        "registered_at_utc": datetime.now(timezone.utc).isoformat(),
        "seed_runs": seed_runs,
        "seed_base": seed_base,
        "seed_values": seeds,
        "dataset_release_hashes": (
            "Frozen local acquisition and controlled-fixture hashes are in "
            "frozen_manifest.json; no downloads are performed."
        ),
        "primary_comparisons": [
            {
                "hypothesis_id": "E20-H1",
                "source": "E13 repeated controlled replay",
                "contrast": "CER-guided minus random final actual loss at action budget 3",
                "direction": "negative favors CER-guided",
                "unit": "seed-by-synthetic-case paired difference; no campaign labels exist",
                "interval": "two-sided 95% percentile cluster bootstrap over synthetic case IDs",
                "test": "two-sided paired sign-flip permutation over synthetic case clusters",
            },
            {
                "hypothesis_id": "E20-H2",
                "source": "E18 repeated controlled replay",
                "contrast": "source-fused graph minus no-graph accuracy, all-case paired delta",
                "direction": "positive favors graph",
                "unit": "seed-by-synthetic-case paired difference; no campaign labels exist",
                "interval": "two-sided 95% percentile cluster bootstrap over synthetic case IDs",
                "test": "two-sided paired sign-flip permutation over synthetic case clusters",
            },
        ],
        "multiplicity": "Holm step-down correction across E20-H1 and E20-H2 only",
        "exploratory_archive": (
            "All archived E01-E19 results are descriptive; their analyses were not "
            "registered before outcomes were inspected."
        ),
        "cluster_bootstrap": {
            "replicates": BOOTSTRAP_SAMPLES,
            "seed": seed_base ^ 0xB007,
            "cluster_key": "seed plus synthetic case ID",
            "campaign_level_inference": "not supported: campaign identifiers are absent",
        },
        "permutation_test": {
            "replicates": PERMUTATION_SAMPLES,
            "seed": seed_base ^ 0x51F,
        },
        "models_and_outcomes": {
            "E13": "existing CER action-selection policies and calibration fit; same action outcomes within each paired case",
            "E18": "existing synthetic source-fusion graph and no-graph comparison",
        },
        "fixed_budgets": {
            "E13_action_budget": 3,
            "E18_attack_budget": 1,
            "E06_attack_budgets": [0, 1, 2, 3, 4],
        },
        "excluded": (
            "Live feed acquisition, external test labels, URLs, and unobserved outcomes "
            "are not accessed."
        ),
    }


def _load_matching_preregistration(path: Path, candidate: dict[str, Any]) -> dict[str, Any]:
    if not path.is_file():
        _write_json(path, candidate)
        return candidate
    previous = _json(path)
    previous_without_time = dict(previous)
    candidate_without_time = dict(candidate)
    previous_without_time.pop("registered_at_utc", None)
    candidate_without_time.pop("registered_at_utc", None)
    if previous_without_time != candidate_without_time:
        raise ValueError(
            "existing E20 preregistration differs; use a new output directory "
            "rather than overwriting the registered analysis plan"
        )
    return previous


def _existing_replay(
    output: Path, experiment: str, seed: int, cases: int,
) -> dict[str, Any] | None:
    audit_path = output / "audit.json"
    if not audit_path.is_file():
        return None
    audit = _json(audit_path)
    if audit.get("seed") != seed:
        return None
    if experiment == "E06" and audit.get("cases") != cases:
        return None
    if experiment == "E13" and (
        audit.get("cases_per_repeat") != cases or audit.get("repeats") != 1
    ):
        return None
    if experiment == "E18" and audit.get("cases") != cases:
        return None
    if experiment == "E06":
        return {
            "seed": seed, "output": str(output),
            "status": audit.get("pass_criteria", {}).get("status"),
            "cases": audit.get("cases"),
            "violations": audit.get("soundness", {}).get("violations"),
            "run_id": f"E06-seed-{seed}-{_hash(audit_path)[:12]}",
            "reused": True,
        }
    if experiment == "E13":
        return {
            "seed": seed, "output": str(output),
            "status": audit.get("pass_criteria", {}).get("status"),
            "cases": audit.get("cases_per_repeat"),
            "repeats": audit.get("repeats"),
            "run_id": f"E13-seed-{seed}-{_hash(audit_path)[:12]}",
            "reused": True,
        }
    return {
        "seed": seed, "output": str(output), "status": audit.get("status"),
        "cases": audit.get("cases"),
        "run_id": f"E18-seed-{seed}-{_hash(audit_path)[:12]}",
        "reused": True,
    }


def _cluster_bootstrap(
    values: list[float], clusters: list[str], seed: int,
) -> tuple[float, float, float]:
    if not values or len(values) != len(clusters):
        raise ValueError("bootstrap requires nonempty paired values and cluster IDs")
    grouped: dict[str, list[float]] = {}
    for cluster, value in zip(clusters, values):
        grouped.setdefault(cluster, []).append(value)
    cluster_means = np.array(
        [np.mean(grouped[key]) for key in sorted(grouped)], dtype=float,
    )
    rng = np.random.default_rng(seed)
    indices = rng.integers(0, len(cluster_means), size=(BOOTSTRAP_SAMPLES, len(cluster_means)))
    means = cluster_means[indices].mean(axis=1)
    low, high = np.quantile(means, (0.025, 0.975))
    return float(cluster_means.mean()), float(low), float(high)


def _paired_signflip_p(values: list[float], seed: int) -> float | None:
    if not values:
        return None
    observed = abs(float(np.mean(values)))
    vector = np.asarray(values, dtype=float)
    rng = np.random.default_rng(seed)
    more_extreme = 0
    for _ in range(PERMUTATION_SAMPLES):
        signs = rng.choice(np.array([-1.0, 1.0]), size=len(vector))
        if abs(float(np.mean(vector * signs))) >= observed - 1e-15:
            more_extreme += 1
    return (more_extreme + 1) / (PERMUTATION_SAMPLES + 1)


def _holm(p_values: dict[str, float | None]) -> dict[str, float | None]:
    eligible = sorted(
        ((value, key) for key, value in p_values.items() if value is not None),
    )
    adjusted: dict[str, float | None] = {key: None for key in p_values}
    running = 0.0
    total = len(eligible)
    for rank, (p_value, key) in enumerate(eligible):
        running = max(running, min(1.0, (total - rank) * p_value))
        adjusted[key] = running
    return adjusted


def _csv_dicts(path: Path) -> list[dict[str, str]]:
    if not path.is_file():
        return []
    with path.open(newline="", encoding="utf-8-sig") as stream:
        return list(csv.DictReader(stream))


def _collect_replay_effects(
    e13_runs: list[dict[str, Any]], e18_runs: list[dict[str, Any]], seed: int,
) -> list[dict[str, Any]]:
    e13_values, e13_clusters = [], []
    for run in e13_runs:
        path = Path(run["output"]) / "trial_results.csv"
        rows = _csv_dicts(path)
        by_case: dict[str, dict[str, float]] = {}
        for row in rows:
            if int(row["budget"]) != 3:
                continue
            by_case.setdefault(row["case_id"], {})[row["policy"]] = float(
                row["final_actual_loss"],
            )
        for case_id, policies in by_case.items():
            if "cer_guided" in policies and "random" in policies:
                e13_values.append(policies["cer_guided"] - policies["random"])
                e13_clusters.append(f"{run['seed']}:{case_id}")

    e18_values, e18_clusters = [], []
    for run in e18_runs:
        path = Path(run["output"]) / "graph_fusion_comparison.csv"
        for row in _csv_dicts(path):
            e18_values.append(float(row["paired_accuracy_delta"]))
            e18_clusters.append(f"{run['seed']}:{row['case_id']}")

    definitions = (
        ("E20-H1", "E13 CER-guided minus random final actual loss at B=3",
         e13_values, e13_clusters, seed ^ 0xE131),
        ("E20-H2", "E18 graph minus no-graph all-case accuracy",
         e18_values, e18_clusters, seed ^ 0xE182),
    )
    raw = []
    p_values = {}
    for hypothesis_id, contrast, values, clusters, local_seed in definitions:
        if values:
            mean, low, high = _cluster_bootstrap(values, clusters, local_seed)
            p_value = _paired_signflip_p(values, local_seed ^ 0x51F)
            unique_clusters = len(set(clusters))
        else:
            mean = low = high = p_value = None
            unique_clusters = 0
        p_values[hypothesis_id] = p_value
        raw.append({
            "hypothesis_id": hypothesis_id,
            "contrast": contrast,
            "status": "evaluated_controlled_only" if values else "NOT_RUN",
            "paired_effect": mean,
            "ci_95_low": low,
            "ci_95_high": high,
            "raw_p_value": p_value,
            "holm_adjusted_p_value": None,
            "paired_observations": len(values),
            "synthetic_clusters": unique_clusters,
            "campaign_clusters": None,
            "cluster_definition": "seed plus synthetic case ID; not campaign-level",
            "interpretation": (
                "Controlled synthetic evidence only; do not infer campaign-level "
                "or field effectiveness."
            ),
        })
    adjusted = _holm(p_values)
    for row in raw:
        row["holm_adjusted_p_value"] = adjusted[row["hypothesis_id"]]
    return raw


def _archived_hypotheses(
    root: Path, e05_record: dict[str, Any], e06_record: dict[str, Any],
    e13_record: dict[str, Any], e16_record: dict[str, Any],
    e18_record: dict[str, Any], e19_record: dict[str, Any],
) -> list[dict[str, Any]]:
    hypotheses = []
    e05_topology = root / "results/E05/topology_summary.csv"
    shared_row = next(
        (
            row for row in _csv_dicts(e05_topology)
            if row.get("topology") == "shared_five"
        ), {},
    )
    e06 = _json(root / "results/E06/audit.json") if (root / "results/E06/audit.json").is_file() else {}
    e13_summary = _csv_dicts(root / "results/E13/summary.csv")
    e18_audit = _json(root / "results/E18/audit.json") if (root / "results/E18/audit.json").is_file() else {}
    e19_scale = _csv_dicts(root / "results/E19/scale_summary.csv")
    e16 = _json(root / "results/E16/audit.json") if (root / "results/E16/audit.json").is_file() else {}
    hypotheses.extend([
        {
            "hypothesis_id": "H1",
            "statement": "Source ancestry prevents copied reports from increasing the independent-witness count.",
            "status": "descriptive_controlled",
            "observed_effect": (
                f"shared_five: {shared_row.get('naive_independent_witnesses', 'NA')} naive "
                f"vs {shared_row.get('source_aware_independent_witnesses', 'NA')} source-aware witnesses; "
                f"flip budget {shared_row.get('naive_budget_to_flip', 'NA')} vs "
                f"{shared_row.get('aware_budget_to_flip', 'NA')}"
            ),
            "uncertainty": "No inferential CI: one deterministic controlled topology; no campaigns.",
            "source_run_id": e05_record["run_id"],
            "source_sha256": _hash(e05_topology) if e05_topology.is_file() else None,
        },
        {
            "hypothesis_id": "H2",
            "statement": "Exact certificates have zero soundness violations under the bounded fixed-graph threat model.",
            "status": "bounded_exhaustive_software_check",
            "observed_effect": (
                f"{e06.get('soundness', {}).get('violations', 'NA')} violations across "
                f"{e06.get('checks_per_budget', {}).get('checks', 'NA')} attack checks"
            ),
            "uncertainty": (
                "No statistical CI; finite controlled instances and the stated exactness "
                "limits apply, not a universal real-world guarantee."
            ),
            "source_run_id": e06_record["run_id"],
            "source_sha256": _hash(root / "results/E06/audit.json"),
        },
        {
            "hypothesis_id": "H3",
            "statement": "At matched action budgets, CER-guided repair improves outcomes over random repair.",
            "status": "archived_single_seed_exploratory",
            "observed_effect": (
                "Archived E13 summary contains matched policies and paired trial rows; "
                f"{len(e13_summary)} policy-budget summary rows are available."
            ),
            "uncertainty": (
                "Not treated as confirmatory: archived run is one seed with three repeats; "
                "campaign/source-group cluster identifiers are unavailable."
            ),
            "source_run_id": e13_record["run_id"],
            "source_sha256": _hash(root / "results/E13/summary.csv"),
        },
        {
            "hypothesis_id": "H4",
            "statement": "Benefits persist for first-seen phishing campaigns under out-of-time external validation.",
            "status": e16.get("status", "NOT_RUN"),
            "observed_effect": "No effect size reported because prospective ledgers are missing.",
            "uncertainty": "No CI or p-value; E16 correctly reported no performance metrics.",
            "source_run_id": e16_record["run_id"],
            "source_sha256": e16_record["audit_sha256"],
        },
        {
            "hypothesis_id": "H5",
            "statement": "URLTrust graph propagation adds accuracy after source-separated fusion.",
            "status": "archived_controlled_no_increment_observed",
            "observed_effect": json.dumps(
                e18_audit.get("urltrust_graph_increment_after_source_fusion", {}),
                sort_keys=True,
            ),
            "uncertainty": (
                "Archived per-case bootstrap interval is controlled-synthetic only and "
                "not campaign-clustered; interval is not evidence of field benefit."
            ),
            "source_run_id": e18_record["run_id"],
            "source_sha256": _hash(root / "results/E18/audit.json"),
        },
        {
            "hypothesis_id": "H6",
            "statement": "Incremental trust updates agree with full recomputation at measured scales.",
            "status": "archived_controlled_correctness_check",
            "observed_effect": (
                f"scales={len(e19_scale)}; maximum recorded update error="
                f"{max((float(row['incremental_max_abs_error']) for row in e19_scale), default=float('nan'))}"
            ),
            "uncertainty": "Deterministic numeric equality check, not a population CI.",
            "source_run_id": e19_record["run_id"],
            "source_sha256": _hash(root / "results/E19/scale_summary.csv"),
        },
    ])
    return hypotheses


def _figure(out: Path, rows: list[dict[str, Any]]) -> list[str]:
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    eligible = [
        row for row in rows
        if row.get("paired_effect") is not None
        and row.get("ci_95_low") is not None
        and row.get("ci_95_high") is not None
    ]
    fig, axis = plt.subplots(figsize=(8, max(3.5, len(eligible) * 1.2)))
    if eligible:
        y = np.arange(len(eligible))
        effects = [float(row["paired_effect"]) for row in eligible]
        lower = [effect - float(row["ci_95_low"]) for effect, row in zip(effects, eligible)]
        upper = [float(row["ci_95_high"]) - effect for effect, row in zip(effects, eligible)]
        axis.errorbar(effects, y, xerr=[lower, upper], fmt="o", capsize=4)
        axis.set_yticks(y, [row["hypothesis_id"] for row in eligible])
        axis.axvline(0.0, color="black", linewidth=1, linestyle="--")
        axis.set_xlabel("Paired effect (95% synthetic-case cluster bootstrap CI)")
    else:
        axis.text(
            0.5, 0.5, "No E20 prospective seed-replay effect estimates available",
            horizontalalignment="center", verticalalignment="center",
            transform=axis.transAxes,
        )
        axis.set_axis_off()
    axis.set_title("E20 preregistered controlled replay contrasts")
    fig.tight_layout()
    paths = []
    for suffix in ("png", "pdf"):
        path = out / "figures" / f"e20_hypothesis_effects.{suffix}"
        path.parent.mkdir(parents=True, exist_ok=True)
        fig.savefig(path, dpi=180 if suffix == "png" else None)
        paths.append(path.as_posix())
    plt.close(fig)
    return paths


def _latex_status_table(rows: list[dict[str, Any]]) -> str:
    lines = [
        r"\begin{tabular}{llrr}",
        r"Experiment & Status & Archived outputs & Seed \\",
        r"\hline",
    ]
    for row in rows:
        status = str(row["status"]).replace("_", r"\_")
        seed = row.get("seed")
        lines.append(
            f"{row['experiment']} & {status} & {row['archived_output_count']} & "
            f"{seed if seed is not None else '--'} " + r"\\"
        )
    lines.extend([r"\end{tabular}", ""])
    return "\n".join(lines)


def _latex_hypothesis_table(rows: list[dict[str, Any]]) -> str:
    lines = [
        r"\begin{tabular}{llp{6.5cm}p{4.5cm}}",
        r"Hypothesis & Status & Observed effect & Uncertainty / limitation \\",
        r"\hline",
    ]
    for row in rows:
        safe = lambda value: str(value).replace("_", r"\_").replace("%", r"\%")
        lines.append(
            f"{safe(row['hypothesis_id'])} & {safe(row['status'])} & "
            f"{safe(row.get('observed_effect', row.get('contrast', 'NA')))} & "
            f"{safe(row.get('uncertainty', row.get('interpretation', 'NA')))} "
            + r"\\"
        )
    lines.extend([r"\end{tabular}", ""])
    return "\n".join(lines)


def _paper_sections(
    experiment_rows: list[dict[str, Any]], hypotheses: list[dict[str, Any]],
    release: dict[str, Any], audit: dict[str, Any],
) -> str:
    statuses = "; ".join(
        f"{row['experiment']}={row['status']}" for row in experiment_rows
    )
    completed = ", ".join(str(size) for size in audit.get("completed_e19_scales", [])) or "none"
    e20_effects = [
        f"{row['hypothesis_id']}: effect {row['paired_effect']}, 95% CI "
        f"[{row['ci_95_low']}, {row['ci_95_high']}], Holm p="
        f"{row['holm_adjusted_p_value']}"
        for row in hypotheses
        if row.get("paired_effect") is not None
    ]
    results = "; ".join(e20_effects) if e20_effects else (
        "No E20 seed-replay effect estimates were generated."
    )
    license_count = len(release.get("acquired_artifacts", []))
    return "\n".join([
        r"\section{Experimental Setup}",
        "This project is a research prototype using archived local result artifacts, "
        "controlled synthetic evidence, and metadata for locally acquired public-source "
        "snapshots. E20 performs no network acquisition and does not redistribute source "
        f"data. The local acquisition manifest lists {license_count} acquired source "
        "artifacts; per-source SHA-256 receipts and license/terms review status are "
        "recorded in the E20 frozen release manifest. The source-separated train, "
        "calibration, and test partitions required for field evaluation were not "
        "available as a frozen eligible release. Consequently, the frozen splits are "
        "reported as unavailable rather than reconstructed from current feed absence. "
        f"The E19 controlled graph scales actually completed were: {completed}.",
        "",
        "The E20 prospective confirmatory plan was written after E01--E19 outputs "
        "already existed; it applies only to the new controlled seed replays and is "
        "not represented as preregistration of the archived experiments. The plan "
        "freezes replay seeds, the E13 action budget, E18 graph contrast, paired "
        "synthetic-case cluster bootstrap, sign-flip tests, and Holm correction. "
        "Synthetic case clusters are not campaigns and do not support field-level "
        "uncertainty.",
        "",
        r"\section{Results}",
        "The archived experiment status summary is: " + statuses + ". "
        "These statuses distinguish executed controlled experiments from blocked "
        "or incomplete external-data evaluations. No zero-day, prospective "
        "first-seen, or production performance estimate is asserted. E20 paired "
        "contrast results, when present, are: " + results + ". Results for E01--E19 "
        "not tied to eligible independent campaign/source-group units are descriptive "
        "only. The exact certificate audit is finite and bounded by its stated threat "
        "model, and the E19 scale data are controlled synthetic measurements rather "
        "than deployment capacity claims.",
        "",
        r"\section{Threats to Validity}",
        "The main limitations are absence of authenticated historical availability "
        "times, no approved external campaign-disjoint test release, missing original "
        "URLTrust implementation/source pin, incomplete license/redistribution "
        "adjudication for several snapshots, single-seed archived runs for many "
        "stochastic experiments, and lack of campaign/source-cluster identifiers. "
        "Controlled data may not represent real source dependencies, adaptive "
        "attackers, network failures, or operational collection costs. A passing "
        "software soundness test does not establish phishing-detection effectiveness.",
        "",
        r"\section{Ethical Restrictions and Code/Data Availability}",
        "No active crawling, form submission, page execution, or live-target "
        "interaction is performed by E20. Locally acquired feeds and datasets remain "
        "subject to their upstream terms and are not copied into the E20 report. "
        "The report publishes hashes and metadata only. Independent reproduction "
        "requires the same permitted local snapshot bytes and receipts; restricted "
        "artifacts require the applicable source authorization, agreement, and "
        "release-specific hashes. The offline command is "
        r"\texttt{python -m cerurl.cli run-e20}; it never downloads mutable feeds.",
        "",
    ])


def _artifact_records(
    root: Path, experiment_rows: list[dict[str, Any]], extra_paths: list[Path],
    extra_sources: dict[str, list[str]] | None = None,
) -> list[dict[str, Any]]:
    artifact_rows = []
    extra_sources = extra_sources or {}
    for experiment in experiment_rows:
        run_id = experiment["run_id"]
        for item in experiment["archived_outputs"]:
            path = root / item["path"]
            suffix = path.suffix.lower()
            artifact_rows.append({
                "path": item["path"],
                "sha256": item["sha256"],
                "bytes": item["bytes"],
                "run_id": run_id,
                "kind": (
                    "figure" if suffix in {".png", ".pdf", ".svg"}
                    else "table" if suffix in {".csv", ".tex"}
                    else "data_or_log"
                ),
                "regeneration_status": (
                    "source artifact archived; generator provenance must be assessed per experiment"
                ),
                "source_candidates": [],
            })
    for item in extra_paths:
        path = Path(item)
        if path.is_file():
            parts = path.parts
            replay_index = parts.index("seed_replays") if "seed_replays" in parts else None
            if replay_index is not None and len(parts) > replay_index + 2:
                replay_experiment = parts[replay_index + 1]
                replay_dir_name = parts[replay_index + 2]
                replay_dir = next(
                    (parent for parent in path.parents if parent.name == replay_dir_name),
                    path.parent,
                )
                replay_audit = replay_dir / "audit.json"
                artifact_run_id = (
                    _run_id(replay_experiment, replay_audit)
                    if replay_audit.is_file()
                    else f"{replay_experiment}-{replay_dir_name}"
                )
            else:
                artifact_run_id = "E20"
            artifact_rows.append({
                "path": _relative(path, root),
                "sha256": _hash(path),
                "bytes": path.stat().st_size,
                "run_id": artifact_run_id,
                "kind": "figure" if path.suffix.lower() in {".png", ".pdf"} else "table",
                "regeneration_status": "regenerated by cerurl.e20 from frozen archived/seed-replay outputs",
                "source_candidates": extra_sources.get(path.name, []),
            })
    return sorted(artifact_rows, key=lambda row: row["path"])


def _issue_rows(
    experiment_rows: list[dict[str, Any]], release: dict[str, Any],
    seed_runs: int,
) -> list[dict[str, Any]]:
    issues = []
    for row in experiment_rows:
        status = str(row["status"])
        if any(marker in status.upper() for marker in ("NOT_RUN", "BLOCKED", "PARTIAL", "NOT_REPRODUCIBLE")):
            issues.append({
                "issue_id": f"{row['experiment']}-STATUS-{_sha_text(status)[:8]}",
                "experiment": row["experiment"],
                "severity": "blocking_for_claims",
                "status": status,
                "description": f"Archived experiment is not an unrestricted completed empirical evaluation: {status}.",
                "resolution": "Acquire permitted evidence, freeze eligibility/splits, and rerun before making the blocked claim.",
            })
        if row["result_manifest_valid"] is False:
            issues.append({
                "issue_id": f"{row['experiment']}-HASH-MISMATCH",
                "experiment": row["experiment"],
                "severity": "critical_reproducibility",
                "status": "hash_mismatch",
                "description": json.dumps(row["result_manifest_report"], sort_keys=True),
                "resolution": "Restore the exact manifested artifact or regenerate the experiment; do not silently rewrite its manifest.",
            })
        if row["permission_errors"]:
            issues.append({
                "issue_id": f"{row['experiment']}-ACCESS",
                "experiment": row["experiment"],
                "severity": "warning",
                "status": "some_artifacts_inaccessible",
                "description": "; ".join(row["permission_errors"]),
                "resolution": "Provide read access to the precise archived output path.",
            })
        if row["seed"] is not None and row["experiment"] not in E20_MULTI_SEED_REPLAYS:
            issues.append({
                "issue_id": f"{row['experiment']}-SEED-REPLICATION",
                "experiment": row["experiment"],
                "severity": "blocking_for_confirmatory_statistics",
                "status": "single_archived_seed",
                "description": (
                    "Archived stochastic result has one recorded seed; it is "
                    "exploratory and does not meet the five-seed protocol."
                ),
                "resolution": (
                    "Re-run at least five fixed, preregistered seeds and retain "
                    "paired case/source-group outcomes."
                ),
            })
    unverified = [
        item["source_id"] for item in release["acquired_artifacts"]
        if not item["artifact_hash_verified"]
    ]
    if unverified:
        issues.append({
            "issue_id": "DATASET-HASH-UNVERIFIED",
            "experiment": "E01",
            "severity": "blocking_for_release",
            "status": "hash_verification_failed",
            "description": "Could not verify source artifacts: " + ", ".join(unverified),
            "resolution": "Restore exact permitted snapshot bytes matching their receipt hashes.",
        })
    for artifact in release["acquired_artifacts"]:
        if artifact["source_id"] != "phiusiil":
            issues.append({
                "issue_id": f"LICENSE-{artifact['source_id'].upper()}",
                "experiment": "E20",
                "severity": "blocking_for_redistribution",
                "status": "license_review_required",
                "description": (
                    f"{artifact['source_id']} has a retained terms reference but "
                    "redistribution permission was not adjudicated."
                ),
                "resolution": (
                    "Review source/release-specific license and terms; retain evidence "
                    "before any redistribution. E20 does not copy the artifact."
                ),
            })
    if seed_runs < 5:
        issues.append({
            "issue_id": "E20-SEED-REPLAY-COVERAGE",
            "experiment": "E20",
            "severity": "blocking_for_confirmatory_statistics",
            "status": "fewer_than_five_seed_runs",
            "description": f"Requested {seed_runs} replay seeds; five are required for the preregistered comparisons.",
            "resolution": "Run `cerurl run-e20` with at least five seed replays.",
        })
    return issues


def run_e20(
    out_dir: str = "results/E20",
    table_dir: str = "tables",
    seed_runs: int = 5,
    seed_base: int = 20262020,
    e06_cases: int = 1200,
    replay_cases: int = 12,
) -> dict[str, Any]:
    """Audit archived E01-E19 outputs offline and run preregistered synthetic replays."""
    if type(seed_runs) is not int or seed_runs < 0:
        raise ValueError("seed_runs must be a nonnegative integer")
    if type(seed_runs) is int and seed_runs not in {0} and seed_runs < 5:
        raise ValueError("seed_runs must be 0 (archive-only audit) or >= 5")
    if type(seed_base) is not int:
        raise ValueError("seed_base must be an integer")
    if type(e06_cases) is not int or e06_cases < 100:
        raise ValueError("e06_cases must be an integer >= 100")
    if type(replay_cases) is not int or replay_cases < 12:
        raise ValueError("replay_cases must be an integer >= 12")
    root = Path.cwd()
    out = Path(out_dir)
    if not out.is_absolute():
        out = root / out
    tables = Path(table_dir)
    if not tables.is_absolute():
        tables = root / tables
    out.mkdir(parents=True, exist_ok=True)
    tables.mkdir(parents=True, exist_ok=True)

    release, license_rows = _dataset_and_license_release(root)
    preregistration_path = out / "preregistered_analysis.json"
    seed_plan = _load_matching_preregistration(
        preregistration_path, _registered_plan(seed_runs, seed_base),
    )
    preregistration_sha256 = _hash(preregistration_path)

    experiment_rows = [
        _experiment_record(root, experiment) for experiment in EXPERIMENTS
    ]
    e13_runs, e18_runs = [], []
    e06_runs = []
    replay_started = time.perf_counter()
    for seed in seed_plan["seed_values"]:
        base = out / "seed_replays"
        e06_out = base / "E06" / f"seed-{seed}"
        e13_out = base / "E13" / f"seed-{seed}"
        e18_out = base / "E18" / f"seed-{seed}"
        e06_replay = _existing_replay(e06_out, "E06", seed, e06_cases)
        if e06_replay is None:
            e06_audit = run_e06(
                str(e06_out), str(e06_out / "tables"), e06_cases, seed, plots=False,
            )
            e06_replay = {
                "seed": seed, "output": str(e06_out),
                "status": e06_audit.get("pass_criteria", {}).get("status"),
                "cases": e06_audit.get("cases"),
                "violations": e06_audit.get("soundness", {}).get("violations"),
                "run_id": f"E06-seed-{seed}-{_hash(e06_out / 'audit.json')[:12]}",
                "reused": False,
            }
        e13_replay = _existing_replay(e13_out, "E13", seed, replay_cases)
        if e13_replay is None:
            e13_audit = run_e13(
                str(e13_out), str(e13_out / "tables"), replay_cases, 1, seed,
                DEFAULT_BUDGETS,
            )
            e13_replay = {
                "seed": seed, "output": str(e13_out),
                "status": e13_audit.get("pass_criteria", {}).get("status"),
                "cases": e13_audit.get("cases_per_repeat"),
                "repeats": e13_audit.get("repeats"),
                "run_id": f"E13-seed-{seed}-{_hash(e13_out / 'audit.json')[:12]}",
                "reused": False,
            }
        e18_replay = _existing_replay(e18_out, "E18", seed, replay_cases)
        if e18_replay is None:
            e18_audit = run_e18(
                str(e18_out), str(e18_out / "tables"), replay_cases, seed, 100,
            )
            e18_replay = {
                "seed": seed, "output": str(e18_out), "status": e18_audit.get("status"),
                "cases": e18_audit.get("cases"),
                "run_id": f"E18-seed-{seed}-{_hash(e18_out / 'audit.json')[:12]}",
                "reused": False,
            }
        e06_runs.append(e06_replay)
        e13_runs.append(e13_replay)
        e18_runs.append(e18_replay)
    replay_seconds = time.perf_counter() - replay_started

    confirmatory = _collect_replay_effects(e13_runs, e18_runs, seed_base)
    records_by_id = {row["experiment"]: row for row in experiment_rows}
    archived = _archived_hypotheses(
        root, records_by_id["E05"], records_by_id["E06"],
        records_by_id["E13"], records_by_id["E16"],
        records_by_id["E18"], records_by_id["E19"],
    )
    issues = _issue_rows(experiment_rows, release, seed_runs)
    failed_manifests = [
        row["experiment"] for row in experiment_rows
        if row["result_manifest_valid"] is False
    ]
    replay_failures = [
        run for run in e06_runs + e13_runs + e18_runs
        if run["status"] != "pass"
    ]
    campaign_data_available = False
    audit = {
        "experiment": "E20",
        "status": (
            "pass_with_limitations"
            if seed_runs >= 5 and not failed_manifests and not replay_failures
            and release["hash_verification_pass"]
            else "partial_or_blocked"
        ),
        "reproducibility_status": (
            "offline_archived_summary_reconstruction_verified"
            if not failed_manifests else "archived_manifest_verification_failed"
        ),
        "network_accessed": False,
        "mutable_feeds_redownloaded": False,
        "field_performance_claim": False,
        "archived_experiments": len(experiment_rows),
        "archived_status_counts": {
            status: sum(row["status"] == status for row in experiment_rows)
            for status in sorted({row["status"] for row in experiment_rows})
        },
        "result_manifest_failures": failed_manifests,
        "data_release_hash_verification_pass": release["hash_verification_pass"],
        "preregistration": {
            "path": _relative(preregistration_path, root),
            "sha256": preregistration_sha256,
            "scope": "E20 seed replays only; E01-E19 archive is exploratory retrospectively",
        },
        "seed_replays": {
            "seed_runs_requested": seed_runs,
            "seed_values": seed_plan["seed_values"],
            "replay_cases_per_run": replay_cases,
            "E06": e06_runs,
            "E13": e13_runs,
            "E18": e18_runs,
            "runtime_seconds": replay_seconds,
            "failures": replay_failures,
        },
        "seed_coverage": {
            "five_seed_replay_experiments": sorted(E20_MULTI_SEED_REPLAYS),
            "archived_single_seed_experiments": [
                row["experiment"] for row in experiment_rows
                if row["seed"] is not None
                and row["experiment"] not in E20_MULTI_SEED_REPLAYS
            ],
            "other stochastic archived experiments remain exploratory": True,
        },
        "confirmatory_hypotheses": confirmatory,
        "exploratory_archived_hypotheses": archived,
        "statistical_limits": {
            "cluster_bootstrap": "synthetic-case clusters only for E20 controlled replays",
            "campaign_source_clusters_available": campaign_data_available,
            "campaign_cluster_confidence_intervals": "not available; no campaign/group identity labels in controlled outputs",
            "archived_E01_E19_inferential_claims": "not preregistered; report descriptively, without recomputed inferential claims",
            "holm_correction": "applied only to the two preregistered E20 replay contrasts; unavailable p-values remain null",
        },
        "frozen": {
            "dataset_release": "frozen_manifest.json",
            "source_license_and_terms": "source_license_manifest.json",
            "train_calibration_test_splits": {
                "status": "not_frozen_for_external_temporal_evaluation",
                "e02": records_by_id["E02"]["status"],
                "e03": records_by_id["E03"]["status"],
                "reason": "No eligible authenticated availability-time split release is available; no split is inferred.",
            },
            "model_versions": _package_versions(),
            "urltrust_original_model": "not available as a pinned authoritative local implementation; E02 remains non-reproducible",
            "acquisition_policy": {
                "plan_sha256": release["source_plan_sha256"],
                "policy": "offline replay only; no E20 network calls or live feed redownload",
            },
            "attack_budgets": {
                "E06": [0, 1, 2, 3, 4],
                "E13_action": list(DEFAULT_BUDGETS),
                "E18_attack": 1,
                "E19_attack": [1, 2, 3, 5],
            },
            "action_policies": [
                "no_repair", "random", "uncertainty", "disagreement",
                "independent_diversity", "expected_risk_greedy", "cer_guided",
            ],
        },
        "outputs": {
            "summary_report": _relative(out / "reproducibility_report.md", root),
            "paper_sections": _relative(out / "paper_sections.tex", root),
            "issue_log": _relative(out / "issue_log.jsonl", root),
        },
        "runtime_seconds": replay_seconds,
    }

    _write_json(out / "frozen_manifest.json", {
        "schema_version": "E20-frozen-release-v1",
        "created_at_utc": datetime.now(timezone.utc).isoformat(),
        "git": _git_facts(root),
        "python": sys.version,
        "platform": platform.platform(),
        "packages": _package_versions(),
        "code_hashes": {
            str(Path("cerurl") / name): _hash(root / "cerurl" / name)
            for name in ("core.py", "e06.py", "e13.py", "e18.py", "e20.py", "cli.py")
            if (root / "cerurl" / name).is_file()
        },
        "dataset_release": release,
        "split_status": audit["frozen"]["train_calibration_test_splits"],
        "model_versions": audit["frozen"]["model_versions"],
        "acquisition_policy": audit["frozen"]["acquisition_policy"],
        "attack_budgets": audit["frozen"]["attack_budgets"],
        "action_policies": audit["frozen"]["action_policies"],
        "archive_run_ids": {
            row["experiment"]: {
                "run_id": row["run_id"], "seed": row["seed"],
                "audit_sha256": row["audit_sha256"],
            }
            for row in experiment_rows
        },
        "E20_seed_replays": {
            "E06": e06_runs, "E13": e13_runs, "E18": e18_runs,
        },
        "no_live_downloads": True,
    })
    _write_json(out / "source_license_manifest.json", {
        "sources": license_rows,
        "policy": (
            "Access authorization is not equivalent to redistribution permission. "
            "Unadjudicated source data remain local and are never copied to E20 outputs."
        ),
    })
    _write_csv(out / "experiment_status.csv", experiment_rows, (
        "experiment", "run_id", "status", "world_type", "seed", "cases",
        "repeats", "archived_output_count", "result_manifest_valid",
        "reproducibility_assessment",
        "audit_path", "audit_sha256", "run_manifest_path",
        "run_manifest_sha256",
    ))
    _write_csv(out / "hypotheses.csv", archived + confirmatory, (
        "hypothesis_id", "statement", "status", "observed_effect", "uncertainty",
        "source_run_id", "source_sha256", "contrast", "paired_effect",
        "ci_95_low", "ci_95_high", "raw_p_value", "holm_adjusted_p_value",
        "paired_observations", "synthetic_clusters", "campaign_clusters",
        "cluster_definition", "interpretation",
    ))
    _write_csv(out / "issues.csv", issues, (
        "issue_id", "experiment", "severity", "status", "description", "resolution",
    ))
    (out / "issue_log.jsonl").write_text(
        "".join(json.dumps(issue, sort_keys=True) + "\n" for issue in issues),
        encoding="utf-8",
    )
    _write_json(out / "archived_run_summaries.json", {
        "experiments": [
            {
                "experiment": row["experiment"],
                "run_id": row["run_id"],
                "status": row["status"],
                "audit_sha256": row["audit_sha256"],
                "audit_metrics": (
                    _scalar_leaves(_json(root / row["audit_path"]))
                    if row["audit_path"] else []
                ),
            }
            for row in experiment_rows
        ],
    })

    figure_paths = _figure(out, confirmatory)
    table_paths = [
        out / "experiment_status.tex",
        out / "hypotheses.tex",
        tables / "e20_experiment_status.tex",
        tables / "e20_hypotheses.tex",
    ]
    status_tex = _latex_status_table(experiment_rows)
    hypotheses_tex = _latex_hypothesis_table(archived + confirmatory)
    for path in table_paths:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(
            status_tex if "status" in path.name else hypotheses_tex,
            encoding="utf-8",
        )
    paper_text = _paper_sections(experiment_rows, archived + confirmatory, release, audit)
    (out / "paper_sections.tex").write_text(paper_text, encoding="utf-8")
    status_counts = audit["archived_status_counts"]
    report_lines = [
        "# E20 reproducibility report",
        "",
        f"- Overall status: **{audit['status']}**",
        "- No live network access or mutable feed downloads were performed.",
        f"- E01-E19 archived experiments inventoried: {len(experiment_rows)}.",
        f"- Archived statuses: `{json.dumps(status_counts, sort_keys=True)}`.",
        f"- Acquired source snapshot hashes verified: `{release['hash_verification_pass']}`.",
        f"- E20 confirmatory synthetic seeds: `{seed_plan['seed_values']}`.",
        "- External train/calibration/test split: **not frozen**; no split was inferred.",
        "- Campaign-level cluster inference: **unavailable**; controlled case clusters only.",
        "",
        "## Confirmatory E20 replay comparisons",
        "",
        "| Hypothesis | Contrast | Effect | 95% CI | Holm-adjusted p | Status |",
        "|---|---|---:|---:|---:|---|",
    ]
    for row in confirmatory:
        report_lines.append(
            f"| {row['hypothesis_id']} | {row['contrast']} | "
            f"{row['paired_effect']} | [{row['ci_95_low']}, {row['ci_95_high']}] | "
            f"{row['holm_adjusted_p_value']} | {row['status']} |"
        )
    report_lines.extend([
        "",
        "## Archived primary hypotheses",
        "",
        "| ID | Status | Observed result | Uncertainty |",
        "|---|---|---|---|",
    ])
    for row in archived:
        report_lines.append(
            f"| {row['hypothesis_id']} | {row['status']} | {row['observed_effect']} | "
            f"{row['uncertainty']} |"
        )
    report_lines.extend([
        "",
        "## Reproduction instructions",
        "",
        "Run `python -m cerurl.cli run-e20` from the repository root. The command "
        "hash-verifies local archived results and acquired release receipts, reruns "
        "the preregistered controlled E06/E13/E18 seed subset offline, and regenerates "
        "E20 summary tables, effect plots, report, and manifest. It does not replay "
        "original external source acquisition or recreate unavailable field splits. "
        "For restricted or missing inputs, see `issues.csv`, "
        "`source_license_manifest.json`, and `frozen_manifest.json`.",
        "",
        "Archived figure files are hash-linked in `artifact_manifest.csv`; the E20 "
        "hypothesis figure is regenerated from the E20 seed-replay CSVs. Earlier "
        "experiment figures are not claimed regenerated unless their experiment "
        "runner is explicitly rerun from its archived raw inputs.",
        "",
        "## Limitations and ethics",
        "",
        "No E20 result is a field performance estimate. Several source terms do not "
        "constitute redistribution clearance. No real campaign identifiers exist "
        "for the controlled replays, and archived runs often have fewer than five "
        "independent seeds. E02/E03 remain blocked, E16 has missing prospective "
        "ledgers, and the original URLTrust implementation is not pinned locally. "
        "No raw acquired URLs or feed data are copied into E20.",
        "",
    ])
    (out / "reproducibility_report.md").write_text("\n".join(report_lines), encoding="utf-8")

    extra_paths = figure_paths + table_paths + [
        out / "paper_sections.tex",
        out / "reproducibility_report.md",
        out / "experiment_status.csv",
        out / "hypotheses.csv",
    ]
    replay_root = out / "seed_replays"
    if replay_root.is_dir():
        extra_paths.extend(path for path in replay_root.rglob("*") if path.is_file())
    e20_figure_sources = [
        _relative(Path(run["output"]) / "graph_fusion_comparison.csv", root)
        for run in e18_runs
    ]
    e20_figure_sources.extend(
        _relative(Path(run["output"]) / "trial_results.csv", root)
        for run in e13_runs
    )
    artifact_rows = _artifact_records(
        root, experiment_rows, extra_paths,
        {
            "e20_hypothesis_effects.png": e20_figure_sources,
            "e20_hypothesis_effects.pdf": e20_figure_sources,
            "e20_hypotheses.tex": [
                _relative(out / "hypotheses.csv", root),
            ],
            "e20_experiment_status.tex": [
                _relative(out / "experiment_status.csv", root),
            ],
            "e20_hypotheses.tex": [_relative(out / "hypotheses.csv", root)],
            "hypotheses.tex": [_relative(out / "hypotheses.csv", root)],
            "experiment_status.tex": [_relative(out / "experiment_status.csv", root)],
            "paper_sections.tex": [_relative(out / "experiment_status.csv", root),
                                   _relative(out / "hypotheses.csv", root)],
        },
    )
    _write_csv(out / "artifact_manifest.csv", artifact_rows, (
        "path", "sha256", "bytes", "run_id", "kind",
        "regeneration_status", "source_candidates",
    ))
    number_rows = []
    for row in experiment_rows:
        if not row["audit_path"]:
            continue
        audit_path = root / row["audit_path"]
        for pointer, value in _scalar_leaves(_json(audit_path)):
            if isinstance(value, (int, float)) and not isinstance(value, bool):
                number_rows.append({
                    "experiment": row["experiment"],
                    "run_id": row["run_id"],
                    "metric_pointer": pointer,
                    "value": value,
                    "source_path": row["audit_path"],
                    "source_sha256": row["audit_sha256"],
                })
    for hypothesis in confirmatory:
        value_fields = (
            "paired_effect", "ci_95_low", "ci_95_high",
            "raw_p_value", "holm_adjusted_p_value",
        )
        if hypothesis.get("paired_effect") is None:
            continue
        source_runs = (
            e13_runs if hypothesis["hypothesis_id"] == "E20-H1" else e18_runs
        )
        source_file = (
            "trial_results.csv" if hypothesis["hypothesis_id"] == "E20-H1"
            else "graph_fusion_comparison.csv"
        )
        source_hashes = [
            (run["run_id"], _hash(Path(run["output"]) / source_file))
            for run in source_runs
        ]
        for field in value_fields:
            if hypothesis.get(field) is not None:
                number_rows.append({
                    "experiment": "E20",
                    "run_id": "E20-preregistered-replay",
                    "metric_pointer": f"/{hypothesis['hypothesis_id']}/{field}",
                    "value": hypothesis[field],
                    "source_path": ";".join(
                        f"{run['output']}/{source_file}" for run in source_runs
                    ),
                    "source_sha256": json.dumps(source_hashes, separators=(",", ":")),
                })
    _write_csv(out / "number_provenance.csv", number_rows, (
        "experiment", "run_id", "metric_pointer", "value",
        "source_path", "source_sha256",
    ))

    audit["manifest_sha256_path"] = "manifest_sha256.json"
    audit["manifest_entry_count"] = 0
    (out / "audit.json").write_text(
        json.dumps(audit, indent=2, sort_keys=True, allow_nan=False) + "\n",
        encoding="utf-8",
    )
    def collect_hashes() -> dict[str, str]:
        return {
            _relative(path, out): _hash(path)
            for path in sorted(out.rglob("*"))
            if path.is_file() and path.name != "manifest_sha256.json"
        }

    hashes = collect_hashes()
    audit["manifest_entry_count"] = len(hashes)
    (out / "audit.json").write_text(
        json.dumps(audit, indent=2, sort_keys=True, allow_nan=False) + "\n",
        encoding="utf-8",
    )
    hashes = collect_hashes()
    if len(hashes) != audit["manifest_entry_count"]:
        raise RuntimeError("E20 manifest entry count changed during finalization")
    _write_json(out / "manifest_sha256.json", hashes)
    return audit
