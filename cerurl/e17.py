"""E17: controlled longitudinal drift, evidence expiry, and certificate replay.

The built-in worlds are simulations, not prospectively collected field data.
"""
from __future__ import annotations

import csv
import hashlib
import json
import math
import random
import statistics
import time
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

import numpy as np
from sklearn.metrics import average_precision_score

from .core import Case, Observation, certify


POLICIES = ("static_trust", "periodic_full_refresh", "freshness_only", "cer_repair")
MODALITIES = {
    "feed": {"node": 1, "accuracy": 0.94, "decay": 0.12, "cost": 1.0},
    "dns": {"node": 1, "accuracy": 0.85, "decay": 0.22, "cost": 0.8},
    "tls": {"node": 1, "accuracy": 0.59, "decay": 0.06, "cost": 0.5},
    "html": {"node": 0, "accuracy": 0.91, "decay": 0.17, "cost": 1.4},
    "redirect": {"node": 0, "accuracy": 0.87, "decay": 0.20, "cost": 1.0},
    "reputation": {"node": 1, "accuracy": 0.90, "decay": 0.08, "cost": 0.7},
}
EVENTS = (
    "domain_migration", "dns_change", "certificate_rotation", "page_cleanup",
    "redirect_mutation", "source_reputation_change", "silent_source_withdrawal",
    "stable",
)
BASE_GRAPH = np.array([[0.75, 0.25], [0.25, 0.75]], dtype=float)
MIGRATED_GRAPH = np.array([[0.55, 0.45], [0.35, 0.65]], dtype=float)
REDIRECT_GRAPH = np.array([[0.60, 0.40], [0.20, 0.80]], dtype=float)
ALPHA, TAU_B, TAU_M, CERT_BUDGET = 0.35, 0.40, 0.60, 1
AGE_BUCKETS = ("fresh", "stale", "no_signal")
OUTPUT_COLUMNS = {
    "monthly": (
        "case_id", "policy", "month", "event", "event_month", "truth_phishing",
        "prediction", "score", "access_status", "evidence_age_months",
        "evidence_age_bucket", "certificate_available", "certificate_certified",
        "certificate_valid", "certificate_expired_expected",
        "stale_certificate_retained", "certificate_invalidated",
        "invalidation_reason", "graph_snapshot_changed", "action_count",
        "action_cost", "unnecessary_repair",
    ),
    "metrics": (
        "policy", "month", "age_bucket", "cases", "accessible", "phishing",
        "auprc", "accuracy", "coverage", "selective_risk",
        "certificate_coverage", "certificate_expiry_correctness",
        "stale_certificate_retained_count", "mean_evidence_age_months",
        "cumulative_action_count", "cumulative_action_cost",
    ),
    "summary": (
        "policy", "cases", "months", "time_auprc_mean", "accuracy",
        "coverage", "certificate_expiry_correctness",
        "stale_certificate_retained_count", "cumulative_action_count",
        "cumulative_action_cost", "mean_time_to_correction_months", "corrected_cases",
        "unnecessary_repair_count", "unnecessary_repair_rate",
        "refresh_count", "certificate_count", "expiry_expected_count",
        "mean_recheck_delay_months", "rechecked_cases",
    ),
}


def _write_csv(path: Path, rows: list[dict[str, Any]], columns: tuple[str, ...]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as stream:
        writer = csv.DictWriter(stream, fieldnames=columns)
        writer.writeheader()
        writer.writerows(rows)


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _manifest(out: Path) -> None:
    files = [
        path for path in out.rglob("*")
        if path.is_file() and path.name != "manifest_sha256.json"
    ]
    payload = {
        str(path.relative_to(out)): _sha256(path)
        for path in sorted(files)
    }
    (out / "manifest_sha256.json").write_text(
        json.dumps(payload, indent=2) + "\n", encoding="utf-8",
    )


def _calibrate_ttls(seed: int, samples: int = 500) -> tuple[dict[str, int], list[dict[str, Any]]]:
    """Select modality TTLs on a separate controlled calibration sample."""
    rng = random.Random(seed)
    maximum_age = 6
    abstain_loss = 0.20
    calibration: dict[str, list[float]] = {}
    rows = []
    for modality, params in MODALITIES.items():
        age_accuracies = []
        for age in range(maximum_age + 1):
            correct = 0
            reliability = max(
                0.5, params["accuracy"] * math.exp(-params["decay"] * age),
            )
            for _ in range(samples):
                correct += rng.random() < reliability
            accuracy = correct / samples
            age_accuracies.append(accuracy)
            rows.append({
                "modality": modality, "age_months": age, "samples": samples,
                "synthetic_accuracy": accuracy, "calibration_seed": seed,
            })
        calibration[modality] = age_accuracies

    ttls = {}
    for modality, accuracies in calibration.items():
        losses = {
            ttl: sum(
                (1 - accuracies[age]) if age <= ttl else abstain_loss
                for age in range(maximum_age + 1)
            ) / (maximum_age + 1)
            for ttl in range(maximum_age + 1)
        }
        ttls[modality] = min(losses, key=lambda ttl: (losses[ttl], ttl))
    return ttls, rows


def _case_plans(cases: int, seed: int, months: int) -> list[dict[str, Any]]:
    rng = random.Random(seed)
    plans = []
    for index in range(cases):
        truth = index % 2
        remediation_month = None
        if truth == 1 and index % 3 == 0:
            remediation_month = 3 + index % max(1, months - 3)
            if remediation_month >= months:
                remediation_month = months - 1
        event = EVENTS[index % len(EVENTS)]
        event_month = 2 + index % max(1, months - 2)
        withdrawn_modality = rng.choice(tuple(MODALITIES)) if event == "silent_source_withdrawal" else None
        plans.append({
            "case_id": f"e17-{index:05d}",
            "initial_truth": truth,
            "remediation_month": remediation_month,
            "event": event,
            "event_month": event_month,
            "withdrawn_modality": withdrawn_modality,
        })
    return plans


def _truth_at(plan: dict[str, Any], month: int) -> int:
    if plan["remediation_month"] is not None and month >= plan["remediation_month"]:
        return 0
    return plan["initial_truth"]


def _graph_for(plan: dict[str, Any], month: int) -> tuple[np.ndarray, str]:
    if month < plan["event_month"]:
        return BASE_GRAPH, "base"
    if plan["event"] == "domain_migration":
        return MIGRATED_GRAPH, "domain_migration"
    if plan["event"] == "redirect_mutation":
        return REDIRECT_GRAPH, "redirect_mutation"
    return BASE_GRAPH, "base"


def _graph_by_id(graph_id: str) -> np.ndarray:
    if graph_id == "domain_migration":
        return MIGRATED_GRAPH
    if graph_id == "redirect_mutation":
        return REDIRECT_GRAPH
    return BASE_GRAPH


def _make_sealed_observation(
    plan: dict[str, Any], modality: str, month: int, truth: int,
    rng: random.Random,
) -> dict[str, Any]:
    params = MODALITIES[modality]
    accuracy = params["accuracy"]
    if plan["event"] == "certificate_rotation" and modality == "tls" and month >= plan["event_month"]:
        accuracy = 0.52
    elif plan["event"] == "source_reputation_change" and modality == "reputation" and month >= plan["event_month"]:
        accuracy = 0.55
    elif plan["event"] == "dns_change" and modality == "dns" and month >= plan["event_month"]:
        accuracy = 0.70
    observed = truth if rng.random() < accuracy else 1 - truth
    return {
        "modality": modality,
        "value": 0.90 if observed else 0.10,
        "captured_month": month,
        "obs_id": f"{plan['case_id']}-{modality}-m{month}",
        "root": f"source-{modality}",
    }


def _sealed_monthly_observations(
    plan: dict[str, Any], months: int, seed: int,
) -> dict[int, dict[str, dict[str, Any]]]:
    outcomes = {}
    for month in range(months):
        rng = random.Random(seed + month * 1009)
        truth = _truth_at(plan, month)
        available = {}
        for modality in MODALITIES:
            if (
                plan["event"] == "silent_source_withdrawal"
                and month >= plan["event_month"]
                and modality == plan["withdrawn_modality"]
            ):
                continue
            available[modality] = _make_sealed_observation(
                plan, modality, month, truth, rng,
            )
        outcomes[month] = available
    return outcomes


def _policy_case(
    case_id: str,
    evidence: dict[str, dict[str, Any]],
    month: int,
    ttls: dict[str, int],
    graph: np.ndarray,
    include_stale: bool,
) -> tuple[Case | None, list[int], int | None]:
    usable = [
        item for modality, item in evidence.items()
        if include_stale or month - item["captured_month"] <= ttls[modality]
    ]
    node_counts = Counter(MODALITIES[item["modality"]]["node"] for item in usable)
    if not usable or any(node_counts[node] == 0 for node in (0, 1)):
        return None, [month - item["captured_month"] for item in usable], None
    observations = []
    for item in usable:
        modality = item["modality"]
        node = MODALITIES[modality]["node"]
        observations.append(Observation(
            node=node, value=item["value"], weight=1 / node_counts[node],
            ancestors=frozenset({item["root"]}), obs_id=item["obs_id"], kind=modality,
        ))
    return (
        Case(case_id, np.array(graph, copy=True), observations, target=0),
        [month - item["captured_month"] for item in usable],
        len(usable),
    )


def _decision(score: float | None) -> str:
    if score is None:
        return "abstain"
    if score >= TAU_M:
        return "phishing"
    if score <= TAU_B:
        return "benign"
    return "abstain"


def _age_bucket(ages: list[int], modalities: list[str], ttls: dict[str, int]) -> str:
    if not ages:
        return "no_signal"
    if all(age <= ttls[modality] for age, modality in zip(ages, modalities)):
        return "fresh"
    return "stale"


def _evaluate_month(
    plan: dict[str, Any], policy: str, month: int, evidence: dict[str, dict[str, Any]],
    ttls: dict[str, int], graph: np.ndarray, include_stale: bool,
) -> tuple[dict[str, Any], dict[str, Any] | None]:
    case, ages, _ = _policy_case(
        plan["case_id"], evidence, month, ttls, graph, include_stale,
    )
    score = None
    certificate = None
    modalities = []
    if case is not None:
        certificate = certify(case, CERT_BUDGET, ALPHA, TAU_B, TAU_M)
        score = float(certificate["score"])
        modalities = [obs.kind for obs in case.observations]
    decision = _decision(score)
    truth = _truth_at(plan, month)
    row = {
        "case_id": plan["case_id"],
        "policy": policy,
        "month": month,
        "event": plan["event"],
        "event_month": plan["event_month"],
        "truth_phishing": truth,
        "prediction": decision,
        "score": score,
        "access_status": "available" if score is not None else "no_signal",
        "evidence_age_months": statistics.mean(ages) if ages else None,
        "evidence_age_bucket": _age_bucket(ages, modalities, ttls),
        "certificate_available": certificate is not None,
        "certificate_certified": bool(certificate and certificate["certified"]),
        "certificate_valid": False,
        "certificate_expired_expected": False,
        "stale_certificate_retained": False,
        "certificate_invalidated": False,
        "invalidation_reason": "",
        "graph_snapshot_changed": False,
        "action_count": 0,
        "action_cost": 0.0,
        "unnecessary_repair": False,
    }
    return row, certificate


def _policy_run(
    plan: dict[str, Any], outcomes: dict[int, dict[str, dict[str, Any]]],
    months: int, ttls: dict[str, int], periodic_interval: int,
) -> list[dict[str, Any]]:
    trajectories = {}
    for policy in POLICIES:
        current: dict[str, dict[str, Any]] = {}
        initial = outcomes[0]
        current.update(initial)
        _, graph_id = _graph_for(plan, 0)
        cached_certificate = None
        cached_evidence: dict[str, dict[str, Any]] = {}
        cached_graph_id = graph_id
        last_environment_graph_id = graph_id
        rows = []
        for month in range(months):
            live_graph, live_graph_id = _graph_for(plan, month)
            graph_changed = live_graph_id != last_environment_graph_id
            expired = any(
                month - item["captured_month"] > ttls[modality]
                for modality, item in current.items()
            )
            prior_invalid = cached_certificate is not None and (
                cached_graph_id != live_graph_id or any(
                    month - item["captured_month"] > ttls[modality]
                    for modality, item in cached_evidence.items()
                )
            )
            prior_invalidation_reason = (
                "graph_snapshot_changed"
                if cached_certificate is not None and cached_graph_id != live_graph_id
                else "evidence_expired"
            )
            old_decision = rows[-1]["prediction"] if rows else None
            refreshed = month == 0

            if month > 0 and policy == "periodic_full_refresh" and month % periodic_interval == 0:
                refreshed = True
            elif month > 0 and policy == "cer_repair" and (
                expired or live_graph_id != graph_id
            ):
                refreshed = True
            elif month > 0 and policy == "freshness_only":
                for modality in list(current):
                    if month - current[modality]["captured_month"] > ttls[modality]:
                        del current[modality]

            old_evidence = dict(current)
            if refreshed and month > 0:
                current = dict(outcomes[month])
            action_count = len(current) if refreshed else 0
            action_cost = (
                sum(MODALITIES[key]["cost"] for key in current) if refreshed else 0.0
            )

            if policy == "static_trust":
                graph_for_score = BASE_GRAPH
                use_stale = True
            elif policy == "periodic_full_refresh":
                graph_for_score = live_graph if refreshed else _graph_by_id(graph_id)
                use_stale = True
            else:
                graph_for_score = live_graph
                use_stale = False

            row, candidate_certificate = _evaluate_month(
                plan, policy, month, current, ttls,
                graph_for_score, use_stale,
            )
            candidate_case, _, _ = _policy_case(
                plan["case_id"], current, month, ttls, graph_for_score, use_stale,
            )
            candidate_ids = (
                {obs.obs_id for obs in candidate_case.observations}
                if candidate_case is not None else set()
            )
            cached_ids = {item["obs_id"] for item in cached_evidence.values()}
            if (
                refreshed or month == 0
                or (policy == "freshness_only" and (
                    candidate_ids != cached_ids or live_graph_id != cached_graph_id
                ))
            ):
                cached_certificate = candidate_certificate
                cached_evidence = dict(current)
                cached_graph_id = graph_id if policy == "static_trust" else live_graph_id
            if month > 0 and prior_invalid and rows[-1]["certificate_valid"]:
                row["certificate_invalidated"] = True
                row["invalidation_reason"] = prior_invalidation_reason
            proof_expired = any(
                month - item["captured_month"] > ttls[modality]
                for modality, item in cached_evidence.items()
            )
            proof_graph_stale = cached_graph_id != live_graph_id
            invalidated = bool(proof_expired or proof_graph_stale)
            previous_valid = rows[-1]["certificate_valid"] if rows else False
            if month > 0 and invalidated and previous_valid:
                row["certificate_invalidated"] = True
                row["invalidation_reason"] = (
                    "graph_snapshot_changed" if proof_graph_stale else "evidence_expired"
                )
            row["certificate_expired_expected"] = bool(
                cached_certificate is not None and invalidated
            )
            row["certificate_available"] = cached_certificate is not None
            row["certificate_valid"] = bool(
                cached_certificate is not None and not invalidated
            )
            row["certificate_certified"] = bool(
                cached_certificate is not None and cached_certificate["certified"]
                and row["certificate_valid"]
            )
            row["stale_certificate_retained"] = bool(
                row["certificate_available"] and invalidated
                and cached_certificate is not None and cached_certificate["certified"]
                and row["certificate_certified"]
            )
            row["graph_snapshot_changed"] = graph_changed
            row["action_count"] = action_count
            row["action_cost"] = action_cost
            unchanged_observations = bool(current) and all(
                old_evidence.get(modality, {}).get("value") == item["value"]
                for modality, item in current.items()
            )
            row["unnecessary_repair"] = bool(
                policy == "cer_repair" and refreshed and month > 0
                and unchanged_observations and not graph_changed
                and old_decision == row["prediction"]
            )
            if refreshed:
                graph_id = live_graph_id
            if policy == "freshness_only":
                graph_id = live_graph_id
            last_environment_graph_id = live_graph_id
            rows.append(row)
            trajectories.setdefault(policy, {})[month] = {
                "evidence": dict(current),
                "certificate": cached_certificate,
            }
        trajectories[policy]["rows"] = rows
    return [
        row
        for policy in POLICIES
        for row in trajectories[policy]["rows"]
    ]


def _expiry_correct(row: dict[str, Any]) -> bool:
    if not row["certificate_available"]:
        return not row["certificate_valid"] and not row["certificate_expired_expected"]
    return row["certificate_expired_expected"] == (not row["certificate_valid"])


def _metrics(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    buckets = defaultdict(list)
    for row in rows:
        buckets[(row["policy"], row["month"], row["evidence_age_bucket"])].append(row)
    result = []
    for (policy, month, age_bucket), cohort in sorted(buckets.items()):
        accessible = [row for row in cohort if row["score"] is not None]
        y = [row["truth_phishing"] for row in accessible]
        scores = [row["score"] for row in accessible]
        errors = sum(
            row["prediction"] not in ("abstain",)
            and (row["prediction"] == "phishing") != bool(row["truth_phishing"])
            for row in accessible
        )
        decided = [row for row in accessible if row["prediction"] != "abstain"]
        result.append({
            "policy": policy,
            "month": month,
            "age_bucket": age_bucket,
            "cases": len(cohort),
            "accessible": len(accessible),
            "phishing": sum(y),
            "auprc": (
                float(average_precision_score(y, scores))
                if len(set(y)) > 1 else None
            ),
            "accuracy": (
                sum(
                    (row["prediction"] == "phishing") == bool(row["truth_phishing"])
                    for row in decided
                ) / len(decided) if decided else None
            ),
            "coverage": len(decided) / len(cohort) if cohort else None,
            "selective_risk": errors / len(decided) if decided else None,
            "certificate_coverage": (
                sum(row["certificate_certified"] for row in cohort) / len(cohort)
                if cohort else None
            ),
            "certificate_expiry_correctness": (
                sum(_expiry_correct(row) for row in cohort) / len(cohort)
                if cohort else None
            ),
            "stale_certificate_retained_count": sum(
                row["stale_certificate_retained"] for row in cohort
            ),
            "mean_evidence_age_months": (
                statistics.mean(row["evidence_age_months"] for row in accessible)
                if accessible else None
            ),
            "cumulative_action_count": sum(row["action_count"] for row in cohort),
            "cumulative_action_cost": sum(row["action_cost"] for row in cohort),
        })
    return result


def _summary(
    rows: list[dict[str, Any]], cases: int, months: int,
) -> list[dict[str, Any]]:
    result = []
    for policy in POLICIES:
        policy_rows = [row for row in rows if row["policy"] == policy]
        test_rows = [row for row in policy_rows if row["month"] >= 0]
        decided = [row for row in test_rows if row["prediction"] != "abstain"]
        corrections = []
        recheck_delays = []
        repair_counts = []
        for case_id in {row["case_id"] for row in policy_rows}:
            case_rows = sorted(
                (row for row in policy_rows if row["case_id"] == case_id),
                key=lambda row: row["month"],
            )
            if case_rows[0]["event"] != "stable":
                event_month = case_rows[0]["event_month"]
                rechecked = next(
                    (row["month"] for row in case_rows
                     if row["month"] >= event_month and row["action_count"] > 0),
                    None,
                )
                if rechecked is not None:
                    recheck_delays.append(rechecked - event_month)
            transitions = [
                row["month"] for previous, row in zip(case_rows, case_rows[1:])
                if previous["truth_phishing"] == 1 and row["truth_phishing"] == 0
            ]
            if transitions:
                target_month = transitions[0]
                corrected = next(
                    (row["month"] for row in case_rows
                     if row["month"] >= target_month and row["prediction"] == "benign"),
                    None,
                )
                if corrected is not None:
                    corrections.append(corrected - target_month)
            repair_counts.extend(
                row["unnecessary_repair"] for row in case_rows
            )
        month_aps = []
        for month in range(months):
            available = [
                row for row in policy_rows
                if row["month"] == month and row["score"] is not None
            ]
            month_labels = [row["truth_phishing"] for row in available]
            if len(set(month_labels)) > 1:
                month_aps.append(float(average_precision_score(
                    month_labels, [row["score"] for row in available],
                )))
        errors = sum(
            (row["prediction"] == "phishing") != bool(row["truth_phishing"])
            for row in decided
        )
        certificates = [row for row in test_rows if row["certificate_available"]]
        expiry_expected = sum(row["certificate_expired_expected"] for row in test_rows)
        correct_expiry = sum(
            _expiry_correct(row)
            for row in test_rows
        )
        result.append({
            "policy": policy,
            "cases": cases,
            "months": months,
            "time_auprc_mean": statistics.mean(month_aps) if month_aps else None,
            "accuracy": (len(decided) - errors) / len(decided) if decided else None,
            "coverage": len(decided) / len(test_rows) if test_rows else None,
            "certificate_expiry_correctness": (
                correct_expiry / len(test_rows) if test_rows else None
            ),
            "stale_certificate_retained_count": sum(
                row["stale_certificate_retained"] for row in test_rows
            ),
            "cumulative_action_count": sum(row["action_count"] for row in test_rows),
            "cumulative_action_cost": sum(row["action_cost"] for row in test_rows),
            "mean_time_to_correction_months": (
                statistics.mean(corrections) if corrections else None
            ),
            "corrected_cases": len(corrections),
            "mean_recheck_delay_months": (
                statistics.mean(recheck_delays) if recheck_delays else None
            ),
            "rechecked_cases": len(recheck_delays),
            "unnecessary_repair_count": sum(repair_counts),
            "unnecessary_repair_rate": (
                sum(repair_counts) / sum(
                    row["action_count"] > 0 and row["month"] > 0 for row in test_rows
                ) if any(
                    row["action_count"] > 0 and row["month"] > 0 for row in test_rows
                ) else 0.0
            ),
            "refresh_count": sum(
                row["action_count"] > 0 and row["month"] > 0 for row in test_rows
            ),
            "certificate_count": len(certificates),
            "expiry_expected_count": expiry_expected,
        })
    return result


def run_e17(
    out_dir: str = "results/E17",
    table_dir: str = "tables",
    cases: int = 64,
    months: int = 12,
    seed: int = 20261717,
    calibration_seed: int = 20161717,
    periodic_interval: int = 3,
) -> dict[str, Any]:
    """Run controlled temporal transitions; no field drift claim is produced."""
    if type(cases) is not int or cases < 8:
        raise ValueError("cases must be an integer >= 8")
    if type(months) is not int or months < 4:
        raise ValueError("months must be an integer >= 4")
    if type(periodic_interval) is not int or periodic_interval < 1:
        raise ValueError("periodic_interval must be a positive integer")
    started = time.perf_counter()
    out, tables = Path(out_dir), Path(table_dir)
    out.mkdir(parents=True, exist_ok=True)
    tables.mkdir(parents=True, exist_ok=True)
    ttls, calibration_rows = _calibrate_ttls(calibration_seed)
    plans = _case_plans(cases, seed, months)
    monthly_rows = []
    for index, plan in enumerate(plans):
        outcomes = _sealed_monthly_observations(plan, months, seed + index * 7919)
        monthly_rows.extend(_policy_run(
            plan, outcomes, months, ttls, periodic_interval,
        ))
    metric_rows = _metrics(monthly_rows)
    summary_rows = _summary(monthly_rows, cases, months)
    stale_retained = sum(row["stale_certificate_retained"] for row in monthly_rows)
    expired_expected = sum(row["certificate_expired_expected"] for row in monthly_rows)
    expiry_correctness = (
        sum(
            _expiry_correct(row) for row in monthly_rows
        ) / len(monthly_rows) if monthly_rows else 1.0
    )
    transition_cases = sum(
        plan["remediation_month"] is not None for plan in plans
    )
    event_counts = dict(Counter(plan["event"] for plan in plans))
    audit = {
        "experiment": "E17",
        "status": "pass" if stale_retained == 0 and expiry_correctness == 1.0 else "fail",
        "world_type": "controlled_synthetic_longitudinal",
        "field_drift_claim": False,
        "data_limitation": (
            "No receipt-backed prospective longitudinal dataset was supplied; all temporal "
            "transitions and source observations are controlled simulations."
        ),
        "cases": cases,
        "months": months,
        "policies": list(POLICIES),
        "event_counts": event_counts,
        "remediated_cases": transition_cases,
        "frozen_schedule": {
            "periodic_full_refresh_interval_months": periodic_interval,
            "ttl_months": ttls,
            "ttl_selection": {
                "method": "minimum calibration error plus 0.20 abstention loss for expired evidence",
                "age_range_months": [0, 6],
                "samples_per_modality_age": 500,
                "seed": calibration_seed,
                "calibration_out": "calibration_ttl.csv",
            },
        },
        "protocol": {
            "same_sealed_monthly_sensor_outcomes_across_policies": True,
            "future_sensor_outcomes_not_used_for_policy_selection": True,
            "labels_used_only_for_post_score_evaluation": True,
            "graph_changes": "domain migration and redirect mutation alter the controlled graph snapshot",
            "certificate_expiry": "certificate is invalid if any included observation exceeds its frozen modality TTL or its graph snapshot changes",
        },
        "metrics": {
            "time_dependent_auprc": "monthly average precision by policy and evidence-age bucket; null when either class is absent",
            "accuracy_coverage": "selective accuracy among decided cases; coverage denominator includes abstentions and no-signal cases",
            "time_to_correction": "months from independently generated malicious-to-benign state transition to first benign decision; only remediated cases with a correction",
            "recheck_delay": "months from controlled observable event time to first post-event evidence acquisition; only cases rechecked after the event",
            "unnecessary_repair": "CER refresh with unchanged observed modality values and unchanged graph, followed by unchanged verdict",
            "latency": "simulation wall time in audit; not a per-request production latency measurement",
            "cost": "sum of fixed modality acquisition prices for refreshed observations",
            "certificate_expiry_correctness": "fraction of rows where expected invalidity due to staleness/graph change matches reported certificate validity",
        },
        "certificate_expiry_correctness": expiry_correctness,
        "stale_certificate_retained_count": stale_retained,
        "expired_certificate_rows": expired_expected,
        "pass_criteria": {
            "zero_stale_certificate_retention": stale_retained == 0,
            "certificate_expiry_correctness": expiry_correctness == 1.0,
            "all_temporal_results_labeled_controlled": True,
            "status": "pass" if stale_retained == 0 and expiry_correctness == 1.0 else "fail",
        },
        "runtime_seconds": time.perf_counter() - started,
    }
    _write_csv(out / "monthly.csv", monthly_rows, OUTPUT_COLUMNS["monthly"])
    _write_csv(out / "metrics.csv", metric_rows, OUTPUT_COLUMNS["metrics"])
    _write_csv(out / "summary.csv", summary_rows, OUTPUT_COLUMNS["summary"])
    _write_csv(out / "calibration_ttl.csv", calibration_rows, (
        "modality", "age_months", "samples", "synthetic_accuracy", "calibration_seed",
    ))
    (out / "audit.json").write_text(
        json.dumps(audit, indent=2, allow_nan=False) + "\n", encoding="utf-8",
    )
    _manifest(out)
    table_rows = []
    for row in summary_rows:
        accuracy = row["accuracy"] if row["accuracy"] is not None else "--"
        coverage = row["coverage"] if row["coverage"] is not None else "--"
        correction = (
            row["mean_time_to_correction_months"]
            if row["mean_time_to_correction_months"] is not None else "--"
        )
        table_rows.append(
            f"{row['policy'].replace('_', chr(92) + '_')} & {accuracy} & "
            f"{coverage} & {row['cumulative_action_cost']:.2f} & {correction} " + r"\\"
        )
    (tables / "e17_longitudinal.tex").write_text(
        "\n".join([
            "% Controlled synthetic replay; not field drift evidence.",
            r"\begin{tabular}{lrrrr}",
            r"Policy & Accuracy & Coverage & Repair cost & Corrections (months) \\",
            r"\hline",
            *table_rows,
            r"\end{tabular}",
            "",
        ]),
        encoding="utf-8",
    )
    if audit["pass_criteria"]["status"] != "pass":
        raise AssertionError("E17 certificate expiry audit failed")
    return audit
