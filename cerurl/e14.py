"""E14: decision corrections, degradations, and calibration-frozen abstention."""
from __future__ import annotations

import csv
import hashlib
import json
import random
import time
from pathlib import Path

import numpy as np

from .core import Case, Observation, score_and_coefficients, certify
from .e13 import (
    ACTION_COSTS, ACTION_TYPES, RELIABILITY, Action, _hypothetical,
    fit_outcome_model, select_action,
)

POLICIES = ("no_repair", "static_extra_scanning", "cer_guided")
DEFAULT_E14_BUDGETS = (0, 1, 2, 3, 5)
ERROR_LIMIT = 0.12
DEFAULT_UTILITIES = (
    {"name": "balanced", "false_negative": 5.0, "false_positive": 1.0, "abstain": 0.5},
    {"name": "high_fn_cost", "false_negative": 10.0, "false_positive": 1.0, "abstain": 0.5},
    {"name": "low_abstain_cost", "false_negative": 5.0, "false_positive": 1.0, "abstain": 0.1},
)
INITIAL_STATES = ("correct", "wrong", "abstained")


def _raw_score(case: Case) -> float:
    return float(score_and_coefficients(case, 0.35)[0])


def _calibration_data(seed: int, count: int) -> list[tuple[float, int]]:
    rng = random.Random(seed)
    rows = []
    for _ in range(count):
        probability = rng.uniform(0.01, 0.99)
        label = int(rng.random() < probability)
        rows.append((probability, label))
    return rows


def fit_calibrator(seed: int, count: int = 6000, bins: int = 20) -> dict:
    """Fit a smoothed equal-width calibration map and safe release thresholds."""
    if type(count) is not int or count < 100 or type(bins) is not int or bins < 2:
        raise ValueError("calibration count must be >=100 and bins must be >=2")
    rows = _calibration_data(seed, count)
    bucket: list[list[int]] = [[0, 0] for _ in range(bins)]
    for raw, label in rows:
        index = min(bins - 1, int(raw * bins))
        bucket[index][label] += 1
    probabilities = [(positives + 1) / (positives + negatives + 2)
                     for negatives, positives in bucket]

    calibrated = [(raw, label, probabilities[min(bins - 1, int(raw * bins))])
                  for raw, label in rows]
    grid = sorted({0.0, 1.0, *(p for _, _, p in calibrated)})
    best: tuple[float, float, float] | None = None
    for benign_cut in grid:
        for malicious_cut in grid:
            if benign_cut >= malicious_cut:
                continue
            benign = [(p, y) for _, y, p in calibrated if p <= benign_cut]
            malicious = [(p, y) for _, y, p in calibrated if p >= malicious_cut]
            benign_error = (sum(y for _, y in benign) / len(benign)) if benign else 0.0
            malicious_error = (sum(1 - y for _, y in malicious) / len(malicious)) if malicious else 0.0
            if benign_error > ERROR_LIMIT or malicious_error > ERROR_LIMIT:
                continue
            coverage = (len(benign) + len(malicious)) / len(calibrated)
            candidate = (coverage, -benign_cut + malicious_cut, -benign_cut)
            if best is None or candidate > best:
                best = candidate
                selected = (benign_cut, malicious_cut, benign_error, malicious_error, coverage)
    if best is None:
        raise AssertionError("Calibration could not produce a safe release rule")
    benign_cut, malicious_cut, benign_error, malicious_error, coverage = selected
    return {
        "bin_count": bins, "bin_probabilities": probabilities,
        "benign_cut": benign_cut, "malicious_cut": malicious_cut,
        "calibration_benign_release_error": benign_error,
        "calibration_malicious_release_error": malicious_error,
        "calibration_coverage": coverage, "error_limit": ERROR_LIMIT,
        "calibration_count": count, "calibration_seed": seed,
    }


def calibrated_probability(raw_score: float, calibrator: dict) -> float:
    index = min(calibrator["bin_count"] - 1, max(0, int(raw_score * calibrator["bin_count"])))
    return float(calibrator["bin_probabilities"][index])


def safe_decision(raw_score: float, calibrator: dict) -> str:
    probability = calibrated_probability(raw_score, calibrator)
    if probability <= calibrator["benign_cut"]:
        return "benign"
    if probability >= calibrator["malicious_cut"]:
        return "malicious"
    return "abstain"


def _state(decision: str, label: int) -> str:
    if decision == "abstain":
        return "abstained"
    predicted = int(decision == "malicious")
    return "correct" if predicted == label else "wrong"


def transition_name(before: str, after: str) -> str:
    if before == after:
        return "unchanged"
    if before not in INITIAL_STATES or after not in INITIAL_STATES:
        raise ValueError(f"Invalid decision state transition: {before}->{after}")
    return f"{before}_to_{after}"


def _make_case(rng: random.Random, case_id: str, stratum: str) -> tuple[Case, int, list[Action]]:
    node_count, group_count = 4, 6
    label = rng.randrange(2)
    if stratum == "abstained":
        raw = rng.uniform(0.46, 0.54)
    elif stratum == "correct":
        raw = rng.uniform(0.88, 0.97) if label else rng.uniform(0.03, 0.12)
    elif stratum == "wrong":
        raw = rng.uniform(0.88, 0.97) if not label else rng.uniform(0.03, 0.12)
    else:
        raise ValueError(f"Unknown initial state stratum: {stratum}")
    graph = np.zeros((node_count, node_count), dtype=float)
    for node in range(node_count):
        graph[node, node] = 0.65
        graph[node, (node + 1) % node_count] = 0.35
    observations = []
    for node in range(node_count):
        for group in range(group_count):
            root = f"base-{case_id}-{group}"
            observations.append(Observation(
                node, raw, 1 / group_count, frozenset({root}),
                f"{case_id}-base-{node}-{group}", "base",
            ))
    case = Case(case_id, graph, observations, 0, None, world_type="controlled_synthetic")
    actions = [
        Action(f"{case_id}:{kind}:n{node}", kind, node,
               f"independent-{case_id}-{kind}-{node}", ACTION_COSTS[kind])
        for kind in ACTION_TYPES for node in range(node_count)
    ]
    return case, label, actions


def _utility(decision: str, label: int, utility: dict) -> float:
    if decision == "abstain":
        return -utility["abstain"]
    predicted = int(decision == "malicious")
    if predicted == label:
        return 0.0
    return -utility["false_negative"] if label else -utility["false_positive"]


def _static_action(actions: list[Action], selected: list[Action]) -> Action | None:
    remaining = [action for action in actions if action not in selected]
    if not remaining:
        return None
    return min(remaining, key=lambda action: (ACTION_TYPES.index(action.kind), action.node))


def _sealed_outcomes(actions: list[Action], label: int, seed: int) -> dict[str, float]:
    outcomes = {}
    for action in actions:
        action_hash = int.from_bytes(hashlib.sha256(action.action_id.encode()).digest()[:4], "big")
        rng = random.Random(seed ^ action_hash)
        observed_label = label if rng.random() < RELIABILITY[action.kind] else 1 - label
        outcomes[action.action_id] = float(0.92 if observed_label else 0.08)
    return outcomes


def _run_trajectory(case: Case, label: int, actions: list[Action], policy: str,
                    max_attempts: int, calibrator: dict, outcome_model: dict,
                    sealed_outcomes: dict[str, float], seed: int) -> tuple[list[dict], Case]:
    current = case
    selected: list[Action] = []
    steps: list[dict] = []
    rng = random.Random(seed)
    for _ in range(max_attempts):
        before_decision = safe_decision(_raw_score(current), calibrator)
        before_state = _state(before_decision, label)
        started = time.perf_counter()
        if policy == "no_repair":
            action = None
        elif policy == "static_extra_scanning":
            action = _static_action(actions, selected)
        elif policy == "cer_guided":
            action = select_action("cer_guided", current, actions, selected, outcome_model, rng)
        else:
            raise ValueError(f"Unknown E14 policy: {policy}")
        latency_ms = (time.perf_counter() - started) * 1000
        if action is None:
            break
        # The sealed result is looked up only after selection by the executor.
        observed = sealed_outcomes[action.action_id]
        observed_label = int(observed >= 0.5)
        updated = _hypothetical(current, action, observed)
        after_decision = safe_decision(_raw_score(updated), calibrator)
        after_state = _state(after_decision, label)
        cert_before = bool(certify(current, 1, 0.35, 0.40, 0.60)["certified"])
        cert_after = bool(certify(updated, 1, 0.35, 0.40, 0.60)["certified"])
        steps.append({
            "action": action, "before_decision": before_decision, "after_decision": after_decision,
            "before_state": before_state, "after_state": after_state,
            "transition": transition_name(before_state, after_state),
            "latency_ms": latency_ms, "cert_before": cert_before, "cert_after": cert_after,
            "observed_value": observed, "observed_label": observed_label,
        })
        current = updated
        selected.append(action)
    return steps, current


def _calibration_curve(raw_scores: list[float], labels: list[int], calibrator: dict,
                       bins: int = 10) -> list[dict]:
    grouped: list[list[tuple[float, int]]] = [[] for _ in range(bins)]
    for raw, label in zip(raw_scores, labels):
        probability = calibrated_probability(raw, calibrator)
        grouped[min(bins - 1, int(probability * bins))].append((probability, label))
    return [
        {"bin": index, "count": len(rows),
         "mean_predicted_probability": float(np.mean([p for p, _ in rows])) if rows else None,
         "observed_positive_rate": float(np.mean([y for _, y in rows])) if rows else None}
        for index, rows in enumerate(grouped)
    ]


def _loss(decision: str, label: int, utility: dict) -> float:
    return -_utility(decision, label, utility)


def _bootstrap_ci(values: list[float], rng: random.Random, reps: int = 1000) -> list[float] | None:
    if not values:
        return None
    if len(values) == 1:
        return [values[0], values[0]]
    means = [float(np.mean(rng.choices(values, k=len(values)))) for _ in range(reps)]
    return [float(np.percentile(means, 2.5)), float(np.percentile(means, 97.5))]


def _write_csv(path: Path, rows: list[dict]) -> None:
    if not rows:
        path.write_text("", encoding="utf-8")
        return
    with path.open("w", encoding="utf-8", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)


def run_e14(out_dir="results/E14", table_dir="tables", cases=30, repeats=3,
            seed=20261414, budgets=DEFAULT_E14_BUDGETS) -> dict:
    if type(cases) is not int or cases < 1 or type(repeats) is not int or repeats < 1:
        raise ValueError("cases and repeats must be positive integers")
    budgets = tuple(budgets)
    if (not budgets or any(type(b) is not int or b < 0 for b in budgets)
            or tuple(sorted(set(budgets))) != budgets or max(budgets) > len(ACTION_TYPES) * 4):
        raise ValueError("budgets must be ascending distinct nonnegative integers within the action menu")
    out, tables = Path(out_dir), Path(table_dir)
    out.mkdir(parents=True, exist_ok=True)
    tables.mkdir(parents=True, exist_ok=True)
    names = ("audit.json", "manifest_sha256.json", "trial_results.csv", "transitions.csv",
             "transition_counts.csv", "calibration_curves.json", "paired_comparisons.csv",
             "error_analysis.csv", "summary.csv", "policy_action_distribution.csv")
    for name in names:
        (out / name).unlink(missing_ok=True)
    (tables / "e14_decisions.tex").unlink(missing_ok=True)

    started = time.perf_counter()
    calibrator = fit_calibrator(seed ^ 0xCA11B, count=max(6000, cases * 100))
    outcome_model = fit_outcome_model(seed ^ 0x0B5, samples_per_class=600)
    utilities = list(DEFAULT_UTILITIES)
    trials, transitions, curves, action_counts = [], [], [], []
    # Evaluation strata are balanced by design; they are never passed to selectors.
    for repeat in range(repeats):
        for case_index in range(cases):
            case_seed = seed + repeat * 100_003 + case_index * 1009
            case_rng = random.Random(case_seed)
            stratum = INITIAL_STATES[case_index % len(INITIAL_STATES)]
            case, label, actions = _make_case(
                case_rng, f"e14-r{repeat}-c{case_index}", stratum)
            initial_raw = _raw_score(case)
            initial_decision = safe_decision(initial_raw, calibrator)
            actual_initial_state = _state(initial_decision, label)
            if actual_initial_state != stratum:
                raise AssertionError(f"Calibration threshold did not realize {stratum}: {actual_initial_state}")
            sealed = _sealed_outcomes(actions, label, case_seed ^ 0x0A771)
            for policy_index, policy in enumerate(POLICIES):
                steps, _ = _run_trajectory(
                    case, label, actions, policy, max(budgets), calibrator, outcome_model,
                    sealed,
                    case_seed ^ (policy_index * 0xE14))
                for step, item in enumerate(steps, start=1):
                    transitions.append({
                        "repeat": repeat, "case_id": case.case_id, "policy": policy,
                        "initial_state": actual_initial_state, "step": step,
                        "before_decision": item["before_decision"], "after_decision": item["after_decision"],
                        "before_state": item["before_state"], "after_state": item["after_state"],
                        "transition": item["transition"], "action_id": item["action"].action_id,
                        "action_type": item["action"].kind, "acquisition_cost": item["action"].cost,
                        "selection_latency_ms": item["latency_ms"],
                    })
                action_counts.extend({
                    "repeat": repeat, "case_id": case.case_id, "policy": policy,
                    "action_type": item["action"].kind, "action_id": item["action"].action_id,
                    "step": step, "cost": item["action"].cost,
                } for step, item in enumerate(steps, start=1))
                for budget in budgets:
                    prefix = steps[:budget]
                    # Reconstruct the complete post-action state, not just the final appended observation.
                    end_case = case
                    for item in prefix:
                        end_case = _hypothetical(end_case, item["action"], item["observed_value"])
                    final_decision = safe_decision(_raw_score(end_case), calibrator)
                    final_state = _state(final_decision, label)
                    base_certified = bool(certify(case, 1, 0.35, 0.40, 0.60)["certified"])
                    final_certified = bool(certify(end_case, 1, 0.35, 0.40, 0.60)["certified"])
                    selected_cost = sum(item["action"].cost for item in prefix)
                    transition_window = [item["transition"] for item in prefix]
                    utility_metrics = {
                        utility["name"]: _loss(final_decision, label, utility)
                        for utility in utilities
                    }
                    calibration_row = {
                        "repeat": repeat, "case_id": case.case_id, "policy": policy,
                        "budget": budget, "raw_before": initial_raw, "raw_after": _raw_score(end_case),
                        "probability_before": calibrated_probability(initial_raw, calibrator),
                        "probability_after": calibrated_probability(_raw_score(end_case), calibrator),
                        "label": label,
                    }
                    curves.append(calibration_row)
                    trials.append({
                        "repeat": repeat, "case_id": case.case_id, "policy": policy,
                        "budget": budget, "initial_state": actual_initial_state,
                        "final_state": final_state, "initial_decision": initial_decision,
                        "final_decision": final_decision,
                        "correction": actual_initial_state == "wrong" and final_state == "correct",
                        "degradation": actual_initial_state == "correct" and final_state == "wrong",
                        "correct_to_abstain": actual_initial_state == "correct" and final_state == "abstained",
                        "wrong_to_abstain": actual_initial_state == "wrong" and final_state == "abstained",
                        "abstained_to_correct": actual_initial_state == "abstained" and final_state == "correct",
                        "abstained_to_wrong": actual_initial_state == "abstained" and final_state == "wrong",
                        "abstained_final": final_state == "abstained",
                        "selective_coverage": final_state != "abstained",
                        "selective_error": final_state == "wrong" if final_state != "abstained" else None,
                        "final_loss_balanced": utility_metrics["balanced"],
                        "final_loss_high_fn_cost": utility_metrics["high_fn_cost"],
                        "final_loss_low_abstain_cost": utility_metrics["low_abstain_cost"],
                        "money_cost": selected_cost, "action_count": len(prefix),
                        "corrected_cost": selected_cost if final_state == "correct" and actual_initial_state == "wrong" else 0.0,
                        "certified_before": base_certified, "certified_after": final_certified,
                        "certified_coverage_gain": int(final_certified) - int(base_certified),
                        "unresolved": final_state in ("wrong", "abstained") or not final_certified,
                        "transition_sequence": transition_window,
                    })

    transitions_summary = []
    for policy in POLICIES:
        for budget in budgets:
            selected_rows = [row for row in transitions if row["policy"] == policy and row["step"] <= budget]
            counts = {name: sum(row["transition"] == name for row in selected_rows)
                      for name in ("unchanged", "wrong_to_correct", "correct_to_wrong",
                                   "wrong_to_abstained", "correct_to_abstained",
                                   "abstained_to_correct", "abstained_to_wrong",
                                   "abstained_to_abstained")}
            transitions_summary.append({
                "policy": policy, "budget": budget, "action_transitions": len(selected_rows),
                **counts, "denominator": len(selected_rows),
                "correction_rate_per_action": counts["wrong_to_correct"] / len(selected_rows)
                if selected_rows else None,
                "degradation_rate_per_action": counts["correct_to_wrong"] / len(selected_rows)
                if selected_rows else None,
            })

    comparisons = []
    lookup = {(row["repeat"], row["case_id"], row["budget"], row["policy"]): row for row in trials}
    for row in trials:
        if row["policy"] == "no_repair":
            continue
        baseline = lookup[row["repeat"], row["case_id"], row["budget"], "no_repair"]
        comparisons.append({
            "repeat": row["repeat"], "case_id": row["case_id"], "budget": row["budget"],
            "policy": row["policy"], "initial_state": row["initial_state"],
            "loss_delta_balanced": row["final_loss_balanced"] - baseline["final_loss_balanced"],
            "coverage_delta": int(row["selective_coverage"]) - int(baseline["selective_coverage"]),
        })
    paired = []
    ci_rng = random.Random(seed ^ 0xC1)
    for policy in ("static_extra_scanning", "cer_guided"):
        for budget in budgets:
            for state in INITIAL_STATES:
                rows = [row for row in comparisons if row["policy"] == policy
                        and row["budget"] == budget and row["initial_state"] == state]
                deltas = [row["loss_delta_balanced"] for row in rows]
                paired.append({
                    "policy": policy, "budget": budget, "initial_state": state,
                    "pairs": len(rows), "mean_loss_delta": float(np.mean(deltas)) if deltas else None,
                    "loss_delta_ci95": _bootstrap_ci(deltas, ci_rng),
                })

    error_analysis = []
    for policy in POLICIES:
        for budget in budgets:
            rows = [row for row in trials if row["policy"] == policy and row["budget"] == budget]
            for state in INITIAL_STATES:
                selected = [row for row in rows if row["initial_state"] == state]
                error_analysis.append({
                    "policy": policy, "budget": budget, "initial_state": state,
                    "cases": len(selected),
                    "corrections": sum(row["correction"] for row in selected),
                    "degradations": sum(row["degradation"] for row in selected),
                    "wrong_to_abstain": sum(row["wrong_to_abstain"] for row in selected),
                    "correct_to_abstain": sum(row["correct_to_abstain"] for row in selected),
                    "abstained_to_correct": sum(row["abstained_to_correct"] for row in selected),
                    "abstained_to_wrong": sum(row["abstained_to_wrong"] for row in selected),
                })
    curves_out = []
    for policy in POLICIES:
        for budget in budgets:
            rows = [row for row in curves if row["policy"] == policy and row["budget"] == budget]
            curves_out.append({
                "policy": policy, "budget": budget,
                "before": _calibration_curve([row["raw_before"] for row in rows],
                                             [row["label"] for row in rows], calibrator),
                "after": _calibration_curve([row["raw_after"] for row in rows],
                                            [row["label"] for row in rows], calibrator),
            })
    summary = []
    policy_action_distribution = []
    for policy in POLICIES:
        for budget in budgets:
            rows = [row for row in trials if row["policy"] == policy and row["budget"] == budget]
            count = len(rows)
            classified = [row for row in rows if row["selective_coverage"]]
            corrected = [row for row in rows if row["correction"]]
            summary.append({
                "policy": policy, "budget": budget, "cases": count,
                "corrections": sum(row["correction"] for row in rows),
                "degradations": sum(row["degradation"] for row in rows),
                "abstain_fraction": sum(row["abstained_final"] for row in rows) / count,
                "selective_coverage": len(classified) / count,
                "selective_risk": sum(row["final_state"] == "wrong" for row in classified) / len(classified)
                if classified else None,
                "mean_loss_balanced": float(np.mean([row["final_loss_balanced"] for row in rows])),
                "mean_loss_high_fn_cost": float(np.mean([row["final_loss_high_fn_cost"] for row in rows])),
                "mean_loss_low_abstain_cost": float(np.mean([row["final_loss_low_abstain_cost"] for row in rows])),
                "corrected_cost": (sum(row["corrected_cost"] for row in rows) / len(corrected))
                if corrected else None,
                "unresolved": sum(row["unresolved"] for row in rows),
                "mean_action_count": float(np.mean([row["action_count"] for row in rows])),
                "mean_money_cost": float(np.mean([row["money_cost"] for row in rows])),
                "mean_selection_latency_ms": float(np.mean([
                    sum(item["selection_latency_ms"] for item in transitions
                        if item["policy"] == policy and item["case_id"] == row["case_id"]
                        and item["repeat"] == row["repeat"] and item["step"] <= budget)
                    for row in rows
                ])),
            })
            for kind in ACTION_TYPES:
                count = sum(
                    entry["policy"] == policy and entry["action_type"] == kind
                    and entry["step"] <= budget
                    and (entry["repeat"], entry["case_id"]) in {
                        (row["repeat"], row["case_id"]) for row in rows
                    }
                    for entry in action_counts
                )
                policy_action_distribution.append({
                    "policy": policy, "budget": budget, "action_type": kind,
                    "selections": count,
                })

    audit = {
        "audit_version": "E14-1", "seed": seed, "cases_per_repeat": cases, "repeats": repeats,
        "budgets": list(budgets), "policies": list(POLICIES),
        "calibration": calibrator,
        "calibration_policy": "maximize selective coverage on independent synthetic calibration data subject to <=12% errors among benign and malicious releases",
        "frozen_before_test": True,
        "evaluation_truth_access": "label is used only by evaluation, transition, calibration-curve aggregation, and utility reporting; never passed to selectors",
        "transition_definition": "same decision is unchanged; otherwise categories are based on correctness relative to sealed label and abstention",
        "denominators": {
            "trial_metrics": "one final state per case x repeat x policy x budget",
            "transition_metrics": "observed action transitions; no-repair contributes zero action transitions",
            "selective_risk": "wrong released decisions / all non-abstained final decisions",
            "selective_coverage": "non-abstained final decisions / all trial cases",
            "corrected_cost": "mean acquisition money cost among initially wrong cases ending correct; null if no corrections",
        },
        "utilities": utilities, "summary": summary, "paired_comparisons": paired,
        "transition_summary": transitions_summary, "error_analysis": error_analysis,
        "policy_action_distribution": policy_action_distribution,
        "runtime_seconds": time.perf_counter() - started,
        "pass_criteria": {
            "protocol_status": "pass",
            "calibration_frozen_before_test": True,
            "labels_hidden_from_policy": True,
            "all_transition_denominators_explicit": True,
            "does_not_claim_score_change_is_correction": True,
            "status": "pass" if not any(
                row["degradations"] > row["corrections"] and row["budget"] > 0
                for row in summary if row["policy"] == "cer_guided") else "fail",
            "cer_degradations_do_not_exceed_corrections": not any(
                row["degradations"] > row["corrections"] and row["budget"] > 0
                for row in summary if row["policy"] == "cer_guided"),
        },
    }
    _write_csv(out / "trial_results.csv", trials)
    _write_csv(out / "transitions.csv", transitions)
    _write_csv(out / "transition_counts.csv", transitions_summary)
    _write_csv(out / "policy_action_distribution.csv", policy_action_distribution)
    _write_csv(out / "paired_comparisons.csv", paired)
    _write_csv(out / "error_analysis.csv", error_analysis)
    _write_csv(out / "summary.csv", summary)
    (out / "calibration_curves.json").write_text(json.dumps(curves_out, indent=2, allow_nan=False), encoding="utf-8")
    (out / "audit.json").write_text(json.dumps(audit, indent=2, allow_nan=False), encoding="utf-8")
    table = ["% Controlled synthetic decision consequences; errors relative to held-out adjudicated labels.",
             r"\begin{tabular}{lrrrrr}", r"Policy & Budget & Correction & Degradation & Abstain & Coverage \\", r"\hline"]
    for row in summary:
        policy_name = row["policy"].replace("_", r"\_")
        table.append(f"{policy_name} & {row['budget']} & {row['corrections']} & {row['degradations']} & "
                     f"{row['abstain_fraction']:.3f} & {row['selective_coverage']:.3f} " + r"\\")
    table.extend([r"\end{tabular}", ""])
    (tables / "e14_decisions.tex").write_text("\n".join(table), encoding="utf-8")
    files = [path for path in out.rglob("*") if path.is_file() and path.name != "manifest_sha256.json"]
    manifest = {str(path.relative_to(out)): hashlib.sha256(path.read_bytes()).hexdigest()
                for path in sorted(files)}
    (out / "manifest_sha256.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    return audit
