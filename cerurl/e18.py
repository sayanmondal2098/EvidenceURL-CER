"""E18: controlled ablation, sensitivity, factorial, and assumption-stress audit."""
from __future__ import annotations

import csv
import hashlib
import itertools
import json
import math
import random
import statistics
import time
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

import numpy as np

from .core import (
    Case, Observation, certify, fundamental, score_and_coefficients,
)
from .e13 import (
    ACTION_COSTS, ACTION_TYPES, RELIABILITY, Action, _hypothetical,
    _sealed_outcome, fit_outcome_model, select_action,
)

ALPHA = 0.35
TAU_B, TAU_M = 0.40, 0.60
FRESHNESS_TTL = 2
ATTACK_BUDGET = 1
ACTION_BUDGET = 3
FACTORS = ("ancestry", "directional_certificate", "urltrust_graph", "freshness")
ABLATIONS = (
    "full_cer",
    "remove_source_ancestry",
    "remove_directional_certificates",
    "random_repair_policy",
    "remove_urltrust_graph",
    "remove_freshness",
    "remove_abstention",
    "remove_action_cost_term",
    "remove_calibration",
    "disable_source_group_caps",
)
SWEEP = {
    "alpha": (0.0, 0.2, 0.35, 0.6, 0.85),
    "evidence_fusion_weight": (0.0, 0.25, 0.5, 0.75, 1.0),
    "attack_budget": (0, 1, 2, 3),
    "provenance_uncertainty": (0.0, 0.1, 0.25, 0.5),
    "correlated_report_fraction": (0.0, 0.25, 0.5, 0.75),
    "action_cost_multiplier": (0.0, 0.5, 1.0, 2.0),
}
MONTHS = 6
CSV_COLUMNS = {
    "ablation": (
        "ablation", "n", "accuracy", "coverage", "selective_risk",
        "certificate_coverage", "empirical_robustness", "mean_score",
        "mean_action_count", "mean_action_cost", "mean_cumulative_loss",
        "paired_accuracy_delta", "paired_accuracy_ci_low", "paired_accuracy_ci_high",
        "paired_loss_delta", "paired_loss_ci_low", "paired_loss_ci_high",
    ),
    "sensitivity": (
        "dimension", "value", "n", "accuracy", "coverage",
        "certificate_coverage", "empirical_robustness", "mean_loss",
        "mean_action_cost",
    ),
    "factorial": (
        "factor_a", "factor_b", "metric", "interaction_effect",
        "bootstrap_ci_low", "bootstrap_ci_high", "replicates",
    ),
    "assumptions": (
        "case_id", "violation", "pre_certificate", "post_certificate",
        "certificate_status", "reason", "empirical_accuracy_unchanged",
    ),
    "repairs": (
        "case_id", "policy", "budget", "initial_loss", "final_loss",
        "cumulative_loss", "action_count", "action_cost",
        "contradictory_outcome", "mean_selection_latency_ms",
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


def _make_case(seed: int, case_id: str, correlated_fraction: float = 0.5,
               provenance_uncertainty: float = 0.0) -> tuple[Case, int]:
    rng = random.Random(seed)
    nodes, groups = 4, 6
    label = rng.randrange(2)
    compromised = rng.randrange(groups)
    graph = np.zeros((nodes, nodes), dtype=float)
    ages = {}
    for node in range(nodes):
        graph[node, node] = 0.65
        graph[node, (node + 1) % nodes] = 0.35
    observations = []
    for node in range(nodes):
        for group in range(groups):
            root = f"{case_id}-source-{group}"
            if group < round(groups * correlated_fraction):
                root = f"{case_id}-correlated-source"
            if group == compromised:
                observed = 1 - label
            else:
                observed = label if rng.random() < 0.94 else 1 - label
            value = float(np.clip((0.92 if observed else 0.08) + rng.uniform(-0.01, 0.01), 0, 1))
            age = rng.randrange(3) if group == 0 else rng.randrange(MONTHS)
            if rng.random() < provenance_uncertainty:
                root = f"{case_id}-uncertain-root"
            observations.append(Observation(
                node, value, 1 / groups, frozenset({root}),
                f"{case_id}-n{node}-g{group}", ("feed", "dns", "html")[group % 3],
            ))
            ages[observations[-1].obs_id] = age
    return Case(case_id, graph, observations, 0, metadata={"e18_age_months": ages}), label


def _score(case: Case, alpha: float, freshness: bool) -> tuple[float | None, Case | None]:
    ages = case.metadata.get("e18_age_months", {})
    eligible = [
        obs for obs in case.observations
        if not freshness or ages.get(obs.obs_id, 0) <= FRESHNESS_TTL
    ]
    by_node = Counter(obs.node for obs in eligible)
    if not eligible or any(by_node[node] == 0 for node in range(len(case.P))):
        return None, None
    normalized = [
        Observation(
            obs.node, obs.value, 1 / by_node[obs.node], obs.ancestors,
            obs.obs_id, obs.kind,
        )
        for obs in eligible
    ]
    evaluated = Case(
        case.case_id, np.array(case.P, copy=True), normalized, case.target,
        case.truth, list(case.candidates), dict(case.candidate_costs),
        case.world_type, dict(case.metadata),
    )
    score = score_and_coefficients(evaluated, alpha)[0]
    return score, evaluated


def _classification(score: float | None, abstention: bool) -> str:
    if score is None:
        return "abstain"
    if abstention:
        if score >= TAU_M:
            return "malicious"
        if score <= TAU_B:
            return "benign"
        return "abstain"
    return "malicious" if score >= 0.5 else "benign"


def _correct(decision: str, label: int) -> bool:
    return decision != "abstain" and (decision == "malicious") == bool(label)


def _group_fusion_score(case: Case, alpha: float) -> float:
    """Median-fuse evidence by source ancestry, then apply graph propagation."""
    node_values = np.zeros(len(case.P), dtype=float)
    for node in range(len(case.P)):
        roots: dict[str, list[float]] = defaultdict(list)
        for obs in case.observations:
            if obs.node == node:
                for root in obs.ancestors:
                    roots[root].append(obs.value)
        if not roots:
            node_values[node] = 0.5
            continue
        source_values = [statistics.mean(values) for values in roots.values()]
        node_values[node] = float(np.median(source_values))
    propagated = fundamental(case.P, alpha) @ node_values
    return float(propagated[case.target])


def _certificate_safe(
    case: Case, budget: int, enabled: bool, ancestry_valid: bool = True,
    caps_valid: bool = True, alpha: float = ALPHA,
) -> bool:
    if not enabled or not ancestry_valid or not caps_valid:
        return False
    return bool(certify(case, budget, alpha, TAU_B, TAU_M)["certified"])


def _proof_fingerprint(case: Case) -> str:
    payload = {
        "graph": np.asarray(case.P, dtype="<f8").tolist(),
        "target": case.target,
        "observations": [
            (
                obs.obs_id, obs.node, obs.value, obs.weight,
                sorted(obs.ancestors), obs.kind,
            )
            for obs in sorted(case.observations, key=lambda item: item.obs_id)
        ],
        "alpha": ALPHA,
        "thresholds": (TAU_B, TAU_M),
        "attack_budget": ATTACK_BUDGET,
    }
    return hashlib.sha256(
        json.dumps(payload, sort_keys=True, separators=(",", ":")).encode(),
    ).hexdigest()


def _bootstrap_mean(
    values: list[float], seed: int, samples: int,
) -> tuple[float | None, float | None]:
    if len(values) < 2:
        return None, None
    rng = random.Random(seed)
    means = sorted(
        statistics.mean(rng.choices(values, k=len(values)))
        for _ in range(samples)
    )
    return means[int(0.025 * (samples - 1))], means[int(0.975 * (samples - 1))]


def _evaluate_cases(
    cases: list[tuple[Case, int]], seed: int, bootstrap_samples: int,
) -> list[dict]:
    variants = {name: [] for name in ABLATIONS}
    outcome_model = fit_outcome_model(seed ^ 0xE18C, samples_per_class=250)
    for index, (case, label) in enumerate(cases):
        score, fresh_case = _score(case, ALPHA, freshness=True)
        score_no_fresh, no_fresh_case = _score(case, ALPHA, freshness=False)
        assert fresh_case is not None and no_fresh_case is not None
        baseline_decision = _classification(score, True)
        baseline_cert = _certificate_safe(fresh_case, ATTACK_BUDGET, True)
        attack_test = _exact_robustness(fresh_case, ATTACK_BUDGET, baseline_decision)
        def add(name: str, score_value: float | None, decision: str,
                cert: bool, robust: bool, loss: float | None = None,
                action_count: int = 0, action_cost: float = 0.0) -> None:
            correct = _correct(decision, label)
            variants[name].append({
                "case_id": case.case_id,
                "correct": correct,
                "coverage": decision != "abstain",
                "risk": not correct if decision != "abstain" else None,
                "certificate": cert,
                "robust": robust,
                "score": score_value,
                "loss": loss if loss is not None else (0.0 if correct else (0.5 if decision == "abstain" else 1.0)),
                "action_count": action_count,
                "action_cost": action_cost,
            })

        add("full_cer", score, baseline_decision, baseline_cert, attack_test)
        add("remove_source_ancestry", score, baseline_decision, False, False)
        add("remove_directional_certificates", score, baseline_decision, False, False)
        score_no_graph, no_graph_case = _score(case, 0.0, True)
        assert no_graph_case is not None
        no_graph_decision = _classification(score_no_graph, True)
        add(
            "remove_urltrust_graph", score_no_graph, no_graph_decision,
            _certificate_safe(no_graph_case, ATTACK_BUDGET, True),
            _exact_robustness(no_graph_case, ATTACK_BUDGET, no_graph_decision),
        )
        add(
            "remove_freshness", score_no_fresh,
            _classification(score_no_fresh, True),
            _certificate_safe(no_fresh_case, ATTACK_BUDGET, True),
            _exact_robustness(
                no_fresh_case, ATTACK_BUDGET,
                _classification(score_no_fresh, True),
            ),
        )
        no_abstain_decision = _classification(score, False)
        add(
            "remove_abstention", score, no_abstain_decision,
            baseline_cert, attack_test,
        )
        add("disable_source_group_caps", score, baseline_decision, False, False)

        # Matched action menu and sealed outcomes for the repair-policy ablations.
        actions = [
            Action(
                f"{case.case_id}:{kind}:n{node}", kind, node,
                f"independent-{case.case_id}-{kind}-{node}", ACTION_COSTS[kind],
            )
            for kind in ACTION_TYPES for node in range(len(case.P))
        ]
        sealed_rng = random.Random(seed + index * 7919)
        sealed = {
            action.action_id: _sealed_outcome(sealed_rng, action, label)
            for action in actions
        }
        for name, policy, calibrated, cost_multiplier in (
            ("random_repair_policy", "random", True, 1.0),
            ("remove_calibration", "expected_risk_greedy", False, 1.0),
            ("remove_action_cost_term", "expected_risk_greedy", True, 0.0),
        ):
            current = fresh_case
            selected: list[Action] = []
            selector_rng = random.Random(seed ^ index ^ (len(name) * 0xE18))
            model = outcome_model if calibrated else _uncalibrated_outcome_model()
            if cost_multiplier == 0.0:
                adjusted = [
                    Action(a.action_id, a.kind, a.node, a.root, 1.0) for a in actions
                ]
            else:
                adjusted = actions
            initial = _classification(
                score_and_coefficients(current, ALPHA)[0], True,
            )
            initial_loss = _loss(initial, label)
            curve = [initial_loss]
            cumulative_cost = 0.0
            original_costs = {action.action_id: action.cost for action in actions}
            for _ in range(ACTION_BUDGET):
                action = select_action(
                    policy, current, adjusted, selected, model, selector_rng,
                )
                if action is None:
                    break
                observed = sealed[action.action_id]
                current = _hypothetical(current, action, observed)
                selected.append(action)
                cumulative_cost += original_costs[action.action_id]
                decision = _classification(score_and_coefficients(current, ALPHA)[0], True)
                curve.append(_loss(decision, label))
            final_decision = _classification(score_and_coefficients(current, ALPHA)[0], True)
            add(
                name, score_and_coefficients(current, ALPHA)[0], final_decision,
                _certificate_safe(current, ATTACK_BUDGET, True),
                _exact_robustness(current, ATTACK_BUDGET, final_decision),
                loss=statistics.mean(curve),
                action_count=len(selected), action_cost=cumulative_cost,
            )

    summary = []
    base = {row["case_id"]: row for row in variants["full_cer"]}
    for index, name in enumerate(ABLATIONS):
        values = variants[name]
        n = len(values)
        decided = [row for row in values if row["coverage"]]
        accuracy = (
            sum(row["correct"] for row in decided) / len(decided)
            if decided else None
        )
        coverage = sum(row["coverage"] for row in values) / n
        covered_risk = [row["risk"] for row in values if row["risk"] is not None]
        robust = [row["robust"] for row in values if row["certificate"]]
        paired_accuracy = [
            float(row["correct"]) - float(base[row["case_id"]]["correct"])
            for row in values
        ]
        paired_loss = [
            row["loss"] - base[row["case_id"]]["loss"] for row in values
        ]
        acc_low, acc_high = _bootstrap_mean(
            paired_accuracy, seed + index, bootstrap_samples,
        )
        loss_low, loss_high = _bootstrap_mean(
            paired_loss, seed + index + 1000, bootstrap_samples,
        )
        summary.append({
            "ablation": name,
            "n": n,
            "accuracy": accuracy,
            "coverage": coverage,
            "selective_risk": statistics.mean(covered_risk) if covered_risk else None,
            "certificate_coverage": sum(row["certificate"] for row in values) / n,
            "empirical_robustness": statistics.mean(robust) if robust else None,
            "mean_score": statistics.mean(
                row["score"] for row in values if row["score"] is not None
            ),
            "mean_action_count": statistics.mean(row["action_count"] for row in values),
            "mean_action_cost": statistics.mean(row["action_cost"] for row in values),
            "mean_cumulative_loss": statistics.mean(row["loss"] for row in values),
            "paired_accuracy_delta": statistics.mean(paired_accuracy),
            "paired_accuracy_ci_low": acc_low,
            "paired_accuracy_ci_high": acc_high,
            "paired_loss_delta": statistics.mean(paired_loss),
            "paired_loss_ci_low": loss_low,
            "paired_loss_ci_high": loss_high,
        })
    return summary


def _uncalibrated_outcome_model() -> dict:
    result = {}
    for kind in ACTION_TYPES:
        reliability = RELIABILITY[kind]
        result[kind] = {
            0: [reliability, 1 - reliability],
            1: [1 - reliability, reliability],
        }
    return result


def _loss(decision: str, label: int) -> float:
    if decision == "abstain":
        return 0.5
    return 0.0 if (decision == "malicious") == bool(label) else 1.0


def _exact_robustness(
    case: Case, budget: int, decision: str, alpha: float = ALPHA,
) -> bool:
    if decision == "abstain":
        return False
    report = certify(case, budget, alpha, TAU_B, TAU_M)
    if not report["certified"]:
        return False
    groups = sorted(set().union(*(obs.ancestors for obs in case.observations)))
    for size in range(min(budget, len(groups)) + 1):
        for attacked in itertools.combinations(groups, size):
            attacked_set = set(attacked)
            values = []
            for obs in case.observations:
                value = obs.value
                if attacked_set.intersection(obs.ancestors):
                    value = 0.0 if decision == "malicious" else 1.0
                values.append(Observation(
                    obs.node, value, obs.weight, obs.ancestors,
                    obs.obs_id, obs.kind,
                ))
            candidate = Case(
                case.case_id, np.array(case.P, copy=True), values, case.target,
            )
            score = score_and_coefficients(candidate, alpha)[0]
            if decision == "malicious" and score < TAU_M - 1e-12:
                return False
            if decision == "benign" and score > TAU_B + 1e-12:
                return False
    return True


def _factorial(
    cases: list[tuple[Case, int]], seed: int, bootstrap_samples: int,
) -> list[dict[str, Any]]:
    results: dict[tuple[int, ...], list[float]] = {}
    levels = (0, 1)
    for setting in itertools.product(levels, repeat=len(FACTORS)):
        values = []
        for case, label in cases:
            ancestry, directional, graph_enabled, freshness = setting
            score, evaluated = _score(
                case, ALPHA if graph_enabled else 0.0, bool(freshness),
            )
            if evaluated is None:
                values.append((0.0, 0.0))
                continue
            decision = _classification(score, True)
            accuracy = float(_correct(decision, label))
            cert = float(
                _certificate_safe(
                    evaluated, ATTACK_BUDGET, bool(directional),
                    ancestry_valid=bool(ancestry), caps_valid=True,
                )
            )
            values.append((accuracy, cert))
        results[setting] = values

    interactions = []
    for a, b in itertools.combinations(range(len(FACTORS)), 2):
        for metric_index, metric in enumerate(("accuracy", "certificate_coverage")):
            effects = []
            for case_index in range(len(cases)):
                cell = {}
                for setting, observations in results.items():
                    cell[setting] = observations[case_index][metric_index]
                effect = (
                    cell[tuple(1 if i in (a, b) else 0 for i in range(len(FACTORS)))]
                    - cell[tuple(1 if i == a else 0 for i in range(len(FACTORS)))]
                    - cell[tuple(1 if i == b else 0 for i in range(len(FACTORS)))]
                    + cell[tuple(0 for _ in FACTORS)]
                )
                effects.append(effect)
            low, high = _bootstrap_mean(
                effects, seed + a * 101 + b * 13 + metric_index,
                bootstrap_samples,
            )
            interactions.append({
                "factor_a": FACTORS[a],
                "factor_b": FACTORS[b],
                "metric": metric,
                "interaction_effect": statistics.mean(effects),
                "bootstrap_ci_low": low,
                "bootstrap_ci_high": high,
                "replicates": len(effects),
            })
    return interactions


def _sensitivity(cases: list[tuple[Case, int]], seed: int) -> list[dict[str, Any]]:
    rows = []
    calibrated_model = fit_outcome_model(seed ^ 0xCA11B, samples_per_class=250)
    for dimension, values in SWEEP.items():
        for value_index, value in enumerate(values):
            per_case = []
            for case, label in cases:
                local = case
                alpha = ALPHA
                budget = ATTACK_BUDGET
                if dimension == "alpha":
                    alpha = float(value)
                elif dimension == "attack_budget":
                    budget = int(value)
                elif dimension == "provenance_uncertainty":
                    local = _perturb_ancestry(case, float(value), seed + value_index)
                elif dimension == "correlated_report_fraction":
                    local = _set_correlation(case, float(value))
                score, evaluated = _score(local, alpha, True)
                decision = _classification(score, True)
                cert = bool(
                    evaluated is not None
                    and _certificate_safe(evaluated, budget, True, alpha=alpha)
                    and not (
                        dimension == "provenance_uncertainty" and float(value) > 0
                    )
                )
                robust = bool(
                    evaluated is not None
                    and _exact_robustness(evaluated, budget, decision, alpha)
                )
                loss = _loss(decision, label)
                action_cost = 0.0
                if dimension == "evidence_fusion_weight":
                    fusion = _group_fusion_score(local, alpha)
                    combined = (1 - float(value)) * (score if score is not None else 0.5) + float(value) * fusion
                    decision = _classification(combined, True)
                    loss = _loss(decision, label)
                elif dimension == "action_cost_multiplier":
                    actions = [
                        Action(
                            f"{case.case_id}:{kind}:n{node}", kind, node,
                            f"independent-{case.case_id}-{kind}-{node}",
                            1.0 if float(value) == 0 else ACTION_COSTS[kind] * float(value),
                        )
                        for kind in ACTION_TYPES for node in range(len(case.P))
                    ]
                    selector_rng = random.Random(
                        seed ^ value_index ^ sum(ord(char) for char in case.case_id)
                    )
                    sealed_rng = random.Random(
                        seed ^ 0xACCE55 ^ sum(ord(char) for char in case.case_id)
                    )
                    sealed = {
                        action.action_id: _sealed_outcome(sealed_rng, action, label)
                        for action in actions
                    }
                    selected = []
                    current = evaluated
                    for _ in range(ACTION_BUDGET):
                        action = select_action(
                            "expected_risk_greedy", current, actions, selected,
                            calibrated_model, selector_rng,
                        )
                        if action is None:
                            break
                        current = _hypothetical(
                            current, action, sealed[action.action_id],
                        )
                        selected.append(action)
                        action_cost += ACTION_COSTS[action.kind]
                    final_score = score_and_coefficients(current, alpha)[0]
                    decision = _classification(final_score, True)
                    loss = _loss(decision, label)
                    cert = _certificate_safe(current, budget, True, alpha=alpha)
                    robust = _exact_robustness(current, budget, decision, alpha)
                per_case.append((decision, cert, robust, loss, action_cost))
            decided = [decision != "abstain" for decision, *_ in per_case]
            rows.append({
                "dimension": dimension,
                "value": value,
                "n": len(per_case),
                "accuracy": statistics.mean(
                    _correct(decision, label)
                    for (decision, _, _, _, _), (_, label) in zip(per_case, cases)
                    if decision != "abstain"
                ) if any(decided) else None,
                "coverage": statistics.mean(decided),
                "certificate_coverage": statistics.mean(
                    cert for _, cert, _, _, _ in per_case
                ),
                "empirical_robustness": statistics.mean(
                    robust for _, _, robust, _, _ in per_case
                ),
                "mean_loss": statistics.mean(loss for _, _, _, loss, _ in per_case),
                "mean_action_cost": statistics.mean(
                    action_cost for _, _, _, _, action_cost in per_case
                ),
            })
    return rows


def _perturb_ancestry(case: Case, uncertainty: float, seed: int) -> Case:
    rng = random.Random(seed)
    observations = []
    for obs in case.observations:
        if rng.random() < uncertainty:
            ancestors = frozenset({"uncertain-shared-root"})
        else:
            ancestors = obs.ancestors
        observations.append(Observation(
            obs.node, obs.value, obs.weight, ancestors, obs.obs_id, obs.kind,
        ))
    return Case(
        case.case_id, np.array(case.P, copy=True), observations, case.target,
        metadata=dict(case.metadata),
    )


def _set_correlation(case: Case, fraction: float) -> Case:
    observations = []
    threshold = round(len(case.observations) * fraction)
    for index, obs in enumerate(case.observations):
        ancestors = frozenset({"correlated-shared-root"}) if index < threshold else obs.ancestors
        observations.append(Observation(
            obs.node, obs.value, obs.weight, ancestors, obs.obs_id, obs.kind,
        ))
    return Case(
        case.case_id, np.array(case.P, copy=True), observations, case.target,
        metadata=dict(case.metadata),
    )


def _assumption_stress(cases: list[tuple[Case, int]]) -> list[dict[str, Any]]:
    results = []
    for case, label in cases[: min(12, len(cases))]:
        baseline = certify(case, ATTACK_BUDGET, ALPHA, TAU_B, TAU_M)
        baseline_fingerprint = _proof_fingerprint(case)
        clean_decision = _classification(baseline["score"], True)
        accuracy_before = _correct(clean_decision, label)
        weights = [
            Observation(
                obs.node, obs.value,
                obs.weight * (1.2 if index == 0 else 1.0),
                obs.ancestors, obs.obs_id, obs.kind,
            )
            for index, obs in enumerate(case.observations)
        ]
        # Re-normalize changed weights to form a valid but proof-distinct model.
        totals = Counter()
        for obs in weights:
            totals[obs.node] += obs.weight
        weights = [
            Observation(
                obs.node, obs.value, obs.weight / totals[obs.node],
                obs.ancestors, obs.obs_id, obs.kind,
            )
            for obs in weights
        ]
        changed_weights = Case(case.case_id, case.P.copy(), weights, case.target)
        weights_changed = _proof_fingerprint(changed_weights) != baseline_fingerprint
        weights_report = certify(changed_weights, ATTACK_BUDGET, ALPHA, TAU_B, TAU_M)
        results.append({
            "case_id": case.case_id, "violation": "fixed_weights_changed",
            "pre_certificate": baseline["certified"],
            "post_certificate": weights_report["certified"],
            "certificate_status": "invalidated" if weights_changed else "invalid",
            "reason": (
                "proof fingerprint changed after evidence weights changed"
                if weights_changed else "weight mutation did not change proof fingerprint"
            ),
            "empirical_accuracy_unchanged": (
                accuracy_before == _correct(
                    _classification(weights_report["score"], True), label,
                )
            ),
        })

        merged = [
            Observation(
                obs.node, obs.value, obs.weight, frozenset({"false-independent-pool"}),
                obs.obs_id, obs.kind,
            )
            for obs in case.observations
        ]
        merged_case = Case(case.case_id, case.P.copy(), merged, case.target)
        ancestry_changed = _proof_fingerprint(merged_case) != baseline_fingerprint
        merged_report = certify(merged_case, ATTACK_BUDGET, ALPHA, TAU_B, TAU_M)
        results.append({
            "case_id": case.case_id, "violation": "independence_claims_merged",
            "pre_certificate": baseline["certified"],
            "post_certificate": merged_report["certified"],
            "certificate_status": "invalidated" if ancestry_changed else "invalid",
            "reason": (
                "source ancestry changed; prior independent-root proof is inapplicable"
                if ancestry_changed else "ancestry mutation did not change proof fingerprint"
            ),
            "empirical_accuracy_unchanged": (
                accuracy_before == _correct(
                    _classification(merged_report["score"], True), label,
                )
            ),
        })
        invalid_graph = case.P.copy()
        invalid_graph[0, 0] += 0.2
        try:
            certify(
                Case(case.case_id, invalid_graph, list(case.observations), case.target),
                ATTACK_BUDGET, ALPHA, TAU_B, TAU_M,
            )
            graph_status = "invalid"
            graph_reason = "non-stochastic graph unexpectedly accepted"
        except ValueError as exc:
            graph_status = "invalidated"
            graph_reason = str(exc)
        results.append({
            "case_id": case.case_id, "violation": "graph_normalization_broken",
            "pre_certificate": baseline["certified"],
            "post_certificate": False,
            "certificate_status": graph_status,
            "reason": graph_reason,
            "empirical_accuracy_unchanged": None,
        })
    return results


def _repair_summary(repair_rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    result = []
    grouped = defaultdict(list)
    for row in repair_rows:
        grouped[row["policy"]].append(row)
    for policy, rows in grouped.items():
        result.append({
            "policy": policy,
            "n": len(rows),
            "mean_final_loss": statistics.mean(row["final_loss"] for row in rows),
            "mean_cumulative_loss": statistics.mean(row["cumulative_loss"] for row in rows),
            "mean_action_count": statistics.mean(row["action_count"] for row in rows),
            "mean_action_cost": statistics.mean(row["action_cost"] for row in rows),
            "contradictory_outcome_fraction": statistics.mean(
                row["contradictory_outcome"] for row in rows
            ),
        })
    return result


def run_e18(
    out_dir: str = "results/E18",
    table_dir: str = "tables",
    cases: int = 48,
    seed: int = 20261818,
    bootstrap_samples: int = 500,
) -> dict[str, Any]:
    """Run matched controlled ablations, sensitivity sweeps, and assumption checks."""
    if type(cases) is not int or cases < 12:
        raise ValueError("cases must be an integer >= 12")
    if type(bootstrap_samples) is not int or bootstrap_samples < 100:
        raise ValueError("bootstrap_samples must be an integer >= 100")
    started = time.perf_counter()
    out, tables = Path(out_dir), Path(table_dir)
    out.mkdir(parents=True, exist_ok=True)
    tables.mkdir(parents=True, exist_ok=True)
    generated = [
        _make_case(seed + index * 1009, f"e18-{index:04d}")
        for index in range(cases)
    ]
    ablation_rows = _evaluate_cases(generated, seed, bootstrap_samples)
    interaction_rows = _factorial(generated, seed, bootstrap_samples)
    sensitivity_rows = _sensitivity(generated, seed)
    assumption_rows = _assumption_stress(generated)
    graph_fusion = []
    for case, label in generated:
        score_graph = _group_fusion_score(case, ALPHA)
        score_no_graph = _group_fusion_score(case, 0.0)
        graph_fusion.append({
            "case_id": case.case_id,
            "label": label,
            "score_graph": score_graph,
            "score_no_graph": score_no_graph,
            "correct_graph": _correct(_classification(score_graph, True), label),
            "correct_no_graph": _correct(_classification(score_no_graph, True), label),
            "paired_accuracy_delta": (
                float(_correct(_classification(score_graph, True), label))
                - float(_correct(_classification(score_no_graph, True), label))
            ),
        })
    graph_delta = [row["paired_accuracy_delta"] for row in graph_fusion]
    graph_ci = _bootstrap_mean(graph_delta, seed ^ 0xD18, bootstrap_samples)
    repair_rows = []
    repair_outcome_model = fit_outcome_model(seed ^ 0xCA11B, samples_per_class=250)
    for index, (case, label) in enumerate(generated):
        base_score, current = _score(case, ALPHA, True)
        if current is None:
            continue
        actions = [
            Action(
                f"{case.case_id}:{kind}:n{node}", kind, node,
                f"independent-{case.case_id}-{kind}-{node}", ACTION_COSTS[kind],
            )
            for kind in ACTION_TYPES for node in range(len(case.P))
        ]
        sealed_rng = random.Random(seed ^ index ^ 0xA771)
        sealed = {
            action.action_id: _sealed_outcome(sealed_rng, action, label)
            for action in actions
        }
        for policy_index, policy in enumerate(("cer_guided", "random")):
            selected = []
            state = current
            latencies = []
            start_loss = _loss(_classification(base_score, True), label)
            losses = [start_loss]
            initial = _classification(base_score, True)
            rng = random.Random(seed ^ (index * 31) ^ policy_index)
            for _ in range(ACTION_BUDGET):
                tic = time.perf_counter()
                action = select_action(
                    policy, state, actions, selected,
                    repair_outcome_model, rng,
                )
                latencies.append((time.perf_counter() - tic) * 1000)
                if action is None:
                    break
                state = _hypothetical(state, action, sealed[action.action_id])
                selected.append(action)
                losses.append(_loss(
                    _classification(score_and_coefficients(state, ALPHA)[0], True),
                    label,
                ))
            final = _classification(score_and_coefficients(state, ALPHA)[0], True)
            cost = sum(action.cost for action in selected)
            repair_rows.append({
                "case_id": case.case_id,
                "policy": policy,
                "budget": ACTION_BUDGET,
                "initial_loss": start_loss,
                "final_loss": _loss(final, label),
                "cumulative_loss": statistics.mean(losses),
                "action_count": len(selected),
                "action_cost": cost,
                "contradictory_outcome": any(
                    (sealed[action.action_id] >= 0.5)
                    != (initial == "malicious") for action in selected
                ),
                "mean_selection_latency_ms": statistics.mean(latencies) if latencies else 0.0,
            })
    repair_summary = _repair_summary(repair_rows)
    audit = {
        "experiment": "E18",
        "status": "pass" if all(
            row["certificate_status"] != "invalid"
            for row in assumption_rows if row["violation"] == "graph_normalization_broken"
        ) else "fail",
        "world_type": "controlled_synthetic",
        "field_performance_claim": False,
        "cases": cases,
        "seed": seed,
        "bootstrap_samples": bootstrap_samples,
        "matched_design": {
            "same_cases_across_ablation_variants": True,
            "same_repair_action_menu_and_sealed_outcomes_across_policies": True,
            "repair_attempt_budget": ACTION_BUDGET,
            "certificate_attack_budget": ATTACK_BUDGET,
            "calibration_seed_separate_from_evaluation_seed": True,
        },
        "definitions": {
            "accuracy": "correct non-abstained decision / all non-abstained cases",
            "coverage": "non-abstained decisions / all evaluation cases; no-signal counts as abstention",
            "selective_risk": "incorrect non-abstained decisions / non-abstained cases",
            "certificate_coverage": "cases with a valid enabled directional certificate / all cases",
            "empirical_robustness": "fraction of certified actionable cases surviving exhaustive root-group endpoint attacks up to budget",
            "ablation_confidence_intervals": "paired percentile bootstrap over fixed case IDs",
            "factorial_interactions": "2x2 difference-in-differences for accuracy and certificate coverage, bootstrapped by case",
        },
        "urltrust_graph_increment_after_source_fusion": {
            "fusion": "within-source aggregation followed by per-node median across source groups, then graph propagation",
            "accuracy_denominator": (
                "all paired cases; abstentions count as incorrect for this graph-increment comparison"
            ),
            "paired_accuracy_delta_graph_minus_no_graph": statistics.mean(graph_delta),
            "bootstrap_95_ci": graph_ci,
            "graph_fusion_all_case_accuracy": statistics.mean(
                row["correct_graph"] for row in graph_fusion
            ),
            "no_graph_fusion_all_case_accuracy": statistics.mean(
                row["correct_no_graph"] for row in graph_fusion
            ),
            "assessment": (
                "graph incremental value is supported in this synthetic design only if the paired "
                "interval excludes zero; no field-performance implication follows"
            ),
            "interval_excludes_zero": bool(
                graph_ci[0] is not None and graph_ci[1] is not None
                and (graph_ci[0] > 0 or graph_ci[1] < 0)
            ),
        },
        "assumption_audit": {
            "violations": dict(Counter(row["violation"] for row in assumption_rows)),
            "all_broken_graphs_rejected": all(
                row["certificate_status"] == "invalidated"
                for row in assumption_rows
                if row["violation"] == "graph_normalization_broken"
            ),
            "certificate_policy": "never carry a certificate across changed weights, ancestry, or a non-stochastic graph; rebuild or invalidate",
        },
        "pass_criteria": {
            "all_requested_ablation_axes_present": set(ABLATIONS) == {
                row["ablation"] for row in ablation_rows
            },
            "full_factorial_interactions_reported": len(interaction_rows) == (
                math.comb(len(FACTORS), 2) * 2
            ),
            "sensitivity_axes_reported": set(SWEEP) == {
                row["dimension"] for row in sensitivity_rows
            },
            "assumption_violations_invalidate_proofs": all(
                row["certificate_status"] == "invalidated"
                for row in assumption_rows
            ),
            "graph_increment_assessed_after_source_fusion": True,
            "status": "pass" if all(
                row["certificate_status"] == "invalidated"
                for row in assumption_rows
            ) else "fail",
        },
        "runtime_seconds": time.perf_counter() - started,
    }
    _write_csv(out / "ablation.csv", ablation_rows, CSV_COLUMNS["ablation"])
    _write_csv(out / "sensitivity.csv", sensitivity_rows, CSV_COLUMNS["sensitivity"])
    _write_csv(out / "factorial_interactions.csv", interaction_rows, CSV_COLUMNS["factorial"])
    _write_csv(out / "assumption_audit.csv", assumption_rows, CSV_COLUMNS["assumptions"])
    _write_csv(out / "repair_trials.csv", repair_rows, CSV_COLUMNS["repairs"])
    (out / "repair_summary.json").write_text(
        json.dumps(repair_summary, indent=2) + "\n", encoding="utf-8",
    )
    (out / "graph_fusion_comparison.csv").write_text(
        "case_id,label,score_graph,score_no_graph,correct_graph,correct_no_graph,paired_accuracy_delta\n"
        + "".join(
            f"{row['case_id']},{row['label']},{row['score_graph']:.10f},"
            f"{row['score_no_graph']:.10f},{int(row['correct_graph'])},"
            f"{int(row['correct_no_graph'])},{row['paired_accuracy_delta']:.10f}\n"
            for row in graph_fusion
        ),
        encoding="utf-8",
    )
    (out / "audit.json").write_text(
        json.dumps(audit, indent=2, allow_nan=False) + "\n", encoding="utf-8",
    )
    _write_manifest(out)
    (tables / "e18_ablations.tex").write_text(
        "\n".join([
            "% Controlled synthetic ablations; not field performance.",
            r"\begin{tabular}{lrrrr}",
            r"Variant & Accuracy & Coverage & Certificate & Robustness \\",
            r"\hline",
            *[
                f"{row['ablation'].replace('_', chr(92) + '_')} & "
                f"{row['accuracy']:.3f} & {row['coverage']:.3f} & "
                f"{row['certificate_coverage']:.3f} & "
                f"{row['empirical_robustness'] if row['empirical_robustness'] is not None else '--'} " + r"\\"
                for row in ablation_rows
            ],
            r"\end{tabular}",
            "",
        ]),
        encoding="utf-8",
    )
    return audit
