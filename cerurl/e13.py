"""E13: matched-budget repair action selection in controlled synthetic cases."""
from __future__ import annotations

import csv
import hashlib
import json
import random
import time
from dataclasses import dataclass
from pathlib import Path

import numpy as np

from .core import Case, Observation, add_observation, certify, score_and_coefficients

POLICIES = ("no_repair", "random", "uncertainty", "disagreement",
           "independent_diversity", "expected_risk_greedy", "cer_guided")
DEFAULT_BUDGETS = (0, 1, 2, 3, 5, 10)
ACTION_TYPES = ("network_vantage", "dns_second_measurement", "archived_html",
                "redirect_inspection", "source_verification", "signed_feed")
ALPHA, TAU_B, TAU_M = 0.35, 0.40, 0.60
NEW_WEIGHT = 0.30
ABSTAIN_LOSS = 0.5
FP_COST, FN_COST = 1.0, 5.0
ACTION_COSTS = {
    "network_vantage": 0.30, "dns_second_measurement": 0.12,
    "archived_html": 0.22, "redirect_inspection": 0.18,
    "source_verification": 0.15, "signed_feed": 0.10,
}
RELIABILITY = {
    "network_vantage": 0.84, "dns_second_measurement": 0.78,
    "archived_html": 0.86, "redirect_inspection": 0.76,
    "source_verification": 0.91, "signed_feed": 0.88,
}


@dataclass(frozen=True)
class Action:
    action_id: str
    kind: str
    node: int
    root: str
    cost: float


def _verdict(value: float) -> str:
    if value >= TAU_M:
        return "malicious"
    if value <= TAU_B:
        return "benign"
    return "abstain"


def _decision(case: Case) -> str:
    return _verdict(score_and_coefficients(case, ALPHA)[0])


def fit_outcome_model(seed: int, samples_per_class: int = 600) -> dict:
    """Estimate action likelihoods on an independent synthetic calibration pool."""
    if type(samples_per_class) is not int or samples_per_class < 1:
        raise ValueError("samples_per_class must be a positive integer")
    rng = random.Random(seed)
    counts = {kind: {0: [1, 1], 1: [1, 1]} for kind in ACTION_TYPES}
    for kind in ACTION_TYPES:
        for label in (0, 1):
            for _ in range(samples_per_class):
                correct = rng.random() < RELIABILITY[kind]
                observed = label if correct else 1 - label
                counts[kind][label][observed] += 1
    return {
        kind: {
            label: [count / sum(pair) for count in counts[kind][label]]
            for label, pair in counts[kind].items()
        }
        for kind in ACTION_TYPES
    }


def _make_case(rng: random.Random, case_id: str) -> tuple[Case, dict, list[Action]]:
    node_count, group_count = 4, 6
    label = rng.randrange(2)
    compromised = f"root-{rng.randrange(group_count)}"
    weights = {root: (0.72 if root == compromised else 0.28 / (group_count - 1))
               for root in (f"root-{i}" for i in range(group_count))}
    graph = np.zeros((node_count, node_count), dtype=float)
    for node in range(node_count):
        graph[node, node] = 0.65
        graph[node, (node + 1) % node_count] = 0.35
    obs = []
    for node in range(node_count):
        for group in range(group_count):
            root = f"root-{group}"
            if root == compromised:
                observed_label = 1 - label
            else:
                observed_label = label if rng.random() < 0.96 else 1 - label
            value = float(np.clip((0.92 if observed_label else 0.08) + rng.uniform(-0.015, 0.015), 0, 1))
            obs.append(Observation(node, value, weights[root], frozenset({root}),
                                   f"{case_id}-base-{node}-{group}", "feed"))
    case = Case(case_id, graph, obs, 0, None, world_type="controlled_synthetic")
    actions = [
        Action(f"{case_id}:{kind}:n{node}", kind, node,
               f"independent-{case_id}-{kind}-{node}", ACTION_COSTS[kind])
        for kind in ACTION_TYPES for node in range(node_count)
    ]
    truth = {"label": label, "compromised_root": compromised}
    return case, truth, actions


def _p_malicious_from_score(value: float) -> float:
    return float(np.clip(value, 0.05, 0.95))


def outcome_distribution(case: Case, action: Action, model: dict) -> tuple[float, float]:
    """Return probabilities for low/high reports using observed score + calibration only."""
    score = score_and_coefficients(case, ALPHA)[0]
    p_malicious = _p_malicious_from_score(score)
    p_high_given_benign = model[action.kind][0][1]
    p_high_given_malicious = model[action.kind][1][1]
    p_high = p_malicious * p_high_given_malicious + (1 - p_malicious) * p_high_given_benign
    return 1 - p_high, p_high


def _hypothetical(case: Case, action: Action, value: float) -> Case:
    candidate = Observation(action.node, value, 0.0, frozenset({action.root}),
                            action.action_id, action.kind)
    return add_observation(case, candidate, NEW_WEIGHT)


def _risk(case: Case) -> float:
    value = score_and_coefficients(case, ALPHA)[0]
    label_probability = _p_malicious_from_score(value)
    decision = _verdict(value)
    if decision == "malicious":
        return FN_COST * (1 - label_probability)
    if decision == "benign":
        return FP_COST * label_probability
    return ABSTAIN_LOSS


def _certificate_utility(report: dict) -> float:
    if report["verdict"] == "malicious":
        return report["lower_bound"] - report["tau_m"]
    if report["verdict"] == "benign":
        return report["tau_b"] - report["upper_bound"]
    return -ABSTAIN_LOSS - min(abs(report["score"] - report["tau_b"]),
                               abs(report["score"] - report["tau_m"]))


def _node_disagreement(case: Case, node: int) -> float:
    values = [obs.value for obs in case.observations if obs.node == node]
    return float(np.std(values)) if len(values) > 1 else 0.0


def select_action(policy: str, case: Case, actions: list[Action], selected: list[Action],
                  outcome_model: dict, rng: random.Random) -> Action | None:
    """Selectors receive public evidence and calibrated outcomes, never sealed outcomes."""
    if policy not in POLICIES:
        raise ValueError(f"Unknown E13 policy: {policy}")
    if policy == "no_repair":
        return None
    remaining = [action for action in actions if action not in selected]
    if not remaining:
        return None
    if policy == "random":
        return rng.choice(remaining)

    _, _, node_scores = score_and_coefficients(case, ALPHA)
    current_risk = _risk(case)
    current_cert = certify(case, 1, ALPHA, TAU_B, TAU_M)
    current_cert_utility = _certificate_utility(current_cert)
    used_kinds = {action.kind for action in selected}
    used_nodes = {action.node for action in selected}
    ranked = []
    for action in remaining:
        low_prob, high_prob = outcome_distribution(case, action, outcome_model)
        low_case = _hypothetical(case, action, 0.08)
        high_case = _hypothetical(case, action, 0.92)
        if policy == "uncertainty":
            priority = -abs(float(node_scores[action.node]) - 0.5)
        elif policy == "disagreement":
            priority = _node_disagreement(case, action.node)
        elif policy == "independent_diversity":
            priority = 2.0 * float(action.root not in {
                root for observation in case.observations for root in observation.ancestors
            }) + float(action.kind not in used_kinds) + 0.5 * float(action.node not in used_nodes)
        elif policy == "expected_risk_greedy":
            expected_risk = low_prob * _risk(low_case) + high_prob * _risk(high_case)
            priority = current_risk - expected_risk
        elif policy == "cer_guided":
            low_utility = _certificate_utility(certify(low_case, 1, ALPHA, TAU_B, TAU_M))
            high_utility = _certificate_utility(certify(high_case, 1, ALPHA, TAU_B, TAU_M))
            priority = low_prob * low_utility + high_prob * high_utility - current_cert_utility
        else:
            raise ValueError(f"Unsupported E13 policy: {policy}")
        ranked.append((priority / action.cost, -actions.index(action), action))
    return max(ranked, key=lambda row: (row[0], row[1]))[2]


def _sealed_outcome(rng: random.Random, action: Action, label: int) -> float:
    correct = rng.random() < RELIABILITY[action.kind]
    observed_label = label if correct else 1 - label
    return float(0.92 if observed_label else 0.08)


def _classification_loss(decision: str, label: int) -> float:
    if decision == "abstain":
        return ABSTAIN_LOSS
    if decision == "malicious" and label == 0:
        return FP_COST
    if decision == "benign" and label == 1:
        return FN_COST
    return 0.0


def _bootstrap_mean_ci(values: list[float], rng: random.Random, samples: int = 1000) -> list[float] | None:
    if not values:
        return None
    if len(values) == 1:
        return [values[0], values[0]]
    means = [sum(rng.choices(values, k=len(values))) / len(values) for _ in range(samples)]
    return [float(np.percentile(means, 2.5)), float(np.percentile(means, 97.5))]


def _write_csv(path: Path, rows: list[dict]) -> None:
    if not rows:
        path.write_text("", encoding="utf-8")
        return
    with path.open("w", encoding="utf-8", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)


def run_e13(out_dir="results/E13", table_dir="tables", cases=40, repeats=3,
            seed=20261313, budgets=DEFAULT_BUDGETS) -> dict:
    if type(cases) is not int or cases < 1:
        raise ValueError("cases must be a positive integer")
    if type(repeats) is not int or repeats < 1:
        raise ValueError("repeats must be a positive integer")
    budgets = tuple(budgets)
    if (not budgets or any(type(value) is not int or value < 0 for value in budgets)
            or len(set(budgets)) != len(budgets) or tuple(sorted(budgets)) != budgets):
        raise ValueError("budgets must be distinct, nonnegative integers in ascending order")
    if max(budgets) > len(ACTION_TYPES) * 4:
        raise ValueError("largest attempt budget exceeds the shared action-menu size")
    out, tables = Path(out_dir), Path(table_dir)
    out.mkdir(parents=True, exist_ok=True)
    tables.mkdir(parents=True, exist_ok=True)
    for name in ("audit.json", "manifest_sha256.json", "trial_results.csv", "summary.csv",
                 "paired_comparisons.csv", "chosen_actions.jsonl", "policy_action_counts.csv"):
        (out / name).unlink(missing_ok=True)
    (tables / "e13_repair.tex").unlink(missing_ok=True)

    started = time.perf_counter()
    outcome_model = fit_outcome_model(seed ^ 0xCA11B, samples_per_class=600)
    trials: list[dict] = []
    action_log: list[dict] = []
    for repeat in range(repeats):
        for case_index in range(cases):
            case_seed = seed + repeat * 100_003 + case_index * 1009
            case_rng = random.Random(case_seed)
            case, hidden, actions = _make_case(case_rng, f"e13-r{repeat}-c{case_index}")
            initial_decision = _decision(case)
            if initial_decision == "abstain" or initial_decision == ("malicious" if hidden["label"] else "benign"):
                raise AssertionError("Controlled source attack failed to create an initially wrong actionable decision")
            # Sealed outcomes are generated independently and are unavailable to selectors.
            outcome_rng = random.Random(case_seed ^ 0x0A771)
            sealed = {action.action_id: _sealed_outcome(outcome_rng, action, hidden["label"])
                      for action in actions}
            trajectories = {}
            for policy_index, policy in enumerate(POLICIES):
                current = case
                selected: list[Action] = []
                trajectory = []
                selector_rng = random.Random(case_seed ^ (policy_index * 0xE13))
                for step in range(max(budgets, default=0)):
                    selection_started = time.perf_counter()
                    action = select_action(policy, current, actions, selected, outcome_model, selector_rng)
                    selection_latency_ms = (time.perf_counter() - selection_started) * 1000
                    if action is None:
                        break
                    # Reveal only after selection; this is the experiment executor boundary.
                    observed_value = sealed[action.action_id]
                    current = _hypothetical(current, action, observed_value)
                    selected.append(action)
                    report = certify(current, 1, ALPHA, TAU_B, TAU_M)
                    trajectory.append({
                        "action": action, "observed_value": observed_value,
                        "decision": _decision(current),                         "certified": bool(report["certified"]),
                        "loss": _classification_loss(_decision(current), hidden["label"]),
                        "selection_latency_ms": selection_latency_ms,
                        "contradicts_initial": (
                            observed_value >= 0.5 if initial_decision == "benign"
                            else observed_value < 0.5),
                    })
                trajectories[policy] = (case, hidden, initial_decision, selected, trajectory)

            for policy in POLICIES:
                _, _, _, selected, trajectory = trajectories[policy]
                for budget in budgets:
                    prefix = trajectory[:budget]
                    final_decision = prefix[-1]["decision"] if prefix else initial_decision
                    final_certified = prefix[-1]["certified"] if prefix else bool(
                        certify(case, 1, ALPHA, TAU_B, TAU_M)["certified"])
                    final_loss = _classification_loss(final_decision, hidden["label"])
                    # Expected loss is estimated from the calibrated outcome model,
                    # not from the sealed observations or the evaluation label.
                    expected_curve = [_risk(case)]
                    public_state = case
                    for item in trajectory[:budget]:
                        action = item["action"]
                        low_prob, high_prob = outcome_distribution(public_state, action, outcome_model)
                        expected_curve.append(
                            low_prob * _risk(_hypothetical(public_state, action, 0.08))
                            + high_prob * _risk(_hypothetical(public_state, action, 0.92))
                        )
                        public_state = _hypothetical(public_state, action, item["observed_value"])
                    actual_curve = [_classification_loss(initial_decision, hidden["label"])]
                    actual_curve.extend(item["loss"] for item in prefix)
                    while len(actual_curve) < budget + 1:
                        actual_curve.append(actual_curve[-1])
                    while len(expected_curve) < budget + 1:
                        expected_curve.append(expected_curve[-1])
                    contradiction_count = sum(item["contradicts_initial"] for item in prefix)
                    trial = {
                        "repeat": repeat, "case_id": case.case_id, "policy": policy, "budget": budget,
                        "initial_decision": initial_decision, "final_decision": final_decision,
                        "truth_for_evaluation_only": hidden["label"], "initial_loss": actual_curve[0],
                        "final_actual_loss": final_loss, "cumulative_actual_loss": sum(actual_curve),
                        "cumulative_expected_loss": sum(expected_curve[:len(prefix) + 1]),
                        "certified_before": bool(certify(case, 1, ALPHA, TAU_B, TAU_M)["certified"]),
                        "certified_after": final_certified,
                        "certified_coverage_gain": int(final_certified) - int(
                            certify(case, 1, ALPHA, TAU_B, TAU_M)["certified"]),
                        "action_count": len(prefix), "money_cost": sum(a.cost for a in selected[:budget]),
                        "unresolved": final_decision == "abstain" or not final_certified,
                        "extra_evidence_contradicted_initial": contradiction_count > 0,
                        "contradictory_action_count": contradiction_count,
                        "attempt_latency_ms": sum(item["selection_latency_ms"] for item in prefix),
                    }
                    trials.append(trial)
                for step, item in enumerate(trajectory, start=1):
                    action_log.append({
                        "repeat": repeat, "case_id": case.case_id, "policy": policy,
                        "step": step, "action_id": item["action"].action_id,
                        "action_type": item["action"].kind, "node": item["action"].node,
                        "cost": item["action"].cost, "observed_value": item["observed_value"],
                        "contradicts_initial": item["contradicts_initial"],
                        "selection_latency_ms": item["selection_latency_ms"],
                    })

    paired = []
    lookup = {(row["repeat"], row["case_id"], row["budget"], row["policy"]): row for row in trials}
    for row in trials:
        if row["policy"] == "no_repair":
            continue
        baseline = lookup[row["repeat"], row["case_id"], row["budget"], "no_repair"]
        paired.append({
            "repeat": row["repeat"], "case_id": row["case_id"], "budget": row["budget"],
            "policy": row["policy"], "reference": "no_repair",
            "actual_loss_delta": row["final_actual_loss"] - baseline["final_actual_loss"],
            "cumulative_actual_loss_delta": row["cumulative_actual_loss"] - baseline["cumulative_actual_loss"],
            "expected_loss_delta": row["cumulative_expected_loss"] - baseline["cumulative_expected_loss"],
            "certified_coverage_gain_delta": row["certified_coverage_gain"] - baseline["certified_coverage_gain"],
            "contradictory": row["extra_evidence_contradicted_initial"],
        })

    paired_summary = []
    ci_rng = random.Random(seed ^ 0xC1)
    for policy in POLICIES:
        if policy == "no_repair":
            continue
        for budget in budgets:
            rows = [row for row in paired if row["policy"] == policy and row["budget"] == budget]
            for condition, selected_rows in (
                ("all", rows),
                ("contradictory", [r for r in rows if r["contradictory"]]),
            ):
                values = [r["actual_loss_delta"] for r in selected_rows]
                expected = [r["expected_loss_delta"] for r in selected_rows]
                paired_summary.append({
                    "policy": policy, "budget": budget, "condition": condition,
                    "pairs": len(selected_rows),
                    "actual_loss_delta_mean": float(np.mean(values)) if values else None,
                    "actual_loss_delta_ci95": _bootstrap_mean_ci(values, ci_rng),
                    "expected_loss_delta_mean": float(np.mean(expected)) if expected else None,
                    "expected_loss_delta_ci95": _bootstrap_mean_ci(expected, ci_rng),
                })

    summary = []
    for policy in POLICIES:
        for budget in budgets:
            rows = [row for row in trials if row["policy"] == policy and row["budget"] == budget]
            summary.append({
                "policy": policy, "budget": budget, "trials": len(rows),
                "mean_final_actual_loss": float(np.mean([r["final_actual_loss"] for r in rows])),
                "mean_cumulative_actual_loss": float(np.mean([r["cumulative_actual_loss"] for r in rows])),
                "mean_cumulative_expected_loss": float(np.mean([r["cumulative_expected_loss"] for r in rows])),
                "mean_certified_coverage_gain": float(np.mean([r["certified_coverage_gain"] for r in rows])),
                "mean_action_count": float(np.mean([r["action_count"] for r in rows])),
                "mean_money_cost": float(np.mean([r["money_cost"] for r in rows])),
                "unresolved": sum(r["unresolved"] for r in rows),
                "contradictory_trials": sum(r["extra_evidence_contradicted_initial"] for r in rows),
                "mean_attempt_latency_ms": float(np.mean([
                    row["attempt_latency_ms"] for row in rows
                ])),
            })
    counts = {}
    for policy in POLICIES:
        for kind in ACTION_TYPES:
            counts[policy, kind] = sum(row["action_type"] == kind and row["policy"] == policy
                                       for row in action_log)
    action_counts = [{"policy": policy, "action_type": kind, "selected": counts[policy, kind]}
                     for policy in POLICIES for kind in ACTION_TYPES]

    cer_rows = [r for r in paired_summary if r["policy"] == "cer_guided" and r["condition"] in ("all", "contradictory")]
    efficacy = {}
    for condition in ("all", "contradictory"):
        rows = [row for row in cer_rows
                if row["condition"] == condition and row["budget"] > 0 and row["pairs"] > 0]
        efficacy[condition] = bool(rows) and all(
            row["actual_loss_delta_ci95"] is not None and row["actual_loss_delta_ci95"][1] < 0
            for row in rows
        )
    fairness = all(action.cost == ACTION_COSTS[action.kind]
                    for _, _, actions in [_make_case(random.Random(seed), "fairness")]
                    for action in actions)
    protocol_pass = (fairness and len(trials) == repeats * cases * len(POLICIES) * len(budgets)
                    and all(row["action_count"] <= row["budget"] for row in trials))
    audit = {
        "audit_version": "E13-1", "seed": seed, "cases_per_repeat": cases, "repeats": repeats,
        "budgets": list(budgets), "policies": list(POLICIES), "action_types": list(ACTION_TYPES),
        "shared_action_menu": True, "shared_action_prices": dict(ACTION_COSTS),
        "shared_outcome_model": "synthetic training/calibration likelihoods, independent of evaluation labels/outcomes",
        "selector_access": "observed evidence, remaining public actions, acquisition prices, calibration outcome model; never sealed outcome or evaluation truth",
        "sealed_outcome_access": "execution layer reveals an outcome only after action selection",
        "expected_loss_definition": "calibration-model risk accumulated at baseline and each post-action hypothetical state",
        "actual_loss_definition": "weighted false-negative/false-positive/abstention loss accumulated at baseline and each observed post-action state",
        "certificate_definition": "core source-group certificate with compromise budget 1; stability is not correctness",
        "runtime_seconds": time.perf_counter() - started, "trial_count": len(trials),
        "summary": summary, "paired_summary": paired_summary,
        "policy_action_counts": action_counts, "efficacy": efficacy,
        "pass_criteria": {
            "protocol_status": "pass" if protocol_pass else "fail",
            "matched_menu_prices_outcomes_and_budget": protocol_pass,
            "cer_improvement_all_trials": efficacy["all"],
            "cer_improvement_when_evidence_contradicts_initial": efficacy["contradictory"],
            "status": "pass" if protocol_pass and all(efficacy.values()) else "fail",
        },
        "limitations": [
            "All data and calibration estimates are controlled synthetic fixtures, not field performance.",
            "Certified coverage means robustness to the declared source-group threat model, not label correctness.",
            "Paired bootstrap intervals are descriptive and resample paired case deltas within each budget.",
        ],
    }
    _write_csv(out / "trial_results.csv", trials)
    _write_csv(out / "paired_comparisons.csv", paired)
    _write_csv(out / "policy_action_counts.csv", action_counts)
    with (out / "chosen_actions.jsonl").open("w", encoding="utf-8") as stream:
        for row in action_log:
            stream.write(json.dumps(row, sort_keys=True, allow_nan=False) + "\n")
    (out / "audit.json").write_text(json.dumps(audit, indent=2, allow_nan=False), encoding="utf-8")
    table = ["% Controlled synthetic outcomes; E13 CER efficacy is judged on paired loss intervals.",
             r"\begin{tabular}{lrrrr}", r"Policy & Budget & Final loss & Cert. gain & Cost \\", r"\hline"]
    for row in summary:
        policy_name = row["policy"].replace("_", r"\_")
        table.append(f"{policy_name} & {row['budget']} & "
                     f"{row['mean_final_actual_loss']:.3f} & {row['mean_certified_coverage_gain']:.3f} & "
                     f"{row['mean_money_cost']:.3f} " + r"\\")
    table.extend([r"\end{tabular}", ""])
    (tables / "e13_repair.tex").write_text("\n".join(table), encoding="utf-8")
    _write_csv(out / "summary.csv", summary)
    files = [path for path in out.rglob("*") if path.is_file() and path.name != "manifest_sha256.json"]
    manifest = {str(path.relative_to(out)): hashlib.sha256(path.read_bytes()).hexdigest()
                for path in sorted(files)}
    (out / "manifest_sha256.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    return audit
