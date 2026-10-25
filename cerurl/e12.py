"""E12: admissible counterfactual challenges and attack localization.

Challenge selection receives only the observed case and its declared intervention
menu. Injected attacker identities and labels remain in the evaluator.
"""
from __future__ import annotations

import csv
import hashlib
import itertools
import json
import random
import time
from pathlib import Path

import numpy as np

from .core import Case, Observation, score_and_coefficients, transition

TAU_B, TAU_M, ALPHA = 0.40, 0.60, 0.35
METHODS = ("counterfactual", "random", "gradient", "feature_importance", "disagreement")
EXACT_ACTION_LIMIT = 10


def score(case: Case) -> float:
    return score_and_coefficients(case, ALPHA)[0]


def verdict(value: float) -> str:
    if value >= TAU_M:
        return "malicious"
    if value <= TAU_B:
        return "benign"
    return "abstain"


def _flipped(before: str, after: str) -> bool:
    return (before, after) in {("malicious", "benign"), ("benign", "malicious")}


def intervention_menu(case: Case) -> list[dict]:
    groups = sorted(set().union(*(o.ancestors for o in case.observations)))
    kinds = sorted({o.kind for o in case.observations})
    actions = [{"kind": "source_group", "key": group, "cost": 1.0} for group in groups]
    actions.extend({"kind": "evidence_type", "key": kind, "cost": 1.0} for kind in kinds)
    P = transition(case.P)
    for row in range(len(P)):
        for col in range(len(P)):
            if row != col and P[row, col] > 1e-12:
                actions.append({"kind": "graph_relation", "key": f"{row}:{col}", "cost": 1.0})
                break
    return actions


def apply_interventions(case: Case, actions: list[dict]) -> Case:
    """Apply declared feasible model edits; source/type changes use the opposite endpoint."""
    original_verdict = verdict(score(case))
    endpoint = 0.0 if original_verdict == "malicious" else 1.0
    changed_obs = list(case.observations)
    P = np.array(case.P, dtype=float, copy=True)
    for action in actions:
        kind, key = action["kind"], action["key"]
        if kind == "source_group":
            changed_obs = [
                Observation(o.node, endpoint if key in o.ancestors else o.value, o.weight,
                            o.ancestors, o.obs_id, o.kind)
                for o in changed_obs
            ]
        elif kind == "evidence_type":
            changed_obs = [
                Observation(o.node, endpoint if o.kind == key else o.value, o.weight,
                            o.ancestors, o.obs_id, o.kind)
                for o in changed_obs
            ]
        elif kind == "graph_relation":
            try:
                row, col = (int(part) for part in key.split(":"))
            except (TypeError, ValueError) as exc:
                raise ValueError(f"Invalid graph relation intervention: {key}") from exc
            if not (0 <= row < len(P) and 0 <= col < len(P)) or row == col or P[row, col] <= 0:
                raise ValueError(f"Inadmissible graph relation intervention: {key}")
            moved = min(P[row, col], 0.25)
            P[row, col] -= moved
            P[row, row] += moved
        else:
            raise ValueError(f"Unknown intervention kind: {kind}")
    transition(P)
    return Case(case.case_id, P, changed_obs, case.target, None, list(case.candidates),
                dict(case.candidate_costs), case.world_type, dict(case.metadata))


def admissibility(case: Case, actions: list[dict]) -> dict:
    try:
        changed = apply_interventions(case, actions)
        before, after = verdict(score(case)), verdict(score(changed))
        valid = _flipped(before, after)
        return {"admissible": valid, "before": before, "after": after,
                "score_before": score(case), "score_after": score(changed),
                "reason": "decision_reversed" if valid else "does_not_reverse_actionable_verdict"}
    except (ValueError, np.linalg.LinAlgError) as exc:
        return {"admissible": False, "before": verdict(score(case)), "after": None,
                "score_before": score(case), "score_after": None, "reason": str(exc)}


def exact_challenge(case: Case, actions: list[dict]) -> dict:
    """Exhaustively find a minimum-cardinality admissible set."""
    if len(actions) > EXACT_ACTION_LIMIT:
        raise ValueError(f"Exact challenge accepts at most {EXACT_ACTION_LIMIT} actions")
    for size in range(len(actions) + 1):
        for subset in itertools.combinations(actions, size):
            selected = list(subset)
            check = admissibility(case, selected)
            if check["admissible"]:
                return {"actions": selected, "check": check, "method": "exact",
                        "guarantee": "exact_minimum_cardinality"}
    return {"actions": [], "check": admissibility(case, []), "method": "exact",
            "guarantee": "no_admissible_challenge"}


def _action_score(case: Case, action: dict) -> float:
    return score(apply_interventions(case, [action]))


def _rank_actions(case: Case, actions: list[dict], method: str, rng: random.Random) -> list[dict]:
    before = score(case)
    current = verdict(before)
    if current == "malicious":
        direction = -1
    elif current == "benign":
        direction = 1
    else:
        direction = 0

    if method == "random":
        ranked = list(actions)
        rng.shuffle(ranked)
        return ranked
    scored = []
    kind_means: dict[str, float] = {}
    for kind in sorted({o.kind for o in case.observations}):
        values = [o.value * o.weight for o in case.observations if o.kind == kind]
        kind_means[kind] = sum(values)
    total = sum(kind_means.values())
    for action in actions:
        after = _action_score(case, action)
        impact = direction * (after - before)
        if method == "gradient":
            # The score is linear in evidence values for a fixed graph, so this
            # finite intervention derivative is exact for each atomic action.
            priority = impact
        elif method == "feature_importance":
            priority = (abs(kind_means.get(action["key"], 0.0)
                            - total * 0.5) if action["kind"] == "evidence_type" else impact * 0.25)
        elif method == "disagreement":
            group_values = []
            if action["kind"] == "source_group":
                group_values = [o.value for o in case.observations if action["key"] in o.ancestors]
            elif action["kind"] == "evidence_type":
                group_values = [o.value for o in case.observations if o.kind == action["key"]]
            spread = (max(group_values) - min(group_values)) if len(group_values) > 1 else 0.0
            priority = impact + spread * 0.25
        else:
            raise ValueError(f"Unknown ranking method: {method}")
        scored.append((priority / action["cost"], -actions.index(action), action))
    return [row[2] for row in sorted(scored, reverse=True)]


def heuristic_challenge(case: Case, actions: list[dict], method: str,
                        rng: random.Random) -> dict:
    """Constrained ranked greedy search; never reports success without re-scoring."""
    ranked = _rank_actions(case, actions, method, rng)
    selected = []
    for action in ranked:
        selected.append(action)
        check = admissibility(case, selected)
        if check["admissible"]:
            return {"actions": selected, "check": check, "method": "heuristic",
                    "guarantee": "admissibility_checked_not_minimal"}
    return {"actions": [], "check": admissibility(case, []), "method": "heuristic",
            "guarantee": "no_admissible_challenge"}


def _make_case(rng: random.Random, index: int, group_count: int) -> tuple[Case, dict]:
    n = 3
    truth = int(rng.randrange(2))
    attacked_group = f"g{rng.randrange(group_count)}"
    weights = np.full(group_count, 0.25 / max(1, group_count - 1))
    weights[int(attacked_group[1:])] = 0.75
    P = np.zeros((n, n), dtype=float)
    for row in range(n):
        P[row, row] = 0.65
        P[row, (row + 1) % n] = 0.35
    observations = []
    clean_value = 0.05 if truth == 0 else 0.95
    attack_value = 0.95 if truth == 0 else 0.05
    kinds = ("feed", "html", "dns")
    for node in range(n):
        for group in range(group_count):
            jitter = rng.uniform(-0.025, 0.025)
            value = attack_value if f"g{group}" == attacked_group else clean_value + jitter
            observations.append(Observation(
                node, float(np.clip(value, 0, 1)), float(weights[group]),
                frozenset({f"g{group}"}), f"e{node}-{group}", kinds[group % len(kinds)],
            ))
    case = Case(f"e12-{index:05d}", P, observations, 0, None,
                world_type="controlled_synthetic", metadata={"group_count": group_count})
    # Attack truth is returned separately and never passed to challenge selection.
    return case, {"label": truth, "vulnerable_groups": [attacked_group]}


def _write_csv(path: Path, rows: list[dict]) -> None:
    if not rows:
        path.write_text("", encoding="utf-8")
        return
    with path.open("w", encoding="utf-8", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)


def _rate(numerator: int, denominator: int) -> float | None:
    return numerator / denominator if denominator else None


def _summary(rows: list[dict]) -> dict:
    valid = [r for r in rows if r["challenge_valid"]]
    precision = [r["group_precision"] for r in rows if r["group_precision"] is not None]
    recall = [r["group_recall"] for r in rows if r["group_recall"] is not None]
    gaps = [r["minimality_gap"] for r in rows if r["minimality_gap"] is not None]
    gap_lower_bounds = [r["minimality_gap_lower_bound"] for r in rows
                        if r["minimality_gap_lower_bound"] is not None]
    loc = [r["attempts_to_localize"] for r in rows if r["attempts_to_localize"] is not None]
    return {
        "cases": len(rows),
        "challenge_validity": _rate(len(valid), len(rows)),
        "false_counterfactual_claims": sum(not r["challenge_valid"] for r in rows),
        "group_precision": float(np.mean(precision)) if precision else None,
        "group_recall": float(np.mean(recall)) if recall else None,
        "minimality_gap_mean": float(np.mean(gaps)) if gaps else None,
        "minimality_gap_cases": len(gaps),
        "minimality_gap_lower_bound_mean": (
            float(np.mean(gap_lower_bounds)) if gap_lower_bounds else None),
        "minimality_gap_lower_bound_cases": len(gap_lower_bounds),
        "top1_localization": _rate(sum(r["top1_localized"] for r in rows), len(rows)),
        "top3_localization": _rate(sum(r["top3_localized"] for r in rows), len(rows)),
        "attempts_to_localize_mean": float(np.mean(loc)) if loc else None,
        "runtime_ms_mean": float(np.mean([r["runtime_ms"] for r in rows])) if rows else None,
    }


def run_e12(out_dir="results/E12", table_dir="tables", cases=120, seed=20261212) -> dict:
    if type(cases) is not int or cases < 1:
        raise ValueError("cases must be a positive integer")
    out, tables = Path(out_dir), Path(table_dir)
    out.mkdir(parents=True, exist_ok=True)
    tables.mkdir(parents=True, exist_ok=True)
    for name in ("audit.json", "manifest_sha256.json", "challenge_results.csv", "challenge_sets.jsonl"):
        (out / name).unlink(missing_ok=True)
    (tables / "e12_counterfactual.tex").unlink(missing_ok=True)

    attack_rng = random.Random(seed ^ 0xA7712)
    policy_seed = seed ^ 0xE12
    result_rows, set_rows = [], []
    exact_cases = heuristic_cases = 0
    for index in range(cases):
        group_count = 4 if index % 2 == 0 else 12 + (index % 7)
        case, hidden_truth = _make_case(attack_rng, index, group_count)
        public_case = Case(case.case_id, case.P.copy(), list(case.observations), case.target,
                           None, world_type=case.world_type, metadata={"group_count": group_count})
        initial = verdict(score(public_case))
        if initial == "abstain" or initial == ("malicious" if hidden_truth["label"] else "benign"):
            raise AssertionError("Controlled attack did not create an actionable error")
        actions = intervention_menu(public_case)
        is_exact = len(actions) <= EXACT_ACTION_LIMIT
        exact = exact_challenge(public_case, actions) if is_exact else None
        exact_cases += int(is_exact)
        heuristic_cases += int(not is_exact)
        for method in METHODS:
            started = time.perf_counter()
            method_seed = policy_seed ^ (index * 1009) ^ (METHODS.index(method) * 0xE12)
            method_rng = random.Random(method_seed)
            if method == "counterfactual":
                challenge = exact if exact is not None else heuristic_challenge(
                    public_case, actions, "gradient", method_rng)
            else:
                challenge = heuristic_challenge(public_case, actions, method, method_rng)
            elapsed_ms = (time.perf_counter() - started) * 1000
            selected = challenge["actions"]
            check = admissibility(public_case, selected)
            guessed = {a["key"] for a in selected if a["kind"] == "source_group"}
            actual = set(hidden_truth["vulnerable_groups"])
            action_ranking = _rank_actions(public_case, actions, method if method != "counterfactual"
                                           else "gradient", random.Random(method_seed))
            ranked_group_positions = {
                action["key"]: position for position, action in enumerate(action_ranking, start=1)
                if action["kind"] == "source_group"
            }
            ranks = [ranked_group_positions[group] for group in actual if group in ranked_group_positions]
            row = {
                "case_id": case.case_id, "method": method, "world_size": group_count,
                "search_regime": challenge["method"], "guarantee": challenge["guarantee"],
                "initial_verdict": initial, "final_verdict": check["after"],
                "challenge_valid": check["admissible"], "challenge_reason": check["reason"],
                "challenge_size": len(selected), "exact_minimum_size": (
                    len(exact["actions"]) if exact and exact["check"]["admissible"] else None),
                "minimality_gap": (len(selected) - len(exact["actions"])
                                   if exact and check["admissible"] and exact["check"]["admissible"] else None),
                "minimality_gap_lower_bound": (
                    max(0, len(selected) - 1) if check["admissible"] and not is_exact else None),
                "group_precision": len(guessed & actual) / len(guessed) if guessed else 0.0,
                "group_recall": len(guessed & actual) / len(actual),
                "top1_localized": any(rank <= 1 for rank in ranks),
                "top3_localized": any(rank <= 3 for rank in ranks),
                "attempts_to_localize": min(ranks) if ranks else None,
                "runtime_ms": elapsed_ms, "admissibility_checked": True,
            }
            result_rows.append(row)
            set_rows.append({"case_id": case.case_id, "method": method, "actions": selected,
                             "admissibility": check, "exact_or_bounded_guarantee": challenge["guarantee"]})
    summaries = [{"method": method, **_summary([r for r in result_rows if r["method"] == method])}
                 for method in METHODS]
    violations = [r for r in result_rows if not r["challenge_valid"]]
    audit = {
        "audit_version": "E12-1", "seed": seed, "cases": cases, "exact_cases": exact_cases,
        "heuristic_cases": heuristic_cases, "exact_action_limit": EXACT_ACTION_LIMIT,
        "methods": list(METHODS), "runtime_seconds": sum(r["runtime_ms"] for r in result_rows) / 1000,
        "selection_inputs": "observed Case, declared intervention menu, public thresholds and model only",
        "held_out_inputs": "independently derived attack-generation seed and injected vulnerable source-group identities are evaluator-only",
        "unobserved_action_outcomes": "none are generated or available during challenge selection",
        "admissibility": "every claimed challenge is reapplied to the public model and must reverse benign<->malicious",
        "guarantee_policy": "exact minimum-cardinality only for exhaustive sets of <=10 actions; all larger cases are heuristic and admissibility checked",
        "summary": summaries, "false_counterfactual_claims": len(violations),
        "pass_criteria": {"status": "pass" if not violations else "fail",
                          "all_reported_challenges_admissible": not violations,
                          "only_bounded_cases_claim_exactness": all(
                              r["guarantee"] == "exact_minimum_cardinality"
                              for r in result_rows if r["search_regime"] == "exact")},
        "violations": [{"case_id": r["case_id"], "method": r["method"], "reason": r["challenge_reason"]}
                       for r in violations],
    }
    _write_csv(out / "challenge_results.csv", result_rows)
    with (out / "challenge_sets.jsonl").open("w", encoding="utf-8") as stream:
        for row in set_rows:
            stream.write(json.dumps(row, sort_keys=True, allow_nan=False) + "\n")
    (out / "audit.json").write_text(json.dumps(audit, indent=2, allow_nan=False), encoding="utf-8")
    table = ["% Controlled synthetic challenge experiment; heuristic gaps are not guarantees.",
             r"\begin{tabular}{lrrrr}", r"Method & Validity & Precision & Recall & Top-3 \\", r"\hline"]
    for summary in summaries:
        fmt = lambda value: "--" if value is None else f"{value:.3f}"
        method_name = summary["method"].replace("_", r"\_")
        table.append(f"{method_name} & {fmt(summary['challenge_validity'])} & "
                     f"{fmt(summary['group_precision'])} & {fmt(summary['group_recall'])} & "
                     f"{fmt(summary['top3_localization'])} " + r"\\")
    table.extend([r"\end{tabular}", ""])
    (tables / "e12_counterfactual.tex").write_text("\n".join(table), encoding="utf-8")
    if audit["pass_criteria"]["status"] != "pass":
        (tables / "e12_counterfactual.tex").unlink(missing_ok=True)
        raise AssertionError(f"E12 admissibility audit failed: {audit['violations'][:5]}")
    files = [p for p in out.rglob("*") if p.is_file() and p.name != "manifest_sha256.json"]
    manifest = {str(path.relative_to(out)): hashlib.sha256(path.read_bytes()).hexdigest()
                for path in sorted(files)}
    (out / "manifest_sha256.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    return audit
