"""E15: certificate updates, provenance invalidation, and rebuild agreement."""
from __future__ import annotations

import csv
import hashlib
import json
import statistics
import time
from dataclasses import dataclass
from pathlib import Path

import numpy as np

from .core import (
    Case, Observation, add_observation, certify, fundamental, prior,
    transition, worst_damage_safe_bound,
)

ALPHA, TAU_B, TAU_M = 0.35, 0.40, 0.60
CERT_BUDGET = 1
MAX_REPORTED_BUDGET = 3
EVENTS = (
    "no_op_refresh",
    "shared_ancestor_support",
    "independent_contradiction",
    "independent_support",
    "new_mirror_discovered",
    "upstream_independence_loss",
    "freshness_expiration",
    "graph_snapshot_change",
)
EVENT_ACTIONS = {
    "no_op_refresh": "no_op_refresh",
    "shared_ancestor_support": "evidence_added",
    "independent_contradiction": "evidence_added",
    "independent_support": "evidence_added",
    "new_mirror_discovered": "mirror_discovered",
    "upstream_independence_loss": "independence_lost",
    "freshness_expiration": "freshness_expired",
    "graph_snapshot_change": "graph_changed",
}
INVALIDATION_REASONS = (
    "evidence_changed", "ancestry_changed", "mirror_discovered",
    "independence_lost", "freshness_expired", "graph_snapshot_changed",
)
PROOF_CHANGING_EVENTS = tuple(event for event in EVENTS if event != "no_op_refresh")


@dataclass
class CertificateSnapshot:
    fingerprint: str
    graph_fingerprint: str
    ancestry_fingerprint: str
    active_observation_ids: frozenset[str]
    report: dict
    propagation: np.ndarray
    created_at: float


def _graph_fingerprint(case: Case) -> str:
    graph = transition(case.P)
    return hashlib.sha256(graph.astype("<f8", copy=False).tobytes()).hexdigest()


def _ancestry_fingerprint(case: Case) -> str:
    payload = [
        (o.obs_id, tuple(sorted(o.ancestors)))
        for o in sorted(case.observations, key=lambda item: item.obs_id)
    ]
    return hashlib.sha256(json.dumps(payload, separators=(",", ":")).encode()).hexdigest()


def _active_observations(case: Case, evidence_meta: dict[str, dict], now: float) -> list[Observation]:
    active = [
        obs for obs in case.observations
        if evidence_meta[obs.obs_id]["expires_at"] > now
    ]
    nodes = set(range(len(case.P)))
    weights_by_node = {
        node: sum(obs.weight for obs in active if obs.node == node)
        for node in nodes
    }
    missing = [node for node, weight in weights_by_node.items() if weight <= 0]
    if missing:
        raise ValueError(f"Freshness invalidation leaves nodes without evidence: {missing}")
    return [
        Observation(obs.node, obs.value, obs.weight / weights_by_node[obs.node],
                    obs.ancestors, obs.obs_id, obs.kind)
        for obs in active
    ]


def _case_at_time(case: Case, evidence_meta: dict[str, dict], now: float) -> Case:
    active = _active_observations(case, evidence_meta, now)
    return Case(case.case_id, np.array(case.P, copy=True), active, case.target,
                case.truth, list(case.candidates), dict(case.candidate_costs),
                case.world_type, dict(case.metadata))


def _case_fingerprint(case: Case, evidence_meta: dict[str, dict], now: float) -> str:
    rows = []
    for obs in sorted(case.observations, key=lambda item: item.obs_id):
        meta = evidence_meta[obs.obs_id]
        rows.append((obs.obs_id, obs.node, obs.value, obs.weight,
                     tuple(sorted(obs.ancestors)), obs.kind,
                     meta["captured_at"], meta["expires_at"],
                     bool(meta["expires_at"] > now)))
    payload = {
        "graph": _graph_fingerprint(case),
        "target": case.target,
        "observations": rows,
        "alpha": ALPHA,
        "thresholds": (TAU_B, TAU_M),
        "certificate_budget": CERT_BUDGET,
    }
    return hashlib.sha256(json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def _certificate_from_propagation(case: Case, propagation: np.ndarray) -> dict:
    n = len(propagation)
    r = prior(case.observations, n)
    score = float(propagation[case.target] @ r)
    coefficients = np.array([
        propagation[case.target, obs.node] * obs.weight for obs in case.observations
    ])
    down, up, down_groups, up_groups, method = worst_damage_safe_bound(
        case.observations, coefficients, CERT_BUDGET)
    lower, upper = max(0.0, score - down), min(1.0, score + up)
    if score >= TAU_M:
        verdict, certified = "malicious", lower >= TAU_M + 1e-12
    elif score <= TAU_B:
        verdict, certified = "benign", upper <= TAU_B - 1e-12
    else:
        verdict, certified = "abstain", False
    return {
        "case_id": case.case_id, "verdict": verdict, "score": score,
        "certified": bool(certified), "budget": CERT_BUDGET, "alpha": ALPHA,
        "tau_b": TAU_B, "tau_m": TAU_M, "lower_bound": float(lower),
        "upper_bound": float(upper), "down_damage": float(down),
        "up_damage": float(up), "down_worst_groups": down_groups,
        "up_worst_groups": up_groups, "cert_method": method,
    }


def _full_rebuild(case: Case) -> tuple[dict, np.ndarray]:
    report = certify(case, CERT_BUDGET, ALPHA, TAU_B, TAU_M)
    propagation = fundamental(case.P, ALPHA)
    return report, propagation


def _same_report(left: dict, right: dict) -> bool:
    numeric = ("score", "lower_bound", "upper_bound", "down_damage", "up_damage")
    return (left["verdict"] == right["verdict"]
            and left["certified"] == right["certified"]
            and left["cert_method"] == right["cert_method"]
            and left["down_worst_groups"] == right["down_worst_groups"]
            and left["up_worst_groups"] == right["up_worst_groups"]
            and all(np.isclose(left[key], right[key], atol=1e-11) for key in numeric))


def _max_certified_budget(case: Case) -> int | None:
    group_count = len(set().union(*(obs.ancestors for obs in case.observations)))
    certified_budgets = [
        budget for budget in range(min(group_count, MAX_REPORTED_BUDGET) + 1)
        if certify(case, budget, ALPHA, TAU_B, TAU_M)["certified"]
    ]
    return max(certified_budgets) if certified_budgets else None


class CertificateCache:
    """Caches propagation only while its graph snapshot remains identical."""

    def __init__(self, case: Case, evidence_meta: dict[str, dict], now: float):
        eligible = _case_at_time(case, evidence_meta, now)
        report, propagation = _full_rebuild(eligible)
        self.snapshot = CertificateSnapshot(
            _case_fingerprint(case, evidence_meta, now), _graph_fingerprint(case),
            _ancestry_fingerprint(eligible),
            frozenset(obs.obs_id for obs in eligible.observations),
            report, propagation, now,
        )

    def update(self, case: Case, evidence_meta: dict[str, dict], now: float,
               event: str) -> tuple[dict, dict]:
        started = time.perf_counter()
        eligible = _case_at_time(case, evidence_meta, now)
        graph_hash = _graph_fingerprint(case)
        ancestry_hash = _ancestry_fingerprint(eligible)
        active_ids = frozenset(obs.obs_id for obs in eligible.observations)
        fingerprint = _case_fingerprint(case, evidence_meta, now)
        reasons = []
        if graph_hash != self.snapshot.graph_fingerprint:
            reasons.append("graph_snapshot_changed")
        if ancestry_hash != self.snapshot.ancestry_fingerprint:
            reasons.append("ancestry_changed")
        if active_ids != self.snapshot.active_observation_ids:
            reasons.append("freshness_expired" if event == "freshness_expiration"
                           else "evidence_changed")
        if fingerprint != self.snapshot.fingerprint and not reasons:
            reasons.append("evidence_changed")
        explicit_reason = {
            "new_mirror_discovered": "mirror_discovered",
            "upstream_independence_loss": "independence_lost",
            "freshness_expiration": "freshness_expired",
            "graph_snapshot_change": "graph_snapshot_changed",
        }.get(event)
        if explicit_reason and explicit_reason not in reasons:
            reasons.append(explicit_reason)
        invalidated = fingerprint != self.snapshot.fingerprint
        graph_unchanged = graph_hash == self.snapshot.graph_fingerprint
        if graph_unchanged:
            report = _certificate_from_propagation(eligible, self.snapshot.propagation)
            propagation = self.snapshot.propagation
            strategy = "cached_graph_rebuild_evidence"
        else:
            report, propagation = _full_rebuild(eligible)
            strategy = "full_graph_rebuild"
        incremental_ms = (time.perf_counter() - started) * 1000
        reference = certify(eligible, CERT_BUDGET, ALPHA, TAU_B, TAU_M)
        agreement = _same_report(report, reference)
        self.snapshot = CertificateSnapshot(
            fingerprint, graph_hash, ancestry_hash, active_ids, report,
            propagation, now,
        )
        return report, {
            "invalidated": invalidated, "invalidation_reasons": reasons,
            "strategy": strategy, "incremental_ms": incremental_ms,
            "agreement_with_full_rebuild": agreement,
        }


def _base_case(case_id: str, label: int = 1) -> tuple[Case, dict[str, dict]]:
    graph = np.array([[0.70, 0.30, 0.0], [0.0, 0.70, 0.30], [0.30, 0.0, 0.70]])
    value = 0.90 if label else 0.10
    observations, evidence_meta = [], {}
    for node in range(3):
        for group in range(3):
            obs_id = f"{case_id}-n{node}-g{group}"
            observations.append(Observation(
                node, value, 1 / 3, frozenset({f"root-{group}"}), obs_id, "feed",
            ))
            evidence_meta[obs_id] = {
                "captured_at": 0.0, "expires_at": 100.0 if group == 2 else 200.0,
            }
    return Case(case_id, graph, observations, 0, world_type="controlled_synthetic"), evidence_meta


def _normalize(case: Case, observations: list[Observation]) -> Case:
    totals = {node: sum(obs.weight for obs in observations if obs.node == node)
              for node in range(len(case.P))}
    if any(weight <= 0 for weight in totals.values()):
        raise ValueError("Update leaves a node without positive evidence")
    normalized = [
        Observation(obs.node, obs.value, obs.weight / totals[obs.node],
                    obs.ancestors, obs.obs_id, obs.kind)
        for obs in observations
    ]
    return Case(case.case_id, np.array(case.P, copy=True), normalized, case.target,
                case.truth, list(case.candidates), dict(case.candidate_costs),
                case.world_type, dict(case.metadata))


def _add_group(case: Case, metadata: dict[str, dict], root: str, value: float,
               event_id: str, weight: float = 0.25) -> tuple[Case, dict[str, dict]]:
    updated = case
    new_metadata = {key: dict(value) for key, value in metadata.items()}
    for node in range(len(case.P)):
        obs_id = f"{event_id}-node-{node}"
        obs = Observation(node, value, 0.0, frozenset({root}), obs_id, "feed")
        updated = add_observation(updated, obs, weight)
        new_metadata[obs_id] = {"captured_at": 10.0, "expires_at": 100.0}
    return updated, new_metadata


def _apply_event(case: Case, metadata: dict[str, dict], event: str) -> tuple[Case, dict[str, dict], float]:
    updated, new_metadata, now = case, {key: dict(value) for key, value in metadata.items()}, 10.0
    if event == "shared_ancestor_support":
        updated, new_metadata = _add_group(
            case, metadata, "root-0", 0.92, f"{case.case_id}-{event}")
    elif event == "independent_contradiction":
        updated, new_metadata = _add_group(
            case, metadata, f"independent-{event}", 0.08, f"{case.case_id}-{event}")
    elif event == "independent_support":
        updated, new_metadata = _add_group(
            case, metadata, f"independent-{event}", 0.92, f"{case.case_id}-{event}")
    elif event == "new_mirror_discovered":
        updated, new_metadata = _add_group(
            case, metadata, "root-0", 0.92, f"{case.case_id}-{event}")
    elif event == "upstream_independence_loss":
        observations = []
        for obs in case.observations:
            ancestry = {"root-0" if root == "root-1" else root for root in obs.ancestors}
            observations.append(Observation(
                obs.node, obs.value, obs.weight, frozenset(ancestry), obs.obs_id, obs.kind,
            ))
        updated = Case(case.case_id, np.array(case.P, copy=True), observations, case.target,
                       case.truth, list(case.candidates), dict(case.candidate_costs),
                       case.world_type, dict(case.metadata))
    elif event == "freshness_expiration":
        now = 100.0
        for obs in case.observations:
            if "root-2" in obs.ancestors:
                new_metadata[obs.obs_id]["expires_at"] = now
        active = [obs for obs in case.observations if new_metadata[obs.obs_id]["expires_at"] > now]
        updated = _normalize(case, active)
    elif event == "graph_snapshot_change":
        graph = np.array(case.P, copy=True)
        for row in range(len(graph)):
            moved = min(0.15, graph[row, (row + 1) % len(graph)])
            graph[row, (row + 1) % len(graph)] -= moved
            graph[row, row] += moved
        transition(graph)
        updated = Case(case.case_id, graph, list(case.observations), case.target,
                       case.truth, list(case.candidates), dict(case.candidate_costs),
                       case.world_type, dict(case.metadata))
    elif event == "no_op_refresh":
        pass
    else:
        raise ValueError(f"Unknown E15 event: {event}")
    return updated, new_metadata, now


def _write_csv(path: Path, rows: list[dict]) -> None:
    if not rows:
        path.write_text("", encoding="utf-8")
        return
    with path.open("w", encoding="utf-8", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)


def _median(values: list[float]) -> float | None:
    return float(statistics.median(values)) if values else None


def run_e15(out_dir="results/E15", table_dir="tables", cases=30, seed=20261515) -> dict:
    if type(cases) is not int or cases < 1:
        raise ValueError("cases must be a positive integer")
    out, tables = Path(out_dir), Path(table_dir)
    out.mkdir(parents=True, exist_ok=True)
    tables.mkdir(parents=True, exist_ok=True)
    for name in ("audit.json", "manifest_sha256.json", "updates.csv", "summary.csv",
                 "certificate_transitions.csv"):
        (out / name).unlink(missing_ok=True)
    (tables / "e15_certificates.tex").unlink(missing_ok=True)

    started = time.perf_counter()
    updates = []
    for index in range(cases):
        for event in EVENTS:
            case_id = f"e15-{index:05d}-{event}"
            case, metadata = _base_case(case_id, label=1)
            cache = CertificateCache(case, metadata, now=10.0)
            before_report = cache.snapshot.report
            before_budget = _max_certified_budget(_case_at_time(case, metadata, 10.0))
            updated, updated_meta, now = _apply_event(case, metadata, event)
            after_report, update_audit = cache.update(updated, updated_meta, now, event)
            measured_incremental_ms = update_audit["incremental_ms"]
            eligible = _case_at_time(updated, updated_meta, now)
            after_budget = _max_certified_budget(eligible)
            full_times = []
            for _ in range(5):
                full_start = time.perf_counter()
                certify(eligible, CERT_BUDGET, ALPHA, TAU_B, TAU_M)
                full_times.append((time.perf_counter() - full_start) * 1000)
            full_ms = _median(full_times) or 0.0
            before_roots = set().union(*(obs.ancestors for obs in case.observations))
            after_roots = set().union(*(obs.ancestors for obs in eligible.observations))
            row = {
                "case_id": case_id, "event": event, "action": EVENT_ACTIONS[event],
                "before_score": before_report["score"], "after_score": after_report["score"],
                "before_certified": before_report["certified"],
                "after_certified": after_report["certified"],
                "certificate_transition": (
                    "certified_to_certified" if before_report["certified"] and after_report["certified"]
                    else "certified_to_uncertified" if before_report["certified"]
                    else "uncertified_to_certified" if after_report["certified"]
                    else "uncertified_to_uncertified"),
                "before_max_certified_budget": before_budget,
                "after_max_certified_budget": after_budget,
                "certified_budget_gain": (
                    after_budget - before_budget
                    if before_budget is not None and after_budget is not None else None),
                "before_root_count": len(before_roots), "after_root_count": len(after_roots),
                "root_count_gain": len(after_roots) - len(before_roots),
                "invalidation_reasons": update_audit["invalidation_reasons"],
                "invalidated": update_audit["invalidated"],
                "certificate_retained_after_invalidation": (
                    False if update_audit["invalidated"] else None),
                "incremental_strategy": update_audit["strategy"],
                "incremental_agrees_with_full": update_audit["agreement_with_full_rebuild"],
                "incremental_ms": measured_incremental_ms,
                "full_rebuild_median_ms": full_ms,
                "incremental_speedup": full_ms / measured_incremental_ms
                if measured_incremental_ms > 0 else None,
            }
            updates.append(row)

    summary = []
    for event in EVENTS:
        rows = [row for row in updates if row["event"] == event]
        gains = [row["certified_budget_gain"] for row in rows
                 if row["certified_budget_gain"] is not None]
        summary.append({
            "event": event, "action": EVENT_ACTIONS[event], "cases": len(rows),
            "invalidated": sum(row["invalidated"] for row in rows),
            "valid_updates": sum(not row["invalidated"] for row in rows),
            "stale_certificate_retained": sum(
                row["invalidated"] and row["certificate_retained_after_invalidation"]
                for row in rows),
            "agreement_rate": sum(row["incremental_agrees_with_full"] for row in rows) / len(rows),
            "median_certified_budget_gain": _median(gains),
            "certified_to_certified": sum(row["certificate_transition"] == "certified_to_certified" for row in rows),
            "certified_to_uncertified": sum(row["certificate_transition"] == "certified_to_uncertified" for row in rows),
            "uncertified_to_certified": sum(row["certificate_transition"] == "uncertified_to_certified" for row in rows),
            "uncertified_to_uncertified": sum(row["certificate_transition"] == "uncertified_to_uncertified" for row in rows),
            "median_incremental_ms": _median([row["incremental_ms"] for row in rows]),
            "median_full_rebuild_ms": _median([row["full_rebuild_median_ms"] for row in rows]),
            "median_speedup": _median([row["incremental_speedup"] for row in rows
                                       if row["incremental_speedup"] is not None]),
        })
    transitions = []
    for event in EVENTS:
        for transition_name in ("certified_to_certified", "certified_to_uncertified",
                                "uncertified_to_certified", "uncertified_to_uncertified"):
            transitions.append({
                "event": event, "action": EVENT_ACTIONS[event],
                "certificate_transition": transition_name,
                "count": sum(row["event"] == event and row["certificate_transition"] == transition_name
                             for row in updates),
                "denominator": cases,
            })
    errors = [row for row in updates if not row["incremental_agrees_with_full"]]
    stale_retained = sum(bool(row["certificate_retained_after_invalidation"])
                         for row in updates if row["invalidated"])
    invalidated_count = sum(row["invalidated"] for row in updates)
    audit = {
        "audit_version": "E15-1", "seed": seed, "cases": cases, "events": list(EVENTS),
        "invalidation_reasons": list(INVALIDATION_REASONS),
        "proof_inputs": ["graph snapshot", "source ancestry", "evidence IDs, values, weights, and kinds",
                         "capture/expiry times", "target", "alpha", "thresholds", "source-group budget"],
        "update_protocol": "every changed proof input invalidates the prior certificate; unchanged graph reuses only cached propagation and rebuilds all evidence-dependent score and bounds",
        "freshness_protocol": "expired observations are removed and remaining node weights renormalized; nodes without eligible evidence reject the update",
        "incremental_full_agreement_violations": len(errors),
        "invalidated_updates": invalidated_count,
        "stale_certificate_retention_rate": stale_retained / invalidated_count if invalidated_count else 0.0,
        "median_certified_budget_gain": _median([
            row["certified_budget_gain"] for row in updates
            if row["certified_budget_gain"] is not None
        ]),
        "median_incremental_speedup": _median([
            row["incremental_speedup"] for row in updates
            if row["incremental_speedup"] is not None
        ]),
        "summary": summary, "certificate_transitions": transitions,
        "runtime_seconds": time.perf_counter() - started,
        "pass_criteria": {
            "incremental_matches_full_rebuild": not errors,
            "no_stale_certificate_retained_after_invalidation": stale_retained == 0,
            "all_proof_changing_events_invalidate": all(
                row["invalidated"] for row in updates if row["event"] in PROOF_CHANGING_EVENTS),
            "no_op_refresh_preserves_valid_certificate": all(
                not row["invalidated"] for row in updates if row["event"] == "no_op_refresh"),
            "status": "pass" if not errors and stale_retained == 0
            and all(row["invalidated"] for row in updates if row["event"] in PROOF_CHANGING_EVENTS)
            and all(not row["invalidated"] for row in updates if row["event"] == "no_op_refresh")
            else "fail",
        },
        "violations": [{"case_id": row["case_id"], "event": row["event"]}
                       for row in errors],
    }
    _write_csv(out / "updates.csv", updates)
    _write_csv(out / "summary.csv", summary)
    _write_csv(out / "certificate_transitions.csv", transitions)
    (out / "audit.json").write_text(json.dumps(audit, indent=2, allow_nan=False), encoding="utf-8")
    table = ["% Controlled synthetic certificate updates; cached graph does not imply cached proof.",
             r"\begin{tabular}{lrrrr}", r"Event & Invalidated & Cert. loss & Cert. gain & Speedup \\", r"\hline"]
    for row in summary:
        name = row["event"].replace("_", r"\_")
        speedup = "--" if row["median_speedup"] is None else f"{row['median_speedup']:.2f}"
        table.append(f"{name} & {row['invalidated']} & {row['certified_to_uncertified']} & "
                     f"{row['uncertified_to_certified']} & {speedup} " + r"\\")
    table.extend([r"\end{tabular}", ""])
    (tables / "e15_certificates.tex").write_text("\n".join(table), encoding="utf-8")
    files = [path for path in out.rglob("*") if path.is_file() and path.name != "manifest_sha256.json"]
    manifest = {str(path.relative_to(out)): hashlib.sha256(path.read_bytes()).hexdigest()
                for path in sorted(files)}
    (out / "manifest_sha256.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    if audit["pass_criteria"]["status"] != "pass":
        (tables / "e15_certificates.tex").unlink(missing_ok=True)
        raise AssertionError(f"E15 certificate audit failed: {audit['violations'][:5]}")
    return audit
