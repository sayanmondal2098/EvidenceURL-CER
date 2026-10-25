import json

import pytest

from cerurl.e15 import (
    EVENTS, CertificateCache, _apply_event, _base_case, _case_at_time,
    _max_certified_budget, run_e15,
)


def update_event(event):
    case, metadata = _base_case(f"test-{event}", label=1)
    cache = CertificateCache(case, metadata, now=10.0)
    before = cache.snapshot.report
    before_budget = _max_certified_budget(_case_at_time(case, metadata, 10.0))
    updated, updated_metadata, now = _apply_event(case, metadata, event)
    report, audit = cache.update(updated, updated_metadata, now, event)
    eligible = _case_at_time(updated, updated_metadata, now)
    after_budget = _max_certified_budget(eligible)
    return case, updated, eligible, before, report, audit, before_budget, after_budget


def test_shared_ancestor_and_mirror_do_not_add_independent_roots():
    for event in ("shared_ancestor_support", "new_mirror_discovered"):
        _, _, _, _, _, audit, before_budget, after_budget = update_event(event)
        assert audit["invalidated"]
        assert audit["agreement_with_full_rebuild"]
        assert audit["invalidation_reasons"]
        case, _, eligible, *_ = update_event(event)
        before_roots = set().union(*(obs.ancestors for obs in case.observations))
        after_roots = set().union(*(obs.ancestors for obs in eligible.observations))
        assert len(after_roots) == len(before_roots)
        assert before_budget is not None and after_budget is not None


def test_independent_contradiction_weakens_score_and_support_can_strengthen_budget():
    _, _, _, before, contradiction, audit, before_budget, after_budget = update_event(
        "independent_contradiction")
    assert contradiction["score"] < before["score"]
    assert audit["agreement_with_full_rebuild"]
    assert after_budget is None or before_budget is None or after_budget <= before_budget

    _, _, _, before, support, audit, before_budget, after_budget = update_event(
        "independent_support")
    assert support["score"] > before["score"]
    assert audit["agreement_with_full_rebuild"]
    assert after_budget is not None and before_budget is not None
    assert after_budget > before_budget


def test_freshness_expiration_and_graph_change_invalidate_with_correct_strategy():
    _, _, eligible, _, _, audit, _, _ = update_event("freshness_expiration")
    assert audit["invalidated"]
    assert "freshness_expired" in audit["invalidation_reasons"]
    assert len(eligible.observations) < 9
    assert not audit.get("certificate_retained_after_invalidation", False)

    _, _, _, _, _, audit, _, _ = update_event("graph_snapshot_change")
    assert audit["invalidated"]
    assert audit["strategy"] == "full_graph_rebuild"
    assert "graph_snapshot_changed" in audit["invalidation_reasons"]


def test_independence_loss_merges_roots_and_invalidates_ancestry():
    case, _, eligible, _, _, audit, _, _ = update_event("upstream_independence_loss")
    before_roots = set().union(*(obs.ancestors for obs in case.observations))
    after_roots = set().union(*(obs.ancestors for obs in eligible.observations))
    assert len(after_roots) == len(before_roots) - 1
    assert "ancestry_changed" in audit["invalidation_reasons"]
    assert "independence_lost" in audit["invalidation_reasons"]
    assert audit["agreement_with_full_rebuild"]


def test_no_op_refresh_keeps_cached_certificate_valid():
    _, _, _, _, _, audit, _, _ = update_event("no_op_refresh")
    assert not audit["invalidated"]
    assert audit["strategy"] == "cached_graph_rebuild_evidence"
    assert audit["agreement_with_full_rebuild"]


def test_small_e15_run_passes_and_manifest_is_validated(tmp_path):
    audit = run_e15(tmp_path / "out", tmp_path / "tables", cases=2, seed=15)
    assert audit["pass_criteria"]["status"] == "pass"
    assert audit["pass_criteria"]["incremental_matches_full_rebuild"]
    assert audit["pass_criteria"]["no_stale_certificate_retained_after_invalidation"]
    assert audit["pass_criteria"]["all_proof_changing_events_invalidate"]
    assert audit["pass_criteria"]["no_op_refresh_preserves_valid_certificate"]
    assert {row["event"] for row in audit["summary"]} == set(EVENTS)
    manifest = json.loads((tmp_path / "out" / "manifest_sha256.json").read_text())
    assert {"audit.json", "updates.csv", "summary.csv", "certificate_transitions.csv"} <= set(manifest)
    assert (tmp_path / "tables" / "e15_certificates.tex").exists()


@pytest.mark.parametrize("cases", [0, -1, 1.5])
def test_invalid_case_count_rejected(tmp_path, cases):
    with pytest.raises(ValueError):
        run_e15(tmp_path, tmp_path, cases=cases)
