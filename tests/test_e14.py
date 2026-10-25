import random

import pytest

from cerurl.e14 import (DEFAULT_E14_BUDGETS, INITIAL_STATES, POLICIES,
                        _make_case, _raw_score, _sealed_outcomes, _state,
                        fit_calibrator, safe_decision, transition_name, run_e14)


def test_calibration_rule_is_reproducible_and_safe_on_calibration_split():
    first = fit_calibrator(91, count=3000)
    second = fit_calibrator(91, count=3000)
    assert first == second
    assert first["calibration_benign_release_error"] <= first["error_limit"]
    assert first["calibration_malicious_release_error"] <= first["error_limit"]
    assert first["benign_cut"] < first["malicious_cut"]


def test_transition_names_distinguish_unchanged_and_correctness_changes():
    assert transition_name("correct", "correct") == "unchanged"
    assert transition_name("wrong", "correct") == "wrong_to_correct"
    assert transition_name("correct", "wrong") == "correct_to_wrong"
    assert transition_name("abstained", "wrong") == "abstained_to_wrong"
    with pytest.raises(ValueError):
        transition_name("invalid", "wrong")


def test_test_case_strata_match_frozen_calibration_decisions():
    calibrator = fit_calibrator(32)
    for index, expected in enumerate(INITIAL_STATES):
        case, label, _ = _make_case(random.Random(index), f"fixture-{index}", expected)
        actual = _state(safe_decision(_raw_score(case), calibrator), label)
        assert actual == expected


def test_action_outcomes_are_shared_across_policies_and_seeded():
    _, label, actions = _make_case(random.Random(5), "paired-actions", "wrong")
    assert _sealed_outcomes(actions, label, 48) == _sealed_outcomes(actions, label, 48)
    assert _sealed_outcomes(actions, label, 48) != _sealed_outcomes(actions, label, 49)


def test_small_run_outputs_transition_denominators_and_paired_summary(tmp_path):
    audit = run_e14(tmp_path / "out", tmp_path / "tables", cases=3, repeats=1,
                    seed=14, budgets=(0, 1, 2))
    assert audit["pass_criteria"]["calibration_frozen_before_test"]
    assert audit["pass_criteria"]["labels_hidden_from_policy"]
    assert {row["policy"] for row in audit["summary"]} == set(POLICIES)
    assert {row["budget"] for row in audit["summary"]} == {0, 1, 2}
    assert all(row["denominator"] == row["action_transitions"]
               for row in audit["transition_summary"])
    for output in ("trial_results.csv", "transitions.csv", "transition_counts.csv",
                   "calibration_curves.json", "paired_comparisons.csv",
                   "policy_action_distribution.csv", "manifest_sha256.json"):
        assert (tmp_path / "out" / output).exists()
    assert (tmp_path / "tables" / "e14_decisions.tex").exists()


@pytest.mark.parametrize("budgets", [(), (1, 0), (-1,), (1, 1), (100,)])
def test_invalid_budget_lists_rejected(tmp_path, budgets):
    with pytest.raises(ValueError):
        run_e14(tmp_path, tmp_path, cases=1, repeats=1, budgets=budgets)


@pytest.mark.parametrize("cases,repeats", [(0, 1), (1, 0), (1.5, 1)])
def test_invalid_run_sizes_rejected(tmp_path, cases, repeats):
    with pytest.raises(ValueError):
        run_e14(tmp_path, tmp_path, cases=cases, repeats=repeats,
                budgets=DEFAULT_E14_BUDGETS)
