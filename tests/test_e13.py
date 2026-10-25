import random

import numpy as np
import pytest

from cerurl.core import Case, Observation
from cerurl.e13 import (ACTION_TYPES, DEFAULT_BUDGETS, POLICIES, _make_case,
                        fit_outcome_model, outcome_distribution, run_e13,
                        select_action)


def test_calibration_model_is_reproducible_and_shared():
    left = fit_outcome_model(71, samples_per_class=40)
    right = fit_outcome_model(71, samples_per_class=40)
    assert left == right
    assert set(left) == set(ACTION_TYPES)
    assert all(sum(row) == pytest.approx(1) for pair in left.values() for row in pair.values())


def test_selectors_do_not_require_sealed_candidate_outcomes():
    case, truth, actions = _make_case(random.Random(9), "no-outcome-field")
    model = fit_outcome_model(21, samples_per_class=50)
    for policy in POLICIES:
        first = select_action(policy, case, actions, [], model, random.Random(3))
        second = select_action(policy, case, actions, [], model, random.Random(3))
        assert first == second
    assert truth["label"] in (0, 1)
    low, high = outcome_distribution(case, actions[0], model)
    assert low + high == pytest.approx(1.0)


def test_action_menu_prices_are_fixed_and_independent():
    _, _, actions = _make_case(random.Random(2), "menu")
    assert len(actions) == len(ACTION_TYPES) * 4
    assert len({action.action_id for action in actions}) == len(actions)
    assert all(action.cost > 0 for action in actions)


def test_small_matched_budget_run_passes_protocol_and_writes_results(tmp_path):
    audit = run_e13(tmp_path / "out", tmp_path / "tables", cases=3, repeats=1,
                    seed=13, budgets=(0, 1, 2))
    assert audit["trial_count"] == 3 * len(POLICIES) * 3
    assert audit["pass_criteria"]["matched_menu_prices_outcomes_and_budget"]
    assert {row["budget"] for row in audit["summary"]} == {0, 1, 2}
    assert (tmp_path / "out" / "paired_comparisons.csv").exists()
    assert (tmp_path / "out" / "policy_action_counts.csv").exists()
    assert (tmp_path / "out" / "manifest_sha256.json").exists()


@pytest.mark.parametrize("budgets", [(), (1, 0), (-1,), (1, 1), (100,)])
def test_invalid_budgets_rejected(tmp_path, budgets):
    with pytest.raises(ValueError):
        run_e13(tmp_path, tmp_path, cases=1, repeats=1, budgets=budgets)
