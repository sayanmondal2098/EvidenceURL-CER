import random

import numpy as np
import pytest

from cerurl.core import Case, Observation
from cerurl.e12 import (METHODS, admissibility, apply_interventions, exact_challenge,
                       heuristic_challenge, intervention_menu, run_e12, score, verdict)


def simple_case():
    observations = [
        Observation(0, 0.95, 0.75, frozenset({"attacker"}), "a", "feed"),
        Observation(0, 0.05, 0.25, frozenset({"independent"}), "b", "html"),
    ]
    return Case("small", [[1.0]], observations, 0)


def test_exact_challenge_is_minimum_and_admissible():
    case = simple_case()
    actions = intervention_menu(case)
    challenge = exact_challenge(case, actions)
    assert challenge["guarantee"] == "exact_minimum_cardinality"
    assert len(challenge["actions"]) == 1
    assert challenge["check"]["admissible"]
    assert admissibility(case, challenge["actions"])["admissible"]
    assert verdict(score(apply_interventions(case, challenge["actions"]))) == "benign"


def test_graph_intervention_preserves_stochasticity_and_changes_score():
    case = Case(
        "graph", np.array([[0.5, 0.5], [0.0, 1.0]]),
        [Observation(0, 0.0, 1.0, frozenset({"a"})),
         Observation(1, 1.0, 1.0, frozenset({"b"}))], 0,
    )
    action = next(a for a in intervention_menu(case) if a["kind"] == "graph_relation")
    changed = apply_interventions(case, [action])
    assert changed.P.sum(axis=1).tolist() == pytest.approx([1.0, 1.0])
    assert changed.P[0, 1] < case.P[0, 1]


def test_heuristic_never_claims_an_unchecked_flip():
    case = simple_case()
    actions = intervention_menu(case)
    result = heuristic_challenge(case, actions, "gradient", random.Random(3))
    assert result["check"] == admissibility(case, result["actions"])
    assert not result["actions"] or result["check"]["admissible"]


def test_run_small_passes_and_separates_exact_and_heuristic_cases(tmp_path):
    audit = run_e12(tmp_path / "out", tmp_path / "tables", cases=4, seed=12)
    assert audit["pass_criteria"]["status"] == "pass"
    assert audit["exact_cases"] == 2
    assert audit["heuristic_cases"] == 2
    assert audit["false_counterfactual_claims"] == 0
    assert {row["method"] for row in audit["summary"]} == set(METHODS)
    assert (tmp_path / "out" / "challenge_sets.jsonl").exists()
    assert (tmp_path / "tables" / "e12_counterfactual.tex").exists()


@pytest.mark.parametrize("cases", [0, -1, 1.5])
def test_invalid_case_count_rejected(tmp_path, cases):
    with pytest.raises(ValueError):
        run_e12(tmp_path, tmp_path, cases=cases)
