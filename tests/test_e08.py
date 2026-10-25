import random

import numpy as np
import pytest

from cerurl.e08 import (HYPER, REDIR, STRUCT, Op, OpRejected, apply_op, matrix, property_checks, regime_gate, run_e08,
                        semantic_checks, make_case, typed_rejection_controls, target_row)


def test_joint_bound_property_holds_and_negative_control_fails():
    p = property_checks(1500, seed=1)
    assert p["assertion_violations"] == 0
    assert p["max_observed_over_bound"] <= 1.0 + 1e-6
    neg = p["negative_control_non_stochastic_Q"]
    assert neg["bound_violated"] and neg["gate_rejects"]


def test_out_of_type_ops_are_rejected():
    assert all(r[1] != "accepted" for r in typed_rejection_controls())


def test_row_l1_cap_per_op():
    rng = random.Random(3)
    for i in range(30):
        sp = make_case(rng, i); P = matrix(sp["edges"], sp["n"])
        for a in range(sp["n"]):
            for b in range(sp["n"]):
                for kind in ("insert_link", "reweight_up", "reweight_down", "remove_link"):
                    try: e = apply_op(sp["edges"], sp["site"], sp["open"], Op(kind, a, b, None, 0.1))
                    except OpRejected: continue
                    assert np.abs(matrix(e, sp["n"]) - P).sum(1).max() <= 0.2 + 1e-9


def test_semantic_preserving_edits_are_free():
    rng = random.Random(4)
    specs = [make_case(rng, i) for i in range(10)]
    assert semantic_checks(specs, random.Random(5))["violations"] == 0


def test_regime_gate_abstains():
    assert "alpha_outside_validated_domain" in regime_gate(0.97, 0.2, .3, .7)
    assert "graph_term_vacuous" in regime_gate(0.9, 1.0, .3, .7)
    assert not regime_gate(0.35, 0.2, .3, .7)


def test_run_small_is_sound_and_abstains_outside_domain(tmp_path):
    a = run_e08(str(tmp_path / "o"), str(tmp_path / "t"), cases=16, random_trials=10, prop_trials=500, plots=False)
    assert a["pass_criteria"]["status"] == "pass"
    assert a["soundness"]["unknown_regime_certified"] == 0
