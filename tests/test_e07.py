import numpy as np

from cerurl.e07 import enumerate_damage, greedy_attack, knapsack_bound, make_case, run_e07, solve_milp


def test_milp_matches_enumeration_and_bounds_are_valid():
    for k in range(12):
        case = make_case(100 + k, 20, ["low", "medium", "high"][k % 3], ["sparse", "dense"][k % 2], costed=k % 4 == 3)
        for d in ("down", "up"):
            for b in (1, 2, 3):
                ex = enumerate_damage(case, d, b); r = solve_milp(case, d, b)
                assert r["status"] == "optimal" and abs(r["primal"] - ex) < 1e-7
                assert r["bound"] >= ex - 1e-7
                assert solve_milp(case, d, b, integer=False)["bound"] >= ex - 1e-7
                assert knapsack_bound(case, d, b) >= ex - 1e-7 >= greedy_attack(case, d, b) - 2e-7


def test_run_small_and_timeout_is_not_a_proof(tmp_path):
    a = run_e07(str(tmp_path / "o"), str(tmp_path / "t"), sizes=(20, 50), budgets=(0, 1, 3), reps=2, time_limit=5, plots=False)
    assert a["pass_criteria"]["status"] == "pass" and a["soundness"]["violations"] == 0
    assert (tmp_path / "o" / "solver_inputs.npz").is_file()
    # near-zero time limit: result must be a valid bound or None, never a guessed value below the optimum
    case = make_case(7, 100, "high", "dense", False); opt = solve_milp(case, "down", 5, time_limit=60)
    r = solve_milp(case, "down", 5, time_limit=0.001)
    assert r["bound"] is None or r["bound"] >= (opt["primal"] or 0) - 1e-7
