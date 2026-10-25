import numpy as np

from cerurl.e09 import (ALPHA, BMAX, blackbox_subset, check_attack_implementation, cert_state, crosscheck_core, fast_cer, greybox_subset,
                        knowledge_isolation_checks, make_world, run_e09, score_naive, score_pa, score_robust, to_mask, brute_flips)


def worlds(n=6, seed=5):
    rng = np.random.default_rng(seed)
    return [make_world(rng, i) for i in range(n)]


def test_fast_certifier_and_repair_match_core():
    r = crosscheck_core(worlds(6), n_cert=6, n_repair=3)
    assert r["certificate_mismatches"] == 0 and r["repair_mismatches"] == 0


def test_attack_matches_scalar_reference_and_control_limits():
    assert check_attack_implementation(worlds(8), np.random.default_rng(1), trials=20)["mismatches"] == 0


def test_attacker_views_exclude_hidden_information():
    r = knowledge_isolation_checks(worlds(4))
    assert r["signatures_exclude_hidden_info"]
    assert blackbox_subset(10, 3, 1) == blackbox_subset(10, 3, 1)


def test_provenance_fusion_ignores_reported_weight_and_copies():
    c = worlds(1)[0]; m = to_mask(c, [0, 1])[None]
    base = score_pa(c, m, 0.0)[0]
    c.owrep = c.owrep * 7  # attacker-controlled reported weights are irrelevant to the audited fusion
    assert score_pa(c, m, 0.0)[0] == base


def test_certified_state_has_no_flip_within_budget():
    for c in worlds(8):
        for b in (1, 2):
            comp = (to_mask(c, blackbox_subset(c.G, b, 3)) @ c.uanc.T) > 0
            uv = np.where(comp, 0.0, c.uval)
            r = cert_state(c.unode, c.uanc, c.uw, uv, c.brow, b)
            if r["certified"]:
                assert brute_flips((c.unode, c.uanc, c.uw, uv, c.uval), c.brow, b, r["verdict"], np.random.default_rng(0)) == 0


def test_run_small_passes(tmp_path):
    a = run_e09(str(tmp_path / "o"), str(tmp_path / "t"), cases=6, plots=False)
    assert a["pass_criteria"]["status"] == "pass"
    assert a["soundness"]["violations"] == 0
