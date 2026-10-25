from cerurl.e05 import ProvGraph, analyse, run_e05, topologies


def test_e05_controls_and_outputs(tmp_path):
    a = run_e05(str(tmp_path / "o"), str(tmp_path / "t"), plots=True)
    assert a["pass_criteria"]["status"] == "pass"
    assert (tmp_path / "o" / "plots" / "shared_five.png").is_file()
    by = {t["topology"]: t for t in a["topologies"]}
    assert by["shared_five"]["aware_budget_to_flip"] == 1 and by["shared_five"]["naive_budget_to_flip"] == 3
    assert by["shared_five"]["unit_corrupts_reports"]["unit:S"] == ["r1", "r2", "r3", "r4", "r5"]
    assert by["independent_five"]["aware_budget_to_flip"] == 3


def test_cycle_and_unknown_never_independent():
    g = ProvGraph("c"); g.node("S", "source")
    for r in ("a", "b"): g.report(r); g.node("f" + r, "feed"); g.edge(r, "f" + r, "derived_from")
    g.edge("fa", "fb", "mirrors_feed"); g.edge("fb", "fa", "mirrors_feed")
    g.report("u")
    res = analyse(g)
    assert res["cycles"] and not res["valid"] and res["unknown_reports"] == ["u"]
    assert res["source_aware_independent_witnesses"] == 2


def test_copy_does_not_add_witnesses():
    g = topologies()["independent_five"]; before = analyse(g)["source_aware_independent_witnesses"]
    g.report("dup"); g.edge("dup", "r1", "derived_from")
    assert analyse(g)["source_aware_independent_witnesses"] == before
