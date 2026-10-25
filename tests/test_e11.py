import copy
import json
import random
from http.client import HTTPConnection

import pytest

from cerurl.e11 import (POLICIES, decision, run_e11, run_trial,
                       select_action, validate_observations, witness_certificate)
from cerurl.e11_testbed import (ACTIONS, COLLECTORS, MARKER, Action, Site, Testbed,
                               classify, collect, digest, make_sites, safe_redirect,
                               site_state)


def site(scenario="ua_cloak", redirect=True):
    return Site("e11-00001", scenario, 1, redirect, 123)


def observation(action_id="correlated_a@0", value="benign"):
    cid, slot = action_id.split("@")
    c = next(c for c in COLLECTORS if c.collector_id == cid)
    return dict(action_id=action_id, collector_id=cid, slot=int(slot), available=value is not None,
                observed=value, source_ancestors=list(c.ancestors), network=c.network, ua_family=c.ua_family)


def test_actual_http_cloaking_hashes_redirects_and_shared_ancestors(tmp_path):
    s = site()
    with Testbed([s]) as server:
        records = [collect(server.port, s.host, Action(c, 0), c, tmp_path)
                   for c in ("correlated_a", "correlated_b", "mobile_east")]
    a, b, mobile = records
    assert a["observed"] == b["observed"] == "benign"
    assert a["body_sha256"] == b["body_sha256"]
    assert a["source_ancestors"] == b["source_ancestors"]
    assert mobile["observed"] == "malicious"
    assert mobile["body_sha256"] != a["body_sha256"]
    assert [h["status"] for h in mobile["redirect_chain"]] == [302, 200]
    assert not set(a["source_ancestors"]) & set(mobile["source_ancestors"])
    assert validate_observations(records, server.request_log, tmp_path) == []
    body = (tmp_path / f"{mobile['body_sha256']}.html").read_bytes()
    assert MARKER.encode() in body
    assert b"<form" not in body and b"<input" not in body and b"<script" not in body


def test_rules_depend_on_ua_network_and_time_not_collector_names():
    desktop, mobile = COLLECTORS[0].user_agent, COLLECTORS[3].user_agent
    assert site_state(site("combined_cloak"), mobile, "cellular-east", 0)["latent_state"] == MARKER
    assert site_state(site("combined_cloak"), desktop, "cellular-east", 0)["latent_state"] == "benign"
    assert site_state(site("combined_cloak"), mobile, "datacenter-main", 0)["latent_state"] == "benign"
    assert site_state(site("window_cloak"), mobile, "cellular-east", 0)["latent_state"] == "benign"
    assert site_state(site("window_cloak"), mobile, "cellular-east", 1)["latent_state"] == MARKER
    assert site_state(site("window_cloak"), mobile, "cellular-east", 2)["latent_state"] == "benign"


@pytest.mark.parametrize("scenario", ["full_outage", "targeted_outage"])
def test_outages_are_missing_and_do_not_relabel_latent_truth(tmp_path, scenario):
    s = site(scenario)
    with Testbed([s]) as server:
        o = collect(server.port, s.host, Action("mobile_east", 0), "outage", tmp_path)
    assert o["status"] == 503 and not o["available"] and o["observed"] is None
    assert o["acquisition_cost"] == 1 and o["body_sha256"]
    assert decision([o]) == "abstain"
    assert site_state(s, COLLECTORS[3].user_agent, "cellular-east", 0)["latent_state"] == MARKER


def test_connection_failure_is_missing_and_charged(tmp_path):
    with Testbed([site()]) as server:
        port = server.port
    o = collect(port, site().host, Action("correlated_a", 0), "closed", tmp_path)
    assert not o["available"] and o["observed"] is None
    assert o["acquisition_cost"] == 1 and o["http_requests"] == 1
    assert o["body_sha256"] is None and o["missing_reason"]


def test_connection_reuse_preserves_per_request_conditions(tmp_path):
    s = site()
    with Testbed([s]) as server:
        connection = HTTPConnection("127.0.0.1", server.port, timeout=3)
        try:
            a = collect(server.port, s.host, Action("correlated_a", 0), "reuse-a", tmp_path, connection)
            b = collect(server.port, s.host, Action("mobile_east", 0), "reuse-b", tmp_path, connection)
        finally:
            connection.close()
    assert a["observed"] == "benign" and b["observed"] == "malicious"
    assert len({r["peer_port"] for r in server.request_log}) == 1
    assert {r["peer_ip"] for r in server.request_log} == {"127.0.0.1"}
    assert validate_observations([a, b], server.request_log, tmp_path) == []


def test_isolation_and_submission_refusal(tmp_path):
    with pytest.raises(ValueError):
        collect(80, "example.com", ACTIONS[0], "bad", tmp_path)
    for target in ("https://example.com/", "//other.test/template", "http://127.0.0.1/template", "/template?q=x"):
        with pytest.raises(ValueError):
            safe_redirect(site().url, target, site().host)
    assert safe_redirect(site().url, "/template", site().host) == site().url + "template"
    with Testbed([site()]) as server:
        assert server.server.server_address[0] == "127.0.0.1"
        connection = HTTPConnection("127.0.0.1", server.port)
        connection.request("POST", "/", headers={"Host": site().host})
        assert connection.getresponse().status == 405
        connection.close()
        connection = HTTPConnection("127.0.0.1", server.port)
        connection.request("GET", "/", headers={"Host": "example.com"})
        assert connection.getresponse().status == 400
        connection.close()


def test_benign_marker_mention_and_error_body_are_not_positive(tmp_path):
    s = site("benign_marker_mention")
    with Testbed([s]) as server:
        o = collect(server.port, s.host, ACTIONS[0], "mention", tmp_path)
    body = (tmp_path / f"{o['body_sha256']}.html").read_bytes()
    assert MARKER.encode() in body and o["observed"] == "benign"
    assert classify(f'<meta name="e11-state" content="{MARKER}">'.encode(), 503) is None
    assert classify(b"unrecognized", 200) is None


def test_policy_selection_has_no_hidden_truth_or_outcome_interface():
    # All selectors operate on this minimal public history. No Site or evaluator
    # object exists here; changing a private schedule cannot change their choice.
    history = [observation()]
    for policy in POLICIES:
        a, _ = select_action(policy, history, 2, random.Random(9))
        b, _ = select_action(policy, copy.deepcopy(history), 2, random.Random(9))
        assert a == b
    a, _ = select_action("cer_challenge", history, 2, random.Random(9))
    c = next(c for c in COLLECTORS if c.collector_id == a.collector_id)
    assert not set(c.ancestors).intersection(history[0]["source_ancestors"])
    assert select_action("cer_challenge", history, 0, random.Random(9))[0] is None


def test_correlated_mirrors_do_not_shrink_source_interval():
    a = observation()
    b = observation("correlated_b@0")
    assert witness_certificate([a, b])["upper_bound"] == 1
    independent = observation("mobile_east@0")
    assert witness_certificate([a, independent])["upper_bound"] == .5
    assert witness_certificate([observation(value=None)]) is None


def test_policy_time_budget_and_random_new_constraints(tmp_path):
    s = site("benign_static", False)
    with Testbed([s]) as server:
        for policy in POLICIES:
            history = run_trial(server.port, s.host, policy, 5, 7, tmp_path)
            assert sum(o["acquisition_cost"] for o in history) <= 5
            assert [o["slot"] for o in history] == sorted(o["slot"] for o in history)
            assert len({o["action_id"] for o in history}) == len(history)
            if policy == "random_new":
                assert len({o["collector_id"] for o in history}) == len(history)
            if policy == "fixed_three":
                assert [o["action_id"] for o in history] == ["correlated_a@0", "correlated_b@0", "desktop_independent@0"]
            if policy == "one_vantage":
                assert len(history) == 1


def test_byte_and_label_tampering_fails_audit(tmp_path):
    with Testbed([site()]) as server:
        o = collect(server.port, site().host, ACTIONS[0], "tamper", tmp_path)
    changed = copy.deepcopy(o)
    changed["observed"] = "malicious"
    assert any("truth_disagrees" in e for e in validate_observations([changed], server.request_log, tmp_path))
    changed = copy.deepcopy(o)
    changed["source_ancestors"] = ["invented-independent-root"]
    assert any("condition_or_ancestry" in e for e in validate_observations([changed], server.request_log, tmp_path))
    path = tmp_path / f"{o['body_sha256']}.html"
    path.write_bytes(path.read_bytes() + b"tampered")
    assert any("artifact_hash" in e for e in validate_observations([o], server.request_log, tmp_path))


def test_small_run_ground_truth_denominators_and_outputs(tmp_path):
    out = tmp_path / "run"
    a = run_e11(out, tmp_path / "tables", n_per=1, budgets=(1, 3, 5), plots=False)
    assert a["pass_criteria"]["status"] == "pass"
    assert all(a["controls"].values())
    assert a["sites"] == 14 and a["policy_trials"] == 210
    assert a["evaluation_probe_cost"] == 14 * len(ACTIONS)
    s = next(r for r in a["summary"] if r["policy"] == "fixed_three" and r["budget"] == 3)
    assert s["cloaked_sites"] == 8 and s["available_opportunity_sites"] == 6
    assert s["false_positives"] == 0 and s["true_contradiction_sites"] == 1
    assert s["mean_cost"] == 3 and s["positive_sites_without_evidence"] > 0
    assert (out / "paired_comparisons.csv").exists()
    assert (out / "server_requests.jsonl").exists()
    manifest = json.loads((out / "manifest_sha256.json").read_text())
    assert all(digest((out / path).read_bytes()) == sha for path, sha in manifest.items())
    truth = [json.loads(line) for line in (out / "ground_truth.jsonl").read_text().splitlines()]
    assert any(c["latent_state"] == MARKER and not c["measured_available"] for c in truth)


@pytest.mark.parametrize("budgets", [(), (0,), (-1,), (1, 1), (1.5,), (100,)])
def test_invalid_budgets_refused(tmp_path, budgets):
    with pytest.raises(ValueError):
        run_e11(tmp_path, tmp_path, n_per=1, budgets=budgets)


def test_failed_audit_withholds_stale_success_artifacts(tmp_path, monkeypatch):
    import cerurl.e11 as experiment
    out, tables = tmp_path / "bad", tmp_path / "tables"
    out.mkdir()
    tables.mkdir()
    plot, table = out / "cloaking_exposure.png", tables / "e11_cloaking.tex"
    plot.write_bytes(b"old plot")
    table.write_text("old table")
    (out / "audit.json").write_text('{"pass_criteria":{"status":"pass"}}')
    original = experiment.collect

    def poison(*args, **kwargs):
        result = original(*args, **kwargs)
        if not result["available"]:
            result["observed"] = "benign"  # deliberate forbidden outage conversion
        return result

    monkeypatch.setattr(experiment, "collect", poison)
    with pytest.raises(AssertionError, match="integrity audit failed"):
        experiment.run_e11(out, tables, n_per=1, budgets=(1,), plots=False)
    assert not plot.exists() and not table.exists()
    audit = json.loads((out / "audit.json").read_text())
    assert audit["pass_criteria"]["status"] == "fail"
    assert any("missing_used_as_evidence" in e for e in audit["violations"])
    assert not (out / "manifest_sha256.json").exists()


def test_schedules_reproducible():
    assert make_sites(2, 42) == make_sites(2, 42)
    assert make_sites(2, 42) != make_sites(2, 43)
