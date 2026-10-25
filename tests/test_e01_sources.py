import csv
import hashlib
import json

from cerurl.e01_sources import PublicSuffixList, audit_acquired_sources


def _put(raw, rel, text, authorised=True, sha=None):
    p = raw / rel; p.parent.mkdir(parents=True, exist_ok=True); p.write_bytes(text.encode())
    receipt = {"source_id": rel.split("/")[0], "acquired_at": "2026-01-01T00:00:00Z", "download_url": "https://example.invalid/x",
               "sha256": sha or hashlib.sha256(text.encode()).hexdigest(), "authorisation": {"acquisition_authorized_by_user": authorised, "terms_reference": "t"}}
    (p.parent / (p.name + ".receipt.json")).write_text(json.dumps(receipt))


def _fixture(tmp_path, tamper=False):
    raw = tmp_path / "raw"
    _put(raw, "phiusiil/PhiUSIIL_Phishing_URL_Dataset.csv", "FILENAME,URL,label\n1.txt,https://shared.example/a,1\n2.txt,https://ok.example/,1\n3.txt,https://x.example/,0\n")
    _put(raw, "openphish/feed.txt", "https://shared.example/a\nhttps://only.openphish.example/\nftp://nope.example/\n")
    _put(raw, "phishing_database/phishing-links-ACTIVE.txt", "https://shared.example/a\nhttps://only.pd.example/\n", sha="0" * 64 if tamper else None)
    _put(raw, "phishtank/online-valid.csv", "phish_id,url,phish_detail_url,submission_time,verified,verification_time,online,target\n"
         "1,https://future.example/,u,2026-02-01T00:00:00+00:00,yes,2026-02-01T00:01:00+00:00,yes,Other\n2,https://p.example/,u,2026-01-01T00:00:00+00:00,no,,yes,Other\n")
    (raw / "public_suffix_list").mkdir()
    (raw / "public_suffix_list" / "public_suffix_list.dat").write_text("// c\ncom\nuk\nco.uk\n*.ck\n!www.ck\nexample\n")
    return raw


def test_psl_rules(tmp_path):
    f = tmp_path / "p.dat"; f.write_text("com\nco.uk\n*.ck\n!www.ck\n")
    p = PublicSuffixList(f)
    assert p.etld1("a.b.example.co.uk")[0] == "example.co.uk"
    assert p.etld1("co.uk")[0] is None and p.etld1("1.2.3.4")[0] is None
    assert p.etld1("a.b.ck")[0] == "a.b.ck" and p.etld1("www.ck")[0] == "www.ck"


def test_label_flip_mirroring_and_future_time_are_flagged(tmp_path):
    raw = _fixture(tmp_path)
    audit = audit_acquired_sources(str(raw), str(tmp_path / "out"), str(tmp_path / "tables"))
    assert audit["controls"]["passed"]
    assert audit["pass_criteria"]["silent_label_flips"] == 0 and audit["pass_criteria"]["conflicting_label_urls_flagged"] == 1
    assert audit["findings"]["counts"]["conflicting_labels"] == 1
    assert audit["findings"]["counts"]["source_timestamp_after_snapshot_acquisition"] >= 1
    assert audit["leakage"]["ancestry_clusters"]
    assert any(m["suspected_mirroring"] for m in audit["leakage"]["cross_feed_url_overlap_and_mirroring"])
    assert audit["timestamp_semantics"]["first_seen_evaluation"]["evaluable"] is False
    assert audit["flow"]["per_source"]["phishtank"]["excluded"] == 1
    assert audit["flow"]["exclusion_reasons"]["openphish"]["missing_or_invalid_or_non_http_url"] == 1
    with (tmp_path / "tables" / "urls.csv").open() as f: rows = list(csv.DictReader(f))
    assert all(r["capture_at"] == "" and r["capture_status"] == "unavailable" for r in rows)
    assert {r["label_class"] for r in rows if r["source_dataset"] != "phiusiil"} == {"phishing"}
    with (tmp_path / "out" / "sample_ledger.csv").open() as f: assert "http" not in f.read()


def test_hash_mismatch_source_is_not_ingested(tmp_path):
    raw = _fixture(tmp_path, tamper=True)
    audit = audit_acquired_sources(str(raw), str(tmp_path / "out"), str(tmp_path / "tables"))
    assert audit["flow"]["per_source"]["phishing_database"]["raw_rows"] == 0
    assert any(s["acquisition_status"].startswith("not_ingested") for s in audit["sources"])
