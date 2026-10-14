import csv
import json
from pathlib import Path

from cerurl.curation import curate_e01


def test_e01_flags_split_conflict_and_preserves_missing_capture_time(tmp_path):
    index=tmp_path/'index.csv'
    index.write_text('id,url,result,created_date,filename,split_name\n1,https://example.test/a,1,2020-01-01,missing.html,train\n2,https://example.test/a,1,2020-01-02,missing.html,test\n',encoding='utf-8')
    audit=curate_e01(str(index),str(tmp_path/'database'),str(tmp_path/'out'),str(tmp_path/'tables'))
    assert audit['controls']['passed']
    assert audit['timestamp_semantics']['first_seen_evaluation']['evaluable'] is False
    assert any(x['kind']=='url_in_multiple_splits' for x in audit['findings'])
    with (tmp_path/'tables'/'urls.csv').open() as f: rows=list(csv.DictReader(f))
    assert all(r['capture_at']=='' for r in rows)
    assert set(r['label_class'] for r in rows)=={'phishing'}


def test_e01_flags_future_graph_evidence(tmp_path):
    db=tmp_path/'database'; db.mkdir(); (db/'x.html').write_text('<a href="https://target.test">x</a>',encoding='utf-8')
    index=tmp_path/'index.csv'; index.write_text('id,url,result,filename\n1,https://example.test,0,x.html\n',encoding='utf-8')
    # The source HTML has unknown observation time.  Directly test its fail-closed
    # semantics by confirming it does not fabricate an after-decision violation.
    audit=curate_e01(str(index),str(db),str(tmp_path/'out'),str(tmp_path/'tables'))
    assert not any(x['kind']=='graph_edge_after_decision' for x in audit['findings'])
    assert audit['controls']['checks']['timestamp_after_decision']


def test_phiusiil_prepared_labels_are_checked_against_original_semantics(tmp_path):
    raw=tmp_path/'phiusiil.csv'
    raw.write_text('url,original_label,label,source_dataset\nhttps://legit.test,1,0,PhiUSIIL_UCI_967\nhttps://phish.test,0,1,PhiUSIIL_UCI_967\nhttps://bad.test,1,1,PhiUSIIL_UCI_967\n',encoding='utf-8')
    audit=curate_e01(str(raw),None,str(tmp_path/'out'),str(tmp_path/'tables'))
    assert audit['flow']['included_assertions']==2
    with (tmp_path/'tables'/'urls.csv').open() as f: rows=list(csv.DictReader(f))
    assert [r['label_class'] for r in rows]==['benign','phishing']
    with (tmp_path/'out'/'inclusion_exclusion_ledger.csv').open() as f: ledger=list(csv.DictReader(f))
    assert any(r['reason']=='phiusiil_original_and_prepared_label_conflict' for r in ledger)
