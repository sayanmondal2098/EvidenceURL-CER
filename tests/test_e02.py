import json

from cerurl.e02 import prepare_e02


def test_e02_refuses_to_substitute_missing_urltrust(tmp_path):
    audit=tmp_path/'audit.json'
    audit.write_text(json.dumps({'flow':{'included_assertions':1,'graph_edges':0},'missingness':{'html_unavailable':1},'timestamp_semantics':{'first_seen_evaluation':{'evaluable':False}}}),encoding='utf-8')
    result=prepare_e02(str(tmp_path/'E02'),str(audit))
    assert result['run_status']=='BASELINE_NOT_REPRODUCIBLE'
    mode=json.loads((tmp_path/'E02'/'model_modes'/'urltrust_full_frozen'/'mode.json').read_text())
    assert mode['status']=='NOT_RUN_AUTHORITATIVE_URLTRUST_MISSING'
    assert (tmp_path/'E02'/'metrics.csv').read_text().count('\n')==1
