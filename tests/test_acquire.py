import json

from cerurl.acquire import acquire_sources


def test_one_command_plan_dry_run_handles_public_and_restricted_gates(tmp_path):
    proof=tmp_path/'approval.txt'; proof.write_text('approved')
    plan={'sources':[{'source_id':'tranco','enabled':True,'authorisation':{'acquisition_authorized_by_user':True,'terms_reference':'terms'}},{'source_id':'phishark2026','enabled':True,'download_url':'https://provider.example/archive.zip','restricted_access_receipt_path':str(proof),'authorisation':{'acquisition_authorized_by_user':True,'terms_reference':'dua'}}]}
    source=tmp_path/'plan.json'; source.write_text(json.dumps(plan))
    result=acquire_sources(str(source),str(tmp_path/'out'),dry_run=True,log_path=str(tmp_path/'source_acquisition.jsonl'))
    assert len(result['acquired'])==2
    assert not result['refused']


def test_restricted_source_is_refused_without_local_access_proof(tmp_path):
    plan={'sources':[{'source_id':'phishark2026','enabled':True,'download_url':'https://provider.example/archive.zip','authorisation':{'acquisition_authorized_by_user':True,'terms_reference':'dua'}}]}
    source=tmp_path/'plan.json'; source.write_text(json.dumps(plan))
    result=acquire_sources(str(source),str(tmp_path/'out'),dry_run=True,log_path=str(tmp_path/'source_acquisition.jsonl'))
    assert result['refused'][0]['reason']=='restricted_access_receipt_or_signed_DUA_not_supplied'


def test_existing_phiusiil_file_is_receipted_under_data_output(tmp_path):
    local=tmp_path/'data'/'raw'/'phiusiil.csv'; local.parent.mkdir(parents=True); local.write_text('url,label\n')
    plan={'sources':[{'source_id':'phiusiil','enabled':True,'local_artifact_path':str(local),'authorisation':{'acquisition_authorized_by_user':True,'terms_reference':'UCI CC BY 4.0'}}]}
    source=tmp_path/'plan.json'; source.write_text(json.dumps(plan))
    result=acquire_sources(str(source),str(tmp_path/'data'/'acquired'),log_path=str(tmp_path/'source_acquisition.jsonl'))
    assert result['acquired'][0]['status']=='registered_existing_local_artifact'


def test_only_limits_one_command_plan_to_requested_source(tmp_path):
    plan={'sources':[{'source_id':'tranco','enabled':True,'authorisation':{'acquisition_authorized_by_user':True,'terms_reference':'terms'}},{'source_id':'phishtank','enabled':True,'authorisation':{'acquisition_authorized_by_user':True,'terms_reference':'terms'}}]}
    source=tmp_path/'plan.json'; source.write_text(json.dumps(plan))
    result=acquire_sources(str(source),str(tmp_path/'out'),dry_run=True,only={'tranco'},log_path=str(tmp_path/'source_acquisition.jsonl'))
    assert [item['source_id'] for item in result['acquired']]==['tranco']


def test_one_source_can_queue_multiple_dataset_artifacts(tmp_path):
    plan={'sources':[{'source_id':'phishingeval','enabled':True,'authorisation':{'acquisition_authorized_by_user':True,'terms_reference':'terms'},'artifacts':[{'artifact_id':'data_a','enabled':True,'download_url':'https://example.test/a.zip','filename':'a.zip'},{'artifact_id':'data_b','enabled':True,'download_url':'https://example.test/b.zip','filename':'b.zip'}]}]}
    source=tmp_path/'plan.json'; source.write_text(json.dumps(plan))
    result=acquire_sources(str(source),str(tmp_path/'out'),dry_run=True,log_path=str(tmp_path/'source_acquisition.jsonl'))
    assert len(result['acquired'])==2


def test_acquisition_run_is_appended_to_url_free_jsonl_log(tmp_path):
    plan={'sources':[{'source_id':'phiusiil','enabled':True,'local_artifact_path':str(tmp_path/'missing.csv'),'authorisation':{'acquisition_authorized_by_user':True,'terms_reference':'terms'}}]}
    source=tmp_path/'plan.json'; source.write_text(json.dumps(plan))
    log=tmp_path/'data'/'logs'/'source_acquisition.jsonl'
    result=acquire_sources(str(source),str(tmp_path/'out'),log_path=str(log))
    entry=json.loads(log.read_text().strip())
    assert result['log_path']==str(log)
    assert entry['event']=='source_acquisition_run'
    assert entry['refused_count']==1
    assert 'download_url' not in log.read_text()
