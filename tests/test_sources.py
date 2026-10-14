import json

from cerurl.sources import write_source_registry


def test_source_registry_lists_requested_sources_without_marking_them_acquired(tmp_path):
    result=write_source_registry(str(tmp_path/'registry.json'),str(tmp_path/'registry.md'))
    sources=json.loads((tmp_path/'registry.json').read_text())['sources']
    assert result['sources']==6 and result['acquired']==0
    assert {s['source_id'] for s in sources}=={'phiusiil','phishtank','phishingeval','common_crawl','tranco','phishark2026'}
    assert next(s for s in sources if s['source_id']=='tranco')['label_policy'].startswith('ranked domains are benign candidates')
