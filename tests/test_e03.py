from cerurl.e03 import validate_group_disjoint, validate_replay


def test_e03_flags_future_feature_and_domain_overlap():
    assert validate_replay([{'url_id':'u','decision_at':'2025-01-01T00:00:00Z'}],[{'url_id':'u','feature_id':'f','available_at':'2025-01-02T00:00:00Z'}])[0]['kind']=='feature_after_decision'
    overlaps=validate_group_disjoint([{'etld_plus_one':'x.test','campaign_id':None,'infrastructure_id':None,'split_name':'train'},{'etld_plus_one':'x.test','campaign_id':None,'infrastructure_id':None,'split_name':'test'}])
    assert overlaps[0]['kind']=='disallowed_group_overlap'
