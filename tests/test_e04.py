from cerurl.e04 import controlled_cases, validate_separation


def test_e04_does_not_turn_assurance_into_benignness():
    result=validate_separation(controlled_cases())
    assert result['passed']
    assert result['checks']['unsigned_informative_not_benign']
    assert result['checks']['verified_signature_not_interpreted_as_benign']
