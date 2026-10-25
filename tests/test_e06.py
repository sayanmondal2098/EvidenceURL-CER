import random
from fractions import Fraction as F

import numpy as np
import pytest

from cerurl.core import fundamental
from cerurl.e06 import check_instance, exact_target_row, make_instance, run_e06


def test_exact_row_matches_numpy():
    rng = random.Random(1)
    for i in range(20):
        inst = make_instance(rng, i)
        P = np.array([[float(x) for x in r] for r in inst["P"]])
        B = fundamental(P, float(inst["alpha"]))
        row = exact_target_row(inst["P"], inst["alpha"], inst["target"])
        assert sum(row) == 1 and np.allclose([float(x) for x in row], B[inst["target"]], atol=1e-9)


def test_zero_violations_and_detector_controls(tmp_path):
    a = run_e06(str(tmp_path / "o"), str(tmp_path / "t"), n_cases=400, plots=False)
    assert a["soundness"]["violations"] == 0 and a["pass_criteria"]["status"] == "pass"
    assert all(v > 0 for v in a["detector_controls"]["mutant_violations"].values())
    assert a["coverage"]["ties"] > 0 and a["coverage"]["alpha0"] > 0 and a["coverage"]["alpha_ge_099"] > 0


def test_unsound_certifier_halts_outputs(tmp_path, monkeypatch):
    import cerurl.e06 as e06
    real = e06.certify
    monkeypatch.setattr(e06, "certify", lambda c, b, *a, **k: real(c, max(b - 1, 0), *a, **k))
    with pytest.raises(AssertionError):
        e06.run_e06(str(tmp_path / "o"), str(tmp_path / "t"), n_cases=60, plots=False)
    assert not (tmp_path / "t" / "e06_soundness.tex").exists()
    assert not (tmp_path / "o" / "per_case_min_attack_cost.csv").exists()
