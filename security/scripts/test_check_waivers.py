import datetime as dt
import os
import sys

sys.path.insert(0, os.path.dirname(__file__))
from check_waivers import validate  # noqa: E402

TODAY = dt.date(2026, 10, 10)


def base(**kw):
    w = dict(id="W1", scanner="trivy", target="CVE-1", severity="HIGH", reason="r",
             compensating_control="c", threat="T2", requested_by="alice",
             approved_by="bob", created="2026-10-01", expires="2026-12-01", ticket="S-1")
    w.update(kw)
    return w


def test_valid():
    assert validate([base()], TODAY) == ([], [base()])


def test_expired_fails():
    errs, valid = validate([base(expires="2026-10-09")], TODAY)
    assert valid == [] and "EXPIRED" in errs[0]


def test_self_approval_fails():
    errs, _ = validate([base(approved_by="alice")], TODAY)
    assert any("self-approved" in e for e in errs)


def test_gitleaks_not_waivable():
    errs, _ = validate([base(scanner="gitleaks")], TODAY)
    assert any("not waivable" in e for e in errs)


def test_critical_max_30_days():
    errs, _ = validate([base(severity="CRITICAL", expires="2026-12-01")], TODAY)
    assert any("> 30d" in e for e in errs)


def test_missing_compensating_control():
    errs, _ = validate([base(compensating_control="")], TODAY)
    assert any("missing" in e for e in errs)
