import logging
import os
import sys

sys.path.insert(0, os.path.dirname(__file__))
from redact import RedactingFilter, redact  # noqa: E402


def test_iban():
    assert "GB82WEST12345698765432" not in redact("pay to GB82WEST12345698765432 now")
    assert "[REDACTED:IBAN]" in redact("iban DE89 3704 0044 0532 0130 00")


def test_email():
    assert redact("user a.b+x@bank.co.uk logged in") == "user [REDACTED:EMAIL] logged in"


def test_phone():
    assert "[REDACTED:PHONE]" in redact("call +91 98765 43210")


def test_structured_keys(caplog):
    log = logging.getLogger("t")
    log.addFilter(RedactingFilter())
    with caplog.at_level(logging.INFO):
        log.info("lookup %s", {"iban": "GB82WEST12345698765432", "id": 7})
    assert "GB82WEST" not in caplog.text and "'id': 7" in caplog.text


def test_known_gap_names_not_redacted():
    # Documented limitation: personal names have no pattern.
    assert "Priya Sharma" in redact("customer Priya Sharma updated")


def test_known_gap_base64_not_redacted():
    # Documented limitation: encoded PII passes through.
    assert "YS5iQGJhbmsuY28udWs=" in redact("blob YS5iQGJhbmsuY28udWs=")
