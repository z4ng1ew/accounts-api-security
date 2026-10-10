"""Best-effort PII redaction for accounts-api logs (Threat T8).

Install as a logging.Filter on the root logger. It masks values in the message
and in dict-style structured fields before any handler formats them.

WHAT THIS DOES NOT GUARANTEE (read before relying on it):
- It is pattern matching. Names are not redacted (no reliable pattern).
- Data split across fields, base64/URL-encoded, or embedded in exception
  tracebacks from third-party libs (repr of ORM objects) can slip through.
- Logs written by sidecars, the ALB, or stdout prints bypass this filter.
- Regexes produce false positives (e.g. a 15-digit order id matched as phone).
The primary control is *not logging PII in the first place* (structured logging
with an allow-list of fields); this filter is the safety net, not the wall.
"""
import logging
import re

_PATTERNS = [
    # IBAN: 2 letters, 2 digits, 11-30 alnum, optionally space-grouped
    ("IBAN", re.compile(r"\b[A-Z]{2}\d{2}(?:[ ]?[A-Z0-9]{4}){2,7}(?:[ ]?[A-Z0-9]{1,4})?\b")),
    ("EMAIL", re.compile(r"\b[\w.+-]+@[\w-]+(?:\.[\w-]+)+\b")),
    # Card PAN 13-19 digits (we only store last-4, but defend anyway)
    ("PAN", re.compile(r"\b(?:\d[ -]?){12,18}\d\b")),
    ("PHONE", re.compile(r"(?<!\w)\+?\d[\d ()-]{8,}\d\b")),
]
SENSITIVE_KEYS = {"iban", "email", "phone", "balance", "password", "token", "api_key", "authorization"}


def redact(text: str) -> str:
    for label, rx in _PATTERNS:
        text = rx.sub(f"[REDACTED:{label}]", text)
    return text


def _redact_obj(obj):
    if isinstance(obj, dict):
        return {k: ("[REDACTED]" if str(k).lower() in SENSITIVE_KEYS else _redact_obj(v))
                for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return type(obj)(_redact_obj(v) for v in obj)
    if isinstance(obj, str):
        return redact(obj)
    return obj


class RedactingFilter(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        record.msg = redact(str(record.msg))
        if record.args:
            record.args = _redact_obj(record.args)
        for key in list(vars(record)):
            if key.lower() in SENSITIVE_KEYS:
                setattr(record, key, "[REDACTED]")
        return True
