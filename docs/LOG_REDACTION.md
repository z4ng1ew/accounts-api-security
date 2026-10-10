# Log redaction — accounts-api

**Data in scope:** name, email, phone, IBAN, balance, card last-4 (full PAN is not stored, but can arrive in a malformed client request). Logs are readable by ~40 engineers and support, so anything that reaches a log is effectively disclosed to them (threat T8).

## Principle
Redaction by pattern is a **safety net**. The control that actually works is **not putting PII into the log in the first place**: an allow-list of fields per log event. Everything else catches mistakes.

## What is redacted, at which layer

| # | Layer | What it does | Catches |
|---|---|---|---|
| L1 | **App: structured logger with field allow-list** (primary) | Request logs carry only `request_id, route_template, method, status, latency_ms, customer_id (opaque UUID), caller service`. Route is the **template** (`/accounts/{id}`), never the raw path. Bodies, headers, query strings are never logged. | By design: no PII field exists to log |
| L2 | **App: `RedactingFilter`** (`app/logging/redact.py`) | Regex-masks IBAN, email, phone, PAN-like digit runs in messages and args; replaces values of keys `iban, email, phone, balance, password, token, api_key, authorization`. Tested, including tests that assert the known gaps. | Developer logs `f"... {customer}"` by mistake |
| L3 | **Node: Fluent Bit filter** (platform DaemonSet) | Same regex set applied to *all* container stdout before it leaves the node. | `print()`, third-party libraries, crash output that bypassed the Python logger |
| L4 | **CloudWatch Logs data-protection policy** on the log group | AWS managed identifiers (`EmailAddress`, `CreditCardNumber`, bank-account identifiers) are masked for readers without `logs:Unmask`; findings go to an audit destination. | Last line, and a **measurement**: a non-zero finding count means L1–L3 failed somewhere → ticket to the owning team |

Last-4 of card is intentionally **not** redacted: it is permitted to display under PCI DSS and is needed by support.
`balance` is redacted by key (L2), but a bare number in free text cannot be recognised as a balance.

## What the redaction still leaks (honest list)
1. **Names.** No pattern recognises "Priya Sharma". Only L1 (not logging them) works. There is a test asserting this gap.
2. **Encoded or split data.** Base64/URL-encoded values, a JSON blob inside a string, an IBAN split across two fields, or spaced oddly, all pass. Tested gap for base64.
3. **Exception tracebacks and `repr()` of ORM objects.** A stack trace can contain local variables or a full customer row. L2 sees only the message text, L3/L4 catch only matching patterns.
4. **Logs this code never sees.** CloudFront and ALB access logs record the **raw URL including query string** (e.g. `?email=...`); RDS slow-query and error logs can contain SQL parameters; the KYC vendor's error messages may echo what we sent. L1–L2 do nothing for these. Mitigation: no PII in URLs (API design rule), `log_min_duration_statement` without parameters, ALB logs in a restricted bucket.
5. **Other telemetry.** Traces (span attributes), metrics labels, Falco alert output (`proc.cmdline`) and error-tracking tools are separate pipelines; redaction is not applied there unless configured per tool.
6. **Pseudonymous identifiers are still personal data.** `customer_id` + client IP + timestamps let anyone with DB access re-identify a person. That is acceptable for operations, but it is not "anonymised", and access to logs is still access to personal data under India's DPDP Act.
7. **False positives.** A 15-digit order number can be masked as a phone/PAN, which costs debuggability. Accepted.
8. **Already-written logs.** Redaction is not retroactive; a leak found today is still in the archive (S3 Object Lock prevents deleting it before retention ends). Handling: restrict access to the affected window, record it as an incident.

## How we know it is working
The L4 finding count per day is a metric with an alarm at > 0. It is the only signal that tells us L1–L3 failed, so it is a measurement of the control, not just another filter.
