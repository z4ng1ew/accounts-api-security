#!/usr/bin/env python3
"""Validate waivers.yaml and emit scanner ignore files from it.

Usage:
  check_waivers.py validate <waivers.yaml> [--today YYYY-MM-DD]
  check_waivers.py trivyignore <waivers.yaml> > .trivyignore

Exit 1 on any invalid or expired waiver. Ignore files are generated only from
valid, unexpired entries, so an expired waiver re-breaks the build.
"""
import datetime as dt
import sys

import yaml

REQUIRED = ["id", "scanner", "target", "severity", "reason", "compensating_control",
            "threat", "requested_by", "approved_by", "created", "expires", "ticket"]
WAIVABLE_SCANNERS = {"trivy", "checkov", "kyverno", "conftest"}
APPROVERS = {"bob", "carol"}          # platform team; mirrors CODEOWNERS
MAX_DAYS = {"CRITICAL": 30, "HIGH": 90, "MEDIUM": 90, "LOW": 90}


def _date(v):
    return v if isinstance(v, dt.date) else dt.date.fromisoformat(str(v))


def validate(waivers, today):
    errors, valid, seen = [], [], set()
    for w in waivers:
        wid = w.get("id", "<no id>")
        missing = [f for f in REQUIRED if not w.get(f)]
        if missing:
            errors.append(f"{wid}: missing fields {missing}")
            continue
        if wid in seen:
            errors.append(f"{wid}: duplicate id")
        seen.add(wid)
        if w["scanner"] not in WAIVABLE_SCANNERS:
            errors.append(f"{wid}: scanner '{w['scanner']}' is not waivable")
        if w["requested_by"] == w["approved_by"]:
            errors.append(f"{wid}: self-approved")
        if w["approved_by"] not in APPROVERS:
            errors.append(f"{wid}: approver '{w['approved_by']}' not in platform team")
        created, expires = _date(w["created"]), _date(w["expires"])
        limit = MAX_DAYS.get(str(w["severity"]).upper(), 90)
        if (expires - created).days > limit:
            errors.append(f"{wid}: lifetime {(expires - created).days}d > {limit}d for {w['severity']}")
        if expires < today:
            errors.append(f"{wid}: EXPIRED on {expires} — fix the finding or renew with fresh approval")
            continue
        if (expires - today).days <= 14:
            print(f"::warning::{wid} expires {expires}", file=sys.stderr)
        if not any(e.startswith(wid + ":") for e in errors):
            valid.append(w)
    return errors, valid


def main(argv):
    if len(argv) < 3:
        print(__doc__)
        return 2
    cmd, path = argv[1], argv[2]
    today = dt.date.today()
    if "--today" in argv:
        today = dt.date.fromisoformat(argv[argv.index("--today") + 1])
    with open(path) as f:
        waivers = (yaml.safe_load(f) or {}).get("waivers") or []
    errors, valid = validate(waivers, today)
    if cmd == "validate":
        for e in errors:
            print(f"::error::{e}")
        print(f"{len(valid)} valid waiver(s), {len(errors)} error(s)")
        return 1 if errors else 0
    if cmd == "trivyignore":
        for w in valid:
            if w["scanner"] == "trivy":
                print(f"# {w['id']} expires {w['expires']} ({w['ticket']})")
                print(f"{w['target']} exp:{w['expires']}")
        return 0
    print(__doc__)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv))
