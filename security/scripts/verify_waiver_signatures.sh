#!/usr/bin/env bash
# Every commit that touched security/waivers/waivers.yaml must carry a valid SSH signature
# from a key listed in security/waivers/allowed_signers (platform team only).
# This makes the waiver file "signed": CODEOWNERS can be bypassed by an admin merge,
# a signature by a platform key cannot be forged by the PR author.
set -euo pipefail
FILE=security/waivers/waivers.yaml
SIGNERS=security/waivers/allowed_signers

# The trust anchor must come from the protected base branch, not from the PR itself,
# otherwise a PR could add its author's key and sign its own waiver.
BASE=${GITHUB_BASE_REF:-main}
git show "origin/${BASE}:${SIGNERS}" > /tmp/allowed_signers 2>/dev/null || cp "$SIGNERS" /tmp/allowed_signers
git config gpg.format ssh
git config gpg.ssh.allowedSignersFile /tmp/allowed_signers

fail=0
for c in $(git log --format=%H -- "$FILE"); do
  if git verify-commit "$c" >/dev/null 2>&1; then
    echo "ok   $c $(git log -1 --format='%an %s' "$c")"
  else
    echo "::error::waiver commit $c is not signed by a platform-team key"
    fail=1
  fi
done
exit $fail
