# Decisions and Trade-offs

Context that drives every choice: **40 people can merge, 2 run the platform, nobody owns security.** So the budget goes to controls that (a) run without a human, (b) fail closed, and (c) have a cheap, auditable way to say "not now". Anything that needs a person to triage alerts daily is deprioritised, because nobody will.

## Where the budget went (and didn't)

| Priority | Control | Threat | State |
|---|---|---|---|
| 1 | Waiver path (schema, expiry, approver≠author, generated ignore files, daily expiry job) | T2, T4 | **Built + unit-tested** |
| 1 | Admission policies (pod security, digest, secrets, resources) with must-pass/must-fail fixtures | T1, T3, T5 | **Built + `kyverno test` 16/16** |
| 1 | Keyless signing + verifyImages pinned to workflow identity | T1, T4 | Built; verify policy validated in kind only (needs network) |
| 2 | IRSA + scoped IAM + CMK + Secrets Manager + GitHub OIDC trust on environment | T4, T7 | Authored; `terraform validate` not run in my env |
| 2 | Default-deny NetworkPolicy | T6 | Built; egress hostname pinning **not** achieved (see D6) |
| 2 | Log redaction | T8 | Built + tests, including tests that **assert known gaps** |
| 3 | Falco rules | T5, T7, T9 | Authored, not run |
| — | Semgrep SAST | app bugs (out of TM) | Advisory only (D5) |
| — | Audit-record integrity | T10 | Not built (D8) |

## Decisions

**D1 — Gitleaks is blocking and not waivable.** A leaked secret's fix is rotation, which is always possible. Allowing a waiver would train people to waive instead of rotate. False positives are handled with a `.gitleaksignore` fingerprint that goes through CODEOWNERS — same review, but it's an "this isn't a secret" decision, not a "this secret is fine" one.

**D2 — Trivy blocks only on fixable CRITICAL/HIGH.** Blocking on unfixed CVEs creates gates nobody can satisfy, which is exactly how gates get disabled. Unfixed CVEs are visible via the SBOM attestation; weekly base-image rebuild picks up fixes. *Compensating control:* distroless base + Falco "unexpected process" rule shrinks exploitability.

**D3 — Waiver design (the part I'd defend hardest).**
- One file, in-repo, reviewed like code → git history *is* the audit trail examiners ask for.
- Ignore files are **generated**, never hand-edited, so the only way to suppress a finding is a waiver entry.
- Expiry is mandatory and short (30d CRITICAL / 90d other). Expired → build breaks again *and* a daily job opens an issue, so expiry isn't only discovered on the next unrelated PR.
- `approved_by ≠ requested_by` and approver ∈ platform team, enforced in code *and* by CODEOWNERS on `security/`.
- Every waiver must name a threat and a compensating control — forces the requester to think, gives the approver something to check.
- Break-glass label for incidents (admin-only, opens an issue, reviewed within 48h). Without it, the first 2 a.m. incident is when someone disables the gate.
- **Weakness I accept:** with 2 approvers, bus factor is 2 and the platform team could collude/rubber-stamp. Compensating: waivers are a single greppable file, so a quarterly review is a 15-minute read.

**D4 — Policy rollout: Enforce on `accounts`, Audit cluster-wide first.** Enforcing pod security on 12 other teams' workloads on day one would break them and get the policies removed. Audit for one week, publish the violations, then flip to Enforce. Kyverno `PolicyException` resources (in a platform-owned namespace, CODEOWNERS-reviewed) are the cluster-side waiver path — same rules as D3.

**D5 — SAST is advisory.** Semgrep's default ruleset has a high false-positive rate and nobody is staffed to triage it; blocking on it would burn goodwill I need for the gates that matter. Revisit with a curated ruleset once there's an owner.

**D6 — Egress pinning is incomplete (honest gap).** Kubernetes NetworkPolicy is L3/L4; I can't express "only kyc-provider.example.com". Current policy allows 443 to the internet minus private ranges and IMDS. Proper fix: Cilium FQDN policy or an egress proxy (Squid/Envoy) allow-listing the KYC host. Compensating today: GuardDuty EKS + Falco network rules for detection; NAT gateway flow logs.

**D7 — Secret rotation not automated.** Secrets Manager + KMS is set up; rotation lambda for the DB password and KYC key isn't. External Secrets refreshes hourly, so rotation works once wired. Next step after this exercise.

**D8 — Audit integrity (T10) deprioritised.** Lower likelihood than T1–T5, and the right control (separate DB role with INSERT-only on audit table, or stream to an append-only store with Object Lock) is an app/data change outside a 4-hour pipeline exercise.

## Signature caveats (honesty section)
- Signing proves *which workflow built the image*, not that the code is safe. A malicious merge to `main` produces a perfectly signed malicious image. The control against that is branch protection + CODEOWNERS (T4), not cosign.
- The keyless identity pins `build-sign.yml@refs/heads/main`. Anyone who can edit that workflow on main can make it sign anything — hence CODEOWNERS on `.github/`.
- Kyverno verification depends on Rekor/registry reachability; with `failurePolicy: Fail`, a sigstore outage blocks deploys. I chose fail-closed for the `accounts` namespace; I'd document a break-glass `PolicyException`.
- verifyImages only runs at admission. Already-running pods aren't re-verified; background scan reports but doesn't evict.
- The Dockerfile digests are placeholders; the CI build will not run as-is until they are pinned to real digests.

## Log redaction caveats
See the header of `app/logging/redact.py`. In short: regex redaction misses names, encoded data, sidecar/ALB logs, and tracebacks; it also over-redacts. Two tests explicitly assert those misses so nobody mistakes the filter for a guarantee. The real control is an allow-list of loggable fields — an app change I'd push the owning team to make.

## AWS ↔ local mapping
| AWS | Here |
|---|---|
| EKS | kind / `kyverno test` |
| ECR (immutable tags, scan-on-push) | ghcr.io; ECR defined in `terraform/github_oidc.tf` |
| IAM / IRSA | `terraform/iam_irsa.tf` (not applied) |
| KMS, Secrets Manager | `terraform/kms.tf`, `secrets.tf` (not applied) |
| GuardDuty EKS Runtime | Falco rules |
| CloudTrail | not modelled; assumed org-trail exists |

## What I'd do next (in order)
1. Egress proxy / Cilium FQDN policy for KYC (closes D6).
2. Secret rotation (D7).
3. Promote cluster-wide policies from Audit → Enforce with PolicyExceptions.
4. Audit-table INSERT-only role (T10).
