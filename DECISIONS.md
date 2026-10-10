# Decisions and Trade-offs — accounts-api

Context driving every choice: **40 people can merge, 2 run the platform, nobody owns security.** Controls must run without a human, fail closed where it matters, and have a cheap, auditable way to say "not now".

## 1. The three decisions I'd defend hardest

**D1 — Exceptions are a signed, expiring file; secrets are never an exception.** All suppression goes through `security/waivers/waivers.yaml`: approver ≠ requester, platform-team SSH-signed commits verified against keys from the base branch, 30/90-day hard expiry that re-breaks the build, ignore files generated, never hand-edited. Gitleaks findings cannot be waived — the fix (rotate) is always possible.
*Trade-off:* two approvers is a bottleneck and a bus factor of 2, and 40 engineers will feel the friction. Accepted because the alternative — a gate with no exit — gets disabled in a month. Break-glass exists for incidents.

**D2 — I chose *not* to enforce the baseline cluster-wide on day one.** Kyverno enforces in `accounts` (plus PSA `restricted`); for the other 12 teams it is Audit until each namespace shows 7 clean days, hard deadline 60 days. Signature verification is enforced only in `accounts`.
*Trade-off:* for up to 60 days, another team's privileged or hostPath pod can escape to a node — and if `accounts-api` is scheduled on that node, reach its memory and mounted credentials. Compensating: Falco on every node; the first Monday item (§6) removes co-tenancy for this service. Enforcing everywhere on day one would break other teams' deploys and the policy would be deleted, giving the same exposure permanently.

**D3 — The egress proxy does not terminate TLS.** It allow-lists the KYC host by CONNECT hostname and SNI, nothing else.
*Trade-off:* it cannot see the Host header, so domain fronting through a shared CDN, and exfiltration *to* the KYC provider itself, are not stopped. Terminating TLS would put customer PII in clear on a second system and make the proxy the most valuable target in the cluster. I'd rather have a smaller, honest control than a bigger PII store.

## 2. Enforcement posture

| Gate | Day one | Moves to block when |
|---|---|---|
| Gitleaks (full history) | **Block** new findings. Day 0: one full-history run, rotate anything live, fingerprint the rest into a reviewed baseline | — |
| Trivy, fixable CRITICAL/HIGH | **Block** (waivable) | — ; unfixed findings stay SBOM-tracked, never block |
| Conftest rules for defects that already reached prod (§4 of build) | **Block** | — |
| Checkov | Block on a pinned list; **warn** on the rest | per check: FP rate < 10 % over 2 weeks of PR runs and ≤ 1 waiver |
| Semgrep SAST | **Warn** (SARIF only) | after a curated ruleset exists and someone owns triage; same FP criterion |
| Kyverno baseline | **Block** in `accounts`, **audit** elsewhere | namespace PolicyReport = 0 violations for 7 consecutive days → label `policy.bank/enforce=true`; hard deadline 60 days for escape-class rules |
| Image signature | **Block** in `accounts` | another team onboards signing → their namespace is added |

**Evidence that a gate is ready:** data, not opinion — PolicyReport violation counts per namespace, SARIF finding counts and dismissal reasons per rule, and the number of active waivers per check. A rule that needs many waivers is a wrong threshold, not a team problem.

## 3. Blast radius

**(a) RCE in `accounts-api`.**
*Reaches:* the DB credential files and KYC key mounted in the pod → full read/write of customer PII through the `accounts_app` DB user, the same as the app. STS credentials that can read only the two `prod/accounts-api/*` secrets.
*Denied:* node escape (non-root, no hostPath or host namespaces, read-only rootfs, PSA); IMDS and node role; other namespaces and the internet (default-deny NetworkPolicy, egress only through the proxy to one host); AWS beyond two secrets (the original policy would have been account admin); the Kubernetes API (no token mounted, no RBAC).
*Evidence:* Falco `unexpected outbound connection` on any connect attempt outside the profile; proxy access logs with bytes out per request; CloudTrail for every STS/Secrets Manager call by the role; Kyverno/Falco events if a new process or pod is attempted.
*Goes dark:* reads of customer data through the existing DB connection look exactly like normal app queries — there is no query-level audit. Data sent out in small volumes via the allowed KYC host, or via DNS, looks like normal traffic. Anything done purely in the Python process without new processes or connections leaves no syscall-level trace.

**(b) Maintainer's GitHub account taken over, workflow modified.**
*Reaches:* can push a branch with a modified workflow and open a PR; if the account is a repo admin, can change repository settings.
*Denied:* AWS — the OIDC trust requires `environment:prod-release`, which only `main` can deploy to, so branch and fork runs get no AWS credentials. Merging to `main` — `.github/` and `security/` need a CODEOWNERS approval from a *different* platform engineer, and GitHub does not allow approving your own PR. Running in prod — images built anywhere other than `build-sign.yml@refs/heads/main` fail Kyverno signature verification. Self-waiving — the attacker has the GitHub session, not the maintainer's SSH signing key, and adding a key to the repo's `allowed_signers` is read from the base branch.
*Evidence:* GitHub audit log (branch-protection or environment changes, PR approvals); Actions run logs; Rekor transparency log entry for every signature (public, append-only); CloudTrail `AssumeRoleWithWebIdentity` with the token's `sub`.
*Goes dark:* what actually executed on the ephemeral runner; secrets read from runner memory during a run; and, if the org is not on Enterprise with audit-log streaming to S3, admin actions older than the UI retention or deleted run logs. An admin who disables branch protection, merges, and re-enables it leaves only audit-log entries — nothing in git shows it.

## 4. Detection gap I'd name first

**Bulk reading of customer data through the legitimate path** — an attacker with RCE using the app's own DB connection, or a valid customer session enumerating other customers' accounts through an authorization bug (BOLA). Every request is authenticated, every query is one the app normally runs, every byte leaves through an allowed channel. Nothing above fires.
*Cost to close:* a per-principal "records returned per hour" metric in the app with an anomaly alarm (≈ 1–2 engineer-weeks plus an owner for the alert), and `pgaudit` READ logging on the customer tables for forensics (≈ tens of GB of logs a day at this size, plus CloudWatch cost). RDS Database Activity Streams would be the managed option but are not available for RDS PostgreSQL, only Aurora — so a migration, not a toggle.

## 5. Regulatory framing

| Control built | Obligation it serves |
|---|---|
| Single region ap-south-1 for RDS, ECR, Secrets Manager, KMS, log archive; no CloudFront caching of API responses | **Data residency** — RBI directive that payment-system data is stored only in India |
| Org CloudTrail: multi-region, log-file validation, global events; S3 Object Lock | **Audit-trail integrity** — CERT-In 2022 directions (logs kept in India, ≥ 180 days); RBI cyber-security framework |
| Signed, expiring waivers; approver ≠ requester; CODEOWNERS; signed images from `main` only | **Change management and segregation of duties** — RBI IT Governance Master Direction; PCI DSS change control |
| Only card last-4 stored; PAN patterns redacted in 3 log layers; no PII in URLs | **Cardholder-data scope** — PCI DSS v4.0 req. 3 (masking; last-4 display permitted) keeps logs out of the CDE |
| Falco runbook with a 6-hour clock; credential rotation ≤ 60 min, practised quarterly | **Breach-notification readiness** — CERT-In 6-hour reporting; DPDP Act notification to the Data Protection Board |
| CMK encryption with key policy (admins cannot decrypt); 1-year log retention | **Retention and protection of personal data** — DPDP Act security safeguards; CERT-In retention |

## 6. What I cut, and Monday

**Cut for time:** signature verification run against a real kind cluster with Sigstore (authored, validated only by YAML and `cosign` commands); Falco rules not loaded on a live kernel; the DB rotation Lambda itself; Route 53 DNS Firewall and VPC-endpoint policies (both on the egress "still leaks" list); `pgaudit`; Semgrep ruleset curation; a dedicated node group for this service.

**Monday, first thing: the GitHub settings the whole pipeline story rests on** — branch protection on `main` with "do not allow bypass" for admins, the `prod-release` environment restricted to `main` with required reviewers, label protection for `break-glass`, and audit-log streaming to S3. They are configuration outside the repo, CI cannot test them, and blast radius (b) collapses without them — while they take an hour. Second: a tainted node group for `accounts-api`, which closes the co-tenancy window that decision D2 knowingly leaves open.
