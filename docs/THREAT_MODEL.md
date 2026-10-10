# Threat Model — accounts-api

## Assumptions (one line each)
- A1: Each AWS account = one environment (dev/stage/prod); prod EKS lives in a dedicated workload account.
- A2: GitHub Actions authenticates to AWS via OIDC only; no long-lived AWS keys exist anywhere.
- A3: Images are stored in ECR in a shared tooling account; prod pulls cross-account.
- A4: The cluster runs Kyverno as the single admission controller; other teams' namespaces use the same baseline.
- A5: `main` is protected: 1 approving review required, but any of the ~40 engineers can approve.
- A6: KYC provider is reached over HTTPS on a fixed hostname; egress goes via a NAT gateway with a known IP.
- A7: Logs ship to CloudWatch → a central logging account; ~40 engineers + support can read app logs.

## Assets (ranked)
1. Customer PII/financial data in RDS (IBAN, balance, contact data) — regulatory + fraud impact.
2. DB credentials and KYC API key.
3. The deploy path (CI → registry → cluster) — whoever controls it controls (1) and (2).
4. Audit records — integrity required by regulator.

## Trust boundaries
Internet → CloudFront/ALB → pod · pod → RDS · pod → KYC (internet egress) · GitHub → AWS (OIDC) · team namespaces ↔ each other inside one cluster.

## Threats (STRIDE-tagged, ranked by likelihood × impact)

| ID | Threat | STRIDE | L | I | Priority | Controls |
|----|--------|--------|---|---|----------|----------|
| **T1** | Untrusted image runs in prod: built outside CI, tampered in registry, or pulled by mutable tag | T | M | H | **P1** | Cosign keyless signing + Kyverno verifyImages pinned to this repo's workflow identity; digest pinning |
| **T2** | Malicious/compromised dependency or base image with known exploitable CVE ships | T/E | H | H | **P1** | Trivy gate on CRITICAL/HIGH-fixable; SBOM; waiver path |
| **T3** | Secret committed to repo or baked into image | I | H | H | **P1** | Gitleaks gate (no waiver for real secrets — rotate instead) |
| **T4** | Workflow abuse: an engineer (or compromised account) edits CI to skip gates, exfiltrate OIDC token, or self-approves a waiver | E | M | H | **P1** | CODEOWNERS on `.github/` + `security/`; waiver approver ≠ author; OIDC trust scoped to `ref:refs/heads/main` + environment |
| **T5** | Container escape / lateral movement in shared cluster from an insecure pod spec (privileged, hostPath, root, SA token) | E | M | H | **P1** | Kyverno pod-security policies (enforce) + tests; Falco runtime rules |
| **T6** | Other team's compromised pod reaches accounts-api pods or RDS | I/E | M | H | P2 | Default-deny NetworkPolicy; RDS SG allows only accounts-api SG (security groups for pods) |
| **T7** | Over-broad AWS credentials on the pod (node role, wildcard IAM) → read any secret / any bucket | E | M | H | P2 | IRSA role scoped to one secret ARN + one KMS key; IMDS hop limit 1 |
| **T8** | PII (IBAN, email, phone) leaks into logs readable by many people | I | H | M | P2 | Structured-log redaction filter (best-effort, limits documented) |
| **T9** | Exfiltration from a compromised pod to arbitrary internet hosts | I | L | H | P3 | Egress restricted to KYC host (NetworkPolicy/egress proxy); Falco unexpected-egress rule; GuardDuty EKS runtime |
| **T10** | Audit record tampering / repudiation | R | L | M | P3 | Out of build scope — append-only DB role + CloudTrail; see DECISIONS.md |

## Explicitly out of scope / accepted
- App-layer bugs (authz, IDOR, injection) in accounts-api — "broadly competent" per brief; covered by Semgrep advisory scan only (non-blocking).
- DDoS / WAF tuning at CloudFront — owned by edge, not this service.
- KYC provider compromise — contractual/vendor risk; we only limit blast radius (T9).
