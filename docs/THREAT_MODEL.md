# Threat Model — accounts-api

**Assumptions:** prod runs in its own AWS account; CI reaches AWS only via GitHub OIDC; any of the ~40 engineers can approve a PR; Kyverno is the cluster's admission controller; logs are readable by all engineers + support.

## Trust boundaries

```
   Internet ──► CloudFront ──► ALB ═══[B1]═══► accounts-api pod ──[B4]──► RDS (PII)
                                                 │    ▲      │
                                         [B5] KYC│    │[B3]  └──[B6]──► Secrets Manager / KMS (IRSA)
                                       (internet)▼    │
                                                 other teams' pods (same EKS cluster)

   40 engineers ──► GitHub (merge) ──► Actions ═══[B2: OIDC]═══► ECR ──► EKS (admission)
```
B1 public→app · B2 CI→AWS/registry · B3 tenant↔tenant in shared cluster · B4 app→DB · B5 app→internet · B6 pod→AWS IAM.

## Top 5 threats (ranked by likelihood × impact here)

| # | Threat | Entry point → what they reach | Control in this submission |
|---|---|---|---|
| **1 · T2** | Known-exploitable CVE in a dependency or base image ships to prod | Public internet via B1 → RCE in pod → DB creds → all customer PII | Trivy gate on fixable CRITICAL/HIGH + **waiver path** with expiry (`security/`); distroless base |
| **2 · T3** | Secret committed to the repo or baked into the image | Repo read access (40 people, forks, logs) → DB / KYC credentials | Gitleaks gate, **not waivable**; secrets only via External Secrets; `disallow-secret-literals` policy |
| **3 · T4** | Pipeline abuse: an engineer or stolen account edits CI to skip gates or self-waives | GitHub PR (B2) → signed image of attacker's choice in prod | CODEOWNERS on `.github/`, `security/`, `policies/`; waiver approver ≠ author; OIDC trust pinned to `main` + protected environment |
| **4 · T5** | Insecure pod spec (privileged, root, hostPath) enables escape in the shared cluster | Compromised pod in *any* team's namespace (B3) → node → every pod incl. accounts-api | Kyverno pod-security policies, tested pass/fail (`policies/kyverno`); Falco shell/IMDS rules |
| **5 · T1** | Image not built by our CI runs in prod (tampered, mutable tag) | Registry write or `kubectl` access → arbitrary code next to PII | Cosign keyless signing + `verify-image-signature` pinned to workflow identity; digest-only policy |

**Tracked, lower priority (controls built, rationale in DECISIONS.md):** T6 lateral network access (default-deny NetworkPolicy) · T7 over-broad pod IAM (scoped IRSA + CMK) · T8 PII in logs (best-effort redaction, limits documented) · T9 exfiltration to arbitrary hosts (partial — see D6) · T10 audit tampering (**risk accepted**, D8).

## Overrated here: "block on every CVE" / scanner-count as security

Raw CVE counts in base images feel like the biggest risk and generate the most noise, but most are unfixed, unreachable, or in packages distroless doesn't even ship. Blocking on them makes the gate unpassable, and an unpassable gate gets disabled — which removes protection against threat #1. So we block only on *fixable* CRITICAL/HIGH, track the rest via SBOM, and spend the saved budget on the pipeline-abuse controls (#3), which are likelier to be used against a 40-engineer, no-security-team org.
