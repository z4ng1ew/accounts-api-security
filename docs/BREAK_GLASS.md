# Break-glass: shipping a fix while a security gate is red

**When:** production is down or customer funds/data are at risk, the fix is ready, and a gate (Trivy or Checkov) blocks it for a reason unrelated to the fix (e.g. a CVE published an hour ago). **Never** for Gitleaks: a leaked secret is rotated, not bypassed.

## Procedure
1. **Incident first.** An incident ticket (INC-xxx) must exist. The PR title starts with `[BREAK-GLASS INC-xxx]`.
2. **Two people.** The PR author requests break-glass; one of the 2 platform-team members or the on-call engineering manager applies the `break-glass` label. Only repo admins can apply that label (label protection via a ruleset), so the author cannot self-apply it.
3. **What changes.** With the label present, the `sca` and `iac` jobs run in report-only mode (`exit-code: 0`). Their results are still uploaded as artifacts. `secrets`, `waivers` and `policies` stay blocking. Signing and admission do **not** change: the image is still built by `build-sign.yml` on `main`, signed, and verified by Kyverno.
4. **Merge and deploy** normally.
5. **Within 48h:** a follow-up PR either fixes the finding or adds a normal, signed, expiring waiver. Until then the next PR without the label fails, so the debt cannot be forgotten.

## Audit trail it leaves
| Record | Where | Retained |
|---|---|---|
| Who applied the label, when | GitHub audit log + PR timeline | org audit log (exported to S3 with Object Lock) |
| Which gates were bypassed and their findings | workflow run artifacts + job summary | 90 days in Actions, copied to S3 |
| Automatic issue `Break-glass used: PR #N / INC-xxx`, assigned to the author, labelled `security-debt` | GitHub Issues | permanent |
| Image digest and signature deployed | Rekor transparency log + CloudTrail (ECR push) | permanent / org trail |
| Review | weekly platform sync goes through every open `security-debt` issue | — |

## Abuse limits
- More than 2 break-glass uses in 30 days triggers a mandatory review of why the gate is failing (usually a threshold problem, not a people problem).
- An open break-glass issue older than 48h blocks the *next* break-glass by the same author.
