# 4(c) IAM policy for the accounts-api pod identity role

**What this denies that the original allowed:** every AWS action except reading the two `prod/accounts-api/*` secrets (and decrypting them only through Secrets Manager with their own key). The original's `NotAction` + `Resource "*"` was effectively AdministratorAccess: `iam:CreateAccessKey`/`AttachRolePolicy` (account takeover), `rds:DeleteDBInstance`, `s3:*`, `cloudtrail:StopLogging`, and reading **every** secret and decrypting with **every** KMS key in the account.

## Defects in the original, ranked by exploitability
1. `Allow` + `NotAction [DeleteRole, DeleteUser]` on `*` — any RCE in the pod gets admin of the AWS account: create an IAM user with keys for persistence, stop CloudTrail, snapshot and share the RDS. The two exclusions protect nothing (an attacker uses `DetachRolePolicy`, `CreateUser`, etc.).
2. `secretsmanager:GetSecretValue` on `*` — reads every team's secrets in the account, not only accounts-api's.
3. `kms:Decrypt` on `*` with no `kms:ViaService` — decrypts any ciphertext with any key, directly, outside Secrets Manager.

## Notes
- Secret ARNs use `-??????` because Secrets Manager appends a 6-character suffix; a trailing `*` would also match `prod/accounts-api/db-old-backup`.
- Network-origin conditions (`aws:SourceVpc`) are deliberately not used: Secrets Manager calls from the pod go via a VPC endpoint whose condition works, but a mistake there breaks prod at 3 a.m.; the scoping above already removes the blast radius. Added as a follow-up, not a blocker.
- Prevented from recurring by `policies/conftest/terraform/terraform.rego` (NotAction-allow, `Action "*"`, sensitive actions on `Resource "*"`) — tests `test_original_iam_denied` / `test_fixed_iam_allowed`.
