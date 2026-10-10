# Credential rotation — accounts-api

## Every credential this service holds

| Credential | Source of truth | Scheduled rotation | Mechanism | **Target time to rotate in an incident** |
|---|---|---|---|---|
| DB app user `accounts_app` | Secrets Manager `prod/accounts-api/db` | **30 days** | Secrets Manager rotation Lambda, *alternating-users* strategy | **≤ 15 min** to old credential being useless |
| RDS master user | Secrets Manager (RDS-managed) | 7 days (RDS default) | `manage_master_user_password` | ≤ 5 min (`rotate-secret`) — nobody uses it day to day |
| KYC provider API key | Secrets Manager `prod/accounts-api/kyc` | **90 days** | vendor API: create key B → store → verify → revoke key A | **≤ 60 min** (vendor-dependent; runbook has the vendor's 24/7 contact) |
| AWS credentials (IRSA) | STS, issued per pod | automatic, ≤ 1 h lifetime | projected SA token → `AssumeRoleWithWebIdentity` | **≤ 5 min**: revoke all sessions issued before now (below) |
| Message-stream access | IAM via the same IRSA role (assumption: MSK IAM auth / Kinesis) | n/a — no static secret | — | same as IRSA |
| K8s SA token | — | not mounted (`automountServiceAccountToken: false`) | — | n/a |

**Overall target: every credential the service holds rotated within 60 minutes of the decision, DB and AWS within 15.**

## Normal (scheduled) rotation, DB credential
1. Secrets Manager invokes the rotation Lambda every 30 days. *Alternating users*: the Lambda sets a new password on the **other** user (`accounts_app_a` / `accounts_app_b`, identical grants) and marks it `AWSCURRENT`; the previous one stays valid as `AWSPREVIOUS`.
2. External Secrets refreshes every 5 min; kubelet updates the mounted file within ~60 s.
3. The app opens new connections with the new file; existing connections on the old user keep working until they are recycled (pool max lifetime 30 min). **No restart, no downtime.**
4. Rotation succeeds only if the Lambda's `testSecret` step logs in with the new value; failure raises a CloudWatch alarm to the platform on-call, the old credential remains valid.

Why alternating users: single-user rotation invalidates the old password the moment it changes, so every pod that has not yet re-read the file fails for up to ~6 min. Alternating users removes that race — which is exactly the property we have to give up in an incident (below).

## Emergency rotation (credential believed compromised) — minutes, not schedule
Trigger: Falco/GuardDuty alert with suspected credential access, secret found in a log/leak, insider event. Decision by incident commander; executed by either platform engineer or the accounts-api on-call (both have the break-glass role `secrets-incident-rotator`).

**DB credential (target ≤ 15 min):**
1. `aws secretsmanager rotate-secret --secret-id prod/accounts-api/db` **twice**, waiting for the first to finish. With alternating users, one rotation still leaves the old password valid as `AWSPREVIOUS`; the second rotation changes the *other* user too, so **both** previously known passwords are dead. (≈ 2 × 1 min)
2. Kill existing sessions of the old user in Postgres: `SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE usename = '<old user>';` — rotation does not end established connections an attacker may already hold.
3. Force delivery instead of waiting for the 5-min refresh: `kubectl -n accounts annotate externalsecret accounts-api-db force-sync=$(date +%s) --overwrite`, then `kubectl -n accounts rollout restart deploy/accounts-api`. Expect a few seconds of elevated 5xx while pods reconnect — **accepted during an incident**; that is the trade we refuse on schedule.
4. Verify: CloudTrail shows `GetSecretValue` only from the ESO role; `pg_stat_activity` shows only the new user; app health green.

**AWS (IRSA) credentials (target ≤ 5 min):** attach an inline deny to role `accounts-api-*` with condition `aws:TokenIssueTime < <now>` (the console "Revoke active sessions" button does exactly this). Pods get fresh tokens automatically within minutes; any stolen STS credential stops working immediately.

**KYC key (target ≤ 60 min):** create a second key at the vendor, put it in Secrets Manager (`put-secret-value`), force-sync + restart as above, verify a KYC call succeeds, **then** revoke the old key at the vendor. Bounded by vendor API/support availability, hence 60 min not 15.

**Afterwards:** the old values are never "restored"; the incident ticket records each rotation's timestamp (CloudTrail `RotateSecret`, `PutSecretValue` events are the audit trail).

## Practised, not just written
Quarterly game day: run the emergency procedure against staging with a timer. If the DB target is missed twice, the procedure is changed, not the target.

## Encryption (one line)
RDS storage and snapshots, Secrets Manager secrets and EKS etcd Secrets are encrypted with customer-managed KMS keys held in the prod account (key policy: only service roles decrypt; key admins cannot), which protects against stolen/shared snapshots, backups and storage — **not** against an attacker running code in the pod, who sees what the app sees.
