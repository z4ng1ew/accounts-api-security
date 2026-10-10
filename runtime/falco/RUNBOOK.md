# Runbook — `accounts-api unexpected outbound connection` (Falco, CRITICAL)

## Alert payload (Falco JSON → Falcosidekick)
```json
{
  "rule": "accounts-api unexpected outbound connection",
  "priority": "Critical",
  "time": "2026-10-10T09:41:07.312Z",
  "output_fields": {
    "fd.sip": "185.220.101.4", "fd.sport": 443, "fd.sip.name": "",
    "proc.name": "python3", "proc.cmdline": "python3 /app/main.py", "proc.pname": "tini",
    "user.uid": 65532,
    "k8s.pod.name": "accounts-api-7d9c8b6f5-x2k4p", "k8s.ns.name": "accounts",
    "container.image.repository": "123456789012.dkr.ecr.ap-south-1.amazonaws.com/accounts-api",
    "container.image.digest": "sha256:4f2b9d0e...",
    "evt.hostname": "ip-10-0-12-34.ap-south-1.compute.internal"
  },
  "tags": ["accounts-api", "network", "T9", "T7", "T2"]
}
```

## Where it lands, who is woken
| Destination | Purpose |
|---|---|
| **PagerDuty service `accounts-api`, urgency HIGH** | pages the **accounts-api on-call engineer** (owning team rota). Escalates to the **platform on-call** after 15 min unacknowledged. |
| Slack `#sec-alerts` | visibility for both teams; thread = incident log |
| CloudWatch Logs → S3 (Object Lock) in log-archive account | evidence, retained 1 year (regulatory) |

Owner: accounts-api team (they know what the service should talk to). Platform team owns the rule's tuning; allow-list changes go through CODEOWNERS like any policy.

Dedup: Falcosidekick groups by `k8s.pod.name + fd.sip` for 10 min, so a looping process pages once.

## First three steps (target: within 15 minutes)
1. **Contain without destroying evidence.** Do **not** delete the pod. Isolate it:
   `kubectl -n accounts label pod <pod> quarantine=true --overwrite` — a pre-installed NetworkPolicy denies all ingress/egress for `quarantine=true`, and the Deployment's selector excludes the label, so a clean replacement pod starts and traffic is unaffected. If `proc.name` is **not** `python3` (shell, curl, unknown binary) treat as confirmed compromise and go straight to step 3 in parallel.
2. **Scope: what did it reach and with which identity?** In the first 10 minutes check:
   - the destination: is `fd.sip` the KYC provider's new IP or a known CDN (benign config drift), or unknown/TOR/hosting (hostile)?
   - CloudTrail for the pod's IRSA role `accounts-api-prod` over the last 24h: any `GetSecretValue` outside the normal pattern, any call from an IP that is not the NAT gateway?
   - GuardDuty EKS findings for the same node; other Falco alerts on the same pod/node.
   - the image digest in the alert vs. the digest currently deployed and signed (`cosign verify`).
3. **Decide and act.**
   - *Benign* (e.g. KYC vendor added an endpoint): unquarantine, open a PR to update the allow-list, close as false positive with reason.
   - *Hostile or unclear*: declare an incident (SEV-1). Rotate the DB and KYC secrets in Secrets Manager (External Secrets picks them up within 1h; force a sync), roll the Deployment to the last known-good signed digest, snapshot the node's EBS volume and cordon the node. If customer data may have left: notify the incident manager and DPO immediately — CERT-In requires reporting within **6 hours** for a bank operating in India (ap-south-1), and the RBI incident reporting window also applies.
