# accounts-api-security

Security controls for `accounts-api`, a containerised banking API on EKS (ap-south-1): threat model, signed build, gated pipeline with a waiver path, admission and runtime policy, egress control, secrets delivery and log redaction.

**Start here:** [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md) → [`DECISIONS.md`](DECISIONS.md). Every control names the threat it serves (T1–T10).

## Run the policy tests

Requirements: Python 3.10+, [Kyverno CLI](https://kyverno.io/docs/kyverno-cli/) ≥ 1.13, [Conftest](https://www.conftest.dev/) ≥ 0.56. Optional: OpenTofu or Terraform ≥ 1.6.

```bash
pip install pyyaml pytest
make test
```

Expected output:

| Check | Command | Result |
|---|---|---|
| Waiver + redaction unit tests | `pytest -q security/scripts app/logging` | `12 passed` |
| Waiver file validity | `check_waivers.py validate` | `1 valid waiver(s), 0 error(s)` |
| Baseline admission policies | `kyverno test policies/kyverno/tests` | `16 tests passed` |
| Section 4 production manifest (fails) vs fix (passes) | `kyverno test policies/kyverno/tests-review` | `18 tests passed` |
| IaC rules unit tests | `conftest verify -p policies/conftest/terraform` | `7 passed` |
| Section 4 Terraform: prod version | `conftest test --parser hcl2 ... review/terraform/before` | **10 failures (expected)** |
| Section 4 Terraform: fixed version | `conftest test --parser hcl2 ... review/terraform/after` | `0 failures` |

See a bad manifest rejected with messages:
```bash
kyverno apply policies/kyverno/require-pod-security.yaml policies/kyverno/restrict-rbac.yaml -r review/workload/before.yaml
```

See the waiver gate fail on expiry:
```bash
python security/scripts/check_waivers.py validate security/waivers/waivers.yaml --today 2027-01-01   # exit 1
```

Not covered by `make test`: signature verification (`policies/kyverno/verify-image-signature.yaml`) needs network access to Rekor and the registry, so apply it to a kind cluster with Kyverno and try an unsigned image in namespace `accounts`. IaC validation: `make tf-validate` (I used OpenTofu, a drop-in Terraform fork, because HashiCorp downloads are blocked in my region; `TF=terraform` works too).

## Layout

| Path | Section | Threats |
|---|---|---|
| `docs/THREAT_MODEL.md` | 1 Threat model | — |
| `.github/workflows/build-sign.yml`, `terraform/gha-oidc-trust.json`, `app/Dockerfile` | 2 Build & release integrity | T1, T2, T4 |
| `.github/workflows/security-gates.yml`, `security/waivers/`, `security/scripts/`, `docs/BREAK_GLASS.md` | 3 Gates & waiver path | T2, T3, T4 |
| `review/` (before/after fixtures), `policies/kyverno/restrict-rbac.yaml`, `policies/conftest/` | 4 Review & remediate | T1, T3, T5, T6, T7 |
| `policies/kyverno/`, `k8s/fixed/namespace.yaml`, `runtime/falco/`, `k8s/egress/` | 5 Admission, runtime, egress | T1, T5, T6, T7, T9 |
| `k8s/secrets/`, `docs/ROTATION.md`, `docs/LOG_REDACTION.md`, `app/logging/`, `terraform/` | 6 Secrets & data protection | T3, T7, T8 |
| `DECISIONS.md` | Part 2 | all |

## AWS ↔ local mapping

| AWS (production) | In this repo |
|---|---|
| EKS | Kyverno CLI tests; kind for a live run |
| ECR (immutable tags, KMS) | `terraform/github_oidc.tf`; ghcr.io as a free stand-in |
| IAM / IRSA / GitHub OIDC | `terraform/*.tf`, `terraform/gha-oidc-trust.json`, `review/iam/` (authored, not applied) |
| KMS, Secrets Manager | `terraform/kms.tf`, `terraform/secrets.tf`, `k8s/secrets/` |
| GuardDuty EKS Runtime Monitoring | Falco rule `runtime/falco/accounts-api-rules.yaml` |
| CloudTrail | `review/terraform/after/main.tf` (org trail) |
