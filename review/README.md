# Section 4 — Review and Remediate

| Artefact | Before (prod today, fixture must FAIL) | After (fixture must PASS) | Prevention | Test |
|---|---|---|---|---|
| (a) Deployment + Role | `workload/before.yaml` | `workload/after.yaml` (ranked defects in header) | `policies/kyverno/require-pod-security.yaml`, `disallow-latest-tag.yaml`, `require-resources.yaml`, `restrict-rbac.yaml` | `kyverno test policies/kyverno/tests-review` → 18/18 |
| (b) Terraform | `terraform/before/main.tf` | `terraform/after/main.tf` (ranked defects in header) | `policies/conftest/terraform/terraform.rego` | `conftest test --parser hcl2 ...` → before 10 failures, after 0 |
| (c) IAM | original in brief | `iam/accounts-api-pod-role.json` | same rego (IAM rules) | `conftest verify` → 7/7 |

Where they run: Kyverno policies in the cluster (admission, Enforce) **and** in CI (`policies` job), so a bad manifest fails the PR before it ever reaches admission. Conftest runs in the `iac` job on every PR, blocking; exceptions only via `security/waivers` (scanner `conftest`).
