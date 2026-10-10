# accounts-api-security

Security controls for a containerised banking API on EKS: threat model, signed build, gated pipeline with a waiver path, admission + runtime policy, secrets and log redaction.

**Start here:** [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md) → [`DECISIONS.md`](DECISIONS.md). Every control names its threat ID (T1–T10).

## Run the tests

Requirements: Python 3.10+, [Kyverno CLI](https://kyverno.io/docs/kyverno-cli/) ≥ 1.13, optionally Terraform ≥ 1.6.

```bash
pip install pyyaml pytest
make test          # waiver unit tests + redaction tests + waiver validation + kyverno policy tests
make tf-validate   # optional
```

Expected: `12 passed` (pytest), `1 valid waiver(s), 0 error(s)`, `16 tests passed and 0 tests failed` (kyverno).

Try the waiver gate failing:
```bash
python security/scripts/check_waivers.py validate security/waivers/waivers.yaml --today 2027-01-01   # expired → exit 1
```

Signature verification (`policies/kyverno/verify-image-signature.yaml`) needs network access to Rekor and the registry, so it isn't in `kyverno test`; apply it to a kind cluster with Kyverno installed and try an unsigned image in namespace `accounts`.

## Layout
| Path | Section | Threats |
|---|---|---|
| `docs/THREAT_MODEL.md` | 1 | — |
| `.github/workflows/build-sign.yml`, `app/Dockerfile` | 2 | T1, T2, T4 |
| `.github/workflows/security-gates.yml`, `security/` | 3 | T2, T3, T4 |
| `k8s/vulnerable`, `k8s/fixed`, `k8s/FINDINGS.md` | 4 | T1, T3, T5, T7 |
| `policies/kyverno`, `runtime/falco` | 5 | T1, T3, T5, T7 |
| `terraform/`, `app/logging/`, `k8s/fixed/externalsecret.yaml` | 6 | T4, T7, T8 |
| `DECISIONS.md` | Part 2 | all |
