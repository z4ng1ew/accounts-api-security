# Section 4 — Findings and structural prevention

Finding the bugs is the easy half; each row names the policy that makes it impossible to reintroduce.

| # | Finding (vulnerable/deployment.yaml) | Threat | Fix (fixed/) | Prevented by |
|---|---|---|---|---|
| F1 | `hostNetwork: true` — bypasses NetworkPolicy, sees node traffic | T5/T6 | removed | `require-pod-security` › host-namespaces |
| F2 | `:latest` tag — mutable, unverifiable | T1 | pinned digest | `disallow-latest-tag` + `verify-image-signature` (digest required) |
| F3 | `privileged: true` — trivial node escape | T5 | false, caps drop ALL | `require-pod-security` › privileged |
| F4 | runs as root | T5 | runAsNonRoot, UID 65532 | `require-pod-security` › non-root |
| F5 | DB password literal in env | T3 | ExternalSecret → secretRef | `disallow-secret-literals` + Gitleaks in CI |
| F6 | static AWS key in env | T3/T7 | IRSA | `disallow-secret-literals` (AWS key names) + Gitleaks |
| F7 | no resource limits — noisy neighbour in shared cluster | (availability, not in TM; added because shared cluster) | requests/limits | `require-resources` |
| F8 | hostPath `/` mount | T5 | removed | `require-pod-security` › hostPath |

Policies are tested in `policies/kyverno/tests` with the vulnerable manifest as a must-fail fixture and the fixed one as must-pass — so a regression in either the manifests or the policies breaks CI.

**Rollout:** policies start in `Audit` cluster-wide for one week (other teams' workloads), `Enforce` from day 1 on the `accounts` namespace. See DECISIONS.md D3.
