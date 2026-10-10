# How to get a waiver

A gate failed and you can't fix it now. Do this — it takes ~10 minutes, not a ticket queue.

1. Add an entry to `waivers.yaml` in the same PR (copy WVR-0001). Fill **reason**, **compensating_control**, **threat**, **ticket**.
2. Max lifetime: 30 days for CRITICAL, 90 days otherwise.
3. A platform-team member (CODEOWNERS) approves. You cannot approve your own waiver.
4. Merge. CI regenerates `.trivyignore` from the file — never edit ignore files by hand (CI regenerates and overwrites them).
5. 14 days before expiry CI emits a warning; on expiry the build breaks again and the daily `waiver-expiry` job opens an issue to the owner.

**Not waivable:** Gitleaks findings. A leaked secret is rotated, not excepted.

**Break-glass (prod incident, platform team asleep):** label the PR `break-glass`; gates run in report-only, deploy proceeds, and a mandatory issue is opened. A break-glass merge without a waiver PR within 48h is reviewed at the weekly platform sync. The label can only be applied by a repo admin.
