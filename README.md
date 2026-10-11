# okta-ideas

Okta / IAM automation scripts and tooling. Each script is standalone and
solves one real problem; all of them share one client module so auth,
pagination, and rate-limiting are solved once.

Every tool ships in **Python** and **PowerShell**.

## Setup

```bash
pip install -r requirements.txt
export OKTA_DOMAIN=https://dev-123456.okta.com   # your tenant, no trailing slash needed
export OKTA_API_TOKEN=00...                      # SSWS token; read-only is enough for auditors
```

PowerShell users need no extra modules beyond the repo itself:

```powershell
$env:OKTA_DOMAIN    = "https://dev-123456.okta.com"
$env:OKTA_API_TOKEN = "00..."                    # SSWS token; read-only is enough for auditors
```

Tokens live in environment variables only -- nothing here will ever ask you
to paste one into a file.

## okta-guardrails (`okta-guardrails/`)

Okta-aware guardrails and a who-gains/who-loses access preview for Terraform
plans. Reads `terraform show -json`, re-evaluates changed group rules against a
user population, and fails PRs that weaken the tenant. Standalone Python package
with its own tests and GitHub Action; see [okta-guardrails/README.md](okta-guardrails/README.md).

## Scripts

### Python (`scripts/`)

| Script | What it does |
|---|---|
| `scripts/mfa_coverage.py` | Audits MFA enrollment: who has no MFA, who has only phishable factors (push/TOTP/SMS), and who has phishing-resistant MFA (WebAuthn/FIDO2). |
| `scripts/sign_on_policy_linter.py` | Lints sign-on policies: flags password-only rules, missing device-trust conditions, and over-broad network zones. |
| `scripts/stale_account_sweeper.py` | Finds dormant and never-logged-in accounts; dry-run by default, `--disable --confirm` to deactivate. |
| `scripts/license_optimizer.py` | Finds unused app assignments and duplicate identities, with a per-seat dollar-waste estimate. |
| `scripts/break_glass_monitor.py` | Watches emergency break-glass admin logins: one-shot scan or `--watch` polling; success vs failed. |
| `scripts/admin_privilege_reviewer.py` | Reviews super admin + elevated role holders: grant dates, last admin activity, MFA status, stale grants. |
| `scripts/jml_automation_kit.py` | CSV-driven joiner/mover/leaver provisioning; dry-run by default, `--apply` to execute, idempotent. |
| `scripts/app_rationalizer.py` | Ranks SSO apps by login volume; flags duplicates and zero-use removal candidates. |
| `scripts/system_log_threat_detections.py` | Detects impossible travel, MFA fatigue, and token replay / session anomalies in the System Log. |
| `scripts/tenant_drift_detector.py` | Snapshots tenant config to versioned JSON and diffs snapshots over time. |

### PowerShell (`scripts/`)

| Script | What it does |
|---|---|
| `scripts/sign_on_policy_linter.ps1` | Lints sign-on policies: flags password-only rules, missing device-trust conditions, and over-broad network zones. |
| `scripts/stale_account_sweeper.ps1` | Finds dormant and never-logged-in accounts; dry-run by default, `-Disable -Confirm` to deactivate. |
| `scripts/license_optimizer.ps1` | Finds unused app assignments and duplicate identities, with a per-seat dollar-waste estimate. |
| `scripts/break_glass_monitor.ps1` | Watches emergency break-glass admin logins: one-shot scan or `-Watch` polling; success vs failed. |
| `scripts/admin_privilege_reviewer.ps1` | Reviews super admin + elevated role holders: grant dates, last admin activity, MFA status, stale grants. |
| `scripts/jml_automation_kit.ps1` | CSV-driven joiner/mover/leaver provisioning; dry-run by default, `-Apply` to execute, idempotent. |
| `scripts/app_rationalizer.ps1` | Ranks SSO apps by login volume; flags duplicates and zero-use removal candidates. |
| `scripts/system_log_threat_detections.ps1` | Detects impossible travel, MFA fatigue, and token replay / session anomalies in the System Log. |
| `scripts/tenant_drift_detector.ps1` | Snapshots tenant config to versioned JSON and diffs snapshots over time. |

Run any script with `--help` for its options (Python) or `Get-Help` (PowerShell), e.g.:

```bash
python scripts/sign_on_policy_linter.py --help
```

```powershell
Get-Help ./scripts/sign_on_policy_linter.ps1 -Full
```

Python examples:

```bash
python scripts/mfa_coverage.py --limit 25        # trial run on 25 users
python scripts/mfa_coverage.py --json --output report.json
python scripts/tenant_drift_detector.py --snapshot
```

PowerShell examples:

```powershell
./scripts/stale_account_sweeper.ps1 -Days 90 -Json -Output stale.json
./scripts/tenant_drift_detector.ps1 -Snapshot
```

## Roadmap

The original nine ideas are all implemented (both languages). Further ideas welcome as issues.

- ✅ Sign-on policy linter — [`sign_on_policy_linter.py`](scripts/sign_on_policy_linter.py) · [`sign_on_policy_linter.ps1`](scripts/sign_on_policy_linter.ps1)
- ✅ Stale account sweeper — [`stale_account_sweeper.py`](scripts/stale_account_sweeper.py) · [`stale_account_sweeper.ps1`](scripts/stale_account_sweeper.ps1)
- ✅ License optimizer — [`license_optimizer.py`](scripts/license_optimizer.py) · [`license_optimizer.ps1`](scripts/license_optimizer.ps1)
- ✅ Break-glass monitor — [`break_glass_monitor.py`](scripts/break_glass_monitor.py) · [`break_glass_monitor.ps1`](scripts/break_glass_monitor.ps1)
- ✅ Admin privilege reviewer — [`admin_privilege_reviewer.py`](scripts/admin_privilege_reviewer.py) · [`admin_privilege_reviewer.ps1`](scripts/admin_privilege_reviewer.ps1)
- ✅ JML automation kit — [`jml_automation_kit.py`](scripts/jml_automation_kit.py) · [`jml_automation_kit.ps1`](scripts/jml_automation_kit.ps1)
- ✅ App rationalizer — [`app_rationalizer.py`](scripts/app_rationalizer.py) · [`app_rationalizer.ps1`](scripts/app_rationalizer.ps1)
- ✅ System Log threat detections — [`system_log_threat_detections.py`](scripts/system_log_threat_detections.py) · [`system_log_threat_detections.ps1`](scripts/system_log_threat_detections.ps1)
- ✅ Tenant drift detector — [`tenant_drift_detector.py`](scripts/tenant_drift_detector.py) · [`tenant_drift_detector.ps1`](scripts/tenant_drift_detector.ps1)
