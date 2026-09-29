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

## Scripts

### Python (`scripts/python/`)

| Script | What it does |
|---|---|
| `scripts/mfa_coverage.py` | Audits MFA enrollment: who has no MFA, who has only phishable factors (push/TOTP/SMS), and who has phishing-resistant MFA (WebAuthn/FIDO2). |
| `scripts/python/sign_on_policy_linter.py` | Lints sign-on policies: flags password-only rules, missing device-trust conditions, and over-broad network zones. |
| `scripts/python/stale_account_sweeper.py` | Finds dormant and never-logged-in accounts; dry-run by default, `--disable --confirm` to deactivate. |
| `scripts/python/license_optimizer.py` | Finds unused app assignments and duplicate identities, with a per-seat dollar-waste estimate. |
| `scripts/python/break_glass_monitor.py` | Watches emergency break-glass admin logins: one-shot scan or `--watch` polling; success vs failed. |
| `scripts/python/admin_privilege_reviewer.py` | Reviews super admin + elevated role holders: grant dates, last admin activity, MFA status, stale grants. |
| `scripts/python/jml_automation_kit.py` | CSV-driven joiner/mover/leaver provisioning; dry-run by default, `--apply` to execute, idempotent. |
| `scripts/python/app_rationalizer.py` | Ranks SSO apps by login volume; flags duplicates and zero-use removal candidates. |
| `scripts/python/system_log_threat_detections.py` | Detects impossible travel, MFA fatigue, and token replay / session anomalies in the System Log. |
| `scripts/python/tenant_drift_detector.py` | Snapshots tenant config to versioned JSON and diffs snapshots over time. |

### PowerShell (`scripts/powershell/`)

| Script | What it does |
|---|---|
| `scripts/powershell/Sign-OnPolicyLinter.ps1` | Lints sign-on policies: flags password-only rules, missing device-trust conditions, and over-broad network zones. |
| `scripts/powershell/Stale-AccountSweeper.ps1` | Finds dormant and never-logged-in accounts; dry-run by default, `-Disable -Confirm` to deactivate. |
| `scripts/powershell/License-Optimizer.ps1` | Finds unused app assignments and duplicate identities, with a per-seat dollar-waste estimate. |
| `scripts/powershell/Break-GlassMonitor.ps1` | Watches emergency break-glass admin logins: one-shot scan or `-Watch` polling; success vs failed. |
| `scripts/powershell/Admin-PrivilegeReviewer.ps1` | Reviews super admin + elevated role holders: grant dates, last admin activity, MFA status, stale grants. |
| `scripts/powershell/JML-AutomationKit.ps1` | CSV-driven joiner/mover/leaver provisioning; dry-run by default, `-Apply` to execute, idempotent. |
| `scripts/powershell/App-Rationalizer.ps1` | Ranks SSO apps by login volume; flags duplicates and zero-use removal candidates. |
| `scripts/powershell/SystemLog-ThreatDetections.ps1` | Detects impossible travel, MFA fatigue, and token replay / session anomalies in the System Log. |
| `scripts/powershell/Tenant-DriftDetector.ps1` | Snapshots tenant config to versioned JSON and diffs snapshots over time. |

Run any script with `--help` for its options (Python) or `Get-Help` (PowerShell), e.g.:

```bash
python scripts/python/sign_on_policy_linter.py --help
```

```powershell
Get-Help ./scripts/powershell/Sign-OnPolicyLinter.ps1 -Full
```

Python examples:

```bash
python scripts/mfa_coverage.py --limit 25        # trial run on 25 users
python scripts/mfa_coverage.py --json --output report.json
python scripts/python/tenant_drift_detector.py --snapshot
```

PowerShell examples:

```powershell
./scripts/powershell/Stale-AccountSweeper.ps1 -Days 90 -Json -Output stale.json
./scripts/powershell/Tenant-DriftDetector.ps1 -Snapshot
```

## Roadmap

The original nine ideas are all implemented (both languages). Further ideas welcome as issues.

- ✅ Sign-on policy linter — [`sign_on_policy_linter.py`](scripts/python/sign_on_policy_linter.py) · [`Sign-OnPolicyLinter.ps1`](scripts/powershell/Sign-OnPolicyLinter.ps1)
- ✅ Stale account sweeper — [`stale_account_sweeper.py`](scripts/python/stale_account_sweeper.py) · [`Stale-AccountSweeper.ps1`](scripts/powershell/Stale-AccountSweeper.ps1)
- ✅ License optimizer — [`license_optimizer.py`](scripts/python/license_optimizer.py) · [`License-Optimizer.ps1`](scripts/powershell/License-Optimizer.ps1)
- ✅ Break-glass monitor — [`break_glass_monitor.py`](scripts/python/break_glass_monitor.py) · [`Break-GlassMonitor.ps1`](scripts/powershell/Break-GlassMonitor.ps1)
- ✅ Admin privilege reviewer — [`admin_privilege_reviewer.py`](scripts/python/admin_privilege_reviewer.py) · [`Admin-PrivilegeReviewer.ps1`](scripts/powershell/Admin-PrivilegeReviewer.ps1)
- ✅ JML automation kit — [`jml_automation_kit.py`](scripts/python/jml_automation_kit.py) · [`JML-AutomationKit.ps1`](scripts/powershell/JML-AutomationKit.ps1)
- ✅ App rationalizer — [`app_rationalizer.py`](scripts/python/app_rationalizer.py) · [`App-Rationalizer.ps1`](scripts/powershell/App-Rationalizer.ps1)
- ✅ System Log threat detections — [`system_log_threat_detections.py`](scripts/python/system_log_threat_detections.py) · [`SystemLog-ThreatDetections.ps1`](scripts/powershell/SystemLog-ThreatDetections.ps1)
- ✅ Tenant drift detector — [`tenant_drift_detector.py`](scripts/python/tenant_drift_detector.py) · [`Tenant-DriftDetector.ps1`](scripts/powershell/Tenant-DriftDetector.ps1)
