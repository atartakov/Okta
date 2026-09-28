# okta-ideas

Okta / IAM automation scripts and tooling. Each script is standalone and
solves one real problem; all of them share one client module so auth,
pagination, and rate-limiting are solved once.

## Setup

```bash
pip install -r requirements.txt
export OKTA_DOMAIN=https://dev-123456.okta.com   # your tenant, no trailing slash needed
export OKTA_API_TOKEN=00...                      # SSWS token; read-only is enough for auditors
```

Tokens live in environment variables only -- nothing here will ever ask you
to paste one into a file.

## Scripts

| Script | What it does |
|---|---|
| `scripts/mfa_coverage.py` | Audits MFA enrollment: who has no MFA, who has only phishable factors (push/TOTP/SMS), and who has phishing-resistant MFA (WebAuthn/FIDO2). |

Run any script with `--help` for its options, e.g.:

```bash
python scripts/mfa_coverage.py --limit 25        # trial run on 25 users
python scripts/mfa_coverage.py --json --output report.json
```

## Roadmap

Ideas queued for future scripts (see issues):

- Sign-on policy linter -- flag password-only auth, missing device trust, over-broad network zones
- Stale account sweeper -- dormant users, auto-disable + report
- License optimizer -- unused app assignments, duplicate identities, estimated waste
- Break-glass monitor -- alert on emergency admin account usage
- Admin privilege reviewer -- super admin holders, stale grants
- JML automation kit -- joiner/mover/leaver provisioning scripts
- App rationalizer -- duplicate/unused SSO apps by login stats
- System Log threat detections -- impossible travel, MFA fatigue, token replay
- Tenant drift detector -- snapshot config, diff over time
