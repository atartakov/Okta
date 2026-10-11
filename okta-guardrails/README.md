# okta-guardrails

**Know who gains access before you merge.**

`okta-guardrails` reads a Terraform plan for Okta and answers the two questions a reviewer actually has:

1. **Who gains and who loses access?** It re-evaluates every changed group rule against a user population and reports, per group and per app, exactly who is added and who is removed.
2. **Does this weaken the tenant?** Okta-specific checks catch super admin grants, write scopes on service apps, wildcard redirects, single-factor rules, dropped phishing resistance, long sessions and deleted controls.

It runs as a CLI or a GitHub Action, needs no Okta credentials to analyse a plan, and has no runtime dependencies.

```
$ okta-guardrails check --plan plan.json --population users.json

## okta-guardrails: ❌ blocked
5 critical, 9 high, 5 medium (fails on high and above)

### Who gains and loses access
| Group                | Apps                    | Admin role                    | Before | After | Gains | Loses |
|----------------------|-------------------------|-------------------------------|-------:|------:|------:|------:|
| Salesforce-Admin     | Salesforce              | -                             |      5 |   352 |  +347 |    -0 |
| AWS-Prod             | AWS IAM Identity Center | -                             |    342 |   118 |    +0 |  -224 |
| Okta-Helpdesk-Admins | -                       | HELP_DESK_ADMIN, SUPER_ADMIN  |      0 |    50 |   +50 |    -0 |
| Sales-Leadership     | -                       | -                             |      0 |     5 |    +5 |    -0 |
```

That first row is a one-line change: `user.department == "Sales Operations" && user.title == "Salesforce Administrator"` became `String.stringContains(user.department, "Sales")`. It reads like a cleanup. It makes 347 people Salesforce admins. Nothing in a normal `terraform plan` tells you that.

## Why this exists

In Okta, a group rule is an access decision written as a string. Terraform shows you the string changed; it can't show you what the string *means* for your users. Reviewers approve expression edits on trust, and the consequences show up later in an access review, or an incident.

Generic plan scanners (Checkov, readtheplan, ChangeGate) classify infrastructure changes but don't understand Okta identity semantics. Okta's own Access Testing Tool and Policy Simulation API test authentication policies for chosen users. Single-expression evaluators (the Burnham provider's `oelevaluate`, the VS Code OEL extension, the Okta Expression Builder) test one expression against one sample profile. None of them answer "across everyone, who gains and loses access in this PR?" See [docs/DESIGN.md](docs/DESIGN.md#prior-art) for the full survey.

## Quick start

```bash
pip install .
# the bundled demo: 1,500 synthetic users and a deliberately bad PR
python scripts/gen_population.py > fixtures/population.json
okta-guardrails check --plan fixtures/plan_risky.json --population fixtures/population.json
okta-guardrails check --plan fixtures/plan_clean.json --population fixtures/population.json

# your own plan
terraform plan -out plan.bin && terraform show -json plan.bin > plan.json
okta-guardrails check --plan plan.json --population users.json
```

Exit codes: `0` passed, `1` a finding at or above `--fail-on` (default `high`), `2` bad input.

| Option | Meaning |
|---|---|
| `--population FILE` | Users to evaluate rules against (enables the access preview) |
| `--fail-on SEVERITY` | `info`, `low`, `medium`, `high`, `critical` |
| `--max-change N` | Flag any group whose membership moves by more than N in one PR (default 50) |
| `--skip RULE_ID` | Turn a check off (repeatable) |
| `--format json` | Machine-readable output |

## GitHub Action

```yaml
- run: terraform show -json plan.bin > plan.json
- uses: dorkagent/Okta/okta-guardrails@main
  with:
    plan: plan.json
    population: users.json   # optional
    fail-on: high
```

The report goes to the job summary and to a single PR comment that updates on every push. [`okta-guardrails-plan.yml`](../.github/workflows/okta-guardrails-plan.yml) plans [`examples/baseline`](examples/baseline) against a real developer tenant and runs the action; it stays off until the tenant secrets exist.

## Checks

| ID | Check | Severity |
|---|---|---|
| OG001 | Super admin or org admin granted to a group, user or service app | critical / high |
| OG002 | `okta.*.manage` scopes granted to an app (role, policy, authenticator, IdP and API-token scopes are critical) | critical / high |
| OG003 | Redirect URI with a wildcard or plain http, or `wildcard_redirect` turned on | high |
| OG004 | Implicit or password grant, public client without PKCE, service app on a shared secret | high / medium |
| OG005 | App sign-in rule becomes single-factor, or drops the phishing-resistant requirement | high / critical |
| OG006 | Global session over 12 h, idle over 2 h, persistent cookies, re-authentication over 12 h | medium / low |
| OG007 | A policy, rule, network zone, authenticator or behavior is deleted | high |
| OG008 | A group rule feeds a group that holds an admin role | critical / high |
| BR001 | Users become admins through a rule change (with the count) | critical / high |
| BR002 | A group's membership changes by more than `--max-change` | high |
| BR003 | A changed rule uses syntax the evaluator doesn't model, so its impact is unknown | low |
| BR004 | A rule is deleted or deactivated and its members stay behind with nothing maintaining them | medium |

Checks look at the change, not the end state. A wildcard redirect that already exists isn't re-flagged when someone renames the app; one that's added is.

## The population file

```json
{
  "groups": {"00g...": "Engineering"},
  "users": [
    {"id": "00u...", "login": "sam@example.com", "status": "ACTIVE",
     "profile": {"department": "Sales", "title": "Account Executive", "employeeType": "Employee"},
     "groups": ["Everyone", "Sales"]}
  ]
}
```

`groups` on a user are memberships that *don't* come from group rules: directory-sourced and manual assignments. Membership from rules is computed. The bundled file is synthetic (`scripts/gen_population.py`). A read-only exporter for a real tenant is on the roadmap.

## How the access preview works

For every group a changed rule touches, membership is rebuilt twice, before and after the plan, from three sources: direct members, every other active rule that targets the group, and the changed rule. The difference is the gain and loss. That's why narrowing one rule doesn't report a loss for users another rule still covers, and why direct members never show up as lost.

Rules that are deleted or deactivated without `remove_assigned_users = true` leave their members behind as plain assignments, so they're reported as kept rather than lost.

**Limits, stated plainly.** The evaluator is a local approximation of Okta Expression Language written from Okta's public docs. It is not Okta's engine. It covers comparisons, boolean logic, ternaries, common `String.*` and `Arrays.*` functions, and the `isMemberOf*` group functions. Anything else is reported as BR003 instead of guessed. It doesn't model rule chaining, `user.isMemberOf({...})`, or app-profile (`appuser.*`) attributes. Okta's server is the source of truth; this tool tells you where to look before you find out the hard way.

## Repository layout

```
src/okta_guardrails/   plan reader, OEL evaluator, checks, access preview, report, CLI
tests/                 pytest suite (run: pytest)
fixtures/              demo plans (population.json is generated)
scripts/               generators for the fixtures
examples/baseline/     Terraform for a small, safe baseline tenant (OAuth service app, private_key_jwt)
docs/DESIGN.md         decisions, prior art, roadmap
action.yml             composite GitHub Action
(workflows live in the repo root: .github/workflows/okta-guardrails-*.yml)
```

## Safety

- Analysing a plan needs no credentials and makes no network calls.
- The example Terraform authenticates as an OAuth service app with `private_key_jwt` and narrow scopes, never an SSWS token.
- Break-glass admin accounts belong outside Terraform.
- Nothing here applies changes. The workflow plans; a human applies.
- All data in this repo is synthetic.
