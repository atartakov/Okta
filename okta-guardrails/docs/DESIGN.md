# Design notes

## Goal

Make an Okta Terraform pull request reviewable by a human in under a minute: who gains access, who loses it, and whether the tenant gets weaker.

## Decisions

**Read the plan, not the HCL.** `terraform show -json` has resolved variables, `for` expressions, modules and the prior state. Static HCL scanning can't see that `join(" || ", local.depts)` expands to a three-department rule, or what an existing rule looked like before the edit. The plan can.

**Judge the change, not the end state.** Every check compares `before` and `after`. A tenant with existing debt can adopt the tool on day one without a wall of findings; new risk is still caught.

**Rebuild group membership, don't diff one expression.** A user only loses access if *nothing* else grants it. The preview rebuilds each touched group from direct members plus every active rule targeting it, before and after. Diffing just the edited rule over-reports losses whenever rules overlap, which in real tenants is constantly.

**Resolve names, not ids.** Plans are full of `00g…` ids and, for new resources, values that are unknown until apply. Ids are resolved from state; unknown values are resolved through the plan's `configuration` references, so a new group created in the same PR still shows by name.

**Refuse to guess.** Unsupported expression syntax produces BR003 ("impact not computed"), never a silent zero.

**No dependencies.** Standard-library Python 3.10+. Easy to audit, easy to run in a locked-down pipeline.

**Python checks over Rego, for now.** The checks need cross-resource joins (group rule → group → admin role, group → app assignment) and id/reference resolution. That's straightforward in Python and awkward in Rego. Exporting findings as OPA input for teams that standardise on Rego is on the roadmap.

## Prior art

Surveyed October 2026 (GitHub repository and code search, Terraform Registry, web search). Searches can't prove nobody has built something; this is what turned up.

| Project | What it does | How this differs |
|---|---|---|
| Checkov `CKV_OKTA_1` | One static check: app sign-on rule requires 2FA | Plan-aware, cross-resource, plus access impact |
| Mondoo cnspec (HashiTalks 2023 demo) | MQL policies over Okta Terraform code and plans | Demo policy pack; no membership impact |
| readtheplan, ChangeGate, PlanShield, tfplan2md | Generic plan risk tiers and summaries | Not Okta-aware |
| Okta Access Testing Tool / Policy Simulation API | Simulates authentication-policy outcomes for chosen users | Auth policies only, live tenant, per user; doesn't evaluate group-rule membership |
| Okta app sign-in policy branches (monitoring) | Trial policy changes against live traffic | Auth policies, after deployment, in-product |
| Burnham provider `oelevaluate`, Okta EL VS Code extension, Okta Expression Builder, ORB | Evaluate one expression against one sample context | No population, no before/after, no PR report |
| idpdrift | Read-only drift alerts on live admin/credential posture | Detects after the fact; this runs before apply |
| delize/okta-tools | Generates Terraform from existing Okta config | Import tooling; complementary |
| Okta Terraform templates (oktadev, joevanhorn, cjparker102 and others) | Okta-as-code layouts with plan/apply pipelines | This plugs into them as a check |

## Roadmap

- **Phase 1 (this release):** checks OG001–OG008, access preview BR001–BR004, CLI, Action, demo fixtures, CI.
- **Phase 2:** capture real plans from a developer tenant to replace the hand-built fixtures; read-only population exporter (Okta API, `okta.users.read` + `okta.groups.read`, private_key_jwt); SARIF output.
- **Phase 3:** apps reached through `okta_app_group_assignments` and push groups; group-to-AWS permission-set mapping; waivers file with expiry and owner.
- **Phase 4:** optional cross-check of authentication-policy changes with Okta's Policy Simulation API for named VIP and service accounts.
