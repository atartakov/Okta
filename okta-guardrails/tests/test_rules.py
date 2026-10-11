from okta_guardrails.rules import iso_minutes, run_rules

from conftest import make_plan


def ids(findings):
    return sorted({f.rule_id for f in findings})


def test_risky_plan_trips_every_guardrail(risky):
    found = run_rules(risky)
    assert ids(found) == ["OG001", "OG002", "OG003", "OG004", "OG005", "OG006", "OG007", "OG008"]


def test_clean_plan_has_no_findings(clean):
    assert run_rules(clean) == []


def test_existing_debt_is_not_reflagged():
    # The app already had a wildcard redirect; renaming it must not fail the PR.
    before = {"label": "Old", "type": "web", "redirect_uris": ["https://*.example.com/cb"], "wildcard_redirect": "SUBDOMAIN"}
    after = {**before, "label": "Old (renamed)"}
    plan = make_plan([("okta_app_oauth.old", ["update"], before, after)])
    assert run_rules(plan) == []


def test_localhost_http_redirect_allowed():
    after = {"label": "Dev", "type": "web", "redirect_uris": ["http://localhost:8080/cb"], "wildcard_redirect": "DISABLED"}
    plan = make_plan([("okta_app_oauth.dev", ["create"], None, after)])
    assert run_rules(plan, only={"OG003"}) == []


def test_super_admin_resolves_new_group_through_config_references():
    plan = make_plan(
        [("okta_group.ops", ["create"], None, {"name": "Ops-Admins"}, {"id": True}),
         ("okta_group_role.ops", ["create"], None, {"role_type": "SUPER_ADMIN", "group_id": None}, {"group_id": True})],
        configs=[("okta_group_role.ops", {"group_id": {"references": ["okta_group.ops.id", "okta_group.ops"]}})])
    [f] = run_rules(plan, only={"OG001"})
    assert f.severity == "critical" and "Ops-Admins" in f.title


def test_signon_rules_plural_resource():
    before = {"rule": [{"name": "r1", "access": "ALLOW", "factor_mode": "2FA", "constraints": [
        '{"possession":{"phishingResistant":"REQUIRED"}}']}]}
    after = {"rule": [{"name": "r1", "access": "ALLOW", "factor_mode": "2FA", "constraints": [
        '{"possession":{"required":true}}']}]}
    plan = make_plan([("okta_app_signon_policy_rules.p", ["update"], before, after)])
    [f] = run_rules(plan, only={"OG005"})
    assert f.severity == "critical"


def test_iso_minutes():
    assert iso_minutes("PT12H") == 720
    assert iso_minutes("P1DT30M") == 1470
    assert iso_minutes("PT0S") is None
    assert iso_minutes(None) is None
