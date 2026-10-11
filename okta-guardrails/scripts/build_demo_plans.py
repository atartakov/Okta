"""Build the demo Terraform JSON plans in fixtures/.

These are hand-built in the shape `terraform show -json` produces (format 1.2)
so the demo runs with no Okta tenant. Phase 2 replaces them with plans captured
from a real developer tenant.

    python scripts/build_demo_plans.py
"""
import json
from pathlib import Path

from gen_population import gid

PROVIDER = "registry.terraform.io/okta/okta"
OUT = Path(__file__).resolve().parent.parent / "fixtures"

SF_APP = "0oaSALESFORCE000001"
AWS_APP = "0oaAWSIDC0000000001"
HR_SYNC = "0oaHRSYNC0000000001"
SF_POLICY = "rstSALESFORCEPOL001"
GLOBAL_POLICY = "00pGLOBALSESSION001"


def res(addr, values):
    typ, name = addr.split(".")[-2:]
    return {"address": addr, "mode": "managed", "type": typ, "name": name,
            "provider_name": PROVIDER, "schema_version": 0, "values": values}


def change(addr, actions, before, after, after_unknown=None):
    typ, name = addr.split(".")[-2:]
    return {"address": addr, "mode": "managed", "type": typ, "name": name, "provider_name": PROVIDER,
            "change": {"actions": actions, "before": before, "after": after,
                       "after_unknown": after_unknown or {}, "before_sensitive": {}, "after_sensitive": {}}}


def cfg(addr, expressions):
    typ, name = addr.split(".")[-2:]
    return {"address": addr, "mode": "managed", "type": typ, "name": name,
            "provider_config_key": "okta", "expressions": expressions, "schema_version": 0}


def group(key, name):
    return res(f"okta_group.{key}", {"id": gid(name), "name": name, "description": None,
                                     "custom_profile_attributes": None, "skip_users": None})


def grule(rid, name, expr, groups, status="ACTIVE"):
    return {"id": rid, "name": name, "status": status, "expression_type": "urn:okta:expression:1.0",
            "expression_value": expr, "group_assignments": [gid(g) for g in groups],
            "users_excluded": [], "remove_assigned_users": False}


SIGNON_PHR = ['{"knowledge":{"required":false},"possession":{"authenticationMethods":[{"key":"okta_verify","method":"signed_nonce"}],"phishingResistant":"REQUIRED","required":true}}']
SIGNON_ANY = ['{"possession":{"required":true}}']


def prior_resources():
    groups = [group(k, n) for k, n in [
        ("everyone", "Everyone"), ("sales", "Sales"), ("sales_ops", "Sales Operations"),
        ("engineering", "Engineering"), ("it", "IT"), ("sf_users", "Salesforce-Users"),
        ("sf_admin", "Salesforce-Admin"), ("aws_prod", "AWS-Prod"), ("helpdesk", "Okta-Helpdesk-Admins")]]
    return groups + [
        res("okta_app_saml.salesforce", {"id": SF_APP, "label": "Salesforce", "status": "ACTIVE",
                                         "authentication_policy": SF_POLICY}),
        res("okta_app_saml.aws", {"id": AWS_APP, "label": "AWS IAM Identity Center", "status": "ACTIVE"}),
        res("okta_app_oauth.hr_sync", {"id": HR_SYNC, "label": "HR Sync", "type": "service",
                                       "grant_types": ["client_credentials"], "response_types": ["token"],
                                       "token_endpoint_auth_method": "private_key_jwt", "redirect_uris": None,
                                       "pkce_required": False, "wildcard_redirect": "DISABLED"}),
        res("okta_app_group_assignment.sf_admin", {"id": "sfadm", "app_id": SF_APP, "group_id": gid("Salesforce-Admin")}),
        res("okta_app_group_assignment.sf_users", {"id": "sfusr", "app_id": SF_APP, "group_id": gid("Salesforce-Users")}),
        res("okta_app_group_assignment.aws_prod", {"id": "awsprd", "app_id": AWS_APP, "group_id": gid("AWS-Prod")}),
        res("okta_group_role.helpdesk", {"id": "irbHELPDESK", "group_id": gid("Okta-Helpdesk-Admins"),
                                         "role_type": "HELP_DESK_ADMIN", "disable_notifications": False}),
        res("okta_group_rule.sf_users", grule("0prSFUSERS", "Salesforce users",
                                              'user.department == "Sales" || user.department == "Sales Operations" || user.department == "Sales Engineering"', ["Salesforce-Users"])),
        res("okta_group_rule.sf_admin", grule("0prSFADMIN", "Salesforce admins",
                                              'user.department == "Sales Operations" && user.title == "Salesforce Administrator"',
                                              ["Salesforce-Admin"])),
        res("okta_group_rule.aws_prod", grule("0prAWSPROD", "AWS prod engineers",
                                              'user.department == "Engineering" && user.employeeType == "Employee"',
                                              ["AWS-Prod"])),
        res("okta_app_oauth_api_scope.hr_sync", {"id": HR_SYNC, "app_id": HR_SYNC, "issuer": "https://example.okta.com",
                                                 "scopes": ["okta.users.read", "okta.groups.read"]}),
        res("okta_app_signon_policy_rule.salesforce", {
            "id": "rulSF0001", "policy_id": SF_POLICY, "name": "Salesforce - phishing resistant", "access": "ALLOW",
            "factor_mode": "2FA", "constraints": SIGNON_PHR, "re_authentication_frequency": "PT2H",
            "priority": 1, "status": "ACTIVE"}),
        res("okta_policy_rule_signon.default", {"id": "0prGLOBAL01", "policy_id": GLOBAL_POLICY, "name": "Default session",
                                                "access": "ALLOW", "session_lifetime": 720, "session_idle": 120,
                                                "session_persistent": False, "mfa_required": True}),
        res("okta_network_zone.block_anonymizers", {"id": "nzoBLOCK01", "name": "Block anonymizers",
                                                    "type": "DYNAMIC_V2", "usage": "BLOCKLIST", "status": "ACTIVE"}),
    ]


def risky_plan():
    prior = prior_resources()
    by = {r["address"]: r["values"] for r in prior}
    rc = []

    def upd(addr, **after):
        rc.append(change(addr, ["update"], by[addr], {**by[addr], **after}))

    # 1. "Simplify" the Salesforce admin rule. It now matches every Sales* department.
    upd("okta_group_rule.sf_admin", expression_value='String.stringContains(user.department, "Sales")')
    # 2. Restrict AWS prod to one cost center. Correct intent, large removal.
    upd("okta_group_rule.aws_prod",
        expression_value='user.department == "Engineering" && user.employeeType == "Employee" && user.costCenter == "CC-100"')
    # 3. Upgrade helpdesk admins to super admin, and feed the group from a new rule.
    rc.append(change("okta_group_role.helpdesk_super", ["create"], None,
                     {"group_id": gid("Okta-Helpdesk-Admins"), "role_type": "SUPER_ADMIN",
                      "disable_notifications": True, "resource_set_id": None, "role_id": None,
                      "target_app_list": None, "target_group_list": None},
                     {"id": True}))
    rc.append(change("okta_group_rule.it_helpdesk", ["create"], None,
                     {**grule(None, "IT to helpdesk admins", 'user.department == "IT"', ["Okta-Helpdesk-Admins"])},
                     {"id": True}))
    # 4. New group plus rule; the group id is unknown until apply.
    rc.append(change("okta_group.sales_leadership", ["create"], None,
                     {"name": "Sales-Leadership", "description": "VPs and directors", "custom_profile_attributes": None,
                      "skip_users": None}, {"id": True}))
    new_rule = grule(None, "Sales leadership", 'user.title == "VP Sales" || user.title == "Director, Sales"', [])
    new_rule["group_assignments"] = [None]
    rc.append(change("okta_group_rule.sales_leadership", ["create"], None, new_rule,
                     {"id": True, "group_assignments": [True]}))
    # 5. New partner portal SPA with risky redirects and implicit flow.
    rc.append(change("okta_app_oauth.partner_portal", ["create"], None, {
        "label": "Partner Portal", "type": "browser", "grant_types": ["authorization_code", "implicit"],
        "response_types": ["code", "token", "id_token"], "pkce_required": False,
        "redirect_uris": ["https://*.partners.example.com/callback", "http://portal.partners.example.com/cb"],
        "post_logout_redirect_uris": ["https://partners.example.com"], "wildcard_redirect": "SUBDOMAIN",
        "token_endpoint_auth_method": "none", "status": "ACTIVE"}, {"id": True, "client_id": True}))
    # 6. HR sync asks for write and role-management scopes.
    upd("okta_app_oauth_api_scope.hr_sync",
        scopes=["okta.users.read", "okta.groups.read", "okta.users.manage", "okta.roles.manage"])
    # 7. A new reporting service app on a shared secret.
    rc.append(change("okta_app_oauth.bi_export", ["create"], None, {
        "label": "BI Export", "type": "service", "grant_types": ["client_credentials"], "response_types": ["token"],
        "token_endpoint_auth_method": "client_secret_basic", "redirect_uris": None, "pkce_required": False,
        "wildcard_redirect": "DISABLED", "status": "ACTIVE"}, {"id": True, "client_id": True, "client_secret": True}))
    # 8. Salesforce sign-in rule relaxed "temporarily".
    upd("okta_app_signon_policy_rule.salesforce", factor_mode="1FA", constraints=SIGNON_ANY,
        re_authentication_frequency="PT720H")
    # 9. Longer global sessions.
    upd("okta_policy_rule_signon.default", session_lifetime=10080, session_persistent=True)
    # 10. Remove the anonymizer block list.
    rc.append(change("okta_network_zone.block_anonymizers", ["delete"], by["okta_network_zone.block_anonymizers"], None))

    configs = [
        cfg("okta_group_rule.sales_leadership",
            {"group_assignments": {"references": ["okta_group.sales_leadership.id", "okta_group.sales_leadership"]},
             "expression_value": {"constant_value": new_rule["expression_value"]}}),
        cfg("okta_group_rule.it_helpdesk", {"group_assignments": {"references": ["okta_group.helpdesk.id", "okta_group.helpdesk"]}}),
        cfg("okta_group_role.helpdesk_super", {"group_id": {"references": ["okta_group.helpdesk.id", "okta_group.helpdesk"]}}),
        cfg("okta_app_oauth_api_scope.hr_sync", {"app_id": {"references": ["okta_app_oauth.hr_sync.id", "okta_app_oauth.hr_sync"]}}),
    ]
    return plan_doc(prior, rc, configs)


def clean_plan():
    prior = prior_resources()
    by = {r["address"]: r["values"] for r in prior}
    rc = [
        change("okta_group.finance_readonly", ["create"], None,
               {"name": "Finance-Reports", "description": "Read-only finance dashboards",
                "custom_profile_attributes": None, "skip_users": None}, {"id": True}),
        change("okta_app_oauth_api_scope.hr_sync", ["update"], by["okta_app_oauth_api_scope.hr_sync"],
               {**by["okta_app_oauth_api_scope.hr_sync"],
                "scopes": ["okta.users.read", "okta.groups.read", "okta.logs.read"]}),
        change("okta_group_rule.sf_admin", ["update"], by["okta_group_rule.sf_admin"],
               {**by["okta_group_rule.sf_admin"], "name": "Salesforce admins (Sales Ops)"}),
    ]
    return plan_doc(prior, rc, [])


def plan_doc(prior, rc, configs):
    return {
        "format_version": "1.2",
        "terraform_version": "1.9.8",
        "prior_state": {"format_version": "1.0", "terraform_version": "1.9.8",
                        "values": {"root_module": {"resources": prior}}},
        "resource_changes": rc,
        "configuration": {"provider_config": {"okta": {"name": "okta", "full_name": PROVIDER}},
                          "root_module": {"resources": configs}},
        "_comment": "Hand-built demo plan in Terraform JSON plan format. Synthetic data only.",
    }


if __name__ == "__main__":
    (OUT / "plan_risky.json").write_text(json.dumps(risky_plan(), indent=1) + "\n")
    (OUT / "plan_clean.json").write_text(json.dumps(clean_plan(), indent=1) + "\n")
    print("wrote", OUT / "plan_risky.json", OUT / "plan_clean.json")
