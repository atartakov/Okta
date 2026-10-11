"""Guardrails: Okta-specific checks on what a Terraform plan is about to change.

Every check looks at the *change* (before -> after), not just the final
config, so a PR is flagged for what it introduces rather than for debt that
already exists in the tenant.
"""
from __future__ import annotations

import json
import re
from typing import Any, Callable, Iterator
from urllib.parse import urlparse

from .findings import Finding
from .plan import Change, Plan

Rule = Callable[[Plan], Iterator[Finding]]
RULES: list[tuple[str, str, Rule]] = []


def rule(rule_id: str, summary: str):
    def wrap(fn: Rule) -> Rule:
        RULES.append((rule_id, summary, fn))
        return fn
    return wrap


def _as_list(v: Any) -> list:
    if v is None:
        return []
    return list(v) if isinstance(v, (list, tuple, set)) else [v]


def _new_items(ch: Change, key: str) -> list:
    before = set(map(str, _as_list(ch.before_get(key))))
    return [x for x in _as_list(ch.after_get(key)) if str(x) not in before]


PRIVILEGED_ROLES = {"SUPER_ADMIN": "critical", "ORG_ADMIN": "high"}


# --------------------------------------------------------------------- OG001
@rule("OG001", "Privileged Okta admin role granted")
def privileged_role(plan: Plan) -> Iterator[Finding]:
    for ch in plan.changes_of("okta_group_role"):
        if not ch.writes:
            continue
        role = ch.after_get("role_type")
        if role in PRIVILEGED_ROLES and ch.before_get("role_type") != role:
            groups = plan.resolve(ch.address, "group_id", [ch.after_get("group_id")], "name")
            yield Finding("OG001", PRIVILEGED_ROLES[role], ch.address,
                          f"{role} granted to group {', '.join(groups) or '?'}",
                          f"Every current and future member of the group becomes {role}.",
                          "Use a custom admin role scoped to a resource set, and keep super admin "
                          "to named break-glass accounts managed outside Terraform.")
    for ch in plan.changes_of("okta_user_admin_roles"):
        if not ch.writes:
            continue
        for role in _new_items(ch, "admin_roles"):
            if role in PRIVILEGED_ROLES:
                yield Finding("OG001", PRIVILEGED_ROLES[role], ch.address,
                              f"{role} granted to a user",
                              f"user_id {ch.after_get('user_id') or '(new user)'} gains {role}.",
                              "Grant a custom role with a resource set, or document the break-glass reason.")
    for ch in plan.changes_of("okta_app_oauth_role_assignment"):
        if not ch.writes:
            continue
        role = ch.after_get("type")
        if role in PRIVILEGED_ROLES and ch.before_get("type") != role:
            yield Finding("OG001", "critical", ch.address,
                          f"{role} granted to an OAuth service app",
                          "A machine credential with this role can change any setting in the org, "
                          "and nobody is prompted for MFA when it does.",
                          "Give the service app only the okta.* scopes and custom role it needs.")


# --------------------------------------------------------------------- OG002
CRITICAL_SCOPES = {"okta.roles.manage", "okta.policies.manage", "okta.authenticators.manage",
                   "okta.apiTokens.manage", "okta.idps.manage"}


@rule("OG002", "Broad Okta management scopes granted to an app")
def broad_scopes(plan: Plan) -> Iterator[Finding]:
    for ch in plan.changes_of("okta_app_oauth_api_scope"):
        if not ch.writes:
            continue
        for scope in _new_items(ch, "scopes"):
            if not str(scope).endswith(".manage"):
                continue
            sev = "critical" if scope in CRITICAL_SCOPES else "high"
            apps = plan.resolve(ch.address, "app_id", [ch.after_get("app_id")], "label")
            yield Finding("OG002", sev, ch.address,
                          f"{scope} granted to {', '.join(apps) or 'an app'}",
                          "Write access to the Okta management API. "
                          + ("This scope can change who is an admin or how people authenticate."
                             if sev == "critical" else "Check the app really needs to write, not read."),
                          "Grant the matching .read scope where possible; if it must write, "
                          "use private_key_jwt and pair the scope with a narrow custom admin role.")


# --------------------------------------------------------------------- OG003
def _risky_uri(uri: str) -> str | None:
    if "*" in uri:
        return "contains a wildcard"
    parsed = urlparse(uri)
    host = (parsed.hostname or "").lower()
    if parsed.scheme == "http" and host not in ("localhost", "127.0.0.1", "::1"):
        return "uses plain http on a non-local host"
    return None


@rule("OG003", "Risky OAuth redirect URI")
def redirect_uris(plan: Plan) -> Iterator[Finding]:
    for ch in plan.changes_of("okta_app_oauth"):
        if not ch.writes:
            continue
        label = ch.after_get("label") or ch.address
        for key in ("redirect_uris", "post_logout_redirect_uris"):
            for uri in _new_items(ch, key):
                why = _risky_uri(str(uri))
                if why:
                    yield Finding("OG003", "high", ch.address, f"{label}: {key} entry {why}",
                                  f"{uri} lets authorization codes or tokens be sent somewhere you do not control.",
                                  "Register exact https redirect URIs; one per environment.")
        wildcard = ch.after_get("wildcard_redirect")
        if wildcard and wildcard != "DISABLED" and ch.before_get("wildcard_redirect") != wildcard:
            yield Finding("OG003", "high", ch.address, f"{label}: wildcard_redirect = {wildcard}",
                          "Any subdomain matching the pattern can receive tokens; one subdomain takeover is enough.",
                          "Keep wildcard_redirect = \"DISABLED\".")


# --------------------------------------------------------------------- OG004
@rule("OG004", "Weak OAuth flow")
def weak_flows(plan: Plan) -> Iterator[Finding]:
    for ch in plan.changes_of("okta_app_oauth"):
        if not ch.writes:
            continue
        label = ch.after_get("label") or ch.address
        new_grants = _new_items(ch, "grant_types")
        if "implicit" in new_grants:
            yield Finding("OG004", "high", ch.address, f"{label}: implicit grant enabled",
                          "Tokens are returned in the browser URL fragment, where history, logs and extensions can read them.",
                          "Use authorization_code with PKCE.")
        if "password" in new_grants:
            yield Finding("OG004", "high", ch.address, f"{label}: resource owner password grant enabled",
                          "The app collects the user's password itself, which bypasses Okta's sign-in policies and phishing resistance.",
                          "Use authorization_code with PKCE, or a device/CIBA flow.")
        app_type = ch.after_get("type")
        if app_type in ("browser", "native") and ch.after_get("pkce_required") is False \
                and ch.before_get("pkce_required") is not False:
            yield Finding("OG004", "medium", ch.address, f"{label}: PKCE not required on a public client",
                          "A public client has no secret, so an intercepted authorization code can be redeemed by anyone.",
                          "Set pkce_required = true.")
        if app_type == "service":
            method = ch.after_get("token_endpoint_auth_method") or "client_secret_basic"
            if method in ("client_secret_basic", "client_secret_post", "client_secret_jwt") and \
                    (ch.is_create or ch.before_get("token_endpoint_auth_method") != method):
                yield Finding("OG004", "medium", ch.address, f"{label}: service app authenticates with a shared secret",
                              f"token_endpoint_auth_method = {method}. A shared secret is copied into every system that uses it.",
                              "Use private_key_jwt and keep the private key in a secrets manager.")


# ------------------------------------------------------------- OG005 / OG006
def _constraints(raw: Any) -> list[dict]:
    out = []
    for item in _as_list(raw):
        try:
            out.append(json.loads(item) if isinstance(item, str) else dict(item))
        except (ValueError, TypeError):
            continue
    return out


def _requires_phishing_resistance(raw: Any) -> bool:
    text = json.dumps(_constraints(raw))
    return '"phishingResistant": "REQUIRED"' in text


def _signon_rules(ch: Change, side: str) -> list[dict]:
    vals = ch.before if side == "before" else ch.after
    if not vals:
        return []
    if ch.type == "okta_app_signon_policy_rules":
        return [r for r in _as_list(vals.get("rule")) if isinstance(r, dict)]
    return [vals]


_DUR = re.compile(r"^P(?:(\d+)D)?(?:T(?:(\d+)H)?(?:(\d+)M)?)?$")


def iso_minutes(value: Any) -> int | None:
    if not value:
        return None
    m = _DUR.match(str(value))
    if not m:
        return None
    d, h, mins = (int(x) if x else 0 for x in m.groups())
    return d * 1440 + h * 60 + mins


@rule("OG005", "App sign-in rule weakened")
def app_signon_weakened(plan: Plan) -> Iterator[Finding]:
    for ch in plan.changes_of("okta_app_signon_policy_rule", "okta_app_signon_policy_rules"):
        if not ch.writes:
            continue
        before_rules = {r.get("name"): r for r in _signon_rules(ch, "before")}
        for r in _signon_rules(ch, "after"):
            name = r.get("name") or ch.address
            old = before_rules.get(r.get("name"), {})
            if r.get("access", "ALLOW") == "ALLOW" and r.get("factor_mode") == "1FA" \
                    and old.get("factor_mode") != "1FA":
                yield Finding("OG005", "high", ch.address, f"Rule '{name}' allows single-factor access",
                              "factor_mode = 1FA. One stolen password (or one phished factor) is enough.",
                              "Use 2FA, and require phishing-resistant factors for admin and production apps.")
            if old and _requires_phishing_resistance(old.get("constraints")) \
                    and not _requires_phishing_resistance(r.get("constraints")):
                yield Finding("OG005", "critical", ch.address,
                              f"Rule '{name}' drops the phishing-resistant requirement",
                              "Before this change the rule required a phishing-resistant authenticator "
                              "(FastPass, FIDO2/WebAuthn); after it, push or OTP satisfies it.",
                              "Keep \"phishingResistant\": \"REQUIRED\"; if a population cannot use it yet, "
                              "give them a separate, narrower rule.")


@rule("OG006", "Session or re-authentication lifetime too long")
def long_sessions(plan: Plan) -> Iterator[Finding]:
    for ch in plan.changes_of("okta_policy_rule_signon"):
        if not ch.writes:
            continue
        name = ch.after_get("name") or ch.address
        life = ch.after_get("session_lifetime")
        if isinstance(life, (int, float)) and life > 720 and life != ch.before_get("session_lifetime"):
            yield Finding("OG006", "medium", ch.address, f"Global session rule '{name}': session_lifetime {int(life)} min",
                          f"A stolen session cookie stays valid for up to {life / 60:.0f} hours.",
                          "Keep session_lifetime at 720 minutes (12 hours) or less.")
        idle = ch.after_get("session_idle")
        if isinstance(idle, (int, float)) and idle > 120 and idle != ch.before_get("session_idle"):
            yield Finding("OG006", "low", ch.address, f"Global session rule '{name}': session_idle {int(idle)} min",
                          "Idle sessions stay open for longer than two hours.", "Keep session_idle at 120 minutes or less.")
        if ch.after_get("session_persistent") is True and ch.before_get("session_persistent") is not True:
            yield Finding("OG006", "medium", ch.address, f"Global session rule '{name}': persistent session cookie",
                          "The session survives browser restarts.", "Leave session_persistent = false.")
    for ch in plan.changes_of("okta_app_signon_policy_rule", "okta_app_signon_policy_rules"):
        if not ch.writes:
            continue
        before_rules = {r.get("name"): r for r in _signon_rules(ch, "before")}
        for r in _signon_rules(ch, "after"):
            mins = iso_minutes(r.get("re_authentication_frequency"))
            old = iso_minutes(before_rules.get(r.get("name"), {}).get("re_authentication_frequency"))
            if mins is not None and mins > 720 and mins != old:
                yield Finding("OG006", "medium", ch.address,
                              f"Rule '{r.get('name')}': re-authentication every {mins / 60:.0f} hours",
                              f"re_authentication_frequency = {r.get('re_authentication_frequency')}.",
                              "Re-authenticate at least every 12 hours (PT12H), shorter for admin apps.")


# --------------------------------------------------------------------- OG007
SECURITY_TYPES = {
    "okta_policy_signon", "okta_policy_rule_signon", "okta_policy_password", "okta_policy_rule_password",
    "okta_policy_mfa", "okta_policy_rule_mfa", "okta_app_signon_policy", "okta_app_signon_policy_rule",
    "okta_app_signon_policy_rules", "okta_authenticator", "okta_network_zone", "okta_behavior",
    "okta_threat_insight_settings", "okta_policy_device_assurance_android", "okta_policy_device_assurance_ios",
    "okta_policy_device_assurance_macos", "okta_policy_device_assurance_windows",
}


@rule("OG007", "Security control deleted")
def security_deleted(plan: Plan) -> Iterator[Finding]:
    for ch in plan.changes_of(*SECURITY_TYPES):
        if ch.is_delete:
            name = ch.before_get("name") or ch.before_get("key") or ch.address
            yield Finding("OG007", "high", ch.address, f"{ch.type} '{name}' will be deleted",
                          "Deleting a policy, rule, zone or authenticator usually means a fallback rule now applies.",
                          "Confirm which rule takes over, or remove it in a separate PR with the replacement in place.")


# --------------------------------------------------------------------- OG008
def admin_groups(plan: Plan, side: str = "after") -> dict[str, set[str]]:
    """Map group name -> admin role types held by that group."""
    out: dict[str, set[str]] = {}
    resources = plan.resources_after("okta_group_role") if side == "after" else plan.resources_before("okta_group_role")
    for addr, vals in resources:
        role = vals.get("role_type")
        if not role:
            continue
        for g in plan.resolve(addr, "group_id", [vals.get("group_id")], "name", side=side):
            out.setdefault(g, set()).add(role)
    return out


@rule("OG008", "Group rule feeds an admin group")
def rule_feeds_admin(plan: Plan) -> Iterator[Finding]:
    admins = admin_groups(plan, "after")
    for ch in plan.changes_of("okta_group_rule"):
        if not ch.writes or ch.after_get("status", "ACTIVE") != "ACTIVE":
            continue
        changed = ch.is_create or ch.before_get("expression_value") != ch.after_get("expression_value") \
            or set(_as_list(ch.before_get("group_assignments"))) != set(_as_list(ch.after_get("group_assignments")))
        if not changed:
            continue
        for g in plan.resolve(ch.address, "group_assignments", ch.after_get("group_assignments"), "name"):
            roles = admins.get(g)
            if roles:
                sev = "critical" if roles & set(PRIVILEGED_ROLES) else "high"
                yield Finding("OG008", sev, ch.address,
                              f"Rule '{ch.after_get('name')}' assigns members to admin group {g}",
                              f"{g} holds {', '.join(sorted(roles))}. Anyone whose profile matches "
                              f"`{ch.after_get('expression_value')}` becomes an admin automatically, "
                              "including when HR data changes.",
                              "Make admin groups request-and-approve (Okta Identity Governance) rather than rule-driven.")


def run_rules(plan: Plan, only: set[str] | None = None) -> list[Finding]:
    findings: list[Finding] = []
    for rule_id, _summary, fn in RULES:
        if only and rule_id not in only:
            continue
        findings.extend(fn(plan))
    return findings
