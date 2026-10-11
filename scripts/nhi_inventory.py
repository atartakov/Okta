#!/usr/bin/env python3
"""Non-human identity (NHI) inventory: every machine identity in Okta, risk-ranked.

AI agents, pipelines and integrations reach Okta through three kinds of
non-human identity. This script finds all three, scores each one, and says in
plain English why it is risky:

    oauth-service-app   OIDC apps that can mint tokens without a user
                        (client_credentials grant / service type), plus
                        token-exchange "agent" apps. Looks at granted okta.*
                        scopes (write and takeover-capable ones), admin roles
                        assigned to the client, client secret vs
                        private_key_jwt, secret/key age, and when it last got
                        an access token (System Log).
    api-service         API service integrations (OIN machine-to-machine).
    api-token           SSWS API tokens: owner, owner status and admin roles,
                        network restriction, last use.
    service-user        users that look like service accounts (name pattern
                        such as svc-/bot/api, or a service-ish user type):
                        MFA, interactive sign-ins, admin roles, password age.

One table across all types, highest risk first, so the riskiest machine
identity is on top whatever kind it is. find_orphaned_api_token.ps1 (token
owner evidence pack) and admin_privilege_reviewer.py (human admins) go
deeper on their own slice; this is the cross-type NHI view.

READ-ONLY: every API call is a GET. Listing API tokens needs a super-admin
token; anything the token cannot read is reported under "errors" and the rest
of the inventory still runs.

Usage:
    export OKTA_DOMAIN=https://dev-123456.okta.com
    export OKTA_API_TOKEN=00...
    python scripts/nhi_inventory.py
    python scripts/nhi_inventory.py --json --output nhi.json
    python scripts/nhi_inventory.py --csv --output nhi.csv --min-risk medium
    python scripts/nhi_inventory.py --save-raw snapshot.json     # keep the raw pull
    python scripts/nhi_inventory.py --input snapshot.json        # offline re-score
    python scripts/nhi_inventory.py --fail-on high               # CI gate

Exit codes: 0 = ok, 2 = an identity at or above --fail-on, 1 = error.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from datetime import datetime, timedelta, timezone

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

LEVELS = ["low", "medium", "high", "critical"]

# Points for the single highest admin role an identity holds (+5 per extra role).
ROLE_POINTS = {
    "SUPER_ADMIN": 50, "ORG_ADMIN": 40, "API_ACCESS_MANAGEMENT_ADMIN": 25,
    "APP_ADMIN": 25, "USER_ADMIN": 25, "CUSTOM": 25,
    "GROUP_MEMBERSHIP_ADMIN": 20, "HELP_DESK_ADMIN": 20,
    "ACCESS_CERTIFICATIONS_ADMIN": 15, "ACCESS_REQUESTS_ADMIN": 15,
    "MOBILE_ADMIN": 15, "REPORT_ADMIN": 10, "READ_ONLY_ADMIN": 5,
}
DEFAULT_ROLE_POINTS = 15

# Write scopes that can lead to tenant takeover or lockout.
TAKEOVER_SCOPES = {
    "okta.roles.manage", "okta.users.manage", "okta.policies.manage",
    "okta.authenticators.manage", "okta.apiTokens.manage", "okta.apps.manage",
    "okta.clients.manage", "okta.idps.manage", "okta.networkZones.manage",
    "okta.sessions.manage", "okta.orgs.manage", "okta.factors.manage",
    "okta.authorizationServers.manage", "okta.groups.manage",
}
SECRET_AUTH = {"client_secret_basic", "client_secret_post", "client_secret_jwt"}
GRANT_EVENTS = ["app.oauth2.token.grant.access_token",
                "app.oauth2.as.token.grant.access_token"]
DEFAULT_PATTERN = (r"(^|[^a-z])(svc|service|bot|api|automation|integration|robot|"
                   r"sa|system|noreply|no-reply|daemon|sync|terraform|agent)([^a-z]|$)")


# ---------------------------------------------------------------- helpers

def norm_time(value) -> str | None:
    """Okta timestamp -> 'YYYY-MM-DDTHH:MM:SSZ' (UTC), or None."""
    if not value:
        return None
    try:
        dt = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def days_since(value, now: datetime) -> int | None:
    t = norm_time(value)
    if not t:
        return None
    dt = datetime.strptime(t, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    return int((now - dt).total_seconds() // 86400)


def level_for(score: int) -> str:
    if score >= 60:
        return "critical"
    if score >= 40:
        return "high"
    if score >= 20:
        return "medium"
    return "low"


def role_score(roles: list) -> tuple[int, str | None]:
    """(points, reason) for a list of role dicts with 'type'/'label'."""
    types = sorted({r.get("type") or "?" for r in roles})
    if not types:
        return 0, None
    best = max(ROLE_POINTS.get(t, DEFAULT_ROLE_POINTS) for t in types)
    pts = best + 5 * (len(types) - 1)
    labels = sorted({(r.get("label") or r.get("type") or "?") for r in roles})
    if "SUPER_ADMIN" in types:
        why = "holds SUPER_ADMIN: full control of the tenant"
    elif "ORG_ADMIN" in types:
        why = "holds ORG_ADMIN: can manage users, groups, apps and most settings"
    elif types == ["READ_ONLY_ADMIN"]:
        why = "holds READ_ONLY_ADMIN: can read all admin data"
    else:
        why = f"holds admin role(s): {', '.join(labels)}"
    return pts, why


def scope_score(scopes: list) -> tuple[int, list]:
    manage = sorted(s for s in scopes if s.endswith(".manage"))
    takeover = [s for s in manage if s in TAKEOVER_SCOPES]
    other = [s for s in manage if s not in TAKEOVER_SCOPES]
    pts = min(30, 6 * len(takeover)) + min(10, 3 * len(other))
    reasons = []
    if takeover:
        reasons.append(f"{len(takeover)} takeover-capable write scope(s): {', '.join(takeover)}")
    if other:
        reasons.append(f"{len(other)} other write scope(s): {', '.join(other)}")
    if "okta.roles.manage" in scopes:
        pts += 15
        reasons.append("okta.roles.manage lets it grant admin roles, including to itself")
    if len(scopes) > 10:
        pts += 5
        reasons.append(f"broad grant: {len(scopes)} okta.* scopes")
    return pts, reasons


def privilege_text(roles: list, scopes: list | None) -> str:
    parts = []
    rtypes = sorted({r.get("type") or "?" for r in roles})
    if rtypes:
        parts.append(",".join(rtypes))
    if scopes is not None:
        n_manage = sum(1 for s in scopes if s.endswith(".manage"))
        parts.append(f"{len(scopes)} scopes, {n_manage} write")
    return "; ".join(parts) or "none"


def finish(row: dict, score: int, reasons: list) -> dict:
    row["score"] = max(0, score)
    row["risk"] = level_for(row["score"])
    row["reasons"] = reasons
    row["why"] = "; ".join(reasons) if reasons else "no risk signals found"
    return row


# ---------------------------------------------------------------- scoring

def score_app(app: dict, raw: dict, now: datetime, opts: dict) -> dict:
    scopes = sorted(app.get("scopes") or [])
    roles = app.get("roles") or []
    auth = app.get("auth_method") or "unknown"
    score, reasons = 0, []
    if app.get("status") != "ACTIVE":
        reasons.append(f"app is {app.get('status')} (cannot get tokens until reactivated)")
    pts, why = role_score(roles)
    if why:
        score += pts
        reasons.append(why + " (assigned to the client itself)")
    pts, why_list = scope_score(scopes)
    score += pts
    reasons += why_list
    if auth in SECRET_AUTH:
        score += 15
        reasons.append(f"authenticates with a shared client secret ({auth}): it can be copied "
                       "and replayed from anywhere; prefer private_key_jwt")
    active_secrets = [s for s in app.get("secrets") or [] if s.get("status") == "ACTIVE"]
    if active_secrets:
        oldest = max(days_since(s.get("created"), now) or 0 for s in active_secrets)
        if oldest > opts["rotation_days"]:
            score += 10
            reasons.append(f"client secret not rotated in {oldest} days "
                           f"(> {opts['rotation_days']})")
        if len(active_secrets) > 1:
            score += 5
            reasons.append(f"{len(active_secrets)} active client secrets (old one never retired?)")
    active_keys = [k for k in app.get("keys") or [] if k.get("status") == "ACTIVE"]
    if auth == "private_key_jwt" and active_keys:
        oldest = max(days_since(k.get("created"), now) or 0 for k in active_keys)
        if oldest > 365:
            score += 5
            reasons.append(f"signing key is {oldest} days old")
    last = None
    if raw.get("logs_available"):
        last = (raw.get("token_grants") or {}).get(app.get("client_id") or app["id"])
        if not last and (scopes or roles) and app.get("status") == "ACTIVE":
            score += 10
            reasons.append(f"no access token issued in the last {raw.get('log_window_days')} "
                           "days: standing access nobody uses, deactivation candidate")
    if app.get("status") != "ACTIVE":
        score //= 2
    if "urn:ietf:params:oauth:grant-type:token-exchange" in (app.get("grant_types") or []):
        reasons.append("token-exchange client: can act on behalf of signed-in users "
                       "(AI agent / Cross App Access pattern)")
    row = {
        "type": "oauth-service-app", "id": app["id"], "name": app.get("label") or app["id"],
        "status": app.get("status"), "privilege": privilege_text(roles, scopes),
        "credential": auth,
        "last_used": norm_time(last) if raw.get("logs_available") else "unknown",
        "created": norm_time(app.get("created")),
        "details": {"scopes": scopes, "admin_roles": sorted({r.get("type") for r in roles}),
                    "grant_types": sorted(app.get("grant_types") or [])},
    }
    return finish(row, score, reasons)


def score_api_service(svc: dict, raw: dict, now: datetime, opts: dict) -> dict:
    scopes = sorted(svc.get("grantedScopes") or [])
    score, reasons = 0, []
    pts, why_list = scope_score(scopes)
    score += pts
    reasons += why_list
    score += 10
    reasons.append("authenticates with a client secret (API service integrations "
                   "have no private-key option)")
    active = [s for s in svc.get("secrets") or [] if s.get("status") == "ACTIVE"]
    if active:
        oldest = max(days_since(s.get("created"), now) or 0 for s in active)
        if oldest > opts["rotation_days"]:
            score += 10
            reasons.append(f"client secret not rotated in {oldest} days "
                           f"(> {opts['rotation_days']})")
        if len(active) > 1:
            score += 5
            reasons.append(f"{len(active)} active client secrets")
    last = None
    if raw.get("logs_available"):
        last = (raw.get("token_grants") or {}).get(svc["id"])
        if not last and scopes:
            score += 10
            reasons.append(f"no access token issued in the last {raw.get('log_window_days')} "
                           "days: unused integration, removal candidate")
    row = {
        "type": "api-service", "id": svc["id"], "name": svc.get("name") or svc["id"],
        "status": "ACTIVE", "privilege": privilege_text([], scopes),
        "credential": "client_secret",
        "last_used": norm_time(last) if raw.get("logs_available") else "unknown",
        "created": norm_time(svc.get("createdAt")),
        "details": {"scopes": scopes, "admin_roles": [], "created_by": svc.get("createdBy")},
    }
    return finish(row, score, reasons)


def score_token(tok: dict, raw: dict, now: datetime, opts: dict) -> dict:
    owner = (raw.get("users") or {}).get(tok.get("userId") or "") or {"missing": True}
    roles = owner.get("roles") or []
    score = 25
    reasons = ["SSWS API token: a long-lived bearer secret with no scopes; it carries "
               "every admin right its owner has"]
    if owner.get("unknown"):
        reasons.append("owner could not be read")
        owner_txt = tok.get("userId")
    elif owner.get("missing"):
        score += 40
        reasons.append("owner's user record is gone: nobody is accountable for this token")
        owner_txt = "(gone)"
    else:
        owner_txt = owner.get("login") or tok.get("userId")
        if owner.get("status") != "ACTIVE":
            score += 30
            reasons.append(f"owner is {owner.get('status')}: the token outlived its owner")
    pts, why = role_score(roles)
    if why:
        score += pts
        reasons.append("owner " + why)
    net = (tok.get("network") or {}).get("connection") or "ANYWHERE"
    if net == "ANYWHERE":
        score += 15
        reasons.append("usable from any IP address (no network zone restriction)")
    age = days_since(tok.get("lastUpdated"), now)
    if age is not None and age > opts["stale_days"]:
        score += 10
        reasons.append(f"not used in {age} days: revoke if nothing depends on it")
    row = {
        "type": "api-token", "id": tok["id"], "name": tok.get("name") or tok["id"],
        "status": "ACTIVE", "privilege": privilege_text(roles, None),
        "credential": f"SSWS (network {net})",
        "last_used": norm_time(tok.get("lastUpdated")),
        "created": norm_time(tok.get("created")),
        "details": {"owner": owner_txt, "owner_status": owner.get("status"),
                    "admin_roles": sorted({r.get("type") for r in roles}),
                    "expires_at": norm_time(tok.get("expiresAt")),
                    "idle_window": tok.get("tokenWindow"), "client_name": tok.get("clientName")},
    }
    return finish(row, score, reasons)


def score_user(u: dict, raw: dict, now: datetime, opts: dict) -> dict:
    roles = u.get("roles") or []
    factors = u.get("factors") or []
    score, reasons = 0, [f"looks like a service account ({u.get('matched')})"]
    pts, why = role_score(roles)
    if why:
        score += pts
        reasons.append(why)
    if u.get("has_password") and not factors:
        score += 15
        reasons.append("no MFA enrolled: the password alone unlocks it")
    if u.get("lastLogin"):
        score += 10
        reasons.append("has signed in interactively: someone is using it like a person "
                       "(shared credential)")
    age = days_since(u.get("passwordChanged"), now)
    if u.get("has_password") and age is not None and age > 365:
        score += 5
        reasons.append(f"password not changed in {age} days")
    owned = [t for t in raw.get("api_tokens") or [] if t.get("userId") == u["id"]]
    if owned:
        score += 5
        reasons.append(f"owns {len(owned)} API token(s)")
    if u.get("status") != "ACTIVE":
        score //= 2
    row = {
        "type": "service-user", "id": u["id"], "name": u.get("login") or u["id"],
        "status": u.get("status"), "privilege": privilege_text(roles, None),
        "credential": ("password" if u.get("has_password") else "no password") +
                      (f" + {len(factors)} factor(s)" if factors else ", no MFA"),
        "last_used": norm_time(u.get("lastLogin")),
        "created": norm_time(u.get("created")),
        "details": {"admin_roles": sorted({r.get("type") for r in roles}),
                    "factors": sorted(factors), "user_type": u.get("type_name")},
    }
    return finish(row, score, reasons)


def analyze(raw: dict, now: datetime | None = None, rotation_days: int = 90,
            stale_days: int = 30) -> list:
    now = now or datetime.now(timezone.utc)
    opts = {"rotation_days": rotation_days, "stale_days": stale_days}
    rows = [score_app(a, raw, now, opts) for a in raw.get("apps") or []]
    rows += [score_api_service(s, raw, now, opts) for s in raw.get("api_services") or []]
    rows += [score_token(t, raw, now, opts) for t in raw.get("api_tokens") or []]
    rows += [score_user(u, raw, now, opts) for u in (raw.get("users") or {}).values()
             if u.get("candidate")]
    rows.sort(key=lambda r: (-r["score"], r["type"], (r["name"] or "").lower()))
    return rows


def summarize(rows: list) -> dict:
    by_type = {t: 0 for t in ("oauth-service-app", "api-service", "api-token", "service-user")}
    by_risk = {lv: 0 for lv in reversed(LEVELS)}
    for r in rows:
        by_type[r["type"]] += 1
        by_risk[r["risk"]] += 1
    return {"total": len(rows), "by_type": by_type, "by_risk": by_risk}


# ---------------------------------------------------------------- collection

def is_machine_app(app: dict) -> bool:
    oc = (app.get("settings") or {}).get("oauthClient") or {}
    grants = oc.get("grant_types") or []
    return (oc.get("application_type") == "service" or "client_credentials" in grants
            or "urn:ietf:params:oauth:grant-type:token-exchange" in grants)


def match_service(user: dict, pattern: re.Pattern, type_names: dict) -> str | None:
    p = user.get("profile") or {}
    local = str(p.get("login") or "").split("@")[0].lower()
    for label, val in (("login", local), ("first name", str(p.get("firstName") or "").lower()),
                       ("last name", str(p.get("lastName") or "").lower())):
        m = pattern.search(val)
        if m:
            return f"{label} matches '{m.group(2)}'"
    tname = type_names.get(((user.get("type") or {}).get("id")) or "")
    if tname and pattern.search(tname.lower()):
        return f"user type '{tname}'"
    return None


def collect(client, pattern: re.Pattern, log_days: int, use_logs: bool = True,
            now: datetime | None = None) -> dict:
    """Pull everything the scorer needs with GETs only. Optional endpoints that
    the token cannot read are recorded in 'errors' instead of failing the run."""
    import requests
    from lib.okta_client import OktaAuthError

    now = now or datetime.now(timezone.utc)
    errors = []

    def code_of(e):
        if isinstance(e, requests.HTTPError) and e.response is not None:
            return str(e.response.status_code)
        m = re.search(r"HTTP (\d{3})", str(e))
        return m.group(1) if m else "?"

    def get_list(path, params=None, what=None):
        try:
            return list(client.paged_get(path, params))
        except (OktaAuthError, requests.HTTPError) as e:
            errors.append(f"{what or path}: HTTP {code_of(e)}")
            return None

    def get_one(path, what):
        """Object, None when it does not exist (404), False when unreadable."""
        try:
            return client._request("GET", path).json()
        except (OktaAuthError, requests.HTTPError) as e:
            if code_of(e) == "404":
                return None
            errors.append(f"{what}: HTTP {code_of(e)}")
            return False

    raw = {"tenant": client.base_url, "collected_at": norm_time(now.isoformat()),
           "log_window_days": log_days, "logs_available": False,
           "apps": [], "api_services": [], "api_tokens": [], "users": {},
           "token_grants": {}, "errors": errors}

    print("listing OAuth apps...", file=sys.stderr)
    for app in get_list("/api/v1/apps", {"filter": 'name eq "oidc_client"'}, "apps") or []:
        if not is_machine_app(app):
            continue
        oc = (app.get("settings") or {}).get("oauthClient") or {}
        cred = (app.get("credentials") or {}).get("oauthClient") or {}
        cid = cred.get("client_id") or app["id"]
        grants = get_list(f"/api/v1/apps/{app['id']}/grants", None, f"grants for {app['label']}")
        roles = get_list(f"/oauth2/v1/clients/{cid}/roles", None, f"roles for {app['label']}")
        secrets = get_list(f"/api/v1/apps/{app['id']}/credentials/secrets", None,
                           f"secrets for {app['label']}")
        jwks = get_one(f"/api/v1/apps/{app['id']}/credentials/jwks", f"keys for {app['label']}")
        keys = jwks.get("keys", []) if isinstance(jwks, dict) else (jwks or [])
        raw["apps"].append({
            "id": app["id"], "label": app.get("label"), "status": app.get("status"),
            "created": app.get("created"), "client_id": cid,
            "application_type": oc.get("application_type"),
            "grant_types": oc.get("grant_types") or [],
            "auth_method": cred.get("token_endpoint_auth_method"),
            "scopes": sorted({g.get("scopeId") for g in grants or []
                              if g.get("status") == "ACTIVE" and g.get("scopeId")}),
            "roles": [{"type": r.get("type"), "label": r.get("label")} for r in roles or []
                      if r.get("status", "ACTIVE") == "ACTIVE"],
            "secrets": [{"status": s.get("status"), "created": s.get("created")}
                        for s in secrets or []],
            "keys": [{"status": k.get("status"), "created": k.get("created")} for k in keys],
        })

    print("listing API service integrations...", file=sys.stderr)
    for svc in get_list("/integrations/api/v1/api-services", None, "api service integrations") or []:
        secrets = get_list(f"/integrations/api/v1/api-services/{svc['id']}/credentials/secrets",
                           None, f"secrets for {svc.get('name')}")
        raw["api_services"].append({
            "id": svc["id"], "name": svc.get("name"), "type": svc.get("type"),
            "createdAt": svc.get("createdAt"), "createdBy": svc.get("createdBy"),
            "grantedScopes": svc.get("grantedScopes") or [],
            "secrets": [{"status": s.get("status"), "created": s.get("created")}
                        for s in secrets or []],
        })

    print("listing API tokens...", file=sys.stderr)
    tokens = get_list("/api/v1/api-tokens", None,
                      "api tokens (needs a SUPER_ADMIN token)") or []
    raw["api_tokens"] = [{k: t.get(k) for k in ("id", "name", "userId", "clientName", "created",
                                                "expiresAt", "lastUpdated", "tokenWindow",
                                                "network")} for t in tokens]

    print("scanning users for service accounts...", file=sys.stderr)
    type_names = {t["id"]: t.get("name") or t.get("displayName") or ""
                  for t in get_list("/api/v1/meta/types/user", None, "user types") or []}
    users = {}
    for u in get_list("/api/v1/users", None, "users") or []:
        matched = match_service(u, pattern, type_names)
        if matched:
            users[u["id"]] = (u, matched)
    for t in raw["api_tokens"]:
        uid = t.get("userId")
        if uid and uid not in users:
            u = get_one(f"/api/v1/users/{uid}", f"token owner {uid}")
            users[uid] = (u or None, None)
            if u is None:
                raw["users"][uid] = {"id": uid, "missing": True}
            elif u is False:
                raw["users"][uid] = {"id": uid, "unknown": True}
    for uid, (u, matched) in users.items():
        if u is None:
            continue
        p = u.get("profile") or {}
        rec = {"id": uid, "login": p.get("login"), "status": u.get("status"),
               "created": u.get("created"), "lastLogin": u.get("lastLogin"),
               "passwordChanged": u.get("passwordChanged"),
               "has_password": "password" in (u.get("credentials") or {}),
               "type_name": type_names.get(((u.get("type") or {}).get("id")) or ""),
               "candidate": bool(matched), "matched": matched,
               "roles": [{"type": r.get("type"), "label": r.get("label")}
                         for r in get_list(f"/api/v1/users/{uid}/roles", None,
                                           f"roles for {p.get('login')}") or []]}
        if matched:
            rec["factors"] = [f.get("factorType") for f in
                              get_list(f"/api/v1/users/{uid}/factors", None,
                                       f"factors for {p.get('login')}") or []
                              if f.get("status") == "ACTIVE"]
        raw["users"][uid] = rec

    if use_logs:
        print("reading System Log for last token grants...", file=sys.stderr)
        since = (now - timedelta(days=log_days)).strftime("%Y-%m-%dT%H:%M:%S.000Z")
        until = now.strftime("%Y-%m-%dT%H:%M:%S.000Z")
        ev_filter = " or ".join(f'eventType eq "{e}"' for e in GRANT_EVENTS)
        ok = True
        for cid in [a["client_id"] for a in raw["apps"]] + [s["id"] for s in raw["api_services"]]:
            params = {"filter": f'({ev_filter}) and actor.id eq "{cid}" and '
                                f'outcome.result eq "SUCCESS"',
                      "since": since, "until": until, "sortOrder": "DESCENDING", "limit": 1}
            try:
                latest = next(iter(client.paged_get("/api/v1/logs", params)), None)
            except (OktaAuthError, requests.HTTPError) as e:
                errors.append(f"system log: HTTP {code_of(e)}")
                ok = False
                break
            raw["token_grants"][cid] = latest.get("published") if latest else None
        raw["logs_available"] = ok
    return raw


# ---------------------------------------------------------------- output

def render_text(raw: dict, rows: list) -> str:
    s = summarize(rows)
    bt, br = s["by_type"], s["by_risk"]
    lines = [f"Non-human identity inventory: {raw.get('tenant')} "
             f"(collected {norm_time(raw.get("collected_at"))})",
             f"  {s['total']} identities: {bt['oauth-service-app']} OAuth service apps, "
             f"{bt['api-service']} API service integrations, {bt['api-token']} API tokens, "
             f"{bt['service-user']} service-account users",
             "  " + " | ".join(f"{k.upper()} {v}" for k, v in br.items()), ""]
    if not rows:
        lines.append("No non-human identities found.")
    else:
        lines.append(f"{'RISK':9}{'SCORE':>5}  {'TYPE':18}{'NAME':28}{'PRIVILEGE':38}"
                     f"{'CREDENTIAL':24}LAST USED")
        lines.append("-" * 132)
        for r in rows:
            last = (r["last_used"] or "never")[:10]
            lines.append(f"{r['risk'].upper():9}{r['score']:>5}  {r['type']:18}"
                         f"{(r['name'] or '')[:27]:28}{(r['privilege'] or '')[:37]:38}"
                         f"{(r['credential'] or '')[:23]:24}{last}")
            lines.append(f"{'':16}why: {r['why']}")
    if raw.get("errors"):
        lines += ["", "Could not read (inventory may be incomplete):"]
        lines += [f"  - {e}" for e in raw["errors"]]
    if not raw.get("logs_available"):
        lines += ["", "System Log not read: 'last used' for OAuth apps is unknown."]
    return "\n".join(lines) + "\n"


CSV_FIELDS = ["risk", "score", "type", "name", "id", "status", "privilege", "credential",
              "last_used", "created", "why"]


def render_csv(rows: list) -> str:
    def q(v):
        return '"' + ("" if v is None else str(v)).replace('"', '""') + '"'
    out = [",".join(q(f) for f in CSV_FIELDS)]
    for r in rows:
        out.append(",".join(q(r[f]) for f in CSV_FIELDS))
    return "\n".join(out) + "\n"


def render_json(raw: dict, rows: list) -> str:
    return json.dumps({"tenant": raw.get("tenant"), "collected_at": norm_time(raw.get("collected_at")),
                       "log_window_days": raw.get("log_window_days"),
                       "logs_available": raw.get("logs_available"),
                       "summary": summarize(rows), "identities": rows,
                       "errors": raw.get("errors") or []}, indent=2) + "\n"


# ---------------------------------------------------------------- main

def main(argv: list | None = None) -> int:
    p = argparse.ArgumentParser(
        description="Inventory and risk-rank Okta non-human identities: OAuth service apps, "
                    "API service integrations, API tokens, service-account users (read-only).")
    p.add_argument("--log-days", type=int, default=30,
                   help="System Log window for 'last used' of OAuth apps (default 30)")
    p.add_argument("--no-logs", action="store_true", help="skip the System Log lookups")
    p.add_argument("--rotation-days", type=int, default=90,
                   help="flag client secrets older than this (default 90)")
    p.add_argument("--stale-days", type=int, default=30,
                   help="flag API tokens unused for longer than this (default 30)")
    p.add_argument("--name-pattern", default=DEFAULT_PATTERN, metavar="REGEX",
                   help="regex (2nd group = keyword) marking service-account users")
    p.add_argument("--min-risk", choices=LEVELS, default="low",
                   help="only show identities at or above this level")
    p.add_argument("--fail-on", choices=["none"] + LEVELS, default="none",
                   help="exit 2 if any identity is at or above this level")
    p.add_argument("--input", metavar="RAW_JSON", help="score a saved --save-raw snapshot offline")
    p.add_argument("--save-raw", metavar="PATH", help="also save the raw pull for --input")
    p.add_argument("--now", help=argparse.SUPPRESS)  # fixed clock for tests
    fmt = p.add_mutually_exclusive_group()
    fmt.add_argument("--json", action="store_true", help="emit JSON")
    fmt.add_argument("--csv", action="store_true", help="emit CSV")
    p.add_argument("--output", help="write the report to this file")
    args = p.parse_args(argv)

    now = datetime.now(timezone.utc)
    if args.now:
        now = datetime.strptime(norm_time(args.now), "%Y-%m-%dT%H:%M:%SZ").replace(
            tzinfo=timezone.utc)
    try:
        if args.input:
            with open(args.input, encoding="utf-8") as f:
                raw = json.load(f)
        else:
            from lib.okta_client import OktaClient
            raw = collect(OktaClient(), re.compile(args.name_pattern, re.I), args.log_days,
                          use_logs=not args.no_logs, now=now)
    except Exception as e:  # auth errors, network, bad file
        print(f"error: {e}", file=sys.stderr)
        return 1
    if args.save_raw:
        with open(args.save_raw, "w", encoding="utf-8") as f:
            json.dump(raw, f, indent=2)
        print(f"wrote {args.save_raw}", file=sys.stderr)

    all_rows = analyze(raw, now, args.rotation_days, args.stale_days)
    rows = [r for r in all_rows if LEVELS.index(r["risk"]) >= LEVELS.index(args.min_risk)]
    if args.json:
        report = render_json(raw, rows)
    elif args.csv:
        report = render_csv(rows)
    else:
        report = render_text(raw, rows)

    if args.output:
        with open(args.output, "w", encoding="utf-8", newline="\n") as f:
            f.write(report)
        print(f"wrote {args.output}", file=sys.stderr)
    else:
        sys.stdout.write(report)

    if args.fail_on != "none" and any(
            LEVELS.index(r["risk"]) >= LEVELS.index(args.fail_on) for r in all_rows):
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
