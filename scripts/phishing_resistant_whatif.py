#!/usr/bin/env python3
"""Phishing-resistant MFA enforcement what-if. READ-ONLY.

Before you require phishing-resistant MFA (passkeys / FIDO2 WebAuthn, Okta
FastPass with phishing resistance, smart card) for a group or an app, this
simulates who would be locked out and in what order to roll it out.

For every user in scope it joins three things Okta keeps in different places:

  1. what they have enrolled          GET /api/v1/users/{id}/factors
  2. what they actually used, and     System Log user.authentication.auth_via_mfa
     from which OS, in the window     and user.authentication.verify events
                                      (Okta marks each method PHISHING_RESISTANT
                                      or not, so this is Okta's own verdict)
  3. the policy rules in their path   app sign-in, global session and
                                      authenticator enrollment policies

and sorts each user into one class:

    READY              has a phishing-resistant authenticator and used it
    ENROLLED_NOT_USED  has one enrolled, no phishing-resistant sign-in seen
    AT_RISK            only phishable factors (SMS, voice, email, push, TOTP)
    NO_MFA             nothing enrolled

plus PLATFORM_BLOCKER: users who are phishing-resistant somewhere but sign in
from an OS where they have no working option (FastPass doesn't run on Linux
or ChromeOS; FastPass is per device, so an Android enrollment doesn't cover a
Windows laptop).

Only GET requests are made. Nothing in Okta is changed. Needs a read-only
token that can read users, factors, groups, apps, policies, authenticators
and the System Log.

This is not mfa_coverage.py (tenant-wide enrollment census) and not
test_oie_posture.ps1 / sign_on_policy_linter (policy configuration linting):
it answers "if I flip this one rule to phishing-resistant, who breaks?".

Usage:
    export OKTA_DOMAIN=https://dev-123456.okta.com
    export OKTA_API_TOKEN=00...
    python scripts/phishing_resistant_whatif.py --group "Engineering"
    python scripts/phishing_resistant_whatif.py --app "Salesforce" --lookback-days 60
    python scripts/phishing_resistant_whatif.py --group 00g1abc --app 0oa1xyz --json
    python scripts/phishing_resistant_whatif.py --group Engineering --save-snapshot snap.json
    python scripts/phishing_resistant_whatif.py --input snap.json      # offline re-run

Exit codes: 0 = report written, 2 = --fail-on-lockout and someone would be
locked out, 1 = error.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from datetime import datetime, timedelta, timezone

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

AUTH_EVENTS = ("user.authentication.auth_via_mfa", "user.authentication.verify")
# Statuses whose users can still sign in (and so can be locked out).
SIGNIN_STATUSES = {"ACTIVE", "PASSWORD_EXPIRED", "LOCKED_OUT", "RECOVERY"}
PR_FACTOR_TYPES = {"webauthn", "u2f", "signed_nonce"}
# Okta Verify (and so FastPass) runs on these. Not on Linux or ChromeOS.
FASTPASS_OS = {"Windows", "macOS", "iOS", "Android"}
MAX_LOOKBACK = 90  # System Log retention
CLASSES = ["READY", "ENROLLED_NOT_USED", "AT_RISK", "NO_MFA"]
CLASS_HELP = {
    "READY": "enrolled in a phishing-resistant authenticator and used it in the window",
    "ENROLLED_NOT_USED": "enrolled, but no phishing-resistant sign-in in the window",
    "AT_RISK": "only phishable factors (SMS, voice, email, push, TOTP)",
    "NO_MFA": "no MFA factor enrolled",
    "PLATFORM_BLOCKER": "phishing-resistant somewhere, but not on every OS they sign in from",
}
FACTOR_LABELS = {
    "webauthn": "passkey", "u2f": "U2F key", "push": "push",
    "token:software:totp": "TOTP", "token:hotp": "HOTP",
    "token:hardware": "hardware OTP", "token": "OTP token", "sms": "SMS",
    "call": "voice", "email": "email", "question": "security question",
    "web": "Duo",
}
PLATFORM_LABELS = {"ANDROID": "Android", "IOS": "iOS", "WINDOWS": "Windows",
                   "MACOS": "macOS", "OSX": "macOS"}
GROUP_ID = re.compile(r"^00g[A-Za-z0-9]{17}$")
APP_ID = re.compile(r"^0oa[A-Za-z0-9]{17}$")
PR_REQUIRED_RE = re.compile(r'"phishingResistant"\s*:\s*"REQUIRED"')


# ---------------------------------------------------------------- helpers

def parse_time(value) -> datetime:
    s = str(value).replace("Z", "+00:00")
    t = datetime.fromisoformat(s)
    if t.tzinfo is None:
        t = t.replace(tzinfo=timezone.utc)
    return t.astimezone(timezone.utc)


def norm_os(value) -> str | None:
    s = (value or "").strip().lower()
    if not s or s == "unknown":
        return None
    if "windows" in s:
        return "Windows"
    if "android" in s:
        return "Android"
    if "chrome os" in s or "chromeos" in s or "cros" in s:
        return "ChromeOS"
    if "mac" in s or "os x" in s:
        return "macOS"
    if "ios" in s or "iphone" in s or "ipad" in s:
        return "iOS"
    if any(k in s for k in ("linux", "ubuntu", "fedora", "debian")):
        return "Linux"
    return value.strip()


def norm_method(value) -> str | None:
    s = (value or "").strip().lower()
    if not s or "password" in s:
        return None
    if "fastpass" in s or "signed_nonce" in s:
        return "fastpass"
    if any(k in s for k in ("webauthn", "passkey", "fido", "security key",
                            "security_key", "u2f")):
        return "passkey"
    if any(k in s for k in ("smart", "piv", "x509", "cert")):
        return "smart card"
    if "push" in s:
        return "push"
    if "sms" in s:
        return "sms"
    if "voice" in s or "call" in s:
        return "voice"
    if "email" in s:
        return "email"
    if any(k in s for k in ("otp", "code", "soft_token", "google")):
        return "totp"
    if "question" in s:
        return "security question"
    return s


def factor_label(f: dict) -> str:
    t = f.get("factorType") or "?"
    if t == "signed_nonce":
        plat = (f.get("platform") or "").upper()
        return f"FastPass ({PLATFORM_LABELS.get(plat, plat.title() or '?')})"
    return FACTOR_LABELS.get(t, t)


def pad(value, width: int) -> str:
    s = str(value)
    return s[:width].ljust(width)


def people_scope(conditions, group_id, everyone_id):
    """How a rule/policy's people condition relates to the target group.

    Returns (applies, label). applies is False when it can't match the group.
    """
    people = (conditions or {}).get("people") or {}
    groups = people.get("groups") or {}
    users = people.get("users") or {}
    inc = groups.get("include") or []
    exc = groups.get("exclude") or []
    if group_id and group_id in exc:
        return False, "excludes this group"
    if inc:
        if group_id and group_id in inc:
            return True, "this group"
        if everyone_id and everyone_id in inc:
            return True, "everyone"
        if group_id:
            return False, "other groups"
        return True, f"only {len(inc)} group(s)"
    if users.get("include"):
        return True, f"only {len(users['include'])} named user(s)"
    return True, "everyone"


def rule_conditions(conditions) -> list:
    c = conditions or {}
    out = []
    net = c.get("network") or {}
    if net.get("connection") and net.get("connection") != "ANYWHERE":
        out.append("network zone")
    if c.get("device"):
        out.append("device")
    if c.get("platform"):
        out.append("platform")
    risk = c.get("riskScore") or c.get("risk") or {}
    if risk.get("level") and risk.get("level") != "ANY":
        out.append("risk")
    if c.get("elCondition"):
        out.append("expression")
    ut = c.get("userType") or {}
    if ut.get("include") or ut.get("exclude"):
        out.append("user type")
    return out


def pr_requirement(rule: dict) -> str:
    sign_on = (rule.get("actions") or {}).get("appSignOn") or {}
    vm = sign_on.get("verificationMethod") or {}
    if vm.get("type") == "AUTH_METHOD_CHAIN":
        if PR_REQUIRED_RE.search(json.dumps(vm.get("chains") or [])):
            return "auth method chain with phishing resistance on some steps"
        return "auth method chain (check its steps by hand)"
    cons = vm.get("constraints") or []
    req = [((c or {}).get("possession") or {}).get("phishingResistant") == "REQUIRED"
           for c in cons]
    if req and all(req):
        return "phishing resistance REQUIRED"
    if any(req):
        return "phishing resistance required on some paths only"
    return "phishing resistance NOT required"


def enroll_setting(policy: dict, key: str) -> str:
    settings = policy.get("settings") or {}
    aliases = {"webauthn": ("webauthn", "fido_webauthn"),
               "okta_verify": ("okta_verify", "okta_push")}[key]
    for a in settings.get("authenticators") or []:
        if a.get("key") in aliases:
            return ((a.get("enroll") or {}).get("self")) or "NOT_ALLOWED"
    factors = settings.get("factors") or {}
    for k in aliases:
        if k in factors:
            return ((factors[k].get("enroll") or {}).get("self")) or "NOT_ALLOWED"
    return "NOT_ALLOWED"


def by_priority(items: list) -> list:
    return sorted(items, key=lambda x: (int(x.get("priority") or 0), x.get("name") or ""))


# ---------------------------------------------------------------- analysis

def event_methods(ev: dict) -> list:
    """[(method, phishing_resistant)] for the authenticators an event used."""
    out = []
    for m in ev.get("methods") or []:
        name = norm_method(m.get("method")) or (
            None if "password" in (m.get("key") or "") else norm_method(m.get("key")))
        if not name:
            continue
        props = (m.get("props") or "").upper()
        out.append((name, "PHISHING_RESISTANT" in props or name in ("passkey", "smart card")))
    if not out:
        name = norm_method(ev.get("factor"))
        if name:
            out.append((name, name in ("passkey", "smart card")))
    return out


def classify_user(user: dict, events: list) -> dict:
    factors = [f for f in user.get("factors") or [] if f.get("status") == "ACTIVE"]
    types = {f.get("factorType") for f in factors}
    fp_os = {PLATFORM_LABELS.get((f.get("platform") or "").upper())
             for f in factors if f.get("factorType") == "signed_nonce"} - {None}
    has_key = bool(types & {"webauthn", "u2f"})
    has_pr = bool(types & PR_FACTOR_TYPES)

    os_seen, pr_os, used, last_pr, last_seen = set(), set(), set(), None, None
    fp_not_pr = False
    for ev in events:
        os_name = norm_os(ev.get("os"))
        when = parse_time(ev["published"])
        last_seen = when if last_seen is None or when > last_seen else last_seen
        if os_name:
            os_seen.add(os_name)
        for name, pr in event_methods(ev):
            used.add(name)
            if pr:
                last_pr = when if last_pr is None or when > last_pr else last_pr
                if os_name:
                    pr_os.add(os_name)
            elif name == "fastpass":
                fp_not_pr = True

    if last_pr:
        cls = "READY"
    elif has_pr:
        cls = "ENROLLED_NOT_USED"
    elif factors:
        cls = "AT_RISK"
    else:
        cls = "NO_MFA"

    uncovered = sorted(o for o in os_seen
                       if not (has_key or o in fp_os or o in pr_os))
    platform_blocker = cls in ("READY", "ENROLLED_NOT_USED") and bool(uncovered)

    notes = []
    if cls in ("NO_MFA", "AT_RISK"):
        no_fp = [o for o in sorted(os_seen) if o not in FASTPASS_OS]
        if no_fp:
            notes.append(f"enroll a passkey/security key (FastPass doesn't run on {', '.join(no_fp)})")
        else:
            notes.append("enroll Okta Verify with FastPass, or a passkey")
    if platform_blocker:
        for o in uncovered:
            if o in FASTPASS_OS:
                notes.append(f"{o}: no FastPass there; set it up or add a passkey")
            else:
                notes.append(f"{o}: FastPass unsupported; add a passkey/security key")
    if cls == "ENROLLED_NOT_USED":
        if fp_not_pr:
            notes.append("FastPass used, but never phishing-resistant (Okta Verify app or unsupported browser)")
        else:
            notes.append("ask them to sign in once with it to prove it works")
    if last_seen is None:
        notes.append("no sign-ins in window")

    labels = sorted({factor_label(f) for f in factors})
    return {
        "login": user.get("login") or user.get("id"),
        "id": user.get("id"),
        "class": cls,
        "platform_blocker": platform_blocker,
        "enrolled": labels,
        "methods_used": sorted(used),
        "os_seen": sorted(os_seen),
        "os_uncovered": uncovered,
        "last_phishing_resistant_use": last_pr.strftime("%Y-%m-%d") if last_pr else None,
        "last_sign_in": last_seen.strftime("%Y-%m-%d") if last_seen else None,
        "fix": "; ".join(notes),
    }


def tenant_checks(snap: dict, group_id, everyone_id, need_passkey: int = 0) -> list:
    auths = {a.get("key"): a for a in snap.get("authenticators") or []}
    checks = []
    wa = auths.get("webauthn")
    wa_on = bool(wa) and wa.get("status") == "ACTIVE"
    ov = auths.get("okta_verify")
    fp_on = bool(ov) and ov.get("status") == "ACTIVE" and any(
        m.get("type") == "signed_nonce" and m.get("status") == "ACTIVE"
        for m in ov.get("methods") or [])
    sc = auths.get("smart_card_idp")
    sc_on = bool(sc) and sc.get("status") == "ACTIVE"
    if not (wa_on or fp_on or sc_on):
        checks.append(["BLOCKER", "No phishing-resistant authenticator is active in this tenant: "
                                  "enforcing now would lock out everyone in scope."])
    if wa_on:
        checks.append(["OK", "Passkey/security key (WebAuthn) authenticator is ACTIVE."])
    else:
        state = wa.get("status") if wa else "not set up"
        who = (f"{need_passkey} user(s) in scope who sign in from an OS without FastPass"
               if need_passkey else "users who can't use FastPass (Linux, ChromeOS, no Okta Verify)")
        checks.append(["BLOCKER" if need_passkey or not fp_on else "WARN",
                       f"Passkey/security key (WebAuthn) authenticator is {state}, so {who} "
                       "have no phishing-resistant option until it is activated."])
    if fp_on:
        checks.append(["OK", "Okta Verify FastPass is ACTIVE."])
    else:
        checks.append(["WARN", "Okta Verify FastPass is not active."])
    if sc_on:
        checks.append(["OK", "Smart card (PIV) authenticator is ACTIVE. Smart card enrollment "
                             "isn't visible in the factors API; it counts only from sign-in evidence."])

    enroll = None
    for p in by_priority([p for p in snap.get("enroll_policies") or []
                          if p.get("status") == "ACTIVE"]):
        applies, who = people_scope(p.get("conditions"), group_id, everyone_id)
        if applies and who in ("this group", "everyone"):
            enroll = p
            break
    if enroll is None:
        checks.append(["WARN", "No active authenticator enrollment policy covers this target."])
    else:
        w = enroll_setting(enroll, "webauthn")
        o = enroll_setting(enroll, "okta_verify")
        where = f"Enrollment policy \"{enroll.get('name')}\""
        if w == "NOT_ALLOWED" and o == "NOT_ALLOWED":
            checks.append(["BLOCKER", f"{where} lets these users enroll neither FastPass nor a passkey."])
        elif w == "NOT_ALLOWED":
            checks.append(["WARN", f"{where} doesn't offer passkey/security key enrollment "
                                   f"(Okta Verify: {o}): users without FastPass can't self-enroll."])
        elif o == "NOT_ALLOWED":
            checks.append(["WARN", f"{where} doesn't offer Okta Verify enrollment "
                                   f"(passkey: {w}): FastPass isn't self-service."])
        else:
            checks.append(["OK", f"{where} offers passkey ({w}) and Okta Verify ({o})."])
    return checks


def policy_path(snap: dict, group_id, everyone_id) -> dict:
    out = {"app_sign_in": [], "global_session": None}
    for pol in snap.get("access_policies") or []:
        rows, matched = [], False
        for r in by_priority([r for r in pol.get("rules") or [] if r.get("status") == "ACTIVE"]):
            applies, who = people_scope(r.get("conditions"), group_id, everyone_id)
            if not applies:
                continue
            conds = rule_conditions(r.get("conditions"))
            sign_on = (r.get("actions") or {}).get("appSignOn") or {}
            vm = sign_on.get("verificationMethod") or {}
            first = not matched and not conds and not who.startswith("only")
            matched = matched or first
            rows.append({
                "priority": int(r.get("priority") or 0),
                "name": r.get("name"),
                "applies_to": who,
                "only_when": conds,
                "access": sign_on.get("access") or "ALLOW",
                "factor_mode": vm.get("factorMode") or "?",
                "phishing_resistance": pr_requirement(r),
                "first_unconditional_match": first,
            })
        out["app_sign_in"].append({"policy": pol.get("name"), "id": pol.get("id"),
                                   "apps": sorted(pol.get("apps") or []), "rules": rows})
    for pol in by_priority([p for p in snap.get("sign_on_policies") or []
                            if p.get("status") == "ACTIVE"]):
        applies, who = people_scope(pol.get("conditions"), group_id, everyone_id)
        if not applies or who not in ("this group", "everyone"):
            continue
        for r in by_priority([r for r in pol.get("rules") or [] if r.get("status") == "ACTIVE"]):
            ok, who = people_scope(r.get("conditions"), group_id, everyone_id)
            if not ok or rule_conditions(r.get("conditions")) or who.startswith("only"):
                continue
            so = (r.get("actions") or {}).get("signon") or {}
            out["global_session"] = {
                "policy": pol.get("name"), "rule": r.get("name"),
                "access": so.get("access") or "ALLOW",
                "require_factor": bool(so.get("requireFactor")),
                "primary_factor": so.get("primaryFactor") or "?",
            }
            break
        break
    return out


def analyze(snap: dict) -> dict:
    now = parse_time(snap["collected_at"])
    lookback = int(snap.get("lookback_days") or 30)
    cutoff = now - timedelta(days=lookback)
    target = snap.get("target") or {}
    group = target.get("group")
    group_id = group.get("id") if group else None
    everyone_id = snap.get("everyone_group_id")

    by_actor = {}
    for ev in snap.get("events") or []:
        if ev.get("eventType") not in AUTH_EVENTS or ev.get("result") != "SUCCESS":
            continue
        if parse_time(ev["published"]) < cutoff:
            continue
        by_actor.setdefault(ev.get("actor_id"), []).append(ev)

    users, skipped = [], {}
    for u in snap.get("users") or []:
        if u.get("status") not in SIGNIN_STATUSES:
            skipped[u.get("status") or "?"] = skipped.get(u.get("status") or "?", 0) + 1
            continue
        users.append(classify_user(u, by_actor.get(u.get("id"), [])))
    users.sort(key=lambda r: (r["login"] or "").lower())

    counts = {c: sum(1 for r in users if r["class"] == c) for c in CLASSES}
    counts["PLATFORM_BLOCKER"] = sum(1 for r in users if r["platform_blocker"])
    rank = {"NO_MFA": 0, "AT_RISK": 1, "ENROLLED_NOT_USED": 2, "READY": 3}
    lockout = [r for r in users if r["class"] in ("NO_MFA", "AT_RISK") or r["platform_blocker"]]
    lockout.sort(key=lambda r: (rank[r["class"]], (r["login"] or "").lower()))
    waves = {
        "wave1_enforce_now": [r["login"] for r in users
                              if r["class"] == "READY" and not r["platform_blocker"]],
        "wave2_nudge": [r["login"] for r in users
                        if r["class"] == "ENROLLED_NOT_USED" and not r["platform_blocker"]],
        "wave3_enroll_first": [r["login"] for r in users if r["class"] == "AT_RISK"],
        "hold": [r["login"] for r in users
                 if r["class"] == "NO_MFA" or r["platform_blocker"]],
    }
    return {
        "target": target,
        "collected_at": now.strftime("%Y-%m-%d"),
        "lookback_days": lookback,
        "users_in_scope": len(users),
        "skipped_not_active": dict(sorted(skipped.items())),
        "summary": counts,
        "would_lock_out": len(lockout),
        "tenant_checks": tenant_checks(
            snap, group_id, everyone_id,
            sum(1 for r in users if r["class"] != "READY" or r["platform_blocker"]
                if any(o not in FASTPASS_OS for o in r["os_seen"]))),
        "policies": policy_path(snap, group_id, everyone_id),
        "lockout": lockout,
        "waves": waves,
        "users": users,
    }


# ---------------------------------------------------------------- output

def target_label(target: dict) -> str:
    g, a = target.get("group"), target.get("app")
    parts = []
    if g:
        parts.append(f"group \"{g.get('name')}\" ({g.get('id')})")
    if a:
        parts.append(f"app \"{a.get('label')}\" ({a.get('id')})")
    return " on ".join(parts) if parts else "?"


def render_text(res: dict) -> str:
    n, lock = res["users_in_scope"], res["would_lock_out"]
    s = res["summary"]
    skipped = res["skipped_not_active"]
    skip_txt = ""
    if skipped:
        skip_txt = " (skipped, can't sign in: " + ", ".join(
            f"{v} {k}" for k, v in skipped.items()) + ")"
    L = ["Phishing-resistant MFA enforcement what-if (read-only; nothing in Okta was changed)",
         f"Target:   {target_label(res['target'])}",
         f"Evidence: System Log sign-ins over the last {res['lookback_days']} days "
         f"(through {res['collected_at']} UTC)",
         f"Scope:    {n} user(s) who can sign in{skip_txt}", ""]
    if n == 0:
        L.append("VERDICT: nobody in scope can sign in, so nobody would be locked out.")
    else:
        pct = (200 * lock + n) // (2 * n)
        L.append(f"VERDICT: enforcing phishing-resistant MFA for this target today would "
                 f"lock out {lock} of {n} user(s) ({pct}%).")
        if s["ENROLLED_NOT_USED"]:
            L.append(f"         {s['ENROLLED_NOT_USED']} more are enrolled but haven't used it "
                     "in the window (unproven).")
    L += ["", "SUMMARY"]
    for c in CLASSES + ["PLATFORM_BLOCKER"]:
        L.append(f"  {pad(c, 18)} {s[c]:>3}  {CLASS_HELP[c]}")

    L += ["", "TENANT READINESS"]
    for level, msg in res["tenant_checks"]:
        L.append(f"  {pad(level, 8)} {msg}")

    L += ["", "POLICY RULES IN THE PATH (read with GET only)"]
    pols = res["policies"]
    if not pols["app_sign_in"]:
        L.append("  No app sign-in policy in scope (pass --app, or assign apps to the group).")
    for p in pols["app_sign_in"]:
        L.append(f"  App sign-in policy \"{p['policy']}\" (apps: {', '.join(p['apps']) or '-'})")
        if not p["rules"]:
            L.append("    no active rule applies to this target")
        for r in p["rules"]:
            when = f"only when: {', '.join(r['only_when'])}; " if r["only_when"] else ""
            if r["access"] == "DENY":
                what = "denies access"
            else:
                what = f"{r['factor_mode']}; {r['phishing_resistance']}"
            mark = ""
            if r["first_unconditional_match"]:
                mark = ("  <- first unconditional match: ALREADY enforces it (the lockout "
                        "list is who it blocks today)"
                        if r["phishing_resistance"] == "phishing resistance REQUIRED"
                        else "  <- first unconditional match: the rule you'd tighten")
            L.append(f"    priority {pad(r['priority'], 3)} \"{r['name']}\": applies to "
                     f"{r['applies_to']}; {when}{what}{mark}")
    g = pols["global_session"]
    if g:
        mfa = "MFA required" if g["require_factor"] else "no MFA at session level"
        pw = " (passwordless allowed)" if g["primary_factor"] == "PASSWORD_IDP_ANY_FACTOR" else ""
        L.append(f"  Global session policy \"{g['policy']}\" rule \"{g['rule']}\": {mfa}; "
                 f"primary factor {g['primary_factor']}{pw}")

    L += ["", f"WOULD BE LOCKED OUT ({lock})"]
    if not res["lockout"]:
        L.append("  nobody")
    else:
        L.append(f"  {pad('LOGIN', 34)} {pad('CLASS', 18)} {pad('ENROLLED', 28)} "
                 f"{pad('LAST PR USE', 11)} {pad('SIGN-IN OS', 18)} FIX")
        for r in res["lockout"]:
            cls = r["class"] + ("+PLATFORM" if r["platform_blocker"] else "")
            L.append(f"  {pad(r['login'], 34)} {pad(cls, 18)} "
                     f"{pad(', '.join(r['enrolled']) or '-', 28)} "
                     f"{pad(r['last_phishing_resistant_use'] or 'never', 11)} "
                     f"{pad(', '.join(r['os_seen']) or '-', 18)} {r['fix']}")

    w = res["waves"]
    L += ["", "SUGGESTED ROLLOUT ORDER"]
    for key, title in (("wave1_enforce_now", "Wave 1  enforce now"),
                       ("wave2_nudge", "Wave 2  nudge (enrolled, unproven)"),
                       ("wave3_enroll_first", "Wave 3  enroll first, then enforce"),
                       ("hold", "Hold    fix before enforcing")):
        L.append(f"  {title} ({len(w[key])}): {', '.join(w[key]) or '-'}")

    L += ["", "NEXT STEP"]
    blockers = [m for lvl, m in res["tenant_checks"] if lvl == "BLOCKER"]
    if blockers:
        L.append("  Clear the tenant BLOCKER(s) above first; until then the users in Wave 3 and "
                 "Hold have no path to comply.")
    marked = any(r["first_unconditional_match"] for p in pols["app_sign_in"] for r in p["rules"])
    if w["wave1_enforce_now"]:
        where = "above the rule marked <-" if marked else "in the app sign-in policy"
        L.append("  Start with Wave 1 only: put those users in a pilot group and add a "
                 f"phishing-resistant rule for it {where}.")
    else:
        L.append("  Nobody is ready yet: get users enrolled (Wave 3 / Hold) before any "
                 "enforcement.")
    L.append("  Re-run this after each wave; it only reads.")
    return "\n".join(L) + "\n"


# ---------------------------------------------------------------- collection (GET only)

def trim_event(ev: dict) -> dict:
    methods = []
    for t in ev.get("target") or []:
        de = t.get("detailEntry") or {}
        if t.get("type") in ("AuthenticatorEnrollment", "AuthenticatorMethod") or \
                de.get("methodTypeUsed"):
            methods.append({"method": de.get("methodTypeUsed") or t.get("displayName"),
                            "props": de.get("methodUsedVerifiedProperties") or "",
                            "key": de.get("authenticatorKey") or ""})
    return {
        "published": ev.get("published"),
        "eventType": ev.get("eventType"),
        "actor_id": (ev.get("actor") or {}).get("id"),
        "result": (ev.get("outcome") or {}).get("result"),
        "os": ((ev.get("client") or {}).get("userAgent") or {}).get("os"),
        "factor": ((ev.get("debugContext") or {}).get("debugData") or {}).get("factor"),
        "methods": methods,
    }


def trim_user(u: dict, factors: list) -> dict:
    prof = u.get("profile") or {}
    return {
        "id": u.get("id"), "status": u.get("status"), "login": prof.get("login"),
        "factors": [{"factorType": f.get("factorType"), "status": f.get("status"),
                     "provider": f.get("provider"),
                     "platform": (f.get("profile") or {}).get("platform")}
                    for f in factors],
    }


def collect(client, group_arg, app_arg, lookback: int, progress=None) -> dict:
    def get(path, params=None):
        return client._request("GET", path, params=params).json()

    def say(msg):
        if progress:
            print(msg, file=sys.stderr)

    now = datetime.now(timezone.utc).replace(microsecond=0)
    target = {"group": None, "app": None}
    group = app = None
    if group_arg:
        if GROUP_ID.match(group_arg):
            group = get(f"/api/v1/groups/{group_arg}")
        else:
            hits = [g for g in client.list_groups(group_arg)
                    if (g.get("profile") or {}).get("name", "").lower() == group_arg.lower()]
            if len(hits) != 1:
                raise ValueError(f"--group {group_arg!r}: {len(hits)} groups have that exact "
                                 "name; pass the group id instead")
            group = hits[0]
        target["group"] = {"id": group["id"], "name": group["profile"]["name"]}
    if app_arg:
        if APP_ID.match(app_arg):
            app = get(f"/api/v1/apps/{app_arg}")
        else:
            cands = list(client.paged_get("/api/v1/apps", {"q": app_arg}))
            hits = [a for a in cands if (a.get("label") or "").lower() == app_arg.lower()] or \
                [a for a in cands if (a.get("name") or "").lower() == app_arg.lower()]
            if len(hits) != 1:
                raise ValueError(f"--app {app_arg!r}: {len(hits)} apps have that exact label; "
                                 "pass the app id instead")
            app = hits[0]
        target["app"] = {"id": app["id"], "label": app.get("label")}

    everyone_id = None
    for g in client.list_groups("Everyone"):
        if g.get("type") == "BUILT_IN" and (g.get("profile") or {}).get("name") == "Everyone":
            everyone_id = g["id"]

    # Users in scope.
    say("... reading users in scope")
    members = {}
    if group:
        for u in client.paged_get(f"/api/v1/groups/{group['id']}/users"):
            members[u["id"]] = u
    if app:
        app_ids = [au["id"] for au in client.paged_get(f"/api/v1/apps/{app['id']}/users")]
        if group:
            members = {i: members[i] for i in app_ids if i in members}
        else:
            for i in app_ids:
                members[i] = get(f"/api/v1/users/{i}")
    users = []
    for n, u in enumerate(members.values(), 1):
        factors = client.list_factors(u["id"]) if u.get("status") in SIGNIN_STATUSES else []
        users.append(trim_user(u, factors))
        if n % 50 == 0:
            say(f"... read factors for {n} users")

    # Sign-in evidence: one bounded System Log query, kept to in-scope users.
    say("... reading System Log sign-in evidence")
    ids = {u["id"] for u in users}
    since = (now - timedelta(days=lookback)).strftime("%Y-%m-%dT%H:%M:%S.000Z")
    until = now.strftime("%Y-%m-%dT%H:%M:%S.000Z")
    filt = " or ".join(f'eventType eq "{e}"' for e in AUTH_EVENTS)
    events = [trim_event(ev) for ev in client.paged_get(
        "/api/v1/logs", {"filter": filt, "since": since, "until": until,
                         "sortOrder": "ASCENDING", "limit": 1000})
        if (ev.get("actor") or {}).get("id") in ids]

    # Authenticators and policies (GET only).
    say("... reading authenticators and policies")
    auths = []
    for a in client.paged_get("/api/v1/authenticators"):
        row = {"key": a.get("key"), "status": a.get("status"), "methods": []}
        if a.get("key") == "okta_verify":
            row["methods"] = [{"type": m.get("type"), "status": m.get("status")}
                              for m in get(f"/api/v1/authenticators/{a['id']}/methods")]
        auths.append(row)

    apps = []
    if app:
        apps = [app]
    elif group:
        apps = [a for a in client.paged_get("/api/v1/apps", {"filter": f'group.id eq "{group["id"]}"'})
                if a.get("status") == "ACTIVE"]
    access = {}
    for a in apps:
        href = (((a.get("_links") or {}).get("accessPolicy")) or {}).get("href")
        if not href:
            continue
        pid = href.rstrip("/").split("/")[-1]
        if pid not in access:
            pol = get(f"/api/v1/policies/{pid}")
            access[pid] = {"id": pid, "name": pol.get("name"), "apps": [],
                           "rules": list(client.list_policy_rules(pid))}
        access[pid]["apps"].append(a.get("label"))

    sign_on = []
    for p in client.list_policies("OKTA_SIGN_ON"):
        p = {k: p.get(k) for k in ("id", "name", "priority", "status", "conditions")}
        p["rules"] = list(client.list_policy_rules(p["id"]))
        sign_on.append(p)
    enroll = [{k: p.get(k) for k in ("id", "name", "priority", "status", "conditions", "settings")}
              for p in client.list_policies("MFA_ENROLL")]

    return {
        "collected_at": now.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "lookback_days": lookback,
        "target": target,
        "everyone_group_id": everyone_id,
        "users": users,
        "events": events,
        "authenticators": auths,
        "access_policies": list(access.values()),
        "sign_on_policies": sign_on,
        "enroll_policies": enroll,
    }


def main(argv: list | None = None) -> int:
    p = argparse.ArgumentParser(
        description="Simulate who would be locked out if you enforced phishing-resistant "
                    "MFA for a group and/or app. READ-ONLY (GET requests only).")
    p.add_argument("--group", help="target group name or id")
    p.add_argument("--app", help="target app label or id")
    p.add_argument("--lookback-days", type=int, default=30,
                   help=f"System Log evidence window, 1-{MAX_LOOKBACK} (default 30)")
    p.add_argument("--input", metavar="SNAPSHOT_JSON",
                   help="analyze a saved snapshot instead of calling Okta")
    p.add_argument("--save-snapshot", metavar="PATH",
                   help="also write the raw data read from Okta (for --input re-runs)")
    p.add_argument("--json", action="store_true", help="emit JSON instead of text")
    p.add_argument("--output", help="write the report to this file")
    p.add_argument("--fail-on-lockout", action="store_true",
                   help="exit 2 if anyone in scope would be locked out")
    args = p.parse_args(argv)

    if not args.input and not (args.group or args.app):
        p.error("give --group and/or --app (or --input SNAPSHOT_JSON)")
    if not 1 <= args.lookback_days <= MAX_LOOKBACK:
        p.error(f"--lookback-days must be 1-{MAX_LOOKBACK} (System Log retention)")

    try:
        if args.input:
            with open(args.input, encoding="utf-8") as f:
                snap = json.load(f)
        else:
            from lib.okta_client import OktaClient
            snap = collect(OktaClient(), args.group, args.app, args.lookback_days, progress=True)
            if args.save_snapshot:
                with open(args.save_snapshot, "w", encoding="utf-8") as f:
                    json.dump(snap, f, indent=2)
                print(f"wrote {args.save_snapshot}", file=sys.stderr)
    except Exception as e:  # auth errors, network, bad file, ambiguous names
        print(f"error: {e}", file=sys.stderr)
        return 1

    res = analyze(snap)
    report = json.dumps(res, indent=2) + "\n" if args.json else render_text(res)
    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            f.write(report)
        print(f"wrote {args.output}", file=sys.stderr)
    else:
        sys.stdout.write(report)
    return 2 if args.fail_on_lockout and res["would_lock_out"] else 0


if __name__ == "__main__":
    sys.exit(main())
