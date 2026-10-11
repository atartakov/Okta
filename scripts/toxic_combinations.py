#!/usr/bin/env python3
"""Toxic access combinations (separation-of-duties checker). READ-ONLY.

You describe access that must never sit with one person in a small JSON
policy file ("AWS prod admin" + "finance approver", "creates vendors" +
"approves payments", "Okta super admin" + "no phishing-resistant factor").
The script pulls users, group memberships, app assignments (direct and via
group) and admin role assignments, then reports every user who holds a
toxic combination:

    * HOW they got each side: assigned directly, via a group, via a group
      that a group rule fills automatically, via a directory-synced group,
      or via the Everyone group
    * the SMALLEST FIX: the fewest, most targeted changes that break the
      combination (e.g. "unassign app X from this user" beats "remove them
      from a group that also gives them five other things")
    * a risk-ranked table, plain-English explanations, JSON and CSV

Policy entry types (each side of a rule is "any_of" or "all_of" a list):
    {"type": "app", "value": "<app label, name or id>"}
    {"type": "app_group", "app": "<app>", "group": "<group>"}   app via that group only
    {"type": "group", "value": "<group name or id>"}
    {"type": "admin_role", "value": "SUPER_ADMIN | <role label> | <custom role id>"}
    {"type": "no_phishing_resistant_factor"}
See examples/sod_policy.example.json.

Every HTTP call is a GET. Nothing in the tenant is created, changed or deleted.

Usage:
    export OKTA_DOMAIN=https://dev-123456.okta.com
    export OKTA_API_TOKEN=00...
    python scripts/toxic_combinations.py --policy examples/sod_policy.example.json
    python scripts/toxic_combinations.py --policy sod.json --json --output sod.json --csv sod.csv
    python scripts/toxic_combinations.py --policy sod.json --fail-on high        # CI gate
    python scripts/toxic_combinations.py --policy sod.json --save-snapshot snap.json
    python scripts/toxic_combinations.py --policy sod.json --snapshot snap.json  # offline

Exit codes: 0 = no finding at or above --fail-on, 2 = findings at or above
--fail-on, 1 = error (bad policy, auth failure).
"""

from __future__ import annotations

import argparse
import csv
import io
import json
import os
import re
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

SEVERITIES = ["low", "medium", "high", "critical"]
BASE_SCORE = {"critical": 90, "high": 70, "medium": 50, "low": 30}
ENTRY_TYPES = {"app", "app_group", "group", "admin_role", "no_phishing_resistant_factor"}
# Okta FastPass (signed_nonce) counts as phishing-resistant; override with
# "phishing_resistant_factors" in the policy if yours is not configured so.
DEFAULT_PR_FACTORS = ["webauthn", "smart_card", "signed_nonce"]
CAN_SIGN_IN = {"ACTIVE", "PASSWORD_EXPIRED", "LOCKED_OUT", "RECOVERY"}
COST_EVERYONE = 50


class PolicyError(ValueError):
    """Raised when the policy file is malformed."""


# ---------------------------------------------------------------- policy

def load_policy(path: str) -> dict:
    with open(path, encoding="utf-8") as f:
        try:
            policy = json.load(f)
        except json.JSONDecodeError as e:
            raise PolicyError(f"{path} is not valid JSON: {e}") from e
    validate_policy(policy)
    return policy


def validate_policy(policy: dict) -> None:
    rules = policy.get("rules") if isinstance(policy, dict) else None
    if not isinstance(rules, list) or not rules:
        raise PolicyError("policy needs a non-empty \"rules\" list")
    seen = set()
    for i, rule in enumerate(rules, 1):
        rid = rule.get("id") or f"rule #{i}"
        if not rule.get("id") or not rule.get("name"):
            raise PolicyError(f"{rid}: every rule needs an \"id\" and a \"name\"")
        if rid in seen:
            raise PolicyError(f"{rid}: duplicate rule id")
        seen.add(rid)
        if str(rule.get("severity", "high")).lower() not in SEVERITIES:
            raise PolicyError(f"{rid}: severity must be one of {', '.join(SEVERITIES)}")
        sides = rule.get("sides")
        if not isinstance(sides, list) or len(sides) < 2:
            raise PolicyError(f"{rid}: \"sides\" needs at least two entries")
        for s in sides:
            entries = s.get("any_of", s.get("all_of"))
            if not s.get("label") or not isinstance(entries, list) or not entries:
                raise PolicyError(f"{rid}: each side needs a \"label\" and a non-empty \"any_of\" or \"all_of\" list")
            for e in entries:
                t = e.get("type")
                if t not in ENTRY_TYPES:
                    raise PolicyError(f"{rid}: unknown entry type {t!r}")
                if t in ("app", "group", "admin_role") and not e.get("value"):
                    raise PolicyError(f"{rid}: {t} entry needs a \"value\"")
                if t == "app_group" and not (e.get("app") and e.get("group")):
                    raise PolicyError(f"{rid}: app_group entry needs \"app\" and \"group\"")


def policy_entries(policy: dict):
    for rule in policy["rules"]:
        for side in rule["sides"]:
            for e in side.get("any_of", side.get("all_of")):
                yield e


# ---------------------------------------------------------------- matching helpers

def _eq(a, b) -> bool:
    return a is not None and b is not None and str(a).lower() == str(b).lower()


def app_matches(app: dict, value: str) -> bool:
    return any(_eq(app.get(k), value) for k in ("id", "label", "name"))


def group_name(group: dict) -> str:
    return (group.get("profile") or {}).get("name") or group.get("id")


def group_matches(group: dict, value: str) -> bool:
    return _eq(group.get("id"), value) or _eq(group_name(group), value)


def role_matches(role: dict, value: str) -> bool:
    return any(_eq(role.get(k), value) for k in ("type", "label", "role", "id"))


def role_name(role: dict) -> str:
    label, rtype = role.get("label") or "", role.get("type") or ""
    if label and rtype and label != rtype:
        return f"{label} ({rtype})"
    return label or rtype or "?"


def user_login(user: dict) -> str:
    return (user.get("profile") or {}).get("login") or user.get("id")


def sort_by_key(items, keyfunc):
    """Ordinal string sort; the PowerShell port sorts the same keys the same way."""
    keyed = sorted(((keyfunc(x), i) for i, x in enumerate(items)))
    return [items[i] for _, i in keyed]


# ---------------------------------------------------------------- the index

class Tenant:
    """Indexes a snapshot so the analysis is plain lookups."""

    def __init__(self, snap: dict):
        self.users = [u for u in snap.get("users", []) if u.get("status") != "DEPROVISIONED"]
        self.groups = {g["id"]: g for g in snap.get("groups", [])}
        self.apps = {a["id"]: a for a in snap.get("apps", [])}
        self.app_users = snap.get("app_users", {})
        self.app_groups = snap.get("app_groups", {})
        self.user_roles = snap.get("user_roles", {})
        self.group_roles = snap.get("group_roles", {})
        self.factors = snap.get("factors", {})
        self.members = {gid: set(uids) for gid, uids in snap.get("group_members", {}).items()}
        self.everyone = {g["id"] for g in self.groups.values()
                         if g.get("type") == "BUILT_IN" and group_name(g) == "Everyone"}
        all_ids = {u["id"] for u in self.users}
        for gid in self.everyone:
            self.members[gid] = all_ids
        self.rule_for_group = {}
        for r in snap.get("group_rules", []):
            if r.get("status") != "ACTIVE":
                continue
            gids = (((r.get("actions") or {}).get("assignUserToGroups") or {}).get("groupIds") or [])
            for gid in gids:
                self.rule_for_group.setdefault(gid, []).append(r.get("name") or r.get("id"))
        self.user_groups = {}
        for gid, uids in self.members.items():
            for uid in uids:
                self.user_groups.setdefault(uid, set()).add(gid)

    def find_apps(self, value):
        return [a for a in self.apps.values() if app_matches(a, value) and a.get("status", "ACTIVE") == "ACTIVE"]

    def find_groups(self, value):
        return [g for g in self.groups.values() if group_matches(g, value)]

    def gname(self, gid):
        g = self.groups.get(gid)
        return group_name(g) if g else gid

    def membership_path(self, gid, login, thing, via_text):
        """How a user is in group gid, and what it takes to get them out."""
        name = self.gname(gid)
        g = self.groups.get(gid) or {}
        if gid in self.everyone:
            return {"via": "everyone",
                    "how": f"{via_text} the Everyone group (every user gets it)",
                    "fix": f"Stop granting {thing} to the Everyone group (affects every user)",
                    "cost": COST_EVERYONE}
        if gid in self.rule_for_group:
            rules = ", ".join(f"'{r}'" for r in sorted(self.rule_for_group[gid]))
            return {"via": "rule-managed group",
                    "how": f"{via_text} group '{name}', which group rule {rules} fills automatically",
                    "fix": (f"Change group rule {rules} (or {login}'s profile attributes) so {login} "
                            f"no longer lands in group '{name}'; removing them by hand is undone by the rule"),
                    "cost": 3}
        if g.get("type") == "APP_GROUP":
            return {"via": "directory group",
                    "how": f"{via_text} group '{name}', which is synced in from a directory or app",
                    "fix": f"Remove {login} from group '{name}' in the directory it is synced from",
                    "cost": 3}
        return {"via": "group",
                "how": f"{via_text} group '{name}' (direct membership; no group rule feeds this group)",
                "fix": f"Remove {login} from group '{name}'",
                "cost": 2}


# ---------------------------------------------------------------- per-entry evaluation

def eval_entry(t: Tenant, user: dict, entry: dict, pr_factors) -> list:
    """Return the matched items for one policy entry: [{item, paths[]}]."""
    uid, login = user["id"], user_login(user)
    mygroups = t.user_groups.get(uid, set())
    etype = entry["type"]
    found = []
    if etype == "app":
        for app in t.find_apps(entry["value"]):
            thing = f"app '{app.get('label') or app['id']}'"
            paths = []
            assigned_groups = set(t.app_groups.get(app["id"], []))
            for au in t.app_users.get(app["id"], []):
                if au.get("id") != uid:
                    continue
                if au.get("scope") == "USER":
                    paths.append({"via": "direct", "how": "assigned to the user directly",
                                  "fix": f"Unassign {thing} from {login} (direct assignment)", "cost": 1})
            for gid in sorted(assigned_groups & mygroups):
                paths.append(t.membership_path(gid, login, thing, "via"))
            if paths:
                found.append({"item": thing, "paths": paths})
    elif etype == "app_group":
        for app in t.find_apps(entry["app"]):
            for g in t.find_groups(entry["group"]):
                if g["id"] in t.app_groups.get(app["id"], []) and g["id"] in mygroups:
                    thing = f"app '{app.get('label') or app['id']}' via group '{group_name(g)}'"
                    found.append({"item": thing,
                                  "paths": [t.membership_path(g["id"], login, thing, "member of")]})
    elif etype == "group":
        for g in t.find_groups(entry["value"]):
            if g["id"] in mygroups:
                thing = f"group '{group_name(g)}'"
                found.append({"item": thing,
                              "paths": [t.membership_path(g["id"], login, thing, "member of")]})
    elif etype == "admin_role":
        value = entry["value"]
        hits = {}
        for r in t.user_roles.get(uid, []):
            if r.get("assignmentType", "USER") == "USER" and role_matches(r, value):
                thing = f"admin role '{role_name(r)}'"
                hits.setdefault(thing, []).append(
                    {"via": "direct", "how": "assigned to the user directly",
                     "fix": f"Remove {thing} from {login} (direct assignment)", "cost": 1})
        for gid in sorted(mygroups):
            for r in t.group_roles.get(gid, []):
                if role_matches(r, value):
                    thing = f"admin role '{role_name(r)}'"
                    hits.setdefault(thing, []).append(t.membership_path(gid, login, thing, "via"))
        for thing in sorted(hits):
            found.append({"item": thing, "paths": hits[thing]})
    elif etype == "no_phishing_resistant_factor":
        active = [f for f in t.factors.get(uid, []) if f.get("status", "ACTIVE") == "ACTIVE"]
        types = sorted({f.get("factorType") or "?" for f in active})
        if not any(f.get("factorType") in pr_factors for f in active):
            has = ", ".join(types) if types else "none"
            found.append({"item": f"no phishing-resistant factor (enrolled: {has})",
                          "paths": [{"via": "condition",
                                     "how": ("no ACTIVE factor of a phishing-resistant type ("
                                            + ", ".join(sorted(pr_factors)) + ")"),
                                     "fix": (f"Enroll {login} in a phishing-resistant factor "
                                             "(FIDO2/WebAuthn key or Okta FastPass)"),
                                     "cost": 1}]})
    for f in found:
        f["paths"] = sort_by_key(f["paths"], lambda p: f"{p['cost']:03d}|{p['how']}")
    return found


def eval_side(t, user, side, pr_factors):
    """(holds, items, fix) for one side of a rule."""
    mode = "all_of" if "all_of" in side else "any_of"
    per_entry = [eval_entry(t, user, e, pr_factors) for e in side[mode]]
    if mode == "all_of":
        holds = all(per_entry)
    else:
        holds = any(per_entry)
    items, seen = [], set()
    for lst in per_entry:
        for it in lst:
            if it["item"] not in seen:
                seen.add(it["item"])
                items.append(it)
    if not holds:
        return False, [], None

    def actions_for(its):
        acts, costs, have = [], 0, set()
        for it in its:
            for p in it["paths"]:
                if p["fix"] not in have:
                    have.add(p["fix"])
                    acts.append(p["fix"])
                    costs += p["cost"]
        return acts, costs

    if mode == "any_of":
        acts, cost = actions_for(items)
    else:
        # Breaking an all_of side only needs the cheapest single entry gone.
        best = None
        for lst in per_entry:
            a, c = actions_for(lst)
            if best is None or c < best[1]:
                best = (a, c)
        acts, cost = best
    return True, items, {"side": side["label"], "actions": acts, "cost": cost}


def analyze(snapshot: dict, policy: dict) -> dict:
    """Pure analysis over a snapshot. Returns {findings, excepted, users_scanned}."""
    t = Tenant(snapshot)
    pr = set(policy.get("phishing_resistant_factors") or DEFAULT_PR_FACTORS)
    findings, excepted = [], []
    for rule in policy["rules"]:
        exceptions = {str(x).lower() for x in rule.get("exceptions", [])}
        severity = str(rule.get("severity", "high")).lower()
        for user in t.users:
            sides, fixes = [], []
            for side in rule["sides"]:
                holds, items, fix = eval_side(t, user, side, pr)
                if not holds:
                    break
                sides.append({"label": side["label"], "items": items})
                fixes.append(fix)
            else:
                login = user_login(user)
                if login.lower() in exceptions or user["id"].lower() in exceptions:
                    excepted.append({"user": login, "rule_id": rule["id"]})
                    continue
                # Fewest/cheapest changes wins; on a tie, the side listed LAST
                # (list the access you'd rather keep first).
                best = None
                for f in fixes:
                    if best is None or f["cost"] <= best["cost"]:
                        best = f
                status = user.get("status") or "?"
                indirect = any(p["via"] not in ("direct", "condition")
                               for s in sides for it in s["items"] for p in it["paths"])
                score = BASE_SCORE[severity]
                if status == "ACTIVE":
                    score += 5
                elif status not in CAN_SIGN_IN:
                    score -= 20
                if indirect:
                    score += 3
                score = max(0, min(100, score))
                profile = user.get("profile") or {}
                name = f"{profile.get('firstName') or ''} {profile.get('lastName') or ''}".strip()
                findings.append({
                    "risk": severity.upper(), "score": score,
                    "user": login, "user_id": user["id"], "name": name, "status": status,
                    "rule_id": rule["id"], "rule": rule["name"],
                    "why": rule.get("why", ""),
                    "sides": sides,
                    "smallest_fix": best,
                    "fix_options": fixes,
                    "explanation": explain(login, status, rule, sides, best),
                })
    findings = sort_by_key(findings, lambda f: f"{1000 - f['score']:04d}|{f['user'].lower()}|{f['rule_id']}")
    for i, f in enumerate(findings, 1):
        f["rank"] = i
    return {"findings": findings, "excepted": excepted, "users_scanned": len(t.users)}


def explain(login, status, rule, sides, fix) -> str:
    labels = [f'"{s["label"]}"' for s in sides]
    held = labels[0] if len(labels) == 1 else ", ".join(labels[:-1]) + " and " + labels[-1]
    text = f"{login} holds both {held}." if len(labels) == 2 else f"{login} holds all of {held}."
    if rule.get("why"):
        text += " " + rule["why"].strip()
    n = len(fix["actions"])
    text += (f" Smallest fix ({n} change{'s' if n != 1 else ''}, breaks \"{fix['side']}\"): "
             + "; ".join(fix["actions"]) + ".")
    if status not in CAN_SIGN_IN:
        text += f" The account is {status}, so it cannot sign in today, but the access is still assigned."
    return text


# ---------------------------------------------------------------- collection (GET only)

def wants(policy, etype):
    return any(e["type"] == etype for e in policy_entries(policy))


def iam_assignee_ids(client) -> list:
    """GET /api/v1/iam/assignees/users -> ids of users holding any admin role."""
    ids, path, params = [], "/api/v1/iam/assignees/users", {"limit": 100}
    while path:
        body = client._request("GET", path, params=params).json()
        ids.extend(u["id"] for u in body.get("value", []))
        nxt = ((body.get("_links") or {}).get("next") or {}).get("href")
        if not nxt:
            break
        from urllib.parse import urlparse, parse_qsl
        parsed = urlparse(nxt)
        path, params = parsed.path, dict(parse_qsl(parsed.query))
    return ids


def slim_user(u):
    p = u.get("profile") or {}
    return {"id": u["id"], "status": u.get("status"),
            "profile": {"login": p.get("login"), "firstName": p.get("firstName"),
                        "lastName": p.get("lastName")}}


def slim_role(r):
    return {k: r.get(k) for k in ("id", "type", "label", "assignmentType", "role") if r.get(k) is not None}


def collect(client, policy, log=lambda m: print(m, file=sys.stderr)) -> dict:
    snap = {"users": [], "groups": [], "group_members": {}, "group_rules": [], "apps": [],
            "app_users": {}, "app_groups": {}, "user_roles": {}, "group_roles": {}, "factors": {}}
    log("reading users...")
    snap["users"] = [slim_user(u) for u in client.list_users(status="")]
    log("reading groups and group rules...")
    snap["groups"] = [{"id": g["id"], "type": g.get("type"),
                       "profile": {"name": group_name(g)}} for g in client.list_groups()]
    snap["group_rules"] = [{"id": r.get("id"), "name": r.get("name"), "status": r.get("status"),
                            "actions": r.get("actions")}
                           for r in client.paged_get("/api/v1/groups/rules")]
    t_groups = {g["id"]: g for g in snap["groups"]}
    needed_groups = set()

    app_values = [e["value"] for e in policy_entries(policy) if e["type"] == "app"]
    app_values += [e["app"] for e in policy_entries(policy) if e["type"] == "app_group"]
    if app_values:
        log("reading apps and their assignments...")
        apps = [{"id": a["id"], "name": a.get("name"), "label": a.get("label"),
                 "status": a.get("status")} for a in client.list_apps()]
        snap["apps"] = apps
        for a in apps:
            if not any(app_matches(a, v) for v in app_values):
                continue
            snap["app_users"][a["id"]] = [{"id": x["id"], "scope": x.get("scope")}
                                          for x in client.list_app_users(a["id"])]
            gids = [x["id"] for x in client.paged_get(f"/api/v1/apps/{a['id']}/groups")]
            snap["app_groups"][a["id"]] = gids
            needed_groups.update(gids)

    for e in policy_entries(policy):
        if e["type"] in ("group", "app_group"):
            v = e["value"] if e["type"] == "group" else e["group"]
            needed_groups.update(g["id"] for g in snap["groups"] if group_matches(g, v))

    if wants(policy, "admin_role"):
        log("reading admin role assignments...")
        for uid in iam_assignee_ids(client):
            roles = [slim_role(r) for r in client.list_user_roles(uid)
                     if r.get("assignmentType", "USER") == "USER"]
            if roles:
                snap["user_roles"][uid] = roles
        for g in snap["groups"]:
            roles = [slim_role(r) for r in client.list_group_roles(g["id"])]
            if roles:
                snap["group_roles"][g["id"]] = roles
                needed_groups.add(g["id"])

    log(f"reading members of {len(needed_groups)} relevant groups...")
    for gid in sorted(needed_groups):
        g = t_groups.get(gid) or {}
        if g.get("type") == "BUILT_IN" and group_name(g) == "Everyone":
            continue  # everyone is a member; no need to page the whole directory
        snap["group_members"][gid] = [u["id"] for u in client.paged_get(f"/api/v1/groups/{gid}/users")]

    if wants(policy, "no_phishing_resistant_factor"):
        # Only users who already match every other side need their factors read.
        prelim = analyze(snap, policy)  # missing factors == no factors -> superset
        cands = sorted({f["user_id"] for f in prelim["findings"]} |
                       {u["id"] for u in snap["users"]
                        if any(x["user"] == user_login(u) for x in prelim["excepted"])})
        log(f"reading factors for {len(cands)} candidate users...")
        for uid in cands:
            snap["factors"][uid] = [{"factorType": f.get("factorType"), "provider": f.get("provider"),
                                     "status": f.get("status")} for f in client.list_factors(uid)]
    return snap


# ---------------------------------------------------------------- output

def cell(value, width):
    s = str(value)
    return s[:width].ljust(width)


def render_text(result, policy_path, n_rules) -> str:
    fs = result["findings"]
    out = ["Toxic access combinations (separation of duties) -- read-only",
           f"Policy: {policy_path} ({n_rules} rules) | users scanned: {result['users_scanned']} | "
           f"findings: {len(fs)} | excepted: {len(result['excepted'])}", ""]
    if not fs:
        out.append("No user holds a toxic combination defined in the policy.")
        return "\n".join(out) + "\n"
    out.append(f"{cell('#', 3)} {cell('RISK', 9)} {cell('SCORE', 5)} {cell('USER', 32)} "
               f"{cell('RULE', 40)} SMALLEST FIX")
    out.append("-" * 140)
    for f in fs:
        fix = f["smallest_fix"]
        first = fix["actions"][0] if fix["actions"] else ""
        more = f" (+{len(fix['actions']) - 1} more)" if len(fix["actions"]) > 1 else ""
        out.append(f"{cell(f['rank'], 3)} {cell(f['risk'], 9)} {cell(f['score'], 5)} "
                   f"{cell(f['user'], 32)} {cell(f['rule_id'] + ' ' + f['rule'], 40)} {first}{more}")
    out += ["", "Details", "-------"]
    for f in fs:
        out.append(f"[{f['rank']}] {f['risk']} (score {f['score']})  {f['user']} [{f['status']}]  "
                   f"{f['rule_id']}: {f['rule']}")
        for s in f["sides"]:
            out.append(f"    \"{s['label']}\":")
            for it in s["items"]:
                for p in it["paths"]:
                    out.append(f"      - {it['item']}: {p['how']}")
        fix = f["smallest_fix"]
        out.append(f"    Smallest fix (breaks \"{fix['side']}\", {len(fix['actions'])} change(s)):")
        for a in fix["actions"]:
            out.append(f"      * {a}")
        out.append(f"    In plain English: {f['explanation']}")
        out.append("")
    return "\n".join(out)


CSV_COLUMNS = ["rank", "risk", "score", "user", "status", "rule_id", "rule",
               "how_they_got_it", "smallest_fix", "fix_changes", "explanation"]


def csv_rows(result):
    for f in result["findings"]:
        how = " | ".join(f"{s['label']}: " + "; ".join(f"{it['item']} ({p['how']})"
                                                       for it in s["items"] for p in it["paths"])
                         for s in f["sides"])
        yield [str(f["rank"]), f["risk"], str(f["score"]), f["user"], f["status"], f["rule_id"],
               f["rule"], how, " ; ".join(f["smallest_fix"]["actions"]),
               str(len(f["smallest_fix"]["actions"])), f["explanation"]]


def render_csv(result) -> str:
    buf = io.StringIO()
    w = csv.writer(buf, quoting=csv.QUOTE_ALL, lineterminator="\n")
    w.writerow(CSV_COLUMNS)
    for row in csv_rows(result):
        w.writerow(row)
    return buf.getvalue()


def render_json(result, policy_path) -> str:
    return json.dumps({
        "policy": policy_path,
        "summary": {"users_scanned": result["users_scanned"],
                    "findings": len(result["findings"]),
                    "excepted": len(result["excepted"]),
                    "by_risk": {s.upper(): sum(1 for f in result["findings"] if f["risk"] == s.upper())
                                for s in reversed(SEVERITIES)}},
        "findings": result["findings"],
        "excepted": result["excepted"],
    }, indent=2)


def main(argv=None):
    p = argparse.ArgumentParser(
        description="Find users holding toxic access combinations (separation of duties). Read-only.")
    p.add_argument("--policy", required=True, help="JSON policy file (see examples/sod_policy.example.json)")
    p.add_argument("--snapshot", help="analyze a saved snapshot instead of calling Okta (offline)")
    p.add_argument("--save-snapshot", help="write the data pulled from Okta to this file")
    p.add_argument("--json", action="store_true", help="emit JSON instead of the text report")
    p.add_argument("--csv", help="also write findings as CSV to this file")
    p.add_argument("--output", help="write the report (text or JSON) to this file")
    p.add_argument("--fail-on", choices=["none"] + SEVERITIES, default="none",
                   help="exit 2 if any finding is at or above this risk (CI gate)")
    args = p.parse_args(argv)

    try:
        policy = load_policy(args.policy)
    except (OSError, PolicyError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 1

    if args.snapshot:
        with open(args.snapshot, encoding="utf-8") as f:
            snap = json.load(f)
    else:
        from lib.okta_client import OktaClient, OktaAuthError
        try:
            client = OktaClient()
            snap = collect(client, policy)
        except OktaAuthError as e:
            print(f"error: {e}", file=sys.stderr)
            return 1
    if args.save_snapshot:
        with open(args.save_snapshot, "w", encoding="utf-8") as f:
            json.dump(snap, f, indent=2)
        print(f"wrote snapshot {args.save_snapshot}", file=sys.stderr)

    result = analyze(snap, policy)
    policy_name = os.path.basename(args.policy)
    report = render_json(result, policy_name) if args.json else render_text(
        result, policy_name, len(policy["rules"]))
    if args.output:
        with open(args.output, "w", encoding="utf-8", newline="\n") as f:
            f.write(report if report.endswith("\n") else report + "\n")
        print(f"wrote {args.output}", file=sys.stderr)
    else:
        sys.stdout.write(report if report.endswith("\n") else report + "\n")
    if args.csv:
        with open(args.csv, "w", encoding="utf-8", newline="") as f:
            f.write(render_csv(result))
        print(f"wrote {args.csv}", file=sys.stderr)

    if args.fail_on != "none":
        floor = SEVERITIES.index(args.fail_on)
        if any(SEVERITIES.index(f["risk"].lower()) >= floor for f in result["findings"]):
            return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
