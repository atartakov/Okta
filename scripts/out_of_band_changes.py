#!/usr/bin/env python3
"""Out-of-band change reporter: who changed Okta outside of code.

If your tenant is managed as code (Terraform, scripts, a CI pipeline), every
legitimate change is made by a known automation identity. This script reads
the System Log for configuration changes in a time window and sorts each one:

    via code     made by an --automation-actor (your Terraform service app,
                 your pipeline's API token user, ...)
    automatic    made by Okta itself (group rules, the system principal)
    manual       anything else: an admin clicked it in the Admin Console or
                 ran an ad-hoc API call. This is the out-of-band list.

Manual changes are ranked by risk (admin grants, policy, network zone and
API token changes are HIGH), grouped by who made them, and can be joined to
a tenant_drift_detector.py diff to answer "who caused this drift?".

Read-only. Needs a token that can read the System Log.

Usage:
    export OKTA_DOMAIN=https://dev-123456.okta.com
    export OKTA_API_TOKEN=00...
    python scripts/out_of_band_changes.py --since 24h --automation-actor 0oa1terraformapp
    python scripts/out_of_band_changes.py --since 7d --automation-actor svc-terraform@example.com \\
        --drift drift.json --markdown --output report.md
    python scripts/out_of_band_changes.py --since 24h --fail-on high      # nightly CI
    python scripts/out_of_band_changes.py --input events.json             # offline, saved events

Exit codes: 0 = nothing at or above --fail-on, 2 = manual changes at or above
--fail-on, 1 = error.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from collections import defaultdict
from datetime import datetime, timedelta, timezone

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

# Event types that mean "someone changed configuration or access".
# Names checked against Okta's event type catalog (okta-event-types.csv).
HIGH_EVENTS = {
    "user.account.privilege.grant", "user.account.privilege.revoke",
    "group.privilege.grant", "group.privilege.revoke",
    "app.oauth2.client.privilege.grant", "app.oauth2.client.privilege.revoke",
    "iam.role.create", "iam.role.permissions.add",
    "iam.resourceset.bindings.add",
    "policy.lifecycle.create", "policy.lifecycle.update",
    "policy.lifecycle.delete", "policy.lifecycle.activate",
    "policy.lifecycle.deactivate",
    "policy.rule.add", "policy.rule.update", "policy.rule.delete",
    "policy.rule.activate", "policy.rule.deactivate",
    "zone.create", "zone.update", "zone.delete", "zone.activate",
    "zone.deactivate", "zone.make_blacklist", "zone.remove_blacklist",
    "system.api_token.create", "system.api_token.revoke",
}
MEDIUM_EVENTS = {
    "group.lifecycle.create", "group.lifecycle.delete", "group.profile.update",
    "group.application_assignment.add", "group.application_assignment.remove",
    "group.application_assignment.update",
    "application.lifecycle.create", "application.lifecycle.update",
    "application.lifecycle.delete", "application.lifecycle.activate",
    "application.lifecycle.deactivate",
}
LOW_EVENTS = {
    "group.user_membership.add", "group.user_membership.remove",
    "application.user_membership.add", "application.user_membership.remove",
}
ALL_EVENTS = HIGH_EVENTS | MEDIUM_EVENTS | LOW_EVENTS

# Server-side prefilter (System Log supports `sw`); exact set applied after.
PREFIXES = ["user.account.privilege", "group.", "app.oauth2.client.privilege",
            "iam.", "policy.lifecycle", "policy.rule", "zone.",
            "system.api_token", "application.lifecycle",
            "application.user_membership"]

RANK = {"low": 0, "medium": 1, "high": 2}
DEFAULT_SENSITIVE = r"admin|super|privileged|break.?glass|security"


# ---------------------------------------------------------------- parsing

def parse_since(value: str, now: datetime | None = None) -> str:
    """'24h', '7d', '90m' or an ISO8601 timestamp -> ISO8601 UTC string."""
    now = now or datetime.now(timezone.utc)
    m = re.fullmatch(r"(\d+)([mhd])", value.strip())
    if m:
        n, unit = int(m.group(1)), m.group(2)
        delta = {"m": timedelta(minutes=n), "h": timedelta(hours=n),
                 "d": timedelta(days=n)}[unit]
        return (now - delta).strftime("%Y-%m-%dT%H:%M:%S.000Z")
    datetime.fromisoformat(value.replace("Z", "+00:00"))  # validate
    return value


def build_filter() -> str:
    return " or ".join(f'eventType sw "{p}"' for p in PREFIXES)


def actor_keys(actor: dict) -> set:
    return {str(actor.get(k)).lower() for k in ("id", "alternateId", "displayName")
            if actor.get(k)}


def _debug(event: dict) -> dict:
    return ((event.get("debugContext") or {}).get("debugData") or {})


def classify(event: dict, automation: set) -> str:
    """Return 'via code', 'automatic', or 'manual'."""
    actor = event.get("actor") or {}
    if actor_keys(actor) & automation:
        return "via code"
    if _debug(event).get("triggeredByGroupRuleId"):
        return "automatic"
    if actor.get("type") == "SystemPrincipal" or \
            str(actor.get("alternateId", "")).lower() in ("system@okta.com",):
        return "automatic"
    return "manual"


def severity(event: dict, sensitive: re.Pattern) -> str:
    etype = event.get("eventType", "")
    if etype in HIGH_EVENTS:
        return "high"
    if etype in LOW_EVENTS:
        # Membership in an admin-ish group is privilege escalation by indirection.
        for t in event.get("targets") or []:
            if t.get("type") in ("UserGroup", "AppInstance") and \
                    sensitive.search(str(t.get("displayName", ""))):
                return "high"
        return "low"
    return "medium"


def describe(event: dict) -> dict:
    targets = event.get("targets") or []
    return {
        "time": event.get("published"),
        "event_type": event.get("eventType"),
        "summary": event.get("displayMessage") or event.get("eventType"),
        "targets": [f"{t.get('type')}: {t.get('displayName') or t.get('alternateId') or t.get('id')}"
                    for t in targets],
        "target_ids": [t.get("id") for t in targets if t.get("id")],
        "ip": ((event.get("client") or {}).get("ipAddress")),
        "outcome": ((event.get("outcome") or {}).get("result")),
        "uuid": event.get("uuid"),
    }


def analyze(events: list, automation: set, sensitive: re.Pattern,
            include_failures: bool = False) -> dict:
    counts = {"via code": 0, "automatic": 0, "manual": 0}
    manual = []
    for ev in events:
        if ev.get("eventType") not in ALL_EVENTS:
            continue
        if not include_failures and \
                ((ev.get("outcome") or {}).get("result") or "SUCCESS") != "SUCCESS":
            continue
        kind = classify(ev, automation)
        counts[kind] += 1
        if kind != "manual":
            continue
        actor = ev.get("actor") or {}
        row = describe(ev)
        row["actor"] = actor.get("alternateId") or actor.get("displayName") or actor.get("id")
        row["actor_type"] = actor.get("type")
        row["severity"] = severity(ev, sensitive)
        manual.append(row)
    manual.sort(key=lambda r: (-RANK[r["severity"]], r["time"] or ""))
    by_actor = defaultdict(list)
    for r in manual:
        by_actor[r["actor"]].append(r)
    return {"counts": counts, "manual": manual,
            "by_actor": {a: rows for a, rows in sorted(
                by_actor.items(), key=lambda kv: -max(RANK[r["severity"]] for r in kv[1]))}}


# ------------------------------------------------- drift join (optional)

def drift_keys(diff: dict) -> list:
    """Flatten a tenant_drift_detector.py --json diff to (label, resource id)."""
    out = []
    for group, sect in (diff or {}).items():
        for verb, items in (("added", sect.get("added", [])),
                            ("removed", sect.get("removed", [])),
                            ("changed", sect.get("changed", []))):
            for item in items:
                res = item.get("resource", item) if verb == "changed" else item
                key = item.get("key") if verb == "changed" else (
                    res.get("id") or f"{res.get('user_id')}::{res.get('role_type')}")
                name = res.get("name") or res.get("label") or res.get("login") or key
                rid = str(key).split("::")[0]
                out.append({"group": group, "verb": verb, "name": name, "id": rid})
    return out


def attribute_drift(diff: dict, events: list) -> list:
    by_target = defaultdict(list)
    for ev in events:
        if ev.get("eventType") not in ALL_EVENTS:
            continue
        actor = ev.get("actor") or {}
        who = actor.get("alternateId") or actor.get("displayName") or actor.get("id")
        for t in ev.get("targets") or []:
            if t.get("id"):
                by_target[t["id"]].append((ev.get("published"), who, ev.get("eventType")))
    rows = []
    for d in drift_keys(diff):
        hits = sorted(by_target.get(d["id"], []))
        if hits:
            when, who, etype = hits[-1]
            d.update({"changed_by": who, "when": when, "event_type": etype,
                      "other_actors": sorted({h[1] for h in hits[:-1]} - {who})})
        else:
            d.update({"changed_by": None, "when": None, "event_type": None,
                      "other_actors": []})
        rows.append(d)
    return rows


# ---------------------------------------------------------------- output

def render_text(result: dict, drift_rows: list | None, window: str) -> str:
    c = result["counts"]
    lines = [f"Okta changes {window}",
             f"  via code: {c['via code']}   automatic: {c['automatic']}   "
             f"manual (out of band): {c['manual']}", ""]
    if not result["manual"]:
        lines.append("No out-of-band changes.")
    for actor, rows in result["by_actor"].items():
        lines.append(f"== {actor} ({len(rows)} change{'s' if len(rows) != 1 else ''})")
        for r in rows:
            tgt = "; ".join(r["targets"][:3])
            lines.append(f"  [{r['severity'].upper():6}] {r['time']}  {r['summary']}"
                         f"{'  -> ' + tgt if tgt else ''}  (ip {r['ip'] or '?'})")
        lines.append("")
    if drift_rows is not None:
        lines.append("== Drift attribution")
        for d in drift_rows:
            who = d["changed_by"] or "no matching System Log event in window"
            lines.append(f"  {d['verb']:7} {d['group']}: {d['name']}  <- {who}"
                         f"{'  at ' + d['when'] if d['when'] else ''}")
    return "\n".join(lines).rstrip() + "\n"


def render_markdown(result: dict, drift_rows: list | None, window: str) -> str:
    c = result["counts"]
    md = [f"## Okta changes made outside code ({window})", "",
          f"**{c['manual']} manual** · {c['via code']} via code · "
          f"{c['automatic']} automatic", ""]
    if result["manual"]:
        md += ["| Severity | When (UTC) | Who | What | Target |",
               "|---|---|---|---|---|"]
        for r in result["manual"]:
            md.append(f"| {r['severity'].upper()} | {r['time']} | {r['actor']} | "
                      f"{r['summary']} | {'; '.join(r['targets'][:2])} |")
    else:
        md.append("No out-of-band changes.")
    if drift_rows is not None:
        md += ["", "### Drift attribution", "",
               "| Change | Resource | Changed by | When |", "|---|---|---|---|"]
        for d in drift_rows:
            md.append(f"| {d['verb']} {d['group']} | {d['name']} | "
                      f"{d['changed_by'] or '_not found in window_'} | {d['when'] or ''} |")
    return "\n".join(md) + "\n"


# ---------------------------------------------------------------- main

def fetch_events(since: str, until: str | None) -> list:
    from lib.okta_client import OktaClient
    client = OktaClient()
    params = {"filter": build_filter(), "since": since, "sortOrder": "ASCENDING"}
    if until:
        params["until"] = until
    return list(client.paged_get("/api/v1/logs", params))


def main(argv: list | None = None) -> int:
    p = argparse.ArgumentParser(
        description="Report Okta configuration and access changes made outside "
                    "your automation (Admin Console clicks, ad-hoc API calls).")
    p.add_argument("--since", default="24h",
                   help="window start: 90m, 24h, 7d, or ISO8601 (default 24h)")
    p.add_argument("--until", default=None, help="window end, ISO8601 (default now)")
    p.add_argument("--automation-actor", action="append", default=[],
                   metavar="ID_OR_LOGIN",
                   help="actor id, login, or name that makes changes via code; repeatable")
    p.add_argument("--sensitive-groups", default=DEFAULT_SENSITIVE, metavar="REGEX",
                   help="group/app names whose membership changes count as HIGH "
                        f"(default: {DEFAULT_SENSITIVE!r})")
    p.add_argument("--drift", metavar="DIFF_JSON",
                   help="tenant_drift_detector.py --diff ... --json output to attribute")
    p.add_argument("--input", metavar="EVENTS_JSON",
                   help="read System Log events from a file instead of the API")
    p.add_argument("--include-failures", action="store_true",
                   help="also report changes whose outcome was not SUCCESS")
    p.add_argument("--fail-on", choices=["none", "low", "medium", "high"], default="none",
                   help="exit 2 if a manual change at or above this severity is found")
    fmt = p.add_mutually_exclusive_group()
    fmt.add_argument("--json", action="store_true", help="emit JSON")
    fmt.add_argument("--markdown", action="store_true",
                     help="emit Markdown (GitHub issue / step summary)")
    p.add_argument("--output", help="write the report to this file")
    args = p.parse_args(argv)

    try:
        since = parse_since(args.since)
    except ValueError:
        p.error(f"--since: can't read {args.since!r}")
    window = f"since {since}" + (f" until {args.until}" if args.until else "")

    try:
        if args.input:
            with open(args.input, encoding="utf-8") as f:
                events = json.load(f)
            window = f"from {os.path.basename(args.input)}"
        else:
            events = fetch_events(since, args.until)
    except Exception as e:  # auth errors, network, bad file
        print(f"error: {e}", file=sys.stderr)
        return 1

    automation = {a.lower() for a in args.automation_actor}
    if not automation:
        print("warning: no --automation-actor given, so every change counts as manual",
              file=sys.stderr)
    result = analyze(events, automation, re.compile(args.sensitive_groups, re.I),
                     args.include_failures)

    drift_rows = None
    if args.drift:
        with open(args.drift, encoding="utf-8") as f:
            drift_rows = attribute_drift(json.load(f), events)

    if args.json:
        report = json.dumps({"window": window, **result,
                             "drift_attribution": drift_rows}, indent=2, default=str)
    elif args.markdown:
        report = render_markdown(result, drift_rows, window)
    else:
        report = render_text(result, drift_rows, window)

    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            f.write(report)
        print(f"wrote {args.output}", file=sys.stderr)
    else:
        sys.stdout.write(report if report.endswith("\n") else report + "\n")

    if args.fail_on != "none" and any(
            RANK[r["severity"]] >= RANK[args.fail_on] for r in result["manual"]):
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
