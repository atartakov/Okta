"""Export a real population file from an Okta tenant, read-only.

    OKTA_DOMAIN=https://dev-123456.okta.com OKTA_API_TOKEN=... \\
        okta-guardrails export-population --out population.json

The access-impact preview needs each user's profile and the groups they are
in *outside* group rules (it re-runs the rules itself). Okta's API does not
say why a user is in a group, so for every group an active rule targets, a
member the rule's expression matches is counted as rule-managed and left out;
anyone else in that group is kept as a direct member. Expressions the local
evaluator can't read keep every member and are listed in the warnings.

Only GET requests are made. The file holds real directory data: keep it out
of git (population*.json is ignored) and delete it when you are done.
"""
from __future__ import annotations

import json
import os
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from email.utils import parsedate_to_datetime
from typing import Any, Callable, Iterator

from .oel import Context, Expression, OELError

# Profile attributes group rules commonly read. Contact details (phones,
# street addresses) are left out unless asked for with --attribute.
DEFAULT_ATTRIBUTES = [
    "login", "email", "department", "title", "employeeType", "userType",
    "costCenter", "division", "organization", "countryCode", "city", "state",
    "managerId", "employeeNumber", "firstName", "lastName",
]
MAX_RETRY_WAIT = 60


def retry_wait_seconds(headers: Any, now: float | None = None) -> int:
    """Seconds to wait after a 429. x-rate-limit-reset is epoch seconds."""
    raw = headers.get("x-rate-limit-reset") if headers else None
    try:
        reset = int(float(raw))
    except (TypeError, ValueError):
        return 5
    if reset < 1_000_000_000:
        return max(1, min(reset, MAX_RETRY_WAIT)) + 1
    if now is None:
        now = time.time()
        date = headers.get("date")
        if date:
            try:
                now = parsedate_to_datetime(date).timestamp()
            except (TypeError, ValueError):
                pass
    return max(0, min(reset - int(now), MAX_RETRY_WAIT)) + 1


class OktaReader:
    """Minimal read-only Okta client (GET only, stdlib only)."""

    def __init__(self, domain: str, token: str, bearer: bool = False,
                 opener: Callable[..., Any] | None = None, sleep: Callable[[float], None] = time.sleep):
        domain = domain.rstrip("/")
        if not domain.startswith("http"):
            domain = "https://" + domain
        self.base = domain
        self.auth = ("Bearer " if bearer else "SSWS ") + token
        self.open = opener or urllib.request.urlopen
        self.sleep = sleep

    def _get(self, url: str) -> tuple[Any, Any]:
        for _ in range(5):
            req = urllib.request.Request(url, method="GET", headers={
                "Authorization": self.auth, "Accept": "application/json",
                "User-Agent": "okta-guardrails-export"})
            try:
                with self.open(req, timeout=30) as resp:
                    return json.loads(resp.read().decode("utf-8")), resp.headers
            except urllib.error.HTTPError as exc:
                if exc.code == 429:
                    self.sleep(retry_wait_seconds(exc.headers))
                    continue
                if exc.code in (401, 403):
                    raise PermissionError(f"Okta refused the token (HTTP {exc.code}) for {url}") from None
                raise
        raise RuntimeError("Okta rate limit persisted after retries")

    def paged(self, path: str, params: dict | None = None) -> Iterator[dict]:
        q = dict(params or {})
        q.setdefault("limit", 200)
        url: str | None = f"{self.base}{path}?{urllib.parse.urlencode(q)}"
        while url:
            body, headers = self._get(url)
            yield from body
            url = None
            for link in headers.get_all("link") or []:
                for part in link.split(","):
                    if 'rel="next"' in part:
                        url = part[part.index("<") + 1:part.index(">")]


def build_population(reader: OktaReader, attributes: list[str]) -> dict:
    users: dict[str, dict] = {}
    for u in reader.paged("/api/v1/users"):
        prof = u.get("profile", {})
        users[u["id"]] = {
            "id": u["id"], "login": prof.get("login", u["id"]), "status": u.get("status", "ACTIVE"),
            "profile": {k: prof[k] for k in attributes if prof.get(k) is not None},
            "groups": [],
        }

    groups = {g["id"]: g["profile"]["name"] for g in reader.paged("/api/v1/groups")}
    members: dict[str, list[str]] = {}
    for gid in groups:
        members[gid] = [m["id"] for m in reader.paged(f"/api/v1/groups/{gid}/users") if m["id"] in users]

    raw_groups: dict[str, set[str]] = {uid: set() for uid in users}
    for gid, uids in members.items():
        for uid in uids:
            raw_groups[uid].add(gid)

    warnings: list[str] = []
    rules = [r for r in reader.paged("/api/v1/groups/rules") if r.get("status") == "ACTIVE"]
    rule_managed: dict[str, set[str]] = {}
    for r in rules:
        src = (r.get("conditions", {}).get("expression") or {}).get("value", "")
        targets = r.get("actions", {}).get("assignUserToGroups", {}).get("groupIds", [])
        try:
            expr = Expression(src)
        except OELError as exc:
            warnings.append(f"rule '{r.get('name')}': could not read expression ({exc}); its members kept as direct")
            continue
        for gid in targets:
            for uid in members.get(gid, []):
                u = users[uid]
                # Judge the rule on the user's other groups, never the one
                # it fills, so a rule can't explain itself.
                other = raw_groups[uid] - set(targets)
                ctx = Context(profile={**u["profile"], "login": u["login"]},
                              group_names={groups[g] for g in other}, group_ids=other,
                              status=u["status"])
                try:
                    if expr.matches(ctx):
                        rule_managed.setdefault(gid, set()).add(uid)
                except OELError as exc:
                    warnings.append(f"rule '{r.get('name')}': {exc}; {u['login']} kept as direct member")

    for gid, uids in members.items():
        for uid in uids:
            if uid not in rule_managed.get(gid, set()):
                users[uid]["groups"].append(groups[gid])

    return {
        "_comment": "Exported read-only from an Okta tenant by okta-guardrails. Real directory data: keep out of git.",
        "source": reader.base,
        "exported_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "groups": groups,
        "rule_managed_memberships": sum(len(v) for v in rule_managed.values()),
        "active_rules": len(rules),
        "warnings": warnings,
        "users": sorted(users.values(), key=lambda u: u["login"]),
    }


def run(out: str, attributes: list[str], domain: str | None = None, token: str | None = None) -> int:
    domain = domain or os.environ.get("OKTA_DOMAIN", "")
    bearer = False
    token = token or os.environ.get("OKTA_API_TOKEN")
    if not token and os.environ.get("OKTA_ACCESS_TOKEN"):
        token, bearer = os.environ["OKTA_ACCESS_TOKEN"], True
    if not domain or not token:
        print("okta-guardrails: set OKTA_DOMAIN and OKTA_API_TOKEN (SSWS) or OKTA_ACCESS_TOKEN (OAuth)",
              file=sys.stderr)
        return 2
    try:
        pop = build_population(OktaReader(domain, token, bearer), attributes)
    except (PermissionError, urllib.error.URLError, RuntimeError) as exc:
        print(f"okta-guardrails: export failed: {exc}", file=sys.stderr)
        return 2
    with open(out, "w", encoding="utf-8") as fh:
        json.dump(pop, fh, indent=1, ensure_ascii=False)
    print(f"Exported {len(pop['users'])} users, {len(pop['groups'])} groups "
          f"({pop['active_rules']} active rules, {pop['rule_managed_memberships']} rule-made memberships set aside) "
          f"to {out}", file=sys.stderr)
    for w in pop["warnings"]:
        print(f"warning: {w}", file=sys.stderr)
    return 0
