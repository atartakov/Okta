"""Blast radius: who gains and who loses group membership (and the apps behind
it) if this plan is applied.

Group membership is rebuilt for every group a changed rule touches, before and
after, from three sources: direct (non-rule) memberships in the population
file, every *other* active rule targeting the group, and the changed rule
itself. That is what makes the diff honest when two rules feed one group.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .findings import Finding
from .oel import Context, Expression, OELError, UnsupportedExpression
from .plan import Plan
from .rules import PRIVILEGED_ROLES, admin_groups


@dataclass
class Population:
    users: list[dict[str, Any]]
    group_ids: dict[str, str] = field(default_factory=dict)  # id -> name

    @classmethod
    def load(cls, path: str | Path) -> "Population":
        with open(path, encoding="utf-8") as fh:
            data = json.load(fh)
        return cls(users=data["users"], group_ids=data.get("groups", {}))

    def contexts(self) -> list[tuple[dict, Context]]:
        name_to_id = {v: k for k, v in self.group_ids.items()}
        out = []
        for u in self.users:
            names = set(u.get("groups", []))
            out.append((u, Context(profile=u.get("profile", {}), group_names=names,
                                   group_ids={name_to_id[n] for n in names if n in name_to_id},
                                   status=u.get("status", "ACTIVE"))))
        return out

    def direct_members(self, group: str) -> set[str]:
        return {u["id"] for u in self.users if group in u.get("groups", [])}


@dataclass
class GroupImpact:
    group: str
    rules: list[str]
    apps: list[str]
    admin_roles: list[str]
    before: int
    after: int
    gained: list[dict] = field(default_factory=list)
    lost: list[dict] = field(default_factory=list)
    retained: list[dict] = field(default_factory=list)

    def to_dict(self) -> dict:
        def logins(us):
            return [u.get("login", u["id"]) for u in us]
        return {"group": self.group, "rules": self.rules, "apps": self.apps,
                "admin_roles": self.admin_roles, "members_before": self.before,
                "members_after": self.after, "gained": logins(self.gained),
                "lost": logins(self.lost), "kept_after_rule_removed": logins(self.retained)}


@dataclass
class BlastResult:
    impacts: list[GroupImpact]
    findings: list[Finding]
    unevaluated: list[tuple[str, str]]
    population_size: int


class _Evaluator:
    def __init__(self, pop: Population):
        self.ctxs = pop.contexts()
        self.cache: dict[str, set[str]] = {}

    def matches(self, src: str, excluded: list[str] | None) -> set[str]:
        if src not in self.cache:
            expr = Expression(src)
            self.cache[src] = {u["id"] for u, ctx in self.ctxs if expr.matches(ctx)}
        return self.cache[src] - set(excluded or [])


def _active(vals: dict | None) -> bool:
    return bool(vals) and (vals.get("status") or "ACTIVE") == "ACTIVE"


def apps_by_group(plan: Plan) -> dict[str, list[str]]:
    out: dict[str, list[str]] = {}
    for addr, vals in plan.resources_after("okta_app_group_assignment"):
        apps = plan.resolve(addr, "app_id", [vals.get("app_id")], "label")
        for g in plan.resolve(addr, "group_id", [vals.get("group_id")], "name"):
            out.setdefault(g, [])
            out[g].extend(a for a in apps if a not in out[g])
    for addr, vals in plan.resources_after("okta_app_group_assignments"):
        apps = plan.resolve(addr, "app_id", [vals.get("app_id")], "label")
        ids = [blk.get("id") for blk in vals.get("group", []) or [] if isinstance(blk, dict)]
        for g in plan.resolve(addr, "group", ids, "name", side="before"):
            out.setdefault(g, [])
            out[g].extend(a for a in apps if a not in out[g])
    return out


def analyze(plan: Plan, pop: Population, max_change: int = 50) -> BlastResult:
    ev = _Evaluator(pop)
    by_id = {u["id"]: u for u in pop.users}
    unevaluated: list[tuple[str, str]] = []
    findings: list[Finding] = []

    changed = [c for c in plan.changes_of("okta_group_rule")
               if c.before_get("expression_value") != c.after_get("expression_value")
               or c.before_get("group_assignments") != c.after_get("group_assignments")
               or c.before_get("status") != c.after_get("status")
               or c.before_get("users_excluded") != c.after_get("users_excluded")
               or c.is_delete or c.is_create]
    if not changed:
        return BlastResult([], [], [], len(pop.users))

    def contributions(side: str) -> dict[str, dict[str, set[str]]]:
        """group -> {rule address -> matched user ids} for one side of the plan."""
        rules = plan.resources_before("okta_group_rule") if side == "before" \
            else plan.resources_after("okta_group_rule")
        out: dict[str, dict[str, set[str]]] = {}
        for addr, vals in rules:
            if not _active(vals):
                continue
            src = vals.get("expression_value")
            if not src:
                continue
            try:
                matched = ev.matches(src, vals.get("users_excluded"))
            except UnsupportedExpression as exc:
                unevaluated.append((addr, str(exc)))
                continue
            except OELError as exc:
                unevaluated.append((addr, f"could not parse: {exc}"))
                continue
            for g in plan.resolve(addr, "group_assignments", vals.get("group_assignments"), "name", side=side):
                out.setdefault(g, {})[addr] = matched
        return out

    before = contributions("before")
    after = contributions("after")

    # Rules that are deleted or deactivated without removing users leave their
    # members in place as plain group members.
    retained: dict[str, set[str]] = {}
    for ch in changed:
        stops = ch.is_delete or (_active(ch.before) and not _active(ch.after))
        removes = (ch.before or {}).get("remove_assigned_users") is True
        if stops and not removes:
            for g, by_rule in before.items():
                if ch.address in by_rule:
                    retained.setdefault(g, set()).update(by_rule[ch.address])

    touched: list[str] = []
    for ch in changed:
        for side, vals in (("before", ch.before), ("after", ch.after)):
            if vals:
                for g in plan.resolve(ch.address, "group_assignments", vals.get("group_assignments"), "name", side=side):
                    if g not in touched:
                        touched.append(g)

    apps = apps_by_group(plan)
    admins = admin_groups(plan, "after")
    impacts: list[GroupImpact] = []
    for g in touched:
        direct = pop.direct_members(g)
        b = direct.union(*before.get(g, {}).values())
        keep = retained.get(g, set())
        a = direct.union(keep, *after.get(g, {}).values())
        gained = sorted(a - b)
        lost = sorted(b - a)
        kept_only = sorted(keep - direct.union(*after.get(g, {}).values()))
        rules = sorted({ch.address for ch in changed
                        if g in plan.resolve(ch.address, "group_assignments", ch.after_get("group_assignments"), "name")
                        or g in plan.resolve(ch.address, "group_assignments", ch.before_get("group_assignments"),
                                             "name", side="before")})
        imp = GroupImpact(group=g, rules=rules, apps=apps.get(g, []), admin_roles=sorted(admins.get(g, set())),
                          before=len(b), after=len(a),
                          gained=[by_id[i] for i in gained], lost=[by_id[i] for i in lost],
                          retained=[by_id[i] for i in kept_only])
        impacts.append(imp)

        where = ", ".join(rules)
        if imp.gained and imp.admin_roles:
            sev = "critical" if set(imp.admin_roles) & set(PRIVILEGED_ROLES) else "high"
            findings.append(Finding("BR001", sev, where,
                                    f"{len(imp.gained)} users become admins via {g}",
                                    f"{g} holds {', '.join(imp.admin_roles)}.",
                                    "Review every new member before merging; admin groups should not be rule-fed."))
        if len(imp.gained) > max_change or len(imp.lost) > max_change:
            target = f" ({', '.join(imp.apps)})" if imp.apps else ""
            findings.append(Finding("BR002", "high", where,
                                    f"{g}{target}: +{len(imp.gained)} / -{len(imp.lost)} members",
                                    f"Membership goes from {imp.before} to {imp.after}; the limit for one PR is {max_change}.",
                                    "Confirm the expression with the owning team, or roll it out in stages."))
        if imp.retained:
            findings.append(Finding("BR004", "medium", where,
                                    f"{len(imp.retained)} users keep {g} after its rule stops",
                                    "Without remove_assigned_users = true these memberships stay behind as "
                                    "direct assignments that nothing maintains.",
                                    "Set remove_assigned_users = true, or plan an access review for these users."))

    for addr, why in unevaluated:
        if any(addr == ch.address for ch in changed):
            findings.append(Finding("BR003", "low", addr, "Access impact not computed", why,
                                    "Check this rule's impact by hand, or extend the evaluator."))

    return BlastResult(impacts, findings, unevaluated, len(pop.users))
