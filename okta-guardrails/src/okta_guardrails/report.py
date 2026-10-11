from __future__ import annotations

import json
from collections import Counter

from .blast import BlastResult
from .findings import Finding, SEVERITIES, sev_rank

ICON = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🔵", "info": "⚪"}


def _sorted(findings: list[Finding]) -> list[Finding]:
    return sorted(findings, key=lambda f: (-sev_rank(f.severity), f.rule_id, f.address))


def _sample(users: list[dict], n: int = 5) -> str:
    names = [u.get("login", u["id"]) for u in users[:n]]
    more = len(users) - len(names)
    return ", ".join(names) + (f" and {more} more" if more > 0 else "")


def markdown(findings: list[Finding], blast: BlastResult | None, failed: bool, fail_on: str) -> str:
    counts = Counter(f.severity for f in findings)
    summary = ", ".join(f"{counts[s]} {s}" for s in reversed(SEVERITIES) if counts[s]) or "no findings"
    status = "❌ blocked" if failed else "✅ passed"
    lines = [f"## okta-guardrails: {status}", "", f"{summary} (fails on {fail_on} and above)", ""]

    if blast is not None and blast.impacts:
        lines += ["### Who gains and loses access", "",
                  "| Group | Apps | Admin role | Before | After | Gains | Loses |",
                  "|---|---|---|---:|---:|---:|---:|"]
        for imp in blast.impacts:
            lines.append(f"| {imp.group} | {', '.join(imp.apps) or '-'} | {', '.join(imp.admin_roles) or '-'} "
                         f"| {imp.before} | {imp.after} | +{len(imp.gained)} | -{len(imp.lost)} |")
        lines.append("")
        for imp in blast.impacts:
            if imp.gained or imp.lost or imp.retained:
                lines.append(f"<details><summary>{imp.group}: sample users</summary>\n")
                if imp.gained:
                    lines.append(f"- **Gain:** {_sample(imp.gained)}")
                if imp.lost:
                    lines.append(f"- **Lose:** {_sample(imp.lost)}")
                if imp.retained:
                    lines.append(f"- **Kept after rule removed:** {_sample(imp.retained)}")
                lines.append(f"- Rules: {', '.join(f'`{r}`' for r in imp.rules)}")
                lines.append("\n</details>\n")
        lines.append(f"_Computed locally against {blast.population_size} users with an approximation of "
                     "Okta Expression Language. Okta's own engine is the source of truth._")
        lines.append("")

    if findings:
        lines += ["### Findings", "", "| | Check | Resource | Finding |", "|---|---|---|---|"]
        for f in _sorted(findings):
            lines.append(f"| {ICON[f.severity]} {f.severity} | {f.rule_id} | `{f.address}` | {f.title} |")
        lines.append("")
        lines.append("<details><summary>Why and how to fix</summary>\n")
        for f in _sorted(findings):
            lines.append(f"**{f.rule_id} · {f.title}**  \n{f.detail}  \n_Fix:_ {f.recommendation}\n")
        lines.append("</details>")
    return "\n".join(lines) + "\n"


def as_json(findings: list[Finding], blast: BlastResult | None, failed: bool) -> str:
    return json.dumps({
        "failed": failed,
        "findings": [f.to_dict() for f in _sorted(findings)],
        "access_impact": [i.to_dict() for i in blast.impacts] if blast else [],
        "unevaluated": [{"address": a, "reason": r} for a, r in blast.unevaluated] if blast else [],
    }, indent=2)
