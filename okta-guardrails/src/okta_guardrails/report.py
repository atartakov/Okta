from __future__ import annotations

import json
import re
from collections import Counter
from pathlib import Path

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


SARIF_LEVEL = {"critical": "error", "high": "error", "medium": "warning", "low": "note", "info": "note"}
SECURITY_SEVERITY = {"critical": "9.5", "high": "8.0", "medium": "5.5", "low": "3.0", "info": "1.0"}


def _rel(path: Path) -> str:
    """Repo-relative URI when the file is under the working directory."""
    try:
        return path.resolve().relative_to(Path.cwd().resolve()).as_posix()
    except ValueError:
        return path.resolve().as_posix()


def _locate(address: str, source_dir: Path | None) -> tuple[str, int] | None:
    """Find `resource "type" "name"` for a plan address in the .tf files."""
    if source_dir is None or not source_dir.is_dir():
        return None
    parts = re.sub(r"\[[^\]]*\]", "", address).split(".")
    if len(parts) < 2 or parts[-3:-2] == ["data"]:
        return None
    typ, name = parts[-2], parts[-1]
    pat = re.compile(r'^\s*resource\s+"%s"\s+"%s"' % (re.escape(typ), re.escape(name)))
    for tf in sorted(source_dir.rglob("*.tf")):
        if ".terraform" in tf.parts:
            continue
        for n, line in enumerate(tf.read_text(encoding="utf-8", errors="replace").splitlines(), 1):
            if pat.match(line):
                return _rel(tf), n
    return None


def sarif(findings: list[Finding], rule_summaries: dict[str, str], plan_path: str,
          source_dir: str | None = None, version: str = "0") -> str:
    """SARIF 2.1.0 for GitHub code scanning. Each finding points at the
    resource block in the .tf files when it can be found, else at the plan."""
    src = Path(source_dir) if source_dir else None
    used = sorted({f.rule_id for f in findings})
    rules = [{"id": r, "name": r, "shortDescription": {"text": rule_summaries.get(r, r)},
              "helpUri": "https://github.com/dorkagent/Okta/tree/main/okta-guardrails#checks"} for r in used]
    results = []
    for f in _sorted(findings):
        loc = _locate(f.address, src)
        uri, line = loc if loc else (_rel(Path(plan_path)), 1)
        results.append({
            "ruleId": f.rule_id,
            "level": SARIF_LEVEL[f.severity],
            "message": {"text": f"{f.title}. {f.detail} Fix: {f.recommendation}"},
            "locations": [{"physicalLocation": {"artifactLocation": {"uri": uri},
                                                "region": {"startLine": line}}}],
            "partialFingerprints": {"oktaGuardrails/v1": f"{f.rule_id}:{f.address}:{f.title}"},
            "properties": {"security-severity": SECURITY_SEVERITY[f.severity], "resource": f.address},
        })
    return json.dumps({
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{"tool": {"driver": {"name": "okta-guardrails", "version": version,
                                      "informationUri": "https://github.com/dorkagent/Okta/tree/main/okta-guardrails",
                                      "rules": rules}},
                  "results": results}],
    }, indent=2) + "\n"
