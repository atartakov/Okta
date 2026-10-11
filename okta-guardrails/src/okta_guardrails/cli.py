"""okta-guardrails command line.

    okta-guardrails check --plan plan.json [--population users.json]
    okta-guardrails rules

Exit codes: 0 passed, 1 findings at or above --fail-on, 2 usage or input error.
"""
from __future__ import annotations

import argparse
import sys

from . import __version__
from .blast import Population, analyze
from .findings import SEVERITIES, sev_rank
from .plan import Plan
from .report import as_json, markdown
from .rules import RULES, run_rules


def _check(args: argparse.Namespace) -> int:
    try:
        plan = Plan.load(args.plan)
    except (OSError, ValueError) as exc:
        print(f"okta-guardrails: cannot read plan: {exc}", file=sys.stderr)
        return 2
    skip = set(args.skip or [])
    findings = [f for f in run_rules(plan) if f.rule_id not in skip]

    blast = None
    if args.population:
        try:
            pop = Population.load(args.population)
        except (OSError, ValueError, KeyError) as exc:
            print(f"okta-guardrails: cannot read population: {exc}", file=sys.stderr)
            return 2
        blast = analyze(plan, pop, max_change=args.max_change)
        findings += [f for f in blast.findings if f.rule_id not in skip]

    failed = any(sev_rank(f.severity) >= sev_rank(args.fail_on) for f in findings)
    out = as_json(findings, blast, failed) if args.format == "json" else markdown(findings, blast, failed, args.fail_on)
    if args.output:
        with open(args.output, "w", encoding="utf-8") as fh:
            fh.write(out)
    else:
        sys.stdout.write(out)
    return 1 if failed else 0


def _rules(_: argparse.Namespace) -> int:
    for rule_id, summary, _fn in RULES:
        print(f"{rule_id}  {summary}")
    for rule_id, summary in (("BR001", "Users become admins through a rule change"),
                             ("BR002", "Membership change larger than --max-change"),
                             ("BR003", "Access impact could not be computed"),
                             ("BR004", "Users keep a group after its rule is removed")):
        print(f"{rule_id}  {summary}")
    return 0


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="okta-guardrails", description=__doc__.split("\n")[0])
    p.add_argument("--version", action="version", version=__version__)
    sub = p.add_subparsers(dest="cmd", required=True)

    c = sub.add_parser("check", help="check a Terraform JSON plan")
    c.add_argument("--plan", required=True, help="output of `terraform show -json plan.bin`")
    c.add_argument("--population", help="users file for the access-impact preview")
    c.add_argument("--fail-on", choices=SEVERITIES, default="high")
    c.add_argument("--max-change", type=int, default=50, help="largest membership change one PR may make")
    c.add_argument("--skip", action="append", metavar="RULE_ID", help="skip a check (repeatable)")
    c.add_argument("--format", choices=["markdown", "json"], default="markdown")
    c.add_argument("--output", help="write the report here instead of stdout")
    c.set_defaults(fn=_check)

    r = sub.add_parser("rules", help="list the checks")
    r.set_defaults(fn=_rules)

    args = p.parse_args(argv)
    return args.fn(args)


if __name__ == "__main__":
    raise SystemExit(main())
