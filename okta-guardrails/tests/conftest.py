from pathlib import Path

import pytest

from okta_guardrails.blast import Population
from okta_guardrails.plan import Plan

FIX = Path(__file__).resolve().parent.parent / "fixtures"


@pytest.fixture
def risky():
    return Plan.load(FIX / "plan_risky.json")


@pytest.fixture
def clean():
    return Plan.load(FIX / "plan_clean.json")


@pytest.fixture(scope="session")
def population():
    path = FIX / "population.json"
    if not path.exists():  # generated, not committed: scripts/gen_population.py
        import subprocess, sys
        script = FIX.parent / "scripts" / "gen_population.py"
        path.write_text(subprocess.run([sys.executable, str(script)], check=True,
                                       capture_output=True, text=True).stdout)
    return Population.load(path)


def make_plan(changes, prior=(), configs=()):
    """Tiny plan builder for focused tests: changes are (address, actions, before, after)."""
    rc = []
    for addr, actions, before, after, *unknown in changes:
        typ, name = addr.split(".")[-2:]
        rc.append({"address": addr, "mode": "managed", "type": typ, "name": name,
                   "change": {"actions": actions, "before": before, "after": after,
                              "after_unknown": unknown[0] if unknown else {}}})
    res = []
    for addr, values in prior:
        typ, name = addr.split(".")[-2:]
        res.append({"address": addr, "mode": "managed", "type": typ, "name": name, "values": values})
    cfg = []
    for addr, expressions in configs:
        typ, name = addr.split(".")[-2:]
        cfg.append({"address": addr, "mode": "managed", "type": typ, "name": name, "expressions": expressions})
    return Plan({"format_version": "1.2", "resource_changes": rc,
                 "prior_state": {"values": {"root_module": {"resources": res}}},
                 "configuration": {"root_module": {"resources": cfg}}})
