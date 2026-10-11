import json
from pathlib import Path

from okta_guardrails.cli import main

FIX = Path(__file__).resolve().parent.parent / "fixtures"


def test_risky_exits_1(capsys, population):
    assert main(["check", "--plan", str(FIX / "plan_risky.json"), "--population", str(FIX / "population.json")]) == 1
    out = capsys.readouterr().out
    assert "blocked" in out and "Salesforce-Admin" in out


def test_clean_exits_0(population):
    assert main(["check", "--plan", str(FIX / "plan_clean.json"), "--population", str(FIX / "population.json")]) == 0


def test_fail_on_critical_and_skip(capsys):
    code = main(["check", "--plan", str(FIX / "plan_risky.json"), "--fail-on", "critical",
                 "--skip", "OG001", "--skip", "OG002", "--skip", "OG005", "--skip", "OG008", "--format", "json"])
    data = json.loads(capsys.readouterr().out)
    assert code == 0 and data["failed"] is False


def test_bad_plan_exits_2(tmp_path):
    p = tmp_path / "x.json"
    p.write_text("{}")
    assert main(["check", "--plan", str(p)]) == 2
