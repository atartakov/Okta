import json
from pathlib import Path

from okta_guardrails.cli import main

FIX = Path(__file__).resolve().parent.parent / "fixtures"


def test_sarif_output(capsys):
    assert main(["check", "--plan", str(FIX / "plan_risky.json"), "--format", "sarif"]) == 1
    doc = json.loads(capsys.readouterr().out)
    assert doc["version"] == "2.1.0"
    run = doc["runs"][0]
    ids = {r["id"] for r in run["tool"]["driver"]["rules"]}
    assert run["results"] and {r["ruleId"] for r in run["results"]} == ids
    for r in run["results"]:
        assert r["level"] in {"error", "warning", "note"}
        assert r["locations"][0]["physicalLocation"]["region"]["startLine"] >= 1


def test_sarif_points_at_resource_block(tmp_path):
    (tmp_path / "main.tf").write_text('# x\n\nresource "okta_app_oauth" "risky" {\n}\n')
    plan = {"format_version": "1.2", "resource_changes": [{
        "address": "okta_app_oauth.risky", "mode": "managed", "type": "okta_app_oauth", "name": "risky",
        "change": {"actions": ["create"], "before": None,
                   "after": {"label": "r", "grant_types": ["implicit"], "redirect_uris": ["https://a.example.com/cb"]},
                   "after_unknown": {}}}]}
    (tmp_path / "plan.json").write_text(json.dumps(plan))
    out = tmp_path / "out.sarif"
    main(["check", "--plan", str(tmp_path / "plan.json"), "--sarif", str(out), "--output", str(tmp_path / "r.md")])
    res = json.loads(out.read_text())["runs"][0]["results"]
    assert res and all(r["locations"][0]["physicalLocation"]["artifactLocation"]["uri"].endswith("main.tf") for r in res)
    assert res[0]["locations"][0]["physicalLocation"]["region"]["startLine"] == 3
