"""Tests for scripts/out_of_band_changes.py (offline: saved System Log events)."""
import json
import os
import re
import sys
from datetime import datetime, timezone

HERE = os.path.dirname(__file__)
sys.path.insert(0, os.path.join(HERE, "..", "scripts"))

import out_of_band_changes as oob  # noqa: E402

EVENTS = os.path.join(HERE, "fixtures", "system_log_changes.json")
DRIFT = os.path.join(HERE, "fixtures", "drift_diff.json")
SENS = re.compile(oob.DEFAULT_SENSITIVE, re.I)


def load():
    with open(EVENTS, encoding="utf-8") as f:
        return json.load(f)


def test_sorts_code_automatic_manual():
    r = oob.analyze(load(), {"0oaterraform01"}, SENS)
    assert r["counts"] == {"via code": 1, "automatic": 1, "manual": 4}


def test_failures_and_non_change_events_skipped():
    r = oob.analyze(load(), {"0oaterraform01"}, SENS)
    types = {m["event_type"] for m in r["manual"]}
    assert "user.account.privilege.grant" not in types   # FAILURE
    assert "user.session.start" not in types             # not a change
    r2 = oob.analyze(load(), {"0oaterraform01"}, SENS, include_failures=True)
    assert r2["counts"]["manual"] == 5


def test_admin_group_membership_is_high():
    r = oob.analyze(load(), {"0oaterraform01"}, SENS)
    sev = {(m["event_type"], m["targets"][-1]): m["severity"] for m in r["manual"]}
    assert sev[("group.user_membership.add", "UserGroup: Okta-Helpdesk-Admins")] == "high"
    assert sev[("group.user_membership.add", "UserGroup: Marketing")] == "low"
    assert sev[("zone.update", "NetworkZone: Corp IPs")] == "high"
    assert sev[("application.lifecycle.update", "AppInstance: Salesforce")] == "medium"


def test_high_first_and_grouped_by_actor():
    r = oob.analyze(load(), {"0oaterraform01"}, SENS)
    assert [m["severity"] for m in r["manual"]] == ["high", "high", "medium", "low"]
    assert list(r["by_actor"]) == ["alice.admin@example.com", "bob.helpdesk@example.com"]


def test_automation_actor_matches_login_or_name():
    r = oob.analyze(load(), {"terraform-okta", "bob.helpdesk@example.com"}, SENS)
    assert r["counts"]["via code"] == 3
    assert r["counts"]["manual"] == 2


def test_no_automation_actor_means_all_manual():
    r = oob.analyze(load(), set(), SENS)
    assert r["counts"]["manual"] == 5 and r["counts"]["via code"] == 0


def test_drift_attribution():
    with open(DRIFT, encoding="utf-8") as f:
        rows = oob.attribute_drift(json.load(f), load())
    who = {r["name"]: r["changed_by"] for r in rows}
    assert who["Corp IPs"] == "alice.admin@example.com"
    assert who["Salesforce"] == "bob.helpdesk@example.com"
    assert who["Mystery policy"] is None


def test_parse_since():
    now = datetime(2026, 10, 10, 12, 0, tzinfo=timezone.utc)
    assert oob.parse_since("24h", now) == "2026-10-09T12:00:00.000Z"
    assert oob.parse_since("7d", now) == "2026-10-03T12:00:00.000Z"
    assert oob.parse_since("2026-10-01T00:00:00Z") == "2026-10-01T00:00:00Z"


def test_filter_uses_prefixes():
    f = oob.build_filter()
    assert 'eventType sw "policy.rule"' in f and " or " in f
    for e in oob.ALL_EVENTS:
        assert any(e.startswith(p) for p in oob.PREFIXES), e


def test_cli_exit_codes_and_markdown(tmp_path, capsys):
    out = tmp_path / "r.md"
    code = oob.main(["--input", EVENTS, "--automation-actor", "0oaTERRAFORM01",
                     "--drift", DRIFT, "--markdown", "--output", str(out), "--fail-on", "high"])
    assert code == 2
    md = out.read_text()
    assert "4 manual" in md and "Okta-Helpdesk-Admins" in md and "Mystery policy" in md
    assert oob.main(["--input", EVENTS, "--automation-actor", "0oaTERRAFORM01"]) == 0
    text = capsys.readouterr().out
    assert "== alice.admin@example.com (2 changes)" in text
