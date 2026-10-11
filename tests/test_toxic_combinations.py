"""Tests for scripts/toxic_combinations.py (offline: saved tenant snapshot)."""
import copy
import json
import os
import shutil
import subprocess
import sys

import pytest

HERE = os.path.dirname(__file__)
ROOT = os.path.join(HERE, "..")
sys.path.insert(0, os.path.join(ROOT, "scripts"))

import toxic_combinations as tc  # noqa: E402

SNAP = os.path.join(HERE, "fixtures", "sod_snapshot.json")
POLICY = os.path.join(ROOT, "examples", "sod_policy.example.json")


def load(path):
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def run(policy=None, snap=None):
    return tc.analyze(snap or load(SNAP), policy or tc.load_policy(POLICY))


def by(result, user, rule_id):
    hits = [f for f in result["findings"] if f["user"] == user and f["rule_id"] == rule_id]
    assert len(hits) == 1, f"expected one {rule_id} finding for {user}, got {len(hits)}"
    return hits[0]


def pairs(result):
    return {(f["user"], f["rule_id"]) for f in result["findings"]}


def test_expected_findings_and_nothing_else():
    r = run()
    assert pairs(r) == {
        ("alice.admin@example.com", "SOD-001"), ("frank.ops@example.com", "SOD-001"),
        ("breakglass@example.com", "SOD-001"), ("carol.cloud@example.com", "SOD-002"),
        ("dave.ap@example.com", "SOD-003"), ("erin.vendor@example.com", "SOD-003"),
        ("alice.admin@example.com", "SOD-004"), ("bob.lead@example.com", "SOD-004"),
    }
    assert r["users_scanned"] == 8  # DEPROVISIONED henry is ignored


def test_phishing_resistant_factor_must_be_active():
    r = run()
    # alice's WebAuthn is only PENDING_ACTIVATION, bob's is ACTIVE.
    assert ("alice.admin@example.com", "SOD-001") in pairs(r)
    assert ("bob.lead@example.com", "SOD-001") not in pairs(r)
    f = by(r, "alice.admin@example.com", "SOD-001")
    assert "enrolled: push, token:software:totp" in f["sides"][1]["items"][0]["item"]


def test_access_paths_are_explained():
    r = run()
    carol = by(r, "carol.cloud@example.com", "SOD-002")
    aws_paths = [p for it in carol["sides"][0]["items"] for p in it["paths"]]
    assert {p["via"] for p in aws_paths} == {"rule-managed group"}
    assert "group rule 'Cloud team to AWS prod'" in aws_paths[0]["how"]
    # Inactive rule does not make Finance-Approvers rule-managed.
    assert carol["sides"][1]["items"][0]["paths"][0]["via"] == "group"
    bob = by(r, "bob.lead@example.com", "SOD-004")
    assert bob["sides"][0]["items"][0]["paths"][0]["via"] == "rule-managed group"
    erin = by(r, "erin.vendor@example.com", "SOD-003")
    assert erin["sides"][1]["items"][0]["paths"][0]["via"] == "directory group"
    dave = by(r, "dave.ap@example.com", "SOD-003")
    assert dave["sides"][1]["items"][0]["paths"][0]["via"] == "direct"


def test_smallest_fix_prefers_cheapest_side():
    r = run()
    # Finance-Approvers is a plain group (cost 2); AWS side is rule-fed (cost 3).
    carol = by(r, "carol.cloud@example.com", "SOD-002")
    assert carol["smallest_fix"]["side"] == "Finance approver"
    assert carol["smallest_fix"]["actions"] == ["Remove carol.cloud@example.com from group 'Finance-Approvers'"]
    # Direct Bill.com assignment (1) beats removing a group membership (2).
    dave = by(r, "dave.ap@example.com", "SOD-003")
    assert dave["smallest_fix"]["actions"] == ["Unassign app 'Bill.com' from dave.ap@example.com (direct assignment)"]
    # The shared AWS-Prod-Admins membership is one change, not two.
    aws = [f for f in carol["fix_options"] if f["side"] == "AWS prod admin"][0]
    assert len(aws["actions"]) == 1 and aws["cost"] == 3


def test_tie_goes_to_side_listed_last():
    r = run()
    frank = by(r, "frank.ops@example.com", "SOD-001")
    assert frank["smallest_fix"]["side"] == "No phishing-resistant factor"
    assert frank["smallest_fix"]["actions"][0].startswith("Enroll frank.ops@example.com")


def test_exceptions_suppress_and_are_counted():
    pol = tc.load_policy(POLICY)
    pol["rules"][0]["exceptions"] = ["BreakGlass@example.com"]
    r = run(policy=pol)
    assert ("breakglass@example.com", "SOD-001") not in pairs(r)
    assert r["excepted"] == [{"user": "breakglass@example.com", "rule_id": "SOD-001"}]


def test_ranking_and_status():
    r = run()
    scores = [f["score"] for f in r["findings"]]
    assert scores == sorted(scores, reverse=True)
    assert [f["rank"] for f in r["findings"]] == list(range(1, len(scores) + 1))
    dave = by(r, "dave.ap@example.com", "SOD-003")
    assert dave["status"] == "SUSPENDED" and dave["score"] == 73  # 90 - 20 + 3 (group path)
    assert "cannot sign in today" in dave["explanation"]


def test_all_of_side_and_custom_role_and_inactive_app():
    pol = {"rules": [{
        "id": "T-1", "name": "custom payments role plus vendor maintenance", "severity": "low",
        "sides": [
            {"label": "Payments approver", "any_of": [{"type": "admin_role", "value": "cr0PAYAPPROVE"}]},
            {"label": "Vendor + AP", "all_of": [{"type": "group", "value": "NetSuite-Vendor-Maintenance"},
                                                {"type": "group", "value": "Payments-Custom-Admins"}]},
        ]}, {
        "id": "T-2", "name": "retired app counts for nothing", "severity": "low",
        "sides": [{"label": "a", "any_of": [{"type": "app", "value": "Retired Payments"}]},
                  {"label": "b", "any_of": [{"type": "group", "value": "Everyone"}]}]}]}
    tc.validate_policy(pol)
    r = run(policy=pol)
    assert pairs(r) == {("ivan.pay@example.com", "T-1")}
    ivan = r["findings"][0]
    assert ivan["sides"][0]["items"][0]["item"] == "admin role 'Payments Approver Role (CUSTOM)'"
    # all_of side: removing either group breaks it -> exactly one action.
    side2 = [f for f in ivan["fix_options"] if f["side"] == "Vendor + AP"][0]
    assert len(side2["actions"]) == 1


def test_everyone_group_is_expensive_to_fix():
    snap = load(SNAP)
    snap["app_groups"]["0oaBILL"] = ["00gEVERYONE"]
    r = run(snap=snap)
    erin = by(r, "erin.vendor@example.com", "SOD-003")
    vias = {p["via"] for it in erin["sides"][1]["items"] for p in it["paths"]}
    assert "everyone" in vias
    assert erin["smallest_fix"]["side"] == "Creates vendors"


@pytest.mark.parametrize("bad, msg", [
    ({}, "non-empty"),
    ({"rules": [{"id": "x", "name": "y", "sides": [{"label": "a", "any_of": [{"type": "app", "value": "v"}]}]}]},
     "at least two"),
    ({"rules": [{"id": "x", "name": "y", "severity": "urgent", "sides": []}]}, "severity"),
    ({"rules": [{"id": "x", "name": "y", "sides": [{"label": "a", "any_of": [{"type": "nope"}]},
                                                     {"label": "b", "any_of": [{"type": "nope"}]}]}]},
     "unknown entry type"),
])
def test_policy_validation(bad, msg):
    with pytest.raises(tc.PolicyError, match=msg):
        tc.validate_policy(bad)


def test_cli_outputs_and_fail_on(tmp_path, capsys):
    out_json, out_csv = tmp_path / "r.json", tmp_path / "r.csv"
    rc = tc.main(["--policy", POLICY, "--snapshot", SNAP, "--json", "--output", str(out_json),
                  "--csv", str(out_csv), "--fail-on", "critical"])
    assert rc == 2
    report = load(out_json)
    assert report["summary"]["findings"] == 8
    assert report["summary"]["by_risk"] == {"CRITICAL": 5, "HIGH": 1, "MEDIUM": 2, "LOW": 0}
    lines = out_csv.read_text(encoding="utf-8").splitlines()
    assert lines[0].startswith('"rank","risk","score","user"')
    assert len(lines) == 9
    assert tc.main(["--policy", POLICY, "--snapshot", SNAP]) == 0
    assert "SMALLEST FIX" in capsys.readouterr().out


PWSH = shutil.which("pwsh")


EDGE = os.path.join(HERE, "fixtures", "sod_policy_edge.json")


@pytest.mark.skipif(not PWSH, reason="pwsh not installed")
@pytest.mark.parametrize("policy", [POLICY, EDGE])
def test_powershell_port_matches(tmp_path, policy):
    """The .ps1 port must print the same text and CSV and the same JSON data."""
    POLICY_ = policy
    ps1 = os.path.join(ROOT, "scripts", "toxic_combinations.ps1")
    py = [sys.executable, os.path.join(ROOT, "scripts", "toxic_combinations.py"),
          "--policy", POLICY_, "--snapshot", SNAP]
    ps = [PWSH, "-NoProfile", "-File", ps1, "-Policy", POLICY_, "-Snapshot", SNAP]
    t_py = subprocess.run(py, capture_output=True, text=True, check=True).stdout
    t_ps = subprocess.run(ps, capture_output=True, text=True, check=True).stdout
    assert t_ps == t_py
    subprocess.run(py + ["--json", "--output", str(tmp_path / "py.json"), "--csv", str(tmp_path / "py.csv")],
                   check=True, capture_output=True)
    subprocess.run(ps + ["-Json", "-Output", str(tmp_path / "ps.json"), "-Csv", str(tmp_path / "ps.csv")],
                   check=True, capture_output=True)
    assert (tmp_path / "ps.csv").read_text(encoding="utf-8") == (tmp_path / "py.csv").read_text(encoding="utf-8")
    assert load(tmp_path / "ps.json") == load(tmp_path / "py.json")
    rc_ps = subprocess.run(ps + ["-FailOn", "high"], capture_output=True).returncode
    rc_py = subprocess.run(py + ["--fail-on", "high"], capture_output=True).returncode
    assert rc_ps == rc_py == 2


def test_edge_policy_three_sides_and_exception_by_id():
    r = run(policy=tc.load_policy(EDGE))
    assert pairs(r) == {("alice.admin@example.com", "E-3"), ("breakglass@example.com", "E-3"),
                        ("ivan.pay@example.com", "E-1")}
    assert r["excepted"] == [{"user": "frank.ops@example.com", "rule_id": "E-3"}]
    alice = by(r, "alice.admin@example.com", "E-3")
    assert alice["explanation"].startswith('alice.admin@example.com holds all of "Super admin", "Everyone member" and "No WebAuthn".')
    # Removing someone from Everyone is never the suggested fix.
    assert alice["smallest_fix"]["side"] != "Everyone member"
