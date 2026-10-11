"""Tests for scripts/phishing_resistant_whatif.py (offline: saved snapshot + fake client)."""
import copy
import json
import os
import re
import shutil
import subprocess
import sys

import pytest

HERE = os.path.dirname(__file__)
ROOT = os.path.join(HERE, "..")
sys.path.insert(0, os.path.join(ROOT, "scripts"))

import phishing_resistant_whatif as prw  # noqa: E402

SNAP = os.path.join(HERE, "fixtures", "phishing_resistant_snapshot.json")
PY = os.path.join(ROOT, "scripts", "phishing_resistant_whatif.py")
PS = os.path.join(ROOT, "scripts", "phishing_resistant_whatif.ps1")


def load():
    with open(SNAP, encoding="utf-8") as f:
        return json.load(f)


def by_login(res):
    return {u["login"]: u for u in res["users"]}


# ---------------------------------------------------------------- classification

def test_classes_and_skips():
    res = prw.analyze(load())
    u = by_login(res)
    assert {k: v["class"] for k, v in u.items()} == {
        "alice@example.com": "READY",
        "bob@example.com": "READY",
        "Carol@example.com": "ENROLLED_NOT_USED",
        "dave@example.com": "AT_RISK",
        "erin@example.com": "AT_RISK",          # PASSWORD_EXPIRED can still sign in
        "frank@example.com": "NO_MFA",
        "ivan@example.com": "ENROLLED_NOT_USED",
        "jill@example.com": "READY",
    }
    assert res["skipped_not_active"] == {"STAGED": 1, "SUSPENDED": 1}
    assert res["summary"] == {"READY": 3, "ENROLLED_NOT_USED": 2, "AT_RISK": 2,
                              "NO_MFA": 1, "PLATFORM_BLOCKER": 2}


def test_pr_use_outside_window_does_not_count():
    u = by_login(prw.analyze(load()))
    assert u["ivan@example.com"]["last_phishing_resistant_use"] is None
    snap = load()
    snap["lookback_days"] = 60
    assert by_login(prw.analyze(snap))["ivan@example.com"]["class"] == "READY"


def test_failed_and_non_auth_events_ignored():
    u = by_login(prw.analyze(load()))
    assert u["dave@example.com"]["class"] == "AT_RISK"          # FAILURE webauthn ignored
    assert "passkey" not in u["dave@example.com"]["methods_used"]
    # policy.evaluate_sign_on with PR on Windows must not cover jill's Windows
    assert u["jill@example.com"]["os_uncovered"] == ["Windows"]


def test_fastpass_without_phishing_resistance_is_not_ready():
    carol = by_login(prw.analyze(load()))["Carol@example.com"]
    assert carol["methods_used"] == ["fastpass"]
    assert "never phishing-resistant" in carol["fix"]


def test_platform_blockers():
    u = by_login(prw.analyze(load()))
    assert u["bob@example.com"]["platform_blocker"]
    assert u["bob@example.com"]["os_uncovered"] == ["Linux"]
    assert "FastPass unsupported" in u["bob@example.com"]["fix"]
    assert u["jill@example.com"]["platform_blocker"]
    assert "no FastPass there" in u["jill@example.com"]["fix"]
    assert not u["alice@example.com"]["platform_blocker"]     # passkey covers any OS
    assert "doesn't run on Linux" in u["erin@example.com"]["fix"]


def test_lockout_and_waves():
    res = prw.analyze(load())
    assert res["would_lock_out"] == 5
    assert [r["login"] for r in res["lockout"]] == [
        "frank@example.com", "dave@example.com", "erin@example.com",
        "bob@example.com", "jill@example.com"]
    assert res["waves"] == {
        "wave1_enforce_now": ["alice@example.com"],
        "wave2_nudge": ["Carol@example.com", "ivan@example.com"],
        "wave3_enroll_first": ["dave@example.com", "erin@example.com"],
        "hold": ["bob@example.com", "frank@example.com", "jill@example.com"],
    }


def test_enrolled_labels_only_active_factors():
    u = by_login(prw.analyze(load()))
    assert u["ivan@example.com"]["enrolled"] == ["passkey"]     # PENDING sms dropped
    assert u["bob@example.com"]["enrolled"] == ["FastPass (Windows)", "push"]


# ---------------------------------------------------------------- tenant + policy

def test_tenant_checks():
    checks = prw.analyze(load())["tenant_checks"]
    assert checks[0][0] == "BLOCKER" and "WebAuthn" in checks[0][1]
    assert "2 user(s)" in checks[0][1]
    assert ["OK", "Okta Verify FastPass is ACTIVE."] in checks
    assert checks[-1][0] == "OK" and '"Default Policy"' in checks[-1][1]


def test_no_pr_authenticator_at_all_is_blocker():
    snap = load()
    for a in snap["authenticators"]:
        a["status"] = "INACTIVE"
    checks = prw.analyze(snap)["tenant_checks"]
    assert checks[0][0] == "BLOCKER" and "No phishing-resistant authenticator" in checks[0][1]


def test_enrollment_policy_without_passkey_warns():
    snap = load()
    snap["enroll_policies"][1]["settings"]["authenticators"] = [
        {"key": "okta_verify", "enroll": {"self": "OPTIONAL"}}]
    last = prw.analyze(snap)["tenant_checks"][-1]
    assert last[0] == "WARN" and "doesn't offer passkey" in last[1]


def test_policy_path():
    pol = prw.analyze(load())["policies"]
    rules = pol["app_sign_in"][0]["rules"]
    assert [r["name"] for r in rules] == ["Office network 1FA", "Engineering 2FA", "Catch-all Rule"]
    assert rules[0]["only_when"] == ["network zone"] and not rules[0]["first_unconditional_match"]
    assert rules[1]["first_unconditional_match"] and rules[1]["applies_to"] == "this group"
    assert rules[2]["phishing_resistance"] == "phishing resistance REQUIRED"
    assert pol["global_session"]["require_factor"] is False


def test_pr_requirement_variants():
    def rule(vm):
        return {"actions": {"appSignOn": {"verificationMethod": vm}}}
    both = [{"possession": {"phishingResistant": "REQUIRED"}}, {"possession": {}}]
    assert prw.pr_requirement(rule({"type": "ASSURANCE", "constraints": both})) == \
        "phishing resistance required on some paths only"
    chain = {"type": "AUTH_METHOD_CHAIN",
             "chains": [{"authenticationMethods": [{"key": "okta_verify", "phishingResistant": "REQUIRED"}]}]}
    assert "some steps" in prw.pr_requirement(rule(chain))
    assert prw.pr_requirement(rule({})) == "phishing resistance NOT required"


def test_norm_helpers():
    assert prw.norm_os("Mac OS X") == "macOS"
    assert prw.norm_os("Chrome OS") == "ChromeOS"
    assert prw.norm_os("Unknown") is None
    assert prw.norm_method("OKTA_SOFT_TOKEN") == "totp"
    assert prw.norm_method("PASSWORD_AS_FACTOR") is None
    assert prw.norm_method("Use Okta FastPass") == "fastpass"


def test_text_report():
    text = prw.render_text(prw.analyze(load()))
    assert "would lock out 5 of 8 user(s) (63%)" in text
    assert "2 more are enrolled but haven't used it" in text
    assert "<- first unconditional match: the rule you'd tighten" in text
    assert "Wave 1  enforce now (1): alice@example.com" in text


def test_empty_scope():
    snap = load()
    snap["users"] = []
    text = prw.render_text(prw.analyze(snap))
    assert "nobody in scope can sign in" in text


# ---------------------------------------------------------------- read-only guard

def test_python_only_issues_get():
    src = open(PY, encoding="utf-8").read()
    assert not re.search(r"\.(post|put|delete)\(", src)
    assert set(re.findall(r'_request\("([A-Z]+)"', src)) == {"GET"}


def test_powershell_only_issues_get():
    src = open(PS, encoding="utf-8").read()
    methods = set(re.findall(r"-Method\s+(\w+)", src))
    assert methods == {"GET"}
    assert "Invoke-RestMethod" not in src


class _Resp:
    def __init__(self, data):
        self._data = data

    def json(self):
        return self._data


class FakeClient:
    """Serves canned GETs; any other verb fails the test."""

    def __init__(self, snap):
        self.calls = []
        self.snap = snap

    def _request(self, method, path, params=None, data=None):
        assert method == "GET", f"non-GET call: {method} {path}"
        self.calls.append(path)
        if path == "/api/v1/groups/00gENGINEERING000001":
            return _Resp({"id": "00gENGINEERING000001", "profile": {"name": "Engineering"}})
        if path.startswith("/api/v1/policies/"):
            return _Resp({"id": path.split("/")[-1], "name": "Salesforce sign-in"})
        if path.endswith("/methods"):
            return _Resp([{"type": "signed_nonce", "status": "ACTIVE"}])
        raise AssertionError(f"unexpected GET {path}")

    def paged_get(self, path, params=None):
        self.calls.append(path)
        if path.endswith("/users") and "/groups/" in path:
            return iter([{"id": "00uA", "status": "ACTIVE", "profile": {"login": "a@x"}},
                         {"id": "00uB", "status": "STAGED", "profile": {"login": "b@x"}}])
        if path == "/api/v1/logs":
            assert params["until"] and params["since"]          # always bounded
            return iter([
                {"published": "2026-10-10T00:00:00.000Z", "eventType": "user.authentication.verify",
                 "actor": {"id": "00uA"}, "outcome": {"result": "SUCCESS"},
                 "client": {"userAgent": {"os": "Windows 11"}},
                 "target": [{"type": "AuthenticatorMethod", "displayName": "Okta Verify",
                             "detailEntry": {"methodTypeUsed": "signed_nonce",
                                             "methodUsedVerifiedProperties": "[PHISHING_RESISTANT]",
                                             "authenticatorKey": "okta_verify"}},
                            {"type": "AppInstance", "detailEntry": None}]},
                {"published": "2026-10-10T00:00:00.000Z", "eventType": "user.authentication.verify",
                 "actor": {"id": "00uOUTSIDER"}, "outcome": {"result": "SUCCESS"}, "target": []},
            ])
        if path == "/api/v1/authenticators":
            return iter([{"id": "autOV", "key": "okta_verify", "status": "ACTIVE"},
                         {"id": "autWA", "key": "webauthn", "status": "ACTIVE"}])
        if path == "/api/v1/apps":
            assert params == {"filter": 'group.id eq "00gENGINEERING000001"'}
            return iter([{"id": "0oa1", "label": "Salesforce", "status": "ACTIVE",
                          "_links": {"accessPolicy": {"href": "https://x/api/v1/policies/rstSALES"}}},
                         {"id": "0oa2", "label": "Old", "status": "INACTIVE", "_links": {}}])
        raise AssertionError(f"unexpected paged GET {path}")

    def list_groups(self, query=None):
        self.calls.append(f"groups?q={query}")
        return iter([{"id": "00gEVERYONE", "type": "BUILT_IN", "profile": {"name": "Everyone"}}])

    def list_factors(self, user_id):
        self.calls.append(f"factors/{user_id}")
        return [{"factorType": "signed_nonce", "status": "ACTIVE", "provider": "OKTA",
                 "profile": {"platform": "WINDOWS", "deviceType": "Laptop"}}]

    def list_policies(self, policy_type):
        self.calls.append(f"policies?type={policy_type}")
        return iter([])

    def list_policy_rules(self, policy_id):
        self.calls.append(f"rules/{policy_id}")
        return iter(copy.deepcopy(self.snap["access_policies"][0]["rules"]))


def test_collect_reads_only_and_trims():
    snap = prw.collect(FakeClient(load()), "00gENGINEERING000001", None, 30)
    assert snap["target"]["group"]["name"] == "Engineering"
    assert snap["everyone_group_id"] == "00gEVERYONE"
    assert [u["login"] for u in snap["users"]] == ["a@x", "b@x"]
    assert snap["users"][1]["factors"] == []                  # STAGED: factors not read
    assert len(snap["events"]) == 1                           # outsider dropped
    assert snap["events"][0]["methods"] == [
        {"method": "signed_nonce", "props": "[PHISHING_RESISTANT]", "key": "okta_verify"}]
    assert snap["access_policies"][0]["apps"] == ["Salesforce"]
    res = prw.analyze(snap)
    assert by_login(res)["a@x"]["class"] == "READY"


# ---------------------------------------------------------------- CLI + parity

def run_py(*args):
    return subprocess.run([sys.executable, PY, *args], capture_output=True, text=True)


def test_cli_exit_codes():
    assert run_py("--input", SNAP).returncode == 0
    assert run_py("--input", SNAP, "--fail-on-lockout").returncode == 2
    assert run_py().returncode == 2                           # argparse: need a target
    assert run_py("--group", "x", "--lookback-days", "120").returncode == 2


PWSH = os.environ.get("PWSH") or shutil.which("pwsh")


@pytest.mark.skipif(not PWSH, reason="pwsh not installed")
def test_powershell_parity_text_and_json():
    py_txt = run_py("--input", SNAP).stdout
    ps = subprocess.run([PWSH, "-NoProfile", "-File", PS, "-InputFile", SNAP],
                        capture_output=True, text=True)
    assert ps.returncode == 0, ps.stderr
    assert ps.stdout == py_txt
    py_json = json.loads(run_py("--input", SNAP, "--json").stdout)
    ps_json = subprocess.run([PWSH, "-NoProfile", "-File", PS, "-InputFile", SNAP, "-Json"],
                             capture_output=True, text=True)
    assert json.loads(ps_json.stdout) == py_json
