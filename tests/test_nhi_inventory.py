"""Tests for scripts/nhi_inventory.py (offline: saved raw snapshot + a fake client)."""
import json
import os
import re
import shutil
import subprocess
import sys
from datetime import datetime, timezone

import pytest
import requests

HERE = os.path.dirname(__file__)
ROOT = os.path.join(HERE, "..")
sys.path.insert(0, os.path.join(ROOT, "scripts"))
sys.path.insert(0, ROOT)

import nhi_inventory as nhi  # noqa: E402
from lib.okta_client import OktaAuthError  # noqa: E402

RAW = os.path.join(HERE, "fixtures", "nhi_raw.json")
NOW = datetime(2026, 10, 11, 12, 0, tzinfo=timezone.utc)
NOW_ARG = "2026-10-11T12:00:00Z"


def load():
    with open(RAW, encoding="utf-8") as f:
        return json.load(f)


def rows_by_name():
    return {r["name"]: r for r in nhi.analyze(load(), NOW)}


def test_inventory_covers_every_type_and_ranks_highest_first():
    rows = nhi.analyze(load(), NOW)
    assert nhi.summarize(rows)["by_type"] == {
        "oauth-service-app": 4, "api-service": 1, "api-token": 3, "service-user": 2}
    scores = [r["score"] for r in rows]
    assert scores == sorted(scores, reverse=True)
    assert rows[0]["name"] == "legacy-sync-bot" and rows[0]["risk"] == "critical"


def test_super_admin_secret_client_reasons():
    r = rows_by_name()["legacy-sync-bot"]
    why = r["why"]
    assert "SUPER_ADMIN" in why
    assert "okta.roles.manage lets it grant admin roles" in why
    assert "shared client secret (client_secret_basic)" in why
    assert "not rotated in 639 days" in why
    assert "2 active client secrets" in why
    assert "no access token issued in the last 30 days" in why
    assert r["last_used"] is None
    assert r["details"]["admin_roles"] == ["SUPER_ADMIN"]


def test_read_only_key_client_is_low_and_used():
    r = rows_by_name()["siem-log-reader"]
    assert r["risk"] == "low" and r["score"] == 5
    assert r["last_used"] == "2026-10-11T11:59:00Z"
    assert r["credential"] == "private_key_jwt"


def test_inactive_app_score_halved():
    r = rows_by_name()["Old Provisioner"]
    assert r["why"].startswith("app is INACTIVE")
    # 25 (USER_ADMIN) + 6 + 3 + 5 (old key) = 39 -> halved, and no dormancy penalty
    assert r["score"] == 19
    assert "no access token issued" not in r["why"]


def test_token_exchange_agent_app_is_inventoried():
    r = rows_by_name()["copilot-agent"]
    assert "token-exchange client" in r["why"] and r["score"] == 0


def test_api_service_integration():
    r = rows_by_name()["Acme SIEM"]
    assert r["type"] == "api-service" and r["credential"] == "client_secret"
    assert "not rotated in 617 days" in r["why"]
    assert r["last_used"] == "2026-10-09T00:00:00Z"


def test_api_tokens_owner_gone_deprovisioned_and_zoned():
    rows = rows_by_name()
    gone = rows["ci-pipeline"]
    assert "owner's user record is gone" in gone["why"] and gone["details"]["owner"] == "(gone)"
    dep = rows["Workday sync"]
    assert "owner is DEPROVISIONED" in dep["why"] and "not used in 71 days" in dep["why"]
    zoned = rows["svc-scim token"]
    assert "any IP address" not in zoned["why"]
    assert zoned["credential"] == "SSWS (network ZONE)"
    assert "owner holds ORG_ADMIN" in zoned["why"]


def test_service_user_signals():
    rows = rows_by_name()
    svc = rows["svc-scim@example.com"]
    for frag in ("login matches 'svc'", "ORG_ADMIN", "no MFA enrolled",
                 "signed in interactively", "password not changed in 983 days",
                 "owns 1 API token(s)"):
        assert frag in svc["why"], frag
    bot = rows["reports-bot@example.com"]
    assert bot["risk"] == "low" and bot["credential"] == "password + 1 factor(s)"
    # token owners that are not service-like are not listed as service users
    assert "jane.former@example.com" not in rows


def test_rotation_and_stale_thresholds_are_tunable():
    rows = {r["name"]: r for r in nhi.analyze(load(), NOW, rotation_days=1000, stale_days=100)}
    assert "not rotated" not in rows["legacy-sync-bot"]["why"]
    assert "not used in" not in rows["Workday sync"]["why"]


def test_logs_unavailable_means_unknown_not_dormant():
    raw = load()
    raw["logs_available"] = False
    r = {x["name"]: x for x in nhi.analyze(raw, NOW)}["legacy-sync-bot"]
    assert r["last_used"] == "unknown" and "no access token issued" not in r["why"]


def test_service_name_pattern():
    pat = re.compile(nhi.DEFAULT_PATTERN, re.I)
    m = lambda login, first="", last="": nhi.match_service(  # noqa: E731
        {"profile": {"login": login, "firstName": first, "lastName": last}}, pat, {})
    assert m("svc-backup@example.com") == "login matches 'svc'"
    assert m("terraform@example.com") == "login matches 'terraform'"
    assert m("x@example.com", "Okta", "Bot") == "last name matches 'bot'"
    assert m("dork@agentmail.to") is None      # domain is ignored
    assert m("abbott@example.com") is None     # 'bot' inside a word is not a match
    assert m("api.reader@example.com") == "login matches 'api'"
    assert nhi.match_service({"profile": {"login": "a@b.c"}, "type": {"id": "oty1"}},
                             pat, {"oty1": "Service Account"}) == "user type 'Service Account'"


def test_cli_outputs_and_exit_codes(tmp_path, capsys):
    assert nhi.main(["--input", RAW, "--now", NOW_ARG]) == 0
    text = capsys.readouterr().out
    assert "10 identities: 4 OAuth service apps, 1 API service integrations" in text
    assert "CRITICAL 5 | HIGH 0 | MEDIUM 1 | LOW 4" in text
    out = tmp_path / "n.csv"
    assert nhi.main(["--input", RAW, "--now", NOW_ARG, "--csv", "--output", str(out),
                     "--min-risk", "critical", "--fail-on", "high"]) == 2
    lines = out.read_text().splitlines()
    assert lines[0].startswith('"risk","score","type","name"') and len(lines) == 6
    out = tmp_path / "n.json"
    nhi.main(["--input", RAW, "--now", NOW_ARG, "--json", "--output", str(out)])
    data = json.loads(out.read_text())
    assert data["summary"]["total"] == 10 and data["collected_at"] == "2026-10-11T12:00:00Z"
    assert all(r["why"] for r in data["identities"])


# ------------------------------------------------- collection (fake client)

class FakeResp:
    def __init__(self, status, body=None):
        self.status_code = status
        self._body = body

    def json(self):
        return self._body


class FakeClient:
    """Serves canned GETs; records every call so we can prove it is read-only."""
    base_url = "https://fake.okta.com"

    def __init__(self, routes):
        self.routes = routes
        self.calls = []

    def _lookup(self, path):
        if path not in self.routes:
            raise AssertionError(f"unexpected GET {path}")
        v = self.routes[path]
        if isinstance(v, int):
            if v in (401, 403):
                raise OktaAuthError(f"Okta rejected the API token (HTTP {v}).")
            raise requests.HTTPError(response=FakeResp(v))
        return v

    def paged_get(self, path, params=None):
        self.calls.append(("GET", path, dict(params or {})))
        if path == "/api/v1/logs":
            actor = re.search(r'actor.id eq "([^"]+)"', params["filter"]).group(1)
            return iter(self.routes["logs"].get(actor, []))
        return iter(self._lookup(path))

    def _request(self, method, path, **_):
        assert method == "GET"
        self.calls.append((method, path, {}))
        return FakeResp(200, self._lookup(path))

    post = put = delete = None  # any write attempt would raise TypeError


def test_collect_is_get_only_and_tolerates_forbidden_endpoints():
    svc_app = {"id": "0oaS", "label": "svc-app", "status": "ACTIVE", "created": "2026-01-01T00:00:00.000Z",
               "settings": {"oauthClient": {"application_type": "service",
                                            "grant_types": ["client_credentials"]}},
               "credentials": {"oauthClient": {"client_id": "0oaS",
                                               "token_endpoint_auth_method": "client_secret_post"}}}
    web_app = {"id": "0oaW", "label": "web", "status": "ACTIVE",
               "settings": {"oauthClient": {"application_type": "web",
                                            "grant_types": ["authorization_code"]}},
               "credentials": {"oauthClient": {"client_id": "0oaW"}}}
    routes = {
        "/api/v1/apps": [svc_app, web_app],
        "/api/v1/apps/0oaS/grants": [{"scopeId": "okta.users.manage", "status": "ACTIVE"},
                                     {"scopeId": "okta.logs.read", "status": "REVOKED"}],
        "/oauth2/v1/clients/0oaS/roles": [{"type": "APP_ADMIN", "label": "Application Administrator",
                                           "status": "ACTIVE"}],
        "/api/v1/apps/0oaS/credentials/secrets": [{"status": "ACTIVE", "created": "2026-01-01T00:00:00.000Z"}],
        "/api/v1/apps/0oaS/credentials/jwks": {"keys": []},
        "/integrations/api/v1/api-services": 403,
        "/api/v1/api-tokens": 403,
        "/api/v1/meta/types/user": [{"id": "oty1", "name": "user"}],
        "/api/v1/users": [{"id": "00uB", "status": "ACTIVE",
                           "profile": {"login": "svc-backup@example.com"},
                           "credentials": {"password": {}}, "type": {"id": "oty1"}},
                          {"id": "00uH", "status": "ACTIVE", "profile": {"login": "alice@example.com"}}],
        "/api/v1/users/00uB/roles": [],
        "/api/v1/users/00uB/factors": [],
        "logs": {"0oaS": [{"published": "2026-10-10T01:02:03.456Z"}]},
    }
    client = FakeClient(routes)
    raw = nhi.collect(client, re.compile(nhi.DEFAULT_PATTERN, re.I), 30, now=NOW)
    assert all(c[0] == "GET" for c in client.calls)
    assert [a["label"] for a in raw["apps"]] == ["svc-app"]          # web app skipped
    assert raw["apps"][0]["scopes"] == ["okta.users.manage"]          # revoked grant dropped
    assert raw["apps"][0]["auth_method"] == "client_secret_post"
    assert raw["errors"] == ["api service integrations: HTTP 403",
                             "api tokens (needs a SUPER_ADMIN token): HTTP 403"]
    assert list(raw["users"]) == ["00uB"] and raw["users"]["00uB"]["candidate"]
    assert raw["logs_available"] and raw["token_grants"]["0oaS"] == "2026-10-10T01:02:03.456Z"
    log_call = [c for c in client.calls if c[1] == "/api/v1/logs"][0][2]
    assert log_call["sortOrder"] == "DESCENDING" and log_call["until"]
    rows = nhi.analyze(raw, NOW)
    assert {r["name"] for r in rows} == {"svc-app", "svc-backup@example.com"}
    assert "Could not read" in nhi.render_text(raw, rows)


def test_missing_token_owner_is_recorded():
    routes = {
        "/api/v1/apps": [], "/integrations/api/v1/api-services": [],
        "/api/v1/api-tokens": [{"id": "00T1", "name": "t", "userId": "00uX"}],
        "/api/v1/meta/types/user": [], "/api/v1/users": [], "/api/v1/users/00uX": 404,
        "logs": {},
    }
    raw = nhi.collect(FakeClient(routes), re.compile(nhi.DEFAULT_PATTERN, re.I), 30, now=NOW)
    assert raw["users"]["00uX"] == {"id": "00uX", "missing": True}
    assert "owner's user record is gone" in nhi.analyze(raw, NOW)[0]["why"]


# ------------------------------------------------- PowerShell parity

PWSH = shutil.which("pwsh")


@pytest.mark.skipif(not PWSH, reason="pwsh not installed")
@pytest.mark.parametrize("py_flag,ps_flag", [([], []), (["--csv"], ["-Csv"]),
                                             (["--min-risk", "high"], ["-MinRisk", "high"])])
def test_powershell_port_prints_the_same(py_flag, ps_flag):
    py = subprocess.run([sys.executable, os.path.join(ROOT, "scripts", "nhi_inventory.py"),
                         "--input", RAW, "--now", NOW_ARG] + py_flag,
                        capture_output=True, text=True, check=True).stdout
    ps = subprocess.run([PWSH, "-NoProfile", "-File", os.path.join(ROOT, "scripts", "nhi_inventory.ps1"),
                         "-InputFile", RAW, "-Now", NOW_ARG] + ps_flag,
                        capture_output=True, text=True, check=True).stdout
    assert py == ps


@pytest.mark.skipif(not PWSH, reason="pwsh not installed")
def test_powershell_port_json_matches():
    py = subprocess.run([sys.executable, os.path.join(ROOT, "scripts", "nhi_inventory.py"),
                         "--input", RAW, "--now", NOW_ARG, "--json"],
                        capture_output=True, text=True, check=True).stdout
    ps = subprocess.run([PWSH, "-NoProfile", "-File", os.path.join(ROOT, "scripts", "nhi_inventory.ps1"),
                         "-InputFile", RAW, "-Now", NOW_ARG, "-Json"],
                        capture_output=True, text=True, check=True).stdout
    assert json.loads(py) == json.loads(ps)
