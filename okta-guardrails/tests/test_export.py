"""export-population against a fake Okta API (no network)."""
import io
import json
import urllib.error
from email.message import Message

from okta_guardrails.export import OktaReader, build_population, retry_wait_seconds, DEFAULT_ATTRIBUTES

BASE = "https://example.okta.com"


def _headers(link=None, extra=None):
    m = Message()
    if link:
        m["link"] = link
    for k, v in (extra or {}).items():
        m[k] = v
    return m


class _Resp(io.BytesIO):
    def __init__(self, body, headers):
        super().__init__(json.dumps(body).encode())
        self.headers = headers

    def __enter__(self):
        return self

    def __exit__(self, *a):
        self.close()


USERS = [
    {"id": "u1", "status": "ACTIVE", "profile": {"login": "ana@example.com", "department": "Sales",
                                                  "mobilePhone": "555-0100"}},
    {"id": "u2", "status": "ACTIVE", "profile": {"login": "bo@example.com", "department": "Finance"}},
    {"id": "u3", "status": "STAGED", "profile": {"login": "cy@example.com", "department": "Sales"}},
]
GROUPS = [{"id": "g1", "profile": {"name": "Everyone"}}, {"id": "g2", "profile": {"name": "Salesforce"}},
          {"id": "g3", "profile": {"name": "VIP"}}]
MEMBERS = {"g1": ["u1", "u2", "u3"], "g2": ["u1", "u2"], "g3": ["u2"]}
RULES = [{"id": "r1", "name": "Sales to Salesforce", "status": "ACTIVE",
          "conditions": {"expression": {"value": 'user.department == "Sales"'}},
          "actions": {"assignUserToGroups": {"groupIds": ["g2"]}}},
         {"id": "r2", "name": "old", "status": "INACTIVE",
          "conditions": {"expression": {"value": 'user.department == "Finance"'}},
          "actions": {"assignUserToGroups": {"groupIds": ["g3"]}}}]


def fake_api(calls, rate_limit_once=False):
    state = {"limited": not rate_limit_once}

    def opener(req, timeout=30):
        assert req.get_method() == "GET"
        url = req.full_url
        calls.append(url)
        if not state["limited"]:
            state["limited"] = True
            raise urllib.error.HTTPError(url, 429, "Too Many Requests",
                                         _headers(extra={"x-rate-limit-reset": "1791708003",
                                                         "date": "Sun, 11 Oct 2026 08:40:00 GMT"}), None)
        path = url.split(BASE, 1)[1].split("?")[0]
        if path == "/api/v1/users":
            # two pages, to exercise the Link header
            if "after=" not in url:
                return _Resp(USERS[:2], _headers(f'<{BASE}/api/v1/users?limit=2>; rel="self", '
                                                 f'<{BASE}/api/v1/users?after=u2&limit=2>; rel="next"'))
            return _Resp(USERS[2:], _headers())
        if path == "/api/v1/groups":
            return _Resp(GROUPS, _headers())
        if path == "/api/v1/groups/rules":
            return _Resp(RULES, _headers())
        gid = path.split("/")[4]
        return _Resp([{"id": u} for u in MEMBERS[gid]], _headers())
    return opener


def test_population_sets_rule_members_aside():
    calls = []
    pop = build_population(OktaReader(BASE, "t", opener=fake_api(calls)), DEFAULT_ATTRIBUTES)
    by = {u["login"]: u for u in pop["users"]}
    assert len(by) == 3                                   # both pages read
    assert by["ana@example.com"]["groups"] == ["Everyone"]  # in Salesforce because of the rule
    assert sorted(by["bo@example.com"]["groups"]) == ["Everyone", "Salesforce", "VIP"]  # direct; inactive rule ignored
    assert pop["rule_managed_memberships"] == 1 and pop["active_rules"] == 1
    assert "mobilePhone" not in by["ana@example.com"]["profile"]  # contact details left out
    assert pop["groups"] == {"g1": "Everyone", "g2": "Salesforce", "g3": "VIP"}


def test_rate_limit_waits_until_reset_and_retries():
    calls, slept = [], []
    reader = OktaReader(BASE, "t", opener=fake_api(calls, rate_limit_once=True), sleep=slept.append)
    pop = build_population(reader, DEFAULT_ATTRIBUTES)
    assert slept == [4] and len(pop["users"]) == 3


def test_unreadable_rule_keeps_members_and_warns():
    calls = []
    bad = [dict(RULES[0], conditions={"expression": {"value": 'user.department == '}})]
    opener = fake_api(calls)

    def patched(req, timeout=30):
        if req.full_url.split("?")[0].endswith("/groups/rules"):
            return _Resp(bad, _headers())
        return opener(req, timeout)
    pop = build_population(OktaReader(BASE, "t", opener=patched), DEFAULT_ATTRIBUTES)
    by = {u["login"]: u for u in pop["users"]}
    assert "Salesforce" in by["ana@example.com"]["groups"] and pop["warnings"]


def test_retry_wait_seconds():
    assert retry_wait_seconds({"x-rate-limit-reset": "1791000005"}, now=1791000000) == 6
    assert retry_wait_seconds({"x-rate-limit-reset": "1791000000"}, now=1791000100) == 1
    assert retry_wait_seconds({}) == 5
