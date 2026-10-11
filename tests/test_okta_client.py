"""Tests for lib/okta_client.py rate-limit handling (offline)."""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from lib import okta_client  # noqa: E402
from lib.okta_client import OktaClient, retry_wait_seconds  # noqa: E402

NOW = 1_791_000_000  # an epoch second in 2026
DATE = "Sun, 11 Oct 2026 08:40:00 GMT"
DATE_EPOCH = 1_791_708_000


def test_epoch_reset_measured_from_now():
    assert retry_wait_seconds({"x-rate-limit-reset": str(NOW + 3)}, now=NOW) == 4


def test_reset_already_passed_waits_one_second():
    assert retry_wait_seconds({"x-rate-limit-reset": str(NOW - 10)}, now=NOW) == 1


def test_far_future_reset_capped():
    assert retry_wait_seconds({"x-rate-limit-reset": str(NOW + 600)}, now=NOW) == 61


def test_uses_okta_date_header_not_local_clock():
    h = {"x-rate-limit-reset": str(DATE_EPOCH + 2), "date": DATE}
    assert retry_wait_seconds(h) == 3


def test_missing_or_garbage_header_defaults_to_five():
    assert retry_wait_seconds({}) == 5
    assert retry_wait_seconds({"x-rate-limit-reset": "soon"}) == 5


def test_small_value_treated_as_duration():
    assert retry_wait_seconds({"x-rate-limit-reset": "7"}) == 8


class FakeResp:
    def __init__(self, status, headers=None, body=None):
        self.status_code = status
        self.headers = headers or {}
        self._body = body if body is not None else []
        self.links = {}

    def json(self):
        return self._body

    def raise_for_status(self):
        pass


def test_429_then_success_sleeps_until_reset(monkeypatch):
    c = OktaClient("https://example.okta.com", "x")
    resps = [FakeResp(429, {"x-rate-limit-reset": str(DATE_EPOCH + 2), "date": DATE}),
             FakeResp(200, body=[{"id": 1}])]
    monkeypatch.setattr(c.session, "request", lambda *a, **k: resps.pop(0))
    slept = []
    monkeypatch.setattr(okta_client.time, "sleep", slept.append)
    assert c._request("GET", "/api/v1/users").json() == [{"id": 1}]
    assert slept == [3]
