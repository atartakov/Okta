"""Shared Okta API client.

Auth comes from environment variables only -- never hardcode a token:

    OKTA_DOMAIN      e.g. https://dev-123456.okta.com
    OKTA_API_TOKEN   an SSWS API token (read-only is enough for auditors)
"""

from __future__ import annotations

import os
import time
import urllib.parse

import requests

DEFAULT_TIMEOUT = 30


class OktaAuthError(RuntimeError):
    """Raised when credentials are missing or rejected."""


class OktaClient:
    def __init__(self, domain: str | None = None, api_token: str | None = None):
        domain = (domain or os.environ.get("OKTA_DOMAIN") or "").rstrip("/")
        token = api_token or os.environ.get("OKTA_API_TOKEN")
        if not domain or not token:
            raise OktaAuthError(
                "Set OKTA_DOMAIN (e.g. https://dev-123456.okta.com) and "
                "OKTA_API_TOKEN environment variables."
            )
        if not domain.startswith("http"):
            domain = "https://" + domain
        self.base_url = domain
        self.session = requests.Session()
        self.session.headers.update({
            "Authorization": f"SSWS {token}",
            "Accept": "application/json",
            "Content-Type": "application/json",
            "User-Agent": "okta-ideas/0.1",
        })

    def _request(self, method: str, path: str, params: dict | None = None,
                 retries: int = 5):
        for _ in range(retries):
            resp = self.session.request(method, self.base_url + path,
                                        params=params, timeout=DEFAULT_TIMEOUT)
            if resp.status_code == 429:
                # Honor Okta's rate-limit reset header, then retry.
                wait = int(resp.headers.get("x-rate-limit-reset", "5"))
                time.sleep(max(1, min(wait, 60)) + 1)
                continue
            if resp.status_code in (401, 403):
                raise OktaAuthError(
                    f"Okta rejected the API token (HTTP {resp.status_code}). "
                    "Check OKTA_API_TOKEN and its permissions."
                )
            resp.raise_for_status()
            return resp
        raise RuntimeError("Okta rate limit persisted after retries; try again later.")

    def paged_get(self, path: str, params: dict | None = None):
        """Yield items across all pages (Okta `after` cursor via Link header)."""
        params = dict(params or {})
        params.setdefault("limit", 200)
        next_url = self.base_url + path
        first = True
        while next_url:
            if first:
                resp = self._request("GET", path, params=params)
                first = False
            else:
                # Follow-up URLs already carry their query string.
                parsed = urllib.parse.urlparse(next_url)
                resp = self._request(
                    "GET", parsed.path,
                    params=dict(urllib.parse.parse_qsl(parsed.query)))
            for item in resp.json():
                yield item
            next_url = resp.links.get("next", {}).get("url")

    # ---- convenience wrappers ----

    def list_users(self, status: str = "ACTIVE"):
        params = {}
        if status:
            params["filter"] = f'status eq "{status}"'
        return self.paged_get("/api/v1/users", params)

    def list_factors(self, user_id: str) -> list:
        return list(self.paged_get(f"/api/v1/users/{user_id}/factors"))
