"""Small Supabase PostgREST client used by the private license API."""
from __future__ import annotations

import base64
import json
import os
import re
from typing import Any, Dict

import httpx


class SupabaseError(RuntimeError):
    """A controlled Supabase request failure."""


def _legacy_bearer_required(key: str) -> bool:
    if re.fullmatch(r"sb_secret_[A-Za-z0-9_-]+", key):
        return False
    if re.fullmatch(r"[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+", key):
        try:
            payload = key.split(".")[1]
            claims = json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))
            if isinstance(claims, dict) and claims.get("role") == "service_role":
                # Local format/role sanity only: Supabase remains responsible
                # for authenticating the legacy JWT's signature.
                return True
        except (ValueError, TypeError):
            pass
    raise SupabaseError("Supabase requires a server secret key or legacy service-role JWT; publishable/anon keys are not permitted.")


class SupabaseLicenseRepository:
    """Server-only repository with service-role privileges.

    The server key is read by this process and is never sent to the
    desktop client. Mutating activation operations use Postgres RPC functions
    from the migration so the row lock and device check are atomic.
    """

    def __init__(self, url: str, service_role_key: str, timeout: float = 15.0):
        self.url = url.strip().rstrip("/")
        key = service_role_key.strip()
        legacy_bearer = _legacy_bearer_required(key)
        self.service_role_key = key
        self.timeout = timeout
        self._headers = {
            "apikey": key,
            "Accept": "application/json",
            "Content-Type": "application/json",
        }
        if legacy_bearer:
            self._headers["Authorization"] = f"Bearer {key}"

    @classmethod
    def from_env(cls) -> "SupabaseLicenseRepository":
        url = os.environ.get("SUPABASE_URL", "").strip().strip("\"'").strip()
        key = (os.environ.get("SUPABASE_SECRET_KEY", "").strip().strip("\"'").strip()
               or os.environ.get("SUPABASE_SERVICE_ROLE_KEY", "").strip().strip("\"'").strip())
        if not url or not key:
            raise SupabaseError("SUPABASE_URL and SUPABASE_SECRET_KEY (or legacy SUPABASE_SERVICE_ROLE_KEY) must be configured.")
        return cls(url, key)

    @classmethod
    def is_configured(cls) -> bool:
        try:
            cls.from_env()
            return True
        except SupabaseError:
            return False

    def _request(self, method: str, path: str, **kwargs: Any) -> Any:
        headers = dict(self._headers)
        headers.update(kwargs.pop("headers", {}) or {})
        try:
            response = httpx.request(method, f"{self.url}/rest/v1/{path.lstrip('/')}", headers=headers, timeout=self.timeout, **kwargs)
        except httpx.HTTPError:
            raise SupabaseError("Supabase network request failed; check server connectivity and configuration.") from None
        try:
            payload = response.json()
        except ValueError:
            payload = {}
        if response.status_code >= 400:
            # Remote database/error text can contain keys or customer data.
            raise SupabaseError(f"Supabase returned HTTP {response.status_code}; check server credentials, permissions and migrations.")
        return payload

    def insert_license(self, row: Dict[str, Any]) -> Dict[str, Any]:
        payload = self._request("POST", "licenses", json=row, headers={"Prefer": "return=representation"})
        if not isinstance(payload, list) or not payload:
            raise SupabaseError("Supabase did not return the created license.")
        return dict(payload[0])

    def activate(self, **values: Any) -> Dict[str, Any]:
        payload = self._request("POST", "rpc/activate_license", json={f"p_{key}": value for key, value in values.items()})
        return dict(payload or {})

    def validate(self, **values: Any) -> Dict[str, Any]:
        payload = self._request("POST", "rpc/validate_license", json={f"p_{key}": value for key, value in values.items()})
        return dict(payload or {})

    def deactivate(self, **values: Any) -> Dict[str, Any]:
        payload = self._request("POST", "rpc/deactivate_license", json={f"p_{key}": value for key, value in values.items()})
        return dict(payload or {})

