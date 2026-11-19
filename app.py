"""Private ElectroShorts license-key API.

Run with::

    uvicorn license_server.app:app --host 0.0.0.0 --port 8787

Only this service knows the Supabase server secret key. The desktop engine
receives a short JSON result and never receives database credentials.
"""
from __future__ import annotations

import hmac
import os
from datetime import datetime, timezone
from typing import Any, Dict, Optional

from fastapi import FastAPI, Header, HTTPException, Request
from pydantic import BaseModel, Field, field_validator
from backend.version import APP_VERSION

from .key_utils import InvalidLicenseKey, SHARED_LICENSE_KEY, generate_license_key, hash_license_key, key_last4, normalize_license_key
from .supabase_client import SupabaseError, SupabaseLicenseRepository
from .receipts import signing_key, sign_receipt


app = FastAPI(title="ElectroShorts License API", version=APP_VERSION, docs_url=None, redoc_url=None, openapi_url=None)
_repository: Optional[SupabaseLicenseRepository] = None


def _repo() -> SupabaseLicenseRepository:
    global _repository
    if _repository is None:
        _repository = SupabaseLicenseRepository.from_env()
    return _repository


def _utc(value: Optional[datetime]) -> Optional[str]:
    if value is None:
        return None
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc).isoformat()


def _admin_guard(authorization: Optional[str], x_admin_token: Optional[str]) -> None:
    expected = os.environ.get("LICENSE_ADMIN_TOKEN", "").strip()
    if not expected:
        raise HTTPException(status_code=503, detail="License admin token is not configured.")
    supplied = x_admin_token or ""
    if not supplied and authorization and authorization.lower().startswith("bearer "):
        supplied = authorization[7:].strip()
    if not supplied or not hmac.compare_digest(supplied, expected):
        raise HTTPException(status_code=401, detail="Admin authentication required.")


def _request_context(request: Request) -> Dict[str, str]:
    return {
        "ip": request.client.host if request.client else "",
        "user_agent": request.headers.get("user-agent", "")[:500],
    }


def _result_or_error(result: Dict[str, Any], *, action: str, valid: bool = True) -> Dict[str, Any]:
    if result.get("ok") is True:
        return {"valid": valid, "license": result.get("license") or {}}
    code = str(result.get("code") or "INVALID_LICENSE")
    messages = {
        "NOT_FOUND": "License key not recognised.",
        "DEVICE_MISMATCH": "This device has no active registration for this license key. Activate it first.",
        "DEVICE_LIMIT_REACHED": "This license key is already active on two devices. Deactivate one device before activating another.",
        "REVOKED": "This license key has been revoked.",
        "EXPIRED": "This license key has expired.",
        "INSTANCE_MISMATCH": "The license activation instance is invalid.",
    }
    status = 409 if code in {"DEVICE_MISMATCH", "INSTANCE_MISMATCH", "DEVICE_LIMIT_REACHED"} else 400
    raise HTTPException(status_code=status, detail={"error": code, "message": messages.get(code, f"License {action} was rejected.")})


class GenerateRequest(BaseModel):
    customer_name: str = Field(min_length=1, max_length=200)
    customer_email: str = Field(min_length=3, max_length=320)
    expires_at: Optional[datetime] = None
    count: int = Field(default=1, ge=1, le=100)
    metadata: Dict[str, Any] = Field(default_factory=dict)

    @field_validator("customer_email")
    @classmethod
    def valid_email(cls, value: str) -> str:
        value = value.strip().lower()
        if "@" not in value or value.startswith("@") or value.endswith("@"):
            raise ValueError("customer_email must be a valid email address")
        return value


class DeviceRequest(BaseModel):
    license_key: str = Field(min_length=1, max_length=64)
    device_fingerprint: str = Field(pattern=r"^[a-fA-F0-9]{64}$")
    instance_id: str = Field(min_length=8, max_length=128)
    app_version: str = Field(default=APP_VERSION, pattern=r"^\d+\.\d+\.\d+$", max_length=64)

    @field_validator("license_key")
    @classmethod
    def valid_key(cls, value: str) -> str:
        try:
            return normalize_license_key(value)
        except InvalidLicenseKey as exc:
            raise ValueError(str(exc)) from exc


@app.post("/v1/licenses/shared")
def create_shared_license(
    payload: GenerateRequest,
    authorization: Optional[str] = Header(default=None),
    x_admin_token: Optional[str] = Header(default=None),
) -> Dict[str, Any]:
    """Retained route returns a clear error for obsolete provisioning tools."""
    _admin_guard(authorization, x_admin_token)
    raise HTTPException(status_code=410, detail={"error": "SHARED_LICENSE_DISABLED", "message": "Public shared licenses are disabled. Issue unique random customer keys through /v1/licenses/generate."})


def _reject_public_license(payload: DeviceRequest) -> None:
    # The published shared key is compromised, even if an old database still
    # reports it active. Recognizing its text never grants an activation.
    if payload.license_key == SHARED_LICENSE_KEY:
        raise HTTPException(status_code=400, detail={"error": "REVOKED", "message": "This publicly known shared license has been revoked. Contact the publisher for a unique customer license key."})


@app.get("/health")
def health() -> Dict[str, Any]:
    return {
        "status": "ok",
        "service": "electroshorts-license-api",
        "supabase_configured": SupabaseLicenseRepository.is_configured(),
    }


@app.post("/v1/licenses/generate")
def generate_license(
    payload: GenerateRequest,
    authorization: Optional[str] = Header(default=None),
    x_admin_token: Optional[str] = Header(default=None),
) -> Dict[str, Any]:
    _admin_guard(authorization, x_admin_token)
    created = []
    try:
        for _ in range(payload.count):
            key = generate_license_key()
            created_row = _repo().insert_license(
                {
                    "license_key": key,
                    "key_hash": hash_license_key(key),
                    "key_last4": key_last4(key),
                    "customer_name": payload.customer_name.strip(),
                    "customer_email": payload.customer_email,
                    "status": "active",
                    "is_universal": False,
                    "expires_at": _utc(payload.expires_at),
                    "metadata": payload.metadata,
                }
            )
            created.append(
                {
                    "id": created_row.get("id"),
                    "license_key": key,
                    "customer_name": created_row.get("customer_name", payload.customer_name.strip()),
                    "customer_email": created_row.get("customer_email", payload.customer_email),
                    "status": created_row.get("status", "active"),
                    "expires_at": created_row.get("expires_at"),
                }
            )
    except SupabaseError as exc:
        raise HTTPException(status_code=502, detail={"error": "LICENSE_STORE_ERROR", "message": "License storage is temporarily unavailable."}) from exc
    return {"licenses": created}


@app.post("/v1/licenses/activate")
def activate_license(payload: DeviceRequest, request: Request) -> Dict[str, Any]:
    _reject_public_license(payload)
    try:
        key = signing_key()
    except RuntimeError as exc:
        raise HTTPException(status_code=503, detail="License verification signing is not configured.") from exc
    context = _request_context(request)
    try:
        result = _repo().activate(
            key_hash=hash_license_key(payload.license_key),
            device_fingerprint=payload.device_fingerprint.lower(),
            instance_id=payload.instance_id,
            ip=context["ip"],
            user_agent=context["user_agent"],
        )
    except SupabaseError as exc:
        raise HTTPException(status_code=502, detail={"error": "LICENSE_STORE_ERROR", "message": "License storage is temporarily unavailable."}) from exc
    response = _result_or_error(result, action="activation")
    try:
        response["receipt"] = sign_receipt(response["license"], payload, key)
    except (ValueError, TypeError) as exc:
        raise HTTPException(status_code=502, detail="License store returned invalid activation data.") from exc
    return response


@app.post("/v1/licenses/validate")
def validate_license(payload: DeviceRequest, request: Request) -> Dict[str, Any]:
    _reject_public_license(payload)
    try:
        key = signing_key()
    except RuntimeError as exc:
        raise HTTPException(status_code=503, detail="License verification signing is not configured.") from exc
    context = _request_context(request)
    try:
        result = _repo().validate(
            key_hash=hash_license_key(payload.license_key),
            device_fingerprint=payload.device_fingerprint.lower(),
            instance_id=payload.instance_id,
            ip=context["ip"],
            user_agent=context["user_agent"],
        )
    except SupabaseError as exc:
        raise HTTPException(status_code=502, detail={"error": "LICENSE_STORE_ERROR", "message": "License storage is temporarily unavailable."}) from exc
    response = _result_or_error(result, action="validation")
    try:
        response["receipt"] = sign_receipt(response["license"], payload, key)
    except (ValueError, TypeError) as exc:
        raise HTTPException(status_code=502, detail="License store returned invalid validation data.") from exc
    return response


@app.post("/v1/licenses/deactivate")
def deactivate_license(payload: DeviceRequest, request: Request) -> Dict[str, Any]:
    context = _request_context(request)
    try:
        result = _repo().deactivate(
            key_hash=hash_license_key(payload.license_key),
            device_fingerprint=payload.device_fingerprint.lower(),
            instance_id=payload.instance_id,
            ip=context["ip"],
            user_agent=context["user_agent"],
        )
    except SupabaseError as exc:
        raise HTTPException(status_code=502, detail={"error": "LICENSE_STORE_ERROR", "message": "License storage is temporarily unavailable."}) from exc
    return _result_or_error(result, action="deactivation", valid=False)
