"""Ed25519 offline receipts. The private key exists only on the API host."""
from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import time
from datetime import datetime, timezone
from typing import Any, Dict

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

OFFLINE_SECONDS = 7 * 86400


def signing_key() -> Ed25519PrivateKey:
    encoded = os.environ.get("LICENSE_RECEIPT_PRIVATE_KEY", "").strip().strip("\"'").strip()
    if not encoded:
        raise RuntimeError("LICENSE_RECEIPT_PRIVATE_KEY environment variable is empty.")
    try:
        raw = base64.b64decode(encoded, validate=False)
        if len(raw) != 32:
            raise ValueError(f"Key length is {len(raw)} bytes, expected 32 bytes.")
        return Ed25519PrivateKey.from_private_bytes(raw)
    except Exception as exc:
        raise RuntimeError(f"License receipt signing key is invalid: {exc}") from exc


def sign_receipt(license_data: Dict[str, Any], device: Any, key: Ed25519PrivateKey) -> Dict[str, str]:
    now = int(time.time())
    offline_until = now + OFFLINE_SECONDS
    expiry = license_data.get("expires_at") or ""
    if expiry:
        parsed = datetime.fromisoformat(str(expiry).replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        offline_until = min(offline_until, parsed.timestamp())
    if license_data.get("status") != "active" or offline_until <= now:
        raise ValueError("Cannot issue a receipt for an inactive or expired license.")
    compact = re.sub(r"[\s-]", "", device.license_key.upper())
    claims = {
        "v": 1,
        "product": "ElectroShorts",
        "app_version": device.app_version,
        "license_id": str(license_data.get("id") or ""),
        "key_digest": hashlib.sha256(compact.encode("utf-8")).hexdigest(),
        "fingerprint_id": device.device_fingerprint.lower(),
        "instance_id": device.instance_id,
        "status": "active",
        "customer_email": str(license_data.get("customer_email") or ""),
        "customer_name": str(license_data.get("customer_name") or ""),
        "key_last4": str(license_data.get("key_last4") or ""),
        "expires_at": str(expiry),
        "issued_at": now,
        "offline_until": offline_until,
    }
    raw = json.dumps(claims, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    return {"payload": base64.b64encode(raw).decode("ascii"), "signature": base64.b64encode(key.sign(raw)).decode("ascii")}
