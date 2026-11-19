"""License-key formatting and hashing helpers.

The raw key is returned only once by the admin generation endpoint. Validation
uses the normalized key hash, so a key can be checked without putting a raw
customer key in application logs or response payloads.
"""
from __future__ import annotations

import hashlib
import os
import re
import secrets


KEY_LENGTH = 16
KEY_GROUP_LENGTH = 4
KEY_GROUPS = 4
SHARED_LICENSE_KEY = "ELECTRO123456789"
KEY_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
_KEY_RE = re.compile(r"^[A-Z0-9]{4}(?:-[A-Z0-9]{4}){3}$")


class InvalidLicenseKey(ValueError):
    """Raised when a supplied key is malformed."""


def normalize_license_key(value: str) -> str:
    """Return a canonical ``XXXX-XXXX-XXXX-XXXX`` key or raise."""
    compact = re.sub(r"[\s-]", "", str(value or "").upper())
    # Kept recognizable only so the API can return authoritative REVOKED to
    # historical clients and clear their cached grant. It cannot be issued.
    if compact == SHARED_LICENSE_KEY:
        return compact
    if len(compact) != KEY_LENGTH or any(char not in KEY_ALPHABET for char in compact):
        raise InvalidLicenseKey("License key must contain four groups of four characters.")
    normalized = "-".join(
        compact[offset : offset + KEY_GROUP_LENGTH]
        for offset in range(0, KEY_LENGTH, KEY_GROUP_LENGTH)
    )
    if not _KEY_RE.fullmatch(normalized):
        raise InvalidLicenseKey("License key format is invalid.")
    return normalized


def generate_license_key() -> str:
    """Generate a printable key with ambiguous characters excluded."""
    raw = "".join(secrets.choice(KEY_ALPHABET) for _ in range(KEY_LENGTH))
    return "-".join(raw[offset : offset + KEY_GROUP_LENGTH] for offset in range(0, KEY_LENGTH, KEY_GROUP_LENGTH))


def hash_license_key(value: str) -> str:
    """Hash a canonical key with an optional server-only pepper."""
    normalized = normalize_license_key(value)
    pepper = os.environ.get("LICENSE_KEY_HASH_PEPPER", "")
    return hashlib.sha256(f"{pepper}\0{normalized}".encode("utf-8")).hexdigest()


def key_last4(value: str) -> str:
    return normalize_license_key(value).replace("-", "")[-4:]
