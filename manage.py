"""Run from the repository root: python -m license_server.manage --help."""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path

from dotenv import load_dotenv

try:
    from .supabase_client import SupabaseError, SupabaseLicenseRepository
except ImportError:
    from supabase_client import SupabaseError, SupabaseLicenseRepository

DISABLED_SHARED_MESSAGE = "Public shared-license provisioning is disabled. Issue unique random customer keys through the admin-authenticated /v1/licenses/generate endpoint."

def shared_row(name: str, email: str) -> dict:
    raise ValueError(DISABLED_SHARED_MESSAGE)


def seed_sql(row: dict) -> str:
    raise ValueError(DISABLED_SHARED_MESSAGE)


def check(repo: SupabaseLicenseRepository) -> dict:
    repo._request("GET", "licenses", params={"select": "id,is_universal", "limit": "0"})
    repo._request("GET", "license_devices", params={"select": "license_id", "limit": "0"})
    policy = repo._request("POST", "rpc/license_policy", json={})
    if policy != {"schema_version": 4, "normal_device_limit": 2, "universal_device_limit": 0}:
        raise SupabaseError("Apply migrations through 004_revoke_public_shared_key.sql to revoke the compromised public grant and enable production device limits.")
    for action in (repo.activate, repo.validate, repo.deactivate):
        result = action(key_hash="readiness-probe-not-a-license-hash", device_fingerprint="0" * 64,
                        instance_id="readiness-probe", ip="", user_agent="readiness-probe")
        if result != {"ok": False, "code": "NOT_FOUND"}:
            raise SupabaseError("License RPC check failed")
    return {"connected": True, "schema_and_rpcs": "ready", **policy}


def main() -> int:
    parser = argparse.ArgumentParser(description="Check Supabase production licensing readiness.")
    parser.add_argument("--env-file", default=str(Path(__file__).with_name(".env")))
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("check")
    for command in ("seed", "seed-sql"):
        sub = commands.add_parser(command)
        sub.add_argument("--name", required=True)
        sub.add_argument("--email", required=True)
        if command == "seed-sql":
            sub.add_argument("--output", required=True)
    args = parser.parse_args()
    if args.command in {"seed", "seed-sql"}:
        print(json.dumps({"ready": False, "error": DISABLED_SHARED_MESSAGE}))
        return 1
    load_dotenv(args.env_file, override=False)
    try:
        if args.command == "check":
            names = ("SUPABASE_URL", "LICENSE_ADMIN_TOKEN")
            missing = [name for name in names if not os.environ.get(name, "").strip()]
            if not (os.environ.get("SUPABASE_SECRET_KEY", "").strip()
                    or os.environ.get("SUPABASE_SERVICE_ROLE_KEY", "").strip()):
                missing.append("SUPABASE_SECRET_KEY (or legacy SUPABASE_SERVICE_ROLE_KEY)")
            if missing:
                print(json.dumps({"ready": False, "missing": missing}))
                return 1
            print(json.dumps(check(SupabaseLicenseRepository.from_env())))
    except (SupabaseError, ValueError, OSError) as exc:
        print(json.dumps({"ready": False, "error": str(exc)}))
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
