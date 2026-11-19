# ElectroShorts License API

This is the private service that creates and validates ElectroShorts device-bound license keys. It is separate from the desktop engine so the Supabase server secret key and admin generation token never ship with the application.

## Deploy once

1. Create a Supabase project and run migrations [`001_license_schema.sql`](../supabase/migrations/001_license_schema.sql), [`002_shared_licenses.sql`](../supabase/migrations/002_shared_licenses.sql), [`003_device_limits.sql`](../supabase/migrations/003_device_limits.sql), then [`004_revoke_public_shared_key.sql`](../supabase/migrations/004_revoke_public_shared_key.sql) in its SQL editor. Run them in order; existing deployments run only migrations not already applied. Never reapply older migrations after 004. Migration 004 is provided for deployment; local tests do not execute it against your server.
   For a new empty project, paste the complete [`fresh_setup.sql`](../supabase/fresh_setup.sql) instead. It applies all four migrations in one transaction and finishes with readiness checks. It refuses an existing license database and creates no license keys. Deleted customer records need a backup import.
2. Deploy the `license_server` package plus generated `backend/version.py` with their parent directory as the working directory and install `license_server/requirements.txt`. Run `node scripts/version.mjs --sync` in the release checkout first to synchronize the application version.
3. Set `SUPABASE_URL`, preferred `SUPABASE_SECRET_KEY`, `LICENSE_ADMIN_TOKEN`, `LICENSE_KEY_HASH_PEPPER`, and `LICENSE_RECEIPT_PRIVATE_KEY` from [`license_server/.env.example`](.env.example). Copy the project's server-only `sb_secret_...` key from **Settings > API Keys**. A legacy `service_role` JWT may instead be supplied through `SUPABASE_SERVICE_ROLE_KEY` while that key remains enabled. Keep these secrets on the API host.
4. Start the service with `uvicorn license_server.app:app --host 0.0.0.0 --port 8787` behind HTTPS.
5. Before building the desktop release, set `license_api_url` to the deployed HTTPS base URL and `license_public_key` to the corresponding base64 raw Ed25519 public key in `backend/release-config.json`. Packaged builds read this bundled release configuration and ignore editable settings or `ELECTRO_LICENSE_API_URL`. The environment override is for source development only.

The Supabase table stores the generated key, a peppered hash, customer name and email, status, expiry, the bound device fingerprint, activation instance, timestamps, and an append-only activation event record. Row-level security denies direct client access; only the service role can call the RPC functions.

The repository sends a modern secret key only in the `apikey` header because it is not a JWT. Legacy service-role JWTs retain both `apikey` and `Authorization: Bearer` headers. A nonblank `SUPABASE_SECRET_KEY` takes precedence over the legacy variable; an invalid preferred value fails rather than silently falling back. Publishable and `anon` keys are rejected. See the [current Supabase key documentation](https://supabase.com/docs/guides/getting-started/api-keys). `/health` reports local configuration validity; `manage check` makes the actual database/RPC readiness checks.

## Generate keys

Generation requires the admin token and returns the raw key so it can be delivered to the customer. It is not returned by activation or validation.

```powershell
$body = @{ customer_name = "Ada Lovelace"; customer_email = "ada@example.com"; count = 1 } | ConvertTo-Json
Invoke-RestMethod -Method Post -Uri "https://license.electroshorts.com/v1/licenses/generate" `
  -Headers @{ "X-Admin-Token" = $env:LICENSE_ADMIN_TOKEN } -ContentType "application/json" -Body $body
```

The desktop sends the normalized key, a SHA-256 hardware fingerprint, and a local instance ID to `/v1/licenses/activate`. Normal keys allow two active hardware fingerprints. The third device returns `DEVICE_LIMIT_REACHED`. Reinstalling on an active fingerprint renews its instance without consuming another slot. Deactivating a registered device frees its slot. Validation requires that device's current instance; one device cannot deactivate another device's session.

## Signed offline receipts and verification after an update

Generate an Ed25519 signing key using a trusted administrative environment. Store its **32 raw private-key bytes encoded as base64** in `LICENSE_RECEIPT_PRIVATE_KEY` on the license server. Put only its matching **32 raw public-key bytes encoded as base64** in the desktop release configuration. Never put private signing keys, either Supabase server key, or admin tokens in the frontend, installer, release metadata, or application resources. Do not generate a development signing key as a production fallback. A missing signing key returns HTTP 503 and activation fails closed.

Activation and validation responses include a receipt whose signed claims bind the product, license-key digest, hardware fingerprint, instance ID, application version, status, expiry, issued time, and offline deadline. The deadline is at most seven days and never exceeds license expiry. Windows stores the key and receipt with user-bound DPAPI; DPAPI failures do not fall back to machine-derived AES encryption. Local `valid` flags, future activation timestamps, editable status fields, and locally edited version markers cannot grant access.

On a normal startup the desktop validates online, or uses an authentic current-version receipt during a network outage. An explicit server rejection clears the activation; service outages preserve it. License validity also expires during a running session. A new application version shows **License Verification**, automatically validates the saved key and instance for that version, then opens the studio. Its successful signed receipt becomes the authoritative `last_license_verified_app_version`; the following startup skips that page. Existing unsigned caches migrate through the same online verification without asking the customer to buy or type the key again. If an update starts offline, verification remains pending and the saved activation is preserved. Invalid/revoked licenses return to Activation.

The same Windows account retains `%APPDATA%/ElectroShorts/.license_vault` across upgrades and reinstalls when user data is preserved. A different Windows user, machine, or changed hardware may require activation again. No desktop-only design can prevent a machine administrator from patching its executable or repeatedly rolling back the system clock across reboots; production signing and controlled distribution are still required.

## Local smoke test

```powershell
python -m pip install -r license_server/requirements.txt
uvicorn license_server.app:app --env-file license_server/.env --host 127.0.0.1 --port 8787
```

For a real activation test, set the Supabase variables and apply the migration first. Do not use a Supabase server secret or service-role key in the desktop or frontend environment.

## Setup check and retirement of the public shared key

Store Supabase credentials only in the private API environment. Local automated tests do not apply anything to your Supabase account; `manage check` verifies the configured remote database. Database readiness alone does not configure receipt signing or deploy the private API.

Copy `.env.example` to `license_server/.env`, fill the values, then start with:

```powershell
.\.venv\Scripts\python.exe -m uvicorn license_server.app:app --env-file license_server/.env --host 127.0.0.1 --port 8787
```

In another terminal, verify the database and RPC functions:

```powershell
.\.venv\Scripts\python.exe -m license_server.manage check
```

The read-only [`check_license_setup.sql`](../supabase/check_license_setup.sql) checks the schema from the dashboard. `manage check` requires policy version 4, two devices per normal customer license, and zero universal grants.

The hardcoded public key `ELECTRO123456789` is compromised and invalid under the production security policy. The API rejects it with `REVOKED` on activation and validation before consulting the database, even if an older database still reports it active. `/v1/licenses/shared` returns `SHARED_LICENSE_DISABLED`; the legacy `manage seed` and `seed-sql` commands fail with instructions to issue unique random keys. There is no opt-in switch to re-enable the public grant. The frontend no longer treats that string as an accepted key.

Migration 004 revokes the known grant, releases its active device sessions, and records those releases once. Database constraints prevent reactivation of that public key and prevent unlimited grants. Existing random customer licenses, their status, keys, instance IDs, expiry, and registered devices remain intact. Customers who used the public shared key need a unique random key issued through the admin-authenticated `/v1/licenses/generate` endpoint. Retain the same `LICENSE_KEY_HASH_PEPPER` for legitimate random licenses; rotating it would invalidate their existing hashes.

Do not run the historical `003_create_shared_key.sql` seed template for a production deployment. Historical migrations 001–003 remain unchanged for migration history, and migration 004 closes their public-grant behavior. Existing signed offline receipts can reflect revocation only when online validation succeeds or their bounded offline period expires; no new receipt is issued for this key after the new API is deployed.

For local desktop testing, set its private API URL to `http://127.0.0.1:8787` only once the check succeeds. Production uses the deployed HTTPS URL. A key is not valid merely because its text is recognized: it must exist as an active record in Supabase.

SQL regression tests run in a disposable local PostgreSQL-compatible PGlite database:

```powershell
npm install --prefix build/license-sql-tests @electric-sql/pglite
node --test supabase/tests/licenses.test.mjs
```
