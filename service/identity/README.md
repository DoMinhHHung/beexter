# Beexster Identity Service

The Identity Service owns credentials, authentication sessions, and the optional
platform-wide administrative role. Ordinary authenticated requests verify access
tokens locally. Account deletion, disablement, or role changes can therefore remain
visible in an already-issued token for at most the access-token lifetime. Privileged
identity creation rechecks and locks the actor row in the same PostgreSQL transaction
as the insert.

## JWT signing-key rotation

`JWT_KEY_ID` and `JWT_PRIVATE_KEY_PATH` identify the active RSA key. Only that private
key signs new access tokens. Additional verification-only keys are configured as a
strict JSON array:

```dotenv
JWT_ADDITIONAL_PUBLIC_KEYS='[{"kid":"identity-2026-06","public_key_path":"./identity-2026-06-public.pem"}]'
```

Unset, blank, or `[]` means there are no additional keys. Each `kid` must be unique
and must not equal `JWT_KEY_ID`. Additional files must contain a single RSA public
key, never a private key. Configuration and key files are loaded once at startup;
invalid configuration prevents the service from starting.

Use this rotation sequence:

1. Generate the replacement key outside the repository and protect its private
   material. Keep the current key active.
2. Add the replacement public key to `JWT_ADDITIONAL_PUBLIC_KEYS`, deploy, and wait
   at least the JWKS cache lifetime (currently 300 seconds) so verifiers can observe
   it.
3. Make the replacement `kid` and private key active. In the same deployment,
   remove the replacement from the additional list and add the old active public
   key to that list. Duplicate `kid` values fail startup.
4. Keep the old public key available for at least:

   ```text
   access-token TTL + JWKS cache TTL + allowed clock skew
   ```

   With the defaults, this is 15 minutes + 5 minutes + 30 seconds = **20 minutes
   30 seconds** after the new signing key becomes active. Remove the old public key
   only after that interval has elapsed.

This is a restart-based operational procedure. There is no hot reload or dynamic
key-management control plane.

## Forward-only subject-model migration

`000002_refactor_identity_subject_model` replaces the mixed `role` column with the
nullable administrative `platform_role`. It intentionally maps `CLIENT`,
`JOB_SEEKER`, and `AGENCY` to `NULL`, then removes information that cannot be
reconstructed accurately. Its down migration therefore fails explicitly.

This migration is **not rollback-safe and is not a zero-downtime migration**:

1. Schedule a coordinated deployment window and stop old Identity writers.
2. Back up the database and verify that the backup can be restored before applying
   the migration to an environment containing real data.
3. Apply `000001` and then `000002` where needed, and deploy the new Identity binary.
   A binary that still reads or writes `role` cannot run after `000002`.
4. Verify Identity health, authentication, and privileged identity creation before
   reopening traffic.
5. If deployment must be reversed, restore the database backup and the old binary.
   Do not run the `000002` down migration or infer discarded business roles.

The project is currently pre-production. Fresh database creation or reset is
acceptable for disposable local, test, and preview environments.

## Integration tests

Tagged integration tests reset the `identity` schema, apply migrations `000001` and
`000002`, and exercise PostgreSQL repositories plus the Redis-backed lifecycle. For
safety, destructive setup refuses to run unless the connected database is named
exactly `identity_test`.

```bash
IDENTITY_INTEGRATION_TEST=1 \
DATABASE_DIRECT_URL='postgres://postgres:postgres@127.0.0.1:5432/identity_test?sslmode=disable' \
REDIS_ADDR='127.0.0.1:6379' \
REDIS_DB=15 \
go test -tags=integration -count=1 ./internal/integration
```

Use only isolated, disposable PostgreSQL and Redis instances. In CI, missing opt-in
or dependency configuration is a hard failure rather than a skipped test.
