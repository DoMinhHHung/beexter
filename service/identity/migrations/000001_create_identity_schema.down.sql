BEGIN;

DROP TABLE identity.outbox_events;
DROP TABLE identity.login_attempts;
DROP TABLE identity.password_reset_tokens;
DROP TABLE identity.email_verification_tokens;
DROP TABLE identity.identities;

DROP SCHEMA identity;

COMMIT;