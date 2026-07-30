BEGIN;

CREATE SCHEMA identity;

CREATE TABLE identity.identities (
    id uuid PRIMARY KEY,
    email text NOT NULL,
    password_hash text NOT NULL,
    role text NOT NULL,
    status text NOT NULL DEFAULT 'active',
    email_verified_at timestamptz,
    soft_delete_count smallint NOT NULL DEFAULT 0,
    created_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    deleted_at timestamptz,

    CONSTRAINT identities_email_unique
        UNIQUE (email),

    CONSTRAINT identities_email_not_blank_check
        CHECK (char_length(email) > 0),

    CONSTRAINT identities_email_length_check
        CHECK (char_length(email) <= 254),

    CONSTRAINT identities_email_normalized_check
        CHECK (
            email = lower(email)
            AND email = btrim(email)
        ),

    CONSTRAINT identities_password_hash_not_blank_check
        CHECK (char_length(password_hash) > 0),

    CONSTRAINT identities_password_hash_algorithm_check
        CHECK (password_hash LIKE '$argon2id$%'),

    CONSTRAINT identities_role_check
        CHECK (
            role IN (
                'CLIENT',
                'JOB_SEEKER',
                'AGENCY',
                'ADMIN',
                'VICE_ADMIN'
            )
        ),

    CONSTRAINT identities_status_check
        CHECK (
            status IN (
                'active',
                'inactive'
            )
        ),

    CONSTRAINT identities_soft_delete_count_check
        CHECK (
            soft_delete_count BETWEEN 0 AND 3
        ),

    CONSTRAINT identities_deleted_status_check
        CHECK (
            deleted_at IS NULL
            OR status = 'inactive'
        ),

    CONSTRAINT identities_updated_at_check
        CHECK (
            updated_at >= created_at
        ),

    CONSTRAINT identities_email_verified_at_check
        CHECK (
            email_verified_at IS NULL
            OR email_verified_at >= created_at
        )
);

CREATE TABLE identity.email_verification_tokens (
    id uuid PRIMARY KEY,
    identity_id uuid NOT NULL,
    expires_at timestamptz NOT NULL,
    used_at timestamptz,
    revoked_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT email_verification_tokens_identity_fk
        FOREIGN KEY (identity_id)
        REFERENCES identity.identities (id)
        ON DELETE CASCADE,

    CONSTRAINT email_verification_tokens_expiry_check
        CHECK (
            expires_at > created_at
        ),

    CONSTRAINT email_verification_tokens_used_at_check
        CHECK (
            used_at IS NULL
            OR used_at >= created_at
        ),

    CONSTRAINT email_verification_tokens_revoked_at_check
        CHECK (
            revoked_at IS NULL
            OR revoked_at >= created_at
        ),

    CONSTRAINT email_verification_tokens_terminal_state_check
        CHECK (
            NOT (
                used_at IS NOT NULL
                AND revoked_at IS NOT NULL
            )
        )
);

CREATE UNIQUE INDEX
    email_verification_tokens_one_active_per_identity_uidx
ON identity.email_verification_tokens (identity_id)
WHERE used_at IS NULL
  AND revoked_at IS NULL;

CREATE INDEX email_verification_tokens_expires_at_idx
ON identity.email_verification_tokens (expires_at);

CREATE TABLE identity.password_reset_tokens (
    id uuid PRIMARY KEY,
    identity_id uuid NOT NULL,
    expires_at timestamptz NOT NULL,
    used_at timestamptz,
    revoked_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT password_reset_tokens_identity_fk
        FOREIGN KEY (identity_id)
        REFERENCES identity.identities (id)
        ON DELETE CASCADE,

    CONSTRAINT password_reset_tokens_expiry_check
        CHECK (
            expires_at > created_at
        ),

    CONSTRAINT password_reset_tokens_used_at_check
        CHECK (
            used_at IS NULL
            OR used_at >= created_at
        ),

    CONSTRAINT password_reset_tokens_revoked_at_check
        CHECK (
            revoked_at IS NULL
            OR revoked_at >= created_at
        ),

    CONSTRAINT password_reset_tokens_terminal_state_check
        CHECK (
            NOT (
                used_at IS NOT NULL
                AND revoked_at IS NOT NULL
            )
        )
);

CREATE UNIQUE INDEX
    password_reset_tokens_one_active_per_identity_uidx
ON identity.password_reset_tokens (identity_id)
WHERE used_at IS NULL
  AND revoked_at IS NULL;

CREATE INDEX password_reset_tokens_expires_at_idx
ON identity.password_reset_tokens (expires_at);

CREATE TABLE identity.login_attempts (
    id uuid PRIMARY KEY,
    identity_id uuid,
    email text NOT NULL,
    success boolean NOT NULL,
    failure_code text,
    ip_address inet NOT NULL,
    user_agent text NOT NULL,
    request_id text NOT NULL,
    attempted_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT login_attempts_identity_fk
        FOREIGN KEY (identity_id)
        REFERENCES identity.identities (id)
        ON DELETE SET NULL,

    CONSTRAINT login_attempts_email_not_blank_check
        CHECK (char_length(email) > 0),

    CONSTRAINT login_attempts_email_length_check
        CHECK (char_length(email) <= 254),

    CONSTRAINT login_attempts_email_normalized_check
        CHECK (
            email = lower(email)
            AND email = btrim(email)
        ),

    CONSTRAINT login_attempts_user_agent_not_blank_check
        CHECK (char_length(user_agent) > 0),

    CONSTRAINT login_attempts_request_id_not_blank_check
        CHECK (char_length(request_id) > 0),

    CONSTRAINT login_attempts_result_check
        CHECK (
            (
                success = true
                AND failure_code IS NULL
            )
            OR
            (
                success = false
                AND failure_code IS NOT NULL
                AND char_length(btrim(failure_code)) > 0
            )
        )
);

CREATE INDEX login_attempts_identity_attempted_at_idx
ON identity.login_attempts (
    identity_id,
    attempted_at DESC
)
WHERE identity_id IS NOT NULL;

CREATE INDEX login_attempts_attempted_at_idx
ON identity.login_attempts (attempted_at);

CREATE TABLE identity.outbox_events (
    id uuid PRIMARY KEY,
    aggregate_id uuid NOT NULL,
    event_type text NOT NULL,
    payload jsonb NOT NULL,
    attempt_count integer NOT NULL DEFAULT 0,
    available_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    locked_at timestamptz,
    lock_id uuid,
    processed_at timestamptz,
    last_error text,
    created_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT outbox_events_event_type_check
        CHECK (
            event_type IN (
                'identity.email_verification_requested',
                'identity.password_reset_requested'
            )
        ),

    CONSTRAINT outbox_events_payload_object_check
        CHECK (
            jsonb_typeof(payload) = 'object'
        ),

    CONSTRAINT outbox_events_attempt_count_check
        CHECK (
            attempt_count >= 0
        ),

    CONSTRAINT outbox_events_available_at_check
        CHECK (
            available_at >= created_at
        ),

    CONSTRAINT outbox_events_lock_pair_check
        CHECK (
            (
                locked_at IS NULL
                AND lock_id IS NULL
            )
            OR
            (
                locked_at IS NOT NULL
                AND lock_id IS NOT NULL
            )
        ),

    CONSTRAINT outbox_events_processed_at_check
        CHECK (
            processed_at IS NULL
            OR processed_at >= created_at
        ),

    CONSTRAINT outbox_events_processed_lock_check
        CHECK (
            processed_at IS NULL
            OR (
                locked_at IS NULL
                AND lock_id IS NULL
            )
        )
);

CREATE INDEX outbox_events_dispatch_idx
ON identity.outbox_events (
    available_at,
    created_at
)
WHERE processed_at IS NULL;

COMMIT;