BEGIN;

ALTER TABLE identity.identities
    ADD COLUMN platform_role text;

UPDATE identity.identities
SET platform_role = CASE role
    WHEN 'ADMIN' THEN 'ADMIN'
    WHEN 'VICE_ADMIN' THEN 'VICE_ADMIN'
    WHEN 'CLIENT' THEN NULL
    WHEN 'JOB_SEEKER' THEN NULL
    WHEN 'AGENCY' THEN NULL
END;

ALTER TABLE identity.identities
    ADD CONSTRAINT identities_platform_role_check
        CHECK (
            platform_role IS NULL
            OR platform_role IN (
                'ADMIN',
                'VICE_ADMIN'
            )
        );

ALTER TABLE identity.identities
    DROP CONSTRAINT identities_role_check;

ALTER TABLE identity.identities
    DROP COLUMN role;

COMMENT ON COLUMN identity.identities.platform_role IS
    'Platform-wide administrative privilege; NULL for ordinary identities.';

COMMIT;
