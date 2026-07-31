BEGIN;

DO $migration$
BEGIN
    RAISE EXCEPTION
        '000002_identity_subject_model is intentionally irreversible: the old mixed role semantics cannot be reconstructed';
END;
$migration$;

COMMIT;
