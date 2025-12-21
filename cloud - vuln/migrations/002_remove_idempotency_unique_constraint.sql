-- =============================================================================
-- Migration: Remove UNIQUE constraint from idempotency_key
-- =============================================================================
-- File: 002_remove_idempotency_unique_constraint.sql
-- Purpose: Allow multiple scans of the same container/image
-- Run this AFTER the initial schema if your database already exists
-- =============================================================================

\echo 'Removing UNIQUE constraint from vulnerability_scans.idempotency_key...'

-- Drop the unique constraint on idempotency_key if it exists
-- This allows the same container/image to be scanned multiple times
DO $$
BEGIN
    -- Try to drop the constraint - PostgreSQL will handle if it doesn't exist
    BEGIN
        ALTER TABLE vulnerability_scans 
        DROP CONSTRAINT IF EXISTS vulnerability_scans_idempotency_key_key;
        RAISE NOTICE 'Successfully removed UNIQUE constraint from idempotency_key';
    EXCEPTION 
        WHEN others THEN
            RAISE NOTICE 'UNIQUE constraint on idempotency_key may not exist or already removed: %', SQLERRM;
    END;
END $$;

-- Update the comment to reflect the new behavior
COMMENT ON COLUMN vulnerability_scans.idempotency_key IS 'Hash of (image_name + tag + timestamp_bucket) for optional deduplication (no longer enforced as unique)';

-- Verify the constraint is removed
SELECT conname, contype
FROM pg_constraint
WHERE conrelid = 'vulnerability_scans'::regclass 
AND conname LIKE '%idempotency%';

\echo 'Migration complete. Multiple scans of the same image are now allowed.'