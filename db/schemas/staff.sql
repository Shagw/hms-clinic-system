Looking at the existing schema, I can see:
- `clinics` table exists with `id` (UUID) and soft-delete pattern
- `roles` table exists from RBAC schema
- `user_clinic_roles` table already links users to clinics/roles
- Naming convention: snake_case, UUID PKs, `deleted_at` soft-delete, audit fields

I'll create migration `003_create_users_staff_schema.sql` that integrates cleanly with existing tables.

```sql
-- =============================================================================
-- Migration: 003_create_users_staff_schema.sql
-- Description: Users and Staff tables for multi-tenant HMS
-- Dependencies: 001_create_base_schema.sql (clinics)
--               002_create_rbac_schema.sql (roles, user_clinic_roles)
-- HIPAA Notice: This file contains schemas for ePHI-adjacent data.
--               User identity and staff records must be access-logged,
--               encrypted at rest, and retained per HIPAA §164.530(j).
-- =============================================================================

-- ---------------------------------------------------------------------------
-- ENUM TYPES
-- Defined once here; extend via ALTER TYPE ... ADD VALUE in future migrations
-- ---------------------------------------------------------------------------

CREATE TYPE employment_status AS ENUM (
  'active',
  'on_leave',
  'suspended',
  'terminated',
  'probation'
);

COMMENT ON TYPE employment_status IS
  'Lifecycle states for a staff member within a clinic. '
  'Terminated records must be retained per HIPAA audit requirements.';

CREATE TYPE employment_type AS ENUM (
  'full_time',
  'part_time',
  'contract',
  'locum',       -- temporary/agency doctor fill-in
  'intern',
  'volunteer'
);

COMMENT ON TYPE employment_type IS
  'Classification of staff engagement type per HR and payroll requirements.';

CREATE TYPE gender AS ENUM (
  'male',
  'female',
  'non_binary',
  'prefer_not_to_say',
  'other'
);

COMMENT ON TYPE gender IS
  'HIPAA-sensitive demographic field. Collect only when clinically necessary.';

-- ---------------------------------------------------------------------------
-- TABLE: users
-- Central identity record. One user can belong to many clinics via
-- user_clinic_roles (already created in 002). Passwords are NEVER stored
-- in plaintext — only bcrypt/argon2 hashes. PII fields noted per HIPAA §164.514.
-- ---------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS users (
  -- Primary key
  id                  UUID          PRIMARY KEY DEFAULT gen_random_uuid(),

  -- Authentication — HIPAA §164.312(d): unique user identification required
  email               VARCHAR(255)  NOT NULL,
  password_hash       TEXT          NOT NULL,   -- bcrypt/argon2id hash ONLY, never plaintext
  
  -- PII fields — HIPAA §164.514(b): treat as PHI-adjacent, minimize exposure
  full_name           VARCHAR(255)  NOT NULL,
  phone               VARCHAR(20),              -- E.164 format recommended: +1234567890
  date_of_birth       DATE,                     -- Optional; only collect if operationally required
  gender              gender,                   -- Optional; only collect if clinically necessary
  avatar_url          TEXT,                     -- S3/storage URL; must be access-controlled
  
  -- Account state
  is_active           BOOLEAN       NOT NULL DEFAULT TRUE,
  is_email_verified   BOOLEAN       NOT NULL DEFAULT FALSE,
  is_phone_verified   BOOLEAN       NOT NULL DEFAULT FALSE,
  failed_login_count  SMALLINT      NOT NULL DEFAULT 0,      -- For brute-force lockout (HIPAA §164.312(d))
  locked_until        TIMESTAMPTZ,                           -- Account lockout expiry
  
  -- Audit trail — HIPAA §164.312(b): hardware/software activity logs
  last_login          TIMESTAMPTZ,
  last_login_ip       INET,                     -- Store for security audit; anonymize after retention period
  password_changed_at TIMESTAMPTZ   NOT NULL DEFAULT NOW(),  -- Enforce periodic rotation policies
  
  -- Soft delete — records must be retained, not hard-deleted, per HIPAA §164.530(j)
  deleted_at          TIMESTAMPTZ,
  deleted_by          UUID,                     -- FK to users.id added below to avoid forward reference

  -- Standard audit fields (consistent with 001 and 002 migrations)
  created_at          TIMESTAMPTZ   NOT NULL DEFAULT NOW(),
  updated_at          TIMESTAMPTZ   NOT NULL DEFAULT NOW(),

  -- Constraints
  CONSTRAINT users_email_format CHECK (email ~* '^[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}$'),
  CONSTRAINT users_phone_format CHECK (phone IS NULL OR phone ~* '^\+?[1-9]\d{6,14}$'),
  CONSTRAINT users_failed_login_count_non_negative CHECK (failed_login_count >= 0)
);

-- Email uniqueness only among non-deleted users (soft-delete safe)
CREATE UNIQUE INDEX IF NOT EXISTS users_email_unique_active
  ON users (email)
  WHERE deleted_at IS NULL;

-- Self-referential FK for deleted_by (added after table creation)
ALTER TABLE users
  ADD CONSTRAINT users_deleted_by_fkey
  FOREIGN KEY (deleted_by) REFERENCES users (id)
  ON DELETE SET NULL
  DEFERRABLE INITIALLY DEFERRED;

-- Indexes for common query patterns
CREATE INDEX IF NOT EXISTS idx_users_email           ON users (email)            WHERE deleted_at IS NULL;
CREATE INDEX IF NOT EXISTS idx_users_is_active       ON users (is_active)        WHERE deleted_at IS NULL;
CREATE INDEX IF NOT EXISTS idx_users_last_login      ON users (last_login DESC)  WHERE deleted_at IS NULL;
CREATE INDEX IF NOT EXISTS idx_users_deleted_at      ON users (deleted_at)       WHERE deleted_at IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_users_locked_until    ON users (locked_until)     WHERE locked_until IS NOT NULL;

-- Auto-update updated_at trigger (reuse pattern from prior migrations)
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER
LANGUAGE plpgsql
SECURITY DEFINER
AS $$
BEGIN
  NEW.updated_at = NOW();
  RETURN NEW;
END;
$$;

COMMENT ON FUNCTION update_updated_at_column IS
  'Generic trigger function to auto-update updated_at on row modification. '
  'Defined once; reused across all tables in this migration.';

CREATE TRIGGER trg_users_updated_at
  BEFORE UPDATE ON users
  FOR EACH ROW
  EXECUTE FUNCTION update_updated_at_column();

-- Table and column comments for HIPAA documentation trail
COMMENT ON TABLE  users                       IS 'Central identity store. Contains PII per HIPAA §164.514. Access must be logged and role-restricted.';
COMMENT ON COLUMN users.id                    IS 'Surrogate UUID primary key. Never expose internal sequences.';
COMMENT ON COLUMN users.email                 IS 'PII — HIPAA §164.514(b)(2)(i). Used as login identifier. Unique among active users.';
COMMENT ON COLUMN users.password_hash         IS 'SECURITY: Stores ONLY bcrypt/argon2id hash. Application must NEVER write plaintext here.';
COMMENT ON COLUMN users.full_name             IS 'PII — Patient/staff legal name. Restrict read access to authorized roles.';
COMMENT ON COLUMN users.phone                 IS 'PII — E.164 format. Used for 2FA and appointment notifications.';
COMMENT ON COLUMN users.date_of_birth         IS 'PII — HIPAA §164.514(b)(2)(ii). Collect only when clinically or operationally required.';
COMMENT ON COLUMN users.last_login_ip         IS 'SECURITY: Stored for audit trail per HIPAA §164.312(b). Anonymize after retention window.';
COMMENT ON COLUMN users.failed_login_count    IS 'SECURITY: Increment on failed auth. Lock account at configurable threshold.';
COMMENT ON COLUMN users.locked_until          IS 'SECURITY: Temporary lockout expiry for brute-force