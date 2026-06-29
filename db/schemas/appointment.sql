-- ============================================================================
-- Migration: 001_create_base_schema.sql
-- Description: Multi-tenant base schema for Clinic HMS
-- Creates foundational `clinics` and `clinic_settings` tables.
-- Every subsequent table references clinic_id for strict tenant isolation.
--
-- HIPAA Notice: This schema establishes the organizational boundary for all
-- Protected Health Information (PHI). clinic_id acts as the primary tenant
-- isolation key. Row-Level Security (RLS) policies must be applied to ALL
-- tables referencing clinic_id to prevent cross-tenant PHI exposure.
-- ============================================================================

-- ----------------------------------------------------------------------------
-- EXTENSIONS
-- ----------------------------------------------------------------------------
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";      -- UUID generation
CREATE EXTENSION IF NOT EXISTS "pgcrypto";       -- Cryptographic functions (future PHI encryption)
CREATE EXTENSION IF NOT EXISTS "citext";         -- Case-insensitive text (emails)

-- ----------------------------------------------------------------------------
-- CUSTOM TYPES
-- ----------------------------------------------------------------------------

-- Subscription tiers control feature access and PHI storage limits
CREATE TYPE subscription_plan_type AS ENUM (
    'free',         -- Limited patients, no lab integrations
    'basic',        -- Standard clinical workflows
    'professional', -- Advanced reporting, multi-doctor
    'enterprise'    -- Unlimited, custom retention policies, BAA-eligible
);

-- ----------------------------------------------------------------------------
-- TABLE: clinics
-- Description: Top-level tenant entity. Each clinic is a completely isolated
--              data boundary. All PHI is scoped under a clinic_id.
--
-- HIPAA Consideration: This table itself contains no PHI, only organizational
-- metadata. However, it is the root of the tenant isolation tree.
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS clinics (
    -- Primary key: UUID v4 preferred over serial to prevent enumeration attacks
    id                  UUID            PRIMARY KEY DEFAULT uuid_generate_v4(),

    -- Core identity
    name                VARCHAR(255)    NOT NULL
                            CONSTRAINT clinics_name_not_empty
                            CHECK (TRIM(name) <> ''),

    -- Physical address stored as structured text; consider jsonb for sub-fields
    -- in future migrations if address parsing is required
    address             TEXT,

    -- E.164 format recommended for phone normalization (+1XXXXXXXXXX)
    phone               VARCHAR(20),

    -- citext ensures case-insensitive uniqueness (no duplicate Jane@Clinic.com)
    email               CITEXT
                            CONSTRAINT clinics_email_format
                            CHECK (email ~* '^[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}$'),

    -- Subscription tier governs data retention rules and feature flags
    subscription_plan   subscription_plan_type  NOT NULL DEFAULT 'free',

    -- Soft-disable without destroying tenant data or breaking FK references
    is_active           BOOLEAN         NOT NULL DEFAULT TRUE,

    -- --------------------------------------------------------------------
    -- Audit fields (HIPAA §164.312(b) - Audit Controls)
    -- All tables in this schema follow this same audit pattern
    -- --------------------------------------------------------------------
    created_at          TIMESTAMPTZ     NOT NULL DEFAULT NOW(),
    updated_at          TIMESTAMPTZ     NOT NULL DEFAULT NOW(),

    -- Soft-delete: NEVER hard-delete clinic records while PHI may exist
    -- Set deleted_at to mark as deleted; purge only after retention period
    deleted_at          TIMESTAMPTZ     DEFAULT NULL
);

-- Ensure email uniqueness only among non-deleted clinics
CREATE UNIQUE INDEX IF NOT EXISTS uq_clinics_email_active
    ON clinics (email)
    WHERE deleted_at IS NULL;

-- Fast lookup for active clinics (dashboard, tenant resolution middleware)
CREATE INDEX IF NOT EXISTS idx_clinics_is_active
    ON clinics (is_active)
    WHERE deleted_at IS NULL;

-- Tenant resolution by name (onboarding, search)
CREATE INDEX IF NOT EXISTS idx_clinics_name
    ON clinics (name)
    WHERE deleted_at IS NULL;

-- Subscription-based queries (billing service, feature-flag middleware)
CREATE INDEX IF NOT EXISTS idx_clinics_subscription_plan
    ON clinics (subscription_plan);

-- ----------------------------------------------------------------------------
-- TABLE: clinic_settings
-- Description: One-to-one extension of clinics for operational configuration.
--              Separated from clinics to keep the core tenant record lean and
--              allow settings to be updated frequently without locking the
--              parent row.
--
-- HIPAA Consideration: working_hours and timezone influence audit log
-- timestamps and appointment scheduling — critical for accurate audit trails.
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS clinic_settings (
    -- 1:1 with clinics; clinic_id is both PK and FK
    clinic_id                   UUID            PRIMARY KEY
                                    REFERENCES clinics (id)
                                    ON DELETE RESTRICT   -- Prevent orphaned settings
                                    ON UPDATE CASCADE,

    -- Publicly accessible logo (CDN URL). Must NOT contain PHI.
    logo_url                    TEXT
                                    CONSTRAINT clinic_settings_logo_url_format
                                    CHECK (
                                        logo_url IS NULL OR
                                        logo_url ~* '^https?://.+'
                                    ),

    -- Structured working hours stored as JSONB for flexibility
    -- Expected shape:
    -- {
    --   "monday":    { "open": "08:00", "close": "17:00", "is_open": true },
    --   "tuesday":   { "open": "08:00", "close": "17:00", "is_open": true },
    --   ...
    --   "sunday":    { "open": null,    "close": null,    "is_open": false }
    -- }
    -- Validated by check constraint for required day keys
    working_hours               JSONB           NOT NULL DEFAULT '{
        "monday":    {"open": "08:00", "close": "17:00", "is_open": true},
        "tuesday":   {"open": "08:00", "close": "17:00", "is_open": true},
        "wednesday": {"open": "08:00", "close": "17:00", "is_open": true},
        "thursday":  {"open": "08:00", "close": "17:00", "is_open": true},
        "friday":    {"open": "08:00", "close": "17:00", "is_open": true},
        "saturday":  {"open": null,    "close": null,    "is_open": false},
        "sunday":    {"open": null,    "close": null,    "is_open": false}
    }'::jsonb,

    -- Ensure all seven day keys are present in the JSON
    CONSTRAINT clinic_settings_working_hours_keys CHECK (
        working_hours ? 'monday'    AND
        working_hours ? 'tuesday'   AND
        working_hours ? 'wednesday' AND
        working_hours ? 'thursday'  AND
        working_hours ? 'friday'    AND
        working_hours ? 'saturday'  AND
        working_hours ? 'sunday'
    ),

    -- Default slot duration in minutes; drives appointment booking grid
    appointment_duration_minutes INTEGER         NOT NULL DEFAULT 30
                                    CONSTRAINT clinic_settings_duration_positive
                                    CHECK (appointment_duration_minutes > 0)
                                    CONSTRAINT clinic_settings_duration_max
                                    CHECK (appointment_duration_minutes <= 480), -- max 8hr block

    -- ISO 4217 currency code (e.g., 'USD', 'EUR', 'GBP')
    -- Used for billing module; 3-char enforced
    currency                    CHAR(3)         NOT NULL DEFAULT 'USD'
                                    CONSTRAINT clinic_settings_currency_format
                                    CHECK (currency ~ '^[A-Z]{3}$'),

    -- IANA timezone string (e.g., 'America/New_York')
    -- Critical for HIPAA audit log accuracy — all timestamps stored in UTC,
    -- displayed in clinic's local timezone
    timezone                    VARCHAR(64)     NOT NULL DEFAULT 'UTC'
                                    CONSTRAINT clinic_settings_timezone_not_empty
                                    CHECK (TRIM(timezone) <> ''),

    -- Audit fields
    created_at                  TIMESTAMPTZ     NOT NULL DEFAULT NOW(),
    updated_at                  TIMESTAMPTZ     NOT NULL DEFAULT NOW()

    -- Note: No deleted_at here — settings row lifecycle is tied to the parent
    -- clinic. Deletion is handled via the clinics.deleted_at soft-delete.
);

-- Index for JSON working_hours queries (e.g., find clinics open on Monday)
CREATE INDEX IF NOT EXISTS idx_clinic_settings_working_hours
    ON clinic_settings USING GIN (working_hours);

-- Index for multi-currency billing reports
CREATE INDEX IF NOT EXISTS idx_clinic_settings_currency
    ON clinic_settings (currency);

-- Index for timezone-aware scheduling queries
CREATE INDEX IF NOT EXISTS idx_clinic_settings_timezone
    ON clinic_settings (timezone);

-- ----------------------------------------------------------------------------
-- FUNCTION: update_updated_at_column()
-- Description: Trigger function to auto-update `updated_at` on row changes.
--              Applied to clinics, clinic_settings, and ALL future tables.
--
-- HIPAA §164.312(b): Supports audit controls by maintaining accurate
-- modification timestamps without relying on application-layer code.
-- ----------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER
LANGUAGE plpgsql
SECURITY DEFINER  -- Runs with definer's privileges to ensure it always succeeds
AS $$
BEGIN
    -- Only update if the row actually changed (avoids spurious audit noise)
    IF ROW(NEW.*) IS DISTINCT FROM ROW(OLD.*) THEN
        NEW.updated_at = NOW();
    END IF;
    RETURN NEW;
END;
$$;

-- Attach trigger to clinics
CREATE TRIGGER trg_clinics_updated_at
    BEFORE UPDATE ON clinics
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

-- Attach trigger to clinic_settings
CREATE TRIGGER trg_clinic_settings_updated_at
    BEFORE UPDATE ON clinic_settings
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

-- ----------------------------------------------------------------------------
-- ROW LEVEL SECURITY (RLS)
-- HIPAA §164.312(a)(1) - Access Control
-- Supabase uses RLS as the primary multi-tenant isolation mechanism.
-- Policies below assume the application sets:
--   SET app.current_clinic_id = '<uuid>';
-- in every session/transaction via the tenantIsolation.js middleware.
-- ----------------------------------------------------------------------------

ALTER TABLE clinics         ENABLE ROW LEVEL SECURITY;
ALTER TABLE clinic_settings ENABLE ROW LEVEL SECURITY;

-- clinics: A session may only see its own clinic row
CREATE POLICY clinic_tenant_isolation ON clinics
    USING (
        id = current_setting('app.current_clinic_id', TRUE)::UUID
    );

-- clinic_settings: Scoped to the session's clinic
CREATE POLICY clinic_settings_tenant_isolation ON clinic_settings
    USING (
        clinic_id = current_setting('app.current_clinic_id', TRUE)::UUID
    );

-- Service role bypass (used by internal admin tooling only — not exposed to API)
CREATE POLICY clinic_service_role_bypass ON clinics
    TO service_role
    USING (TRUE);

CREATE POLICY clinic_settings_service_role_bypass ON clinic_settings
    TO service_role
    USING (TRUE);

-- ----------------------------------------------------------------------------
-- SEED: Default clinic_settings row auto-created on new clinic insert
-- Ensures every clinic always has a settings record (prevents null lookups).
-- ----------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION fn_create_default_clinic_settings()
RETURNS TRIGGER
LANGUAGE plpgsql
SECURITY DEFINER
AS $$
BEGIN
    INSERT INTO clinic_settings (clinic_id)
    VALUES (NEW.id)
    ON CONFLICT (clinic_id) DO NOTHING;  -- Idempotent: safe on upsert patterns

    RETURN NEW;
END;
$$;

CREATE TRIGGER trg_clinics_create_default_settings
    AFTER INSERT ON clinics
    FOR EACH ROW
    EXECUTE FUNCTION fn_create_default_clinic_settings();

-- ----------------------------------------------------------------------------
-- COMMENTS (pg_catalog documentation — visible in pgAdmin, Supabase Studio)
-- ----------------------------------------------------------------------------
COMMENT ON TABLE  clinics                                       IS 'Root tenant entity. Every PHI table references clinic_id. HIPAA: No PHI stored here.';
COMMENT ON COLUMN clinics.id                                    IS 'UUID v4 primary key. Opaque to prevent tenant enumeration.';
COMMENT ON COLUMN clinics.subscription_plan                     IS 'Controls feature access and data retention policy enforcement.';
COMMENT ON COLUMN clinics.deleted_at                            IS 'Soft-delete marker. NULL = active. Never hard-delete while PHI may exist under this clinic.';

COMMENT ON TABLE  clinic_settings                               IS '1:1 operational config for each clinic. Lifecycle tied to parent clinics row.';
COMMENT ON COLUMN clinic_settings.working_hours                 IS 'JSONB map of day->hours. Drives appointment scheduling grid. See schema docs for expected shape.';
COMMENT ON COLUMN clinic_settings.timezone                      IS 'IANA timezone string. All PHI timestamps stored in UTC; convert to this timezone for display.';
COMMENT ON COLUMN clinic_settings.appointment_duration_minutes  IS 'Default slot size in minutes. Individual appointment types may override this value.';

COMMENT ON FUNCTION update_updated_at_column()                  IS 'Universal updated_at trigger. Apply to every table in the HMS schema.';
COMMENT ON FUNCTION fn_create_default_clinic_settings()         IS 'Auto-provisions a clinic_settings row on clinic creation. Ensures settings always exist.';