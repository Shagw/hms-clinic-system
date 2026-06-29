Looking at the existing schema, I need to:
1. Follow the UUID PK pattern, snake_case naming, soft-delete with `deleted_at`
2. Reference existing `users` and `clinics` tables
3. Continue migration numbering with `004_`
4. Add HIPAA-conscious comments, proper indexes, and audit fields

```sql
-- =============================================================================
-- Migration: 004_create_doctors_schema.sql
-- Description: Creates doctors and doctor_schedules tables for multi-tenant HMS
-- HIPAA Note: Doctor credentials and PII are access-controlled via clinic_id
--             tenant isolation. Soft-delete preserves audit trail for compliance.
-- Dependencies: 001_create_base_schema.sql (clinics)
--               003_create_users_staff_schema.sql (users)
-- =============================================================================

-- -----------------------------------------------------------------------------
-- ENUM TYPES
-- -----------------------------------------------------------------------------

-- Days of the week for schedule management
-- Using enum prevents invalid day entries and improves query performance
DO $$ BEGIN
    CREATE TYPE day_of_week_enum AS ENUM (
        'monday',
        'tuesday',
        'wednesday',
        'thursday',
        'friday',
        'saturday',
        'sunday'
    );
EXCEPTION
    WHEN duplicate_object THEN NULL; -- Idempotent: skip if already exists
END $$;

-- -----------------------------------------------------------------------------
-- TABLE: doctors
-- Purpose: Stores professional profiles for doctors linked to users and clinics.
-- HIPAA Note: Contains professional PII (registration_number, qualifications).
--             Access MUST be scoped to clinic_id. Do NOT expose raw rows without
--             row-level security (RLS) or application-level tenant checks.
-- Tenant Isolation: clinic_id foreign key enforces multi-tenant boundary.
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS doctors (
    -- Primary key: UUID for distributed safety, no sequential ID leakage
    id                  UUID            PRIMARY KEY DEFAULT gen_random_uuid(),

    -- Link to authenticated user account (1:1 relationship per clinic context)
    -- A user can be a doctor at multiple clinics (different rows, same user_id)
    user_id             UUID            NOT NULL
                                        REFERENCES users(id)
                                        ON DELETE RESTRICT,   -- Prevent orphan doctor profiles

    -- Tenant isolation: every doctor profile is scoped to exactly one clinic
    clinic_id           UUID            NOT NULL
                                        REFERENCES clinics(id)
                                        ON DELETE RESTRICT,   -- Protect historical records

    -- Medical specialization (e.g., 'Cardiology', 'General Practice', 'Pediatrics')
    -- Stored as text to allow clinic-specific custom specializations
    specialization      VARCHAR(150)    NOT NULL,

    -- Academic and professional qualifications (e.g., 'MBBS, MD, FRCS')
    -- Comma-separated or free-text; structured parsing handled at app layer
    qualification       VARCHAR(500)    NOT NULL,

    -- Medical council registration number — HIPAA/regulatory identifier
    -- CRITICAL: Must be unique per clinic to prevent credential duplication
    -- Treated as sensitive PII; mask in non-privileged API responses
    registration_number VARCHAR(100)    NOT NULL,

    -- Consultation fee in the clinic's local currency (stored as cents/paise
    -- to avoid floating-point precision issues — app layer handles formatting)
    consultation_fee    NUMERIC(10, 2)  NOT NULL DEFAULT 0.00
                                        CONSTRAINT consultation_fee_non_negative
                                        CHECK (consultation_fee >= 0),

    -- Short professional biography for patient-facing profiles
    -- HIPAA Note: This is intentionally patient-visible; keep non-sensitive
    bio                 TEXT,

    -- Days the doctor is generally available, stored as an array of enum values
    -- e.g., ARRAY['monday','wednesday','friday']::day_of_week_enum[]
    -- Granular slot management is handled by doctor_schedules table
    available_days      day_of_week_enum[]  NOT NULL DEFAULT '{}',

    -- Logical activation flag — inactive doctors cannot accept new appointments
    is_active           BOOLEAN         NOT NULL DEFAULT TRUE,

    -- --------------------------------------------------------------------------
    -- Audit fields — required for HIPAA audit trail (who changed what, when)
    -- --------------------------------------------------------------------------
    created_at          TIMESTAMPTZ     NOT NULL DEFAULT NOW(),
    updated_at          TIMESTAMPTZ     NOT NULL DEFAULT NOW(),

    -- Soft-delete: preserves historical appointment/prescription linkages
    -- HIPAA: Hard deletes of medical-linked records are prohibited
    deleted_at          TIMESTAMPTZ     DEFAULT NULL,

    -- --------------------------------------------------------------------------
    -- Constraints
    -- --------------------------------------------------------------------------

    -- A user can only have ONE active doctor profile per clinic
    -- Allows same user_id across clinics (multi-clinic doctor scenario)
    CONSTRAINT uq_doctor_user_clinic
        UNIQUE (user_id, clinic_id),

    -- Registration number must be unique within a clinic context
    -- (different councils may issue same numbers across regions)
    CONSTRAINT uq_doctor_registration_clinic
        UNIQUE (registration_number, clinic_id)
);

-- Descriptive comment for DBA/compliance reference
COMMENT ON TABLE doctors IS
    'Professional profiles for doctors. Contains regulatory identifiers and PII. '
    'Access must be tenant-scoped via clinic_id. Soft-delete preserves audit trail. '
    'HIPAA: registration_number and consultation_fee are sensitive fields.';

COMMENT ON COLUMN doctors.user_id IS
    'FK to users table. Represents the authenticated identity of the doctor.';
COMMENT ON COLUMN doctors.registration_number IS
    'Medical council registration number. Sensitive PII — mask in non-privileged responses.';
COMMENT ON COLUMN doctors.consultation_fee IS
    'Fee in smallest currency unit (e.g., cents). Zero for salaried/no-fee contexts.';
COMMENT ON COLUMN doctors.available_days IS
    'General availability days. Detailed slot rules live in doctor_schedules.';
COMMENT ON COLUMN doctors.deleted_at IS
    'Soft-delete timestamp. Non-NULL means logically deleted. Never hard-delete — HIPAA requirement.';

-- -----------------------------------------------------------------------------
-- INDEXES: doctors
-- Query patterns: lookup by clinic, by user, by specialization, active filter
-- -----------------------------------------------------------------------------

-- Most common query: fetch all doctors for a clinic (tenant-scoped list)
CREATE INDEX IF NOT EXISTS idx_doctors_clinic_id
    ON doctors (clinic_id)
    WHERE deleted_at IS NULL;  -- Partial index — only active records

-- Fetch a specific doctor's profile by their user account
CREATE INDEX IF NOT EXISTS idx_doctors_user_id
    ON doctors (user_id)
    WHERE deleted_at IS NULL;

-- Patient-facing specialty search within a clinic
CREATE INDEX IF NOT EXISTS idx_doctors_clinic_specialization
    ON doctors (clinic_id, specialization)
    WHERE deleted_at IS NULL AND is_active = TRUE;

-- Compliance/admin: find deleted profiles without full-table scan
CREATE INDEX IF NOT EXISTS idx_doctors_deleted_at
    ON doctors (deleted_at)
    WHERE deleted_at IS NOT NULL;

-- -----------------------------------------------------------------------------
-- TRIGGER: Auto-update updated_at on any row modification
-- Consistent with pattern used in earlier migrations
-- -----------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION update_doctors_updated_at()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$;

CREATE TRIGGER trg_doctors_updated_at
    BEFORE UPDATE ON doctors
    FOR EACH ROW
    EXECUTE FUNCTION update_doctors_updated_at();


-- =============================================================================
-- TABLE: doctor_schedules
-- Purpose: Defines granular weekly slot availability for each doctor per clinic.
--          Supports multi-clinic doctors with different schedules per location.
-- HIPAA Note: Operational/scheduling data — lower sensitivity than doctors table,
--             but still tenant-scoped. No direct patient PII stored here.
-- Tenant Isolation: Both doctor_id and clinic_id enforce multi-tenant boundary.
-- =============================================================================
CREATE TABLE IF NOT EXISTS doctor_schedules (
    -- Primary key: UUID consistent with all other tables in this schema
    id                  UUID            PRIMARY KEY DEFAULT gen_random_uuid(),

    -- The doctor this schedule belongs to
    doctor_id           UUID            NOT NULL
                                        REFERENCES doctors(id)
                                        ON DELETE CASCADE,   -- Schedule is meaningless without doctor

    -- Redundant clinic_