```sql
-- =============================================================================
-- Migration: 005_create_patients_schema.sql
-- Description: Creates patients and patient_medical_info tables for HMS
-- Schema: public
-- Dependencies: 001_create_base_schema.sql (clinics table)
-- 
-- HIPAA Compliance Notes:
--   - PHI (Protected Health Information) fields are clearly marked in comments
--   - patient_uid provides a de-identified reference ID for external use
--   - All sensitive medical data isolated in patient_medical_info table
--   - Soft-delete (deleted_at) ensures audit trail is preserved per HIPAA §164.312
--   - Row-level access should be enforced via Supabase RLS policies
--   - Encryption at rest should be enabled at the database/storage level
--   - Access logs should be maintained for all PHI field reads/writes
-- =============================================================================

-- -----------------------------------------------------------------------------
-- TABLE: patients
-- Stores core demographic and contact information for clinic patients.
-- 
-- HIPAA PHI Fields: full_name, date_of_birth, phone, email, address,
--                   emergency_contact_name, emergency_contact_phone, blood_group
-- Access Control: Restrict to authenticated clinic staff with valid clinic_id
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS patients (
    -- Primary identity
    id                          UUID            PRIMARY KEY DEFAULT gen_random_uuid(),

    -- Multi-tenant isolation: every row MUST belong to a clinic
    -- HIPAA §164.308: Isolates PHI per covered entity (clinic)
    clinic_id                   UUID            NOT NULL
                                    REFERENCES clinics(id)
                                    ON DELETE RESTRICT
                                    ON UPDATE CASCADE,

    -- PHI: De-identified public-facing patient reference number
    -- Format recommendation: CLN-{clinic_code}-{sequence} e.g. CLN-ABC-00123
    -- Use this ID in external communications instead of internal UUID
    patient_uid                 VARCHAR(50)     NOT NULL,

    -- PHI: Legal full name of the patient
    full_name                   VARCHAR(255)    NOT NULL
                                    CONSTRAINT patients_full_name_not_empty
                                    CHECK (TRIM(full_name) <> ''),

    -- PHI: Used for age calculation and identity verification
    date_of_birth               DATE            NOT NULL
                                    CONSTRAINT patients_dob_not_future
                                    CHECK (date_of_birth <= CURRENT_DATE),

    -- PHI: Biological sex / gender identity
    -- Constrained to common clinical values; extend as needed
    gender                      VARCHAR(20)     NOT NULL
                                    CONSTRAINT patients_gender_valid
                                    CHECK (gender IN (
                                        'male',
                                        'female',
                                        'non_binary',
                                        'prefer_not_to_say',
                                        'other'
                                    )),

    -- PHI: Primary contact phone number (E.164 format recommended: +1234567890)
    phone                       VARCHAR(20)     NOT NULL
                                    CONSTRAINT patients_phone_not_empty
                                    CHECK (TRIM(phone) <> ''),

    -- PHI: Email address — optional, used for appointment reminders/portal access
    email                       VARCHAR(255)
                                    CONSTRAINT patients_email_format
                                    CHECK (
                                        email IS NULL OR
                                        email ~* '^[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}$'
                                    ),

    -- PHI: Full residential/mailing address stored as JSONB for flexibility
    -- Recommended structure:
    -- {
    --   "street": "123 Main St",
    --   "city": "Springfield",
    --   "state": "IL",
    --   "zip": "62701",
    --   "country": "US"
    -- }
    address                     JSONB           DEFAULT '{}'::jsonb,

    -- PHI: ABO/Rh blood group — critical for emergency medical decisions
    blood_group                 VARCHAR(10)
                                    CONSTRAINT patients_blood_group_valid
                                    CHECK (blood_group IS NULL OR blood_group IN (
                                        'A+', 'A-',
                                        'B+', 'B-',
                                        'AB+', 'AB-',
                                        'O+', 'O-',
                                        'unknown'
                                    )),

    -- PHI: Emergency contact — separate from patient's own contact info
    emergency_contact_name      VARCHAR(255)
                                    CONSTRAINT patients_ecn_not_empty
                                    CHECK (
                                        emergency_contact_name IS NULL OR
                                        TRIM(emergency_contact_name) <> ''
                                    ),

    -- PHI: Emergency contact phone (E.164 format recommended)
    emergency_contact_phone     VARCHAR(20)
                                    CONSTRAINT patients_ecp_not_empty
                                    CHECK (
                                        emergency_contact_phone IS NULL OR
                                        TRIM(emergency_contact_phone) <> ''
                                    ),

    -- Audit fields — HIPAA §164.312(b): Audit controls requirement
    created_at                  TIMESTAMPTZ     NOT NULL DEFAULT NOW(),
    updated_at                  TIMESTAMPTZ     NOT NULL DEFAULT NOW(),

    -- Soft-delete: preserves PHI audit trail; hard-delete requires compliance review
    -- HIPAA §164.316(b)(2): Records must be retained for minimum 6 years
    deleted_at                  TIMESTAMPTZ     DEFAULT NULL,

    -- Constraints
    -- Enforce uniqueness of patient_uid within each clinic (not globally)
    CONSTRAINT patients_uid_unique_per_clinic
        UNIQUE (clinic_id, patient_uid),

    -- A patient should not have duplicate email registrations within same clinic
    CONSTRAINT patients_email_unique_per_clinic
        UNIQUE (clinic_id, email)
);

-- Comments on table and sensitive columns for documentation/tooling
COMMENT ON TABLE patients IS
    'Core patient demographic and contact information. Contains PHI — access restricted per HIPAA guidelines.';
COMMENT ON COLUMN patients.patient_uid IS
    'PHI: De-identified external-facing patient reference ID. Use in communications instead of internal UUID.';
COMMENT ON COLUMN patients.full_name IS
    'PHI: Patient legal full name. Handle with minimum necessary access principle.';
COMMENT ON COLUMN patients.date_of_birth IS
    'PHI: Date of birth used for identity verification and clinical age calculations.';
COMMENT ON COLUMN patients.address IS
    'PHI: JSONB address with keys: street, city, state, zip, country.';
COMMENT ON COLUMN patients.blood_group IS
    'PHI: ABO/Rh blood group. Critical for emergency clinical decisions.';
COMMENT ON COLUMN patients.emergency_contact_name IS
    'PHI: Name of person to contact in medical emergencies.';
COMMENT ON COLUMN patients.emergency_contact_phone IS
    'PHI: Phone number of emergency contact person.';
COMMENT ON COLUMN patients.deleted_at IS
    'Soft-delete timestamp. NULL = active record. Retain per HIPAA 6-year minimum retention policy.';

-- -----------------------------------------------------------------------------
-- INDEXES: patients
-- Optimized for common HMS query patterns with multi-tenant awareness
-- -----------------------------------------------------------------------------

-- Primary lookup: find patients by clinic (always filter by clinic_id first)
CREATE INDEX IF NOT EXISTS idx_patients_clinic_id
    ON patients (clinic_id)
    WHERE deleted_at IS NULL;

-- Patient UID lookup within a clinic (registration desk, search bar)
CREATE INDEX IF NOT EXISTS idx_patients_patient_uid
    ON patients (clinic_id, patient_uid)
    WHERE deleted_at IS NULL;

-- Full-text search on patient name within a clinic
-- Supports partial name searches from the receptionist UI
CREATE INDEX IF NOT EXISTS idx_patients_full_name_search
    ON patients USING GIN (
        to_tsvector('english', full_name)
    )
    WHERE deleted_at IS NULL;

-- Phone number lookup — common for walk-in patient identification
CREATE INDEX IF NOT EXISTS idx_patients_phone
    ON patients (clinic_id, phone)
    WHERE deleted_at IS NULL;

-- Email lookup — used for portal login and appointment notifications
CREATE INDEX IF NOT EXISTS idx_patients_email