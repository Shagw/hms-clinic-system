```sql
-- =============================================================================
-- Migration: 009_create_audit_logs_schema.sql
-- Description: Audit logging for HIPAA compliance - tracks all create, update,
--              delete operations on sensitive resources (patients, bills,
--              prescriptions, medical records, etc.)
--
-- HIPAA Compliance Notes:
--   - 45 CFR §164.312(b): Audit controls requirement - hardware, software, and
--     procedural mechanisms to record and examine PHI access/activity
--   - 45 CFR §164.308(a)(1)(ii)(D): Information system activity review
--   - Audit logs must be retained for a minimum of 6 years per HIPAA standard
--   - old_value/new_value JSONB columns may contain PHI - ensure encryption
--     at rest is enabled at the Supabase/PostgreSQL level
--   - Audit log records must NEVER be deleted (no soft-delete, no hard-delete)
--   - Access to this table should be restricted to admin/compliance roles only
--
-- Dependencies:
--   - 001_create_base_schema.sql    (clinics)
--   - 003_create_users_staff_schema.sql (users)
-- =============================================================================

-- ---------------------------------------------------------------------------
-- Enum: audit_action
-- Represents the type of operation that triggered the audit entry.
-- ---------------------------------------------------------------------------
DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'audit_action') THEN
    CREATE TYPE audit_action AS ENUM (
      'CREATE',       -- New record inserted
      'UPDATE',       -- Existing record modified
      'DELETE',       -- Soft-delete (deleted_at set) or hard-delete
      'VIEW',         -- PHI record accessed/read (for sensitive resources)
      'LOGIN',        -- User authentication event
      'LOGOUT',       -- User session termination
      'EXPORT',       -- Data exported (CSV, PDF, report)
      'PERMISSION_CHANGE' -- Role/permission assignment changed
    );
  END IF;
END$$;

-- ---------------------------------------------------------------------------
-- Enum: audit_resource
-- Enumerates every resource type whose mutations must be captured.
-- Extend this list as new entities are added to the HMS.
-- ---------------------------------------------------------------------------
DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'audit_resource') THEN
    CREATE TYPE audit_resource AS ENUM (
      'patient',              -- 005_create_patients_schema
      'patient_medical_info', -- 005_create_patients_schema (PHI - high sensitivity)
      'appointment',          -- 006_create_appointments_schema
      'appointment_reminder', -- 006_create_appointments_schema
      'doctor',               -- 004_create_doctors_schema
      'doctor_schedule',      -- 004_create_doctors_schema
      'prescription',         -- future migration
      'prescription_item',    -- future migration
      'bill',                 -- 008_create_billing_schema
      'bill_item',            -- 008_create_billing_schema
      'medical_record',       -- future migration
      'lab_result',           -- future migration
      'inventory',            -- future migration
      'user',                 -- 003_create_users_staff_schema
      'staff',                -- 003_create_users_staff_schema
      'role',                 -- 002_create_rbac_schema
      'permission',           -- 002_create_rbac_schema
      'clinic',               -- 001_create_base_schema
      'clinic_settings'       -- 001_create_base_schema
    );
  END IF;
END$$;

-- ---------------------------------------------------------------------------
-- Table: audit_logs
--
-- Immutable append-only ledger of every significant action performed within
-- the system. Rows must never be updated or deleted - enforce via trigger.
--
-- Column notes:
--   clinic_id    - Multi-tenant isolation; NULL allowed for system-level events
--                  (e.g., super-admin creating a new clinic).
--   user_id      - FK to users(id); NULL for automated/system-initiated events.
--   action       - What happened (audit_action enum).
--   resource     - Which entity type was affected (audit_resource enum).
--   resource_id  - UUID of the affected row in its source table.
--   old_value    - Full or partial snapshot of the record BEFORE the change.
--                  NULL for CREATE actions.
--                  ⚠ MAY CONTAIN PHI - ensure column-level encryption if req.
--   new_value    - Full or partial snapshot of the record AFTER the change.
--                  NULL for DELETE actions.
--                  ⚠ MAY CONTAIN PHI - ensure column-level encryption if req.
--   ip_address   - INET type preserves both IPv4 and IPv6 natively in PG.
--   user_agent   - Browser/client string; aids forensic investigation.
--   created_at   - Immutable insert timestamp; DEFAULT now(), never updated.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS audit_logs (
  -- Primary key
  id                UUID          PRIMARY KEY DEFAULT gen_random_uuid(),

  -- Multi-tenant isolation
  -- HIPAA: links every audit event to the covered entity (clinic)
  clinic_id         UUID          REFERENCES clinics(id) ON DELETE RESTRICT,
  -- ON DELETE RESTRICT: prevent clinic deletion while audit history exists

  -- Actor
  -- HIPAA §164.312(a)(2)(i): unique user identification
  user_id           UUID          REFERENCES users(id) ON DELETE RESTRICT,
  -- NULL allowed for system/automated actions (e.g., scheduled jobs)

  -- Event classification
  action            audit_action  NOT NULL,
  resource          audit_resource NOT NULL,

  -- Affected record
  -- Stored as UUID text to remain flexible across all resource tables
  resource_id       UUID          NOT NULL,

  -- State snapshots
  -- HIPAA: before/after values support breach investigation and access review
  -- Recommend Supabase Vault or pgcrypto for encryption of these columns
  old_value         JSONB         DEFAULT NULL,
  -- NULL for CREATE; stores redacted or full prior state for UPDATE/DELETE
  new_value         JSONB         DEFAULT NULL,
  -- NULL for DELETE; stores redacted or full new state for CREATE/UPDATE

  -- Request context
  -- HIPAA: network access tracking for breach analysis
  ip_address        INET          DEFAULT NULL,
  -- INET natively handles '192.168.1.1' and '2001:db8::1'
  user_agent        TEXT          DEFAULT NULL,

  -- Immutable timestamp - no updated_at by design
  created_at        TIMESTAMPTZ   NOT NULL DEFAULT now()

  -- NOTE: No deleted_at, no updated_at columns.
  -- Audit logs are IMMUTABLE by design and regulatory requirement.
  -- Deletion prevention is enforced via trigger below.
);

-- ---------------------------------------------------------------------------
-- Comment annotations for documentation and tooling
-- ---------------------------------------------------------------------------
COMMENT ON TABLE audit_logs IS
  'HIPAA §164.312(b): Immutable audit trail for all PHI-touching operations. '
  'Rows must never be modified or deleted. Retain for minimum 6 years.';

COMMENT ON COLUMN audit_logs.clinic_id IS
  'Multi-tenant scope. NULL only for super-admin / system-level events.';
COMMENT ON COLUMN audit_logs.user_id IS
  'Actor who triggered the event. NULL for automated system processes.';
COMMENT ON COLUMN audit_logs.action IS
  'Classified operation type (CREATE, UPDATE, DELETE, VIEW, etc.).';
COMMENT ON COLUMN audit_logs.resource IS
  'Entity type affected. Maps to a physical HMS table.';
COMMENT ON COLUMN audit_logs.resource_id IS
  'UUID of the specific row affected in the source table.';
COMMENT ON COLUMN audit_logs.old_value IS
  'JSONB snapshot BEFORE change. NULL on CREATE. ⚠ MAY CONTAIN PHI.';
COMMENT ON COLUMN audit_logs.new_value IS
  'JSONB snapshot AFTER change. NULL on DELETE. ⚠ MAY CONTAIN PHI.';
COMMENT ON COLUMN audit_logs.ip_address IS
  'Client IP (IPv4/IPv6) for network-level access tracing.';
COMMENT ON COLUMN audit_logs.user_agent IS
  'HTTP User-Agent