```sql
-- ============================================================================
-- Migration: 002_create_rbac_schema.sql
-- Description: Role-Based Access Control (RBAC) schema for multi-tenant HMS
-- HIPAA Note: Access control is a core HIPAA Administrative Safeguard (§164.308).
--             All role assignments and permission changes should be audit-logged.
--             Minimum necessary access principle must be enforced at application layer.
-- Depends on: 001_create_base_schema.sql (clinics table)
-- ============================================================================

-- ----------------------------------------------------------------------------
-- EXTENSIONS (idempotent)
-- ----------------------------------------------------------------------------
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- ============================================================================
-- TABLE: roles
-- Purpose: Defines named roles scoped to a clinic (multi-tenant).
--          clinic_id = NULL reserved for system-level / global roles.
-- HIPAA:   Role definitions control who can access PHI resources.
-- ============================================================================
CREATE TABLE IF NOT EXISTS roles (
    id                  UUID            PRIMARY KEY DEFAULT uuid_generate_v4(),

    -- NULL clinic_id = global/system role; non-null = clinic-scoped custom role
    clinic_id           UUID            REFERENCES clinics(id)
                                            ON DELETE CASCADE
                                            ON UPDATE CASCADE,

    name                VARCHAR(100)    NOT NULL,
    description         TEXT,

    -- Prevent duplicate role names within the same clinic scope
    -- (NULL clinic_id roles are also deduplicated via partial index below)
    is_system_role      BOOLEAN         NOT NULL DEFAULT FALSE,
    is_active           BOOLEAN         NOT NULL DEFAULT TRUE,

    -- Audit fields
    created_at          TIMESTAMPTZ     NOT NULL DEFAULT NOW(),
    updated_at          TIMESTAMPTZ     NOT NULL DEFAULT NOW(),
    deleted_at          TIMESTAMPTZ,                          -- soft-delete
    created_by          UUID,                                 -- user who created
    updated_by          UUID,                                 -- user who last updated

    -- Enforce unique role names per clinic; system roles unique globally
    CONSTRAINT uq_roles_name_per_clinic
        UNIQUE NULLS NOT DISTINCT (clinic_id, name)
);

COMMENT ON TABLE  roles                 IS 'RBAC roles scoped per clinic. System roles (clinic_id IS NULL) are seeded globally and shared across all tenants.';
COMMENT ON COLUMN roles.clinic_id       IS 'NULL = system-wide role. Non-null = custom role for that clinic only.';
COMMENT ON COLUMN roles.is_system_role  IS 'TRUE = seeded by system; cannot be deleted by clinic admins.';
COMMENT ON COLUMN roles.deleted_at      IS 'Soft-delete timestamp. NULL means active. HIPAA: retain for audit trail.';

-- Indexes
CREATE INDEX IF NOT EXISTS idx_roles_clinic_id
    ON roles (clinic_id)
    WHERE deleted_at IS NULL;

CREATE INDEX IF NOT EXISTS idx_roles_is_system_role
    ON roles (is_system_role)
    WHERE deleted_at IS NULL;

-- Partial unique index: system roles (clinic_id IS NULL) must have unique names
CREATE UNIQUE INDEX IF NOT EXISTS uidx_roles_system_name
    ON roles (name)
    WHERE clinic_id IS NULL AND deleted_at IS NULL;

-- ============================================================================
-- TABLE: permissions
-- Purpose: Atomic permission units defined as resource + action pairs.
--          These are system-wide and not tenant-scoped.
-- HIPAA:   Granular permissions enforce Minimum Necessary Standard (§164.514(b)).
-- ============================================================================
CREATE TABLE IF NOT EXISTS permissions (
    id                  UUID            PRIMARY KEY DEFAULT uuid_generate_v4(),

    -- Human-readable unique key, e.g. "patient:read", "prescription:write"
    name                VARCHAR(150)    NOT NULL UNIQUE,

    -- The resource being protected (maps to HMS entities / API routes)
    resource            VARCHAR(100)    NOT NULL,

    -- CRUD-style action or custom verb
    action              VARCHAR(50)     NOT NULL
                                            CHECK (action IN (
                                                'create', 'read', 'update', 'delete',
                                                'list',   'export', 'print',
                                                'approve','assign', 'revoke'
                                            )),

    description         TEXT,
    is_active           BOOLEAN         NOT NULL DEFAULT TRUE,

    -- Audit fields
    created_at          TIMESTAMPTZ     NOT NULL DEFAULT NOW(),
    updated_at          TIMESTAMPTZ     NOT NULL DEFAULT NOW(),
    deleted_at          TIMESTAMPTZ,                          -- soft-delete

    CONSTRAINT uq_permissions_resource_action
        UNIQUE (resource, action)
);

COMMENT ON TABLE  permissions           IS 'Atomic, system-wide permission definitions. Each row = one allowable operation on one resource.';
COMMENT ON COLUMN permissions.resource  IS 'HMS entity or feature area, e.g. patient, prescription, lab_result, bill, report.';
COMMENT ON COLUMN permissions.action    IS 'Operation verb constrained to known values. Extend CHECK list as features grow.';
COMMENT ON COLUMN permissions.name      IS 'Canonical key used in application code, e.g. "patient:read". Must stay stable after creation.';

-- Indexes
CREATE INDEX IF NOT EXISTS idx_permissions_resource
    ON permissions (resource)
    WHERE deleted_at IS NULL;

CREATE INDEX IF NOT EXISTS idx_permissions_action
    ON permissions (action)
    WHERE deleted_at IS NULL;

-- ============================================================================
-- TABLE: role_permissions
-- Purpose: Many-to-many mapping between roles and permissions.
-- HIPAA:   Changes to this table alter what PHI data a role can access —
--          application layer MUST emit audit events on INSERT/DELETE here.
-- ============================================================================
CREATE TABLE IF NOT EXISTS role_permissions (
    role_id             UUID            NOT NULL
                                            REFERENCES roles(id)
                                            ON DELETE CASCADE
                                            ON UPDATE CASCADE,

    permission_id       UUID            NOT NULL
                                            REFERENCES permissions(id)
                                            ON DELETE CASCADE
                                            ON UPDATE CASCADE,

    -- Who granted this permission assignment
    granted_by          UUID,
    granted_at          TIMESTAMPTZ     NOT NULL DEFAULT NOW(),

    -- Soft-delete so history is preserved for HIPAA audit purposes
    revoked_by          UUID,
    revoked_at          TIMESTAMPTZ,                          -- NULL = still active

    CONSTRAINT pk_role_permissions
        PRIMARY KEY (role_id, permission_id)
);

COMMENT ON TABLE  role_permissions              IS 'Junction table granting permissions to roles. Soft-revoke via revoked_at; never hard-delete HIPAA audit rows.';
COMMENT ON COLUMN role_permissions.granted_by   IS 'UUID of the admin user who created this grant. Application must populate.';
COMMENT ON COLUMN role_permissions.revoked_at   IS 'Non-null = permission removed from role. Row retained for audit trail.';

-- Indexes
CREATE INDEX IF NOT EXISTS idx_role_permissions_role_id
    ON role_permissions (role_id)
    WHERE revoked_at IS NULL;

CREATE INDEX IF NOT EXISTS idx_role_permissions_permission_id
    ON role_permissions (permission_id)
    WHERE revoked_at IS NULL;

-- ============================================================================
-- TABLE: user_clinic_roles
-- Purpose: Assigns a role to a user within a specific clinic (multi-tenant).
--          One user may hold different roles in different clinics.
-- HIPAA:   This is the primary access-control enforcement point.
--          All assignments must be logged. Terminated staff rows must be
--          soft-deleted (revoked_at) — never hard-deleted.
-- ============================================================================
CREATE TABLE IF NOT EXISTS user_clinic_roles (
    id                  UUID            PRIMARY KEY DEFAULT uuid_generate_v4(),

    -- References Supabase auth.users (managed by Supabase Auth)
    user_id             UUID            NOT NULL,

    clinic_id           UUID            NOT NULL
                                            REFERENCES clinics(id)
                                            ON DELETE CASCADE
                                            ON UPDATE CASCADE,

    role_id             UUID            NOT NULL
                                            REFERENCES roles(id)
                                            ON DELETE RESTRICT      -- protect audit trail
                                            ON UPDATE CASCADE,

    -- A user may hold only one role per clinic at a time (enforce at app layer for multi-role)
    -- Remove this unique constraint if multi-role