```sql
-- =============================================================================
-- Migration: 008_create_billing_schema.sql
-- Description: Billing and payment management schema for multi-tenant HMS
-- HIPAA Notice: Bills and payment records constitute financial PHI.
--               Access must be restricted to authorized billing staff only.
--               All financial records must be retained per applicable regulations.
--               Audit trails are mandatory for all billing operations.
-- =============================================================================

-- =============================================================================
-- ENUMS
-- =============================================================================

-- Bill lifecycle status
CREATE TYPE bill_status AS ENUM (
    'draft',        -- Bill being prepared, not yet sent to patient
    'pending',      -- Bill finalized, awaiting payment
    'paid',         -- Payment received in full
    'partial',      -- Partial payment received
    'cancelled',    -- Bill voided/cancelled
    'refunded'      -- Payment refunded after being paid
);

-- Supported payment methods
CREATE TYPE payment_method AS ENUM (
    'cash',
    'card',         -- Credit/Debit card
    'upi',          -- UPI / digital wallets
    'insurance',    -- Insurance claim
    'bank_transfer',
    'cheque'
);

-- Bill item category for reporting and itemization
CREATE TYPE bill_item_type AS ENUM (
    'consultation',
    'procedure',
    'medication',
    'lab_test',
    'imaging',
    'room_charge',
    'nursing_charge',
    'equipment',
    'miscellaneous'
);

-- Payment transaction status
CREATE TYPE payment_status AS ENUM (
    'pending',
    'completed',
    'failed',
    'refunded',
    'disputed'
);

-- =============================================================================
-- TABLE: bills
-- Stores the master bill/invoice record per patient visit or service episode.
-- HIPAA: Contains patient financial PHI — enforce row-level security.
-- =============================================================================

CREATE TABLE bills (
    -- Primary identification
    id                  UUID            PRIMARY KEY DEFAULT gen_random_uuid(),

    -- Multi-tenant isolation — every bill belongs to exactly one clinic
    clinic_id           UUID            NOT NULL
                                        REFERENCES clinics(id)
                                        ON DELETE RESTRICT,

    -- Patient reference — HIPAA PHI linkage
    -- NOTE: Anonymize or pseudonymize in any reporting pipelines
    patient_id          UUID            NOT NULL
                                        REFERENCES patients(id)
                                        ON DELETE RESTRICT,

    -- Optional link to the appointment/consultation that triggered this bill
    -- NULL allowed for bills not tied to a single appointment (e.g., monthly charges)
    appointment_id      UUID            NULL
                                        REFERENCES appointments(id)
                                        ON DELETE SET NULL,

    -- Human-readable bill number; unique per clinic (e.g., CLN001-2024-00123)
    bill_number         VARCHAR(50)     NOT NULL,

    -- Lifecycle status
    status              bill_status     NOT NULL DEFAULT 'draft',

    -- ==========================================================================
    -- Financial breakdown — all amounts in smallest currency unit (e.g., paise)
    -- stored as NUMERIC to avoid floating-point rounding errors in money calcs
    -- ==========================================================================
    subtotal            NUMERIC(12, 2)  NOT NULL DEFAULT 0.00
                                        CHECK (subtotal >= 0),

    -- Flat discount amount (not percentage); percentage logic lives in app layer
    discount_amount     NUMERIC(12, 2)  NOT NULL DEFAULT 0.00
                                        CHECK (discount_amount >= 0),

    -- Discount percentage for display/reporting purposes only
    discount_percent    NUMERIC(5, 2)   NOT NULL DEFAULT 0.00
                                        CHECK (discount_percent BETWEEN 0 AND 100),

    -- Tax amount (e.g., GST); computed and stored for audit immutability
    tax_amount          NUMERIC(12, 2)  NOT NULL DEFAULT 0.00
                                        CHECK (tax_amount >= 0),

    -- Tax rate applied at time of billing (stored for historical accuracy)
    tax_percent         NUMERIC(5, 2)   NOT NULL DEFAULT 0.00
                                        CHECK (tax_percent BETWEEN 0 AND 100),

    -- Final payable amount: subtotal - discount_amount + tax_amount
    -- Enforced via CHECK; authoritative calculation in application layer
    total_amount        NUMERIC(12, 2)  NOT NULL DEFAULT 0.00
                                        CHECK (total_amount >= 0),

    -- Amount already paid (supports partial payments)
    paid_amount         NUMERIC(12, 2)  NOT NULL DEFAULT 0.00
                                        CHECK (paid_amount >= 0),

    -- Balance due = total_amount - paid_amount
    -- Computed column for query convenience
    balance_due         NUMERIC(12, 2)  GENERATED ALWAYS AS
                                        (total_amount - paid_amount) STORED,

    -- Currency code (ISO 4217) — default INR for Indian clinics
    currency            CHAR(3)         NOT NULL DEFAULT 'INR',

    -- Primary payment method used; NULL until payment is recorded
    payment_method      payment_method  NULL,

    -- Insurance details — populated when payment_method = 'insurance'
    insurance_provider  VARCHAR(150)    NULL,
    insurance_policy_no VARCHAR(100)    NULL,  -- HIPAA: sensitive, encrypt at rest
    insurance_claim_no  VARCHAR(100)    NULL,
    insurance_approved_amount NUMERIC(12, 2) NULL
                                        CHECK (insurance_approved_amount >= 0),

    -- Timestamps
    due_date            DATE            NULL,   -- Payment due date for pending bills
    paid_at             TIMESTAMPTZ     NULL,   -- When full/final payment was received
    cancelled_at        TIMESTAMPTZ     NULL,
    cancellation_reason TEXT            NULL,

    -- Additional notes visible to billing staff only
    -- HIPAA: Do NOT store clinical notes here; use medical_records table
    notes               TEXT            NULL,

    -- Audit fields
    created_by          UUID            NULL
                                        REFERENCES users(id)
                                        ON DELETE SET NULL,
    updated_by          UUID            NULL
                                        REFERENCES users(id)
                                        ON DELETE SET NULL,
    created_at          TIMESTAMPTZ     NOT NULL DEFAULT NOW(),
    updated_at          TIMESTAMPTZ     NOT NULL DEFAULT NOW(),

    -- Soft delete — preserve financial records; hard delete should NEVER occur
    -- HIPAA/legal: Financial records must be retained per jurisdictional requirements
    deleted_at          TIMESTAMPTZ     NULL,

    -- Constraints
    CONSTRAINT bills_bill_number_clinic_unique
        UNIQUE (clinic_id, bill_number),

    CONSTRAINT bills_paid_amount_lte_total
        CHECK (paid_amount <= total_amount),

    CONSTRAINT bills_paid_at_required_when_paid
        CHECK (
            (status = 'paid' AND paid_at IS NOT NULL) OR
            (status != 'paid')
        ),

    CONSTRAINT bills_cancelled_at_required_when_cancelled
        CHECK (
            (status = 'cancelled' AND cancelled_at IS NOT NULL) OR
            (status != 'cancelled')
        )
);

COMMENT ON TABLE bills IS
    'Master billing records per patient service episode. Contains financial PHI — restrict access to authorized billing staff. Never hard delete; use deleted_at for soft delete.';
COMMENT ON COLUMN bills.bill_number IS
    'Human-readable invoice number unique per clinic. Format: {CLINIC_CODE}-{YEAR}-{SEQ}';
COMMENT ON COLUMN bills.subtotal IS
    'Sum of all bill_items.line_total before discounts and taxes.';
COMMENT ON COLUMN bills.balance_due IS
    'Computed: total_amount - paid_amount. Negative indicates overpayment/credit.';
COMMENT ON COLUMN bills.insurance_policy_no IS
    'HIPAA Sensitive: Insurance policy number. Encrypt at rest in production.';
COMMENT ON COLUMN bills.deleted_at IS
    'Soft delete timestamp. Financial records MUST be retained; do not hard delete.';

-- =============================================================================
-- TABLE: bill_items
-- Line items that make up a bill (services, medications, procedures, etc.)
-- HIPAA: Procedure/medication details are clinical PHI — restrict accordingly.
-- =============================================================================

CREATE TABLE bill_items (
    id                  UUID            PRIMARY KEY DEFAULT gen_random_uuid(),

    -- Parent bill reference
    bill