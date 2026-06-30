```javascript
const express = require('express');
const Joi = require('joi');
const { createClient } = require('@supabase/supabase-js');
const { verifyToken } = require('../middleware/auth.middleware');

const router = express.Router();

const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_ROLE_KEY
);

// ─── Inline Validators ────────────────────────────────────────────────────────

const createPatientSchema = Joi.object({
  first_name: Joi.string().trim().min(1).max(100).required(),
  last_name: Joi.string().trim().min(1).max(100).required(),
  patient_uid: Joi.string().trim().max(50).optional(),
  date_of_birth: Joi.date().iso().max('now').optional(),
  gender: Joi.string().valid('male', 'female', 'other', 'prefer_not_to_say').optional(),
  phone: Joi.string().trim().max(20).optional(),
  email: Joi.string().email().max(255).optional(),
  address: Joi.string().trim().max(500).optional(),
  blood_group: Joi.string().valid('A+', 'A-', 'B+', 'B-', 'AB+', 'AB-', 'O+', 'O-').optional(),
  allergies: Joi.array().items(Joi.string()).optional(),
  emergency_contact_name: Joi.string().trim().max(100).optional(),
  emergency_contact_phone: Joi.string().trim().max(20).optional(),
});

const updatePatientSchema = Joi.object({
  first_name: Joi.string().trim().min(1).max(100).optional(),
  last_name: Joi.string().trim().min(1).max(100).optional(),
  patient_uid: Joi.string().trim().max(50).optional(),
  date_of_birth: Joi.date().iso().max('now').optional(),
  gender: Joi.string().valid('male', 'female', 'other', 'prefer_not_to_say').optional(),
  phone: Joi.string().trim().max(20).optional(),
  email: Joi.string().email().max(255).optional(),
  address: Joi.string().trim().max(500).optional(),
  blood_group: Joi.string().valid('A+', 'A-', 'B+', 'B-', 'AB+', 'AB-', 'O+', 'O-').optional(),
  allergies: Joi.array().items(Joi.string()).optional(),
  emergency_contact_name: Joi.string().trim().max(100).optional(),
  emergency_contact_phone: Joi.string().trim().max(20).optional(),
}).min(1);

const listQuerySchema = Joi.object({
  page: Joi.number().integer().min(1).default(1),
  limit: Joi.number().integer().min(1).max(100).default(20),
  search: Joi.string().trim().max(100).optional(),
  gender: Joi.string().valid('male', 'female', 'other', 'prefer_not_to_say').optional(),
  blood_group: Joi.string().valid('A+', 'A-', 'B+', 'B-', 'AB+', 'AB-', 'O+', 'O-').optional(),
  sort_by: Joi.string().valid('created_at', 'first_name', 'last_name', 'patient_uid').default('created_at'),
  sort_order: Joi.string().valid('asc', 'desc').default('desc'),
});

// ─── Audit Log Helper ─────────────────────────────────────────────────────────

async function insertAuditLog({ clinicId, userId, action, resource, resourceId, oldValue, newValue }) {
  const { error } = await supabase.from('audit_logs').insert({
    clinic_id: clinicId,
    user_id: userId,
    action,
    resource,
    resource_id: resourceId,
    old_value: oldValue ?? null,
    new_value: newValue ?? null,
    created_at: new Date().toISOString(),
  });

  if (error) {
    console.error('[audit_log] Failed to insert audit log:', error.message);
  }
}

// ─── POST / — Create Patient ──────────────────────────────────────────────────

router.post('/', verifyToken, async (req, res) => {
  const { error: validationError, value } = createPatientSchema.validate(req.body, {
    abortEarly: false,
    stripUnknown: true,
  });

  if (validationError) {
    return res.status(400).json({
      success: false,
      message: 'Validation failed',
      errors: validationError.details.map((d) => ({
        field: d.context?.key,
        message: d.message,
      })),
    });
  }

  const clinicId = req.user.clinic_id;
  const userId = req.user.user_id;

  // Check for duplicate patient_uid within clinic
  if (value.patient_uid) {
    const { data: existing, error: dupError } = await supabase
      .from('patients')
      .select('id')
      .eq('clinic_id', clinicId)
      .eq('patient_uid', value.patient_uid)
      .maybeSingle();

    if (dupError) {
      return res.status(500).json({ success: false, message: 'Database error during duplicate check' });
    }

    if (existing) {
      return res.status(409).json({
        success: false,
        message: 'A patient with this UID already exists in the clinic',
      });
    }
  }

  const insertPayload = {
    ...value,
    clinic_id: clinicId,
    created_by: userId,
    created_at: new Date().toISOString(),
    updated_at: new Date().toISOString(),
  };

  const { data: patient, error: insertError } = await supabase
    .from('patients')
    .insert(insertPayload)
    .select()
    .single();

  if (insertError) {
    console.error('[POST /patients]', insertError.message);
    return res.status(500).json({ success: false, message: 'Failed to create patient' });
  }

  await insertAuditLog({
    clinicId,
    userId,
    action: 'create',
    resource: 'patients',
    resourceId: patient.id,
    oldValue: null,
    newValue: patient,
  });

  return res.status(201).json({
    success: true,
    message: 'Patient created successfully',
    data: patient,
  });
});

// ─── GET / — List Patients ────────────────────────────────────────────────────

router.get('/', verifyToken, async (req,