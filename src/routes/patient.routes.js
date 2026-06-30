// src/validators/patient.validator.js
const Joi = require('joi');

const registerPatientSchema = Joi.object({
  // Patient core fields
  patient_uid: Joi.string().trim().max(50).optional(),
  first_name: Joi.string().trim().min(1).max(100).required(),
  last_name: Joi.string().trim().min(1).max(100).required(),
  date_of_birth: Joi.date().iso().max('now').required(),
  gender: Joi.string().valid('male', 'female', 'other', 'prefer_not_to_say').required(),
  phone: Joi.string().trim().pattern(/^\+?[\d\s\-().]{7,20}$/).required(),
  email: Joi.string().email().trim().lowercase().optional().allow(null, ''),
  address_line1: Joi.string().trim().max(255).optional().allow(null, ''),
  address_line2: Joi.string().trim().max(255).optional().allow(null, ''),
  city: Joi.string().trim().max(100).optional().allow(null, ''),
  state: Joi.string().trim().max(100).optional().allow(null, ''),
  postal_code: Joi.string().trim().max(20).optional().allow(null, ''),
  country: Joi.string().trim().max(100).optional().allow(null, ''),
  emergency_contact_name: Joi.string().trim().max(150).optional().allow(null, ''),
  emergency_contact_phone: Joi.string().trim().pattern(/^\+?[\d\s\-().]{7,20}$/).optional().allow(null, ''),

  // Medical info (optional at registration)
  medical_info: Joi.object({
    blood_group: Joi.string().trim().max(10).optional().allow(null, ''),
    allergies: Joi.string().trim().max(2000).optional().allow(null, ''),
    chronic_conditions: Joi.string().trim().max(2000).optional().allow(null, ''),
    current_medications: Joi.string().trim().max(2000).optional().allow(null, ''),
    past_surgeries: Joi.string().trim().max(2000).optional().allow(null, ''),
    family_history: Joi.string().trim().max(2000).optional().allow(null, ''),
    notes: Joi.string().trim().max(5000).optional().allow(null, ''),
  }).optional(),
});

const updatePatientSchema = Joi.object({
  first_name: Joi.string().trim().min(1).max(100).optional(),
  last_name: Joi.string().trim().min(1).max(100).optional(),
  date_of_birth: Joi.date().iso().max('now').optional(),
  gender: Joi.string().valid('male', 'female', 'other', 'prefer_not_to_say').optional(),
  phone: Joi.string().trim().pattern(/^\+?[\d\s\-().]{7,20}$/).optional(),
  email: Joi.string().email().trim().lowercase().optional().allow(null, ''),
  address_line1: Joi.string().trim().max(255).optional().allow(null, ''),
  address_line2: Joi.string().trim().max(255).optional().allow(null, ''),
  city: Joi.string().trim().max(100).optional().allow(null, ''),
  state: Joi.string().trim().max(100).optional().allow(null, ''),
  postal_code: Joi.string().trim().max(20).optional().allow(null, ''),
  country: Joi.string().trim().max(100).optional().allow(null, ''),
  emergency_contact_name: Joi.string().trim().max(150).optional().allow(null, ''),
  emergency_contact_phone: Joi.string().trim().pattern(/^\+?[\d\s\-().]{7,20}$/).optional().allow(null, ''),

  medical_info: Joi.object({
    blood_group: Joi.string().trim().max(10).optional().allow(null, ''),
    allergies: Joi.string().trim().max(2000).optional().allow(null, ''),
    chronic_conditions: Joi.string().trim().max(2000).optional().allow(null, ''),
    current_medications: Joi.string().trim().max(2000).optional().allow(null, ''),
    past_surgeries: Joi.string().trim().max(2000).optional().allow(null, ''),
    family_history: Joi.string().trim().max(2000).optional().allow(null, ''),
    notes: Joi.string().trim().max(5000).optional().allow(null, ''),
  }).optional(),
}).min(1);

const listPatientsSchema = Joi.object({
  page: Joi.number().integer().min(1).default(1),
  limit: Joi.number().integer().min(1).max(100).default(20),
  search: Joi.string().trim().max(100).optional().allow(''),
  doctor_id: Joi.string().uuid().optional(),
  gender: Joi.string().valid('male', 'female', 'other', 'prefer_not_to_say').optional(),
  sort_by: Joi.string().valid('first_name', 'last_name', 'created_at', 'date_of_birth').default('created_at'),
  sort_order: Joi.string().valid('asc', 'desc').default('desc'),
});

module.exports = { registerPatientSchema, updatePatientSchema, listPatientsSchema };