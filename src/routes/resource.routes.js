// src/validators/staff.validator.js
const Joi = require('joi');

const createStaffSchema = Joi.object({
  email: Joi.string().email().required(),
  full_name: Joi.string().min(2).max(100).required(),
  phone: Joi.string().pattern(/^\+?[\d\s\-]{7,15}$/).optional(),
  password: Joi.string().min(8).required(),
  employee_id: Joi.string().max(50).required(),
  department: Joi.string().max(100).required(),
  joining_date: Joi.date().iso().required(),
  role_id: Joi.string().uuid().required(),
});

const updateStaffSchema = Joi.object({
  full_name: Joi.string().min(2).max(100).optional(),
  phone: Joi.string().pattern(/^\+?[\d\s\-]{7,15}$/).optional(),
  department: Joi.string().max(100).optional(),
  employee_id: Joi.string().max(50).optional(),
  joining_date: Joi.date().iso().optional(),
  role_id: Joi.string().uuid().optional(),
  is_active: Joi.boolean().optional(),
}).min(1);

const listStaffSchema = Joi.object({
  page: Joi.number().integer().min(1).default(1),
  limit: Joi.number().integer().min(1).max(100).default(10),
  department: Joi.string().optional(),
  is_active: Joi.boolean().optional(),
  search: Joi.string().max(100).optional(),
});

module.exports = { createStaffSchema, updateStaffSchema, listStaffSchema };