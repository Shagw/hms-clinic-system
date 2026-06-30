```javascript
// ============================================================
// jwt.config.js
// ============================================================
'use strict';

module.exports = {
  accessToken: {
    secret: process.env.JWT_ACCESS_SECRET || 'access_secret_change_in_production',
    expiresIn: process.env.JWT_ACCESS_EXPIRES_IN || '15m',
  },
  refreshToken: {
    secret: process.env.JWT_REFRESH_SECRET || 'refresh_secret_change_in_production',
    expiresIn: process.env.JWT_REFRESH_EXPIRES_IN || '7d',
  },
};


// ============================================================
// src/validators/auth.validator.js
// ============================================================
'use strict';

const Joi = require('joi');

const registerSchema = Joi.object({
  // Clinic fields
  clinic_name: Joi.string().trim().min(2).max(150).required(),
  clinic_email: Joi.string().email().lowercase().required(),
  clinic_phone: Joi.string().trim().max(20).optional().allow('', null),
  clinic_address: Joi.string().trim().max(500).optional().allow('', null),

  // Admin user fields
  full_name: Joi.string().trim().min(2).max(150).required(),
  email: Joi.string().email().lowercase().required(),
  password: Joi.string()
    .min(8)
    .max(72)
    .pattern(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]/)
    .required()
    .messages({
      'string.pattern.base':
        'Password must contain at least one uppercase letter, one lowercase letter, one number, and one special character.',
    }),
  phone: Joi.string().trim().max(20).optional().allow('', null),
});

const loginSchema = Joi.object({
  email: Joi.string().email().lowercase().required(),
  password: Joi.string().required(),
  clinic_id: Joi.string().uuid().optional().allow('', null),
});

const refreshTokenSchema = Joi.object({
  refresh_token: Joi.string().required(),
});

const validate = (schema) => (req, res, next) => {
  const { error, value } = schema.validate(req.body, { abortEarly: false, stripUnknown: true });
  if (error) {
    const details = error.details.map((d) => ({ field: d.context.key, message: d.message }));
    return res.status(422).json({ success: false, message: 'Validation failed', errors: details });
  }
  req.body = value;
  next();
};

module.exports = {
  validateRegister: validate(registerSchema),
  validateLogin: validate(loginSchema),
  validateRefreshToken: validate(refreshTokenSchema),
};


// ============================================================
// src/middleware/auth.middleware.js
// ============================================================
'use strict';

const jwt = require('jsonwebtoken');
const { accessToken: accessCfg } = require('../../jwt.config');

const verifyAccessToken = (req, res, next) => {
  try {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return res.status(401).json({ success: false, message: 'Access token required.' });
    }

    const token = authHeader.split(' ')[1];
    const decoded = jwt.verify(token, accessCfg.secret);

    req.user = {
      user_id: decoded.user_id,
      clinic_id: decoded.clinic_id,
      role: decoded.role,
      email: decoded.email,
    };

    next();
  } catch (err) {
    if (err.name === 'TokenExpiredError') {
      return res.status(401).json({ success: false, message: 'Access token expired.' });
    }
    if (err.name === 'JsonWebTokenError') {
      return res.status(401).json({ success: false, message: 'Invalid access token.' });
    }
    next(err);
  }
};

const requireRole = (...allowedRoles) => (req, res, next) => {
  if (!req.user) {
    return res.status(401).json({ success: false, message: 'Unauthenticated.' });
  }
  if (!allowedRoles.includes(req.user.role)) {
    return res.status(403).json({ success: false, message: 'Insufficient permissions.' });
  }
  next();
};

module.exports = { verifyAccessToken, requireRole };


// ============================================================
// src/services/auth.service.js
// ============================================================
'use strict';

const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const { v4: uuidv4 } = require('uuid');
const supabase = require('../config/supabase');
const { accessToken: accessCfg, refreshToken: refreshCfg } = require('../../jwt.config');

const SALT_ROUNDS = 12;

// ─── Token Helpers ────────────────────────────────────────────────────────────

const signAccessToken = (payload) =>
  jwt.sign(payload, accessCfg.secret, { expiresIn: accessCfg.expiresIn });

const signRefreshToken = (payload) =>
  jwt.sign(payload, refreshCfg.secret, { expiresIn: refreshCfg.expiresIn });

const buildTokenPayload = ({ user_id, clinic_id, role, email }) => ({
  user_id,
  clinic_id,
  role,
  email,
});

// ─── Register (Clinic + Admin) ─────────────────────────────────────────────────

const register = async ({
  clinic_name,
  clinic_email,
  clinic_phone,
  clinic_address,
  full_name,
  email,
  password,
  phone,
}) => {
  // 1. Check duplicate user email
  const { data: existingUser } = await supabase
    .from('users')
    .select('id')
    .eq('email', email)
    .maybeSingle();

  if (existingUser) {
    const err = new Error('An account with this email already exists.');
    err.statusCode = 409;
    throw err;
  }

  // 2. Check duplicate clinic email
  const { data: existingClinic } = await supabase
    .from('clinics')
    .select('id')
    .eq('email', clinic_email)
    .maybeSingle();

  if (existingClinic) {
    const err = new Error('A clinic with this email already exists.');
    err.statusCode = 409;
    throw err;
  }

  // 3. Create clinic
  const clinicId = uuidv4();
  const { data: clinic, error: clinicError } = await supabase
    .from('clinics')
    .insert({
      id: clinicId,
      name: