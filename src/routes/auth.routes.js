// src/middleware/auth.middleware.js
const jwt = require('jsonwebtoken');
const { jwtConfig } = require('../config/jwt.config');
const supabase = require('../config/supabase.config');

const verifyToken = async (req, res, next) => {
  try {
    const authHeader = req.headers.authorization;

    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return res.status(401).json({
        success: false,
        error: 'Unauthorized',
        message: 'Missing or malformed Authorization header',
      });
    }

    const token = authHeader.split(' ')[1];

    if (!token) {
      return res.status(401).json({
        success: false,
        error: 'Unauthorized',
        message: 'Token not provided',
      });
    }

    let decoded;
    try {
      decoded = jwt.verify(token, jwtConfig.accessToken.secret);
    } catch (err) {
      if (err.name === 'TokenExpiredError') {
        return res.status(401).json({
          success: false,
          error: 'TokenExpired',
          message: 'Access token has expired',
        });
      }
      if (err.name === 'JsonWebTokenError') {
        return res.status(401).json({
          success: false,
          error: 'InvalidToken',
          message: 'Access token is invalid',
        });
      }
      throw err;
    }

    // Verify user still exists and is active
    const { data: user, error: userError } = await supabase
      .from('users')
      .select('id, email, is_active, deleted_at')
      .eq('id', decoded.user_id)
      .single();

    if (userError || !user) {
      return res.status(401).json({
        success: false,
        error: 'Unauthorized',
        message: 'User not found',
      });
    }

    if (!user.is_active || user.deleted_at) {
      return res.status(401).json({
        success: false,
        error: 'Unauthorized',
        message: 'User account is inactive or deleted',
      });
    }

    // Verify user still has role in the clinic from the token
    const { data: userClinicRole, error: roleError } = await supabase
      .from('user_clinic_roles')
      .select('role, clinic_id')
      .eq('user_id', decoded.user_id)
      .eq('clinic_id', decoded.clinic_id)
      .eq('is_active', true)
      .single();

    if (roleError || !userClinicRole) {
      return res.status(403).json({
        success: false,
        error: 'Forbidden',
        message: 'User does not have an active role in this clinic',
      });
    }

    req.user = {
      user_id: decoded.user_id,
      email: user.email,
      clinic_id: decoded.clinic_id,
      role: userClinicRole.role,
    };

    next();
  } catch (err) {
    console.error('[verifyToken] Unexpected error:', err);
    return res.status(500).json({
      success: false,
      error: 'InternalServerError',
      message: 'Authentication failed due to a server error',
    });
  }
};

module.exports = { verifyToken };