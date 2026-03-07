const rateLimit = require('express-rate-limit');

// General IP rate limit for all API routes
const ipRateLimit = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 200,
  message: { error: 'Too many requests from this IP, please try again later.' },
  standardHeaders: true,
  legacyHeaders: false
});

// Strict limit for OTP requests
const otpRateLimit = rateLimit({
  windowMs: 10 * 60 * 1000, // 10 minutes
  max: 10,
  message: { error: 'Too many OTP requests. Please wait before trying again.' },
  keyGenerator: (req) => req.body?.phone || req.ip
});

// Admin login rate limit
const adminLoginLimit = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 10,
  message: { error: 'Too many login attempts. Please try again after 15 minutes.' },
  keyGenerator: (req) => req.ip
});

// Voting rate limit
const votingRateLimit = rateLimit({
  windowMs: 60 * 60 * 1000, // 1 hour
  max: 20,
  message: { error: 'Too many voting attempts.' }
});

module.exports = { ipRateLimit, otpRateLimit, adminLoginLimit, votingRateLimit };
