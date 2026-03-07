const { readFile, writeFile } = require('./fileStorage');

const OTP_EXPIRY_MS = 5 * 60 * 1000;      // 5 minutes
const MAX_ATTEMPTS = 5;
const COOLDOWN_MS = 30 * 1000;             // 30 seconds

function generateOTP() {
  return Math.floor(100000 + Math.random() * 900000).toString();
}

function createOTP(phone) {
  const otps = readFile('otps');
  const otp = generateOTP();
  const now = Date.now();

  // Remove existing OTP for this phone
  const filtered = otps.filter(o => o.phone !== phone);

  filtered.push({
    phone,
    otp,
    createdAt: now,
    expiresAt: now + OTP_EXPIRY_MS,
    attempts: 0,
    lastRequestAt: now
  });

  writeFile('otps', filtered);

  return {
    otp,         // returned for demo display
    expiresIn: OTP_EXPIRY_MS / 1000
  };
}

function verifyOTP(phone, inputOtp) {
  const otps = readFile('otps');
  const entry = otps.find(o => o.phone === phone);

  if (!entry) {
    return { success: false, error: 'No OTP found. Please request a new one.' };
  }

  const now = Date.now();

  if (now > entry.expiresAt) {
    return { success: false, error: 'OTP has expired. Please request a new one.' };
  }

  if (entry.attempts >= MAX_ATTEMPTS) {
    return { success: false, error: 'Too many attempts. Please request a new OTP.' };
  }

  // Increment attempts
  entry.attempts++;
  const idx = otps.findIndex(o => o.phone === phone);
  otps[idx] = entry;
  writeFile('otps', otps);

  if (entry.otp !== inputOtp.toString()) {
    const remaining = MAX_ATTEMPTS - entry.attempts;
    return {
      success: false,
      error: `Invalid OTP. ${remaining} attempt(s) remaining.`
    };
  }

  // Mark as verified - remove it
  const updated = otps.filter(o => o.phone !== phone);
  writeFile('otps', updated);

  return { success: true };
}

function canRequestNewOTP(phone) {
  const otps = readFile('otps');
  const entry = otps.find(o => o.phone === phone);
  if (!entry) return { canRequest: true };

  const now = Date.now();
  const elapsed = now - entry.lastRequestAt;

  if (elapsed < COOLDOWN_MS) {
    return {
      canRequest: false,
      waitSeconds: Math.ceil((COOLDOWN_MS - elapsed) / 1000)
    };
  }

  return { canRequest: true };
}

// Cleanup expired OTPs
function cleanupOTPs() {
  const otps = readFile('otps');
  const now = Date.now();
  const valid = otps.filter(o => now <= o.expiresAt);
  writeFile('otps', valid);
}

module.exports = { createOTP, verifyOTP, canRequestNewOTP, cleanupOTPs };
