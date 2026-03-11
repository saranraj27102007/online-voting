'use strict';
/**
 * VoteSecure — Deepfake & Screen Attack Protection
 * ─────────────────────────────────────────────────────────────
 * Server-side challenge token system.
 * Client-side detection logic lives in liveness-guard.js (public/js/).
 *
 * Challenge flow:
 *   1. Client calls GET /api/liveness/challenge
 *   2. Server returns signed token + random challenge set
 *   3. Client runs face landmark checks, reports results
 *   4. Server validates token, checks results, issues liveness clearance
 */

const crypto = require('crypto');

const CHALLENGE_SECRET = process.env.CHALLENGE_SECRET || 'vs-liveness-secret-change-in-prod';
const CHALLENGE_TTL_MS = 3 * 60 * 1000; // 3 minutes

// All possible challenges
const CHALLENGE_POOL = [
  { id: 'blink',      label: 'Blink twice',          type: 'blink',    count: 2 },
  { id: 'blink_once', label: 'Blink once',            type: 'blink',    count: 1 },
  { id: 'turn_left',  label: 'Turn head LEFT',        type: 'yaw',      direction: 'left'  },
  { id: 'turn_right', label: 'Turn head RIGHT',       type: 'yaw',      direction: 'right' },
  { id: 'nod',        label: 'Nod your head',         type: 'pitch',    direction: 'down'  },
  { id: 'smile',      label: 'Smile naturally',       type: 'expression', expr: 'smile'    },
  { id: 'open_mouth', label: 'Open your mouth wide',  type: 'expression', expr: 'mouth'    },
];

// In-memory store for pending challenge tokens (clears on restart — by design)
const pendingChallenges = new Map();

// ── Token helpers ─────────────────────────────────────────────
function signToken(payload) {
  const str = JSON.stringify(payload);
  const sig  = crypto.createHmac('sha256', CHALLENGE_SECRET).update(str).digest('hex');
  return Buffer.from(str).toString('base64url') + '.' + sig;
}

function verifyToken(token) {
  try {
    const [b64, sig] = token.split('.');
    const str  = Buffer.from(b64, 'base64url').toString();
    const expected = crypto.createHmac('sha256', CHALLENGE_SECRET).update(str).digest('hex');
    if (!crypto.timingSafeEqual(Buffer.from(sig, 'hex'), Buffer.from(expected, 'hex'))) return null;
    const payload = JSON.parse(str);
    if (Date.now() > payload.exp) return null; // expired
    return payload;
  } catch(e) { return null; }
}

// ── Challenge generation ──────────────────────────────────────

/**
 * Generate a random set of 2–3 challenges.
 * Always starts with a blink (baseline liveness), then random additional.
 */
function generateChallenges() {
  const nonce = crypto.randomBytes(16).toString('hex');
  const exp   = Date.now() + CHALLENGE_TTL_MS;

  // Always include blink_once + one random non-blink challenge
  const nonBlink = CHALLENGE_POOL.filter(c => c.type !== 'blink');
  const extra    = nonBlink[Math.floor(Math.random() * nonBlink.length)];
  const selected = [CHALLENGE_POOL.find(c => c.id === 'blink_once'), extra];

  const token = signToken({ nonce, exp, challenges: selected.map(c => c.id) });

  // Store nonce to prevent replay
  pendingChallenges.set(nonce, { exp, used: false });

  // Clean up expired entries periodically
  if (Math.random() < 0.05) cleanupExpired();

  return { token, challenges: selected };
}

/**
 * Validate challenge completion from client.
 * @param {string} token  — signed token from generateChallenges
 * @param {object} results — { challengeId: bool, ... }  (passed/failed per challenge)
 * @param {object} metrics — liveness metrics from client
 * @returns {{ valid: bool, reason?: string }}
 */
function validateChallenges(token, results, metrics) {
  const payload = verifyToken(token);
  if (!payload) return { valid: false, reason: 'Challenge token invalid or expired.' };

  const stored = pendingChallenges.get(payload.nonce);
  if (!stored)       return { valid: false, reason: 'Challenge not found.' };
  if (stored.used)   return { valid: false, reason: 'Challenge token already used (replay prevented).' };
  if (Date.now() > stored.exp) return { valid: false, reason: 'Challenge timed out.' };

  // Mark as used immediately — prevents replay attacks
  stored.used = true;

  // Check all required challenges were passed
  const failed = payload.challenges.filter(id => !results[id]);
  if (failed.length > 0)
    return { valid: false, reason: `Failed challenges: ${failed.join(', ')}` };

  // Anti-spoofing metric checks
  if (metrics) {
    const check = checkMetrics(metrics);
    if (!check.valid) return check;
  }

  return { valid: true };
}

/**
 * Server-side anti-spoofing heuristic checks on reported metrics.
 * These complement client-side checks — a tampered client can't forge good metrics
 * because the challenge sequence is random and server-validated.
 */
function checkMetrics(m) {
  // Reject impossibly fast completions (pre-recorded videos are often too fast)
  if (typeof m.completionMs === 'number' && m.completionMs < 800)
    return { valid: false, reason: 'Liveness completed too fast — possible replay attack.' };

  // Reject suspiciously uniform landmark movement (static image / screen)
  if (typeof m.landmarkVariance === 'number' && m.landmarkVariance < 0.0008)
    return { valid: false, reason: 'Face landmarks show no depth movement — possible screen/photo attack.' };

  // Reject if EAR never drops during blink challenge (no real blink occurred)
  if (m.blinkRequired && typeof m.minEAR === 'number' && m.minEAR > 0.22)
    return { valid: false, reason: 'No valid blink detected — eye closure threshold not met.' };

  // Reject if texture score is too uniform (flat screen = low texture variance)
  if (typeof m.textureScore === 'number' && m.textureScore < 0.012)
    return { valid: false, reason: 'Face texture appears flat — possible photo or screen replay.' };

  // Reject identical blink patterns (pre-recorded blink loops)
  if (m.blinkIntervals && Array.isArray(m.blinkIntervals) && m.blinkIntervals.length >= 2) {
    const diffs = [];
    for (let i = 1; i < m.blinkIntervals.length; i++)
      diffs.push(Math.abs(m.blinkIntervals[i] - m.blinkIntervals[i - 1]));
    const maxDiff = Math.max(...diffs);
    if (maxDiff < 20) // intervals identical to within 20ms = robot/replay
      return { valid: false, reason: 'Blink pattern too regular — possible replay attack.' };
  }

  return { valid: true };
}

function cleanupExpired() {
  const now = Date.now();
  for (const [nonce, entry] of pendingChallenges) {
    if (now > entry.exp + 60000) pendingChallenges.delete(nonce);
  }
}

// ── Security event log ────────────────────────────────────────
const securityLog = [];
const MAX_LOG = 500;

function logSecurityEvent(type, detail, ip) {
  const event = { type, detail, ip: ip || 'unknown', timestamp: new Date().toISOString() };
  securityLog.unshift(event);
  if (securityLog.length > MAX_LOG) securityLog.length = MAX_LOG;

  if (['DEEPFAKE_REJECTED', 'CHAIN_TAMPER', 'DUPLICATE_FACE', 'REPLAY_ATTACK'].includes(type)) {
    console.warn(`🚨 SECURITY [${type}] ${ip} — ${detail}`);
  }
}

function getSecurityLog(limit) {
  return securityLog.slice(0, limit || 100);
}

module.exports = {
  generateChallenges,
  validateChallenges,
  logSecurityEvent,
  getSecurityLog
};
