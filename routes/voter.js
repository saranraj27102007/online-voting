const express = require('express');
const { v4: uuidv4 } = require('uuid');
const router = express.Router();

const { readFile, writeFile, appendItem } = require('../utils/fileStorage');
const { createOTP, verifyOTP, canRequestNewOTP } = require('../utils/otp');
const {
  validatePAN, nameSimilarity, validatePhone, sanitizeString, normalizeDate
} = require('../utils/validation');
const { otpRateLimit } = require('../middleware/rateLimit');

// ─── Step 1: Send OTP ─────────────────────────────────────────────────────────
router.post('/send-otp', otpRateLimit, (req, res) => {
  const { phone } = req.body;

  if (!phone || !validatePhone(phone)) {
    return res.status(400).json({ error: 'Invalid phone number. Must be a valid 10-digit Indian mobile number.' });
  }

  const cooldown = canRequestNewOTP(phone);
  if (!cooldown.canRequest) {
    return res.status(429).json({
      error: `Please wait ${cooldown.waitSeconds} seconds before requesting a new OTP.`,
      waitSeconds: cooldown.waitSeconds
    });
  }

  const { otp, expiresIn } = createOTP(phone);

  // In production, send via SMS. For demo, return OTP.
  return res.json({
    success: true,
    message: 'OTP sent successfully (Demo Mode).',
    demoOtp: otp,  // Remove this in real deployment
    expiresIn
  });
});

// ─── Step 2: Verify OTP ───────────────────────────────────────────────────────
router.post('/verify-otp', (req, res) => {
  const { phone, otp } = req.body;

  if (!phone || !otp) {
    return res.status(400).json({ error: 'Phone and OTP are required.' });
  }

  const result = verifyOTP(phone, otp);
  if (!result.success) {
    return res.status(400).json({ error: result.error });
  }

  // Store phone verification in session
  req.session.verifiedPhone = phone;
  req.session.otpVerified = true;

  return res.json({ success: true, message: 'Phone number verified successfully.' });
});

// ─── Step 3: Verify ID Document (OCR result from frontend) ───────────────────
router.post('/verify-id', (req, res) => {
  if (!req.session.otpVerified) {
    return res.status(403).json({ error: 'Please complete OTP verification first.' });
  }

  const { documentType, ocrData, voterName, voterDob } = req.body;

  if (!documentType || !ocrData) {
    return res.status(400).json({ error: 'Document type and OCR data are required.' });
  }

  const cleanVoterName = sanitizeString(voterName);
  const cleanOcrName   = sanitizeString(ocrData.name  || '');
  const ocrDob         = (ocrData.dob  || '').trim();
  const ocrPan         = (ocrData.pan  || '').toUpperCase().trim();

  // ── Name similarity check ──────────────────────────────────────────────────
  // OCR often fails to extract names from phone-camera photos.
  // Rule: only enforce name match when OCR actually extracted a name (≥ 3 chars).
  // Threshold lowered to 0.55 to tolerate OCR transcription errors.
  let similarity = 100;
  if (cleanOcrName.length >= 3) {
    similarity = Math.round(nameSimilarity(cleanVoterName, cleanOcrName) * 100);
    if (similarity < 55) {
      return res.status(400).json({
        error: `Name on document ("${cleanOcrName}") doesn't match your entered name ("${cleanVoterName}") — ${similarity}% match, need at least 55%. Check your name or re-scan a clearer image.`,
        similarity
      });
    }
  }
  // If OCR couldn't read name at all (< 3 chars) → skip name check silently

  // ── DOB check ─────────────────────────────────────────────────────────────
  // DOB is OPTIONAL: if OCR couldn't extract a date, skip the check.
  // We never hard-block registration due to OCR failure.
  // (DOB mismatch is not enforced here — the voter's self-reported DOB is
  //  stored in the voter record and used for age checks at vote-cast time.)

  // ── PAN-specific: require valid PAN number format ──────────────────────────
  if (documentType === 'pan') {
    if (ocrPan && !validatePAN(ocrPan)) {
      return res.status(400).json({
        error: `PAN number extracted ("${ocrPan}") has invalid format. Expected: ABCDE1234F. Try a clearer scan.`
      });
    }
    // If ocrPan is empty, OCR failed to read it — allow through
  }

  // All checks passed
  req.session.idVerified   = true;
  req.session.documentType = documentType;
  req.session.ocrData      = {
    name: cleanOcrName || null,
    dob:  ocrDob       || null,
    pan:  ocrPan       || null
  };

  return res.json({
    success: true,
    message: cleanOcrName.length >= 3
      ? `Document verified. Name match: ${similarity}%.`
      : 'Document accepted (OCR could not read text — manual review may apply).',
    similarity,
    extractedData: {
      name: cleanOcrName || null,
      dob:  ocrDob       || null,
      pan:  ocrPan       || null
    }
  });
});

// ─── Step 4: Save face descriptor & check for duplicates ─────────────────────
router.post('/verify-face', (req, res) => {
  if (!req.session.idVerified) {
    return res.status(403).json({ error: 'Please complete ID verification first.' });
  }

  const { faceDescriptor } = req.body;

  if (!faceDescriptor || !Array.isArray(faceDescriptor)) {
    return res.status(400).json({ error: 'Face descriptor data is required.' });
  }

  // Check for duplicate face among existing voters
  const voters = readFile('voters');

  for (const voter of voters) {
    if (!voter.faceDescriptor) continue;

    const distance = euclideanDistance(faceDescriptor, voter.faceDescriptor);
    if (distance < 0.45) {
      return res.status(409).json({
        error: 'This voter appears to already be registered.',
        isDuplicate: true
      });
    }
  }

  req.session.faceDescriptor = faceDescriptor;
  req.session.faceVerified = true;

  return res.json({
    success: true,
    message: 'Face captured and verified successfully. No duplicates found.'
  });
});

// ─── Step 5: Complete Registration ───────────────────────────────────────────
router.post('/register', (req, res) => {
  // All steps must be complete
  if (!req.session.otpVerified || !req.session.idVerified || !req.session.faceVerified) {
    return res.status(403).json({
      error: 'Please complete all verification steps before registering.'
    });
  }

  const { fullName, dob, phone, address } = req.body;

  if (!fullName || !dob || !phone || !address) {
    return res.status(400).json({ error: 'All fields are required.' });
  }

  if (!validatePhone(phone)) {
    return res.status(400).json({ error: 'Invalid phone number.' });
  }

  // Verify session phone matches submitted phone
  if (req.session.verifiedPhone !== phone) {
    return res.status(400).json({ error: 'Phone number does not match verified phone.' });
  }

  const normalizedDob = normalizeDate(dob);
  const cleanName = sanitizeString(fullName);

  const voters = readFile('voters');

  // Check for duplicate phone
  if (voters.find(v => v.phone === phone)) {
    return res.status(409).json({ error: 'This voter appears to already be registered.' });
  }

  // Check for duplicate name + DOB
  const nameDobDup = voters.find(v =>
    nameSimilarity(v.fullName, cleanName) >= 0.95 && v.dob === normalizedDob
  );
  if (nameDobDup) {
    return res.status(409).json({ error: 'This voter appears to already be registered.' });
  }

  // Generate Voter ID
  const voterId = generateVoterId();

  const newVoter = {
    id: uuidv4(),
    voterId,
    fullName: cleanName,
    dob: normalizedDob,
    phone,
    address: sanitizeString(address),
    documentType: req.session.documentType,
    faceDescriptor: req.session.faceDescriptor,
    registeredAt: new Date().toISOString(),
    registrationIP: req.ip,
    votedElections: []
  };

  if (!appendItem('voters', newVoter)) {
    return res.status(500).json({ error: 'Failed to save voter data. Please try again.' });
  }

  // Clear registration session
  req.session.otpVerified = false;
  req.session.idVerified = false;
  req.session.faceVerified = false;
  req.session.faceDescriptor = null;
  req.session.verifiedPhone = null;

  return res.status(201).json({
    success: true,
    message: 'Registration successful!',
    voterId,
    voterName: cleanName
  });
});

// ─── Helper: Generate Voter ID ────────────────────────────────────────────────
function generateVoterId() {
  const prefix = 'VS';
  const year = new Date().getFullYear().toString().slice(-2);
  const random = Math.floor(10000000 + Math.random() * 90000000);
  return `${prefix}${year}${random}`;
}

// ─── Helper: Euclidean distance between face descriptors ─────────────────────
function euclideanDistance(desc1, desc2) {
  if (desc1.length !== desc2.length) return Infinity;
  let sum = 0;
  for (let i = 0; i < desc1.length; i++) {
    sum += Math.pow(desc1[i] - desc2[i], 2);
  }
  return Math.sqrt(sum);
}

module.exports = router;
