const express = require('express');
const session = require('express-session');
const bcrypt = require('bcryptjs');
const { v4: uuidv4 } = require('uuid');
const fs = require('fs');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;

const DATA_DIR = path.join(__dirname, 'data');
const VOTERS_FILE = path.join(DATA_DIR, 'voters.json');
const ADMINS_FILE = path.join(DATA_DIR, 'admins.json');
const ELECTIONS_FILE = path.join(DATA_DIR, 'elections.json');
const VOTES_FILE = path.join(DATA_DIR, 'votes.json');

// ── Init Data ────────────────────────────────────────────────────────────────
function initData() {
  if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR);

  if (!fs.existsSync(ADMINS_FILE)) {
    fs.writeFileSync(ADMINS_FILE, JSON.stringify([{
      id: 'admin-001',
      name: 'Chief Administrator',
      username: 'admin',
      password: bcrypt.hashSync('admin123', 10),
      createdAt: new Date().toISOString()
    }], null, 2));
  }

  if (!fs.existsSync(VOTERS_FILE)) {
    fs.writeFileSync(VOTERS_FILE, JSON.stringify([], null, 2));
  }

  if (!fs.existsSync(ELECTIONS_FILE)) {
    fs.writeFileSync(ELECTIONS_FILE, JSON.stringify([{
      id: 'election-001',
      title: 'General Election 2024',
      description: 'Vote for your preferred candidate for the general elections.',
      startDate: new Date().toISOString(),
      endDate: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000).toISOString(),
      status: 'active',
      candidates: [
        { id: 'c1', name: 'Alice Johnson', party: 'Progressive Party', symbol: '🌟', color: '#4f46e5' },
        { id: 'c2', name: 'Bob Williams', party: 'National Alliance', symbol: '🦅', color: '#059669' },
        { id: 'c3', name: 'Carol Smith', party: 'Peoples Front', symbol: '🌹', color: '#dc2626' },
        { id: 'c4', name: 'David Brown', party: 'Liberty Union', symbol: '🗽', color: '#d97706' }
      ],
      createdAt: new Date().toISOString()
    }], null, 2));
  }

  if (!fs.existsSync(VOTES_FILE)) {
    fs.writeFileSync(VOTES_FILE, JSON.stringify([], null, 2));
  }
}

const readJSON = (f) => JSON.parse(fs.readFileSync(f, 'utf8'));
const writeJSON = (f, d) => fs.writeFileSync(f, JSON.stringify(d, null, 2));

// ── Middleware ────────────────────────────────────────────────────────────────
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));
app.use(express.static(path.join(__dirname, 'public')));
app.use(session({
  secret: 'securevote-2024-secret',
  resave: false,
  saveUninitialized: false,
  cookie: { maxAge: 2 * 60 * 60 * 1000 }
}));

const requireVoter = (req, res, next) => {
  if (!req.session.voter) return res.status(401).json({ error: 'Not authenticated as voter' });
  next();
};
const requireAdmin = (req, res, next) => {
  if (!req.session.admin) return res.status(401).json({ error: 'Not authenticated as admin' });
  next();
};

// ══════════════════════════════════════════════════════
// OTP SYSTEM (in-memory, 5-min expiry)
// ══════════════════════════════════════════════════════
const otpStore = new Map(); // phone -> { otp, expiresAt, verified }

function generateOTP() {
  return Math.floor(100000 + Math.random() * 900000).toString();
}

// Send OTP
app.post('/api/otp/send', (req, res) => {
  const { phone } = req.body;
  if (!phone || phone.replace(/\D/g,'').length < 10)
    return res.status(400).json({ error: 'Valid phone number required (10 digits minimum)' });

  const clean = phone.replace(/\D/g,'').slice(-10);
  const otp   = generateOTP();
  const expiresAt = Date.now() + 5 * 60 * 1000; // 5 minutes

  otpStore.set(clean, { otp, expiresAt, verified: false });

  // ── In production: integrate Twilio/MSG91/Fast2SMS here ──
  // For demo: log to console + return in response
  console.log(`\n📱 OTP for ${clean}: ${otp}  (expires in 5 min)\n`);

  res.json({
    success: true,
    message: `OTP sent to +91 ******${clean.slice(-4)}`,
    // DEMO ONLY — remove demoOtp in production
    demoOtp: otp
  });
});

// Verify OTP
app.post('/api/otp/verify', (req, res) => {
  const { phone, otp } = req.body;
  if (!phone || !otp)
    return res.status(400).json({ error: 'Phone and OTP required' });

  const clean  = phone.replace(/\D/g,'').slice(-10);
  const record = otpStore.get(clean);

  if (!record)
    return res.status(400).json({ error: 'OTP not sent to this number. Please request a new OTP.' });
  if (Date.now() > record.expiresAt)
    return res.status(400).json({ error: 'OTP expired. Please request a new one.' });
  if (record.otp !== otp.trim())
    return res.status(400).json({ error: 'Incorrect OTP. Please try again.' });

  record.verified = true;
  otpStore.set(clean, record);
  res.json({ success: true, message: 'Phone verified successfully!' });
});

// ══════════════════════════════════════════════════════
// VOTER ROUTES
// ══════════════════════════════════════════════════════

// ── Euclidean distance between two face descriptor arrays ─────────────────────
function euclideanDistance(a, b) {
  if (!a || !b || a.length !== b.length) return 999;
  let sum = 0;
  for (let i = 0; i < a.length; i++) {
    const diff = a[i] - b[i];
    sum += diff * diff;
  }
  return Math.sqrt(sum);
}

// Register Voter
app.post('/api/voter/register', (req, res) => {
  const { name, dob, phone, address, faceDescriptor, proofType, proofVerified } = req.body;
  if (!name || !dob || !faceDescriptor)
    return res.status(400).json({ error: 'Name, date of birth, and face data are required' });
  if (!phone)
    return res.status(400).json({ error: 'Phone number is required' });

  // Verify OTP was completed
  const clean  = phone.replace(/\D/g,'').slice(-10);
  const record = otpStore.get(clean);
  if (!record || !record.verified)
    return res.status(400).json({ error: 'Phone OTP verification is required before registration.' });

  // Verify document proof was done
  if (!proofVerified)
    return res.status(400).json({ error: 'ID document proof verification is required.' });

  const voters = readJSON(VOTERS_FILE);
  const newDesc = faceDescriptor;

  // ── 1. Check duplicate phone ────────────────────────────────────────────────
  const phoneMatch = voters.find(v => v.phone && v.phone.replace(/\D/g,'').slice(-10) === clean);
  if (phoneMatch) {
    return res.status(409).json({
      error: 'DUPLICATE_VOTER', type: 'phone',
      message: 'This phone number is already registered.',
      existingVoterId: phoneMatch.voterId, existingName: phoneMatch.name
    });
  }

  // ── 2. Check duplicate NAME + DOB ───────────────────────────────────────────
  const nameDobMatch = voters.find(v =>
    v.name.trim().toLowerCase() === name.trim().toLowerCase() && v.dob === dob
  );
  if (nameDobMatch) {
    return res.status(409).json({
      error: 'DUPLICATE_VOTER', type: 'name_dob',
      message: 'You are already registered as a voter!',
      existingVoterId: nameDobMatch.voterId, existingName: nameDobMatch.name
    });
  }

  // ── 3. Check duplicate FACE (biometric) ─────────────────────────────────────
  const FACE_THRESHOLD = 0.45;
  let faceMatch = null, minDist = 999;
  for (const voter of voters) {
    if (!voter.faceDescriptor || voter.faceDescriptor.length !== 128) continue;
    const dist = euclideanDistance(newDesc, voter.faceDescriptor);
    if (dist < minDist) { minDist = dist; if (dist < FACE_THRESHOLD) faceMatch = voter; }
  }
  if (faceMatch) {
    return res.status(409).json({
      error: 'DUPLICATE_VOTER', type: 'face',
      message: 'Your face is already registered as a voter!',
      existingVoterId: faceMatch.voterId, existingName: faceMatch.name,
      confidence: Math.round((1 - minDist) * 130)
    });
  }

  // ── 4. All clear — register ─────────────────────────────────────────────────
  const voterId = 'VTR-' + Math.random().toString(36).toUpperCase().slice(2, 7) +
    Math.floor(Math.random() * 1000).toString().padStart(3, '0');

  const newVoter = {
    id: uuidv4(), voterId, name, dob, phone, address: address || '',
    proofType: proofType || 'aadhaar',
    faceDescriptor,
    registeredAt: new Date().toISOString(),
    status: 'active'
  };

  voters.push(newVoter);
  writeJSON(VOTERS_FILE, voters);
  otpStore.delete(clean); // clear used OTP
  res.json({ success: true, voterId, name });
});

// Voter Login
app.post('/api/voter/login', (req, res) => {
  const { voterId } = req.body;
  if (!voterId) return res.status(400).json({ error: 'Voter ID required' });

  const voters = readJSON(VOTERS_FILE);
  const voter = voters.find(v => v.voterId === voterId.toUpperCase().trim());

  if (!voter) return res.status(404).json({ error: 'Voter ID not found. Please register first.' });
  if (voter.status !== 'active') return res.status(403).json({ error: 'Your voter account is inactive.' });

  // Return voter info + face descriptor for client-side face verification
  res.json({
    success: true,
    voter: {
      id: voter.id,
      voterId: voter.voterId,
      name: voter.name,
      faceDescriptor: voter.faceDescriptor
    }
  });
});

// Complete Login After Face Verification
app.post('/api/voter/session', (req, res) => {
  const { voterId } = req.body;
  const voters = readJSON(VOTERS_FILE);
  const voter = voters.find(v => v.voterId === voterId);
  if (!voter) return res.status(404).json({ error: 'Voter not found' });

  req.session.voter = { id: voter.id, voterId: voter.voterId, name: voter.name, dob: voter.dob };
  res.json({ success: true, voter: req.session.voter });
});

// Voter Logout
app.post('/api/voter/logout', (req, res) => {
  req.session.destroy();
  res.json({ success: true });
});

// Get current voter session
app.get('/api/voter/me', (req, res) => {
  if (!req.session.voter) return res.json({ voter: null });
  // Refresh dob from file in case it wasn't in the session
  const voters = readJSON(VOTERS_FILE);
  const voter  = voters.find(v => v.id === req.session.voter.id);
  res.json({ voter: voter ? { ...req.session.voter, dob: voter.dob } : req.session.voter });
});

// Get elections for voter
app.get('/api/voter/elections', requireVoter, (req, res) => {
  const elections = readJSON(ELECTIONS_FILE);
  const votes = readJSON(VOTES_FILE);
  const voterId = req.session.voter.id;

  const result = elections.map(e => {
    const userVote = votes.find(v => v.electionId === e.id && v.voterId === voterId);
    const totalVotes = votes.filter(v => v.electionId === e.id).length;
    const candidateVotes = e.candidates.map(c => ({
      ...c,
      votes: votes.filter(v => v.electionId === e.id && v.candidateId === c.id).length
    }));
    return { ...e, candidates: candidateVotes, userVoted: !!userVote, userVotedFor: userVote?.candidateId, totalVotes };
  });

  res.json(result);
});

// Cast Vote (face already verified client-side)
app.post('/api/voter/vote', requireVoter, (req, res) => {
  const { electionId, candidateId } = req.body;
  const elections = readJSON(ELECTIONS_FILE);
  const votes     = readJSON(VOTES_FILE);
  const voters    = readJSON(VOTERS_FILE);
  const voterId   = req.session.voter.id;

  const election = elections.find(e => e.id === electionId);
  if (!election) return res.status(404).json({ error: 'Election not found' });
  if (election.status !== 'active') return res.status(400).json({ error: 'Election is not active' });

  const now = new Date();
  if (now < new Date(election.startDate) || now > new Date(election.endDate))
    return res.status(400).json({ error: 'Election is not currently open' });

  // ── Age limit check ──────────────────────────────────────────────────────────
  const minAge = election.minAge || 0;
  const maxAge = election.maxAge || 0;
  if (minAge > 0 || maxAge > 0) {
    const voter = voters.find(v => v.id === voterId);
    if (!voter || !voter.dob) return res.status(400).json({ error: 'Voter date of birth not found.' });

    const dob = new Date(voter.dob);
    let age = now.getFullYear() - dob.getFullYear();
    const monthDiff = now.getMonth() - dob.getMonth();
    if (monthDiff < 0 || (monthDiff === 0 && now.getDate() < dob.getDate())) age--;

    if (minAge > 0 && age < minAge)
      return res.status(403).json({
        error: `AGE_RESTRICTED`,
        message: `You must be at least ${minAge} years old to vote in this election. Your age: ${age}.`
      });

    if (maxAge > 0 && age > maxAge)
      return res.status(403).json({
        error: `AGE_RESTRICTED`,
        message: `You must be ${maxAge} years old or younger to vote in this election. Your age: ${age}.`
      });
  }

  const alreadyVoted = votes.find(v => v.electionId === electionId && v.voterId === voterId);
  if (alreadyVoted) return res.status(400).json({ error: 'You have already voted in this election!' });

  const candidate = election.candidates.find(c => c.id === candidateId);
  if (!candidate) return res.status(400).json({ error: 'Invalid candidate' });

  const vote = {
    id: uuidv4(),
    electionId,
    voterId,
    voterName: req.session.voter.name,
    candidateId,
    votedAt: new Date().toISOString()
  };
  votes.push(vote);
  writeJSON(VOTES_FILE, votes);

  res.json({ success: true, message: `Vote cast for ${candidate.name} successfully!` });
});

// ══════════════════════════════════════════════════════
// ADMIN ROUTES
// ══════════════════════════════════════════════════════

app.post('/api/admin/login', (req, res) => {
  const { username, password } = req.body;
  const admins = readJSON(ADMINS_FILE);
  const admin = admins.find(a => a.username === username);

  if (!admin || !bcrypt.compareSync(password, admin.password))
    return res.status(401).json({ error: 'Invalid username or password' });

  req.session.admin = { id: admin.id, name: admin.name, username: admin.username };
  res.json({ success: true, admin: req.session.admin });
});

app.post('/api/admin/logout', (req, res) => {
  req.session.destroy();
  res.json({ success: true });
});

app.get('/api/admin/me', (req, res) => {
  res.json({ admin: req.session.admin || null });
});

// Stats
app.get('/api/admin/stats', requireAdmin, (req, res) => {
  const voters = readJSON(VOTERS_FILE);
  const elections = readJSON(ELECTIONS_FILE);
  const votes = readJSON(VOTES_FILE);

  res.json({
    totalVoters: voters.length,
    totalElections: elections.length,
    activeElections: elections.filter(e => e.status === 'active').length,
    totalVotes: votes.length,
    votersTurnout: voters.length ? Math.round((new Set(votes.map(v => v.voterId)).size / voters.length) * 100) : 0
  });
});

// All elections with results
app.get('/api/admin/elections', requireAdmin, (req, res) => {
  const elections = readJSON(ELECTIONS_FILE);
  const votes = readJSON(VOTES_FILE);

  const result = elections.map(e => {
    const electionVotes = votes.filter(v => v.electionId === e.id);
    const candidates = e.candidates.map(c => ({
      ...c,
      votes: electionVotes.filter(v => v.candidateId === c.id).length
    })).sort((a, b) => b.votes - a.votes);
    return { ...e, candidates, totalVotes: electionVotes.length };
  });
  res.json(result);
});

// Create election
app.post('/api/admin/elections', requireAdmin, (req, res) => {
  const { title, description, startDate, endDate, candidates, minAge, maxAge } = req.body;
  if (!title || !candidates?.length || candidates.length < 2)
    return res.status(400).json({ error: 'Title and at least 2 candidates required' });

  const elections = readJSON(ELECTIONS_FILE);
  const colors = ['#4f46e5', '#059669', '#dc2626', '#d97706', '#7c3aed', '#0891b2'];
  const newElection = {
    id: uuidv4(),
    title, description,
    startDate: new Date(startDate).toISOString(),
    endDate: new Date(endDate).toISOString(),
    status: 'active',
    minAge: parseInt(minAge) || 0,
    maxAge: parseInt(maxAge) || 0,
    candidates: candidates.map((c, i) => ({ id: uuidv4().slice(0, 8), ...c, color: colors[i % colors.length] })),
    createdAt: new Date().toISOString()
  };
  elections.push(newElection);
  writeJSON(ELECTIONS_FILE, elections);
  res.json({ success: true, election: newElection });
});

// Update election status
app.put('/api/admin/elections/:id/status', requireAdmin, (req, res) => {
  const elections = readJSON(ELECTIONS_FILE);
  const idx = elections.findIndex(e => e.id === req.params.id);
  if (idx === -1) return res.status(404).json({ error: 'Not found' });
  elections[idx].status = req.body.status;
  writeJSON(ELECTIONS_FILE, elections);
  res.json({ success: true });
});

// Delete election
app.delete('/api/admin/elections/:id', requireAdmin, (req, res) => {
  let elections = readJSON(ELECTIONS_FILE);
  elections = elections.filter(e => e.id !== req.params.id);
  writeJSON(ELECTIONS_FILE, elections);
  res.json({ success: true });
});

// All voters
app.get('/api/admin/voters', requireAdmin, (req, res) => {
  const voters = readJSON(VOTERS_FILE).map(v => ({ ...v, faceDescriptor: '[stored]' }));
  const votes = readJSON(VOTES_FILE);
  const result = voters.map(v => ({
    ...v,
    hasVoted: votes.some(vt => vt.voterId === v.id),
    voteCount: votes.filter(vt => vt.voterId === v.id).length
  }));
  res.json(result);
});

// Delete voter
app.delete('/api/admin/voters/:id', requireAdmin, (req, res) => {
  let voters = readJSON(VOTERS_FILE);
  voters = voters.filter(v => v.id !== req.params.id);
  writeJSON(VOTERS_FILE, voters);
  res.json({ success: true });
});

// Vote log
app.get('/api/admin/votes', requireAdmin, (req, res) => {
  const votes = readJSON(VOTES_FILE);
  const elections = readJSON(ELECTIONS_FILE);
  const result = votes.map(v => {
    const election = elections.find(e => e.id === v.electionId);
    const candidate = election?.candidates.find(c => c.id === v.candidateId);
    return { ...v, electionTitle: election?.title, candidateName: candidate?.name };
  });
  res.json(result.reverse());
});

// ── Pages ─────────────────────────────────────────────
app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));
app.get('/register', (req, res) => res.sendFile(path.join(__dirname, 'public', 'pages', 'register.html')));
app.get('/voter-login', (req, res) => res.sendFile(path.join(__dirname, 'public', 'pages', 'voter-login.html')));
app.get('/vote', (req, res) => res.sendFile(path.join(__dirname, 'public', 'pages', 'vote.html')));
app.get('/admin-login', (req, res) => res.sendFile(path.join(__dirname, 'public', 'pages', 'admin-login.html')));
app.get('/admin', (req, res) => res.sendFile(path.join(__dirname, 'public', 'pages', 'admin.html')));

initData();
app.listen(PORT, () => {
  console.log(`\n✅  VoteSecure v2 running → http://localhost:${PORT}\n`);
});
