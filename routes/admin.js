const express = require('express');
const bcrypt = require('bcryptjs');
const { v4: uuidv4 } = require('uuid');
const router = express.Router();

const { readFile, writeFile, findById, updateById, deleteById, appendItem } = require('../utils/fileStorage');
const { requireAdminAuth, checkIdleTimeout } = require('../middleware/auth');
const { adminLoginLimit } = require('../middleware/rateLimit');

const MAX_LOGIN_ATTEMPTS = 5;
const LOCKOUT_DURATION = 15 * 60 * 1000; // 15 minutes

// ─── Admin Login ──────────────────────────────────────────────────────────────
router.post('/login', adminLoginLimit, async (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res.status(400).json({ error: 'Username and password are required.' });
  }

  const admins = readFile('admins');
  const admin = admins.find(a => a.username === username);

  if (!admin) {
    return res.status(401).json({ error: 'Invalid credentials.' });
  }

  // Check lockout
  if (admin.lockoutUntil && new Date() < new Date(admin.lockoutUntil)) {
    const remaining = Math.ceil((new Date(admin.lockoutUntil) - Date.now()) / 60000);
    return res.status(403).json({
      error: `Account locked. Please try again in ${remaining} minute(s).`
    });
  }

  const passwordMatch = await bcrypt.compare(password, admin.password);

  if (!passwordMatch) {
    admin.loginAttempts = (admin.loginAttempts || 0) + 1;

    if (admin.loginAttempts >= MAX_LOGIN_ATTEMPTS) {
      admin.lockoutUntil = new Date(Date.now() + LOCKOUT_DURATION).toISOString();
      admin.loginAttempts = 0;
      writeFile('admins', admins);
      return res.status(403).json({
        error: 'Too many failed attempts. Account locked for 15 minutes.'
      });
    }

    writeFile('admins', admins);
    const remaining = MAX_LOGIN_ATTEMPTS - admin.loginAttempts;
    return res.status(401).json({
      error: `Invalid credentials. ${remaining} attempt(s) remaining.`
    });
  }

  // Successful login - reset attempts
  admin.loginAttempts = 0;
  admin.lockoutUntil = null;
  admin.lastLogin = new Date().toISOString();
  writeFile('admins', admins);

  // Set session
  req.session.adminId = admin.id;
  req.session.adminUsername = admin.username;
  req.session.lastActivity = Date.now();

  return res.json({ success: true, message: 'Login successful.', username: admin.username });
});

// ─── Admin Logout ─────────────────────────────────────────────────────────────
router.post('/logout', (req, res) => {
  req.session.destroy();
  res.json({ success: true, message: 'Logged out successfully.' });
});

// ─── Check auth status ────────────────────────────────────────────────────────
router.get('/check-auth', (req, res) => {
  if (req.session && req.session.adminId) {
    return res.json({ authenticated: true, username: req.session.adminUsername });
  }
  return res.json({ authenticated: false });
});

// ─── All routes below require auth ───────────────────────────────────────────
router.use(requireAdminAuth, checkIdleTimeout);

// ─── Dashboard stats ──────────────────────────────────────────────────────────
router.get('/stats', (req, res) => {
  const voters = readFile('voters');
  const elections = readFile('elections');
  const votes = readFile('votes');
  const now = new Date();

  const activeElections = elections.filter(e =>
    now >= new Date(e.startDate) && now <= new Date(e.endDate)
  );

  const totalVotes = votes.reduce((sum, ev) =>
    sum + ev.results.reduce((s, r) => s + r.count, 0), 0
  );

  res.json({
    totalVoters: voters.length,
    totalElections: elections.length,
    activeElections: activeElections.length,
    totalVotesCast: totalVotes
  });
});

// ─── Elections CRUD ───────────────────────────────────────────────────────────
router.get('/elections', (req, res) => {
  const elections = readFile('elections');
  const votes = readFile('votes');

  const enriched = elections.map(e => {
    const ev = votes.find(v => v.electionId === e.id);
    const totalVotes = ev ? ev.results.reduce((s, r) => s + r.count, 0) : 0;
    const now = new Date();
    let status = 'upcoming';
    if (now >= new Date(e.startDate) && now <= new Date(e.endDate)) status = 'active';
    if (now > new Date(e.endDate)) status = 'ended';

    return { ...e, totalVotes, status };
  });

  res.json({ elections: enriched });
});

router.post('/elections', (req, res) => {
  const { title, description, startDate, endDate, candidates, minAge, maxAge } = req.body;

  if (!title || !startDate || !endDate || !candidates?.length) {
    return res.status(400).json({ error: 'Title, dates, and at least one candidate are required.' });
  }

  if (new Date(startDate) >= new Date(endDate)) {
    return res.status(400).json({ error: 'End date must be after start date.' });
  }

  const validCandidates = candidates.map(c => ({
    id: uuidv4(),
    name: c.name?.trim(),
    party: c.party?.trim() || '',
    symbol: c.symbol?.trim() || '⬤'
  })).filter(c => c.name);

  if (validCandidates.length === 0) {
    return res.status(400).json({ error: 'At least one valid candidate is required.' });
  }

  const newElection = {
    id: uuidv4(),
    title: title.trim(),
    description: description?.trim() || '',
    startDate,
    endDate,
    candidates: validCandidates,
    minAge: minAge ? parseInt(minAge) : null,
    maxAge: maxAge ? parseInt(maxAge) : null,
    createdAt: new Date().toISOString(),
    createdBy: req.session.adminUsername
  };

  appendItem('elections', newElection);

  return res.status(201).json({ success: true, election: newElection });
});

router.put('/elections/:id', (req, res) => {
  const { id } = req.params;
  const { title, description, startDate, endDate, candidates, minAge, maxAge } = req.body;

  const elections = readFile('elections');
  const election = elections.find(e => e.id === id);

  if (!election) {
    return res.status(404).json({ error: 'Election not found.' });
  }

  const updates = {};
  if (title) updates.title = title.trim();
  if (description !== undefined) updates.description = description.trim();
  if (startDate) updates.startDate = startDate;
  if (endDate) updates.endDate = endDate;
  if (minAge !== undefined) updates.minAge = minAge ? parseInt(minAge) : null;
  if (maxAge !== undefined) updates.maxAge = maxAge ? parseInt(maxAge) : null;
  if (candidates) {
    updates.candidates = candidates.map(c => ({
      id: c.id || uuidv4(),
      name: c.name?.trim(),
      party: c.party?.trim() || '',
      symbol: c.symbol?.trim() || '⬤'
    })).filter(c => c.name);
  }

  updateById('elections', id, updates);
  return res.json({ success: true, message: 'Election updated.' });
});

router.delete('/elections/:id', (req, res) => {
  const deleted = deleteById('elections', req.params.id);
  if (!deleted) return res.status(404).json({ error: 'Election not found.' });
  return res.json({ success: true, message: 'Election deleted.' });
});

// ─── Voters management ────────────────────────────────────────────────────────
router.get('/voters', (req, res) => {
  const voters = readFile('voters');
  const safeVoters = voters.map(v => ({
    id: v.id,
    voterId: v.voterId,
    fullName: v.fullName,
    dob: v.dob,
    phone: maskPhone(v.phone),
    address: v.address,
    documentType: v.documentType,
    registeredAt: v.registeredAt,
    votedElections: v.votedElections
  }));
  res.json({ voters: safeVoters });
});

router.delete('/voters/:id', (req, res) => {
  const deleted = deleteById('voters', req.params.id);
  if (!deleted) return res.status(404).json({ error: 'Voter not found.' });
  return res.json({ success: true, message: 'Voter deleted.' });
});

// ─── Live results ─────────────────────────────────────────────────────────────
router.get('/results', (req, res) => {
  const elections = readFile('elections');
  const votes = readFile('votes');

  const results = elections.map(election => {
    const ev = votes.find(v => v.electionId === election.id);
    const totalVotes = ev ? ev.results.reduce((s, r) => s + r.count, 0) : 0;

    return {
      electionId: election.id,
      title: election.title,
      status: getElectionStatus(election),
      totalVotes,
      candidates: election.candidates.map(c => {
        const voteData = ev?.results.find(r => r.candidateId === c.id);
        const count = voteData?.count || 0;
        return {
          id: c.id,
          name: c.name,
          party: c.party,
          votes: count,
          percentage: totalVotes > 0 ? ((count / totalVotes) * 100).toFixed(1) : '0.0'
        };
      })
    };
  });

  res.json({ results });
});

// ─── Vote logs ────────────────────────────────────────────────────────────────
router.get('/vote-logs', (req, res) => {
  const logs = readFile('voteLogs');
  res.json({ logs: logs.slice().reverse() }); // newest first
});

// ─── Helpers ──────────────────────────────────────────────────────────────────
function maskPhone(phone) {
  if (!phone || phone.length < 6) return phone;
  return phone.slice(0, 2) + '******' + phone.slice(-2);
}

function getElectionStatus(election) {
  const now = new Date();
  if (now < new Date(election.startDate)) return 'upcoming';
  if (now > new Date(election.endDate)) return 'ended';
  return 'active';
}

module.exports = router;
