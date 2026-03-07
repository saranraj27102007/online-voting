const express = require('express');
const router = express.Router();

const { readFile, writeFile, appendItem } = require('../utils/fileStorage');
const { calculateAge } = require('../utils/validation');
const { votingRateLimit } = require('../middleware/rateLimit');

// ─── Get active elections ─────────────────────────────────────────────────────
router.get('/elections', (req, res) => {
  const elections = readFile('elections');
  const now = new Date();

  const active = elections.filter(e => {
    const start = new Date(e.startDate);
    const end = new Date(e.endDate);
    return now >= start && now <= end;
  }).map(e => ({
    id: e.id,
    title: e.title,
    description: e.description,
    candidates: e.candidates.map(c => ({
      id: c.id,
      name: c.name,
      party: c.party,
      symbol: c.symbol
    })),
    endDate: e.endDate,
    minAge: e.minAge,
    maxAge: e.maxAge
  }));

  res.json({ elections: active });
});

// ─── Authenticate voter by ID + face ─────────────────────────────────────────
router.post('/authenticate', votingRateLimit, (req, res) => {
  const { voterId, faceDescriptor } = req.body;

  if (!voterId || !faceDescriptor) {
    return res.status(400).json({ error: 'Voter ID and face scan are required.' });
  }

  const voters = readFile('voters');
  const voter = voters.find(v => v.voterId === voterId);

  if (!voter) {
    return res.status(404).json({ error: 'Voter ID not found. Please check and try again.' });
  }

  // Verify face
  const distance = euclideanDistance(faceDescriptor, voter.faceDescriptor);
  if (distance >= 0.45) {
    return res.status(401).json({
      error: 'Face recognition failed. Please try again in good lighting.',
      distance
    });
  }

  // Store voter session
  req.session.voterId = voter.id;
  req.session.voterVoterId = voterId;
  req.session.voterAuthenticated = true;

  return res.json({
    success: true,
    message: `Welcome, ${voter.fullName}!`,
    voter: {
      fullName: voter.fullName,
      voterId: voter.voterId,
      dob: voter.dob,
      votedElections: voter.votedElections
    }
  });
});

// ─── Cast vote ────────────────────────────────────────────────────────────────
router.post('/cast', votingRateLimit, (req, res) => {
  if (!req.session.voterAuthenticated || !req.session.voterId) {
    return res.status(403).json({ error: 'Please authenticate with your Voter ID and face scan first.' });
  }

  const { electionId, candidateId } = req.body;

  if (!electionId || !candidateId) {
    return res.status(400).json({ error: 'Election and candidate selection required.' });
  }

  const voters = readFile('voters');
  const voter = voters.find(v => v.id === req.session.voterId);

  if (!voter) {
    return res.status(404).json({ error: 'Voter not found.' });
  }

  // Check if already voted in this election
  if (voter.votedElections.includes(electionId)) {
    return res.status(409).json({ error: 'You have already voted in this election.' });
  }

  // Get election
  const elections = readFile('elections');
  const election = elections.find(e => e.id === electionId);

  if (!election) {
    return res.status(404).json({ error: 'Election not found.' });
  }

  // Check election is active
  const now = new Date();
  if (now < new Date(election.startDate) || now > new Date(election.endDate)) {
    return res.status(400).json({ error: 'This election is not currently active.' });
  }

  // ── Age limit check ────────────────────────────────────────────────────────
  if (election.minAge || election.maxAge) {
    const age = calculateAge(voter.dob);

    if (age === null) {
      return res.status(400).json({ error: 'Could not determine voter age from date of birth.' });
    }

    if (election.minAge && age < election.minAge) {
      return res.status(403).json({
        error: `You must be at least ${election.minAge} years old to vote in this election. Your age: ${age}.`
      });
    }

    if (election.maxAge && age > election.maxAge) {
      return res.status(403).json({
        error: `You must be no older than ${election.maxAge} years to vote in this election. Your age: ${age}.`
      });
    }
  }

  // Validate candidate
  const candidate = election.candidates.find(c => c.id === candidateId);
  if (!candidate) {
    return res.status(400).json({ error: 'Invalid candidate selection.' });
  }

  // Record vote (anonymized - no link between voter and candidate)
  const votes = readFile('votes');
  const electionVote = votes.find(v => v.electionId === electionId);

  if (electionVote) {
    const candVote = electionVote.results.find(r => r.candidateId === candidateId);
    if (candVote) {
      candVote.count++;
    }
    writeFile('votes', votes);
  } else {
    const newVoteRecord = {
      electionId,
      results: election.candidates.map(c => ({
        candidateId: c.id,
        candidateName: c.name,
        count: c.id === candidateId ? 1 : 0
      }))
    };
    appendItem('votes', newVoteRecord);
  }

  // Mark voter as voted in this election
  voter.votedElections.push(electionId);
  writeFile('voters', voters);

  // Vote log (no candidate info to preserve anonymity)
  appendItem('voteLogs', {
    electionId,
    electionTitle: election.title,
    voterIdHash: simpleHash(req.session.voterVoterId),
    timestamp: new Date().toISOString(),
    ip: req.ip
  });

  // Clear session after voting
  req.session.voterAuthenticated = false;
  req.session.voterId = null;

  return res.json({
    success: true,
    message: `Your vote has been cast successfully in "${election.title}". Thank you for voting!`
  });
});

// ─── Get results (public, only if election ended) ────────────────────────────
router.get('/results/:electionId', (req, res) => {
  const { electionId } = req.params;
  const elections = readFile('elections');
  const election = elections.find(e => e.id === electionId);

  if (!election) {
    return res.status(404).json({ error: 'Election not found.' });
  }

  const now = new Date();
  if (now <= new Date(election.endDate)) {
    return res.status(403).json({ error: 'Results are not available until the election ends.' });
  }

  const votes = readFile('votes');
  const electionVote = votes.find(v => v.electionId === electionId);

  return res.json({
    election: { id: election.id, title: election.title, endDate: election.endDate },
    results: electionVote?.results || []
  });
});

// ─── Helpers ──────────────────────────────────────────────────────────────────
function euclideanDistance(desc1, desc2) {
  if (!desc1 || !desc2 || desc1.length !== desc2.length) return Infinity;
  let sum = 0;
  for (let i = 0; i < desc1.length; i++) {
    sum += Math.pow(desc1[i] - desc2[i], 2);
  }
  return Math.sqrt(sum);
}

function simpleHash(str) {
  let hash = 0;
  for (let i = 0; i < str.length; i++) {
    const chr = str.charCodeAt(i);
    hash = ((hash << 5) - hash) + chr;
    hash |= 0;
  }
  return Math.abs(hash).toString(16);
}

module.exports = router;
