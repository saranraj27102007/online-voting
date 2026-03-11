'use strict';
/**
 * VoteSecure — Blockchain Vote Ledger
 * ─────────────────────────────────────────────────────────────
 * Lightweight append-only blockchain stored as JSON.
 * Each vote creates one block. Genesis block is pre-seeded.
 *
 * Block schema:
 *   blockIndex     — sequential integer
 *   previousHash   — SHA-256 of previous block
 *   timestamp      — ISO-8601 UTC
 *   electionId     — election UUID
 *   candidateId    — candidate UUID
 *   hashedVoterId  — SHA-256(voterId + salt)  — never raw voter ID
 *   voteHash       — SHA-256(voterId + candidateId + timestamp)
 *   nonce          — proof-of-work nonce (lightweight, difficulty=2)
 *   blockHash      — SHA-256(index+prevHash+voteHash+timestamp+nonce)
 */

const crypto = require('crypto');
const fs     = require('fs');
const path   = require('path');

const DATA_DIR    = path.join(__dirname, 'data');
const CHAIN_FILE  = path.join(DATA_DIR, 'blockchain.json');
const VOTER_SALT  = process.env.VOTER_HASH_SALT || 'vs-chain-salt-change-in-production';

// ── Hash helpers ──────────────────────────────────────────────
function sha256(data) {
  return crypto.createHash('sha256').update(String(data)).digest('hex');
}

function hashVoterId(voterId) {
  return sha256(voterId + VOTER_SALT);
}

function computeVoteHash(voterId, candidateId, timestamp) {
  return sha256(voterId + '|' + candidateId + '|' + timestamp);
}

function computeBlockHash(index, previousHash, voteHash, timestamp, nonce) {
  return sha256(index + '|' + previousHash + '|' + voteHash + '|' + timestamp + '|' + nonce);
}

// ── Proof-of-work (difficulty = 2 leading zeros — fast, just for integrity) ─
const DIFFICULTY = 2;
const TARGET     = '0'.repeat(DIFFICULTY);

function mineBlock(index, previousHash, voteHash, timestamp) {
  let nonce = 0;
  let hash;
  do {
    hash = computeBlockHash(index, previousHash, voteHash, timestamp, nonce);
    nonce++;
  } while (!hash.startsWith(TARGET));
  return { nonce: nonce - 1, hash };
}

// ── Atomic write ──────────────────────────────────────────────
function writeChain(chain) {
  if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });
  const tmp = CHAIN_FILE + '.tmp';
  fs.writeFileSync(tmp, JSON.stringify(chain, null, 2));
  fs.renameSync(tmp, CHAIN_FILE);
}

function readChain() {
  if (!fs.existsSync(CHAIN_FILE)) return null;
  try { return JSON.parse(fs.readFileSync(CHAIN_FILE, 'utf8')); }
  catch(e) { return null; }
}

// ── Genesis block ─────────────────────────────────────────────
function createGenesis() {
  const timestamp = '2025-01-01T00:00:00.000Z';
  const voteHash  = sha256('GENESIS');
  const { nonce, hash } = mineBlock(0, '0'.repeat(64), voteHash, timestamp);
  return {
    blockIndex:    0,
    previousHash:  '0'.repeat(64),
    timestamp,
    electionId:    'GENESIS',
    candidateId:   'GENESIS',
    hashedVoterId: 'GENESIS',
    voteHash,
    nonce,
    blockHash:     hash,
    isGenesis:     true
  };
}

// ── Public API ────────────────────────────────────────────────

/**
 * Initialise chain. Creates genesis block if no chain exists.
 * Returns { valid: bool, length: int, error? }
 */
function initChain() {
  let chain = readChain();
  if (!chain || !Array.isArray(chain) || chain.length === 0) {
    chain = [createGenesis()];
    writeChain(chain);
    console.log('🔗 Blockchain: genesis block created');
    return { valid: true, length: 1 };
  }
  const result = verifyChain(chain);
  if (result.valid) {
    console.log(`🔗 Blockchain: verified — ${chain.length} blocks`);
  } else {
    console.error(`⛔ Blockchain: INTEGRITY FAILURE at block ${result.failedAt} — ${result.error}`);
  }
  return { ...result, length: chain.length };
}

/**
 * Add a new vote block.
 * Returns the new block or throws on chain corruption.
 */
function addVoteBlock({ voterId, electionId, candidateId }) {
  const chain = readChain();
  if (!chain || chain.length === 0) throw new Error('Blockchain not initialised.');

  const verify = verifyChain(chain);
  if (!verify.valid) throw new Error(`Chain integrity failure before vote: block ${verify.failedAt} — ${verify.error}`);

  const prev      = chain[chain.length - 1];
  const index     = prev.blockIndex + 1;
  const timestamp = new Date().toISOString();

  // Voter ID is never stored raw on the chain
  const hashedVoterId = hashVoterId(voterId);
  const voteHash      = computeVoteHash(voterId, candidateId, timestamp);
  const { nonce, hash } = mineBlock(index, prev.blockHash, voteHash, timestamp);

  const block = {
    blockIndex:    index,
    previousHash:  prev.blockHash,
    timestamp,
    electionId:    sanitizeChainField(electionId),
    candidateId:   sanitizeChainField(candidateId),
    hashedVoterId,
    voteHash,
    nonce,
    blockHash:     hash
  };

  chain.push(block);
  writeChain(chain);
  return block;
}

/**
 * Verify entire chain from genesis to tip.
 * Returns { valid: bool, failedAt?: int, error?: string, length: int }
 */
function verifyChain(chain) {
  if (!chain) chain = readChain();
  if (!chain || !Array.isArray(chain) || chain.length === 0)
    return { valid: false, error: 'Chain missing or empty', length: 0 };

  // Verify genesis
  const genesis = chain[0];
  if (!genesis.isGenesis || genesis.blockIndex !== 0 || genesis.previousHash !== '0'.repeat(64))
    return { valid: false, failedAt: 0, error: 'Genesis block corrupted', length: chain.length };

  for (let i = 0; i < chain.length; i++) {
    const block = chain[i];

    // Index continuity
    if (block.blockIndex !== i)
      return { valid: false, failedAt: i, error: `Block ${i}: index mismatch (got ${block.blockIndex})`, length: chain.length };

    // Previous hash link
    if (i > 0 && block.previousHash !== chain[i - 1].blockHash)
      return { valid: false, failedAt: i, error: `Block ${i}: broken hash link`, length: chain.length };

    // Block hash integrity
    const recomputed = computeBlockHash(block.blockIndex, block.previousHash, block.voteHash, block.timestamp, block.nonce);
    if (recomputed !== block.blockHash)
      return { valid: false, failedAt: i, error: `Block ${i}: hash tampered`, length: chain.length };

    // Proof-of-work check
    if (!block.blockHash.startsWith(TARGET))
      return { valid: false, failedAt: i, error: `Block ${i}: invalid proof-of-work`, length: chain.length };
  }

  return { valid: true, length: chain.length };
}

/**
 * Get chain stats for admin dashboard.
 */
function getChainStatus() {
  const chain  = readChain();
  const verify = verifyChain(chain);
  return {
    valid:       verify.valid,
    length:      verify.length,
    failedAt:    verify.failedAt  ?? null,
    error:       verify.error     ?? null,
    tip:         chain ? chain[chain.length - 1] : null,
    difficulty:  DIFFICULTY
  };
}

/**
 * Get all vote blocks (excluding genesis) for audit display.
 */
function getVoteBlocks(electionId) {
  const chain = readChain() || [];
  return chain
    .filter(b => !b.isGenesis && (!electionId || b.electionId === electionId))
    .map(b => ({
      blockIndex:    b.blockIndex,
      timestamp:     b.timestamp,
      electionId:    b.electionId,
      candidateId:   b.candidateId,
      blockHash:     b.blockHash.slice(0, 16) + '…',  // truncate for display
      previousHash:  b.previousHash.slice(0, 16) + '…',
      voteHash:      b.voteHash.slice(0, 16) + '…'
    }));
}

// Only allow safe characters on chain fields
function sanitizeChainField(s) {
  return typeof s === 'string' ? s.replace(/[^a-zA-Z0-9\-_]/g, '').slice(0, 64) : '';
}

module.exports = {
  initChain,
  addVoteBlock,
  verifyChain,
  getChainStatus,
  getVoteBlocks,
  hashVoterId
};
