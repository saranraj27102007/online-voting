const fs = require('fs');
const path = require('path');

const DATA_DIR = path.join(__dirname, '..', 'data');

const FILES = {
  voters: path.join(DATA_DIR, 'voters.json'),
  elections: path.join(DATA_DIR, 'elections.json'),
  votes: path.join(DATA_DIR, 'votes.json'),
  admins: path.join(DATA_DIR, 'admins.json'),
  otps: path.join(DATA_DIR, 'otps.json'),
  voteLogs: path.join(DATA_DIR, 'vote_logs.json')
};

function initDataFiles() {
  if (!fs.existsSync(DATA_DIR)) {
    fs.mkdirSync(DATA_DIR, { recursive: true });
  }

  const defaults = {
    voters: [],
    elections: [],
    votes: [],
    admins: [],
    otps: [],
    voteLogs: []
  };

  for (const [key, filePath] of Object.entries(FILES)) {
    if (!fs.existsSync(filePath)) {
      fs.writeFileSync(filePath, JSON.stringify(defaults[key], null, 2));
    }
  }

  // Seed default admin if none exists
  const admins = readFile('admins');
  if (admins.length === 0) {
    const bcrypt = require('bcryptjs');
    const { v4: uuidv4 } = require('uuid');
    const hashedPassword = bcrypt.hashSync('Admin@123', 12);
    admins.push({
      id: uuidv4(),
      username: 'admin',
      password: hashedPassword,
      loginAttempts: 0,
      lockoutUntil: null,
      createdAt: new Date().toISOString()
    });
    writeFile('admins', admins);
    console.log('✅ Default admin created: admin / Admin@123');
  }
}

function readFile(name) {
  try {
    const content = fs.readFileSync(FILES[name], 'utf8');
    return JSON.parse(content);
  } catch {
    return [];
  }
}

function writeFile(name, data) {
  try {
    fs.writeFileSync(FILES[name], JSON.stringify(data, null, 2));
    return true;
  } catch (err) {
    console.error(`Failed to write ${name}:`, err);
    return false;
  }
}

function findById(name, id) {
  const items = readFile(name);
  return items.find(item => item.id === id) || null;
}

function updateById(name, id, updates) {
  const items = readFile(name);
  const idx = items.findIndex(item => item.id === id);
  if (idx === -1) return false;
  items[idx] = { ...items[idx], ...updates };
  return writeFile(name, items);
}

function deleteById(name, id) {
  const items = readFile(name);
  const filtered = items.filter(item => item.id !== id);
  if (filtered.length === items.length) return false;
  return writeFile(name, filtered);
}

function appendItem(name, item) {
  const items = readFile(name);
  items.push(item);
  return writeFile(name, items);
}

module.exports = {
  initDataFiles,
  readFile,
  writeFile,
  findById,
  updateById,
  deleteById,
  appendItem
};
