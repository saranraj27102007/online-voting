require('dotenv').config();
const express = require('express');
const session = require('express-session');
const helmet = require('helmet');
const cors = require('cors');
const path = require('path');
const { initDataFiles } = require('./utils/fileStorage');
const { ipRateLimit } = require('./middleware/rateLimit');

const authRoutes = require('./routes/auth');
const voterRoutes = require('./routes/voter');
const votingRoutes = require('./routes/voting');
const adminRoutes = require('./routes/admin');

const app = express();
const PORT = process.env.PORT || 3000;

// Trust the first proxy (required on Railway / Heroku / any reverse-proxy host)
// Without this, req.ip is always the proxy IP → everyone shares one rate-limit bucket
app.set('trust proxy', 1);

// ─── Initialize data files ───────────────────────────────────────────────────
initDataFiles();

// ─── Security middleware ──────────────────────────────────────────────────────
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: [
        "'self'",
        "'unsafe-inline'",
        "'wasm-unsafe-eval'",
        "blob:",
        "https://cdn.jsdelivr.net",
        "https://cdnjs.cloudflare.com",
        "https://unpkg.com"
      ],
      styleSrc: [
        "'self'",
        "'unsafe-inline'",
        "https://fonts.googleapis.com",
        "https://cdnjs.cloudflare.com"
      ],
      fontSrc: [
        "'self'",
        "https://fonts.gstatic.com",
        "https://cdnjs.cloudflare.com"
      ],
      imgSrc: ["'self'", "data:", "blob:"],
      mediaSrc: ["'self'", "blob:"],
      connectSrc: [
        "'self'",
        "https://cdn.jsdelivr.net",
        "https://unpkg.com",
        "https://raw.githubusercontent.com",
        "https://tessdata.projectnaptha.com"
      ],
      workerSrc: ["'self'", "blob:", "https://cdn.jsdelivr.net", "https://unpkg.com"],
      childSrc:  ["'self'", "blob:"],
      frameSrc: ["'none'"],
    }
  },
  crossOriginEmbedderPolicy: false
}));

app.use(cors({
  origin: process.env.ALLOWED_ORIGIN || '*',
  credentials: true
}));

// ─── Session configuration ────────────────────────────────────────────────────
const isProduction = process.env.NODE_ENV === 'production';
app.use(session({
  secret: process.env.SESSION_SECRET || 'votesecure-demo-secret-change-in-prod',
  resave: false,
  saveUninitialized: false,
  name: 'vs_session',
  cookie: {
    httpOnly: true,
    secure: isProduction,
    sameSite: 'strict',
    maxAge: 2 * 60 * 60 * 1000 // 2 hours idle timeout
  }
}));

// ─── Body parsing ─────────────────────────────────────────────────────────────
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// ─── IP rate limiting ─────────────────────────────────────────────────────────
app.use('/api/', ipRateLimit);

// ─── Static files ─────────────────────────────────────────────────────────────
app.use(express.static(path.join(__dirname, 'public')));

// ─── API Routes ───────────────────────────────────────────────────────────────
app.use('/api/auth', authRoutes);
app.use('/api/voter', voterRoutes);
app.use('/api/voting', votingRoutes);
app.use('/api/admin', adminRoutes);

// ─── Frontend routing ─────────────────────────────────────────────────────────
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.get('/register', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'voter', 'register.html'));
});

app.get('/vote', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'voter', 'vote.html'));
});

app.get('/admin', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'admin', 'login.html'));
});

app.get('/admin/dashboard', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'admin', 'dashboard.html'));
});

// ─── 404 handler ──────────────────────────────────────────────────────────────
app.use((req, res) => {
  res.status(404).json({ error: 'Route not found' });
});

// ─── Error handler ────────────────────────────────────────────────────────────
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).json({ error: 'Internal server error' });
});

// ─── Start server ─────────────────────────────────────────────────────────────
app.listen(PORT, () => {
  console.log(`✅ VoteSecure running on port ${PORT}`);
  console.log(`🌐 Visit: http://localhost:${PORT}`);
  if (!isProduction) {
    console.log(`🔑 Admin: http://localhost:${PORT}/admin`);
    console.log(`📋 Default admin: admin / Admin@123`);
  }
});

module.exports = app;
