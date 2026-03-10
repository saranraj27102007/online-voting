# 🗳️ VoteSecure

**A secure, AI-powered online voting system with real-time face verification and liveness detection.**

Built with Node.js + Express on the backend and vanilla JS on the frontend. No frameworks. No databases — just fast, atomic JSON file storage.

---

## ✨ Features

### 🧑‍💻 Voter Side
- **Multi-step registration** — Name, DOB, phone, address, proof of identity (Aadhaar/passport OCR)
- **OTP verification** — Phone OTP sent during registration (demo mode shows on screen)
- **Face registration** — AI-powered face capture using SSD MobileNet v1 (128-D descriptor)
- **Liveness detection** — Blink-based anti-spoofing check (can't use a photo to register)
- **Voter ID card** — Canvas-rendered ID card with download after successful registration
- **Voter login** — Enter Voter ID manually **or upload your ID card image** (OCR auto-extracts the ID)
- **Face verification login** — Live face comparison against registered descriptor (threshold 0.65)
- **One-vote-per-voter enforcement** — Server-side session + vote record check

### 🔐 Admin Side
- **2-step admin login** — Password credentials + face liveness verification (both required)
- **Election management** — Create elections, add candidates, set start/end time
- **Live results dashboard** — Vote counts, turnout stats, per-election breakdown
- **Voter management** — View all registered voters
- **Vote audit log** — Full record of all cast votes
- **Change password** — In-panel password change with strength meter

### 🛡️ Security
- **Helmet.js** — Full HTTP security headers (CSP, HSTS, X-Frame-Options, etc.)
- **Rate limiting** — Per-route limits on login, registration, OTP, and API endpoints
- **Brute-force lockout** — 5 failed admin login attempts → 15-minute lockout
- **Session fixation prevention** — `req.session.regenerate()` on every login
- **Atomic file writes** — No data corruption on concurrent writes
- **Path traversal blocking** — All file paths validated server-side
- **bcrypt password hashing** — Cost factor 12

---

## 🖥️ Tech Stack

| Layer | Technology |
|---|---|
| Server | Node.js + Express |
| Auth | express-session + bcryptjs |
| Face AI | face-api.js 0.22.2 (SSD MobileNet v1) |
| Liveness | Custom EAR (Eye Aspect Ratio) blink detector |
| OCR | Tesseract.js v5 (client-side, for ID card upload) |
| Security | Helmet.js + express-rate-limit |
| Storage | JSON flat files (atomic writes) |
| Styling | Custom CSS design system (no framework) |

---

## 📁 Project Structure

```
VoteSecure/
├── server.js              # Express server — all routes & business logic
├── package.json
├── .env.example           # Environment variable template
├── start.sh               # Linux/macOS startup script
├── start.bat              # Windows startup script
├── eng.traineddata        # Tesseract English language data
├── data/                  # Auto-created on first run
│   ├── voters.json        # Registered voters + face descriptors
│   ├── elections.json     # Elections + candidates
│   ├── votes.json         # Cast votes (anonymised)
│   └── admins.json        # Admin accounts (bcrypt hashed)
└── public/
    ├── index.html         # Landing page
    ├── css/style.css      # Global design system
    ├── js/face-engine.js  # Face detection + liveness engine
    └── pages/
        ├── register.html      # Voter registration (5 steps)
        ├── voter-login.html   # Voter login + face verification
        ├── vote.html          # Voting page
        ├── admin-login.html   # Admin login (credentials + face)
        └── admin.html         # Admin dashboard
```

---

## 🚀 Getting Started

### Prerequisites

- **Node.js v18 or higher** — [Download](https://nodejs.org)
- A **webcam** — required for face registration and verification

### Installation

```bash
# 1. Clone the repository
git clone https://github.com/your-username/VoteSecure.git
cd VoteSecure

# 2. Install dependencies
npm install

# 3. Set up environment variables
cp .env.example .env
```

Edit `.env`:
```env
SESSION_SECRET=your-long-random-secret-here
PORT=3000
```

> ⚠️ **Never commit your `.env` file.** It's already in `.gitignore`.

### Running the Server

**Linux / macOS:**
```bash
chmod +x start.sh
./start.sh
```

**Windows:**
```bat
start.bat
```

**Or directly:**
```bash
npm start
```

Open your browser at **[http://localhost:3000](http://localhost:3000)**

---

## 🔑 First-Time Admin Setup

On first run, a default admin account is created automatically.

> The default credentials are stored in `data/admins.json`.  
> **Change the password immediately** after first login via Admin Panel → ⚙️ Settings.

---

## 📱 How to Use

### Voter Registration
1. Go to **Register** from the home page
2. Fill in personal details (name, DOB, phone)
3. Verify your phone with OTP
4. Upload proof of identity (Aadhaar / Passport)
5. Complete face scan — **blink once** when prompted
6. Download your **Voter ID card** — save it, it cannot be recovered

### Voter Login
1. Go to **Voter Login**
2. Either **type your Voter ID** (`VTR-XXXXXX`) or **upload your ID card image** — the ID is auto-extracted via OCR
3. Complete **face verification** — look at the camera and blink once
4. You're in — cast your vote

### Admin Login
1. Go to **Admin Login**
2. Enter username and password
3. Complete **face liveness check** — blink once to confirm presence
4. Access the full admin dashboard

---

## 🤳 Face Verification Details

The face verification system uses **face-api.js** with the SSD MobileNet v1 model:

- **Registration** captures the best of 3 face descriptors (128-dimensional vector)
- **Login** captures up to 4 descriptors and server picks the minimum Euclidean distance
- **Match threshold:** 0.65 (lower = stricter; 0.0 = perfect match)
- **Liveness:** Eye Aspect Ratio (EAR) blink detection at 20fps
  - Calibrates to your eye baseline in ~5 frames
  - Real blink = 1–25 frames closed
  - Hand/obstruction (30+ frames) is rejected and does not count

Face models (~5MB) are loaded from jsDelivr CDN and cached by the browser after first load.

---

## 🌐 API Reference

### Voter Endpoints
| Method | Route | Description |
|--------|-------|-------------|
| POST | `/api/otp/send` | Send OTP to phone |
| POST | `/api/otp/verify` | Verify OTP code |
| POST | `/api/voter/register` | Register new voter |
| POST | `/api/voter/login` | Look up voter by ID |
| POST | `/api/voter/face-verify` | Verify face + create session |
| GET  | `/api/voter/me` | Get current voter session |
| GET  | `/api/voter/elections` | List active elections |
| POST | `/api/voter/vote` | Cast a vote |
| POST | `/api/voter/logout` | Destroy session |

### Admin Endpoints
| Method | Route | Description |
|--------|-------|-------------|
| POST | `/api/admin/check-credentials` | Validate credentials (no session) |
| POST | `/api/admin/login` | Create admin session |
| POST | `/api/admin/logout` | Destroy session |
| GET  | `/api/admin/me` | Get current admin session |
| POST | `/api/admin/change-password` | Change admin password |
| GET  | `/api/admin/stats` | Dashboard stats |
| GET  | `/api/admin/elections` | List all elections |
| POST | `/api/admin/elections` | Create election |
| GET  | `/api/admin/voters` | List all voters |
| GET  | `/api/admin/votes` | Audit log of all votes |

---

## ⚙️ Environment Variables

| Variable | Required | Description |
|----------|----------|-------------|
| `SESSION_SECRET` | ✅ Yes | Secret key for signing session cookies — use a long random string |
| `PORT` | No | Server port (default: `3000`) |

---

## 🔒 Security Notes

- **OTP is in demo mode** — the OTP is displayed on screen instead of being sent via SMS. Integrate [Fast2SMS](https://fast2sms.com) or [Twilio](https://twilio.com) for production.
- **JSON file storage** is suitable for demos and small deployments. For production at scale, migrate to PostgreSQL or MongoDB.
- **SESSION_SECRET** must be changed from the default before any public deployment.
- **HTTPS** is strongly recommended in production — run behind nginx or use a service like Render/Railway that provides TLS.

---

## 📸 Screenshots

| Registration | Voter Login | Admin Dashboard |
|---|---|---|
| Face capture with liveness | Upload ID card or type manually | Election management & live results |

---

## 🛠️ Development

```bash
# Run with auto-reload on file changes
npm run dev
```

Requires `nodemon` (included as a dev dependency).

---

## 📄 License

MIT License — see [LICENSE](LICENSE) for details.

---

## 🙏 Credits

- [face-api.js](https://github.com/justadudewhohacks/face-api.js) — Browser face recognition
- [Tesseract.js](https://github.com/naptha/tesseract.js) — Browser OCR
- [Helmet.js](https://helmetjs.github.io/) — Express security headers
- [bcryptjs](https://github.com/dcodeIO/bcrypt.js) — Password hashing
