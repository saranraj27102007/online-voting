# 🗳️ VoteSecure — Secure Online Voting System

A complete, secure online voting system built with Node.js + Express.js.
Designed for the **College Science Expo Project**.

---

## 🌐 Live URLs (after deployment)

| Page | URL |
|------|-----|
| Home | `https://your-app.railway.app/` |
| Register | `https://your-app.railway.app/register` |
| Vote | `https://your-app.railway.app/vote` |
| Admin Login | `https://your-app.railway.app/admin` |
| Admin Dashboard | `https://your-app.railway.app/admin/dashboard` |

**Default Admin Credentials:** `admin` / `Admin@123`

---

## 🚀 Local Setup

```bash
# 1. Clone / download project
cd votesecure

# 2. Install dependencies
npm install

# 3. Set up environment
cp .env.example .env
# Edit .env and set SESSION_SECRET

# 4. Start server
npm start

# Visit http://localhost:3000
```

---

## ☁️ Deploy to Railway

### Method 1: GitHub (Recommended)
1. Push code to GitHub
2. Go to [railway.app](https://railway.app) → New Project → Deploy from GitHub
3. Select your repo
4. Add environment variables:
   - `SESSION_SECRET` = any long random string
   - `NODE_ENV` = `production`
5. Deploy!

### Method 2: Railway CLI
```bash
npm install -g @railway/cli
railway login
railway init
railway up
```

---

## 🔐 Security Features

| Feature | Implementation |
|---------|---------------|
| Password hashing | bcryptjs (salt rounds: 12) |
| Session management | express-session with HttpOnly cookies |
| Admin lockout | 5 attempts → 15 min lockout |
| Idle timeout | 2 hours auto-logout |
| Rate limiting | express-rate-limit (per IP) |
| Security headers | helmet.js |
| CSRF protection | SameSite=strict cookies |
| Tab-close logout | beforeunload → sendBeacon |
| Duplicate prevention | Phone, Name+DOB, Face descriptor |
| IP rate limiting | 200 req/15min globally |

---

## 📋 5-Step Registration Flow

```
Step 1: Personal Info → Name, DOB, Phone, Address
Step 2: OTP Verify   → 6-digit OTP (demo: shown on screen)
Step 3: ID Document  → Aadhaar / PAN / College ID (OCR via Tesseract.js)
Step 4: Face Capture → face-api.js duplicate detection
Step 5: Voter ID     → Unique ID issued (format: VS24XXXXXXXX)
```

---

## 🪪 ID Document Rules

| Document | Name Match | DOB | PAN Format |
|----------|-----------|-----|-----------|
| Aadhaar | ≥ 80% | Required | — |
| PAN Card | ≥ 80% | Required | `^[A-Z]{5}[0-9]{4}[A-Z]{1}$` |
| College ID | ≥ 80% | Optional | — |

---

## 🗳️ Voting Flow

1. Enter **Voter ID** (e.g. `VS241234567`)
2. **Face scan** via webcam (distance threshold: 0.45)
3. Select **active election**
4. **Age check** against election rules
5. Cast vote (anonymous recording)

---

## 👨‍💼 Admin Dashboard Features

- ✅ Create elections with candidates, dates, age limits
- ✅ View/delete voters
- ✅ Live vote results with percentage bars
- ✅ Vote audit logs (anonymized)
- ✅ System stats dashboard

---

## 📁 Project Structure

```
votesecure/
├── server.js              # Express app entry point
├── package.json
├── railway.json           # Railway deployment config
├── .env.example
├── data/                  # JSON storage (auto-created)
│   ├── voters.json
│   ├── elections.json
│   ├── votes.json
│   ├── admins.json
│   ├── otps.json
│   └── vote_logs.json
├── middleware/
│   ├── auth.js            # Session auth middleware
│   └── rateLimit.js       # Rate limiting configs
├── routes/
│   ├── auth.js            # Auth status
│   ├── voter.js           # Registration (5 steps)
│   ├── voting.js          # Vote casting
│   └── admin.js           # Admin CRUD + stats
├── utils/
│   ├── fileStorage.js     # JSON read/write helpers
│   ├── otp.js             # OTP generation/verification
│   └── validation.js      # PAN regex, age calc, fuzzy match
└── public/
    ├── index.html          # Landing page
    ├── assets/style.css    # Shared styles
    ├── voter/
    │   ├── register.html   # 5-step registration
    │   └── vote.html       # Voting interface
    └── admin/
        ├── login.html      # Admin login
        └── dashboard.html  # Admin panel
```

---

## ⚙️ Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `PORT` | Server port | `3000` |
| `NODE_ENV` | `development` or `production` | `development` |
| `SESSION_SECRET` | Session encryption key | demo value |
| `ALLOWED_ORIGIN` | CORS allowed origin | `*` |

---

## 🧪 Demo OTP System

During registration, the OTP is shown on-screen:
```
Demo OTP: 483921
```
In production: replace with SMS API (Twilio, MSG91, etc.)

---

## 📦 Dependencies

```json
{
  "express": "^4.18",
  "bcryptjs": "^2.4",
  "express-session": "^1.17",
  "express-rate-limit": "^7.1",
  "helmet": "^7.1",
  "cors": "^2.8",
  "uuid": "^9.0",
  "dotenv": "^16.3",
  "multer": "^1.4",
  "fuse.js": "^7.0"
}
```

Frontend (CDN):
- **face-api.js** — Face detection & recognition
- **Tesseract.js** — OCR for ID documents
- **Google Fonts** — Bebas Neue + DM Sans

---

*Built for College Science Expo 2024 — VoteSecure*
