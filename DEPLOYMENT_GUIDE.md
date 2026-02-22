# 🗳️ VoteSecure — Complete Deployment Guide

## What You Get
- Voter registration with **Aadhaar / College ID** proof scan
- **Phone OTP** verification
- **Face recognition** for login
- **Age-restricted elections** set by admin
- Admin dashboard with live results
- One vote per person enforcement

---

# ✅ STEP 1 — Install Node.js

### Windows
1. Go to **https://nodejs.org**
2. Download **LTS version** (green button)
3. Run the installer — click Next → Next → Install
4. Open **Command Prompt** (press `Win + R`, type `cmd`, press Enter)
5. Type this and press Enter to confirm install:
   ```
   node -v
   ```
   You should see something like `v20.11.0`

### Mac
1. Go to **https://nodejs.org**
2. Download **LTS version**
3. Run the `.pkg` installer
4. Open **Terminal** (search "Terminal" in Spotlight)
5. Confirm:
   ```
   node -v
   ```

---

# ✅ STEP 2 — Extract the Project

1. Download the **voting-v2-full.zip** file
2. **Right-click** the zip → **Extract All** (Windows) or double-click (Mac)
3. You will get a folder called `voting-v2`
4. Place it somewhere easy like:
   - Windows: `C:\voting-v2\`
   - Mac/Linux: `/home/yourname/voting-v2/`

---

# ✅ STEP 3 — Open the Folder in Terminal

### Windows
1. Open the `voting-v2` folder in File Explorer
2. Click the **address bar** at the top
3. Type `cmd` and press **Enter**
4. A command prompt opens inside that folder ✅

### Mac / Linux
1. Open **Terminal**
2. Type:
   ```
   cd /path/to/voting-v2
   ```
   Example:
   ```
   cd ~/Downloads/voting-v2
   ```

---

# ✅ STEP 4 — Install Dependencies

In the terminal (inside the `voting-v2` folder), run:

```
npm install
```

Wait for it to finish. You will see a `node_modules` folder appear.

---

# ✅ STEP 5 — Start the Server

```
npm start
```

You should see:

```
✅  VoteSecure v2 running → http://localhost:3000
```

---

# ✅ STEP 6 — Open in Browser

Open your browser and go to:

```
http://localhost:3000
```

You will see the VoteSecure home page. ✅

---

# ✅ STEP 7 — Login as Admin

The **admin account** is created automatically on first run.

1. Go to: `http://localhost:3000/admin-login`
2. Username: **admin**
3. Password: **admin123**

> ⚠️ **Change your password immediately** after first login via the admin panel.

---

# ✅ STEP 8 — Create Your First Election

1. Login to Admin Panel
2. Click **"Create Election"** tab
3. Fill in:
   - **Election Title** — e.g. "College President Election 2025"
   - **Description**
   - **Start Date** and **End Date**
4. **Age Limit** (optional):
   - Toggle the switch **ON**
   - Set **Minimum Age** (e.g. 18) — use ▲▼ buttons or type
   - Set **Maximum Age** (e.g. 25 for college election, or 0 for no max)
   - Use **Quick Presets**: 18+ General, 18–25 College, 18–35 Youth, 60+ Senior
5. **Add Candidates** — click "+ Add Candidate" for each one
6. Click **"Create Election"** ✅

---

# ✅ STEP 9 — Voter Registration Flow

Tell your voters to go to:
```
http://localhost:3000/register
```

They will go through **5 steps**:

### Step 1 — Personal Info
- Full Name (must match Aadhaar/College ID)
- Date of Birth
- Phone Number (10 digits)
- Address

### Step 2 — OTP Verification
- Click **Send OTP**
- A 6-digit OTP is generated
- **Demo mode**: OTP is shown on screen in a yellow box
- Enter the OTP in the 6 boxes
- Click **Verify OTP**

> 💡 **For real SMS**: Integrate Twilio or MSG91 in `server.js` at the `sendOTP` function

### Step 3 — ID Proof Scan
- Choose **Aadhaar Card** or **College ID**
- Show the document to the camera
- Hold it **flat** inside the white frame
- Click **Capture**
- The system reads Name and DOB automatically using OCR
- If DOB matches → ✅ Verified → Continue
- If fails → Retake the photo

### Step 4 — Face Scan
- Camera opens
- Align face in the oval
- Click **Start Face Scan**
- 3 frames captured automatically
- Preview shown → click **Complete Registration**

### Step 5 — Voter ID Issued
- A unique Voter ID like `VTR-ABC123` is shown
- Voter must **screenshot** it — cannot be recovered
- They use this ID to login and vote

---

# ✅ STEP 10 — Voter Login & Voting

Voters go to:
```
http://localhost:3000/voter-login
```

1. Enter their **Voter ID** (e.g. `VTR-ABC123`)
2. **Face verification** — camera opens, live match score shown
3. If face matches → auto-verified and redirected to voting page
4. Select candidate → click **Cast Vote**
5. Cannot vote again (blocked)

---

# 📁 File Structure

```
voting-v2/
├── server.js              ← Main server (Node.js + Express)
├── package.json           ← Dependencies list
├── data/                  ← Auto-created — stores all data
│   ├── voters.json        ← Registered voters
│   ├── elections.json     ← Elections and candidates
│   ├── votes.json         ← Cast votes
│   └── admins.json        ← Admin accounts
└── public/
    ├── index.html         ← Home page
    ├── css/style.css      ← Styles
    └── pages/
        ├── register.html      ← Voter registration (5 steps)
        ├── voter-login.html   ← Voter login + face verify
        ├── vote.html          ← Voting page
        ├── admin-login.html   ← Admin login
        └── admin.html         ← Admin dashboard
```

---

# 🌐 Deploy Online (Optional — For Real Use)

### Option A — Railway.app (Free, Easiest)

1. Create account at **https://railway.app**
2. Click **"New Project"** → **"Deploy from GitHub"**
3. Push your code to GitHub first, then connect
4. Railway auto-detects Node.js and runs `npm start`
5. You get a live URL like `https://votesecure.railway.app`

### Option B — Render.com (Free)

1. Go to **https://render.com**
2. Click **"New"** → **"Web Service"**
3. Connect GitHub repo
4. Build command: `npm install`
5. Start command: `npm start`
6. Click **Deploy**

### Option C — VPS / Dedicated Server

1. SSH into your server
2. Install Node.js: `curl -fsSL https://deb.nodesource.com/setup_20.x | sudo -E bash - && sudo apt-get install -y nodejs`
3. Copy the `voting-v2` folder to server
4. Run: `npm install && npm start`
5. Use **PM2** to keep it running:
   ```
   npm install -g pm2
   pm2 start server.js --name votesecure
   pm2 startup
   pm2 save
   ```
6. Use **Nginx** as reverse proxy on port 80

---

# 🔧 Common Issues & Fixes

| Problem | Fix |
|---|---|
| `npm not found` | Reinstall Node.js from nodejs.org |
| `Port 3000 in use` | Change PORT in server.js to 3001 |
| `Camera not working` | Use HTTPS or localhost only (browsers block camera on HTTP) |
| `Face not detected` | Tap ☀️ boost button, improve lighting |
| `OCR not reading DOB` | Ensure document is flat, fully inside frame, good light |
| `OTP not received` | Demo mode shows OTP on screen — integrate SMS provider for real use |
| `Cannot login as admin` | Delete `data/admins.json`, restart — it recreates with admin/admin123 |

---

# 📱 SMS OTP Integration (For Production)

Open `server.js` and find the `sendOTP` function.
Replace the console.log line with your SMS provider:

### Fast2SMS (India — Cheapest)
```javascript
const axios = require('axios');
await axios.get('https://www.fast2sms.com/dev/bulkV2', {
  params: {
    authorization: 'YOUR_API_KEY',
    route: 'otp',
    variables_values: otp,
    flash: 0,
    numbers: clean
  }
});
```

### Twilio (International)
```javascript
const twilio = require('twilio');
const client = twilio('ACCOUNT_SID', 'AUTH_TOKEN');
await client.messages.create({
  body: 'Your VoteSecure OTP is: ' + otp,
  from: '+1XXXXXXXXXX',
  to: '+91' + clean
});
```

---

# 🔒 Security Checklist Before Going Live

- [ ] Change admin password from `admin123`
- [ ] Change session secret in `server.js` line: `secret: 'securevote-2024-secret'`
- [ ] Use HTTPS (required for camera access on real domains)
- [ ] Remove `demoOtp` from the `/api/otp/send` response
- [ ] Back up the `data/` folder regularly
- [ ] Set `NODE_ENV=production`

---

*VoteSecure v2 — Built with Node.js, Express, face-api.js, Tesseract.js*
