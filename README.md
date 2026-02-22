# 🗳️ VoteSecure v2 — Face Recognition Voting System

## 🚀 Setup (3 steps)

```bash
npm install
npm start
```
Open → **http://localhost:3000**

---

## 🔑 Admin Login
| Field | Value |
|-------|-------|
| Username | `admin` |
| Password | `admin123` |

---

## 🔄 How It Works

### Voter Flow
1. **Register** → Enter name, DOB → Camera captures face → Get Voter ID
2. **Login** → Enter Voter ID → Camera verifies face (must match registered face)
3. **Vote** → Select candidate → Confirm → Done (can only vote once per election)

### Admin Flow
1. Login at `/admin-login`
2. View Dashboard → Stats + Charts
3. Create/Manage Elections
4. View Live Vote Counts & Results
5. Manage Voters + Vote Log

---

## 📁 Project Structure
```
voting-v2/
├── server.js
├── package.json
├── data/
│   ├── voters.json       ← Voter profiles + face data
│   ├── admins.json       ← Admin accounts
│   ├── elections.json    ← Election data
│   └── votes.json        ← Vote records
└── public/
    ├── index.html        ← Landing (Voter/Admin choice)
    ├── css/style.css
    └── pages/
        ├── register.html      ← Voter registration + face capture
        ├── voter-login.html   ← Voter ID + face verification
        ├── vote.html          ← Cast vote page
        ├── admin-login.html   ← Admin login
        └── admin.html         ← Full admin dashboard
```

---

## ✨ Features
- ✅ Separate Voter and Admin portals
- ✅ Voter ID generation (e.g. VTR-ABC123)
- ✅ Face registration during signup
- ✅ Face verification before voting (using face-api.js)
- ✅ One vote per person per election (enforced server-side)
- ✅ Admin: Live vote count dashboard with charts
- ✅ Admin: Create/Close/Delete elections
- ✅ Admin: Voter management table
- ✅ Admin: Full vote activity log
- ✅ Live results with progress bars
