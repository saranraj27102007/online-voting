# 🗳️ VoteSecure — Complete Deployment Guide

---

## ✅ OPTION A — Run on Your Own Computer (Local)

### STEP 1 — Install Node.js

1. Open your browser and go to: **https://nodejs.org**
2. Click the big green **"LTS"** button to download
3. Run the installer — click Next → Next → Install
4. After install, open **Command Prompt** (Windows) or **Terminal** (Mac/Linux)
5. Type this to confirm it worked:
   ```
   node -v
   ```
   You should see something like: `v20.11.0`

---

### STEP 2 — Extract Your Project

1. Find the **voting-v2-full.zip** file you downloaded
2. Right-click it → **Extract All** (Windows) or double-click (Mac)
3. You will get a folder called **voting-v2**
4. Remember where this folder is (e.g. `C:\Users\YourName\Downloads\voting-v2`)

---

### STEP 3 — Open Terminal Inside the Folder

**Windows:**
1. Open the `voting-v2` folder
2. Click the address bar at the top of the folder window
3. Type `cmd` and press Enter
4. A black Command Prompt window opens inside the folder ✅

**Mac:**
1. Open Terminal (search "Terminal" in Spotlight)
2. Type: `cd ` (with a space after cd)
3. Drag the `voting-v2` folder into the Terminal window
4. Press Enter ✅

---

### STEP 4 — Install Dependencies

In the terminal, type exactly:
```
npm install
```
Wait for it to finish. You will see a `node_modules` folder appear. This is normal.

---

### STEP 5 — Start the Server

```
npm start
```

You will see:
```
✅  VoteSecure v2 running → http://localhost:3000
```

---

### STEP 6 — Open in Browser

Open your browser and go to:
```
http://localhost:3000
```

🎉 **Your voting system is running!**

---

### STEP 7 — Login as Admin

1. Go to: `http://localhost:3000/admin-login`
2. Username: **admin**
3. Password: **admin123**
4. Change the password immediately after first login!

---

### ⛔ To Stop the Server
Press `Ctrl + C` in the terminal.

### 🔄 To Start Again Later
Open terminal in the `voting-v2` folder and run `npm start` again.

---
---

## ✅ OPTION B — Deploy Online (Free, Anyone Can Access)

Use **Render.com** — free hosting for Node.js apps.

### STEP 1 — Create a GitHub Account
Go to **https://github.com** → Sign Up (free)

---

### STEP 2 — Upload Your Project to GitHub

1. Go to **https://github.com/new**
2. Repository name: `votesecure`
3. Set to **Private** (important for a voting system)
4. Click **Create repository**

Then in your terminal (inside voting-v2 folder):
```
git init
git add .
git commit -m "VoteSecure v2"
git branch -M main
git remote add origin https://github.com/YOUR-USERNAME/votesecure.git
git push -u origin main
```
Replace `YOUR-USERNAME` with your GitHub username.

---

### STEP 3 — Deploy on Render.com

1. Go to **https://render.com** → Sign Up with GitHub
2. Click **"New +"** → **"Web Service"**
3. Click **"Connect"** next to your `votesecure` repository
4. Fill in the settings:

| Field | Value |
|-------|-------|
| Name | votesecure |
| Region | Singapore (closest to India) |
| Branch | main |
| Runtime | Node |
| Build Command | `npm install` |
| Start Command | `npm start` |
| Plan | **Free** |

5. Click **"Create Web Service"**
6. Wait 2–3 minutes for it to build

---

### STEP 4 — Get Your Live URL

After deploy, Render gives you a URL like:
```
https://votesecure.onrender.com
```

Share this URL with voters — anyone can register and vote from anywhere!

---

### STEP 5 — Set Environment Variables on Render

1. In Render dashboard → your service → **Environment**
2. Add this variable:

| Key | Value |
|-----|-------|
| `SESSION_SECRET` | any long random string e.g. `MyVoteApp2024SecretKey!` |

---
---

## ✅ OPTION C — Deploy on Your Own Server / VPS (Advanced)

If you have a VPS (DigitalOcean, AWS, Hostinger VPS etc.)

### STEP 1 — Connect to Your Server
```
ssh root@YOUR_SERVER_IP
```

### STEP 2 — Install Node.js on Server
```
curl -fsSL https://deb.nodesource.com/setup_20.x | sudo -E bash -
sudo apt-get install -y nodejs
```

### STEP 3 — Upload Your Files
On your local machine:
```
scp -r voting-v2 root@YOUR_SERVER_IP:/var/www/votesecure
```

### STEP 4 — Install & Start on Server
```
cd /var/www/votesecure
npm install
npm start
```

### STEP 5 — Keep It Running 24/7 with PM2
```
npm install -g pm2
pm2 start server.js --name votesecure
pm2 startup
pm2 save
```

### STEP 6 — Open Port 3000 in Firewall
```
sudo ufw allow 3000
```

Now access via: `http://YOUR_SERVER_IP:3000`

---
---

## 📋 QUICK REFERENCE — All URLs

| Page | URL |
|------|-----|
| Home | `http://localhost:3000/` |
| Register as Voter | `http://localhost:3000/register` |
| Voter Login | `http://localhost:3000/voter-login` |
| Cast Vote | `http://localhost:3000/vote` |
| Admin Login | `http://localhost:3000/admin-login` |
| Admin Dashboard | `http://localhost:3000/admin` |

---

## 🔑 Default Admin Credentials

```
Username: admin
Password: admin123
```
⚠️ Change this immediately after first login!

---

## ❓ Common Problems & Fixes

| Problem | Fix |
|---------|-----|
| `npm: command not found` | Node.js not installed — redo Step 1 |
| `EADDRINUSE: port 3000` | Another app using port 3000. Run: `npx kill-port 3000` then `npm start` |
| `Cannot find module` | Run `npm install` again |
| Camera not working | Must use **https://** or **localhost** — browsers block camera on plain http |
| OTP not showing | Check terminal/console — demo OTP is printed there |
| Page not loading on Render | Free tier sleeps after 15 min — first load takes ~30 seconds |

---

## 📁 Project File Structure

```
voting-v2/
├── server.js              ← Main server (Node.js)
├── package.json           ← Dependencies list
├── data/                  ← Database (JSON files, auto-created)
│   ├── voters.json
│   ├── elections.json
│   ├── votes.json
│   └── admins.json
└── public/
    ├── index.html         ← Home page
    ├── css/style.css      ← Styles
    └── pages/
        ├── register.html     ← Voter registration
        ├── voter-login.html  ← Voter login
        ├── vote.html         ← Voting page
        ├── admin-login.html  ← Admin login
        └── admin.html        ← Admin dashboard
```
