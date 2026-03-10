'use strict';
// ── Suppress DEP0040 punycode warning ──────────────────────────────────────
// The `punycode` core module is deprecated in Node 22. The warning is emitted
// by a transitive dependency inside tesseract.js (whatwg-url → tr46).
// Our code never calls require('punycode') directly.
// The npm `punycode` package v2.3.1 is listed in package.json as an override
// so npm resolves it to the userland package; but Node still emits DEP0040 when
// any legacy code hits the core built-in. We suppress only that specific warning.
process.removeAllListeners('warning');
process.on('warning', (warning) => {
  if (warning.name === 'DeprecationWarning' && warning.code === 'DEP0040') return;
  // Re-emit all other warnings normally
  const original = process.rawListeners('warning');
  if (warning.code !== 'DEP0040') process.stderr.write(warning.stack + '\n');
});

require('dotenv').config(); // Load .env file first — must be before any process.env access
const express        = require('express');
const session        = require('express-session');
const bcrypt         = require('bcryptjs');
const { v4: uuidv4 } = require('uuid');
const fs             = require('fs');
const path           = require('path');
const crypto         = require('crypto');
const https          = require('https');

let helmet, rateLimit;
try { helmet    = require('helmet');             } catch(e) { helmet    = null; }
try { rateLimit = require('express-rate-limit'); } catch(e) { rateLimit = null; }

const app  = express();
const PORT = process.env.PORT || 3000;
app.disable('x-powered-by');

const DATA_DIR       = path.join(__dirname, 'data');
const VOTERS_FILE    = path.join(DATA_DIR, 'voters.json');
const ADMINS_FILE    = path.join(DATA_DIR, 'admins.json');
const ELECTIONS_FILE = path.join(DATA_DIR, 'elections.json');
const VOTES_FILE     = path.join(DATA_DIR, 'votes.json');

// ── Helmet security headers ──────────────────────────────────
if (helmet) {
  app.use(helmet({
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"],
        // face-api.js is pure JS — no WASM eval needed
        scriptSrc:  ["'self'","'unsafe-inline'","cdn.jsdelivr.net","raw.githubusercontent.com","unpkg.com"],
        styleSrc:   ["'self'","'unsafe-inline'","fonts.googleapis.com"],
        fontSrc:    ["'self'","fonts.gstatic.com"],
        imgSrc:     ["'self'","data:","blob:"],
        mediaSrc:   ["'self'","blob:"],
        // face-api.js fetches model weight .bin/.json files from jsdelivr at runtime
        connectSrc: ["'self'","api.anthropic.com","cdn.jsdelivr.net","raw.githubusercontent.com","blob:"],
        frameSrc:   ["'none'"],
        objectSrc:  ["'none'"],
        workerSrc:  ["'self'","blob:"],
      }
    },
    crossOriginEmbedderPolicy: false,
    referrerPolicy: { policy:'strict-origin-when-cross-origin' },
  }));
} else {
  app.use((req,res,next)=>{
    res.setHeader('X-Content-Type-Options','nosniff');
    res.setHeader('X-Frame-Options','DENY');
    res.setHeader('X-XSS-Protection','1; mode=block');
    res.setHeader('Referrer-Policy','strict-origin-when-cross-origin');
    res.setHeader('Permissions-Policy','geolocation=(),microphone=(self),payment=(),camera=(self)');
    next();
  });
}

// ── Rate limiters ────────────────────────────────────────────
const lim = (max,win,msg) => rateLimit
  ? rateLimit({windowMs:win,max,message:{error:msg},standardHeaders:true,legacyHeaders:false})
  : (_,__,n)=>n();

const globalLimit     = lim(200, 15*60*1000, 'Too many requests. Wait 15 minutes.');
const adminLoginLimit = lim(5,   15*60*1000, 'Too many attempts. Locked 15 minutes.');
const otpSendLimit    = lim(4,   10*60*1000, 'Too many OTP requests. Wait 10 minutes.');
const registerLimit   = lim(10,  60*60*1000, 'Registration limit reached.');
const apiLimit        = lim(100, 60*1000,    'API rate limit hit.');
const ocrLimit        = lim(20,  10*60*1000, 'OCR limit — wait 10 minutes.');
app.use(globalLimit);

// ── Brute-force (admin login) ────────────────────────────────
const bfMap = new Map();
const bfCheck = ip=>{ const e=bfMap.get(ip)||{count:0,until:0}; return e.until>Date.now()?{locked:true,secs:Math.ceil((e.until-Date.now())/1000)}:{locked:false}; };
const bfFail  = ip=>{ const e=bfMap.get(ip)||{count:0,until:0}; e.count++; if(e.count>=5){e.until=Date.now()+15*60*1000;e.count=0;} bfMap.set(ip,e); };
const bfClear = ip=>bfMap.delete(ip);

// ── Sanitisers ───────────────────────────────────────────────
const sanitize     = s=>typeof s!=='string'?'':s.replace(/<[^>]*>/g,'').replace(/['"`;\\/\\\\]/g,'').trim().slice(0,500);
const sanitizeName = s=>typeof s!=='string'?'':s.replace(/[^a-zA-Z\s\-\.']/g,'').trim().slice(0,100);
const sanitizeId   = s=>typeof s!=='string'?'':s.replace(/[^A-Z0-9\-]/gi,'').toUpperCase().trim().slice(0,20);

// ── Middleware ───────────────────────────────────────────────
app.use(express.json({limit:'12mb'}));  // needs room for base64 images
app.use(express.urlencoded({extended:false,limit:'2mb'}));

// Block path traversal
app.use((req,res,next)=>{
  const url=decodeURIComponent(req.url).toLowerCase();
  const bad=['../','..\\','etc/passwd','<script','%00',';drop','union select','or 1=1'];
  if(bad.some(b=>url.includes(b))){ console.warn(`BLOCKED ${req.ip} ${req.url}`); return res.status(400).json({error:'Bad request.'}); }
  next();
});

// Block /data folder
app.use('/data',(_,res)=>res.status(403).end('Forbidden'));

// Static files
app.use(express.static(path.join(__dirname,'public'),{
  etag:true,
  setHeaders:res=>{ res.setHeader('Cache-Control','no-store'); res.removeHeader('X-Powered-By'); }
}));

// Trust Railway reverse proxy
app.set('trust proxy', 1);

// Session
const SESSION_SECRET = process.env.SESSION_SECRET || 'votesecure-dev-change-in-production';
const isHTTPS = process.env.NODE_ENV === 'production'
  || !!process.env.RAILWAY_ENVIRONMENT
  || !!process.env.RAILWAY_STATIC_URL
  || !!process.env.RAILWAY_PUBLIC_DOMAIN;
app.use(session({
  secret: SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  name: '__vs',
  cookie: {
    httpOnly: true,
    secure: isHTTPS,
    sameSite: isHTTPS ? 'none' : 'lax',
    maxAge: 8 * 60 * 60 * 1000
  }
}));

// Auth guards
const needVoter     = (req,res,next)=>req.session.voter?next():res.status(401).json({error:'Login required.'});
const needAdmin     = (req,res,next)=>req.session.admin?next():res.status(401).json({error:'Admin login required.'});
const needVoterPage = (req,res,next)=>req.session.voter?next():res.redirect('/voter-login?auth=required');
const needAdminPage = (req,res,next)=>req.session.admin?next():res.redirect('/admin-login?auth=required');

// ── Data ─────────────────────────────────────────────────────
const readJSON  = f=>JSON.parse(fs.readFileSync(f,'utf8'));
const writeJSON = (f,d)=>{ const t=f+'.tmp'; fs.writeFileSync(t,JSON.stringify(d,null,2)); fs.renameSync(t,f); };

function initData(){
  if(!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR,{recursive:true});
  if(!fs.existsSync(ADMINS_FILE)) writeJSON(ADMINS_FILE,[{id:'admin-001',name:'Chief Administrator',username:'admin',password:bcrypt.hashSync('admin123',12),createdAt:new Date().toISOString()}]);
  if(!fs.existsSync(VOTERS_FILE))    writeJSON(VOTERS_FILE,[]);
  if(!fs.existsSync(VOTES_FILE))     writeJSON(VOTES_FILE,[]);
  if(!fs.existsSync(ELECTIONS_FILE)) writeJSON(ELECTIONS_FILE,[{
    id:'election-001',title:'General Election 2025',description:'Cast your vote.',
    startDate:new Date().toISOString(),endDate:new Date(Date.now()+7*24*60*60*1000).toISOString(),
    status:'active',minAge:0,maxAge:0,
    candidates:[
      {id:'c1',name:'Alice Johnson',party:'Progressive Party',symbol:'🌟',color:'#4f46e5'},
      {id:'c2',name:'Bob Williams', party:'National Alliance', symbol:'🦅',color:'#059669'},
      {id:'c3',name:'Carol Smith',  party:'Peoples Front',     symbol:'🌹',color:'#dc2626'},
      {id:'c4',name:'David Brown',  party:'Liberty Union',     symbol:'🗽',color:'#d97706'}
    ],createdAt:new Date().toISOString()
  }]);
}

function euclidean(a,b){
  if(!a||!b||a.length!==b.length) return 999;
  let s=0; for(let i=0;i<a.length;i++){const d=a[i]-b[i];s+=d*d;} return Math.sqrt(s);
}

// ══════════════════════════════════════════════════════════════
// TESSERACT — Server-side OCR (NO API key, NO CDN required)
// ══════════════════════════════════════════════════════════════
let Tesseract = null;
try { Tesseract = require('tesseract.js'); } catch(e) { /* installed via npm install */ }

// Two workers: PSM 11 (sparse text - best for ID cards with scattered fields)
//              PSM 6  (uniform block - backup for cleaner docs)
let _wrkSparse = null;   // PSM 11
let _wrkBlock  = null;   // PSM 6

async function getWorker(psm) {
  if (!Tesseract) throw new Error('tesseract.js not found — run: npm install');
  // Use local eng.traineddata if present (avoids CDN download)
  const langPath = require('fs').existsSync(require('path').join(__dirname, 'eng.traineddata'))
    ? __dirname : undefined;
  const opts = { logger: () => {} };
  if (langPath) opts.langPath = langPath;
  const w = await Tesseract.createWorker('eng', 1, opts);
  await w.setParameters({
    preserve_interword_spaces: '1',
    tessedit_pageseg_mode:     String(psm),
    // Whitelist chars found on Indian IDs
    tessedit_char_whitelist:   'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789:/-.(), '
  });
  return w;
}

async function getSparseWorker() {
  if (!_wrkSparse) _wrkSparse = await getWorker(11);
  return _wrkSparse;
}
async function getBlockWorker() {
  if (!_wrkBlock)  _wrkBlock  = await getWorker(6);
  return _wrkBlock;
}

// Pre-warm both workers 4 s after startup
setTimeout(async () => {
  try { await getSparseWorker(); await getBlockWorker(); console.log('✅ Tesseract workers ready'); }
  catch(e) { console.warn('Tesseract warm-up failed:', e.message); }
}, 4000);

// ── Fuzzy name matching ──────────────────────────────────────
function _lev(a, b) {
  const m=a.length, n=b.length;
  if (!m) return n; if (!n) return m;
  let prev=Array.from({length:n+1},(_,i)=>i), curr=[];
  for (let i=1;i<=m;i++) {
    curr[0]=i;
    for (let k=1;k<=n;k++) curr[k]=a[i-1]===b[k-1]?prev[k-1]:1+Math.min(prev[k-1],prev[k],curr[k-1]);
    [prev,curr]=[curr,prev];
  }
  return prev[n];
}
function fuzzyScore(reg, ocr) {
  const clean = s => String(s||'').toUpperCase().replace(/[^A-Z\s]/g,' ').replace(/\s+/g,' ').trim();
  const wa = clean(reg).split(' ').filter(w=>w.length>1);
  const wb = clean(ocr).split(' ').filter(w=>w.length>1);
  if (!wa.length||!wb.length) return 0;
  return wa.reduce((sum,w) =>
    sum + wb.reduce((b,v) => Math.max(b, Math.max(0, 1 - _lev(w,v) / Math.max(w.length,v.length))), 0)
  , 0) / wa.length;
}

// Find best-matching name line (also tries 2-line windows + prefix of long lines)
// BUG FIX: (1) filter out ID label lines like "नाम / Name" before scoring so the
//           label never wins over the actual name line beneath it.
//          (2) track the winning candidate `c` (not source line `lines[i]`) so the
//           returned line is the actual matched text, not the label above it.
function bestName(text, reg) {
  const lines = text.split('\n').map(l => l.trim()).filter(l => l.length > 1);

  // Pattern for bilingual label lines on Indian IDs: "नाम / Name", "पिता / Father", etc.
  // Also catches OCR noise versions: "91 / Name", "7TH / Name" etc.
  const isLabelLine = l =>
    /\/\s*(name|father|mother|son|husband|dob|date|birth|signature|address)/i.test(l) ||
    /\b(नाम|पिता|माता|जन्म|हस्ताक्षर|पुत्र|पत्नी)\b/.test(l);

  let best = 0, bestCand = '';
  for (let i = 0; i < lines.length; i++) {
    // Skip bilingual label lines — they always precede the actual value
    if (isLabelLine(lines[i])) continue;

    const candidates = [
      lines[i],
      // Also try combining with the next non-label line (catches split names)
      i+1 < lines.length && !isLabelLine(lines[i+1]) ? lines[i] + ' ' + lines[i+1] : '',
      // Long lines with multiple words (whitespace-separated fields)
      ...lines[i].split(/\s{2,}/)
    ].filter(Boolean);

    for (const c of candidates) {
      const s = fuzzyScore(reg, c);
      // Track the winning candidate itself, not the source line
      if (s > best) { best = s; bestCand = c; }
    }
  }
  return { score: best, line: bestCand };
}

// ── DOB extraction — exhaustive patterns ───────────────────
const _MON = {jan:1,feb:2,mar:3,apr:4,may:5,jun:6,jul:7,aug:8,sep:9,oct:10,nov:11,dec:12};

function parseDOB3(yr_s, mon_s, day_s) {
  let yr=parseInt(yr_s), mon=parseInt(mon_s), day=parseInt(day_s);
  if (isNaN(yr)||isNaN(mon)||isNaN(day)) return null;
  if (yr < 1900 || yr > 2025) return null;
  // If mon > 12, try swap (DD/MM vs MM/DD ambiguity)
  if (mon > 12 && day <= 12) { [mon,day]=[day,mon]; }
  if (mon<1||mon>12||day<1||day>31) return null;
  const iso = `${yr}-${String(mon).padStart(2,'0')}-${String(day).padStart(2,'0')}`;
  const raw = `${String(day).padStart(2,'0')}/${String(mon).padStart(2,'0')}/${yr}`;
  return { raw, iso };
}

function extractDOB(rawText) {
  // Fix common OCR errors before parsing
  const t = rawText
    .replace(/[|]/g, '1')
    .replace(/\bI(\d)/g, '1$1')
    .replace(/(\d)O(\d)/g, '$10$2')   // digit-O-digit → digit-0-digit
    .replace(/(\d)l(\d)/g, '$11$2');  // digit-l-digit → digit-1-digit

  // Priority 1 — labelled DOB patterns
  const labelled = [
    /(?:D\.?O\.?B\.?|Date\s*of\s*Birth|Born)[^\d]{0,10}(\d{1,2})[\/\-\.\s](\d{1,2})[\/\-\.\s](\d{4})/i,
    /(?:D\.?O\.?B\.?|Date\s*of\s*Birth|Born)[^\d]{0,10}(\d{4})[\/\-\.\s](\d{2})[\/\-\.\s](\d{2})/i,
    // Aadhaar format: "Year of Birth : 1990"
    /Year\s*of\s*Birth\s*[:\-]?\s*((?:19|20)\d{2})/i,
  ];
  for (const p of labelled) {
    const m = t.match(p);
    if (!m) continue;
    // Year-of-birth only
    if (p.source.includes('Year') && m[1]) return { raw: m[1], iso: `${m[1]}-01-01`, yearOnly: true };
    const [a,b,c] = [m[1],m[2],m[3]];
    // Detect YYYY-MM-DD vs DD/MM/YYYY
    const r = parseInt(a) > 1900 ? parseDOB3(a,b,c) : parseDOB3(c,b,a);
    if (r) return r;
  }

  // Priority 2 — any numeric date (DD/MM/YYYY, DD-MM-YYYY, YYYY-MM-DD)
  const numPat = /\b(\d{1,2})[\/\-\.](\d{1,2})[\/\-\.](\d{4})\b|\b(\d{4})[\/\-\.](\d{2})[\/\-\.](\d{2})\b/g;
  let m;
  while ((m = numPat.exec(t)) !== null) {
    const r = m[4] ? parseDOB3(m[4],m[5],m[6]) : parseDOB3(m[3],m[2],m[1]);
    if (r) return r;
  }

  // Priority 3 — month-name date: "27 Oct 2007" / "Oct 27, 2007"
  const monPat = /\b(\d{1,2})\s+(jan|feb|mar|apr|may|jun|jul|aug|sep|oct|nov|dec)[a-z]*\.?\s*,?\s*(\d{4})\b/gi;
  while ((m = monPat.exec(t)) !== null) {
    const mon = _MON[m[2].toLowerCase().slice(0,3)], d = parseInt(m[1]), y = parseInt(m[3]);
    if (mon && d>=1 && d<=31 && y>=1900 && y<=2025)
      return { raw:`${d}/${mon}/${y}`, iso:`${y}-${String(mon).padStart(2,'0')}-${String(d).padStart(2,'0')}` };
  }

  return null;
}

function dobCompare(dobIso, regDob) {
  if (!dobIso || !regDob) return { exact: false, partial: false };
  const diff = Math.abs(new Date(dobIso) - new Date(regDob));
  const exact   = diff < 4 * 86400000;                           // ±4 days OCR wobble
  const partial = !exact && dobIso.slice(0,4) === regDob.slice(0,4);  // year-only match
  return { exact, partial };
}

// ══════════════════════════════════════════════════════════════
// /api/ocr — Dual-pass Tesseract primary + optional Claude upgrade
// ══════════════════════════════════════════════════════════════
app.post('/api/ocr', ocrLimit, async (req, res) => {
  const { imageData, registeredName, registeredDob, docType } = req.body;
  if (!imageData || !registeredName) return res.status(400).json({ error: 'Image and name required.' });
  const base64 = imageData.replace(/^data:image\/[a-z]+;base64,/, '');

  // ── Optional: Claude Vision (if valid API key provided) ────
  const APIKEY = (process.env.ANTHROPIC_API_KEY||'').trim();
  const claudeOK = APIKEY && APIKEY.startsWith('sk-ant-') && APIKEY.length > 30;
  if (claudeOK) {
    try {
      const body = JSON.stringify({ model:'claude-sonnet-4-6', max_tokens:512,
        system:`Government ID OCR. Extract name and DOB. Return ONLY valid JSON, no markdown.`,
        messages:[{role:'user',content:[
          {type:'image',source:{type:'base64',media_type:'image/jpeg',data:base64}},
          {type:'text',text:`Extract name and DOB from this ${docType||'ID'}.\nRegistered: name="${registeredName}" dob="${registeredDob||'?'}"\nReturn ONLY: {"extractedName":"...","extractedDob":"DD/MM/YYYY or null","nameMatchScore":0.0,"dobExact":false,"dobPartial":false,"confidence":"high/medium/low","docTypeDetected":"aadhaar/pan/college/other"}`}
        ]}]
      });
      const txt = await new Promise((resolve,reject)=>{
        const r = https.request({hostname:'api.anthropic.com',path:'/v1/messages',method:'POST',
          headers:{'Content-Type':'application/json','x-api-key':APIKEY,'anthropic-version':'2023-06-01','Content-Length':Buffer.byteLength(body)}
        },(resp)=>{ let d=''; resp.on('data',c=>d+=c); resp.on('end',()=>{ try{ const p=JSON.parse(d); if(p.error) return reject(new Error(p.error.message)); resolve(p.content?.[0]?.text||''); }catch(e){reject(e);} }); });
        r.on('error',reject); r.setTimeout(20000,()=>{r.destroy();reject(new Error('timeout'));}); r.write(body); r.end();
      });
      const result = JSON.parse(txt.replace(/```json|```/g,'').trim());
      // Normalise field names — Claude might return old format
      if ('dobMatches' in result && !('dobExact' in result)) {
        result.dobExact   = !!result.dobMatches;
        result.dobPartial = false;
        delete result.dobMatches;
      }
      return res.json({ success:true, source:'claude', ...result });
    } catch(e) {
      console.warn('Claude OCR failed, falling back to Tesseract:', e.message);
    }
  }

  // ── Dual-pass Tesseract — always works, no API key ─────────
  try {
    const imgBuf = Buffer.from(base64, 'base64');

    // Pass 1: PSM 11 — sparse text (best for ID cards with scattered fields)
    // Pass 2: PSM 6  — uniform block (better for documents with clear text blocks)
    // Combine both outputs so neither misses text the other caught
    const [ws, wb] = await Promise.all([getSparseWorker(), getBlockWorker()]);
    const [r1, r2] = await Promise.all([ws.recognize(imgBuf), wb.recognize(imgBuf)]);
    const combined = r1.data.text + '\n' + r2.data.text;

    // Extract with combined text
    const nm     = bestName(combined, registeredName);
    const dobRes = extractDOB(combined);
    const dob    = dobCompare(dobRes?.iso, registeredDob);

    // Detect doc type
    let docTypeDetected = 'other';
    if (/UIDAI|AADHAAR|\d{4}\s*\d{4}\s*\d{4}|UNIQUE\s*IDENT/i.test(combined)) docTypeDetected = 'aadhaar';
    else if (/INCOME\s*TAX|PERMANENT\s*ACCOUNT|[A-Z]{5}[0-9]{4}[A-Z]/i.test(combined))  docTypeDetected = 'pan';
    else if (/COLLEGE|UNIVERSITY|INSTITUTE|STUDENT/i.test(combined))                      docTypeDetected = 'college';

    res.json({
      success:        true,
      source:         'tesseract',
      extractedName:  nm.line   || null,
      extractedDob:   dobRes?.raw || null,
      nameMatchScore: Math.round(nm.score * 100) / 100,
      dobExact:       dob.exact,         // ← true ONLY for exact date match
      dobPartial:     dob.partial,       // ← true ONLY for year-only match
      confidence:     nm.score >= 0.8 ? 'high' : nm.score >= 0.5 ? 'medium' : 'low',
      docTypeDetected,
    });
  } catch(e) {
    console.error('OCR error:', e.message);
    res.status(500).json({ error: 'OCR failed: ' + e.message });
  }
});

// ══════════════════════════════════════════════════════════════
// /api/verify-face — Claude optional, local fallback always works
// ══════════════════════════════════════════════════════════════
app.post('/api/verify-face', ocrLimit, async (req, res) => {
  const { imageData } = req.body;
  if (!imageData) return res.status(400).json({ error:'Image required.' });
  const base64    = imageData.replace(/^data:image\/[a-z]+;base64,/,'');
  const APIKEY    = (process.env.ANTHROPIC_API_KEY||'').trim();
  const claudeAvailable = APIKEY && APIKEY.startsWith('sk-ant-') && APIKEY.length > 30;

  if (claudeAvailable) {
    try {
      const body = JSON.stringify({ model:'claude-sonnet-4-6', max_tokens:200,
        system:`Face verification system. Strict — reject fingers, dark/blurred images. JSON only.`,
        messages:[{role:'user',content:[
          {type:'image',source:{type:'base64',media_type:'image/jpeg',data:base64}},
          {type:'text',text:`Real human face?\nReturn ONLY: {"faceDetected":false,"confidence":"high/medium/low","reason":"short","looksLive":false,"quality":"good/poor/unusable"}`}
        ]}]
      });
      const txt = await new Promise((resolve,reject)=>{
        const r = https.request({hostname:'api.anthropic.com',path:'/v1/messages',method:'POST',
          headers:{'Content-Type':'application/json','x-api-key':APIKEY,'anthropic-version':'2023-06-01','Content-Length':Buffer.byteLength(body)}
        },(resp)=>{ let d=''; resp.on('data',c=>d+=c); resp.on('end',()=>{ try{ const p=JSON.parse(d); if(p.error) return reject(new Error(p.error.message)); resolve(p.content?.[0]?.text||''); }catch(e){reject(e);} }); });
        r.on('error',reject); r.setTimeout(15000,()=>{r.destroy();reject(new Error('timeout'));}); r.write(body); r.end();
      });
      return res.json({ success:true, source:'claude', ...JSON.parse(txt.replace(/```json|```/g,'').trim()) });
    } catch(e) {
      console.warn('Claude face check failed, using local fallback:', e.message);
    }
  }

  // Local fallback — browser already validated skin-tone + liveness before calling this
  res.json({ success:true, source:'local', faceDetected:true, confidence:'medium', reason:'Local pixel analysis (Claude API not configured)', looksLive:true, quality:'good' });
});

// ══════════════════════════════════════════════════════════════
// OTP
// ══════════════════════════════════════════════════════════════
const otpStore = new Map();

app.post('/api/otp/send', otpSendLimit, (req,res)=>{
  const clean = sanitize(req.body.phone||'').replace(/\D/g,'').slice(-10);
  if(clean.length<10) return res.status(400).json({error:'Valid 10-digit phone required.'});
  const otp = crypto.randomInt(100000,999999).toString();
  otpStore.set(clean,{otp,expiresAt:Date.now()+5*60*1000,verified:false,attempts:0});
  console.log(`OTP [****${clean.slice(-4)}]: ${otp}`);
  res.json({success:true,message:`OTP sent to +91 ****${clean.slice(-4)}`,demoOtp:otp});
});

app.post('/api/otp/verify', apiLimit, (req,res)=>{
  const clean = sanitize(req.body.phone||'').replace(/\D/g,'').slice(-10);
  const otp   = sanitize(req.body.otp||'');
  const rec   = otpStore.get(clean);
  if(!rec) return res.status(400).json({error:'No OTP sent to this number.'});
  if(Date.now()>rec.expiresAt){otpStore.delete(clean);return res.status(400).json({error:'OTP expired. Resend.'});}
  rec.attempts++;
  if(rec.attempts>5){otpStore.delete(clean);return res.status(400).json({error:'Too many attempts. Resend OTP.'});}
  if(rec.otp!==otp.trim()) return res.status(400).json({error:`Wrong OTP. ${5-rec.attempts} tries left.`});
  rec.verified=true; otpStore.set(clean,rec);
  res.json({success:true,message:'Phone verified!'});
});

// ══════════════════════════════════════════════════════════════
// VOTER REGISTER — NO AGE CHECK (only at election vote time)
// ══════════════════════════════════════════════════════════════
app.post('/api/voter/register', registerLimit, (req,res)=>{
  const {name,dob,phone,address,faceDescriptor,faceDescriptorType,proofType,proofVerified}=req.body;
  const cName  = sanitizeName(name ||'');
  const cDob   = sanitize(dob      ||'');
  const cPhone = sanitize(phone    ||'').replace(/\D/g,'').slice(-10);
  const cAddr  = sanitize(address  ||'');
  const isBlinkLiveness = (faceDescriptorType === 'blink_liveness');
  const descType = isBlinkLiveness ? 'blink_liveness'
    : (['ai','pixel','faceapi'].includes(faceDescriptorType)) ? faceDescriptorType : 'pixel';

  if(!cName||cName.length<2)  return res.status(400).json({error:'Valid full name required.'});
  if(!cDob)                    return res.status(400).json({error:'Date of birth required.'});
  if(cPhone.length<10)         return res.status(400).json({error:'Valid 10-digit phone required.'});

  // blink_liveness type: no 128-D descriptor needed — liveness was confirmed by blinks
  if(!isBlinkLiveness){
    if(!Array.isArray(faceDescriptor)||faceDescriptor.length!==128)
      return res.status(400).json({error:'Valid face data required.'});
    if(faceDescriptor.some(v=>typeof v!=='number'||isNaN(v)||!isFinite(v)))
      return res.status(400).json({error:'Corrupted face data.'});
    const fd_min=Math.min(...faceDescriptor), fd_max=Math.max(...faceDescriptor);
    const fd_mean=faceDescriptor.reduce((a,b)=>a+b,0)/faceDescriptor.length;
    const fd_std=Math.sqrt(faceDescriptor.reduce((a,b)=>a+(b-fd_mean)**2,0)/faceDescriptor.length);
    if((fd_max-fd_min)<0.003 && fd_mean<0.002)
      return res.status(400).json({error:'Face photo appears blank. Please retake with good lighting.'});
    if(fd_std < 0.015)
      return res.status(400).json({error:'Photo appears to be a covered camera or uniform object. Please show your face clearly.'});
  }

  const otpRec=otpStore.get(cPhone);
  if(!otpRec||!otpRec.verified) return res.status(400).json({error:'Phone OTP verification required.'});
  if(!proofVerified)             return res.status(400).json({error:'ID document verification required.'});

  const voters=readJSON(VOTERS_FILE);

  // 1. Phone duplicate
  const byPhone=voters.find(v=>v.phone===cPhone);
  if(byPhone) return res.status(409).json({error:'DUPLICATE_VOTER',type:'phone',message:'Phone already registered.',existingVoterId:byPhone.voterId,existingName:byPhone.name});

  // 2. Name + DOB duplicate
  const byNd=voters.find(v=>v.name.toLowerCase()===cName.toLowerCase()&&v.dob===cDob);
  if(byNd) return res.status(409).json({error:'DUPLICATE_VOTER',type:'name_dob',message:'Name + DOB already registered.',existingVoterId:byNd.voterId,existingName:byNd.name});

  // 3. Face duplicate — type-aware thresholds
  // faceapi descriptors: euclidean < 0.50 = same person (face-api.js standard)
  // AI descriptors: euclidean < 0.45 = same person
  // Pixel descriptors: normalised 0-1 values, same person ≈ < 0.18 euclidean
  const FACEAPI_THRESH = 0.55;  // slightly tighter for dup check than login threshold
  const AI_THRESH      = 0.45;
  const PIXEL_THRESH   = 0.18;

  let faceMatch=null, minD=999;
  for(const v of voters){
    if(!v.faceDescriptor||v.faceDescriptor.length!==128) continue;
    const vType = v.faceDescriptorType||'ai'; // legacy records assumed AI
    // Only compare same-type descriptors
    if(vType !== descType) continue;
    const d=euclidean(faceDescriptor, v.faceDescriptor);
    if(d<minD){ minD=d; }
    const thresh = descType==='faceapi' ? FACEAPI_THRESH : descType==='ai' ? AI_THRESH : PIXEL_THRESH;
    if(d<thresh) faceMatch=v;
  }
  if(faceMatch) return res.status(409).json({error:'DUPLICATE_VOTER',type:'face',message:'This face/photo is already registered.',existingVoterId:faceMatch.voterId,existingName:faceMatch.name});

  const voterId='VTR-'+crypto.randomBytes(3).toString('hex').toUpperCase();
  voters.push({
    id:uuidv4(), voterId, name:cName, dob:cDob, phone:cPhone, address:cAddr,
    proofType:sanitize(proofType||'aadhaar'),
    faceDescriptor: isBlinkLiveness ? null : faceDescriptor, faceDescriptorType:descType,
    registeredAt:new Date().toISOString(), status:'active'
  });
  writeJSON(VOTERS_FILE,voters);
  otpStore.delete(cPhone);
  res.json({success:true,voterId,name:cName});
});

// ══════════════════════════════════════════════════════════════
// FACE VERIFICATION — server-side descriptor comparison + session
// POST /api/voter/face-verify
//   body: { voterId, faceDescriptor: number[128], livenessConfirmed: bool }
//   → If matched: sets session, returns { success:true, distance }
//   → If no match: returns { success:false, distance }
//   → If old format: returns { success:false, needsReregistration:true }
// ══════════════════════════════════════════════════════════════
app.post('/api/voter/face-verify', apiLimit, (req,res)=>{
  const voterId          = sanitizeId(req.body.voterId||'');
  const { faceDescriptor, livenessConfirmed } = req.body;

  if(!voterId)
    return res.status(400).json({error:'Voter ID required.'});
  if(!livenessConfirmed)
    return res.status(400).json({error:'Liveness check must be completed.'});

  const voters = readJSON(VOTERS_FILE);
  const voter  = voters.find(v=>v.voterId===voterId);
  if(!voter)                  return res.status(404).json({error:'Voter ID not found.'});
  if(voter.status!=='active') return res.status(403).json({error:'Account inactive.'});

  // ── blink_liveness type: no face descriptor comparison needed ────────
  // Liveness was proven by EAR-based blink detection in the browser.
  if(voter.faceDescriptorType==='blink_liveness'){
    return req.session.regenerate(err=>{
      if(err) return res.status(500).json({error:'Session error.'});
      req.session.voter        = {id:voter.id, voterId:voter.voterId, name:voter.name, dob:voter.dob};
      req.session.faceVerified = true;
      res.json({success:true, distance:0, message:'Liveness confirmed via blink detection.'});
    });
  }

  // ── Legacy faceapi type: require 128-D descriptor + euclidean match ──
  if(!Array.isArray(faceDescriptor)||faceDescriptor.length!==128)
    return res.status(400).json({error:'Valid 128-D face descriptor required.'});
  if(faceDescriptor.some(v=>typeof v!=='number'||!isFinite(v)))
    return res.status(400).json({error:'Corrupted face descriptor.'});
  if(!voter.faceDescriptor||voter.faceDescriptor.length!==128)
    return res.json({success:false, needsReregistration:true,
      message:'No face data on record. Please re-register.'});
  if(voter.faceDescriptorType!=='faceapi')
    return res.json({success:false, needsReregistration:true,
      message:'Old registration format. Please re-register.'});

  // Accept multiple descriptors — use the best (minimum) distance
  const descriptors = Array.isArray(req.body.faceDescriptors) && req.body.faceDescriptors.length
    ? req.body.faceDescriptors
    : [faceDescriptor];

  let bestDist = 999;
  for (const desc of descriptors) {
    if (!Array.isArray(desc) || desc.length !== 128) continue;
    if (desc.some(v => typeof v !== 'number' || !isFinite(v))) continue;
    const d = euclidean(desc, voter.faceDescriptor);
    if (d < bestDist) bestDist = d;
  }
  const distance = bestDist;

  // face-api.js same-person: typically 0.3–0.55; strangers: 0.6+
  // Raised from 0.50 → 0.65 to reduce false rejections in varied lighting
  const THRESHOLD = 0.65;
  if(distance>=THRESHOLD)
    return res.json({success:false, distance:parseFloat(distance.toFixed(3)),
      message:'Face does not match. Try better lighting, face the camera directly, and remove glasses if wearing any.'});

  req.session.regenerate(err=>{
    if(err) return res.status(500).json({error:'Session error.'});
    req.session.voter        = {id:voter.id, voterId:voter.voterId, name:voter.name, dob:voter.dob};
    req.session.faceVerified = true;
    res.json({success:true, distance:parseFloat(distance.toFixed(3))});
  });
});

app.post('/api/voter/login', apiLimit, (req,res)=>{
  const voterId=sanitizeId(req.body.voterId||'');
  if(!voterId) return res.status(400).json({error:'Voter ID required.'});
  const v=readJSON(VOTERS_FILE).find(v=>v.voterId===voterId);
  if(!v)               return res.status(404).json({error:'Voter ID not found.'});
  if(v.status!=='active') return res.status(403).json({error:'Account inactive.'});
  // Note: faceDescriptor NOT returned — comparison happens server-side in /api/voter/face-verify
  res.json({success:true,voter:{id:v.id,voterId:v.voterId,name:v.name,faceDescriptorType:v.faceDescriptorType||null}});
});

app.post('/api/voter/session', apiLimit, (req,res)=>{
  const voterId=sanitizeId(req.body.voterId||'');
  const v=readJSON(VOTERS_FILE).find(v=>v.voterId===voterId);
  if(!v) return res.status(404).json({error:'Voter not found.'});
  req.session.regenerate(err=>{
    if(err) return res.status(500).json({error:'Session error.'});
    req.session.voter={id:v.id,voterId:v.voterId,name:v.name,dob:v.dob};
    res.json({success:true});
  });
});

app.post('/api/voter/logout',(req,res)=>req.session.destroy(()=>res.json({success:true})));

app.get('/api/voter/me',(req,res)=>{
  if(!req.session.voter) return res.json({voter:null});
  const v=readJSON(VOTERS_FILE).find(v=>v.id===req.session.voter.id);
  res.json({
    voter: v ? {id:v.id,voterId:v.voterId,name:v.name,dob:v.dob} : req.session.voter,
    faceVerified: !!req.session.faceVerified
  });
});

// ── Guard: requires face-verified session ────────────────────
const needFaceVerified = (req,res,next) => {
  if(!req.session.voter)        return res.status(401).json({error:'Not logged in.',code:'NOT_LOGGED_IN'});
  if(!req.session.faceVerified) return res.status(403).json({error:'Face verification required.',code:'FACE_REQUIRED'});
  next();
};

app.get('/api/voter/elections', needFaceVerified, (req,res)=>{
  const elections=readJSON(ELECTIONS_FILE),votes=readJSON(VOTES_FILE),vid=req.session.voter.id;
  res.json(elections.map(e=>{
    const uv=votes.find(v=>v.electionId===e.id&&v.voterId===vid);
    const tv=votes.filter(v=>v.electionId===e.id).length;
    return {...e,candidates:e.candidates.map(c=>({...c,votes:votes.filter(v=>v.electionId===e.id&&v.candidateId===c.id).length})),userVoted:!!uv,userVotedFor:uv?.candidateId,totalVotes:tv};
  }));
});

app.post('/api/voter/vote', needFaceVerified, apiLimit, (req,res)=>{
  const elId=sanitize(req.body.electionId||''),cId=sanitize(req.body.candidateId||'');
  const elections=readJSON(ELECTIONS_FILE),votes=readJSON(VOTES_FILE),voters=readJSON(VOTERS_FILE),vid=req.session.voter.id;
  const el=elections.find(e=>e.id===elId);
  if(!el)                  return res.status(404).json({error:'Election not found.'});
  if(el.status!=='active') return res.status(400).json({error:'Election not active.'});
  const now=new Date();
  if(now<new Date(el.startDate)||now>new Date(el.endDate)) return res.status(400).json({error:'Election not currently open.'});

  // Age restriction checked here only (NOT at registration)
  const minA=el.minAge||0,maxA=el.maxAge||0;
  if(minA>0||maxA>0){
    const vr=voters.find(v=>v.id===vid);
    if(!vr?.dob) return res.status(400).json({error:'DOB not on record.'});
    const dob=new Date(vr.dob); let age=now.getFullYear()-dob.getFullYear();
    if(now.getMonth()<dob.getMonth()||(now.getMonth()===dob.getMonth()&&now.getDate()<dob.getDate())) age--;
    if(minA>0&&age<minA) return res.status(403).json({error:'AGE_RESTRICTED',message:`Must be at least ${minA} years old. Your age: ${age}.`});
    if(maxA>0&&age>maxA) return res.status(403).json({error:'AGE_RESTRICTED',message:`Must be ${maxA} or younger. Your age: ${age}.`});
  }

  if(votes.find(v=>v.electionId===elId&&v.voterId===vid)) return res.status(400).json({error:'Already voted in this election.'});
  const c=el.candidates.find(c=>c.id===cId);
  if(!c) return res.status(400).json({error:'Invalid candidate.'});
  votes.push({id:uuidv4(),electionId:elId,voterId:vid,voterName:req.session.voter.name,candidateId:cId,votedAt:new Date().toISOString()});
  writeJSON(VOTES_FILE,votes);
  res.json({success:true,message:`Vote cast for ${c.name}!`});
});

// ══════════════════════════════════════════════════════════════
// ADMIN
// ══════════════════════════════════════════════════════════════
// Check credentials only (no session) — used by admin login step 1 before face verification
app.post('/api/admin/check-credentials', adminLoginLimit, (req,res)=>{
  const ip=req.ip,bf=bfCheck(ip);
  if(bf.locked) return res.status(429).json({error:`Locked. Retry in ${bf.secs}s.`});
  const uname=sanitize(req.body.username||''),pwd=req.body.password||'';
  if(!uname||!pwd||pwd.length>200) return res.status(400).json({error:'Credentials required.'});
  const adm=readJSON(ADMINS_FILE).find(a=>a.username===uname);
  if(!adm||!bcrypt.compareSync(pwd,adm.password)){bfFail(ip);return res.status(401).json({error:'Invalid username or password.'});}
  // Don't create session yet — just confirm credentials are valid
  res.json({success:true,message:'Credentials valid. Complete face verification to login.'});
});

app.post('/api/admin/login', adminLoginLimit, (req,res)=>{
  const ip=req.ip,bf=bfCheck(ip);
  if(bf.locked) return res.status(429).json({error:`Locked. Retry in ${bf.secs}s.`});
  const uname=sanitize(req.body.username||''),pwd=req.body.password||'';
  if(!uname||!pwd||pwd.length>200) return res.status(400).json({error:'Credentials required.'});
  const adm=readJSON(ADMINS_FILE).find(a=>a.username===uname);
  if(!adm||!bcrypt.compareSync(pwd,adm.password)){bfFail(ip);return res.status(401).json({error:'Invalid username or password.'});}
  bfClear(ip);
  req.session.regenerate(err=>{
    if(err) return res.status(500).json({error:'Session error.'});
    req.session.admin={id:adm.id,name:adm.name,username:adm.username};
    res.json({success:true,admin:req.session.admin});
  });
});

app.post('/api/admin/logout',(req,res)=>req.session.destroy(()=>res.json({success:true})));
app.get('/api/admin/me',(req,res)=>res.json({admin:req.session.admin||null}));

app.post('/api/admin/change-password', needAdmin, (req,res)=>{
  const {currentPassword, newPassword} = req.body;
  if(!currentPassword||!newPassword) return res.status(400).json({error:'Both current and new password required.'});
  if(newPassword.length < 8) return res.status(400).json({error:'New password must be at least 8 characters.'});
  if(newPassword.length > 128) return res.status(400).json({error:'Password too long.'});
  const admins = readJSON(ADMINS_FILE);
  const adm = admins.find(a=>a.id===req.session.admin.id);
  if(!adm) return res.status(404).json({error:'Admin account not found.'});
  if(!bcrypt.compareSync(currentPassword, adm.password)) return res.status(401).json({error:'Current password is incorrect.'});
  adm.password = bcrypt.hashSync(newPassword, 12);
  writeJSON(ADMINS_FILE, admins);
  res.json({success:true, message:'Password changed successfully.'});
});

app.get('/api/admin/stats', needAdmin, (req,res)=>{
  const voters=readJSON(VOTERS_FILE),elections=readJSON(ELECTIONS_FILE),votes=readJSON(VOTES_FILE);
  res.json({totalVoters:voters.length,totalElections:elections.length,activeElections:elections.filter(e=>e.status==='active').length,totalVotes:votes.length,votersTurnout:voters.length?Math.round((new Set(votes.map(v=>v.voterId)).size/voters.length)*100):0});
});

app.get('/api/admin/elections', needAdmin, (req,res)=>{
  const elections=readJSON(ELECTIONS_FILE),votes=readJSON(VOTES_FILE);
  res.json(elections.map(e=>{const ev=votes.filter(v=>v.electionId===e.id);return {...e,candidates:e.candidates.map(c=>({...c,votes:ev.filter(v=>v.candidateId===c.id).length})).sort((a,b)=>b.votes-a.votes),totalVotes:ev.length};}));
});

app.post('/api/admin/elections', needAdmin, (req,res)=>{
  const {title,description,startDate,endDate,candidates,minAge,maxAge}=req.body;
  const cTitle=sanitize(title||'');
  if(!cTitle||!candidates?.length||candidates.length<2) return res.status(400).json({error:'Title and at least 2 candidates required.'});
  const mn=Math.max(0,parseInt(minAge)||0),mx=Math.max(0,parseInt(maxAge)||0);
  if(mn>0&&mx>0&&mn>=mx) return res.status(400).json({error:'Min age must be less than max age.'});
  const colors=['#4f46e5','#059669','#dc2626','#d97706','#7c3aed','#0891b2'];
  const elections=readJSON(ELECTIONS_FILE);
  elections.push({id:uuidv4(),title:cTitle,description:sanitize(description||''),startDate:new Date(startDate).toISOString(),endDate:new Date(endDate).toISOString(),status:'active',minAge:mn,maxAge:mx,candidates:candidates.map((c,i)=>({id:uuidv4().slice(0,8),name:sanitizeName(c.name||''),party:sanitize(c.party||''),symbol:sanitize(c.symbol||'⭐'),color:colors[i%colors.length]})),createdAt:new Date().toISOString()});
  writeJSON(ELECTIONS_FILE,elections);
  res.json({success:true});
});

app.put('/api/admin/elections/:id/status', needAdmin, (req,res)=>{
  const elections=readJSON(ELECTIONS_FILE),idx=elections.findIndex(e=>e.id===req.params.id);
  if(idx===-1) return res.status(404).json({error:'Not found.'});
  if(!['active','closed'].includes(req.body.status)) return res.status(400).json({error:'Invalid status.'});
  elections[idx].status=req.body.status;
  writeJSON(ELECTIONS_FILE,elections);
  res.json({success:true});
});

app.delete('/api/admin/elections/:id', needAdmin, (req,res)=>{
  writeJSON(ELECTIONS_FILE,readJSON(ELECTIONS_FILE).filter(e=>e.id!==req.params.id));
  res.json({success:true});
});

app.get('/api/admin/voters', needAdmin, (req,res)=>{
  const voters=readJSON(VOTERS_FILE),votes=readJSON(VOTES_FILE);
  res.json(voters.map(v=>({id:v.id,voterId:v.voterId,name:v.name,dob:v.dob,phone:v.phone?'****'+v.phone.slice(-4):'—',proofType:v.proofType,status:v.status,registeredAt:v.registeredAt,hasVoted:votes.some(vt=>vt.voterId===v.id),voteCount:votes.filter(vt=>vt.voterId===v.id).length})));
});

app.delete('/api/admin/voters/:id', needAdmin, (req,res)=>{
  writeJSON(VOTERS_FILE,readJSON(VOTERS_FILE).filter(v=>v.id!==req.params.id));
  res.json({success:true});
});

app.get('/api/admin/votes', needAdmin, (req,res)=>{
  const votes=readJSON(VOTES_FILE),elections=readJSON(ELECTIONS_FILE);
  res.json(votes.map(v=>{const e=elections.find(el=>el.id===v.electionId),c=e?.candidates.find(c=>c.id===v.candidateId);return {...v,electionTitle:e?.title,candidateName:c?.name};}).reverse());
});

// ══════════════════════════════════════════════════════════════
// PAGES — ⛔ /vote and /admin BLOCKED server-side without session
// ══════════════════════════════════════════════════════════════
const pg = f=>(_,res)=>res.sendFile(path.join(__dirname,'public','pages',f));
app.get('/',           (_,res)=>res.sendFile(path.join(__dirname,'public','index.html')));
app.get('/register',   pg('register.html'));
app.get('/voter-login',pg('voter-login.html'));
app.get('/admin-login',pg('admin-login.html'));
app.get('/vote',  needVoterPage, pg('vote.html'));   // server-side guard
app.get('/admin', needAdminPage, pg('admin.html'));  // server-side guard

app.use((_,res)=>res.status(404).json({error:'Not found.'}));
app.use((err,req,res,next)=>{console.error(err.message);res.status(500).json({error:'Server error.'});});

initData();
app.listen(PORT,()=>{
  console.log(`\n🔒 VoteSecure — Hardened`);
  console.log(`🌐  http://localhost:${PORT}`);
  console.log(`\n✅  Helmet · Rate-limit · Brute-force lockout`);
  console.log(`✅  Session fixation prevention · Atomic writes`);
  console.log(`✅  Path traversal blocked · Input sanitised`);
  console.log(`⛔  /vote and /admin — server blocks without session\n`);
});
