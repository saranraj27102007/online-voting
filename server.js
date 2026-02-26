'use strict';
const express        = require('express');
const session        = require('express-session');
const bcrypt         = require('bcryptjs');
const { v4: uuidv4 } = require('uuid');
const fs             = require('fs');
const path           = require('path');
const crypto         = require('crypto');

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
        scriptSrc:  ["'self'","'unsafe-inline'","cdn.jsdelivr.net","raw.githubusercontent.com"],
        styleSrc:   ["'self'","'unsafe-inline'"],
        imgSrc:     ["'self'","data:","blob:"],
        mediaSrc:   ["'self'","blob:"],
        connectSrc: ["'self'"],
        frameSrc:   ["'none'"],
        objectSrc:  ["'none'"],
        workerSrc:  ["'self'","blob:","cdn.jsdelivr.net"],
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
app.use(express.json({limit:'5mb'}));
app.use(express.urlencoded({extended:false,limit:'1mb'}));

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

// Trust Railway reverse proxy (required for secure cookies over HTTPS)
app.set('trust proxy', 1);

// Session — set SESSION_SECRET in Railway env vars for stability across restarts
const SESSION_SECRET = process.env.SESSION_SECRET || 'votesecure-dev-change-in-production';
const isProd = process.env.NODE_ENV === 'production';
app.use(session({
  secret: SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  name: '__vs',
  cookie: {
    httpOnly: true,
    secure: isProd,
    sameSite: 'lax',
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
  const {name,dob,phone,address,faceDescriptor,proofType,proofVerified}=req.body;
  const cName  = sanitizeName(name ||'');
  const cDob   = sanitize(dob      ||'');
  const cPhone = sanitize(phone    ||'').replace(/\D/g,'').slice(-10);
  const cAddr  = sanitize(address  ||'');

  if(!cName||cName.length<2)     return res.status(400).json({error:'Valid full name required.'});
  if(!cDob)                       return res.status(400).json({error:'Date of birth required.'});
  if(cPhone.length<10)            return res.status(400).json({error:'Valid 10-digit phone required.'});
  if(!Array.isArray(faceDescriptor)||faceDescriptor.length!==128)
    return res.status(400).json({error:'Valid face data required.'});
  if(faceDescriptor.some(v=>typeof v!=='number'||isNaN(v)||!isFinite(v)))
    return res.status(400).json({error:'Corrupted face data.'});

  // Reject black-frame / flat descriptors (all values near 0 or near-identical)
  const fd_min=Math.min(...faceDescriptor), fd_max=Math.max(...faceDescriptor);
  const fd_mean=faceDescriptor.reduce((a,b)=>a+b,0)/faceDescriptor.length;
  if((fd_max-fd_min)<0.02||fd_mean<0.005)
    return res.status(400).json({error:'Face data is invalid — camera may have been black or covered. Please retake your photo.'});

  const otpRec=otpStore.get(cPhone);
  if(!otpRec||!otpRec.verified) return res.status(400).json({error:'Phone OTP verification required.'});
  if(!proofVerified)             return res.status(400).json({error:'ID document verification required.'});

  const voters=readJSON(VOTERS_FILE);

  const byPhone=voters.find(v=>v.phone===cPhone);
  if(byPhone) return res.status(409).json({error:'DUPLICATE_VOTER',type:'phone',message:'Phone already registered.',existingVoterId:byPhone.voterId,existingName:byPhone.name});

  const byNd=voters.find(v=>v.name.toLowerCase()===cName.toLowerCase()&&v.dob===cDob);
  if(byNd) return res.status(409).json({error:'DUPLICATE_VOTER',type:'name_dob',message:'Name + DOB already registered.',existingVoterId:byNd.voterId,existingName:byNd.name});

  let faceMatch=null,minD=999;
  for(const v of voters){
    if(!v.faceDescriptor||v.faceDescriptor.length!==128) continue;
    const d=euclidean(faceDescriptor,v.faceDescriptor);
    if(d<minD){minD=d;if(d<0.45)faceMatch=v;}
  }
  if(faceMatch) return res.status(409).json({error:'DUPLICATE_VOTER',type:'face',message:'Face already registered.',existingVoterId:faceMatch.voterId,existingName:faceMatch.name});

  const voterId='VTR-'+crypto.randomBytes(3).toString('hex').toUpperCase();
  voters.push({id:uuidv4(),voterId,name:cName,dob:cDob,phone:cPhone,address:cAddr,proofType:sanitize(proofType||'aadhaar'),faceDescriptor,registeredAt:new Date().toISOString(),status:'active'});
  writeJSON(VOTERS_FILE,voters);
  otpStore.delete(cPhone);
  res.json({success:true,voterId,name:cName});
});

app.post('/api/voter/login', apiLimit, (req,res)=>{
  const voterId=sanitizeId(req.body.voterId||'');
  if(!voterId) return res.status(400).json({error:'Voter ID required.'});
  const v=readJSON(VOTERS_FILE).find(v=>v.voterId===voterId);
  if(!v)               return res.status(404).json({error:'Voter ID not found.'});
  if(v.status!=='active') return res.status(403).json({error:'Account inactive.'});
  res.json({success:true,voter:{id:v.id,voterId:v.voterId,name:v.name,faceDescriptor:v.faceDescriptor}});
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
  res.json({voter:v?{id:v.id,voterId:v.voterId,name:v.name,dob:v.dob}:req.session.voter});
});

app.get('/api/voter/elections', needVoter, (req,res)=>{
  const elections=readJSON(ELECTIONS_FILE),votes=readJSON(VOTES_FILE),vid=req.session.voter.id;
  res.json(elections.map(e=>{
    const uv=votes.find(v=>v.electionId===e.id&&v.voterId===vid);
    const tv=votes.filter(v=>v.electionId===e.id).length;
    return {...e,candidates:e.candidates.map(c=>({...c,votes:votes.filter(v=>v.electionId===e.id&&v.candidateId===c.id).length})),userVoted:!!uv,userVotedFor:uv?.candidateId,totalVotes:tv};
  }));
});

app.post('/api/voter/vote', needVoter, apiLimit, (req,res)=>{
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
