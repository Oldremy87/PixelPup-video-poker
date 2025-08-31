require('dotenv').config();
const express = require('express');
const path = require('path');
const fetch = (...args) => import('node-fetch').then(({ default: fetch }) => fetch(...args));
const helmet = require('helmet');
const winston = require('winston');
const { rateLimit } = require('express-rate-limit');
const hcaptcha = require('hcaptcha');
const session = require('express-session');
const { v4: uuidv4 } = require('uuid');
const cors = require('cors');
const cookieParser = require('cookie-parser');
const { Pool } = require('pg');
const csrf = require('csurf');
const PgSession = require('connect-pg-simple')(session);
const { randomUUID } = require('crypto');

const app = express();
app.set('trust proxy', 1);

// ----- ENV / MODE -----
const isProd = process.env.NODE_ENV === 'production' || !!process.env.RENDER;
function must(name) {
  const v = process.env[name];
  if (!v) throw new Error(`Missing required env: ${name}`);
  return v;
}

function mustBeURL(name) {
  const v = must(name);
  try { new URL(v); } catch (e) {
    throw new Error(`Invalid URL in ${name}: ${v}`);
  }
  return v;
}

// Validate only what you truly need at startup:
if (process.env.RPC_URL) mustBeURL('RPC_URL');   // allow optional, but validate if present
must('SESSION_SECRET');
if (process.env.DATABASE_URL) mustBeURL('DATABASE_URL'); // pg also accepts connection strings

const hasDb = !!process.env.DATABASE_URL;

// ----- DB POOL (accept self-signed cert on Render) -----
const pool = hasDb
  ? new Pool({
      connectionString: process.env.DATABASE_URL,
      ...(isProd ? { ssl: { rejectUnauthorized: false } } : {})
    })
  : null;

// ----- MIDDLEWARE ORDER -----
app.use(cookieParser());

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// ----- SESSION STORE -----
const sessionStore = hasDb
  ? new PgSession({
      pool,
      tableName: 'session',
      createTableIfMissing: true,
      pruneSessionInterval: 60 * 60 // seconds
    })
  : undefined;

// ----- SESSION COOKIE -----
app.use(session({
  name: 'sid',
  secret: process.env.SESSION_SECRET || 'dev-secret-change-me',
  resave: false,
  saveUninitialized: false,
  store: sessionStore,
  cookie: {
    httpOnly: true,
    sameSite: (process.env.CROSS_SITE_COOKIES === 'true') ? 'none' : 'lax',
    secure: isProd, // HTTPS on Render
    maxAge: 1000 * 60 * 60 * 24 * 30
  }
}));

const crossSite = process.env.CROSS_SITE_COOKIES === 'true';
const csrfProtection = csrf({
  cookie: {
    httpOnly: true,
    sameSite: 'lax',
    secure: isProd, // Render uses HTTPS in prod
  }
});
// must be BEFORE you mount csrfProtection on /api/* mutating routes
app.get('/api/csrf', csrfProtection, (req, res) => {
  res.json({ csrfToken: req.csrfToken() });
});
app.use('/api', (req, res, next) => csrfProtection(req, res, next));
app.use((err, req, res, next) => {
  if (err && err.code === 'EBADCSRFTOKEN') {
    return res.status(403).json({ ok: false, error: 'bad_csrf' });
  }
  return next(err);
});

// =================== Config ===================
const SIX_HOURS_MS = 6 * 60 * 60 * 1000;
const ONE_DAY_MS   = 24 * 60 * 60 * 1000;
const DRAW_MIN_MS  = Number(process.env.DRAW_MIN_MS || 1500);     // min time between draws per session
const MAX_PAYOUT   = Number(process.env.MAX_PAYOUT || 100_000);   // per claim cap (minor units)
const BANK_CAP     = Number(process.env.BANK_CAP || 5_000_000);   // max server bank per session
const PAYOUT_COOLDOWN_MS = Number(process.env.PAYOUT_COOLDOWN_MS || SIX_HOURS_MS); // per address cooldown
const HCAPTCHA_SECRET   = process.env.HCAPTCHA_SECRET;  // REQUIRED
const HCAPTCHA_HOSTNAME = process.env.HCAPTCHA_HOSTNAME || '';    // optional hardening

if (!HCAPTCHA_SECRET) console.error('⚠️ HCAPTCHA_SECRET is not set');

function getClientIp(req){
  const xf = (req.headers['x-forwarded-for'] || '').split(',')[0].trim();
  const raw = xf || req.socket?.remoteAddress || req.ip || 'unknown';
  return raw === '::1' ? '127.0.0.1' : raw;
}

// =================== Security headers ===================
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'","'unsafe-inline'" , "https://hcaptcha.com", "https://*.hcaptcha.com"],
      scriptSrcAttr: ["'self'", "'unsafe-inline'"],
      connectSrc: ["'self'", "https://hcaptcha.com", "https://*.hcaptcha.com"],
      styleSrc: ["'self'", "'unsafe-inline'", "https://hcaptcha.com", "https://*.hcaptcha.com"],
      frameSrc: ["'self'", "https://hcaptcha.com", "https://*.hcaptcha.com"],
      imgSrc: ["'self'", "data:"]
    }
  }
}));
// =================== Logging ===================
const logger = winston.createLogger({
  level: 'info',
  format: winston.format.json(),
  transports: [
    new winston.transports.Console(),
    new winston.transports.File({ filename: 'faucet.log' })
  ]
});

app.use((req, _res, next) => {
  logger.info('Incoming request', { method: req.method, url: req.url, ip: req.ip, ua: req.headers['user-agent'] || '' });
  next();
});

// =================== Body & static ===================
app.use(express.json({ limit: '100kb' }));
app.use(express.static('public', {
  setHeaders: (res, filePath) => {
    if (filePath.endsWith('.js'))  res.set('Content-Type', 'application/javascript');
    if (filePath.endsWith('.svg')) res.set('Content-Type', 'image/svg+xml');
    if (filePath.endsWith('.ico')) res.set('Content-Type', 'image/x-icon');
  }
}));
// Helper to reuse pool in your DB functions
async function db() { return pool; }

// --- UID COOKIE (used by getOrCreateUser/saveAfterDraw) ---
app.use((req, res, next) => {
  let uid = req.cookies?.uid;
  if (!uid) {
    uid = randomUUID();
    res.cookie('uid', uid, {
      httpOnly: true,
      sameSite: 'lax',
      secure: process.env.NODE_ENV === 'production',
      maxAge: 1000 * 60 * 60 * 24 * 365
    });
  }
  req.uid = uid;
  next();
});

// =================== Hand/IP limiting ===================

const HANDS_WINDOW_MS  = SIX_HOURS_MS;
const TOKENS_PER_CREDIT = Number(process.env.TOKENS_PER_CREDIT || 1); // tokens per 1 credit
const HANDS_LIMIT = Math.max(1, Number(process.env.IP_HANDS_PER_6H)) || 40;
const WINDOW_MS   = 6 * 60 * 60 * 1000;
const handsByIp   = new Map();
function getClientIp(req){
  const xf = (req.headers['x-forwarded-for'] || '').split(',')[0].trim();
  const raw = xf || req.socket?.remoteAddress || req.ip || 'unknown';
  return raw === '::1' ? '127.0.0.1' : raw;
}

setInterval(() => {
  const now = Date.now();
  for (const [ip, record] of handsByIp) {
    if (now - record.windowStart >= SIX_HOURS_MS) handsByIp.delete(ip);
  }
}, 6 * 60 * 1000);
app.get('/api/profile', async (req, res) => {
  try {
    await getOrCreateUser(req.uid);
    const s = await loadStats(req.uid);
    res.json({
      ok: true,
      wins: s?.wins||0,
      achievements: {
        firstWin: !!s?.first_win, w10: !!s?.w10, w25: !!s?.w25, w50: !!s?.w50, royalFlush: !!s?.royal_win
      },
      bank: Number(s?.bank_minor||0)
    });
  } catch (e) {
    res.status(500).json({ ok:false, error:'profile_error' });
  }
});
app.get('/api/leaderboard', async (req, res) => {
  try {
    const p = await db();
    const sid = await getCurrentSeasonId();
    if (!sid) return res.json({ ok:true, entries: [] });
    const { rows } = await p.query(
      `select user_id, points_total
         from season_points where season_id=$1
         order by points_total desc, last_update asc
         limit 20`, [sid]);
    const entries = rows.map((r,i)=>({
      rank: i+1,
      user: String(r.user_id).slice(0,4)+'…'+String(r.user_id).slice(-4),
      points: Number(r.points_total)
    }));
    res.json({ ok:true, entries });
  } catch(e){
    res.status(500).json({ ok:false, error:'leaderboard_error' });
  }
});



// =================== Draw + Daily reward (server-authoritative) ===================
const RANKS = ['Ace','2','3','4','5','6','7','8','9','10','Jack','Queen','King'];
const SUITS = ['Clubs','Diamonds','Hearts','Spades'];
const RANK_VALUE = { '2':2,'3':3,'4':4,'5':5,'6':6,'7':7,'8':8,'9':9,'10':10,'Jack':11,'Queen':12,'King':13,'Ace':14 };
async function db() { if (!pool) throw new Error('No DATABASE_URL'); return pool; }

async function getOrCreateUser(uid){
  const p = await db();
  await p.query('insert into users(user_id) values($1) on conflict do nothing', [uid]);
  await p.query('insert into user_stats(user_id) values($1) on conflict do nothing', [uid]);
}

async function loadStats(uid){
  const p = await db();
  const { rows } = await p.query('select * from user_stats where user_id=$1', [uid]);
  return rows[0];
}

async function saveAfterDraw(uid, { creditMinor, isWin, isRoyal, flags }){
  const p = await db();
  const sets = ['bank_minor = LEAST(bank_minor + $2, $3)'];
  const vals = [uid, creditMinor, Number(process.env.BANK_CAP||2000000)];
  if (isWin) sets.push('wins = wins + 1');
  if (isRoyal) sets.push('royal_flushes = royal_flushes + 1');
  for (const f of flags||[]) sets.push(`${f} = true`);
  const sql = `update user_stats set ${sets.join(', ')}, last_seen_at=now() where user_id=$1`;
  await p.query(sql, vals);
}

async function getCurrentSeasonId(){
  const p = await db();
  const { rows } = await p.query(
    `select season_id from seasons where status='active' and now() between start_at and end_at
     order by start_at desc limit 1`);
  return rows[0]?.season_id ?? null;
}

async function awardSeasonPoints(uid, points){
  if (!points) return;
  const p = await db();
  const sid = await getCurrentSeasonId();
  if (!sid) return;
  await p.query('begin');
  try {
    await p.query('insert into season_points(season_id,user_id,points_total) values($1,$2,0) on conflict do nothing', [sid, uid]);
    await p.query('update season_points set points_total=points_total+$3, last_update=now() where season_id=$1 and user_id=$2', [sid, uid, points]);
    await p.query('commit');
  } catch(e){ await p.query('rollback'); console.error('awardSeasonPoints', e); }
}


// In server.js, extend ensureBank()
function ensureBank(req) {
  if (!req.session.bank) req.session.bank = 0;
  if (!req.session.stats) req.session.stats = { wins: 0, royalFlushes: 0 };
  if (!req.session.achievements) req.session.achievements = {};
  if (!req.session.lastDailyRewardAt) req.session.lastDailyRewardAt = 0;
  if (!req.session.lastDrawAt) req.session.lastDrawAt = 0;
  if (!req.session.deck) req.session.deck = [];
  if (typeof req.session.hasDrawn !== 'boolean') req.session.hasDrawn = false;
  if (!req.session.currentHand) req.session.currentHand = null;
}

function makeDeck() {
  const d = [];
  for (const s of SUITS) for (const r of RANKS) {
    d.push({ rank: r, suit: s, filename: `${r}_of_${s}.png`, displayText: `${r} of ${s}` });
  }
  for (let i = d.length - 1; i > 0; i--) { const j = Math.floor(Math.random() * (i + 1)); [d[i], d[j]] = [d[j], d[i]]; }
  return d;
}

function evalHand(hand) {
  const sorted = hand.slice().sort((a,b)=>RANK_VALUE[a.rank]-RANK_VALUE[b.rank]);
  const flush  = hand.every(c=>c.suit===hand[0].suit);
  let straight = sorted.every((c,i)=> i===0 || RANK_VALUE[c.rank]===RANK_VALUE[sorted[i-1].rank]+1);
  const values = sorted.map(c=>RANK_VALUE[c.rank]);
  if (!straight && values.join(',')==='2,3,4,5,14') straight = true; // wheel
  const royal = flush && straight && sorted[0].rank==='10' && sorted[4].rank==='Ace';
  const counts = Object.values(hand.reduce((m,c)=> (m[c.rank]=(m[c.rank]||0)+1, m), {})).sort((a,b)=>b-a);

  let payout = 0;
  if (royal) payout = 250;
  else if (straight && flush) payout = 50;
  else if (counts[0]===4) payout = 25;
  else if (counts[0]===3 && counts[1]===2) payout = 9;
  else if (flush) payout = 6;
  else if (straight) payout = 4;
  else if (counts[0]===3) payout = 3;
  else if (counts[0]===2 && counts[1]===2) payout = 2;
  else if (counts[0]===2) {
    const pairs = Object.entries(hand.reduce((m,c)=> (m[c.rank]=(m[c.rank]||0)+1, m), {})).filter(([,c])=>c===2).map(([r])=>r);
    if (pairs.some(r=>['Jack','Queen','King','Ace'].includes(r))) payout = 1;
  }
  return { payout, isWin: payout>0, isRoyal: royal };
}
function gateStartHand(req){
  const ip  = getClientIp(req);
  const now = Date.now();

  let rec = handsByIp.get(ip);
  if (!rec || (now - rec.windowStart) >= WINDOW_MS) {
    rec = { windowStart: now, count: 0 };
    handsByIp.set(ip, rec);
  }
  if (rec.count >= HANDS_LIMIT) {
    const retryMs = Math.max(0, WINDOW_MS - (now - rec.windowStart));
    return { ok:false, error:'ip_limit', retryMs, limit:HANDS_LIMIT };
  }
  rec.count += 1;
  handsByIp.set(ip, rec);
  return { ok:true, remaining: Math.max(0, HANDS_LIMIT - rec.count), windowMs: HANDS_WINDOW_MS };
}

const drawLimiter = rateLimit({ HANDS_WINDOW_MS: 60 * 1000, max: 60, standardHeaders: true, legacyHeaders: false });
const dealLimiter = rateLimit({
  HANDS_WINDOW_MS: 60 * 1000,
  max: 40,
  standardHeaders: true,
  legacyHeaders: false
});
app.post('/api/start-hand', (req, res) => {
  try {
    const g = gateStartHand(req);
    if (!g.ok) return res.status(403).json(g);
    ensureBank(req);
    req.session.hasDrawn = false;
    return res.json(g);
  } catch (e) {
    console.error('start-hand error', e);
    return res.status(500).json({ ok:false, error:'start_hand_error' });
  }
});


app.post('/api/deal', dealLimiter, (req, res) => {
 const ip = getClientIp(req);
  const rec = handsByIp.get(ip);
  if (!rec) return res.status(429).json({ ok:false, error:'use_start_hand_first' });

  const deck = makeDeck();
  const hand = deck.splice(0, 5);

  req.session.deck = deck;
  req.session.currentHand = hand;
  req.session.hasDrawn = false;

  return res.json({ ok: true, hand });
});

async function saveAfterDraw(uid, { creditMinor, isWin, isRoyal, flags }) {
  const p = await db();
  const bankCap = Number(process.env.BANK_CAP || 2000000);

  const sets = ['bank_minor = LEAST(bank_minor + $2, $3)'];
  const vals = [uid, creditMinor, bankCap];

  if (isWin)   sets.push('wins = wins + 1');
  if (isRoyal) sets.push('royal_flushes = royal_flushes + 1');
  for (const f of (flags || [])) sets.push(`${f} = true`);

  await p.query(`UPDATE user_stats SET ${sets.join(', ')} WHERE user_id = $1`, vals);
  await p.query('UPDATE users SET last_seen_at = now() WHERE user_id = $1', [uid]);
}
app.post('/api/draw', drawLimiter, async (req, res) => {
  try {
    const ip = getClientIp(req);
    ensureBank(req);

    // throttle per session (handle first-draw case)
    const now = Date.now();
    if (now - (req.session.lastDrawAt || 0) < DRAW_MIN_MS) {
      return res.status(429).json({ ok:false, error:'too_fast' });
    }
    req.session.lastDrawAt = now;
    const rec = handsByIp.get(ip);
    if (!rec) return res.status(429).json({ ok:false, error:'use_start_hand_first' });

    const { held } = req.body || {};
    if (!Array.isArray(held) || held.length !== 5) {
      return res.status(400).json({ ok:false, error:'bad_hold_array' });
    }
    if (!req.session.currentHand || !Array.isArray(req.session.deck)) {
      return res.status(400).json({ ok:false, error:'deal_first' });
    }
    if (req.session.hasDrawn) {
      return res.status(429).json({ ok:false, error:'already_drawn' });
    }

    // replace only non-held cards
    let hand = req.session.currentHand.slice();
    let deck = req.session.deck.slice();
    for (let i = 0; i < 5; i++) {
      if (!held[i]) {
        if (deck.length === 0) deck = makeDeck();
        hand[i] = deck.shift();
      }
    }

    const result  = evalHand(hand);
    const isWin   = (typeof result.isWin   === 'boolean') ? result.isWin   : (result.payout > 0);
    const isRoyal = (typeof result.isRoyal === 'boolean') ? result.isRoyal : !!result.royal;

    let credit = result.payout * TOKENS_PER_CREDIT * 100; // minor units

    await getOrCreateUser(req.uid);

    // ensure session structures exist
    if (!req.session.stats)         req.session.stats = { wins: 0, royalFlushes: 0 };
    if (!req.session.achievements)  req.session.achievements = {};
    const A = req.session.achievements;

    const bonuses   = [];
    const achFlags  = [];
    const pointsEarned = result.payout || 0; // paytable credits only

    function addBonus(name, amount, flag) {
      bonuses.push({ name, amount });
      credit += amount;
      if (flag) achFlags.push(flag);
    }

    if (isWin)   req.session.stats.wins++;
    if (isRoyal) req.session.stats.royalFlushes++;

    if (isWin && !A.firstWin)                      { addBonus('firstWin', 100*100,    'first_win');  A.firstWin = true; }
    if (req.session.stats.wins >= 10 && !A['10Wins'])  { addBonus('10Wins', 1000*100,  'w10');        A['10Wins'] = true; }
    if (req.session.stats.wins >= 25 && !A['25Wins'])  { addBonus('25Wins', 2500*100,  'w25');        A['25Wins'] = true; }
    if (req.session.stats.wins >= 50 && !A['50Wins'])  { addBonus('50Wins', 5000*100,  'w50');        A['50Wins'] = true; }
    if (isRoyal && !A.royalFlush)                  { addBonus('royalFlush', 50000*100,'royal_win');  A.royalFlush = true; }

    // apply to session + finalize round
    req.session.bank = Math.min(BANK_CAP, req.session.bank + credit);
    req.session.currentHand = null;
    req.session.deck = [];
    req.session.hasDrawn = true;

    // persist to DB
    await saveAfterDraw(req.uid, { creditMinor: credit, isWin, isRoyal, flags: achFlags });

    // leaderboard: award skill points (paytable credits)
    if (typeof awardSeasonPoints === 'function') {
      await awardSeasonPoints(req.uid, pointsEarned);
    }

    return res.json({
      ok: true,
      hand,
      result,
      credit,
      bonuses,
      sessionBalance: req.session.bank,
      stats: req.session.stats,
      points: pointsEarned
    });
  } catch (err) {
    console.error('draw error', err);
    return res.status(500).json({ ok:false, error:'draw_error' });
  }
});



const rewardLimiter = rateLimit({ windowMs: 60 * 1000, max: 12, standardHeaders: true, legacyHeaders: false });
app.post('/api/daily-reward', rewardLimiter, (req, res) => {
  ensureBank(req);
  const now = Date.now();
  const elapsed = now - (req.session.lastDailyRewardAt || 0);
  if (elapsed < ONE_DAY_MS) {
    return res.status(429).json({ ok:false, error:'already_claimed', retryInMs: ONE_DAY_MS - elapsed });
  }
  const DAILY_REWARD = 100 * 100; // minor units
  req.session.bank = Math.min(BANK_CAP, req.session.bank + DAILY_REWARD);
  req.session.lastDailyRewardAt = now;
  res.json({ ok:true, credit: DAILY_REWARD, sessionBalance: req.session.bank, nextClaimAt: now + ONE_DAY_MS });
});

// =================== Payout ===================
// Track used captcha tokens (replay defense) and address cooldowns
const usedCaptchaTokens = new Set();
setInterval(() => usedCaptchaTokens.clear(), 5 * 60 * 1000);
const lastPayoutByAddress = new Map();

function looksLikeNexaAddress(addr = '') {
  if (typeof addr !== 'string') return false;
  if (!addr.startsWith('nexa:')) return false;
  if (addr.length > 120) return false;
  // simple charset check
  return /^[a-z0-9:]+$/i.test(addr);
}

const payoutLimiter = rateLimit({
  windowMs: SIX_HOURS_MS,
  max: 5,
  standardHeaders: true,
  legacyHeaders: false
});
app.use('/api/payout', payoutLimiter);

app.post('/api/payout', async (req, res) => {
  ensureBank(req);
const payoutAmount = req.session.bank; // authoritative server balance
  let { playerAddress, hcaptchaToken } = req.body || {};
  // sanitize lengths early
  if (typeof hcaptchaToken === 'string' && hcaptchaToken.length > 4096) hcaptchaToken = hcaptchaToken.slice(0,4096);

  
  if (!payoutAmount || typeof payoutAmount !== 'number' || payoutAmount <= 0) {
    return res.status(400).json({ error: 'No balance to withdraw' });
  }
  if (!looksLikeNexaAddress(playerAddress)) {
    logger.warn('Invalid address', { ip: req.ip, playerAddress });
    return res.status(400).json({ error: 'Invalid Nexa address' });
  }

  // per-address cooldown
  const lastAt = lastPayoutByAddress.get(playerAddress) || 0;
  if (Date.now() - lastAt < PAYOUT_COOLDOWN_MS) {
    const wait = PAYOUT_COOLDOWN_MS - (Date.now() - lastAt);
    return res.status(429).json({ error: 'address_cooldown', retryInMs: wait });
  }
const captcha = await hcaptcha.verify(process.env.HCAPTCHA_SECRET, hcaptchaToken, req.ip);
if (!captcha.success) return res.status(400).json({ error: 'Captcha failed' });
if (process.env.HCAPTCHA_HOSTNAME && captcha.hostname !== process.env.HCAPTCHA_HOSTNAME) {
  return res.status(400).json({ error: 'Captcha host mismatch' });
}
// replay defense
if (usedCaptchaTokens.has(hcaptchaToken)) return res.status(400).json({ error: 'Captcha token already used' });
usedCaptchaTokens.add(hcaptchaToken);


  // clamp to maximum per-claim
  const sendAmount = Math.min(payoutAmount, MAX_PAYOUT);

  try {
    const rpcUrl = process.env.RPC_URL ? process.env.RPC_URL : `http://localhost:${process.env.RPC_PORT || 7227}`;
    const auth = Buffer.from(`${process.env.RPC_USER}:${process.env.RPC_PASSWORD}`).toString('base64');

    const body = JSON.stringify({
      jsonrpc: "1.0",
      id: "kibl",
      method: "token",
      params: ["send", process.env.KIBL_GROUP_ID, playerAddress, String(sendAmount)]
    });

    let txId = null;
    for (let attempt = 1; attempt <= 3; attempt++) {
      try {
        const response = await fetch(rpcUrl, {
          method: 'POST',
          headers: { 'Content-Type': 'text/plain', 'Authorization': `Basic ${auth}` },
          body
        });
        const data = await response.json();
        if (data.error) throw new Error(data.error.message || 'Unknown RPC error');
        txId = data.result;
        break;
      } catch (err) {
        logger.error(`RPC attempt ${attempt} failed`, { err: String(err) });
        if (attempt === 3) throw err;
        await new Promise(r => setTimeout(r, 1000 * attempt));
      }
    }

    // success → zero session bank & set cooldown
    req.session.bank = 0;
    lastPayoutByAddress.set(playerAddress, Date.now());

    logger.info('Payout success', { ip: req.ip, txId, playerAddress, amount: sendAmount });
    return res.json({ success: true, txId, message: `Sent ${sendAmount} KIBL to ${playerAddress}` });
  } catch (error) {
    logger.error('Token send failed', { error: String(error) });
    return res.status(500).json({ error: 'Failed to send tokens due to a server issue. Please try again later.' });
  }
});

// =================== Root ===================
app.get('/', (_req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));

const port = process.env.PORT || 3000;
app.listen(port, () => {
  logger.info(`Server running at http://localhost:${port}`);
  console.log(`Server running at http://localhost:${port}`);
});

