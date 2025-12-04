require('dotenv').config();
const express = require('express');
const path = require('path');
const fetch = (...args) => import('node-fetch').then(({ default: fetch }) => fetch(...args));
const helmet = require('helmet');
const winston = require('winston');
const { rateLimit } = require('express-rate-limit');
const hcaptcha = require('hcaptcha');
const session = require('express-session');
const cookieParser = require('cookie-parser');
const { Pool } = require('pg');
const csrf = require('csurf');
const PgSession = require('connect-pg-simple')(session);
const {randomBytes, createHash, randomUUID } = require('crypto');
const app = express();
const { WatchOnlyWallet, Wallet, rostrumProvider, AccountType } = require('nexa-wallet-sdk');
app.set('trust proxy', 1);
// ----- ENV / MODE -----
process.on('unhandledRejection', (reason) => {
  console.error('[unhandledRejection]', reason);
});
process.on('uncaughtException', (err) => {
  console.error('[uncaughtException]', err);
});
const PORT = process.env.PORT || 10000;
async function ensureRostrum() {
  // 1. Try Private Node (Fastest)
  try {
    if (rostrumProvider.isConnected) return;
    
    console.log('[Rostrum] Connecting to Private Infrastructure...');
    await rostrumProvider.connect({ 
      scheme: 'wss', 
      host: 'node.remy-dev.com',  
      port: 443 
    });
    console.log('✅ [Rostrum] Connected to Private Node (NVMe Accelerated)');
  } catch (e) {
    console.warn('⚠️ [Rostrum] Private node unreachable, attempting failover:', e.message);
    // 2. Failover to Public Node
    try {
      await rostrumProvider.connect({ 
        scheme: 'wss', 
        host: 'electrum.nexa.org', 
        port: 20004 
      });
      console.log('⚠️ [Rostrum] Connected to Public Backup Node');
    } catch (err) {
      console.error('❌ [Rostrum] CRITICAL: All nodes failed:', err.message);
    }
  }
}


(async () => {
  await ensureRostrum();
})();

const KIBL_GROUP_HEX = '656bfefce8a0885acba5c809c5afcfbfa62589417d84d54108e6bb42a6f30000';



const isProd = process.env.NODE_ENV === 'production' || !!process.env.RENDER;
function must(name) {
  const v = process.env[name];
  if (!v) throw new Error(`Missing required env: ${name}`);
  return v;
}

function mustBeURL(name) {// - REPLACED FUNCTION

  const v = must(name);
  try { new URL(v); } catch (e) {
    throw new Error(`Invalid URL in ${name}: ${v}`);
  }
  return v;
}

if (process.env.RPC_URL) mustBeURL('RPC_URL');   
must('SESSION_SECRET');
if (process.env.DATABASE_URL) mustBeURL('DATABASE_URL');

const hasDb = !!process.env.DATABASE_URL;
let pool = null;
if (hasDb) {
  pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ...(isProd ? { ssl: { rejectUnauthorized: false } } : {})
  });
}
 async function db() {
  if (!hasDb) throw new Error('DB disabled');
  return pool;
}
let cachedServerWallet = null;

// ----- MIDDLEWARE ORDER -----
app.use(cookieParser());
app.use(express.json({ limit: '100kb' }));
app.use(express.static('public', {
  maxAge: isProd ? '1h' : 0,
  etag: true,
  lastModified: true,
  setHeaders: (res, filePath) => {
    if (filePath.endsWith('.html')) {
      // always fetch a fresh HTML shell
      res.setHeader('Cache-Control', 'no-store');
    } else if (/\.(js|css)$/i.test(filePath)) {
      // long cache for versioned assets
      res.setHeader('Cache-Control', isProd ? 'public, max-age=31536000, immutable' : 'no-store');
    } else if (/\.(png|jpg|jpeg|gif|svg|ico)$/i.test(filePath)) {
      res.setHeader('Cache-Control', isProd ? 'public, max-age=86400, immutable' : 'no-store');
    }
  }
}));

app.use(express.urlencoded({ extended: true, limit: '100kb' }));

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
// --- UID COOKIE (robust) ---
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

app.use((req, res, next) => {
  let uid = req.cookies?.uid;
  if (!uid || !UUID_RE.test(uid)) {
    uid = randomUUID();
    res.cookie('uid', uid, {
      httpOnly: true,
      sameSite: 'lax',
      secure: process.env.NODE_ENV === 'production',
      maxAge: 1000 * 60 * 60 * 24 * 365 // 1 year
    });
  }
  req.uid = uid;
  next();
});

const crossSite = process.env.CROSS_SITE_COOKIES === 'true';
const csrfProtection = csrf({
  cookie: {
    key: '_csrf',           
    httpOnly: true,
    sameSite: 'lax',
    secure: isProd,
  }
});
// must be BEFORE you mount csrfProtection 
app.get('/api/csrf', csrfProtection, (req, res) => {
  res.json({ csrfToken: req.csrfToken() });
});
app.use('/api', (req, res, next) => {
  if (req.method === 'GET' || req.method === 'HEAD' || req.method === 'OPTIONS') {
    return next();
  }
  return csrfProtection(req, res, next);
});

// =================== Config ===================
const SIX_HOURS_MS = 6 * 60 * 60 * 1000;
const ONE_DAY_MS   = 24 * 60 * 60 * 1000;
const DRAW_MIN_MS  = Number(process.env.DRAW_MIN_MS || 1500);     // min time between draws per session
const MAX_PAYOUT   = Number(process.env.MAX_PAYOUT || 100_000);   // per claim cap (minor units)
const BANK_CAP     = Number(process.env.BANK_CAP || 5_000_000);   // max server bank per session
const PAYOUT_COOLDOWN_MS = Number(process.env.PAYOUT_COOLDOWN_MS || SIX_HOURS_MS); // per address cooldown
const HCAPTCHA_SECRET   = process.env.HCAPTCHA_SECRET;  
const HCAPTCHA_HOSTNAME = process.env.HCAPTCHA_HOSTNAME || '';   
const tablesByGame = {
  poker:      { stats: 'user_stats',            points: 'season_points' },
  blackjack:  { stats: 'user_stats_blackjack',  points: 'season_points_blackjack' }
};



if (!HCAPTCHA_SECRET) console.error('⚠️ HCAPTCHA_SECRET is not set');


// =================== Security headers ===================
app.use(helmet()); 

app.use(helmet.referrerPolicy({ policy: 'no-referrer' }));

app.use(helmet.frameguard({ action: 'deny' })); // deny being embedded anywhere

// Content Security Policy 
app.use(
  helmet.contentSecurityPolicy({
    useDefaults: false, 
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'", "'unsafe-inline'", "https://hcaptcha.com", "https://*.hcaptcha.com" , "https://esm.sh"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      imgSrc: ["'self'", "data:", "blob:"],
      connectSrc: ["'self'", "https:", "wss:"],
      frameSrc: ["https://hcaptcha.com", "https://*.hcaptcha.com"],
      objectSrc: ["'none'"],
      baseUri: ["'self'"],
      formAction: ["'self'"],
      frameAncestors: ["'none'"], 
     upgradeInsecureRequests: []  
    },
  })
);
// =================== Logging ===================
const logger = winston.createLogger({
  level: 'info',
  format: winston.format.json(),
  transports: [
    new winston.transports.Console(),
    new winston.transports.File({ filename: 'faucet.log' })
  ]
});

app.get('/healthz', async (_req,res)=>{
  let dbOk = hasDb ? 'ok' : 'disabled';
  if (hasDb) {
    try { await pool.query('select 1'); } catch { dbOk = 'down'; }
  }
  res.json({ ok:true, ts:new Date().toISOString(), db: dbOk });
});

app.get('/api/version', (_req,res)=> {
  res.json({ ok:true, commit: process.env.GIT_COMMIT || null, build: process.env.BUILD_ID || null });
});
app.use((req, _res, next) => {
  logger.info('Incoming request', {
    method: req.method, url: req.url,
    ip: getClientIp(req),
    uid: req.uid,
    ua: (req.headers['user-agent'] || '').slice(0,120)
  });
  next();
});


// =================== Hand/IP limiting ===================

const HANDS_WINDOW_MS  = SIX_HOURS_MS;
const TOKENS_PER_CREDIT = Number(process.env.TOKENS_PER_CREDIT || 1); // tokens per 1 credit
const HANDS_LIMIT = Math.max(1, Number(process.env.IP_HANDS_PER_6H)) || 40;
const HANDS_LIMIT_POKER = Number(process.env.IP_HANDS_PER_6H_POKER || HANDS_LIMIT);
const HANDS_LIMIT_BJ    = Number(process.env.IP_HANDS_PER_6H_BJ    || HANDS_LIMIT);
const WINDOW_MS   = 6 * 60 * 60 * 1000;
const handsByUid = new Map(); 
const handsByIp  = new Map(); 
function touch(rec, now) {
  return (!rec || (now - rec.windowStart) >= WINDOW_MS)
    ? { windowStart: now, counts: { poker: 0, blackjack: 0 } }
    : rec;
}
app.get('/api/profile', async (req, res) => {
  try {
    ensureBank(req);

    // Avoid any caching of this endpoint
    res.set('Cache-Control', 'no-store');

    const [userOk, statsOk] = await Promise.allSettled([
      getOrCreateUser(req.uid),
      loadStats(req.uid)
    ]);
    const s = statsOk.status === 'fulfilled' ? statsOk.value : null;
   const displayId = await ensureDisplayId(req.uid);
    const balPoker = Math.max(0, Number(req.session.wallet?.poker || 0));
    const balBJ    = Math.max(0, Number(req.session.wallet?.blackjack || 0));
    const total    = Math.min(BANK_CAP, balPoker + balBJ);
      req.session.bank = total; // keep session total canonical

    let poker=null, bj=null;
    try {
      await getOrCreateUser(req.uid);
      [poker, bj] = await Promise.all([loadStatsFor(req.uid,'poker'), loadStatsFor(req.uid,'blackjack')]);
    } catch {}
    return res.json({
      ok: true,
      displayId,
      bank: total,
      balances: { poker: balPoker, blackjack: balBJ, total },
      stats: {
        poker: {
          wins: poker?.wins || 0,
          royalFlushes: poker?.royal_flushes || 0,
          achievements: {
            firstWin:   !!poker?.first_win,
            w10:        !!poker?.w10,
            w25:        !!poker?.w25,
            w50:        !!poker?.w50,
            royalFlush: !!poker?.royal_win
          }
        },
        blackjack: {
  wins: bj?.wins || 0,
  achievements: {
    firstWin:  !!bj?.first_win,
    w10:       !!bj?.w10,
    w25:       !!bj?.w25,
    w50:       !!bj?.w50,
    natural:   !!bj?.bj_natural,
    doubleWin: !!bj?.bj_double_win,
    splitWin:  !!bj?.bj_split_win
  }
}
}
           
    });
  } catch (e) {
    return res.status(500).json({ ok: false, error: 'profile_error' });
  }
});

function getClientIp(req) {
  if (Array.isArray(req.ips) && req.ips.length) return req.ips[0];

  const xf = (req.headers['x-forwarded-for'] || '').split(',')[0].trim();
  if (xf) return xf;

  let ip = req.ip || req.socket?.remoteAddress || '';
  if (ip === '::1' || ip === '::ffff:127.0.0.1') return '127.0.0.1';
  if (ip.startsWith('::ffff:')) ip = ip.slice(7);
  return ip;
}



// hash-stream PRNG (deterministic, verifiable)
const sha256hex = (s) => createHash('sha256').update(String(s)).digest('hex');
const randHex = (n = 32) => randomBytes(n).toString('hex');
// --- FIX: Unbiased Rejection Sampling Shuffle ---
function* hashStream(seedHex) {
  let h = seedHex;
  while (true) {
    h = sha256hex(h);
    // Yield the full 32-bit integer value (0 to 4294967295)
    yield parseInt(h.slice(0, 8), 16) >>> 0;
  }
}

function shuffleDeterministic(deck, rng) {
  const a = deck.slice();
  for (let i = a.length - 1; i > 0; i--) {
    // Implements Rejection Sampling to eliminate modulo bias
    const max = i + 1;
    const limit = 0xFFFFFFFF - (0xFFFFFFFF % max);
    let r;
    do {
      r = rng.next().value; // Get next 32-bit int
    } while (r >= limit); // Discard if in the "biased zone"
    
    const j = r % max;
    [a[i], a[j]] = [a[j], a[i]];
  }
  return a;
}
// Leaderboard
app.get('/api/leaderboard/top', async (req, res) => {
  try {
    const game = (req.query.game === 'blackjack') ? 'blackjack' : 'poker';
    const limit = Math.max(1, Math.min(50, Number(req.query.limit) || 10));
    const table = tablesByGame[game].points;

    const p = await db();
    const sid = await getCurrentSeasonId();
    if (!sid) return res.json({ ok: true, game, entries: [] });

    const { rows } = await p.query(
      `select
  sp.user_id,
  sp.points_total,
  coalesce(u.display_id,
           'PUP-'||upper(left(sp.user_id::text,4))||'…'||upper(right(sp.user_id::text,4))) as tag
from ${table} sp
left join users u on u.user_id = sp.user_id
where sp.season_id = $1
order by sp.points_total desc, sp.last_update asc, sp.user_id
limit $2

      `,
      [sid, limit]
    );

    const entries = rows.map((r, i) => ({
      rank: i + 1,
      user: r.tag,
      points: Number(r.points_total),
      userId: r.user_id
    }));

    res.json({ ok: true, game, limit, entries });
  } catch (e) {
    res.status(500).json({ ok: false, error: 'leaderboard_top_error' });
  }
});
app.get('/api/leaderboard/window', async (req, res) => {
  try {
    const game = (req.query.game === 'blackjack') ? 'blackjack' : 'poker';
    const k = Math.max(1, Math.min(10, Number(req.query.k) || 3)); // window radius
    const table = tablesByGame[game].points;

    const p = await db();
    const sid = await getCurrentSeasonId();
    if (!sid) return res.json({ ok: true, game, window: [], you: null });

  const { rows } = await p.query(`
  with base as (
    select sp.user_id, sp.points_total, sp.last_update
    from ${table} sp
    where sp.season_id = $1

    union all
    select $2::uuid as user_id, 0::bigint as points_total, now()
    where not exists (
      select 1 from ${table} x
      where x.season_id = $1 and x.user_id = $2::uuid
    )
  ),
  ranked as (
    select
      b.user_id,
      b.points_total,
      row_number() over (
        order by b.points_total desc, b.last_update asc, b.user_id
      ) as rn
    from base b
  ),
  me as (
    select rn from ranked where user_id = $2::uuid
  ),
  bounds as (
    select
      (select rn from me) as my_rn,
      (select max(rn) from ranked) as max_rn
  )
  select
    r.rn as rank,
    r.user_id,
    r.points_total,
    (r.user_id = $2::uuid) as is_you,
    coalesce(
      u.display_id,
      'PUP-'||upper(left(r.user_id::text,4))||'…'||upper(right(r.user_id::text,4))
    ) as tag
  from ranked r
  left join users u on u.user_id = r.user_id
  where r.rn between greatest(1, (select my_rn from bounds) - $3)
                 and least((select max_rn from bounds), (select my_rn from bounds) + $3)
  order by r.rn
`, [sid, req.uid, k]);


    const window = rows.map(r => ({
      rank: Number(r.rank),
      user: r.tag,
      points: Number(r.points_total),
      you: r.is_you
    }));

    // Give handy deltas to the next/prev ranks 
    let you = window.find(x => x.you) || null;
    if (you) {
      const idx = window.findIndex(x => x.you);
      const ahead = window[idx - 1];
      const behind = window[idx + 1];
      you = {
        ...you,
        deltaAhead: ahead ? Math.max(0, ahead.points - you.points) : null,
        deltaBehind: behind ? Math.max(0, you.points - behind.points) : null
      };
    }

    res.json({ ok: true, game, k, window, you });
  } catch (e) {
    res.status(500).json({ ok: false, error: 'leaderboard_window_error' });
  }
});


// =================== Draw + Daily reward (server-authoritative) ===================
const RANKS = ['Ace','2','3','4','5','6','7','8','9','10','Jack','Queen','King'];
const SUITS = ['Clubs','Diamonds','Hearts','Spades'];
const RANK_VALUE = { '2':2,'3':3,'4':4,'5':5,'6':6,'7':7,'8':8,'9':9,'10':10,'Jack':11,'Queen':12,'King':13,'Ace':14 };

async function getOrCreateUser(uid) {
  if (!hasDb) return;
  const p = await db();
  await p.query('BEGIN');
  try {
    await p.query('INSERT INTO users(user_id) VALUES($1) ON CONFLICT DO NOTHING', [uid]);
    await p.query('INSERT INTO user_stats(user_id) VALUES($1) ON CONFLICT DO NOTHING', [uid]);
    await p.query('INSERT INTO user_stats_blackjack(user_id) VALUES($1) ON CONFLICT DO NOTHING', [uid]);
    await p.query('COMMIT');
  } catch (e) {
    await p.query('ROLLBACK');
    throw e;
  }
}
app.use(async (req, _res, next) => {
  try { await getOrCreateUser(req.uid); } catch {}
  next();
});

async function loadStatsFor(uid, game) {
  if (!hasDb) return null;
  const { stats } = tablesByGame[game];
  const p = await db();
  const { rows } = await p.query(`select * from ${stats} where user_id = $1`, [uid]);
  return rows[0] || null;
}

async function saveStatsFor(uid, game, { creditMinor, isWin, isRoyal, flags }) {
  if (!hasDb) return;
  const { stats } = tablesByGame[game];
  const p = await db();
  const sets = ['bank_minor = LEAST(bank_minor + $2, $3)'];
  const vals = [uid, creditMinor, Number(process.env.BANK_CAP || 2_000_000)];
  if (isWin)   sets.push('wins = wins + 1');
  if (isRoyal) sets.push('royal_flushes = royal_flushes + 1'); // harmless for BJ (stays 0)
  for (const f of (flags || [])) sets.push(`${f} = true`);
  await p.query(`update ${stats} set ${sets.join(', ')}, last_seen_at = now() where user_id = $1`, vals);
}

async function awardSeasonPointsFor(uid, game, points) {
  if (!hasDb || !points) return;
  const { points: table } = tablesByGame[game];
  const p = await db();
  const sid = await getCurrentSeasonId();
  if (!sid) return;
  await p.query('begin');
  try {
    await p.query(`insert into ${table}(season_id,user_id,points_total) values($1,$2,0) on conflict do nothing`, [sid, uid]);
    await p.query(`update ${table} set points_total=points_total+$3, last_update=now() where season_id=$1 and user_id=$2`, [sid, uid, points]);
    await p.query('commit');
  } catch (e) {
    await p.query('rollback');
  }
}

async function loadStats(uid){
  if (!hasDb) return null;
  const p = await db();
  const { rows } = await p.query('select * from user_stats where user_id=$1', [uid]);
  return rows[0] || null;
}

async function saveAfterDraw(uid, { creditMinor, isWin, isRoyal, flags }){
  if (!hasDb) return;
  const p = await db();
  const sets = ['bank_minor = LEAST(bank_minor + $2, $3)'];
  const vals = [uid, creditMinor, Number(process.env.BANK_CAP||2000000)];
  if (isWin) sets.push('wins = wins + 1');
  if (isRoyal) sets.push('royal_flushes = royal_flushes + 1');
  for (const f of flags||[]) sets.push(`${f} = true`);
  await p.query(`update user_stats set ${sets.join(', ')}, last_seen_at=now() where user_id=$1`, vals);
}

async function ensureDisplayId(uid){
  const left  = String(uid).slice(0,4).toUpperCase();
  const right = String(uid).slice(-4).toUpperCase();
  const display = `PUP-${left}…${right}`;
  if (!hasDb) return display;
  const p = await db();
  await p.query(
    `UPDATE users
       SET display_id = COALESCE(display_id, $2),
           last_seen_at = now()
     WHERE user_id = $1`,
    [uid, display]
  );
  return display;
}

async function getCurrentSeasonId(){
  if (!hasDb) return null;
  const p = await db();
  const { rows } = await p.query(
    `select season_id from seasons
      where status='active' and now() between start_at and end_at
      order by start_at desc limit 1`
  );
  return rows[0]?.season_id ?? null;
}

async function awardSeasonPoints(uid, points){
  if (!hasDb || !points) return;
  const p = await db();
  const sid = await getCurrentSeasonId();
  if (!sid) return;
  await p.query('begin');
  try {
    await p.query('insert into season_points(season_id,user_id,points_total) values($1,$2,0) on conflict do nothing', [sid, uid]);
    await p.query('update season_points set points_total=points_total+$3, last_update=now() where season_id=$1 and user_id=$2', [sid, uid, points]);
    await p.query('commit');
  } catch(e){ await p.query('rollback'); }
}

function ensureBank(req) {
  if (!req.session.bank) req.session.bank = 0;
  if (!req.session.bank && req.session.bank !== 0) req.session.bank = 0;
  if (!req.session.wallet) req.session.wallet = { poker: 0, blackjack: 0 };
  if (!req.session.stats) req.session.stats = { wins: 0, royalFlushes: 0 };
  if (!req.session.achievements) req.session.achievements = {};
  if (!req.session.lastDailyRewardAt) req.session.lastDailyRewardAt = 0;
  if (!req.session.lastDrawAt) req.session.lastDrawAt = 0;
  if (!req.session.deck) req.session.deck = [];
  if (typeof req.session.hasDrawn !== 'boolean') req.session.hasDrawn = false;
  if (!req.session.round) {
  req.session.round = null; // { handId, commit, serverSeed, clientSeed }
      }
  if (!req.session.currentHand) req.session.currentHand = null;
}
// Wallet functions
// /api/wallet/balance
app.get('/api/wallet/balance', async (req, res) => {
  try {

    const address = String(req.query.address || '');
    if (!/^nexa:[a-z0-9]+$/i.test(address)) {
      return res.status(400).json({ ok:false, error:'bad_address' });
    }

    // Watch-only against the single address, mainnet
    const w = new WatchOnlyWallet({ address }, 'mainnet');

    // New 0.8.0 helpers – already aggregated; no manual UTXO math
    const nexaBal     = await w.getBalance();         // { confirmed:"...", unconfirmed:"..." }
    const tokenBals   = await w.getTokenBalances();   // { [tokenHex]: { confirmed:"...", unconfirmed:"..." }, ... }

    // Pull just KIBL (string → Number → /100). No BigInt anywhere.
    const kiblMinor   = Number(tokenBals[KIBL_GROUP_HEX]?.confirmed || 0);
    const nexaMinor   = Number(nexaBal.confirmed || 0);

    res.json({
      ok: true,
      address,
      tokenHex: KIBL_GROUP_HEX,
      nexaMinor: String(nexaMinor),
      nexa: (nexaMinor / 100).toFixed(2),
      kiblMinor: String(kiblMinor),
      kibl: (kiblMinor / 100).toFixed(2),
    });
  } catch (e) {
    console.error('balance_error', e);
    res.status(500).json({ ok:false, error:'balance_error' });
  }
});


// /api/wallet/link  (server)
app.post('/api/wallet/link', async (req, res) => {
  try {
    const { address, network } = req.body || {};
    if (!address || !/^nexa:/.test(address)) return res.status(400).json({ ok:false, error:'bad_address' });
    const net = (network === 'mainnet') ? 'mainnet' : 'mainnet'; 
    await getOrCreateUser(req.uid);
    if (hasDb) {
      const p = await db();
      await p.query(
        `update users set wallet_addr=$2, wallet_net=$3, last_seen_at=now() where user_id=$1`,
        [req.uid, address, net]
      );
    } else {
      req.session.linkedWallet = { address, network: net };
      if (req.session.save) await new Promise((r,j)=>req.session.save(e=>e?j(e):r()));
    }
    res.json({ ok:true });
  } catch { res.status(500).json({ ok:false, error:'link_error' }); }
});
app.get('/api/wallet/status', async (req,res)=>{
  try {
    if (req.session?.linkedWallet) return res.json({ ok:true, linked:true, ...req.session.linkedWallet });
    if (!hasDb) return res.json({ ok:true, linked:false });
    const p = await db();
    const { rows } = await p.query('select wallet_addr as address, wallet_net as network from users where user_id=$1', [req.uid]);
    if (rows[0]?.address) return res.json({ ok:true, linked:true, ...rows[0] });
    res.json({ ok:true, linked:false });
  } catch { res.status(500).json({ ok:false, error:'status_error' }); }
});

// Optimized /api/bet/build-unsigned
app.post('/api/bet/build-unsigned', async (req, res) => {
  try {
    // 1. Reuse existing connection (Instant)
    await ensureRostrum();

    const { fromAddress, kiblAmount, feeNexa } = req.body;
    
    // Fast Validation
    if (!fromAddress?.startsWith('nexa:')) return res.status(400).json({ ok: false, error: 'bad_address' });
    
    // 2. Constants (Defined once, cheap)
    const house = 'nexa:nqtsq5g5pvucuzm2kh92kqtxy5s3zfutq3xgnhh5src65fc3';
    const tokenId = 'nexa:tpjkhlhuazsgskkt5hyqn3d0e7l6vfvfg97cf42pprntks4x7vqqqcavzypmt'; 

    // 3. Lightweight Instantiation (Cheap)
    const w = new WatchOnlyWallet({ address: fromAddress }, 'mainnet');

    // 4. THE ONLY NETWORK CALL
    // We rely on your NVMe node to return this data in < 50ms.
    const unsignedTx = await w.newTransaction()
      .sendTo(house, feeNexa.toString())  
      .sendToToken(house, '5000', tokenId) 
      .populate() // <--- The only "slow" part (Fetching UTXOs)
      .build();

    return res.json({ ok: true, unsignedTx, house, network: 'mainnet' });

  } catch (e) {
    console.error('Build Error:', e.message);
    const msg = e.message.includes('Insufficient') ? 'Insufficient funds' : 'build_failed';
    return res.status(500).json({ ok: false, error: msg });
  }
});
app.post('/api/tx/broadcast', async (req, res) => {
  try {
    const { hex } = req.body || {};
    if (!hex || typeof hex !== 'string') {
      return res.status(400).json({ ok: false, error: 'bad_hex' });
    }

    // 1. Connection
    await ensureRostrum();

    // 2. LAZY LOAD WALLET (Inline, same as daily-reward)
    if (!cachedServerWallet) {
        console.log('[Broadcast] Initializing Hot Wallet...');
        const secret = process.env.HOT_WALLET_SECRET;
        if (!secret) throw new Error('HOT_WALLET_SECRET missing');

        let w;
        // Import
        if (secret.trim().startsWith('xprv') || secret.trim().startsWith('F6rxz')) {
             w = Wallet.fromXpriv(secret.trim(), 'mainnet');
        } else {
             w = new Wallet(secret, 'mainnet');
        }

        // Scan Chain
        await w.initialize();
        
        // Ensure Account
        if (!w.accountStore.getAccount('2.0')) {
             console.log('[Broadcast] Creating Account 2.0...');
             await w.newAccount('NEXA'); 
        }
        
        cachedServerWallet = w;
        console.log('[Broadcast] Wallet Cached.');
    }
    
    // 3. Select Wallet
    const walletToUse = cachedServerWallet;
    if (!walletToUse) throw new Error('Server wallet not initialized');

    console.log(`[Broadcast] Sending via Server Wallet...`);

    // 4. BROADCAST
    const txid = await walletToUse.sendTransaction(hex);
    
    console.log('[Broadcast] Success! TxId:', txid);
    return res.json({ ok: true, txid });

  } catch (e) {
    console.error('broadcast_error', e);
    // Self-healing: if inputs are missing, clear cache to force rescan next time
    if (e.message && (e.message.includes('inputs') || e.message.includes('UTXO'))) {
        cachedServerWallet = null;
    }
    return res.status(500).json({ ok: false, error: e.message || 'broadcast_failed' });
  }
});

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

function gateStartHand(req, game = 'poker') {
  const now  = Date.now();
  const uid  = req.uid || 'nouid';
  const ip   = getClientIp(req) || 'unknown';
  

  const limit = (game === 'blackjack') ? HANDS_LIMIT_BJ : HANDS_LIMIT_POKER;

  const rUid = touch(handsByUid.get(uid), now);
  const rIp  = touch(handsByIp.get(ip), now);
  

  const usedUid = rUid.counts[game] || 0;
  const usedIp  = rIp.counts[game]  || 0;
 

  // Strict user limit first (changing IP won't help)
  if (usedUid >= limit) {
    const retryMs = Math.max(0, WINDOW_MS - (now - rUid.windowStart));
    logger.warn('gate/limit', { reason:'user', uid, ip, game, used:usedUid, limit, retryMs });
    return { ok:false, error:'user_limit', retryMs, limit };
  }
  // Then IP (stops many UIDs from one IP)
  if (usedIp >= limit) {
    const retryMs = Math.max(0, WINDOW_MS - (now - rIp.windowStart));
    logger.warn('gate/limit', { reason:'ip', uid, ip, game, used:usedIp, limit, retryMs });
    return { ok:false, error:'ip_limit', retryMs, limit };
  }

  // Allowed → increment all three buckets
  rUid.counts[game] = usedUid + 1;
  rIp.counts[game]  = usedIp + 1;
 

  handsByUid.set(uid, rUid);
  handsByIp.set(ip, rIp);
  

  const remaining = Math.max(0, limit - rUid.counts[game]);
  return { ok:true, remaining, windowMs: WINDOW_MS };
}


setInterval(() => {
  const now = Date.now();
  for (const m of [handsByUid, handsByIp]) {
    for (const [k, rec] of m) if (now - rec.windowStart >= WINDOW_MS) m.delete(k);
  }
}, 6 * 60 * 1000);



const drawLimiter = rateLimit({ windowMs: 60 * 1000, max: 60, standardHeaders: true, legacyHeaders: false });
const dealLimiter = rateLimit({ windowMs: 60 * 1000, max: 40, standardHeaders: true, legacyHeaders: false });

app.post('/api/start-hand', async (req, res) => {
  try {
    const g = gateStartHand(req, 'poker');
    if (!g.ok) return res.status(403).json(g);

    ensureBank(req);

    const clientSeed = (req.body && typeof req.body.clientSeed === 'string')
      ? req.body.clientSeed.trim()
      : '';

    const handId     = randomUUID();
    const serverSeed = randHex(32);
    const commitHash = sha256hex(serverSeed);

    req.session.round = {
      handId,
      commit: commitHash,
      serverSeed,
      clientSeed,
      revealed: false
    };
    req.session.hasDrawn = false;

    if (hasDb) {
      try {
        const p = await db();
        await getOrCreateUser(req.uid);
        await ensureDisplayId(req.uid);
        await p.query(
          `INSERT INTO fair_rounds(hand_id, user_id, commit_hash, client_seed)
           VALUES ($1,$2,$3,$4)`,
          [handId, req.uid, commitHash, clientSeed || null]
        );
      } catch (e) {
        logger.error('fair_rounds insert', { e: String(e) });
      }
    }

    // --- FIX: Force save before replying ---
    await new Promise((resolve, reject) => {
      req.session.save((err) => {
        if (err) reject(err);
        else resolve();
      });
    });

    return res.json({
      ok:true,
      g,
      handId,
      commit: commitHash
    });
  } catch (e) {
    console.error('start-hand error', e);
    return res.status(500).json({ ok:false, error:'start_hand_error' });
  }
});

app.post('/api/deal', dealLimiter, async (req, res) => {
  // REMOVED: The specific IP memory check (handsByIp)
  // Why: You already passed the gate at 'start-hand'.
  
  ensureBank(req);

  // Security Check: Do they actually have a paid hand in the session?
  const round = req.session.round;
  if (!round || !round.handId || !round.serverSeed) {
    return res.status(400).json({ ok:false, error:'use_start_hand_first' });
  }

  // ... (Standard Deck Building Logic) ...
  const seedString = `${round.serverSeed}:${round.clientSeed || ''}:${round.handId}:deal`;
  const rng = hashStream(sha256hex(seedString));

  const deck0 = [];
  for (const s of SUITS) {
    for (const r of RANKS) {
      deck0.push({
        rank: r,
        suit: s,
        filename: `${r}_of_${s}.png`,
        displayText: `${r} of ${s}`
      });
    }
  }
  
  const deck = shuffleDeterministic(deck0, rng);
  const hand = deck.slice(0, 5);
  
  req.session.deck = deck.slice(5);
  req.session.currentHand = hand;
  req.session.hasDrawn = false;

  // Force Save to prevent Race Condition
  await new Promise((resolve, reject) => {
    req.session.save((err) => (err ? reject(err) : resolve()));
  });

  return res.json({
    ok: true,
    hand,
    fair: { handId: round.handId, commit: round.commit }
  });
});

   app.post('/api/draw', drawLimiter, async (req, res) => {
  try {
   
    ensureBank(req);

    const now = Date.now();
    const lastDrawAt = Number(req.session.lastDrawAt) || 0;
    if (now - lastDrawAt < DRAW_MIN_MS) {
      return res.status(429).json({ ok: false, error: 'too_fast' });
    }

    const { held } = req.body || {};
    if (!Array.isArray(held) || held.length !== 5) {
      return res.status(400).json({ ok: false, error: 'bad_hold_array' });
    }
    // Security Check: Do they have cards to draw against?
    if (!req.session.currentHand || !Array.isArray(req.session.deck)) {
      return res.status(400).json({ ok: false, error: 'deal_first' });
    }
    if (req.session.hasDrawn) {
      return res.status(429).json({ ok: false, error: 'already_drawn' });
    }

    // ---- Perform draw: replace only non-held cards ----
    let hand = req.session.currentHand.slice();
    let deck = req.session.deck.slice();
        for (let i = 0; i < 5; i++) {
         if (!held[i]) {
          if (deck.length === 0) {
          // should never happen with single-draw flow; guard just in case
          return res.status(500).json({ ok: false, error: 'deck_underflow' });
        }
        hand[i] = deck.shift();
      }
    }

    // Evaluate hand
    const result = evalHand(hand);
    const isWin   = (typeof result.isWin   === 'boolean') ? result.isWin   : (result.payout > 0);
    const isRoyal = (typeof result.isRoyal === 'boolean') ? result.isRoyal : !!result.royal;

    // ---------- CREDIT & ACHIEVEMENTS (minor units) ----------
    const toInt  = (v) => Math.floor(Number(v) || 0);
    const clamp0 = (v) => Math.max(0, toInt(v));

    // 1 credit => N KIBL; BANK_CAP must be MINOR units (KIBL*100)
    const TOKENS_PER_CREDIT = toInt(process.env.TOKENS_PER_CREDIT || 1);
    const BANK_LIMIT = toInt(process.env.BANK_CAP ?? BANK_CAP);

    // base credit from paytable (credits → KIBL → minor units)
    let credit = clamp0((result.payout || 0) * TOKENS_PER_CREDIT * 100);

    // ensure session structures exist
    req.session.stats        ||= { wins: 0, royalFlushes: 0 };
    req.session.achievements ||= {};
    const A = req.session.achievements;

    const bonuses      = [];   // [{ name, amount (minor) }]
    const achFlags     = [];   // e.g., ['first_win', ...]
    const pointsEarned = clamp0(result.payout || 0); // leaderboard points in "credits"

    function addBonus(name, kibls, flag) {
      const amountMinor = clamp0(kibls * 100);
      if (amountMinor <= 0) return;
      bonuses.push({ name, amount: amountMinor });
      credit += amountMinor;
      if (flag) achFlags.push(flag);
    }

    // update stats
    if (isWin)   req.session.stats.wins++;
    if (isRoyal) req.session.stats.royalFlushes++;
    if (isWin) achFlags.push('first_win');
    // achievements (values below are in KIBL; converted in addBonus)
    if (isWin && !A.firstWin)                           { addBonus('firstWin', 100,    'first_win'); A.firstWin = true; }
    if (req.session.stats.wins >= 10 && !A['10Wins'])   { addBonus('10Wins',  1000,    'w10');       A['10Wins'] = true; }
    if (req.session.stats.wins >= 25 && !A['25Wins'])   { addBonus('25Wins',  2500,    'w25');       A['25Wins'] = true; }
    if (req.session.stats.wins >= 50 && !A['50Wins'])   { addBonus('50Wins',  5000,    'w50');       A['50Wins'] = true; }
    if (isRoyal && !A.royalFlush)                       { addBonus('royalFlush', 50000,'royal_win'); A.royalFlush = true; }

    // apply to session (minor units) + finalize round
    const cap = BANK_LIMIT > 0 ? BANK_LIMIT : Number.MAX_SAFE_INTEGER;
 req.session.wallet.poker = Math.max(0, toInt(req.session.wallet.poker) + credit);
 req.session.bank = Math.min(
   cap,
   toInt(req.session.wallet.poker) + toInt(req.session.wallet.blackjack)
 );
    req.session.currentHand  = null;
    req.session.deck         = [];
    req.session.hasDrawn     = true;
    req.session.lastDrawAt   = now; // set last draw time once the draw succeeds

 // persist to DB (only to existing tables/columns)
 await getOrCreateUser(req.uid);
 await saveAfterDraw(req.uid, { creditMinor: credit, isWin, isRoyal, flags: achFlags });
 if (typeof awardSeasonPoints === 'function') {
   await awardSeasonPoints(req.uid, pointsEarned);
 }

    // persist session before replying
    await new Promise((resolve, reject) => {
      if (typeof req.session.save === 'function') {
        req.session.save(err => (err ? reject(err) : resolve()));
      } else {
        resolve();
      }
    });
      const round = req.session.round;
let fair = null;

if (round && !round.revealed) {
  fair = {
    handId: round.handId,
    commit: round.commit,
    serverSeed: round.serverSeed,
    clientSeed: round.clientSeed || null,
    algo: "FY shuffle with hash-stream; seed = sha256(serverSeed:clientSeed:handId:deal)"
  };
  req.session.round.revealed = true;

  // best-effort DB reveal
 if (hasDb) {
  try {
    const p = await db();
    await p.query(
      `UPDATE fair_rounds
          SET server_seed = $2, revealed_at = now()
        WHERE hand_id = $1`,
      [round.handId, round.serverSeed]
    );
  } catch (e) { logger.error('fair_rounds reveal', { e: String(e) }); }
}
}


    // respond (minor units; UI divides by 100)
    return res.json({
      ok: true,
      hand,
      result: { ...result, isWin, isRoyal },
      credit,                          // minor units
      bonuses,                         // [{ name, amount (minor) }]
      sessionBalance: req.session.bank,// minor units
      stats: req.session.stats,
      points: pointsEarned,
      fair
    });
  } catch (err) {
    console.error('draw error', err);
    return res.status(500).json({ ok: false, error: 'draw_error' });
  }
});

app.get('/api/fair/:handId', async (req, res) => {
  if (!hasDb) return res.status(503).json({ ok:false, error:'fair_archive_unavailable' });
  try {
    const p = await db();
    const { rows } = await p.query(
      `SELECT hand_id, commit_hash, server_seed, client_seed, created_at, revealed_at
         FROM fair_rounds WHERE hand_id = $1`, [req.params.handId]
    );
    if (!rows.length) return res.status(404).json({ ok:false, error:'not_found' });
    const r = rows[0];
    return res.json({
      ok: true,
      handId: r.hand_id,
      commit: r.commit_hash,
      serverSeed: r.server_seed || null,
      clientSeed: r.client_seed || null,
      createdAt: r.created_at,
      revealedAt: r.revealed_at,
      algo: "deck=shuffleDeterministic(FY, rng=hashStream(sha256(serverSeed:clientSeed:handId:deal)))"
    });
  } catch { return res.status(500).json({ ok:false, error:'server_error' }); }
});

const rewardLimiter = rateLimit({ windowMs: 60 * 1000, max: 12, standardHeaders: true, legacyHeaders: false });
// DAILY REWARD (minor units throughout)
app.post('/api/daily-reward', async (req, res) => {
  const ip = getClientIp(req);
  const uid = req.uid;
  const FAUCET_AMOUNT = 1000 * 100; // 1000 KIBL

  try {
    // 1. Ensure Network Connection
    await ensureRostrum();

    // 2. LAZY LOAD WALLET (The Speed Fix)
    // Only run the slow init/scan if we haven't done it yet.
    if (!cachedServerWallet) {
        console.log('[Wallet] Initializing Hot Wallet for the first time...');
        const secret = process.env.HOT_WALLET_SECRET;
        if (!secret) throw new Error('HOT_WALLET_SECRET missing');

        // Import
        let w;
        if (secret.trim().startsWith('xprv') || secret.trim().startsWith('F6rxz')) {
             w = Wallet.fromXpriv(secret.trim(), 'mainnet');
        } else {
             w = new Wallet(secret, 'mainnet');
        }

        // Scan Chain (The slow part - happens once)
        await w.initialize();
        
        // Ensure Account 2.0 exists
        if (!w.accountStore.getAccount('2.0')) {
             console.log('[Wallet] Creating Account 2.0...');
             await w.newAccount('NEXA'); 
        }
        
        // Save to cache
        cachedServerWallet = w;
        console.log('[Wallet] Initialization Complete. Cached for future requests.');
    }

    // 3. Use the Cached Wallet
    const spendingAccount = cachedServerWallet.accountStore.getAccount('2.0');
    if (!spendingAccount) throw new Error('Hot Wallet Account 2.0 missing');

    // 4. Address Lookup
    let targetAddress = null;
    if (hasDb && uid) {
       const p = await db();
       const { rows } = await p.query('SELECT wallet_addr FROM users WHERE user_id=$1', [uid]);
       targetAddress = rows[0]?.wallet_addr;
    }
    if (!targetAddress) targetAddress = req.session.linkedWallet?.address;
    if (!targetAddress || !/^nexa:/.test(targetAddress)) {
      return res.status(400).json({ ok: false, error: 'Link valid wallet first.' });
    }

    // 5. Build & Send (Instant now)
    console.log(`[Faucet] Sending ${FAUCET_AMOUNT} KIBL to ${targetAddress}...`);
    
    const tx = await cachedServerWallet.newTransaction(spendingAccount)
      .onNetwork('mainnet')
      .sendTo(targetAddress, '546') 
      .sendToToken(targetAddress, String(FAUCET_AMOUNT), process.env.KIBL_GROUP_ID || KIBL_GROUP_HEX)
      .populate()
      .sign()
      .build();

    // Use provider to broadcast
    const txId = await cachedServerWallet.sendTransaction(tx);
    console.log('[Faucet] Success! TxId:', txId);

    // 6. DB Logging
    if (hasDb) {
      const p = await db();
      await p.query(
        `INSERT INTO payouts(user_id, address, amount_kibl, tx_id, ip, type, status) 
         VALUES ($1, $2, $3, $4, $5, 'faucet', 'success')`,
        [uid, targetAddress, FAUCET_AMOUNT/100, txId, ip]
      );
    }

    return res.json({ ok: true, credit: FAUCET_AMOUNT, txId });

  } catch (e) {
    console.error('Faucet Error:', e);
    // If the wallet state got corrupted, clear cache so next try re-initializes
    if (e.message.includes('UTXO') || e.message.includes('input')) {
        cachedServerWallet = null;
    }
    return res.status(500).json({ ok: false, error: e.message });
  }
});
// =================== Payout (minor units throughout) ===================
const usedCaptchaTokens   = new Set();                  // replay defense
setInterval(() => usedCaptchaTokens.clear(), 5 * 60 * 1000);

const lastPayoutByAddress = new Map();                  // per-address cooldown

function looksLikeNexaAddress(addr = '') {
  if (typeof addr !== 'string') return false;
  if (!addr.startsWith('nexa:')) return false;
  if (addr.length > 120) return false;
  return /^[a-z0-9:]+$/i.test(addr);
}

const payoutLimiter = rateLimit({
  windowMs: SIX_HOURS_MS,
  max: 5,
  standardHeaders: true,
  legacyHeaders: false
});
app.use('/api/payout', payoutLimiter);
app.post('/api/payout', payoutLimiter, async (req, res) => {
  try {
    ensureBank(req);
    // 1. Connection Check
    await ensureRostrum();

    // 2. LAZY LOAD WALLET (Reliability Fix)
    if (!cachedServerWallet) {
        console.log('[Payout] Initializing Hot Wallet for the first time...');
        const secret = process.env.HOT_WALLET_SECRET;
        if (!secret) throw new Error('HOT_WALLET_SECRET missing');

        let w;
        // Import based on key type
        if (secret.trim().startsWith('xprv') || secret.trim().startsWith('F6rxz')) {
             w = Wallet.fromXpriv(secret.trim(), 'mainnet');
        } else {
             w = new Wallet(secret, 'mainnet');
        }

        // Scan Chain (Slow, happens once)
        await w.initialize();
        
        // Ensure Account 2.0 exists
        if (!w.accountStore.getAccount('2.0')) {
             console.log('[Payout] Creating Account 2.0...');
             await w.newAccount('NEXA'); 
        }
        
        cachedServerWallet = w;
        console.log('[Payout] Wallet Cached.');
    }

    // 3. Get Account
    const spendingAccount = cachedServerWallet.accountStore.getAccount('2.0');
    if (!spendingAccount) throw new Error('Hot Wallet Account 2.0 missing');

    // (Address Lookup Logic)
    let targetAddress = null;
    if (hasDb && req.uid) {
       const p = await db();
       const { rows } = await p.query('SELECT wallet_addr FROM users WHERE user_id=$1', [req.uid]);
       targetAddress = rows[0]?.wallet_addr;
    }
    if (!targetAddress) targetAddress = req.session.linkedWallet?.address;
    
    if (!targetAddress || !/^nexa:/.test(targetAddress)) {
        return res.status(400).json({ error: 'Please link a wallet first.' });
    }

    const { 'h-captcha-response': hcapStd, hcaptchaToken: hcapCustom } = req.body || {};
    const captchaToken = hcapCustom || hcapStd;
    
    if (!captchaToken) return res.status(400).json({ error: 'Please complete the captcha!' });
    if (usedCaptchaTokens.has(captchaToken)) return res.status(400).json({ error: 'captcha_replay' });
    usedCaptchaTokens.add(captchaToken);

    // Verify Captcha
    let captchaResponse;
    try {
        captchaResponse = await hcaptcha.verify(process.env.HCAPTCHA_SECRET, captchaToken, req.ip);
    } catch(e) {}
    
    if (!captchaResponse?.success) return res.status(400).json({ error: 'Captcha failed' });
    // Check Balance
    const game = (req.body?.game || 'all').toString().toLowerCase();
    const pokerMinor = Math.max(0, Number(req.session.wallet?.poker || 0));
    const bjMinor    = Math.max(0, Number(req.session.wallet?.blackjack || 0));
    const availableMinor = (game === 'poker') ? pokerMinor : (game === 'blackjack') ? bjMinor : (pokerMinor + bjMinor);

    if (!availableMinor || availableMinor <= 0) return res.status(400).json({ error: 'No balance to withdraw' });

    // 4. PREPARE RPC SEND
    const sendMinor = Math.min(availableMinor, MAX_PAYOUT);
    const sendWholeKibl = Math.floor(sendMinor / 100);

    // Deduction logic
    let deductPoker = 0, deductBJ = 0;
    if (game === 'poker') deductPoker = sendMinor;
    else if (game === 'blackjack') deductBJ = sendMinor;
    else {
        deductPoker = Math.min(pokerMinor, sendMinor);
        deductBJ = sendMinor - deductPoker;
    }

  

    
    // - REPLACING RPC CALL WITH SDK
    console.log(`[Payout] Sending ${sendMinor} KIBL to ${targetAddress}`);



    const tx = await cachedServerWallet.newTransaction(spendingAccount)
      .sendToToken(targetAddress, String(sendMinor), process.env.KIBL_GROUP_ID || KIBL_GROUP_HEX)
      .sendTo(targetAddress, '546') // Dust NEXA
      .populate()
      .sign()
      .build();

    const txId = await cachedServerWallet.sendTransaction(tx);
    console.log('[Payout] Broadcast success:', txId);

     req.session.wallet.poker = Math.max(0, pokerMinor - deductPoker);
    req.session.wallet.blackjack = Math.max(0, bjMinor - deductBJ);
    req.session.bank = req.session.wallet.poker + req.session.wallet.blackjack;
    
    // DB Update
    if (hasDb) {
        const p = await db();
        await p.query(`INSERT INTO payouts(address, amount_kibl, tx_id, session_id, ip, status) VALUES ($1,$2,$3,$4,$5,'success')`, 
            [targetAddress, sendWholeKibl, txId, req.sessionID, req.ip]);
            
        if (deductPoker > 0) await p.query('UPDATE user_stats SET bank_minor = GREATEST(bank_minor - $2, 0) WHERE user_id = $1', [req.uid, deductPoker]);
        if (deductBJ > 0) await p.query('UPDATE user_stats_blackjack SET bank_minor = GREATEST(bank_minor - $2, 0) WHERE user_id = $1', [req.uid, deductBJ]);
    }

    return res.json({
        success: true,
        txId,
        sentKIBL: sendWholeKibl,
        remainingKIBL: Math.floor(req.session.bank / 100)
    });

  } catch (error) {
    logger.error('Payout failed', { error: String(error) });
    return res.status(500).json({ error: 'Payout failed. Please try again.' });
  }
});

// =================== BLACKJACK ENGINE (non-wagering, points-driven) ===================

function bjEnsure(req){
  ensureBank(req);
  req.session.bj ||= { round: null, lastActionAt: 0, wins: 0, achievements: {} };
}

function buildCanonicalDeck(){
  const deck = [];
  for (const s of SUITS) for (const r of RANKS) {
    deck.push({ rank: r, suit: s, filename: `${r}_of_${s}.png`, displayText: `${r} of ${s}` });
  }
  return deck;
}
function scoreHand(cards){
  let t=0,a=0;
  for (const c of cards){
    const r=c.rank;
    t += (r==='Ace')? (a++,11) : (r==='King'||r==='Queen'||r==='Jack')?10 : Number(r);
  }
  while (t>21 && a>0){ t-=10; a--; }
  return { total:t, soft:a>0 };
}
function isBlackjack(cards){ return cards.length===2 && scoreHand(cards).total===21; }
function drawCard(round){ return round.deck[round.deckPos++]; }
// OLD
// function canSplit(cards){ return (cards?.length===2) && (cards[0].rank===cards[1].rank); }

// NEW
function canSplit(cards){
  if (!cards || cards.length !== 2) return false;
  const a = cards[0].rank, b = cards[1].rank;
  if (a === b) return true; // exact pair
  const tenVals = new Set(['10','Jack','Queen','King']);
  return tenVals.has(a) && tenVals.has(b); // any two 10-value cards
}

// ===== BLACKJACK RULES (tweakable) =====
const ALLOW_DOUBLE_AFTER_SPLIT = false;     // common default: DAS off
const SPLIT_ACES_ONE_CARD_ONLY = true;      // common default: one card to each Ace, no hits
const NATURAL_BLACKJACK_ONLY = true;        // count BJ only on original 2-card hand (no split)
const DEALER_HITS_SOFT_17 = false;
function playDealer(round){
  while (true){
    const s = scoreHand(round.dealer);
    if (s.total < 17) round.dealer.push(drawCard(round));
    else if (s.total === 17 && s.soft && DEALER_HITS_SOFT_17) round.dealer.push(drawCard(round));
    else break;
  }
}
function snapshotPlayers(r){
  return r.players.map(p=>{
    const s = scoreHand(p.cards);
    return { cards:p.cards, total:s.total, soft:s.soft, doubled:p.doubled, splitFrom:p.splitFrom, result:p.result||null, locked: !!p.lockedAfterOne };
  });
}
function advanceOrSettle(r){
  // next unsettled player hand?
  const next = r.players.findIndex(ph => !ph.settled);
  if (next >= 0){ r.activeIndex = next; return; }

  // all player hands decided (or bust) → dealer resolves if at least one hand not bust
  if (r.players.some(ph => ph.result !== 'bust')) playDealer(r);

  // compare
  const d = scoreHand(r.dealer);
  for (const ph of r.players){
    if (ph.result==='bust'){ ph.settled=true; continue; }
    const pt = scoreHand(ph.cards).total;
    if (NATURAL_BLACKJACK_ONLY ? (isBlackjack(ph.cards) && !ph.splitFrom) : isBlackjack(ph.cards)) {
      ph.result = 'bj';
   } 
   else if (d.total>21) {
         ph.result='win';}
    else if (pt>d.total)       ph.result='win';
    else if (pt===d.total)     ph.result='push';
    else                       ph.result='loss';
    ph.settled=true;
  }
  r.settled = true;
}

// Points/KIBL policy for v1 (safe, non-wagering)
function settleAndRewardBJ(req, r){
  const toInt = v => Math.floor(Number(v)||0);
  const basePts = res => (res==='bj'?2 : res==='win'?1 : 0);

  let riskPenaltyDouble = 0;
  let pointsFloat = 0;
  const results = [];

  const anySplit = r.players.some(ph => ph.splitFrom);
  let splitLosses = 0;

  for (const ph of r.players){
    const base = basePts(ph.result);
    let handPts = base;

    if (ph.doubled){
      if (ph.result==='win' || ph.result==='bj') handPts = base * 2;
      else if (ph.result==='loss' || ph.result==='bust') riskPenaltyDouble += 1;
    }

    if (ph.splitFrom){
      handPts = handPts / 2;                         // each split hand half credit
      if (ph.result==='loss' || ph.result==='bust') splitLosses++;
    }

    results.push({ result: ph.result, basePoints: base, doubled: ph.doubled, splitFrom: ph.splitFrom, pointDelta: handPts });
    pointsFloat += handPts;
  }

  // Optional: if both split hands lost, add a -1 penalty
  let splitPenalty = 0;
  if (anySplit && splitLosses === r.players.length) splitPenalty = 1;

  let points = Math.max(0, Math.floor(pointsFloat) - riskPenaltyDouble - splitPenalty);

  const TOKENS_PER_CREDIT = toInt(process.env.TOKENS_PER_CREDIT || 1);
  const WIN_C = toInt(process.env.BJ_WIN_CREDITS || 3);
  const BJ_C  = toInt(process.env.BJ_BJ_CREDITS  || 6);
  const DD_B  = toInt(process.env.BJ_DOUBLE_BONUS|| 2);
  const SPLIT_PENALTY = toInt(process.env.BJ_SPLIT_WIN_PENALTY || 1);

  let credits = 0;
  for (const ph of r.players){
    if (ph.result === 'bj') {
      credits += BJ_C;                              // natural only (fixed above)
    } else if (ph.result === 'win') {
      let c = WIN_C + (ph.doubled ? DD_B : 0);      // reward risk on doubles
      if (ph.splitFrom) c = Math.max(1, c - SPLIT_PENALTY);
      credits += c;
    }
    // pushes/losses/busts → 0 credits+  
    }
  const creditMinor = toInt(credits * TOKENS_PER_CREDIT * 100);

  // Achievements/bonuses (reuse your poker flags if you want; none by default)
  const bonuses = [];
  return { points, creditMinor, bonuses, results };
}
async function claimAndAwardBJ(
  req,
  round,
  results,
  { points = 0, creditMinor = 0, bonuses = [], natBjCount = 0 } = {}
) {
  // in-process guard
  if (!round || round._rewarded) return { awarded: false, roundMinor: 0, fair: null };

  const toInt = v => Math.floor(Number(v) || 0);
  const extraMinor = toInt((bonuses || []).reduce((s, b) => s + toInt(b.amount || 0), 0));
  const roundMinor = Math.max(0, toInt(creditMinor) + extraMinor);

  // Try to claim exactly once via DB (best-effort).
  // Expect a UNIQUE constraint on bj_awards.hand_id.
  let claimed = true;
  if (hasDb) {
    try {
      const p = await db();
      await getOrCreateUser(req.uid);
      const { rowCount } = await p.query(
        `INSERT INTO bj_awards (hand_id, user_id, points, credit_minor)
         VALUES ($1,$2,$3,$4)
         ON CONFLICT (hand_id) DO NOTHING`,
        [round.handId, req.uid, toInt(points), roundMinor]
      );
      claimed = (rowCount === 1);
    } catch {
      // If bj_awards table is missing or DB hiccups, fall back to in-memory claim.
      claimed = true;
    }
  }
  if (!claimed) return { awarded: false, roundMinor: 0, fair: null };

  // Credit session wallet (minor units)
  const cap = Math.floor(Number(process.env.BANK_CAP ?? 5_000_000));
  req.session.wallet.blackjack = Math.max(0, toInt(req.session.wallet.blackjack || 0) + roundMinor);
  req.session.bank = Math.min(
    cap,
    toInt(req.session.wallet.poker || 0) + toInt(req.session.wallet.blackjack || 0)
  );

  // Stats + achievements + season points
  const bjFlags = [];
  if ((results || []).some(x => x.result === 'win' || x.result === 'bj')) bjFlags.push('first_win');
  if (natBjCount > 0) bjFlags.push('bj_natural');

  await saveStatsFor(req.uid, 'blackjack', {
    creditMinor: roundMinor,
    isWin: roundMinor > 0,
    isRoyal: false,
    flags: bjFlags
  });
  await awardSeasonPointsFor(req.uid, 'blackjack', toInt(points));

  // (best-effort) increment natural BJ counter
  if (natBjCount > 0 && hasDb) {
    try {
      const p = await db();
      await p.query(
        'UPDATE user_stats_blackjack SET blackjacks = blackjacks + $2, last_seen_at = now() WHERE user_id = $1',
        [req.uid, natBjCount]
      );
    } catch {}
  }

  // Best-effort fairness reveal (only once)
  let fair = null;
  if (!round.revealed) {
    fair = {
      handId: round.handId,
      commit: round.commit,
      serverSeed: round.serverSeed,
      clientSeed: round.clientSeed || null,
      algo: "FY+hashStream sha256(serverSeed:clientSeed:handId:bj)"
    };
    round.revealed = true;
    if (hasDb) {
      try {
        const p = await db();
        await p.query(
          'UPDATE fair_rounds SET server_seed=$2, revealed_at=now() WHERE hand_id=$1',
          [round.handId, round.serverSeed]
        );
      } catch {}
    }
  }

  round._rewarded = true;
  return { awarded: true, roundMinor, fair };
}


// ---- Rate limits for BJ actions
const bjStartLimiter  = rateLimit({
  windowMs: 60_000,
  max: 40,
  keyGenerator: (req) => req.uid || req.ip || 'nouid',
  standardHeaders: true,
  legacyHeaders: false
});
const bjActionLimiter = rateLimit({ windowMs: 60_000, max: 80, standardHeaders:true, legacyHeaders:false });


// ---- /api/bj/start
app.post('/api/bj/start', bjStartLimiter, async (req, res) => {
  try{
    const g = gateStartHand(req, "blackjack");                  // reuse IP gate
    if (!g.ok) return res.status(403).json(g);

    bjEnsure(req);

    const clientSeed = (req.body && typeof req.body.clientSeed === 'string') ? req.body.clientSeed.trim() : '';
    const handId     = randomUUID();
    const serverSeed = randHex(32);
    const commitHash = sha256hex(serverSeed);

    // fair_rounds insert (best-effort)
    if (hasDb){
    try{
      const p = await db();
      await getOrCreateUser(req.uid);
      await ensureDisplayId(req.uid);
      await p.query(
        `INSERT INTO fair_rounds(hand_id, user_id, commit_hash, client_seed)
         VALUES ($1,$2,$3,$4)`,
        [handId, req.uid, commitHash, clientSeed || null]
      );
    } catch(e){ logger.error('fair_rounds insert (bj)', { e:String(e) }); }
  }
    // deterministic deck
    const seedString = `${serverSeed}:${clientSeed}:${handId}:bj`;
    const rng  = hashStream(sha256hex(seedString));
    const deck = shuffleDeterministic(buildCanonicalDeck(), rng);

    const round = {
      handId, commit:commitHash, serverSeed, clientSeed, revealed:false,
      deck, deckPos:0,
      dealer: [], players: [{ cards:[], settled:false, result:null, doubled:false, splitFrom:false }],
      activeIndex: 0, settled:false
    };
    // deal P,D,P,D
    round.players[0].cards.push(drawCard(round));
    round.dealer.push(drawCard(round));
    round.players[0].cards.push(drawCard(round));
    round.dealer.push(drawCard(round));
     req.session.bj.round = round;

    const pTotal = scoreHand(round.players[0].cards).total;
    if (pTotal === 21) {
      const h = round.players[0];
      h.result = 'bj';
      h.settled = true;
      advanceOrSettle(round);

      const tally = settleAndRewardBJ(req, round);
      const natBjCount = 1;
      const claim = await claimAndAwardBJ(req, round, tally.results, { ...tally, natBjCount });

      return res.json({
        ok: true,
        fair: { handId, commit: commitHash },
        settled: true,
        dealer: { up: round.dealer[0], hole: round.dealer[1], full: round.dealer },
        players: snapshotPlayers(round),
        results: tally.results,
        credit: claim.awarded ? claim.roundMinor : 0,
        sessionBalance: req.session.bank,
        points: Math.floor(tally.points || 0),
        bonuses: tally.bonuses || [],
        fairReveal: claim.fair || null,
        can: { hit:false, stand:false, double:false, split:false }
      });
    } else {
      // Normal start path
      return res.json({
        ok: true,
        fair: { handId, commit: commitHash },
        settled: false,
        dealer: { up: round.dealer[0], holeHidden: true },
        player: round.players[0].cards,                  // (your client expects `player` on start)
        can: {
          hit: true,
          stand: true,
          double: true,
          split: canSplit(round.players[0].cards)
        }
      });
    }
  } catch (e) {
    logger.error('bj/start', { e: String(e) });
    return res.status(500).json({ ok:false, error:'bj_start_error' });
  }
});

// ---- /api/bj/hit
app.post('/api/bj/hit', bjActionLimiter, async (req, res) => {
  try {
    bjEnsure(req);
    const r = req.session?.bj?.round;
    if (!r) return res.status(400).json({ ok:false, error:'no_round' });

    const h = r.players[r.activeIndex];
    if (!h || h.settled) return res.status(400).json({ ok:false, error:'hand_settled' });

    // Draw a card
    h.cards.push(drawCard(r));
    const s = scoreHand(h.cards);

    if (s.total > 21) {
      h.result = 'bust';
      h.settled = true;
    } else if (s.total === 21) {
      // Auto-stand on 21
      h.settled = true;
    }

    advanceOrSettle(r);

    // If the whole round is now settled, award here (idempotent)
    if (r.settled) {
      if (!r._rewarded) {
        const tally = settleAndRewardBJ(req, r);
        const claim = await claimAndAwardBJ(req, r, tally.results, tally);

        return res.json({
          ok: true,
          dealer: { up:r.dealer[0], hole:r.dealer[1], full:r.dealer },
          players: snapshotPlayers(r),
          activeIndex: r.activeIndex,
          settled: true,
          results: claim.awarded ? tally.results : [],
          credit: claim.awarded ? claim.roundMinor : 0,
          sessionBalance: req.session.bank,
          points: claim.awarded ? Math.floor(tally.points || 0) : 0,
          bonuses: claim.awarded ? (tally.bonuses || []) : [],
          fair: claim.fair || null
        });
      }
      // already rewarded in this process — snapshot only
      return res.json({
        ok: true,
        dealer: { up:r.dealer[0], hole:r.dealer[1], full:r.dealer },
        players: snapshotPlayers(r),
        activeIndex: r.activeIndex,
        settled: true
      });
    }

    // Not settled yet → normal snapshot
    return res.json({
      ok:true,
      dealer: { up:r.dealer[0], holeHidden:true },
      players: snapshotPlayers(r),
      activeIndex: r.activeIndex,
      settled: false
    });
  } catch (e) {
    logger.error('bj/hit', { e:String(e) });
    return res.status(500).json({ ok:false, error:'bj_hit_error' });
  }
});


// ---- /api/bj/stand
app.post('/api/bj/stand', bjActionLimiter, async (req, res) => {
  try {
    bjEnsure(req);
    const r = req.session?.bj?.round;
    if (!r) return res.status(400).json({ ok:false, error:'no_round' });

    // If it's already settled (e.g., natural BJ on the deal) we may still need to award.
    if (r.settled) {
      // If not rewarded yet, do ONE award pass now.
      if (!r._rewarded) {
        const { points, creditMinor, bonuses, results } = settleAndRewardBJ(req, r);

        // ---- Achievements (only the ones you want right now) ----
        const toMinor = kibl => Math.max(0, Math.floor(Number(kibl || 0) * 100));
        let extraMinor = 0;
        const bjBonuses = [];   // [{ name, amount }]
        const bjFlags   = [];   // ['first_win','bj_natural', ...]
        const A = (req.session.bj.achievements ||= {});
        const winsThisRound = results.filter(x => x.result === 'win' || x.result === 'bj').length;
        if (winsThisRound > 0) bjFlags.push('first_win');
        function unlock(flag, name, kibl){
          if (!A[flag]) {
            A[flag] = true;
            const amt = toMinor(kibl);
            if (amt > 0) { extraMinor += amt; bjBonuses.push({ name, amount: amt }); }
            bjFlags.push(flag);
          }
        }
        
      

        // ---- Deposit to blackjack wallet (base + bonus) ----
        const roundMinor = Math.max(0, (creditMinor || 0) + (extraMinor || 0));
        const cap = Math.floor(Number(process.env.BANK_CAP ?? 5_000_000));
        req.session.wallet.blackjack = Math.max(
          0,
          Math.floor(Number(req.session.wallet.blackjack || 0)) + roundMinor
        );
        req.session.bank = Math.min(
          cap,
          Math.floor(Number(req.session.wallet.poker || 0)) +
          Math.floor(Number(req.session.wallet.blackjack || 0))
        );

        // ---- Persist (best-effort) ----
        await getOrCreateUser(req.uid);
        await saveStatsFor(req.uid, 'blackjack', {
          creditMinor: roundMinor,
          isWin: roundMinor > 0,
          isRoyal: false,
          flags: bjFlags
        });
        await awardSeasonPointsFor(req.uid, 'blackjack', points);
        if (natBjCount > 0 && hasDb) {
          try {
            const p = await db();
            await p.query(
              'update user_stats_blackjack set blackjacks = blackjacks + $2, last_seen_at = now() where user_id = $1',
              [req.uid, natBjCount]
            );
          } catch (e) { logger.error('bj blackjacks increment', { e: String(e) }); }
        }
        
        // Reveal fairness (best-effort)
        let fair = null;
        if (!r.revealed) {
          fair = {
            handId: r.handId,
            commit: r.commit,
            serverSeed: r.serverSeed,
            clientSeed: r.clientSeed || null,
            algo: "FY+hashStream sha256(serverSeed:clientSeed:handId:bj)"
          };
          r.revealed = true;
          try {
            const p = await db();
            await p.query(
              `UPDATE fair_rounds SET server_seed=$2, revealed_at=now() WHERE hand_id=$1`,
              [r.handId, r.serverSeed]
            );
          } catch {}
        }
          // First win (per session) + natural BJ
        if (winsThisRound > 0) {
          req.session.bj.wins = (req.session.bj.wins || 0) + winsThisRound;
          unlock('first_win',  'BJ First Win', Number(process.env.BJ_FIRST_WIN_KIBL || 100));
        }
       // Always mark DB 'first_win' when this round has any win (idempotent)
        if (winsThisRound > 0) bjFlags.push('first_win');

        return res.json({
          ok: true,
          settled: true,
          dealer:  { up: r.dealer[0], hole: r.dealer[1], full: r.dealer },
          players: snapshotPlayers(r),
          results,
          credit: roundMinor,
          sessionBalance: req.session.bank,
          points,
          bonuses: [...bonuses, ...bjBonuses],
          fair
        });
      }
    }

    // Not yet settled: finish and award once
    r.players[r.activeIndex].settled = true;
    advanceOrSettle(r);

    if (!r.settled) {
      return res.json({
        ok:true,
        settled:false,
        dealer:{ up:r.dealer[0], holeHidden:true },
        players: snapshotPlayers(r),
        activeIndex: r.activeIndex
      });
    }

    // Now settled -> normal award path
    const { points, creditMinor, bonuses, results } = settleAndRewardBJ(req, r);

    const toMinor = kibl => Math.max(0, Math.floor(Number(kibl || 0) * 100));
    let extraMinor = 0;
    const bjBonuses = [];
    const bjFlags   = [];
    const A = (req.session.bj.achievements ||= {});
    const winsThisRound = results.filter(x => x.result === 'win' || x.result === 'bj').length;
    if (winsThisRound > 0) {
      req.session.bj.wins = (req.session.bj.wins || 0) + winsThisRound;
      if (!A.first_win) { A.first_win = true; const amt = toMinor(Number(process.env.BJ_FIRST_WIN_KIBL || 100)); if (amt) { extraMinor += amt; bjBonuses.push({ name:'BJ First Win', amount:amt }); } bjFlags.push('first_win'); }
    }
    const natBjCount = results.filter(x => x.result === 'bj' && !x.splitFrom).length;
    if (natBjCount > 0 && !A.bj_natural) {
      A.bj_natural = true;
      const amt = toMinor(Number(process.env.BJ_NATURAL_KIBL || 1000));
      if (amt) { extraMinor += amt; bjBonuses.push({ name:'Natural Blackjack', amount:amt }); }
      bjFlags.push('bj_natural');
    }

    const roundMinor = Math.max(0, (creditMinor || 0) + (extraMinor || 0));
    const cap = Math.floor(Number(process.env.BANK_CAP ?? 5_000_000));
    req.session.wallet.blackjack = Math.max(0, Math.floor(Number(req.session.wallet.blackjack || 0)) + roundMinor);
    req.session.bank = Math.min(cap,
      Math.floor(Number(req.session.wallet.poker || 0)) +
      Math.floor(Number(req.session.wallet.blackjack || 0))
    );

    await getOrCreateUser(req.uid);
    await saveStatsFor(req.uid, 'blackjack', {
      creditMinor: roundMinor,
      isWin: roundMinor > 0,
      isRoyal: false,
      flags: bjFlags
    });
    await awardSeasonPointsFor(req.uid, 'blackjack', points);
    if (natBjCount > 0 && hasDb) {
      try {
        const p = await db();
        await p.query(
          'update user_stats_blackjack set blackjacks = blackjacks + $2, last_seen_at = now() where user_id = $1',
          [req.uid, natBjCount]
        );
      } catch (e) { logger.error('bj blackjacks increment', { e: String(e) }); }
    }

    let fair = null;
    if (!r.revealed) {
      fair = {
        handId: r.handId, commit: r.commit,
        serverSeed: r.serverSeed, clientSeed: r.clientSeed || null,
        algo: "FY+hashStream sha256(serverSeed:clientSeed:handId:bj)"
      };
      r.revealed = true;
      try {
        const p = await db();
        await p.query(`UPDATE fair_rounds SET server_seed=$2, revealed_at=now() WHERE hand_id=$1`, [r.handId, r.serverSeed]);
      } catch {}
    }


    return res.json({
      ok:true,
      settled:true,
      dealer:{ up:r.dealer[0], hole:r.dealer[1], full:r.dealer },
      players: snapshotPlayers(r),
      results,
      credit: roundMinor,
      sessionBalance: req.session.bank,
      points,
      bonuses: [...bonuses, ...bjBonuses],
      fair
    });

  } catch (e) {
    logger.error('bj/stand', { e: String(e) });
    return res.status(500).json({ ok:false, error:'bj_stand_error' });
  }
});

// ---- /api/bj/double (first decision only; draw 1, then settle this hand; award once if round ends)
app.post('/api/bj/double', bjActionLimiter, async (req, res) => {
  try {
    bjEnsure(req);
    const r = req.session?.bj?.round;
    if (!r) return res.status(400).json({ ok:false, error:'no_round' });

    // If the round is already settled, just return a stable snapshot (idempotent)
    if (r.settled || r._rewarded) {
      return res.json({
        ok: true,
        dealer: { up:r.dealer[0], hole:r.dealer[1], full:r.dealer },
        players: snapshotPlayers(r),
        activeIndex: r.activeIndex,
        settled: true
      });
    }

    const h = r.players[r.activeIndex];
    if (!h || h.settled)               return res.status(400).json({ ok:false, error:'hand_settled' });
    if (h.doubled)                      return res.status(400).json({ ok:false, error:'already_doubled' });
    if (h.cards.length !== 2)           return res.status(400).json({ ok:false, error:'cant_double' });
    if (h.splitFrom && !ALLOW_DOUBLE_AFTER_SPLIT)
                                        return res.status(400).json({ ok:false, error:'cant_double_after_split' });
    if (h.lockedAfterOne)               return res.status(400).json({ ok:false, error:'cant_double_split_aces' });

    const s0 = scoreHand(h.cards);
    if (s0.total >= 21)                 return res.status(400).json({ ok:false, error:'cant_double_on_21' });

    // Perform the double: mark doubled, draw exactly one card, then hand is done.
    h.doubled = true;
    h.cards.push(drawCard(r));

    const s1 = scoreHand(h.cards);
    if (s1.total > 21) h.result = 'bust';
    h.settled = true;

    // Advance game; may or may not settle the whole round (e.g., split second hand)
    advanceOrSettle(r);

    // If the round just settled, compute tally and award exactly once.
    if (r.settled) {
      const tally = settleAndRewardBJ(req, r);            // { points, creditMinor, bonuses, results }
      const claim = await claimAndAwardBJ(
        req, r, tally.results, { ...tally, natBjCount: 0 } // no natural BJ on a double
      );

      return res.json({
        ok: true,
        dealer: r.settled ? { up:r.dealer[0], hole:r.dealer[1], full:r.dealer } : { up:r.dealer[0], holeHidden:true },
        players: snapshotPlayers(r),
        activeIndex: r.activeIndex,
        settled: true,
        results: claim.awarded ? tally.results : [],
        credit: claim.awarded ? claim.roundMinor : 0,      // minor units
        sessionBalance: req.session.bank,                  // minor units
        points: claim.awarded ? Math.floor(tally.points || 0) : 0,
        bonuses: claim.awarded ? (tally.bonuses || []) : [],
        fair: claim.fair || null
      });
    }

    // Not fully settled yet — return snapshot so player can act on the next hand.
    return res.json({
      ok: true,
      dealer: { up:r.dealer[0], holeHidden:true },
      players: snapshotPlayers(r),
      activeIndex: r.activeIndex,
      settled: false
    });

  } catch (e) {
    logger.error('bj/double', { e:String(e) });
    return res.status(500).json({ ok:false, error:'bj_double_error' });
  }
});


// ---- /api/bj/split (one split v1; exact pair)
app.post('/api/bj/split', bjActionLimiter, (req, res) => {
  try {
    bjEnsure(req);
    const r = req.session?.bj?.round;
    if (!r)               return res.status(400).json({ ok:false, error:'no_round' });
    if (r.settled)        return res.status(400).json({ ok:false, error:'hand_settled' });

    const i = (typeof r.activeIndex === 'number') ? r.activeIndex : 0;
    const h = r.players[i];
    if (!h || h.settled)  return res.status(400).json({ ok:false, error:'hand_settled' });

    // must be a pair, exactly 2 cards
    if (h.cards.length !== 2 || !canSplit(h.cards)) {
      return res.status(400).json({ ok:false, error:'cant_split' });
    }

    // v1 policy: allow only one split total
    if (r.players.some(p => p.splitFrom)) {
      return res.status(400).json({ ok:false, error:'one_split_only' });
    }

    // perform split
    const a = h.cards[0], b = h.cards[1];
    h.cards = [a];
    h.splitFrom = true;
    h.doubled = false;
    delete h.lockedAfterOne;

    const h2 = { cards: [b], settled:false, result:null, doubled:false, splitFrom:true };

    // insert new hand right after the current hand so play order is clear
    r.players.splice(i + 1, 0, h2);

    // draw one card to each split hand (guard against underflow)
    if (r.deckPos + 2 > r.deck.length) {
      return res.status(500).json({ ok:false, error:'deck_underflow' });
    }
    h.cards.push(drawCard(r));
    h2.cards.push(drawCard(r));

    // Split Aces: one card only, no further hits/doubles on either hand
    if (SPLIT_ACES_ONE_CARD_ONLY && a.rank === 'Ace' && b.rank === 'Ace') {
      h.lockedAfterOne  = true;
      h2.lockedAfterOne = true;
    }

    // stay on the first split hand
    r.activeIndex = i;

    return res.json({
      ok: true,
      dealer: { up: r.dealer[0], holeHidden: true },
      players: snapshotPlayers(r),
      activeIndex: r.activeIndex,
      settled: r.settled
    });
  } catch (e) {
    logger.error('bj/split', { e: String(e) });
    return res.status(500).json({ ok:false, error:'bj_split_error' });
  }
});



// =================== Root ===================
app.get('/', (_req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));
// ----- Errors (keep last) -----
app.use((err, req, res, next) => {
  if (err && err.code === 'EBADCSRFTOKEN') {
    return res.status(403).json({ ok: false, error: 'bad_csrf' });
  }
  // Optional: quick visibility while debugging
  console.error('Unhandled error:', err);
  return res.status(500).json({ ok: false, error: 'server_error' });
});


const port = process.env.PORT || 3000;
app.listen(port, () => {
  logger.info(`Server running at http://localhost:${port}`);
  console.log(`Server running at http://localhost:${port}`);
});

