'use strict';
/* Bluvane server: accounts, document store with access rules, realtime (WebSocket).
   Data lives in Supabase Postgres. The server only ever sees encrypted message bodies;
   encryption keys live in browsers. */
require('dotenv').config();
const express = require('express'), http = require('http'), path = require('path'), fs = require('fs'), crypto = require('crypto');
const { WebSocketServer } = require('ws'), { Pool } = require('pg'), bcrypt = require('bcryptjs'), jwt = require('jsonwebtoken');

const PORT = +process.env.PORT || 3000;
const ADMIN_EMAIL = (process.env.ADMIN_EMAIL || '').trim().toLowerCase();

if (!process.env.DATABASE_URL) { console.error('DATABASE_URL is not set. Copy .env.example to .env and fill it in.'); process.exit(1); }
let SECRET = process.env.JWT_SECRET;
if (!SECRET) { SECRET = crypto.randomBytes(48).toString('hex'); console.warn('JWT_SECRET is not set: using a temporary one. Everyone is signed out on every restart.'); }

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.PGSSL === 'off' ? false : { rejectUnauthorized: false },
  max: 10
});
pool.on('error', (e) => console.error('pg pool error:', e.message));
const sql = (t, p) => pool.query(t, p);
const one = async (t, p) => (await sql(t, p)).rows[0] || null;

async function init() {
  await sql(`
    CREATE TABLE IF NOT EXISTS users(
      id TEXT PRIMARY KEY, name TEXT NOT NULL, email TEXT UNIQUE NOT NULL, phone TEXT, phone_norm TEXT,
      pass TEXT NOT NULL, is_admin BOOLEAN DEFAULT FALSE, find_email BOOLEAN DEFAULT TRUE, created BIGINT);
    CREATE INDEX IF NOT EXISTS users_phone ON users(phone_norm);
    CREATE TABLE IF NOT EXISTS docs(path TEXT PRIMARY KEY, parent TEXT NOT NULL, id TEXT NOT NULL, data JSONB NOT NULL);
    CREATE INDEX IF NOT EXISTS docs_parent ON docs(parent);
    -- Lock the tables away from Supabase's public REST API (anon key). This server connects as
    -- the database owner, which bypasses RLS, so it is unaffected.
    ALTER TABLE users ENABLE ROW LEVEL SECURITY;
    ALTER TABLE docs ENABLE ROW LEVEL SECURITY;`);
}

/* ---------- helpers ---------- */
const ah = (fn) => (req, res, next) => Promise.resolve(fn(req, res, next)).catch((e) => { console.error(e); if (!res.headersSent) res.status(500).json({ error: 'server-error' }); });
const phoneNorm = (p) => { const d = String(p || '').replace(/\D/g, ''); return d.length >= 7 && d.length <= 15 ? d.slice(-9) : null; };
const emailOk = (e) => /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(e) && e.length <= 254;
const userById = (id) => one('SELECT * FROM users WHERE id=$1', [id]);
const meJson = (u) => ({ id: u.id, name: u.name, email: u.email, phone: u.phone || '', isOwner: !!u.is_admin, findEmail: u.find_email !== false });
const hits = new Map();
const limited = (key, max, ms) => { const n = Date.now(), a = (hits.get(key) || []).filter(t => n - t < ms); a.push(n); hits.set(key, a); return a.length > max; };
setInterval(() => hits.clear(), 10 * 60 * 1000).unref();
const PATH_RE = /^[A-Za-z0-9_\-.~:@+]+(\/[A-Za-z0-9_\-.~:@+]+)*$/;
const validPath = (p) => typeof p === 'string' && p.length < 400 && PATH_RE.test(p);
const isObj = (v) => v && typeof v === 'object' && !Array.isArray(v);
const merge = (a, b) => { const o = { ...a }; for (const k in b) o[k] = isObj(b[k]) && isObj(o[k]) ? merge(o[k], b[k]) : b[k]; return o; };

const getDoc = async (p) => { const r = await one('SELECT data FROM docs WHERE path=$1', [p]); return r ? r.data : null; };
const putDoc = (p, d) => { const i = p.lastIndexOf('/'); return sql('INSERT INTO docs(path,parent,id,data) VALUES($1,$2,$3,$4::jsonb) ON CONFLICT(path) DO UPDATE SET data=EXCLUDED.data', [p, p.slice(0, i), p.slice(i + 1), JSON.stringify(d)]); };
const delDoc = (p) => sql('DELETE FROM docs WHERE path=$1', [p]);
const listDocs = async (parent) => (await sql('SELECT id,data FROM docs WHERE parent=$1', [parent])).rows.map(r => ({ id: r.id, data: r.data }));

/* ---------- access rules ---------- */
async function can(user, op, p, newData, oldData, cache) {
  const s = p.split('/'), uid = user.id;
  if (s[0] === 'data' && s[1] === 'users') return s[2] === uid;                 // private to its owner
  if (s[0] === 'keys') return op === 'read' || s[1] === uid;                    // public keys: readable by all, writable by owner
  if (s[0] === 'lookup') {                                                      // hashed email/phone -> user id
    if (op === 'read') return true;
    if (op === 'write') return !!newData && newData.uid === uid;
    return !oldData || oldData.uid === uid;
  }
  if (s[0] === 'notices') return op === 'read' || !!user.is_admin;
  if (s[0] === 'chats') {
    let chat;
    if (s.length === 2) chat = oldData;
    else if (cache && cache.has(s[1])) chat = cache.get(s[1]);
    else { chat = await getDoc('chats/' + s[1]); if (cache) cache.set(s[1], chat); }
    if (s.length === 2) {
      if (op === 'read') return !!chat && chat.members.includes(uid);
      if (!chat) return op === 'write' && !!newData && Array.isArray(newData.members) && newData.members.includes(uid);
      if (op === 'delete') return chat.createdBy === uid;
      return chat.members.includes(uid);
    }
    if (!chat || !chat.members.includes(uid) || s[2] !== 'messages' || s.length !== 4) return false;
    if (op === 'read') return true;
    if (op === 'write') return !oldData && !!newData && newData.from === uid;   // messages are immutable
    return chat.createdBy === uid || (!!oldData && (oldData.from === uid || (oldData.exp && oldData.exp <= Date.now())));
  }
  return false;
}
async function runQuery(user, q) {
  const cache = new Map(), all = await listDocs(q.path); let rows = [];
  for (const r of all) if (await can(user, 'read', q.path + '/' + r.id, null, r.data, cache)) rows.push(r);
  for (const [f, op, v] of (q.where || []).slice(0, 4)) {
    rows = rows.filter(r => op === 'array-contains' ? Array.isArray(r.data[f]) && r.data[f].includes(v) : op === '==' ? r.data[f] === v : false);
  }
  if (q.orderBy && /^\w+$/.test(q.orderBy.field)) { const f = q.orderBy.field, d = q.orderBy.dir === 'desc' ? -1 : 1; rows.sort((a, b) => ((a.data[f] > b.data[f]) - (a.data[f] < b.data[f])) * d); }
  return rows.slice(0, Math.min(+q.limit || 500, 500));
}

/* ---------- realtime (single server instance) ---------- */
const clients = new Set();
const send = (ws, m) => { if (ws.readyState === 1) ws.send(JSON.stringify(m)); };
async function pushSnap(c, sid) { const q = c.subs.get(sid); if (!q) return; try { send(c.ws, { type: 'snap', sid, docs: await runQuery(c.user, q) }); } catch (e) { console.error('snap failed:', e.message); } }
function notify(parent) { for (const c of clients) for (const [sid, q] of c.subs) if (q.path === parent) pushSnap(c, sid); }
function broadcastPeers() { const peers = [...clients].map(c => ({ presence: c.presence })); for (const c of clients) send(c.ws, { type: 'peers', peers }); }

/* ---------- app ---------- */
const app = express(); if (process.env.TRUST_PROXY) app.set('trust proxy', 1);
app.disable('x-powered-by');
app.use((req, res, next) => { res.set({ 'X-Content-Type-Options': 'nosniff', 'Referrer-Policy': 'no-referrer', 'X-Frame-Options': 'DENY' }); next(); });
app.use(express.json({ limit: '300kb' }));

/* Serve ONLY the front-end files. (The old `express.static(__dirname)` exposed server.js, .env and the data folder.) */
const pubDir = path.join(__dirname, 'public');
if (fs.existsSync(pubDir)) app.use(express.static(pubDir));
else {
  app.get('/', (q, r) => r.sendFile(path.join(__dirname, 'index.html')));
  for (const f of ['index.html', 'app.js', 'backend.js', 'style.css']) app.get('/' + f, (q, r) => r.sendFile(path.join(__dirname, f)));
}

const auth = ah(async (req, res, next) => {
  let u = null;
  try { u = await userById(jwt.verify((req.headers.authorization || '').replace(/^Bearer /, ''), SECRET).uid); } catch (e) { if (e.name !== 'JsonWebTokenError' && e.name !== 'TokenExpiredError') throw e; }
  if (!u) return res.status(401).json({ error: 'unauthorized' });
  req.user = u; next();
});
const token = (u) => jwt.sign({ uid: u.id }, SECRET, { expiresIn: '30d' });

app.post('/api/register', ah(async (req, res) => {
  if (limited('reg' + req.ip, 10, 60 * 60 * 1000)) return res.status(429).json({ error: 'too-many-requests' });
  const name = String(req.body.name || '').trim().slice(0, 60), email = String(req.body.email || '').trim().toLowerCase(), pw = String(req.body.password || '');
  const phone = String(req.body.phone || '').trim().slice(0, 30);
  if (!name) return res.status(400).json({ error: 'name-required' });
  if (!emailOk(email)) return res.status(400).json({ error: 'bad-email' });
  if (pw.length < 8) return res.status(400).json({ error: 'weak-password' });
  if (phone && !phoneNorm(phone)) return res.status(400).json({ error: 'bad-phone' });
  if (await one('SELECT 1 FROM users WHERE email=$1', [email])) return res.status(409).json({ error: 'email-taken' });
  const first = !(await one('SELECT 1 FROM users LIMIT 1')), id = 'u_' + crypto.randomBytes(10).toString('hex');
  const hash = await bcrypt.hash(pw, 11);
  try {
    await sql('INSERT INTO users(id,name,email,phone,phone_norm,pass,is_admin,created) VALUES($1,$2,$3,$4,$5,$6,$7,$8)',
      [id, name, email, phone, phoneNorm(phone), hash, !!(first || (ADMIN_EMAIL && email === ADMIN_EMAIL)), Date.now()]);
  } catch (e) { if (e.code === '23505') return res.status(409).json({ error: 'email-taken' }); throw e; }
  res.json({ token: token({ id }) });
}));

const PHONE_MATCH = `phone_norm=$1 OR phone=$2
  OR (phone_norm IS NOT NULL AND $3::text LIKE ('%' || phone_norm))
  OR (phone_norm IS NOT NULL AND phone_norm LIKE ('%' || $3::text))
  OR REPLACE(REPLACE(REPLACE(REPLACE(phone, ' ', ''), '-', ''), '(', ''), ')', '') = $3::text`;

app.post('/api/login', ah(async (req, res) => {
  const idn = String(req.body.id || '').trim().toLowerCase(), pw = String(req.body.password || '');
  if (limited('login' + req.ip + idn, 8, 5 * 60 * 1000)) return res.status(429).json({ error: 'too-many-requests' });
  const digits = idn.replace(/\D/g, ''), pNorm = digits.length >= 7 ? digits.slice(-9) : null;
  const u = idn.includes('@')
    ? await one('SELECT * FROM users WHERE LOWER(TRIM(email))=LOWER(TRIM($1)) LIMIT 1', [idn])
    : (pNorm ? await one(`SELECT * FROM users WHERE ${PHONE_MATCH} LIMIT 1`, [pNorm, idn, digits])
             : await one('SELECT * FROM users WHERE phone=$1 LIMIT 1', [idn]));
  if (!u || !(await bcrypt.compare(pw, u.pass))) return res.status(401).json({ error: 'bad-credentials' });
  res.json({ token: token(u) });
}));
app.get('/api/me', auth, (req, res) => res.json(meJson(req.user)));
app.put('/api/me/phone', auth, ah(async (req, res) => {
  const phone = String(req.body.phone || '').trim().slice(0, 30);
  if (phone && !phoneNorm(phone)) return res.status(400).json({ error: 'bad-phone' });
  await sql('UPDATE users SET phone=$1, phone_norm=$2 WHERE id=$3', [phone, phoneNorm(phone), req.user.id]);
  res.json({ phone });
}));
app.put('/api/me/discover', auth, ah(async (req, res) => { await sql('UPDATE users SET find_email=$1 WHERE id=$2', [!!req.body.email, req.user.id]); res.json({ ok: true }); }));
app.post('/api/profiles', auth, ah(async (req, res) => {
  const ids = (Array.isArray(req.body.ids) ? req.body.ids : []).filter(i => typeof i === 'string').slice(0, 200);
  const rows = ids.length ? (await sql('SELECT id,name,email,phone,find_email FROM users WHERE id = ANY($1)', [ids])).rows : [];
  const byId = new Map(rows.map(r => [r.id, r])), out = {};
  for (const id of ids) { const u = byId.get(id); out[id] = { name: u ? u.name : '', email: u && u.find_email !== false ? u.email : '', phone: u ? (u.phone || '') : '' }; }
  res.json(out);
}));
app.get('/api/lookup', auth, ah(async (req, res) => {   // find a person by exact email or phone number
  if (limited('look' + req.user.id, 60, 60 * 1000)) return res.status(429).json({ error: 'too-many-requests' });
  const raw = String(req.query.q || '').trim();
  if (!raw) return res.json({ user: null });
  let u = null;
  if (raw.includes('@')) {
    u = await one('SELECT id, name, email, phone FROM users WHERE LOWER(TRIM(email)) = LOWER(TRIM($1)) AND find_email IS NOT FALSE LIMIT 1', [raw]);
  } else {
    const digits = raw.replace(/\D/g, ''), norm = digits.length >= 7 ? digits.slice(-9) : null;
    u = norm ? await one(`SELECT id, name, email, phone FROM users WHERE ${PHONE_MATCH} LIMIT 1`, [norm, raw, digits])
             : await one('SELECT id, name, email, phone FROM users WHERE phone = $1 LIMIT 1', [raw]);
  }
  res.json({ user: u ? { id: u.id, name: u.name, email: u.email, phone: u.phone || '' } : null });
}));

app.get('/api/doc', auth, ah(async (req, res) => {
  const p = req.query.path; if (!validPath(p)) return res.status(400).json({ error: 'bad-path' });
  const d = await getDoc(p);
  if (!(await can(req.user, 'read', p, null, d))) return d ? res.status(403).json({ error: 'denied' }) : res.json({ exists: false });
  res.json({ exists: !!d, data: d });
}));
app.post('/api/doc', auth, ah(async (req, res) => {
  let { path: p, mode, data } = req.body;
  if (!validPath(p) || !isObj(data) || JSON.stringify(data).length > 250000) return res.status(400).json({ error: 'invalid_argument' });
  let id = null; if (mode === 'add') { id = crypto.randomBytes(10).toString('hex'); p += '/' + id; }
  const segs = p.split('/').length; if (segs % 2) return res.status(400).json({ error: 'invalid_argument' });
  const old = await getDoc(p); let next = data;
  if (mode === 'update') { if (!old) return res.status(404).json({ error: 'not-found' }); next = merge(old, data); }
  if (!(await can(req.user, 'write', p, next, old))) return res.status(403).json({ error: 'denied' });
  await putDoc(p, next); notify(p.slice(0, p.lastIndexOf('/'))); res.json({ id });
}));
app.delete('/api/doc', auth, ah(async (req, res) => {
  const p = req.query.path; if (!validPath(p)) return res.status(400).json({ error: 'bad-path' });
  const old = await getDoc(p); if (!old) return res.json({ ok: true });
  if (!(await can(req.user, 'delete', p, null, old))) return res.status(403).json({ error: 'denied' });
  await delDoc(p); notify(p.slice(0, p.lastIndexOf('/'))); res.json({ ok: true });
}));
app.post('/api/query', auth, ah(async (req, res) => {
  const q = req.body; if (!validPath(q.path) || q.path.split('/').length % 2 === 0) return res.status(400).json({ error: 'bad-path' });
  res.json({ docs: await runQuery(req.user, q) });
}));

const server = http.createServer(app);
const wss = new WebSocketServer({ server, path: '/ws', maxPayload: 64 * 1024 });
wss.on('connection', (ws, req) => {
  let uid; try { uid = jwt.verify(new URL(req.url, 'http://x').searchParams.get('token'), SECRET).uid; } catch { return ws.close(4001); }
  const c = { ws, user: null, subs: new Map(), presence: {} };
  const ready = userById(uid).then((u) => { if (!u) { ws.close(4001); return false; } c.user = u; clients.add(c); broadcastPeers(); return true; })
    .catch((e) => { console.error('ws auth failed:', e.message); ws.close(1011); return false; });
  ws.on('message', async (raw) => {
    if (!(await ready)) return;
    let m; try { m = JSON.parse(raw); } catch { return; }
    if (m.type === 'sub' && m.query && validPath(m.query.path) && c.subs.size < 50) { c.subs.set(String(m.sid), m.query); pushSnap(c, String(m.sid)); }
    else if (m.type === 'unsub') c.subs.delete(String(m.sid));
    else if (m.type === 'presence') { c.presence = m.data && m.data.uid ? { uid: c.user.id } : {}; broadcastPeers(); }
    else if (m.type === 'emit' && m.topic === 'typing' && m.data && validPath(m.data.chat)) {
      const chat = await getDoc('chats/' + m.data.chat); if (!chat || !chat.members.includes(c.user.id)) return;
      for (const o of clients) if (o !== c && chat.members.includes(o.user.id)) send(o.ws, { type: 'event', topic: 'typing', data: { chat: m.data.chat, uid: c.user.id } });
    }
  });
  ws.on('close', () => { clients.delete(c); broadcastPeers(); });
});

init().then(() => server.listen(PORT, () => console.log('Bluvane running on http://localhost:' + PORT + ' (Supabase Postgres)')))
  .catch((e) => { console.error('Could not connect to the database:', e.message); process.exit(1); });
