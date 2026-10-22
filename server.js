'use strict';
/* Bluvane server: accounts, document store with access rules, realtime (WebSocket).
   The server only ever sees encrypted message bodies; encryption keys live in browsers. */
const express = require('express'), http = require('http'), path = require('path'), fs = require('fs'), crypto = require('crypto');
const { WebSocketServer } = require('ws'), Database = require('better-sqlite3'), bcrypt = require('bcryptjs'), jwt = require('jsonwebtoken');

const PORT = +process.env.PORT || 3000, DATA = process.env.DATA_DIR || path.join(__dirname, 'data');
const ADMIN_EMAIL = (process.env.ADMIN_EMAIL || '').trim().toLowerCase();
fs.mkdirSync(DATA, { recursive: true });
const secretFile = path.join(DATA, 'jwt.secret');
const SECRET = process.env.JWT_SECRET || (fs.existsSync(secretFile) ? fs.readFileSync(secretFile, 'utf8') : (() => { const s = crypto.randomBytes(48).toString('hex'); fs.writeFileSync(secretFile, s, { mode: 0o600 }); return s; })());

const db = new Database(path.join(DATA, 'bluvane.db'));
db.pragma('journal_mode = WAL');
db.exec(`
CREATE TABLE IF NOT EXISTS users(id TEXT PRIMARY KEY, name TEXT NOT NULL, email TEXT UNIQUE NOT NULL, phone TEXT, phone_norm TEXT,
  pass TEXT NOT NULL, is_admin INTEGER DEFAULT 0, find_email INTEGER DEFAULT 1, created INTEGER);
CREATE INDEX IF NOT EXISTS users_phone ON users(phone_norm);
CREATE TABLE IF NOT EXISTS docs(path TEXT PRIMARY KEY, parent TEXT NOT NULL, id TEXT NOT NULL, data TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS docs_parent ON docs(parent);`);

/* ---------- helpers ---------- */
const phoneNorm = (p) => { const d = String(p || '').replace(/\D/g, ''); return d.length >= 7 && d.length <= 15 ? d.slice(-9) : null; };
const emailOk = (e) => /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(e) && e.length <= 254;
const userById = (id) => db.prepare('SELECT * FROM users WHERE id=?').get(id);
const meJson = (u) => ({ id: u.id, name: u.name, email: u.email, phone: u.phone || '', isOwner: !!u.is_admin, findEmail: !!u.find_email });
const hits = new Map();
const limited = (key, max, ms) => { const n = Date.now(), a = (hits.get(key) || []).filter(t => n - t < ms); a.push(n); hits.set(key, a); return a.length > max; };
setInterval(() => hits.clear(), 10 * 60 * 1000).unref();
const PATH_RE = /^[A-Za-z0-9_\-.~:@+]+(\/[A-Za-z0-9_\-.~:@+]+)*$/;
const validPath = (p) => typeof p === 'string' && p.length < 400 && PATH_RE.test(p);
const isObj = (v) => v && typeof v === 'object' && !Array.isArray(v);
const merge = (a, b) => { const o = { ...a }; for (const k in b) o[k] = isObj(b[k]) && isObj(o[k]) ? merge(o[k], b[k]) : b[k]; return o; };

const getDoc = (p) => { const r = db.prepare('SELECT data FROM docs WHERE path=?').get(p); return r ? JSON.parse(r.data) : null; };
const putDoc = (p, d) => { const i = p.lastIndexOf('/'); db.prepare('INSERT INTO docs(path,parent,id,data) VALUES(?,?,?,?) ON CONFLICT(path) DO UPDATE SET data=excluded.data').run(p, p.slice(0, i), p.slice(i + 1), JSON.stringify(d)); };
const delDoc = (p) => db.prepare('DELETE FROM docs WHERE path=?').run(p);
const listDocs = (parent) => db.prepare('SELECT id,data FROM docs WHERE parent=?').all(parent).map(r => ({ id: r.id, data: JSON.parse(r.data) }));

/* ---------- access rules ---------- */
function can(user, op, p, newData, oldData) {
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
    const chat = s.length === 2 ? oldData : getDoc('chats/' + s[1]);
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
function runQuery(user, q) {
  let rows = listDocs(q.path).filter(r => can(user, 'read', q.path + '/' + r.id, null, r.data));
  for (const [f, op, v] of (q.where || []).slice(0, 4)) {
    rows = rows.filter(r => op === 'array-contains' ? Array.isArray(r.data[f]) && r.data[f].includes(v) : op === '==' ? r.data[f] === v : false);
  }
  if (q.orderBy && /^\w+$/.test(q.orderBy.field)) { const f = q.orderBy.field, d = q.orderBy.dir === 'desc' ? -1 : 1; rows.sort((a, b) => ((a.data[f] > b.data[f]) - (a.data[f] < b.data[f])) * d); }
  return rows.slice(0, Math.min(+q.limit || 500, 500));
}

/* ---------- realtime ---------- */
const clients = new Set();
const send = (ws, m) => { if (ws.readyState === 1) ws.send(JSON.stringify(m)); };
function pushSnap(c, sid) { const q = c.subs.get(sid); if (!q) return; try { send(c.ws, { type: 'snap', sid, docs: runQuery(c.user, q) }); } catch { /* ignore */ } }
function notify(parent) { for (const c of clients) for (const [sid, q] of c.subs) if (q.path === parent) pushSnap(c, sid); }
function broadcastPeers() { const peers = [...clients].map(c => ({ presence: c.presence })); for (const c of clients) send(c.ws, { type: 'peers', peers }); }

/* ---------- app ---------- */
const app = express(); if (process.env.TRUST_PROXY) app.set('trust proxy', 1);
app.disable('x-powered-by');
app.use((req, res, next) => { res.set({ 'X-Content-Type-Options': 'nosniff', 'Referrer-Policy': 'no-referrer', 'X-Frame-Options': 'DENY' }); next(); });
app.use(express.json({ limit: '300kb' }));
app.use(express.static(path.join(__dirname, 'public')));

const auth = (req, res, next) => {
  try { const u = userById(jwt.verify((req.headers.authorization || '').replace(/^Bearer /, ''), SECRET).uid); if (!u) throw 0; req.user = u; next(); }
  catch { res.status(401).json({ error: 'unauthorized' }); }
};
const token = (u) => jwt.sign({ uid: u.id }, SECRET, { expiresIn: '30d' });

app.post('/api/register', (req, res) => {
  if (limited('reg' + req.ip, 10, 60 * 60 * 1000)) return res.status(429).json({ error: 'too-many-requests' });
  const name = String(req.body.name || '').trim().slice(0, 60), email = String(req.body.email || '').trim().toLowerCase(), pw = String(req.body.password || '');
  const phone = String(req.body.phone || '').trim().slice(0, 30);
  if (!name) return res.status(400).json({ error: 'name-required' });
  if (!emailOk(email)) return res.status(400).json({ error: 'bad-email' });
  if (pw.length < 8) return res.status(400).json({ error: 'weak-password' });
  if (phone && !phoneNorm(phone)) return res.status(400).json({ error: 'bad-phone' });
  if (db.prepare('SELECT 1 FROM users WHERE email=?').get(email)) return res.status(409).json({ error: 'email-taken' });
  const first = !db.prepare('SELECT 1 FROM users LIMIT 1').get(), id = 'u_' + crypto.randomBytes(10).toString('hex');
  db.prepare('INSERT INTO users(id,name,email,phone,phone_norm,pass,is_admin,created) VALUES(?,?,?,?,?,?,?,?)')
    .run(id, name, email, phone, phoneNorm(phone), bcrypt.hashSync(pw, 11), first || (ADMIN_EMAIL && email === ADMIN_EMAIL) ? 1 : 0, Date.now());
  res.json({ token: token(userById(id)) });
});
app.post('/api/login', (req, res) => {
  const idn = String(req.body.id || '').trim().toLowerCase(), pw = String(req.body.password || '');
  if (limited('login' + req.ip + idn, 8, 5 * 60 * 1000)) return res.status(429).json({ error: 'too-many-requests' });
  const u = idn.includes('@') ? db.prepare('SELECT * FROM users WHERE email=?').get(idn) : (phoneNorm(idn) ? db.prepare('SELECT * FROM users WHERE phone_norm=?').get(phoneNorm(idn)) : null);
  if (!u || !bcrypt.compareSync(pw, u.pass)) return res.status(401).json({ error: 'bad-credentials' });
  res.json({ token: token(u) });
});
app.get('/api/me', auth, (req, res) => res.json(meJson(req.user)));
app.put('/api/me/phone', auth, (req, res) => {
  const phone = String(req.body.phone || '').trim().slice(0, 30);
  if (phone && !phoneNorm(phone)) return res.status(400).json({ error: 'bad-phone' });
  db.prepare('UPDATE users SET phone=?, phone_norm=? WHERE id=?').run(phone, phoneNorm(phone), req.user.id);
  res.json({ phone });
});
app.put('/api/me/discover', auth, (req, res) => { db.prepare('UPDATE users SET find_email=? WHERE id=?').run(req.body.email ? 1 : 0, req.user.id); res.json({ ok: true }); });
app.post('/api/profiles', auth, (req, res) => {
  const out = {}; for (const id of (Array.isArray(req.body.ids) ? req.body.ids : []).slice(0, 200)) { const u = typeof id === 'string' && userById(id); out[id] = { name: u ? u.name : '' }; }
  res.json(out);
});
app.get('/api/lookup', auth, (req, res) => {   // find a person by exact email or phone number
  if (limited('look' + req.user.id, 30, 60 * 1000)) return res.status(429).json({ error: 'too-many-requests' });
  const q = String(req.query.q || '').trim(); let u = null;
  if (q.includes('@')) u = db.prepare('SELECT * FROM users WHERE email=? AND find_email=1').get(q.toLowerCase());
  else if (phoneNorm(q)) u = db.prepare('SELECT * FROM users WHERE phone_norm=?').get(phoneNorm(q));
  res.json({ user: u ? { id: u.id, name: u.name } : null });
});

app.get('/api/doc', auth, (req, res) => {
  const p = req.query.path; if (!validPath(p)) return res.status(400).json({ error: 'bad-path' });
  const d = getDoc(p);
  if (!can(req.user, 'read', p, null, d)) return d ? res.status(403).json({ error: 'denied' }) : res.json({ exists: false });
  res.json({ exists: !!d, data: d });
});
app.post('/api/doc', auth, (req, res) => {
  let { path: p, mode, data } = req.body;
  if (!validPath(p) || !isObj(data) || JSON.stringify(data).length > 250000) return res.status(400).json({ error: 'invalid_argument' });
  let id = null; if (mode === 'add') { id = crypto.randomBytes(10).toString('hex'); p += '/' + id; }
  const segs = p.split('/').length; if (segs % 2) return res.status(400).json({ error: 'invalid_argument' });
  const old = getDoc(p); let next = data;
  if (mode === 'update') { if (!old) return res.status(404).json({ error: 'not-found' }); next = merge(old, data); }
  if (!can(req.user, 'write', p, next, old)) return res.status(403).json({ error: 'denied' });
  putDoc(p, next); notify(p.slice(0, p.lastIndexOf('/'))); res.json({ id });
});
app.delete('/api/doc', auth, (req, res) => {
  const p = req.query.path; if (!validPath(p)) return res.status(400).json({ error: 'bad-path' });
  const old = getDoc(p); if (!old) return res.json({ ok: true });
  if (!can(req.user, 'delete', p, null, old)) return res.status(403).json({ error: 'denied' });
  delDoc(p); notify(p.slice(0, p.lastIndexOf('/'))); res.json({ ok: true });
});
app.post('/api/query', auth, (req, res) => {
  const q = req.body; if (!validPath(q.path) || q.path.split('/').length % 2 === 0) return res.status(400).json({ error: 'bad-path' });
  res.json({ docs: runQuery(req.user, q) });
});

const server = http.createServer(app);
const wss = new WebSocketServer({ server, path: '/ws', maxPayload: 64 * 1024 });
wss.on('connection', (ws, req) => {
  let user; try { user = userById(jwt.verify(new URL(req.url, 'http://x').searchParams.get('token'), SECRET).uid); } catch { /* invalid */ }
  if (!user) return ws.close(4001);
  const c = { ws, user, subs: new Map(), presence: {} }; clients.add(c); broadcastPeers();
  ws.on('message', (raw) => {
    let m; try { m = JSON.parse(raw); } catch { return; }
    if (m.type === 'sub' && m.query && validPath(m.query.path) && c.subs.size < 50) { c.subs.set(String(m.sid), m.query); pushSnap(c, String(m.sid)); }
    else if (m.type === 'unsub') c.subs.delete(String(m.sid));
    else if (m.type === 'presence') { c.presence = m.data && m.data.uid ? { uid: user.id } : {}; broadcastPeers(); }
    else if (m.type === 'emit' && m.topic === 'typing' && m.data && validPath(m.data.chat)) {
      const chat = getDoc('chats/' + m.data.chat); if (!chat || !chat.members.includes(user.id)) return;
      for (const o of clients) if (o !== c && chat.members.includes(o.user.id)) send(o.ws, { type: 'event', topic: 'typing', data: { chat: m.data.chat, uid: user.id } });
    }
  });
  ws.on('close', () => { clients.delete(c); broadcastPeers(); });
});
server.listen(PORT, () => console.log('Bluvane running on http://localhost:' + PORT));
