'use strict';
/* =====================================================================
   Bluvane · by Biltech Technologies
   End-to-end encryption happens in the browser (Web Crypto API).
   ===================================================================== */

/*CRYPTO-START*/
const enc = new TextEncoder(), dec = new TextDecoder();
const subtle = crypto.subtle;
const rnd = (n) => crypto.getRandomValues(new Uint8Array(n));
const b64 = (buf) => { const b = new Uint8Array(buf); let s = ''; for (let i = 0; i < b.length; i += 0x8000) s += String.fromCharCode.apply(null, b.subarray(i, i + 0x8000)); return btoa(s); };
const unb64 = (s) => Uint8Array.from(atob(s), c => c.charCodeAt(0));
const EMOJI64 = ['🐶','🐱','🦊','🐻','🐼','🐸','🐵','🦁','🐯','🐮','🐷','🐙','🦋','🐢','🐬','🦉','🌵','🌲','🍎','🍋','🍇','🍉','🍓','🥑','🌽','🍕','🍔','🍩','🍪','⚽','🏀','🎸','🎲','🎯','🚀','🚲','⛵','🌙','⭐','🔥','💧','🌈','🍀','🎈','🎁','🔔','🔑','📚','📝','💡','🧲','🧩','⚓','🏆','🎧','📷','⌚','🎹','🥁','🍒','🥕','🍄','🐝','🦄'];
const ECDH = { name: 'ECDH', namedCurve: 'P-256' };

const C = {
  async genIdentity() {
    const kp = await subtle.generateKey(ECDH, true, ['deriveBits']);
    return { pubJwk: await subtle.exportKey('jwk', kp.publicKey), privJwk: await subtle.exportKey('jwk', kp.privateKey) };
  },
  importPriv(j) { const { kty, crv, x, y, d } = j; return subtle.importKey('jwk', { kty, crv, x, y, d }, ECDH, false, ['deriveBits']); },
  importPub(j) { const { kty, crv, x, y } = j; return subtle.importKey('jwk', { kty, crv, x, y }, ECDH, true, []); },
  // Shared secret between two people -> AES-256-GCM key (ECDH + HKDF, bound to a context string)
  async pairKey(priv, pub, info) {
    const bits = await subtle.deriveBits({ name: 'ECDH', public: pub }, priv, 256);
    const hk = await subtle.importKey('raw', bits, 'HKDF', false, ['deriveKey']);
    return subtle.deriveKey({ name: 'HKDF', hash: 'SHA-256', salt: new Uint8Array(32), info: enc.encode(info) }, hk, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
  },
  // Passphrase vault for the private key
  async passKey(pass, salt, iter) {
    const base = await subtle.importKey('raw', enc.encode(pass), 'PBKDF2', false, ['deriveKey']);
    return subtle.deriveKey({ name: 'PBKDF2', salt, iterations: iter, hash: 'SHA-256' }, base, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
  },
  async sealVault(pass, privJwk) {
    const salt = rnd(16), iv = rnd(12), iter = 310000, k = await C.passKey(pass, salt, iter);
    const ct = await subtle.encrypt({ name: 'AES-GCM', iv }, k, enc.encode(JSON.stringify(privJwk)));
    return { v: 1, salt: b64(salt), iv: b64(iv), iter, ct: b64(ct) };
  },
  async openVault(pass, v) {
    const k = await C.passKey(pass, unb64(v.salt), v.iter);
    return JSON.parse(dec.decode(await subtle.decrypt({ name: 'AES-GCM', iv: unb64(v.iv) }, k, unb64(v.ct))));
  },
  // Messages (the authenticated data binds ciphertext to chat, sender and time)
  async seal(key, obj, aad) {
    const iv = rnd(12);
    const ct = await subtle.encrypt({ name: 'AES-GCM', iv, additionalData: enc.encode(aad) }, key, enc.encode(JSON.stringify(obj)));
    return { iv: b64(iv), ct: b64(ct) };
  },
  async open(key, m, aad) {
    return JSON.parse(dec.decode(await subtle.decrypt({ name: 'AES-GCM', iv: unb64(m.iv), additionalData: enc.encode(aad) }, key, unb64(m.ct))));
  },
  // Group keys: one random AES key per group, wrapped separately for every member
  newGroupKey() { return subtle.generateKey({ name: 'AES-GCM', length: 256 }, true, ['encrypt', 'decrypt']); },
  async wrapGroupKey(gk, myPriv, theirPub, chatId) {
    const raw = await subtle.exportKey('raw', gk), pk = await C.pairKey(myPriv, theirPub, 'bluvane-wrap|' + chatId), iv = rnd(12);
    const ct = await subtle.encrypt({ name: 'AES-GCM', iv, additionalData: enc.encode(chatId) }, pk, raw);
    return { iv: b64(iv), ct: b64(ct) };
  },
  async unwrapGroupKey(w, myPriv, wrapperPub, chatId) {
    const pk = await C.pairKey(myPriv, wrapperPub, 'bluvane-wrap|' + chatId);
    const raw = await subtle.decrypt({ name: 'AES-GCM', iv: unb64(w.iv), additionalData: enc.encode(chatId) }, pk, unb64(w.ct));
    return subtle.importKey('raw', raw, 'AES-GCM', true, ['encrypt', 'decrypt']);
  },
  // Safety code (same for both people) and key identity for pinning
  async fp(pa, pb) {
    const parts = [pa, pb].map(j => j.x + '.' + j.y).sort();
    const h = new Uint8Array(await subtle.digest('SHA-256', enc.encode(parts.join('|'))));
    const emoji = Array.from({ length: 10 }, (_, i) => EMOJI64[h[i] & 63]).join(' ');
    const digits = Array.from({ length: 5 }, (_, i) => String(((h[10 + 2 * i] << 8) | h[11 + 2 * i]) % 100000).padStart(5, '0')).join(' ');
    return { emoji, digits };
  },
  async pubId(j) { return b64(new Uint8Array(await subtle.digest('SHA-256', enc.encode(j.x + '.' + j.y))).slice(0, 12)); }
};
/*CRYPTO-END*/

/* ---------- Small helpers ---------- */
const $ = (s, r = document) => r.querySelector(s);
const sleep = (ms) => new Promise(r => setTimeout(r, ms));
const ls = {
  get(k, d) { try { const v = localStorage.getItem('bv_' + k); return v == null ? d : JSON.parse(v); } catch { return d; } },
  set(k, v) { try { localStorage.setItem('bv_' + k, JSON.stringify(v)); } catch { /* storage unavailable */ } }
};
const idb = {
  open() { return new Promise((res, rej) => { const r = indexedDB.open('bluvane', 1); r.onupgradeneeded = () => r.result.createObjectStore('k'); r.onsuccess = () => res(r.result); r.onerror = () => rej(r.error); }); },
  async run(mode, fn) { try { const d = await this.open(); return await new Promise((res, rej) => { const q = fn(d.transaction('k', mode).objectStore('k')); q.onsuccess = () => res(q.result); q.onerror = () => rej(q.error); }); } catch { return undefined; } },
  get(k) { return this.run('readonly', s => s.get(k)); },
  set(k, v) { return this.run('readwrite', s => s.put(v, k)); },
  del(k) { return this.run('readwrite', s => s.delete(k)); }
};
function h(tag, attrs, ...kids) {
  const el = document.createElement(tag);
  for (const k in (attrs || {})) {
    const v = attrs[k]; if (v == null || v === false) continue;
    if (k === 'class') el.className = v;
    else if (k === 'style') el.style.cssText = v;
    else if (k.startsWith('on')) el.addEventListener(k.slice(2), v);
    else if (k === 'value' || k === 'checked' || k === 'disabled') el[k] = v;
    else el.setAttribute(k, v === true ? '' : v);
  }
  for (const kid of kids.flat()) { if (kid == null || kid === false) continue; el.append(kid.nodeType ? kid : document.createTextNode(String(kid))); }
  return el;
}
const ICONS = {
  lock: '<rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/>',
  send: '<path d="m22 2-7 20-4-9-9-4Z"/><path d="M22 2 11 13"/>',
  plus: '<path d="M12 5v14M5 12h14"/>',
  users: '<path d="M16 21v-2a4 4 0 0 0-4-4H6a4 4 0 0 0-4 4v2"/><circle cx="9" cy="7" r="4"/><path d="M22 21v-2a4 4 0 0 0-3-3.87M16 3.13a4 4 0 0 1 0 7.75"/>',
  'user-plus': '<path d="M16 21v-2a4 4 0 0 0-4-4H6a4 4 0 0 0-4 4v2"/><circle cx="9" cy="7" r="4"/><path d="M19 8v6M22 11h-6"/>',
  sliders: '<path d="M4 21v-7M4 10V3M12 21v-9M12 8V3M20 21v-5M20 12V3M1 14h6M9 8h6M17 16h6"/>',
  sun: '<circle cx="12" cy="12" r="4"/><path d="M12 2v2M12 20v2M4.93 4.93l1.41 1.41M17.66 17.66l1.41 1.41M2 12h2M20 12h2M6.34 17.66l-1.41 1.41M19.07 4.93l-1.41 1.41"/>',
  moon: '<path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z"/>',
  'shield-check': '<path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><path d="m9 12 2 2 4-4"/>',
  flame: '<path d="M8.5 14.5A2.5 2.5 0 0 0 11 12c0-1.38-.5-2-1-3-1.07-2.14-.22-4.05 2-6 .5 2.5 2 4.9 4 6.5 2 1.6 3 3.5 3 5.5a7 7 0 1 1-14 0c0-1.15.43-2.29 1-3a2.5 2.5 0 0 0 2.5 2.5z"/>',
  clock: '<circle cx="12" cy="12" r="10"/><path d="M12 6v6l4 2"/>',
  'arrow-left': '<path d="m12 19-7-7 7-7M19 12H5"/>',
  x: '<path d="M18 6 6 18M6 6l12 12"/>',
  check: '<path d="M20 6 9 17l-5-5"/>',
  search: '<circle cx="11" cy="11" r="8"/><path d="m21 21-4.3-4.3"/>',
  megaphone: '<path d="m3 11 18-5v12L3 14v-3z"/><path d="M11.6 16.8a3 3 0 1 1-5.8-1.6"/>',
  trash: '<path d="M3 6h18M8 6V4h8v2M19 6l-1 14H6L5 6"/>',
  key: '<circle cx="7.5" cy="15.5" r="5.5"/><path d="m21 2-9.6 9.6M15.5 7.5l3 3L22 7l-3-3"/>',
  refresh: '<path d="M21 12a9 9 0 0 1-15.5 6.2L3 16M3 12a9 9 0 0 1 15.5-6.2L21 8M21 3v5h-5M3 21v-5h5"/>'
};
function ic(name, size = 20) {
  const s = document.createElement('span'); s.className = 'ic'; s.style.width = s.style.height = size + 'px';
  s.innerHTML = `<svg viewBox="0 0 24 24" width="${size}" height="${size}" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">${ICONS[name] || ''}</svg>`;
  return s;
}
let logoN = 0;
function logo(size = 44) {
  const id = 'lg' + (logoN++), s = document.createElement('span'); s.className = 'ic logo';
  s.innerHTML = `<svg viewBox="0 0 48 48" width="${size}" height="${size}" role="img" aria-label="Bluvane logo"><defs><linearGradient id="${id}" x1="0" y1="0" x2="1" y2="1"><stop offset="0" stop-color="#22D3EE"/><stop offset="1" stop-color="#2563EB"/></linearGradient></defs><rect width="48" height="48" rx="14" fill="url(#${id})"/><path d="M13 18a5 5 0 0 1 5-5h12a5 5 0 0 1 5 5v8a5 5 0 0 1-5 5h-7l-7 5v-5.4A5 5 0 0 1 13 26z" fill="#fff"/><circle cx="24" cy="20.5" r="2.7" fill="#2563EB"/><rect x="23" y="21.5" width="2" height="5.5" rx="1" fill="#2563EB"/></svg>`;
  return s;
}
const fmtTime = (ts) => new Date(ts).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
const fmtDay = (ts) => { const d = new Date(ts), n = new Date(), y = new Date(Date.now() - 864e5); if (d.toDateString() === n.toDateString()) return 'Today'; if (d.toDateString() === y.toDateString()) return 'Yesterday'; return d.toLocaleDateString([], { weekday: 'short', day: 'numeric', month: 'short' }); };
const fmtRemain = (ms) => { const s = Math.ceil(Math.max(0, ms) / 1000); if (s < 60) return s + 's'; if (s < 3600) return Math.floor(s / 60) + 'm ' + String(s % 60).padStart(2, '0') + 's'; if (s < 86400) return Math.floor(s / 3600) + 'h ' + Math.floor((s % 3600) / 60) + 'm'; return Math.floor(s / 86400) + 'd ' + Math.floor((s % 86400) / 3600) + 'h'; };
const mmss = (ms) => { const s = Math.max(0, Math.ceil(ms / 1000)); return Math.floor(s / 60) + ':' + String(s % 60).padStart(2, '0'); };
const initials = (n) => { const p = String(n || '?').trim().split(/\s+/); return ((p[0] || '?')[0] + (p.length > 1 ? p[p.length - 1][0] : '')).toUpperCase(); };
const hueBg = (id) => { let x = 0; for (const c of String(id)) x = (x * 31 + c.charCodeAt(0)) >>> 0; const hue = 190 + (x % 60); return `linear-gradient(135deg,hsl(${hue} 80% 46%),hsl(${(hue + 28) % 360} 75% 38%))`; };
const hueText = (id) => { let x = 0; for (const c of String(id)) x = (x * 31 + c.charCodeAt(0)) >>> 0; return `hsl(${190 + (x % 60)} 70% 52%)`; };
function avatar(id, label, size = 42, online = false, emoji = '') {
  const el = h('div', { class: 'av', style: `width:${size}px;height:${size}px;font-size:${Math.round(size * .38)}px;background:${hueBg(id)}` }, emoji || initials(label));
  if (online) el.append(h('i', { class: 'dot' }));
  return el;
}
const sanitizeId = (s) => String(s).replace(/[^A-Za-z0-9_\-.~:@+]/g, '~');
const hex = (n) => Array.from(rnd(n), b => b.toString(16).padStart(2, '0')).join('');
function toast(msg) { const t = h('div', { class: 'toast' }, msg); $('#toasts').append(t); setTimeout(() => t.remove(), 3600); }
function armBtn(btn, armedLabel, action) {
  const orig = btn.textContent; let armed = false, timer;
  btn.addEventListener('click', () => {
    if (!armed) { armed = true; btn.textContent = armedLabel; timer = setTimeout(() => { armed = false; btn.textContent = orig; }, 3500); }
    else { clearTimeout(timer); armed = false; btn.textContent = orig; action(); }
  });
}
function openModal(title, body, opts = {}) {
  const ov = h('div', { class: 'overlay', role: 'dialog', 'aria-modal': 'true', 'aria-label': title });
  const close = () => { ov.remove(); document.removeEventListener('keydown', esc); if (opts.onClose) opts.onClose(); };
  const esc = (e) => { if (e.key === 'Escape') close(); };
  ov.append(h('div', { class: 'sheet' }, h('div', { class: 'sheet-head' }, h('h3', null, title), h('button', { class: 'icon-btn', 'aria-label': 'Close', onclick: close }, ic('x'))), body));
  ov.addEventListener('mousedown', (e) => { if (e.target === ov) close(); });
  document.addEventListener('keydown', esc); document.body.append(ov);
  return close;
}

/* ---------- App state ---------- */
const S = {
  uid: null, me: null, isOwner: false, canWrite: true, priv: null, pubJwk: null,
  keys: new Map(), chats: new Map(), virtual: new Map(), notices: [],
  names: new Map(), activeId: null, tab: 'chats', search: '', unsubs: [], msgUnsub: null,
  msgDocs: [], plain: new Map(), keyCache: new Map(), snapTok: 0, online: new Set(), typing: new Map(),
  draft: { ttl: 0, seal: 0 }, dmInfo: null, read: ls.get('read', {}), lastNoticeSeen: ls.get('noticeSeen', 0),
  contacts: new Map(), prof: null
};
let DB = null, USER = null, ROOM = null, tickTimer = null;

/* ---------- Theme ---------- */
const mqDark = window.matchMedia('(prefers-color-scheme: dark)');
function effectiveTheme() { const t = ls.get('theme', 'system'); return t === 'system' ? (mqDark.matches ? 'dark' : 'light') : t; }
function applyTheme() {
  const t = ls.get('theme', 'system'), r = document.documentElement;
  if (t === 'system') r.removeAttribute('data-theme'); else r.setAttribute('data-theme', t);
  const btn = $('#btnTheme'); if (btn) btn.replaceChildren(ic(effectiveTheme() === 'dark' ? 'sun' : 'moon'));
}
mqDark.addEventListener && mqDark.addEventListener('change', applyTheme);

/* ---------- Names ---------- */
const wantNames = new Set(); let nameTimer = null;
async function resolveNames(ids) {
  const need = [...new Set(ids)].filter(i => i && !S.names.has(i));
  if (!need.length) return;
  try { const ps = await USER.profiles(need); for (const id of need) { const p = ps[id]; S.names.set(id, (p && p.name) || 'Someone'); } }
  catch { for (const id of need) S.names.set(id, 'Someone'); }
}
function nameOf(id) {
  if (id === S.uid) return 'You';
  if (!S.names.has(id)) {
    wantNames.add(id);
    if (!nameTimer) nameTimer = setTimeout(async () => { nameTimer = null; const ids = [...wantNames]; wantNames.clear(); await resolveNames(ids); renderLists(); renderHeader(); renderMessages(); }, 40);
    return '…';
  }
  return S.names.get(id);
}

/* ---------- Contacts: find people by email or phone ---------- */
// Emails and phone numbers are never stored in the shared directory. Only a one-way hash
// points to a user id, so a contact can be found by someone who already knows the address.
function parseHandle(raw) {
  const s = String(raw || '').trim(); if (!s) return null;
  if (s.includes('@')) { if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(s)) return null; return { kind: 'email', norm: s.toLowerCase() }; }
  if (!/^[+\d\s().\-]+$/.test(s)) return null;
  const d = s.replace(/\D/g, ''); if (d.length < 7 || d.length > 15) return null;
  return { kind: 'phone', norm: d.slice(-9) }; // last 9 digits: matches +256772000000 and 0772000000
}
async function handleHash(kind, norm) {
  const hh = new Uint8Array(await subtle.digest('SHA-256', enc.encode('bluvane-lookup|' + kind + '|' + norm)));
  return Array.from(hh.slice(0, 16), b => b.toString(16).padStart(2, '0')).join('');
}
async function findByHandle(raw) {
  const p = parseHandle(raw); if (!p) return { error: true };
  const hid = await handleHash(p.kind, p.norm);
  try { const d = await DB.doc('lookup/' + hid).get(); if (d.exists) { const uid = d.data().uid; if (uid && S.keys.has(uid)) return { id: uid, kind: p.kind }; } } catch { /* fall through */ }
  try {
    const u = await USER.lookup(String(raw).trim());
    if (u) { S.names.set(u.id, u.name || 'Someone'); if (S.keys.has(u.id)) return { id: u.id, kind: p.kind }; return { id: null, kind: p.kind, pending: u.name || 'They' }; }
  } catch { /* ignore */ }
  return { id: null, kind: p.kind };
}
async function loadContacts() {
  try { const d = await DB.doc('data/users/' + S.uid + '/contacts').get(); S.contacts = new Map(Object.entries(d.exists ? (d.data().ids || {}) : {})); } catch { /* keep current */ }
  renderLists();
}
const saveContacts = () => DB.doc('data/users/' + S.uid + '/contacts').set({ ids: Object.fromEntries(S.contacts) });
async function addContact(id) {
  if (id === S.uid || S.contacts.has(id)) return true;
  S.contacts.set(id, Date.now()); renderLists();
  try { await saveContacts(); return true; } catch { S.contacts.delete(id); renderLists(); toast('Could not save contact.'); return false; }
}
async function removeContact(id) {
  const ts = S.contacts.get(id); S.contacts.delete(id); renderLists();
  try { await saveContacts(); toast('Contact removed.'); } catch { S.contacts.set(id, ts); renderLists(); toast('Could not remove contact.'); }
}
async function loadProfile() {
  if (S.prof) return S.prof;
  try { const d = await DB.doc('data/users/' + S.uid + '/profile').get(); S.prof = d.exists ? d.data() : {}; } catch { S.prof = {}; }
  return S.prof;
}
const saveProfile = () => DB.doc('data/users/' + S.uid + '/profile').set(S.prof);
async function ensureLookup(hid) {
  const d = await DB.doc('lookup/' + hid).get();
  if (!d.exists || d.data().uid !== S.uid) await DB.doc('lookup/' + hid).set({ uid: S.uid, ts: Date.now() });
}
async function dropLookup(hid) {
  if (!hid) return;
  try { const d = await DB.doc('lookup/' + hid).get(); if (d.exists && d.data().uid === S.uid) await DB.doc('lookup/' + hid).delete(); } catch { /* ignore */ }
}
async function savePhone(raw) {
  const prof = await loadProfile(), text = String(raw || '').trim();
  if (prof.phoneHash) await dropLookup(prof.phoneHash);
  if (text) {
    const p = parseHandle(text); if (!p || p.kind !== 'phone') throw new Error('bad-phone');
    await USER.setPhone(text); prof.phoneHash = await handleHash('phone', p.norm); prof.phone = text; await ensureLookup(prof.phoneHash);
  } else { await USER.setPhone(''); prof.phoneHash = null; prof.phone = ''; }
  await saveProfile();
}
async function setEmailVisible(on) {
  await USER.setDiscoverable(on); const prof = await loadProfile(); prof.hideEmail = !on; await saveProfile(); await syncLookup();
}
async function syncLookup() {
  if (!S.canWrite) return;
  try {
    const prof = await loadProfile(), em = String(S.me.email || '').trim().toLowerCase();
    if (em && !prof.hideEmail) {
      const hid = await handleHash('email', em);
      if (prof.emailHash && prof.emailHash !== hid) await dropLookup(prof.emailHash);
      await ensureLookup(hid);
      if (prof.emailHash !== hid) { prof.emailHash = hid; await saveProfile(); }
    } else if (prof.emailHash) { await dropLookup(prof.emailHash); prof.emailHash = null; await saveProfile(); }
    if (prof.phoneHash) await ensureLookup(prof.phoneHash);
  } catch { /* lookup is best-effort */ }
}

/* ---------- Chat helpers ---------- */
const dmId = (a, b) => 'dm_' + sanitizeId([a, b].sort().join('_'));
const chatById = (id) => S.chats.get(id) || S.virtual.get(id) || null;
const dmPeer = (c) => c.members.find(m => m !== S.uid) || S.uid;
function chatTitle(c) { if (c.type === 'group') return c.name || 'Group'; const p = dmPeer(c); return p === S.uid ? 'Notes to self' : nameOf(p); }
const isUnread = (c) => c.lastBy && c.lastBy !== S.uid && (c.lastTs || 0) > (S.read[c.id] || 0);
async function pubOf(uid) { const e = S.keys.get(uid); if (!e) return null; if (!e.ck) e.ck = await C.importPub(e.pub); return e.ck; }
async function chatKey(chat) {
  if (S.keyCache.has(chat.id)) return S.keyCache.get(chat.id);
  let key;
  if (chat.type === 'dm') {
    const peer = dmPeer(chat), pub = peer === S.uid ? await C.importPub(S.pubJwk) : await pubOf(peer);
    if (!pub) throw new Error('peer-no-key');
    key = await C.pairKey(S.priv, pub, 'bluvane-dm|' + chat.id);
  } else {
    const w = chat.wk && chat.wk[S.uid]; if (!w) throw new Error('no-wrap');
    const by = w.by === S.uid ? await C.importPub(S.pubJwk) : await pubOf(w.by);
    if (!by) throw new Error('wrapper-no-key');
    key = await C.unwrapGroupKey(w, S.priv, by, chat.id);
  }
  S.keyCache.set(chat.id, key); return key;
}

/* ---------- Gate screens ---------- */
function showGate(...kids) { const g = $('#gate'); g.hidden = false; g.replaceChildren(...kids); }
function hideGate() { const g = $('#gate'); g.hidden = true; g.replaceChildren(); }
function gateCard(...kids) { return h('div', { class: 'card' }, ...kids); }
function blockedCard(title, text) { return gateCard(logo(52), h('h1', null, title), h('p', { class: 'muted' }, text)); }

function showOnboarding(reset = false) {
  const p1 = h('input', { class: 'field', type: 'password', placeholder: 'Create a passphrase (8+ characters)', autocomplete: 'new-password', 'aria-label': 'Passphrase' });
  const p2 = h('input', { class: 'field', type: 'password', placeholder: 'Repeat passphrase', autocomplete: 'new-password', 'aria-label': 'Repeat passphrase' });
  const ph = h('input', { class: 'field', type: 'tel', placeholder: '+256 772 000 000', autocomplete: 'tel', 'aria-label': 'Phone number (optional)', value: (S.prof && S.prof.phone) || S.me.phone || '' });
  const rem = h('input', { type: 'checkbox', checked: true, id: 'remDev' });
  const err = h('div', { class: 'err' }), btn = h('button', { class: 'btn block' }, ic('key', 18), reset ? 'Create new identity' : 'Create my secure identity');
  const go = async () => {
    err.textContent = '';
    if (p1.value.length < 8) { err.textContent = 'Use at least 8 characters.'; return; }
    if (p1.value !== p2.value) { err.textContent = 'The two passphrases do not match.'; return; }
    if (ph.value.trim() && !parseHandle(ph.value)) { err.textContent = 'That phone number does not look right. Leave it empty to skip.'; return; }
    btn.disabled = true; btn.lastChild.textContent = 'Generating keys…';
    try { await createIdentity(p1.value, rem.checked); try { if (ph.value.trim()) await savePhone(ph.value); } catch { toast('Phone number not saved. Add it later in Settings.'); } await enterApp(); }
    catch (e) {
      btn.disabled = false; btn.lastChild.textContent = 'Create my secure identity';
      err.textContent = (e && e.code === 'invalid_argument') ? 'You have view-only access. Ask the owner to make you a Contributor, then reload.' : 'Could not save your keys. Please try again.';
    }
  };
  btn.addEventListener('click', go); ph.addEventListener('keydown', e => { if (e.key === 'Enter') go(); });
  showGate(gateCard(
    logo(52),
    h('h1', null, reset ? 'Start a fresh identity' : `Welcome, ${(S.me.name || 'friend').split(' ')[0]}`),
    h('p', { class: 'muted', style: 'margin:0' }, reset ? 'Your old messages will no longer be readable.' : 'Let’s create your private key. It takes a few seconds.'),
    h('ul', null,
      h('li', null, ic('lock', 18), 'Messages are locked on your device before they are sent.'),
      h('li', null, ic('key', 18), 'Your passphrase protects your key. Nobody, including Biltech, can reset it.'),
      h('li', null, ic('shield-check', 18), 'Verify friends with a short emoji safety code.')),
    h('label', { class: 'lbl' }, 'Passphrase'), p1, h('div', { style: 'height:8px' }), p2,
    h('label', { class: 'lbl' }, 'Phone number (optional)'), ph,
    h('div', { class: 'tiny muted', style: 'margin-top:6px' }, 'Lets friends who know your number find and add you. Your email works automatically.'),
    h('label', { class: 'check' }, rem, 'Keep me unlocked on this device'),
    btn, err));
  p1.focus();
}
function showUnlock(vault, pub) {
  const pass = h('input', { class: 'field', type: 'password', placeholder: 'Your passphrase', autocomplete: 'current-password', 'aria-label': 'Passphrase' });
  const rem = h('input', { type: 'checkbox', checked: true });
  const err = h('div', { class: 'err' }), btn = h('button', { class: 'btn block' }, ic('lock', 18), 'Unlock');
  const reset = h('button', { class: 'link' }, 'Forgot passphrase? Start fresh');
  const go = async () => {
    err.textContent = ''; btn.disabled = true;
    try {
      const jwk = await C.openVault(pass.value, vault);
      if (jwk.x !== pub.x || jwk.y !== pub.y) throw new Error('mismatch');
      S.priv = await C.importPriv(jwk); S.pubJwk = pub;
      if (rem.checked) await idb.set('id:' + S.uid, { priv: S.priv, x: pub.x, y: pub.y });
      await enterApp();
    } catch { btn.disabled = false; err.textContent = 'That passphrase did not work.'; pass.select(); }
  };
  btn.addEventListener('click', go); pass.addEventListener('keydown', e => { if (e.key === 'Enter') go(); });
  reset.addEventListener('click', () => showOnboarding(true));
  showGate(gateCard(logo(52), h('h1', null, `Welcome back, ${(S.me.name || 'friend').split(' ')[0]}`),
    h('p', { class: 'muted', style: 'margin:0 0 12px' }, 'Enter your passphrase to unlock your chats.'),
    pass, h('label', { class: 'check' }, rem, 'Keep me unlocked on this device'), btn, err, reset));
  pass.focus();
}

async function createIdentity(pass, remember) {
  const { pubJwk, privJwk } = await C.genIdentity();
  const pub = { kty: pubJwk.kty, crv: pubJwk.crv, x: pubJwk.x, y: pubJwk.y };
  await DB.doc('data/users/' + S.uid + '/vault').set(await C.sealVault(pass, privJwk));
  await DB.doc('keys/' + S.uid).set({ pub, ts: Date.now() });
  S.priv = await C.importPriv(privJwk); S.pubJwk = pub; S.keyCache.clear(); S.plain.clear();
  if (remember) await idb.set('id:' + S.uid, { priv: S.priv, x: pub.x, y: pub.y }); else await idb.del('id:' + S.uid);
}

/* ---------- Boot ---------- */
async function boot() {
  buildStaticIcons(); applyTheme();
  showGate(gateCard(logo(52), h('h1', null, 'Bluvane'), h('p', { class: 'muted' }, 'Connecting securely…')));
  if (!window.crypto || !crypto.subtle) return showGate(blockedCard('Secure context needed', 'This browser does not offer the encryption tools Bluvane relies on.'));
  if (!window.claude || !window.claude.use) return showGate(blockedCard('Could not start Bluvane', 'The sign-in script did not load. Please reload the page.'));
  let user, db;
  try { [user, db] = await Promise.all([claude.use('user'), claude.use('db')]); } catch { /* fall through */ }
  if (!user || !db) return showGate(blockedCard('Sign in to chat', 'We could not connect to the Bluvane server. Please check your connection and reload.'));
  USER = user; DB = db;
  S.uid = await user.id();
  if (!S.uid) return showGate(blockedCard('Sign in to chat', 'We could not identify your account. Please sign in and reload.'));
  S.me = await user.me(); S.isOwner = await user.isOwner();
  const cw = await user.can('data.write'); S.canWrite = cw !== false;
  S.names.set(S.uid, S.me.name || 'You');
  try {
    const [kd, vd] = await Promise.all([DB.doc('keys/' + S.uid).get(), DB.doc('data/users/' + S.uid + '/vault').get()]);
    if (kd.exists && vd.exists) {
      const pub = kd.data().pub, rec = await idb.get('id:' + S.uid);
      if (rec && rec.priv && rec.x === pub.x && rec.y === pub.y) { S.priv = rec.priv; S.pubJwk = pub; return enterApp(); }
      return showUnlock(vd.data(), pub);
    }
    showOnboarding();
  } catch (e) { showGate(blockedCard('Something went wrong', 'We could not reach the secure store. Please reload and try again.')); }
}

async function enterApp() {
  hideGate(); $('#app').hidden = false;
  $('#btnAdmin').hidden = !S.isOwner;
  startSubs(); startRoom(); applyShield(); renderAll();
  loadContacts(); syncLookup();
  clearInterval(tickTimer); tickTimer = setInterval(tick, 1000);
}
function stopSubs() { S.unsubs.forEach(u => { try { u(); } catch { /* ignore */ } }); S.unsubs = []; if (S.msgUnsub) { S.msgUnsub(); S.msgUnsub = null; } }
async function lockNow() {
  stopSubs(); clearInterval(tickTimer); await idb.del('id:' + S.uid);
  S.priv = null; S.keyCache.clear(); S.plain.clear(); S.msgDocs = []; S.activeId = null; S.chats.clear(); S.keys.clear(); S.contacts = new Map(); S.prof = null;
  $('#app').hidden = true; $('#msgs').replaceChildren(); $('#list').replaceChildren();
  boot();
}

/* ---------- Subscriptions ---------- */
const subErr = (what) => (e) => { if (e && e.code !== 'revoked') toast('Live updates paused (' + what + ')'); };
function startSubs() {
  stopSubs();
  S.unsubs.push(DB.collection('keys').onSnapshot(snap => {
    const next = new Map();
    for (const d of snap.docs) {
      const pub = d.data().pub, old = S.keys.get(d.id);
      if (old && old.pub.x === pub.x && old.pub.y === pub.y) next.set(d.id, old);
      else { next.set(d.id, { pub, ts: d.data().ts || 0 }); S.keyCache.clear(); }
    }
    S.keys = next; renderLists(); computeDmInfo(); refreshActive();
  }, subErr('directory')));
  S.unsubs.push(DB.collection('chats').where('members', 'array-contains', S.uid).onSnapshot(snap => {
    S.chats = new Map(snap.docs.map(d => [d.id, { id: d.id, ...d.data() }]));
    for (const id of S.chats.keys()) S.virtual.delete(id);
    renderLists(); renderHeader(); renderBanner(); refreshActive();
    if (S.activeId && chatById(S.activeId)) markRead();
  }, subErr('chats')));
  S.unsubs.push(DB.collection('notices').orderBy('ts', 'desc').limit(30).onSnapshot(snap => {
    S.notices = snap.docs.map(d => ({ id: d.id, ...d.data() })); renderLists();
  }, subErr('notices')));
}
async function startRoom() {
  try { ROOM = await claude.use('room'); } catch { ROOM = null; }
  if (!ROOM) return;
  const upd = (peers) => { S.online = new Set(peers.map(p => p.presence && p.presence.uid).filter(Boolean)); renderLists(); renderHeader(); };
  ROOM.onPeers(ch => upd(ch.peers)); upd(ROOM.peers());
  ROOM.on('typing', msg => { if (msg.isMe) return; const d = msg.data || {}; if (d.chat && d.uid) { S.typing.set(d.chat + '|' + d.uid, Date.now()); renderHeader(); } });
  applyPresence();
}
function applyPresence() { if (ROOM) ROOM.presence({ uid: ls.get('ghost', false) ? null : S.uid }).catch(() => {}); }

/* ---------- Opening chats ---------- */
function openChat(id) {
  S.activeId = id; S.msgDocs = []; S.snapTok++; S.dmInfo = null;
  if (S.msgUnsub) { S.msgUnsub(); S.msgUnsub = null; }
  $('#app').dataset.view = 'chat'; $('#empty').hidden = true; $('#pane').hidden = false;
  renderHeader(); renderBanner(); renderMessages(); renderChips(); computeDmInfo();
  S.msgUnsub = DB.collection(`chats/${id}/messages`).orderBy('ts', 'desc').limit(200).onSnapshot(async snap => {
    const tok = ++S.snapTok;
    S.msgDocs = snap.docs.map(d => ({ id: d.id, ...d.data() })).reverse();
    await decryptDocs(id); if (tok !== S.snapTok || S.activeId !== id) return;
    renderMessages(); markRead();
  }, subErr('messages'));
  renderLists(); $('#msg').focus();
}
function openDm(peer) {
  const id = dmId(S.uid, peer);
  if (!S.chats.has(id) && !S.virtual.has(id)) S.virtual.set(id, { id, type: 'dm', members: peer === S.uid ? [S.uid, S.uid] : [S.uid, peer], virtual: true });
  openChat(id);
}
async function decryptDocs(chatId) {
  const chat = chatById(chatId); if (!chat) return;
  for (const m of S.msgDocs) {
    const k = chatId + ':' + m.id; if (S.plain.has(k)) continue;
    try { const key = await chatKey(chat); S.plain.set(k, await C.open(key, m, `${chatId}|${m.from}|${m.ts}`)); } catch { /* retried on next refresh */ }
  }
}
async function refreshActive() {
  if (!S.activeId || !chatById(S.activeId) || !S.msgDocs.length) return;
  const before = S.plain.size; await decryptDocs(S.activeId);
  if (S.plain.size !== before) renderMessages();
}
function markRead() { const c = chatById(S.activeId); if (!c) return; const t = Math.max(c.lastTs || 0, ...S.msgDocs.map(m => m.ts)); if (t > (S.read[c.id] || 0)) { S.read[c.id] = t; ls.set('read', S.read); renderLists(); } }

/* ---------- DM safety info (key pinning) ---------- */
async function computeDmInfo() {
  const chat = chatById(S.activeId);
  if (!chat || chat.type !== 'dm') { S.dmInfo = null; renderBanner(); renderHeader(); return; }
  const peer = dmPeer(chat); if (peer === S.uid) { S.dmInfo = { self: true }; renderBanner(); renderHeader(); return; }
  const e = S.keys.get(peer); if (!e) { S.dmInfo = null; renderBanner(); renderHeader(); return; }
  const id = await C.pubId(e.pub), pins = ls.get('pins', {}), ver = ls.get('ver', {});
  let status = 'ok'; if (!pins[peer]) { pins[peer] = id; ls.set('pins', pins); } else if (pins[peer] !== id) status = 'changed';
  S.dmInfo = { peer, id, status, verified: ver[peer] === id };
  renderBanner(); renderHeader();
}

/* ---------- Sending ---------- */
async function sendMessage() {
  const box = $('#msg'), text = box.value.trim(), chat = chatById(S.activeId);
  if (!text || !chat || !S.canWrite) return;
  const ts = Date.now(); let payload;
  const sp = /^\/sprint(?:\s+(\d{1,3}))?\s*(.*)$/i.exec(text);
  if (sp) payload = { t: 'sprint', mins: Math.min(180, Math.max(1, parseInt(sp[1] || '25', 10))), topic: (sp[2] || '').slice(0, 80), start: ts };
  else payload = { t: 'text', body: text.slice(0, 4000) };
  if (S.draft.seal > ts) payload.seal = S.draft.seal;
  const exp = S.draft.ttl ? (payload.seal || ts) + S.draft.ttl : 0;
  const btn = $('#btnSend'); btn.disabled = true; const saved = box.value; box.value = ''; autoGrow();
  try {
    const key = await chatKey(chat);
    if (chat.virtual) {
      await DB.doc('chats/' + chat.id).set({ type: 'dm', members: chat.members, createdBy: S.uid, createdAt: ts, lastTs: ts, lastBy: S.uid });
    }
    const body = await C.seal(key, payload, `${chat.id}|${S.uid}|${ts}`);
    await DB.collection(`chats/${chat.id}/messages`).add({ from: S.uid, ts, iv: body.iv, ct: body.ct, exp });
    if (!chat.virtual) await DB.doc('chats/' + chat.id).update({ lastTs: ts, lastBy: S.uid });
    S.draft.seal = 0; renderChips();
  } catch (e) {
    box.value = saved; autoGrow();
    toast(e && e.message === 'peer-no-key' ? 'They have not set up Bluvane yet.' : e && e.message === 'no-wrap' ? 'You do not have this group’s key yet.' : 'Message not sent. Please try again.');
  }
  btn.disabled = false; box.focus();
}
const purged = new Set(), purgeQ = []; let purging = false;
function purge(chatId, mid) {
  if (!S.canWrite) return; const k = chatId + '/' + mid; if (purged.has(k)) return; purged.add(k); purgeQ.push({ chatId, mid });
  if (!purging) (async () => { purging = true; while (purgeQ.length) { const q = purgeQ.shift(); try { await DB.doc(`chats/${q.chatId}/messages/${q.mid}`).delete(); } catch { /* already gone */ } await sleep(150); } purging = false; })();
}

/* ---------- Groups ---------- */
async function createGroup(name, emoji, memberIds) {
  const id = 'g_' + hex(10), ts = Date.now(), gk = await C.newGroupKey(), members = [S.uid, ...memberIds], wk = {};
  for (const m of members) { const pub = m === S.uid ? await C.importPub(S.pubJwk) : await pubOf(m); const w = await C.wrapGroupKey(gk, S.priv, pub, id); w.by = S.uid; wk[m] = w; }
  await DB.doc('chats/' + id).set({ type: 'group', name, emoji, members, wk, createdBy: S.uid, createdAt: ts, lastTs: ts, lastBy: S.uid });
  S.keyCache.set(id, gk); return id;
}
async function shareGroupKey(chat, uid) {
  const gk = await chatKey(chat), w = await C.wrapGroupKey(gk, S.priv, await pubOf(uid), chat.id); w.by = S.uid;
  return w;
}
async function addMember(chat, uid) {
  const snap = await DB.doc('chats/' + chat.id).get(), cur = snap.data(); if (cur.members.includes(uid)) return;
  const w = await shareGroupKey(chat, uid);
  await DB.doc('chats/' + chat.id).update({ members: [...cur.members, uid], wk: { [uid]: w } });
}
async function reshareKey(chat, uid) { const w = await shareGroupKey(chat, uid); await DB.doc('chats/' + chat.id).update({ wk: { [uid]: w } }); }
async function deleteGroup(chat) {
  for (let i = 0; i < 20; i++) { const snap = await DB.collection(`chats/${chat.id}/messages`).limit(100).get(); if (snap.empty) break; for (const d of snap.docs) { try { await DB.doc(`chats/${chat.id}/messages/${d.id}`).delete(); } catch { /* ignore */ } await sleep(60); } }
  await DB.doc('chats/' + chat.id).delete();
}

/* ---------- Rendering ---------- */
function buildStaticIcons() {
  document.querySelectorAll('[data-ic]').forEach(el => el.replaceChildren(ic(el.dataset.ic, +el.dataset.size || 20)));
  $('#brandLogo').replaceChildren(logo(40)); $('#emptyLogo').replaceChildren(logo(72));
}
function renderAll() { renderLists(); applyTheme(); if (S.activeId) { renderHeader(); renderBanner(); renderMessages(); } }

function renderLists() {
  const list = $('#list'); if (!list || $('#app').hidden) return;
  document.querySelectorAll('.tabs button').forEach(b => b.classList.toggle('on', b.dataset.tab === S.tab));
  const q = S.search.trim().toLowerCase(), unseen = S.notices.filter(n => n.ts > S.lastNoticeSeen).length;
  const nb = $('#noticeBadge'); nb.hidden = !unseen || S.tab === 'notices'; nb.textContent = unseen;
  const rows = [];
  if (S.tab === 'chats') {
    const chats = [...S.chats.values()].filter(c => !q || chatTitle(c).toLowerCase().includes(q)).sort((a, b) => (b.lastTs || 0) - (a.lastTs || 0));
    for (const c of chats) {
      const peer = c.type === 'dm' ? dmPeer(c) : null, title = chatTitle(c);
      rows.push(h('button', { class: 'item' + (c.id === S.activeId ? ' on' : ''), onclick: () => openChat(c.id) },
        c.type === 'group' ? avatar(c.id, title, 46, false, c.emoji || '') : avatar(peer, title, 46, peer !== S.uid && S.online.has(peer)),
        h('div', { class: 'meta' }, h('b', null, title), h('small', null, c.type === 'group' ? `${c.members.length} members · encrypted` : 'Private · end-to-end encrypted')),
        h('div', { class: 'when' }, c.lastTs ? fmtDay(c.lastTs) === 'Today' ? fmtTime(c.lastTs) : fmtDay(c.lastTs) : '', isUnread(c) ? h('div', null, h('span', { class: 'unread', 'aria-label': 'Unread' })) : null)));
    }
    if (!rows.length) rows.push(h('div', { class: 'empty-list' }, q ? 'No chats match.' : 'No chats yet. Add a friend by email or phone number to start chatting.', h('div', { style: 'margin-top:12px' }, h('button', { class: 'btn small', onclick: openAddContact }, 'Add a contact'))));
  } else if (S.tab === 'people') {
    const ids = [...S.keys.keys()].filter(id => id !== S.uid);
    const people = ids.map(id => ({ id, name: nameOf(id) })).filter(p => !q || p.name.toLowerCase().includes(q)).sort((a, b) => (S.online.has(b.id) - S.online.has(a.id)) || a.name.localeCompare(b.name));
    rows.push(h('div', { style: 'padding:6px 8px 8px' }, h('button', { class: 'btn block', onclick: openAddContact }, ic('user-plus', 18), 'Add contact by email or phone')));
    if (!q || 'notes to self'.includes(q)) rows.push(h('button', { class: 'item', onclick: () => openDm(S.uid) }, avatar(S.uid, S.me.name, 46, false, '📝'), h('div', { class: 'meta' }, h('b', null, 'Notes to self'), h('small', null, 'Encrypted notepad only you can read'))));
    const prow = (p, isC) => {
      const open = h('button', { class: 'item', onclick: () => openDm(p.id) }, avatar(p.id, p.name, 46, S.online.has(p.id)), h('div', { class: 'meta' }, h('b', null, p.name), h('small', null, S.online.has(p.id) ? 'Online now' : 'Tap to message privately')));
      const act = h('button', { class: 'btn ghost small', 'aria-label': (isC ? 'Remove ' : 'Add ') + p.name }, isC ? 'Remove' : '+ Add');
      if (isC) armBtn(act, 'Sure?', () => removeContact(p.id)); else act.addEventListener('click', async () => { if (await addContact(p.id)) toast(p.name + ' added to contacts.'); });
      return h('div', { class: 'item-wrap' }, open, act);
    };
    const cons = people.filter(p => S.contacts.has(p.id)), others = people.filter(p => !S.contacts.has(p.id));
    if (cons.length) { rows.push(h('div', { class: 'sec-lbl' }, 'Contacts')); cons.forEach(p => rows.push(prow(p, true))); }
    if (others.length) { rows.push(h('div', { class: 'sec-lbl' }, cons.length ? 'Others on Bluvane' : 'On Bluvane')); others.forEach(p => rows.push(prow(p, false))); }
    if (!people.length) rows.push(h('div', { class: 'empty-list' }, q ? 'Nobody matches.' : 'Nobody else has joined yet. Add a friend by email or phone, then they will appear here.'));
  } else {
    if (!S.notices.length) rows.push(h('div', { class: 'empty-list' }, 'No notices from the admin yet.'));
    for (const n of S.notices) rows.push(h('div', { class: 'notice' }, h('small', { class: 'muted' }, new Date(n.ts).toLocaleString([], { dateStyle: 'medium', timeStyle: 'short' })), h('p', null, n.text)));
  }
  list.replaceChildren(...rows);
}

function renderHeader() {
  const chat = chatById(S.activeId); if (!chat || $('#pane').hidden) return;
  const title = chatTitle(chat), peer = chat.type === 'dm' ? dmPeer(chat) : null;
  $('#chatTitle').textContent = title;
  $('#headAv').replaceChildren(chat.type === 'group' ? avatar(chat.id, title, 42, false, chat.emoji || '') : avatar(peer, title, 42, peer !== S.uid && S.online.has(peer), peer === S.uid ? '📝' : ''));
  const sub = $('#chatSub'), now = Date.now();
  const typing = [...S.typing].some(([k, t]) => k.startsWith(chat.id + '|') && now - t < 4500);
  sub.className = typing ? 'typing' : ''; sub.replaceChildren();
  if (typing) sub.append('typing…');
  else if (chat.type === 'group') sub.append(ic('lock', 13), `${chat.members.length} members · end-to-end encrypted`);
  else if (S.dmInfo && S.dmInfo.verified) sub.append(ic('shield-check', 14), h('span', { class: 'verified' }, 'Verified · end-to-end encrypted'));
  else sub.append(ic('lock', 13), peer !== S.uid && S.online.has(peer) ? 'Online · end-to-end encrypted' : 'End-to-end encrypted');
  $('#btnSend').disabled = !S.canWrite; $('#msg').disabled = !S.canWrite;
}
function renderBanner() {
  const b = $('#banner'), chat = chatById(S.activeId); if (!chat) { b.hidden = true; return; }
  b.replaceChildren(); let msg = null, action = null;
  if (!S.canWrite) msg = 'You have view-only access, so you can read but not send. Ask the owner for Contributor access.';
  else if (chat.type === 'dm' && dmPeer(chat) !== S.uid && !S.keys.has(dmPeer(chat))) msg = 'They have not set up Bluvane yet. You can send once they open the app.';
  else if (chat.type === 'group' && !(chat.wk && chat.wk[S.uid])) msg = 'You do not have this group’s key yet. Ask a member to re-share it.';
  else if (S.dmInfo && S.dmInfo.status === 'changed') { msg = 'This contact’s security key changed. Compare safety emojis before trusting new messages.'; action = h('button', { class: 'btn small', onclick: openSafety }, 'Review'); }
  b.hidden = !msg; if (msg) b.append(h('span', null, msg), action);
}

function bodyFor(m, p, mine, now) {
  if (!p) return h('div', { class: 'cipher' }, ic('lock', 14), 'Can’t decrypt on this device');
  if (p.seal && p.seal > now && !mine) return h('div', { class: 'sealed', 'data-seal': p.seal }, ic('clock', 22), h('b', null, 'Time capsule'), h('span', { class: 'tiny' }, 'Opens in ', h('span', { class: 'st' }, fmtRemain(p.seal - now))));
  const out = [];
  if (p.t === 'sprint') {
    const end = p.start + p.mins * 60000;
    out.push(h('div', { class: 'sprint', 'data-end': end }, h('div', { class: 'sp-top' }, ic('clock', 16), `Study Sprint · ${p.mins} min`), p.topic ? h('div', { class: 'sp-topic' }, p.topic) : null, h('div', { class: 'sp-time' }, mmss(end - now))));
  } else out.push(h('div', { class: 'txt' }, p.body));
  if (p.seal && p.seal > now && mine) out.push(h('div', { class: 'seal-tag' }, ic('clock', 12), 'Sealed for others until ' + new Date(p.seal).toLocaleString([], { dateStyle: 'medium', timeStyle: 'short' })));
  return out;
}
function renderMessages() {
  const box = $('#msgs'), chat = chatById(S.activeId); if (!chat || $('#pane').hidden) return;
  const near = box.scrollHeight - box.scrollTop - box.clientHeight < 140, prev = box.scrollTop, now = Date.now();
  const list = S.msgDocs.filter(m => { if (m.exp && m.exp <= now) { purge(chat.id, m.id); return false; } return true; });
  const frag = document.createDocumentFragment(); let lastDay = '', lastFrom = null;
  if (!list.length) frag.append(h('div', { class: 'hint' }, ic('lock', 28), h('p', null, chat.type === 'group' ? 'This group is private. Only members can read what you send.' : 'Messages here are end-to-end encrypted. Say hello!')));
  for (const m of list) {
    const p = S.plain.get(chat.id + ':' + m.id), mine = m.from === S.uid, day = fmtDay(m.ts);
    if (day !== lastDay) { frag.append(h('div', { class: 'day' }, day)); lastDay = day; lastFrom = null; }
    const row = h('div', { class: 'row ' + (mine ? 'me' : 'them') + (lastFrom === m.from ? ' cont' : ''), 'data-id': m.id });
    if (!mine && chat.type === 'group' && lastFrom !== m.from) row.append(h('div', { class: 'who', style: `color:${hueText(m.from)}` }, nameOf(m.from)));
    row.append(h('div', { class: 'bubble', tabindex: '0' }, bodyFor(m, p, mine, now)));
    const meta = h('div', { class: 'meta-line' }, fmtTime(m.ts));
    if (m.exp) meta.append(h('span', { class: 'burn', 'data-exp': m.exp }, ic('flame', 12), h('span', { class: 'bt' }, fmtRemain(m.exp - now))));
    if (mine && S.canWrite) meta.append(h('button', { class: 'del', 'aria-label': 'Delete this message for everyone', title: 'Delete for everyone', onclick: () => { purge(chat.id, m.id); row.remove(); } }, ic('trash', 13)));
    row.append(meta); frag.append(row); lastFrom = m.from;
  }
  box.replaceChildren(frag); box.scrollTop = near ? box.scrollHeight : prev;
}
function renderChips() {
  const c = $('#chips'); c.replaceChildren();
  if (S.draft.ttl) c.append(h('span', { class: 'chip' }, ic('flame', 14), 'Burns ' + fmtRemain(S.draft.ttl) + ' after sending', h('button', { 'aria-label': 'Remove burn timer', onclick: () => { S.draft.ttl = 0; renderChips(); } }, ic('x', 14))));
  if (S.draft.seal > Date.now()) c.append(h('span', { class: 'chip' }, ic('clock', 14), 'Sealed until ' + new Date(S.draft.seal).toLocaleString([], { dateStyle: 'medium', timeStyle: 'short' }), h('button', { 'aria-label': 'Remove time capsule', onclick: () => { S.draft.seal = 0; renderChips(); } }, ic('x', 14))));
}
function tick() {
  const now = Date.now();
  document.querySelectorAll('[data-exp]').forEach(el => {
    const left = +el.dataset.exp - now;
    if (left <= 0) { const row = el.closest('.row'); if (row) { purge(S.activeId, row.dataset.id); row.remove(); } }
    else el.querySelector('.bt').textContent = fmtRemain(left);
  });
  document.querySelectorAll('.sprint').forEach(el => {
    const left = +el.dataset.end - now, t = el.querySelector('.sp-time');
    if (left > 0) { t.textContent = mmss(left); el.classList.remove('done'); } else { t.textContent = 'Sprint complete 🎉'; el.classList.add('done'); }
  });
  let reveal = false;
  document.querySelectorAll('[data-seal]').forEach(el => { if (+el.dataset.seal <= now) reveal = true; else el.querySelector('.st').textContent = fmtRemain(+el.dataset.seal - now); });
  if (reveal) renderMessages();
  let dirty = false; for (const [k, t] of S.typing) if (now - t > 4500) { S.typing.delete(k); dirty = true; } if (dirty) renderHeader();
}

/* ---------- Composer popover ---------- */
const QUICK = ['😀','😂','😍','🙏','👍','🎉','🔥','💙','😮','🤝','📚','✅'];
function renderPop() {
  const p = $('#pop'), local = (d) => { const t = new Date(d - new Date().getTimezoneOffset() * 60000); return t.toISOString().slice(0, 16); };
  const dt = h('input', { class: 'field', type: 'datetime-local', min: local(Date.now() + 60000), 'aria-label': 'Open the capsule at' });
  if (S.draft.seal > Date.now()) dt.value = local(S.draft.seal);
  dt.addEventListener('change', () => { const v = new Date(dt.value).getTime(); if (v > Date.now()) { S.draft.seal = v; renderChips(); } });
  p.replaceChildren(
    h('button', { class: 'pop-item', onclick: () => { const b = $('#msg'); b.value = '/sprint 25 '; closePop(); b.focus(); } }, ic('clock', 20), h('span', null, h('b', null, 'Study sprint'), h('small', null, 'A shared countdown for everyone in the chat'))),
    h('div', { class: 'pop-sec' }, h('div', { class: 'pop-label' }, ic('flame', 16), 'Burn timer'),
      h('div', { class: 'seg' }, [[0, 'Off'], [30, '30s'], [300, '5m'], [3600, '1h'], [86400, '24h']].map(([s, l]) => h('button', { class: S.draft.ttl === s * 1000 ? 'on' : '', onclick: () => { S.draft.ttl = s * 1000; renderChips(); renderPop(); } }, l)))),
    h('div', { class: 'pop-sec' }, h('div', { class: 'pop-label' }, ic('clock', 16), 'Time capsule'), dt, h('div', { class: 'tiny muted', style: 'margin-top:6px' }, 'The app keeps it closed for others until then.')),
    h('div', { class: 'pop-sec' }, h('div', { class: 'emoji-row' }, QUICK.map(e => h('button', { 'aria-label': 'Insert ' + e, onclick: () => { const b = $('#msg'); b.setRangeText(e, b.selectionStart, b.selectionEnd, 'end'); b.focus(); autoGrow(); } }, e)))));
}
function closePop() { $('#pop').hidden = true; }
function autoGrow() { const b = $('#msg'); b.style.height = 'auto'; b.style.height = Math.min(b.scrollHeight, 140) + 'px'; }
let lastTypingEmit = 0;

/* ---------- Modals ---------- */
function openAddContact() {
  const inp = h('input', { class: 'field', type: 'text', placeholder: 'name@email.com or +256 772 000 000', autocomplete: 'off', 'aria-label': 'Email or phone number' });
  const go = h('button', { class: 'btn block', style: 'margin-top:10px' }, ic('search', 16), 'Find'), out = h('div', { style: 'margin-top:12px' });
  const run = async () => {
    out.replaceChildren(); const raw = inp.value.trim(); if (!raw) return;
    go.disabled = true; const r = await findByHandle(raw); go.disabled = false;
    if (r.error) return out.append(h('div', { class: 'err' }, 'Enter a valid email address or phone number.'));
    if (r.id === S.uid) return out.append(h('div', { class: 'muted' }, 'That’s you! Open People → Notes to self to message yourself.'));
    if (!r.id) return out.append(h('div', { class: 'notice', style: 'margin:0' }, h('b', null, r.pending ? `${r.pending} has not set up Bluvane yet` : 'No Bluvane account found'),
      h('p', { class: 'muted' }, r.pending ? 'Try again once they have opened the app and created their key.' : 'They need to open Bluvane and finish setup' + (r.kind === 'phone' ? ', then add this number under Settings → Find me by.' : ', signed in with this email.'))));
    await resolveNames([r.id]); const name = nameOf(r.id), has = S.contacts.has(r.id);
    const msgB = h('button', { class: 'btn small' }, 'Message'), saveB = h('button', { class: 'btn ghost small' }, has ? 'In contacts ✓' : 'Save contact');
    saveB.disabled = has;
    msgB.addEventListener('click', async () => { await addContact(r.id); close(); S.tab = 'chats'; openDm(r.id); });
    saveB.addEventListener('click', async () => { if (await addContact(r.id)) { saveB.textContent = 'Saved ✓'; saveB.disabled = true; } });
    out.append(h('div', { class: 'row-line' }, avatar(r.id, name, 40), h('div', { class: 'grow' }, h('b', null, name), h('small', { class: 'muted' }, 'On Bluvane · ' + (r.kind === 'email' ? 'found by email' : 'found by phone'))), msgB, saveB));
  };
  go.addEventListener('click', run); inp.addEventListener('keydown', e => { if (e.key === 'Enter') run(); });
  const body = h('div', null, h('p', { class: 'muted', style: 'margin:0 0 10px' }, 'Type the email or phone number your friend uses for Bluvane. They appear here once they have joined.'), inp, go, out,
    h('p', { class: 'tiny muted', style: 'margin-top:14px' }, 'Tip: for phone numbers, include the country code. Friends can add their number in Settings → Find me by.'));
  const close = openModal('Add contact', body); inp.focus();
}
async function openSafety() {
  const chat = chatById(S.activeId); if (!chat || chat.type !== 'dm') return;
  const peer = dmPeer(chat);
  if (peer === S.uid) { const b = h('div', null, h('p', { class: 'muted' }, 'This chat is encrypted with your own key. It is a private notepad that only you can open.')); return openModal('Notes to self', b); }
  const e = S.keys.get(peer); if (!e) return toast('They have not set up Bluvane yet.');
  await computeDmInfo();
  const fp = await C.fp(S.pubJwk, e.pub), info = S.dmInfo, name = nameOf(peer);
  const body = h('div', null,
    h('p', { class: 'muted', style: 'margin:0' }, `Compare these pictures with ${name} in person or on a call. If they match on both phones, nobody is listening in.`),
    h('div', { class: 'emoji-code', 'aria-label': 'Safety emojis' }, fp.emoji), h('div', { class: 'digits' }, fp.digits));
  const actions = h('div', { style: 'display:grid;gap:8px;margin-top:16px' });
  const ver = ls.get('ver', {});
  if (info && info.status === 'changed') {
    const b = h('button', { class: 'btn danger block' }, 'Accept their new key');
    b.addEventListener('click', () => { const pins = ls.get('pins', {}); pins[peer] = info.id; ls.set('pins', pins); delete ver[peer]; ls.set('ver', ver); toast('New key accepted.'); close(); computeDmInfo(); });
    actions.append(b);
  }
  const vb = h('button', { class: 'btn ' + (info && info.verified ? 'ghost' : '') + ' block' }, info && info.verified ? 'Remove verified mark' : 'They match: mark as verified');
  vb.addEventListener('click', () => { if (info.verified) delete ver[peer]; else ver[peer] = info.id; ls.set('ver', ver); close(); computeDmInfo(); });
  actions.append(vb); body.append(actions);
  const close = openModal(`Safety code with ${name}`, body);
}
async function openGroupInfo() {
  const chat = chatById(S.activeId); if (!chat || chat.type !== 'group') return;
  await resolveNames([...chat.members]);
  const body = h('div'), mine = !!(chat.wk && chat.wk[S.uid]), creator = chat.createdBy === S.uid;
  body.append(h('p', { class: 'muted', style: 'margin:0 0 6px' }, 'Everyone below shares one group key. Group names, members and times are visible to the app’s storage; message content is not.'));
  for (const m of chat.members) {
    const rowEl = h('div', { class: 'row-line' }, avatar(m, nameOf(m), 36), h('div', { class: 'grow' }, h('b', null, nameOf(m)), h('small', { class: 'muted' }, m === chat.createdBy ? 'Creator' : 'Member')));
    if (m !== S.uid && mine && S.canWrite) { const b = h('button', { class: 'btn ghost small', title: 'Send this person the key again if they cannot read messages' }, ic('refresh', 14), 'Re-share key'); b.addEventListener('click', async () => { try { await reshareKey(chat, m); toast('Key re-shared.'); } catch { toast('Could not re-share.'); } }); rowEl.append(b); }
    body.append(rowEl);
  }
  const others = [...S.keys.keys()].filter(id => !chat.members.includes(id));
  if (others.length && mine && S.canWrite) {
    await resolveNames(others);
    body.append(h('label', { class: 'lbl' }, 'Add people'));
    for (const id of others) { const b = h('button', { class: 'btn small' }, 'Add'); b.addEventListener('click', async () => { b.disabled = true; try { await addMember(chat, id); toast(nameOf(id) + ' added.'); close(); } catch { b.disabled = false; toast('Could not add.'); } }); body.append(h('div', { class: 'row-line' }, avatar(id, nameOf(id), 36), h('div', { class: 'grow' }, h('b', null, nameOf(id))), b)); }
  }
  if (creator && S.canWrite) { const d = h('button', { class: 'btn danger block', style: 'margin-top:16px' }, 'Delete group for everyone'); armBtn(d, 'Tap again to confirm', async () => { try { await deleteGroup(chat); close(); S.activeId = null; $('#pane').hidden = true; $('#empty').hidden = false; $('#app').dataset.view = 'list'; toast('Group deleted.'); } catch { toast('Could not delete the group.'); } }); body.append(d); }
  const close = openModal(`${chat.emoji || ''} ${chat.name || 'Group'}`.trim(), body);
}
const GROUP_ICONS = ['📚', '🧪', '⚽', '🎵', '💡', '🌍', '🚀', '🎨', '💬', '🏫'];
async function openNewGroup() {
  const all = [...S.keys.keys()].filter(id => id !== S.uid); await resolveNames(all);
  const ids = [...all.filter(id => S.contacts.has(id)), ...all.filter(id => !S.contacts.has(id))];
  let icon = GROUP_ICONS[0]; const picked = new Set();
  const name = h('input', { class: 'field', placeholder: 'e.g. Physics revision', maxlength: '40', 'aria-label': 'Group name' });
  const pick = h('div', { class: 'picker' }), err = h('div', { class: 'err' });
  const paint = () => pick.replaceChildren(...GROUP_ICONS.map(e => h('button', { class: e === icon ? 'on' : '', 'aria-label': 'Icon ' + e, onclick: () => { icon = e; paint(); } }, e)));
  paint();
  const people = h('div');
  if (!ids.length) people.append(h('p', { class: 'muted' }, 'Nobody else has joined yet. Once your friends open Bluvane, you can add them here.'));
  for (const id of ids) { const cb = h('input', { type: 'checkbox', 'aria-label': 'Add ' + nameOf(id) }); cb.addEventListener('change', () => cb.checked ? picked.add(id) : picked.delete(id)); people.append(h('label', { class: 'row-line', style: 'cursor:pointer' }, avatar(id, nameOf(id), 36), h('div', { class: 'grow' }, h('b', null, nameOf(id)), S.contacts.has(id) ? h('small', { class: 'muted' }, 'Contact') : null), cb)); }
  const go = h('button', { class: 'btn block', style: 'margin-top:14px' }, 'Create encrypted group');
  go.addEventListener('click', async () => {
    err.textContent = ''; if (!name.value.trim()) { err.textContent = 'Give the group a name.'; return; } if (!picked.size) { err.textContent = 'Pick at least one person.'; return; }
    go.disabled = true; try { const id = await createGroup(name.value.trim(), icon, [...picked]); close(); S.tab = 'chats'; openChat(id); } catch { go.disabled = false; err.textContent = 'Could not create the group. Please try again.'; }
  });
  const body = h('div', null, h('label', { class: 'lbl' }, 'Group name'), name, h('label', { class: 'lbl' }, 'Icon'), pick, h('label', { class: 'lbl' }, 'Members'), people, go, err);
  const close = openModal('New group', body);
  name.focus();
}
function switchRow(label, desc, checked, onChange) {
  const inp = h('input', { type: 'checkbox', checked, 'aria-label': label }); inp.addEventListener('change', () => onChange(inp.checked));
  return h('div', { class: 'row-line' }, h('div', { class: 'grow' }, h('b', { style: 'white-space:normal' }, label), h('small', { class: 'muted' }, desc)), h('span', { class: 'switch' }, inp, h('i')));
}
async function openSettings() {
  const theme = ls.get('theme', 'system'), seg = h('div', { class: 'seg' });
  const paint = () => seg.replaceChildren(...[['system', 'System'], ['light', 'Light'], ['dark', 'Dark']].map(([v, l]) => h('button', { class: ls.get('theme', 'system') === v ? 'on' : '', onclick: () => { ls.set('theme', v); applyTheme(); paint(); } }, l)));
  paint();
  const mine = await C.pubId(S.pubJwk), myEmoji = (await C.fp(S.pubJwk, S.pubJwk)).emoji;
  const keepDev = !!(await idb.get('id:' + S.uid)), prof = await loadProfile();
  const ph = h('input', { class: 'field', type: 'tel', placeholder: '+256 772 000 000', autocomplete: 'tel', 'aria-label': 'Your phone number', value: prof.phone || S.me.phone || '' });
  const phBtn = h('button', { class: 'btn small', style: 'margin-top:8px' }, 'Save number');
  phBtn.addEventListener('click', async () => {
    phBtn.disabled = true;
    try { await savePhone(ph.value); toast(ph.value.trim() ? 'Number saved. Friends can now find you by phone.' : 'Number removed.'); }
    catch (e) { toast(e && e.message === 'bad-phone' ? 'Enter a valid phone number.' : 'Could not save your number.'); }
    phBtn.disabled = false;
  });
  const so = h('button', { class: 'btn ghost block', onclick: () => window.claude.signOut() }, 'Sign out of this device');
  const reset = h('button', { class: 'btn danger block', style: 'margin-top:8px' }, 'Reset my identity');
  armBtn(reset, 'Tap again: old chats will be lost', () => { close(); stopSubs(); $('#app').hidden = true; showOnboarding(true); });
  const body = h('div', null,
    h('label', { class: 'lbl' }, 'Appearance'), seg,
    h('label', { class: 'lbl' }, 'Find me by'),
    h('div', { class: 'tiny muted', style: 'margin-bottom:6px' }, 'Phone number'), ph, phBtn,
    switchRow('Findable by email', S.me.email ? 'People who know ' + S.me.email + ' can add you.' : 'Your Claude account does not share an email here.', !prof.hideEmail && !!S.me.email, async v => { try { await setEmailVisible(v); } catch { toast('Could not update.'); } }),
    h('label', { class: 'lbl' }, 'Privacy'),
    switchRow('Privacy shield', 'Blur messages when this window loses focus.', ls.get('shield', true), v => { ls.set('shield', v); applyShield(); }),
    switchRow('Ghost mode', 'Hide your online status and typing indicator.', ls.get('ghost', false), v => { ls.set('ghost', v); applyPresence(); }),
    switchRow('Stay unlocked on this device', 'Skip the passphrase here. Turn off on shared computers.', keepDev, async v => { if (v) await idb.set('id:' + S.uid, { priv: S.priv, x: S.pubJwk.x, y: S.pubJwk.y }); else await idb.del('id:' + S.uid); }),
    h('label', { class: 'lbl' }, 'Your key'), h('div', { class: 'emoji-code', style: 'font-size:26px' }, myEmoji), h('div', { class: 'tiny muted', style: 'text-align:center' }, 'Key ID ' + mine),
    h('details', { style: 'margin-top:14px' }, h('summary', { style: 'cursor:pointer;font-weight:600' }, 'How your privacy works'),
      h('p', { class: 'muted tiny' }, 'Messages are encrypted on your device with AES-256-GCM. Chat keys come from ECDH P-256 key exchange. Your private key is locked with your passphrase (PBKDF2) and never stored unlocked on any server.'),
      h('p', { class: 'muted tiny' }, 'Your contacts list is stored privately under your own account. To let friends find you, only a one-way hash of your email or phone number is shared, never the number itself. A determined person could still guess a phone number by hashing candidates, so turn this off if that worries you.'),
      h('p', { class: 'muted tiny' }, 'Not hidden: who is in each chat, group names, message times and burn timers. Time capsules are kept closed by the app, not by cryptography.')),
    h('label', { class: 'lbl' }, 'Account'), so, h('label', { class: 'lbl' }, 'Danger zone'), reset,
    h('p', { class: 'tiny muted', style: 'text-align:center;margin-top:16px' }, 'Bluvane 1.1 · Biltech Technologies'));
  const close = openModal('Settings & privacy', body);
}
async function openAdmin() {
  const ids = [...S.keys.keys()]; await resolveNames(ids);
  const ta = h('textarea', { class: 'field', rows: '3', maxlength: '600', placeholder: 'Write a notice everyone can see…', 'aria-label': 'Notice' });
  const post = h('button', { class: 'btn block', style: 'margin-top:8px' }, ic('megaphone', 16), 'Post notice');
  const noticeBox = h('div');
  const paintNotices = () => { noticeBox.replaceChildren(...S.notices.map(n => { const b = h('button', { class: 'icon-btn', 'aria-label': 'Delete notice' }, ic('trash', 16)); b.addEventListener('click', async () => { try { await DB.doc('notices/' + n.id).delete(); S.notices = S.notices.filter(x => x.id !== n.id); paintNotices(); } catch { toast('Could not delete.'); } }); return h('div', { class: 'row-line' }, h('div', { class: 'grow', style: 'white-space:pre-wrap;overflow-wrap:anywhere' }, n.text), b); })); };
  paintNotices();
  post.addEventListener('click', async () => { const t = ta.value.trim(); if (!t) return; post.disabled = true; try { const ts = Date.now(); const ref = await DB.collection('notices').add({ text: t, ts }); S.notices = [{ id: ref.id, text: t, ts }, ...S.notices]; ta.value = ''; paintNotices(); toast('Notice posted.'); } catch { toast('Could not post.'); } post.disabled = false; });
  const roster = h('div', null, ids.map(id => h('div', { class: 'row-line' }, avatar(id, nameOf(id), 34, S.online.has(id)), h('div', { class: 'grow' }, h('b', null, id === S.uid ? nameOf(id) + ' (you)' : nameOf(id)), h('small', { class: 'muted' }, 'Joined ' + (S.keys.get(id).ts ? new Date(S.keys.get(id).ts).toLocaleDateString() : 'earlier'))))));
  const body = h('div', null, h('label', { class: 'lbl' }, 'Notice board'), ta, post, noticeBox, h('label', { class: 'lbl' }, `Members (${ids.length})`), roster,
    h('p', { class: 'tiny muted' }, 'Admin access comes from owning this app, not from a password in the page. Admins cannot read anyone’s messages.'));
  openModal('Admin console', body);
}

/* ---------- Shield, shortcuts, wiring ---------- */
function applyShield() { const on = ls.get('shield', true) && (document.hidden || !document.hasFocus()); $('#app').classList.toggle('shield', on); }
function wire() {
  $('#btnTheme').addEventListener('click', () => { ls.set('theme', effectiveTheme() === 'dark' ? 'light' : 'dark'); applyTheme(); });
  $('#btnSettings').addEventListener('click', openSettings);
  $('#btnAdmin').addEventListener('click', openAdmin);
  $('#btnAddContact').addEventListener('click', openAddContact);
  $('#btnLock').addEventListener('click', lockNow);
  $('#btnNewGroup').addEventListener('click', openNewGroup);
  $('#btnBack').addEventListener('click', () => { $('#app').dataset.view = 'list'; });
  $('#btnInfo').addEventListener('click', () => { const c = chatById(S.activeId); if (c) c.type === 'group' ? openGroupInfo() : openSafety(); });
  $('#headTitle').addEventListener('click', () => $('#btnInfo').click());
  $('#search').addEventListener('input', e => { S.search = e.target.value; renderLists(); });
  document.querySelectorAll('.tabs button').forEach(b => b.addEventListener('click', () => { S.tab = b.dataset.tab; if (S.tab === 'notices') { S.lastNoticeSeen = Date.now(); ls.set('noticeSeen', S.lastNoticeSeen); } renderLists(); }));
  $('#btnSend').addEventListener('click', sendMessage);
  const msg = $('#msg');
  msg.addEventListener('keydown', e => { if (e.key === 'Enter' && !e.shiftKey && !e.isComposing) { e.preventDefault(); sendMessage(); } });
  msg.addEventListener('input', () => { autoGrow(); const now = Date.now(); if (ROOM && !ls.get('ghost', false) && S.activeId && now - lastTypingEmit > 2500) { lastTypingEmit = now; ROOM.emit('typing', { chat: S.activeId, uid: S.uid }).catch(() => {}); } });
  $('#btnPlus').addEventListener('click', (e) => { e.stopPropagation(); const p = $('#pop'); if (p.hidden) { renderPop(); p.hidden = false; } else p.hidden = true; });
  document.addEventListener('click', (e) => { if (!e.target.closest('.pop-anchor')) closePop(); });
  document.addEventListener('keydown', (e) => { if (e.key === 'Escape') closePop(); if (e.altKey && e.code === 'KeyL' && !$('#app').hidden) { e.preventDefault(); lockNow(); } });
  document.addEventListener('visibilitychange', applyShield); window.addEventListener('blur', applyShield); window.addEventListener('focus', applyShield);
}
wire(); boot();
