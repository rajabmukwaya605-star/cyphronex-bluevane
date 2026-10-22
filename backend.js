'use strict';
/* Bluvane client backend: sign-in screen, REST calls and a WebSocket for live updates.
   Exposes window.claude.use('user' | 'db' | 'room') so app.js works against your own server. */
(function () {
  const KEY = 'bv_token';
  let token = null; try { token = localStorage.getItem(KEY); } catch { /* storage unavailable */ }
  let me = null, authP = null, ws = null, wsTimer = null, sidN = 0, myPresence = null;
  const subs = new Map(), handlers = {}, peerCbs = [], profCache = new Map(); let peers = [];

  async function api(method, url, body) {
    const r = await fetch(url, { method, headers: { 'Content-Type': 'application/json', ...(token ? { Authorization: 'Bearer ' + token } : {}) }, body: body ? JSON.stringify(body) : undefined });
    const j = await r.json().catch(() => ({}));
    if (r.status === 401 && token && !/login|register/.test(url)) { signOut(); }
    if (!r.ok) { const e = new Error(j.error || 'request-failed'); e.code = j.error || String(r.status); throw e; }
    return j;
  }
  function signOut() { try { localStorage.removeItem(KEY); } catch { /* ignore */ } try { indexedDB.deleteDatabase('bluvane'); } catch { /* ignore */ } location.reload(); }

  /* ---------- sign in / create account ---------- */
  const ERR = { 'bad-credentials': 'Wrong email/phone or password.', 'email-taken': 'That email already has an account. Sign in instead.', 'bad-email': 'Enter a valid email address.', 'bad-phone': 'That phone number does not look right.', 'weak-password': 'Use at least 8 characters for the password.', 'name-required': 'Please enter your name.', 'too-many-requests': 'Too many attempts. Please wait a few minutes.' };
  function authUI() {
    return new Promise((resolve) => {
      const g = document.createElement('div'); g.className = 'gate'; g.style.zIndex = 150; document.body.append(g);
      let mode = 'login';
      const draw = () => {
        const reg = mode === 'register';
        g.innerHTML = `<div class="card"><h1>Bluvane</h1><p class="muted" style="margin:0">${reg ? 'Create your account. It takes a minute.' : 'Sign in to your account.'}</p>
          <form id="af" novalidate>
            ${reg ? '<label class="lbl">Your name</label><input class="field" name="name" autocomplete="name" maxlength="60">' : ''}
            <label class="lbl">${reg ? 'Email' : 'Email or phone number'}</label><input class="field" name="id" ${reg ? 'type="email"' : ''} autocomplete="username">
            ${reg ? '<label class="lbl">Phone number (optional)</label><input class="field" name="phone" type="tel" autocomplete="tel" placeholder="+256 772 000 000">' : ''}
            <label class="lbl">Password</label><input class="field" name="pw" type="password" autocomplete="${reg ? 'new-password' : 'current-password'}" placeholder="${reg ? 'At least 8 characters' : ''}">
            <div class="err" id="aerr"></div>
            <button class="btn block" type="submit" style="margin-top:8px">${reg ? 'Create account' : 'Sign in'}</button>
          </form>
          <p style="text-align:center;margin:14px 0 0"><button class="link" id="swap" type="button">${reg ? 'Have an account? Sign in' : 'New here? Create an account'}</button></p></div>`;
        const f = g.querySelector('#af'), err = g.querySelector('#aerr');
        g.querySelector('#swap').onclick = () => { mode = reg ? 'login' : 'register'; draw(); };
        f.onsubmit = async (e) => {
          e.preventDefault(); err.textContent = ''; const v = (n) => (f.elements[n] ? f.elements[n].value : '');
          const btn = f.querySelector('button'); btn.disabled = true;
          try {
            const j = reg ? await api('POST', '/api/register', { name: v('name'), email: v('id'), phone: v('phone'), password: v('pw') }) : await api('POST', '/api/login', { id: v('id'), password: v('pw') });
            token = j.token; try { localStorage.setItem(KEY, token); } catch { /* ignore */ }
            g.remove(); resolve();
          } catch (x) { btn.disabled = false; err.textContent = ERR[x.code] || 'Something went wrong. Please try again.'; }
        };
        const first = f.querySelector('input'); if (first) first.focus();
      };
      draw();
    });
  }
  function ensureAuth() {
    return authP || (authP = (async () => {
      if (token) { try { me = await api('GET', '/api/me'); return; } catch { token = null; } }
      await authUI(); me = await api('GET', '/api/me');
    })());
  }

  /* ---------- user ---------- */
  const user = {
    id: async () => me.id,
    me: async () => ({ id: me.id, name: me.name, email: me.email, phone: me.phone, isOwner: me.isOwner }),
    isOwner: async () => me.isOwner, canEdit: async () => me.isOwner, can: async () => true,
    async profiles(ids) {
      const need = ids.filter(i => !profCache.has(i));
      if (need.length) { const j = await api('POST', '/api/profiles', { ids: need }); for (const i of need) profCache.set(i, j[i] || { name: '' }); }
      const out = {}; for (const i of ids) out[i] = { id: i, name: (profCache.get(i) || {}).name || '' }; return out;
    },
    async lookup(q) { try { return (await api('GET', '/api/lookup?q=' + encodeURIComponent(q))).user; } catch { return null; } },
    async search() { return []; },
    async setPhone(p) { const j = await api('PUT', '/api/me/phone', { phone: p }); me.phone = j.phone; },
    async setDiscoverable(on) { await api('PUT', '/api/me/discover', { email: !!on }); }
  };

  /* ---------- live connection ---------- */
  const wsSend = (m) => { if (ws && ws.readyState === 1) ws.send(JSON.stringify(m)); };
  function connect() {
    if (ws) return;
    const open = () => {
      ws = new WebSocket((location.protocol === 'https:' ? 'wss://' : 'ws://') + location.host + '/ws?token=' + encodeURIComponent(token));
      ws.onopen = () => { for (const [sid, s] of subs) wsSend({ type: 'sub', sid, query: s.query }); if (myPresence) wsSend({ type: 'presence', data: myPresence }); };
      ws.onmessage = (e) => {
        let m; try { m = JSON.parse(e.data); } catch { return; }
        if (m.type === 'snap') { const s = subs.get(m.sid); if (s) s.cb(mkSnap(m.docs)); }
        else if (m.type === 'peers') { peers = m.peers; peerCbs.forEach(cb => cb({ peers })); }
        else if (m.type === 'event') (handlers[m.topic] || []).forEach(cb => cb({ isMe: false, data: m.data }));
      };
      ws.onclose = (e) => { ws = null; if (e.code === 4001) return signOut(); clearTimeout(wsTimer); wsTimer = setTimeout(open, 2000); };
    };
    open();
  }
  const mkSnap = (docs) => ({ docs: docs.map(d => ({ id: d.id, data: () => d.data })), empty: !docs.length });

  /* ---------- database ---------- */
  function query(path, q = {}) {
    return {
      where: (f, op, v) => query(path, { ...q, where: [...(q.where || []), [f, op, v]] }),
      orderBy: (f, dir = 'asc') => query(path, { ...q, orderBy: { field: f, dir } }),
      limit: (n) => query(path, { ...q, limit: n }),
      async get() { return mkSnap((await api('POST', '/api/query', { path, ...q })).docs); },
      onSnapshot(cb, errCb) { const sid = 's' + (++sidN); subs.set(sid, { query: { path, ...q }, cb, errCb }); wsSend({ type: 'sub', sid, query: { path, ...q } }); return () => { subs.delete(sid); wsSend({ type: 'unsub', sid }); }; },
      async add(data) { return { id: (await api('POST', '/api/doc', { path, mode: 'add', data })).id }; }
    };
  }
  const dbNs = {
    collection: (p) => query(p),
    doc: (p) => ({
      async get() { const j = await api('GET', '/api/doc?path=' + encodeURIComponent(p)); return { exists: j.exists, id: p.split('/').pop(), data: () => j.data }; },
      set: (data) => api('POST', '/api/doc', { path: p, mode: 'set', data }).then(() => { }),
      update: (data) => api('POST', '/api/doc', { path: p, mode: 'update', data }).then(() => { }),
      delete: () => api('DELETE', '/api/doc?path=' + encodeURIComponent(p)).then(() => { })
    })
  };

  /* ---------- presence & typing ---------- */
  const room = {
    onPeers: (cb) => { peerCbs.push(cb); }, peers: () => peers,
    on: (topic, cb) => { (handlers[topic] = handlers[topic] || []).push(cb); },
    async presence(d) { myPresence = d; wsSend({ type: 'presence', data: d }); },
    async emit(topic, data) { wsSend({ type: 'emit', topic, data }); }
  };

  window.claude = {
    signOut,
    async use(name) {
      await ensureAuth();
      if (name === 'user') return user;
      if (name === 'db') { connect(); return dbNs; }
      if (name === 'room') { connect(); return room; }
      return null;
    }
  };
})();
