#!/usr/bin/env python3
"""Splits the single-file Bluvane page into public/index.html, style.css and app.js
   and patches the few places that talked to the Claude runtime."""
import re, sys
src = open(sys.argv[1], encoding='utf-8').read()
css = src.split('<style>\n', 1)[1].split('</style>', 1)[0]
body = src.split('<body>', 1)[1].split('<script>', 1)[0].strip()
js = src.split('<script>\n', 1)[1].rsplit('</script>', 1)[0]

def sub(old, new):
    global js
    assert old in js, 'patch target missing: ' + old[:60]
    js = js.replace(old, new, 1)

# 1) look people up on the server (email or phone), keep the hash directory as a fallback
start = js.index("  if (p.kind === 'email') {\n    try {\n      const hits")
end = js.index("  return { id: null, kind: p.kind };\n}", start)
js = js[:start] + """  try {
    const u = await USER.lookup(String(raw).trim());
    if (u) { S.names.set(u.id, u.name || 'Someone'); if (S.keys.has(u.id)) return { id: u.id, kind: p.kind }; return { id: null, kind: p.kind, pending: u.name || 'They' }; }
  } catch { /* ignore */ }
""" + js[end:]
# 2) keep the phone number and email-visibility settings on the server too
sub("prof.phoneHash = await handleHash('phone', p.norm); prof.phone = text;", "await USER.setPhone(text); prof.phoneHash = await handleHash('phone', p.norm); prof.phone = text;")
sub("else { prof.phoneHash = null; prof.phone = ''; }", "else { await USER.setPhone(''); prof.phoneHash = null; prof.phone = ''; }")
sub("const prof = await loadProfile(); prof.hideEmail = !on;", "await USER.setDiscoverable(on); const prof = await loadProfile(); prof.hideEmail = !on;")
sub("value: (S.prof && S.prof.phone) || ''", "value: (S.prof && S.prof.phone) || S.me.phone || ''")
sub("value: prof.phone || ''", "value: prof.phone || S.me.phone || ''")
# 3) sign-out button
sub("const reset = h('button', { class: 'btn danger block', style: 'margin-top:8px' }, 'Reset my identity');",
    "const so = h('button', { class: 'btn ghost block', onclick: () => window.claude.signOut() }, 'Sign out of this device');\n  const reset = h('button', { class: 'btn danger block', style: 'margin-top:8px' }, 'Reset my identity');")
sub("h('label', { class: 'lbl' }, 'Danger zone'), reset,", "h('label', { class: 'lbl' }, 'Account'), so, h('label', { class: 'lbl' }, 'Danger zone'), reset,")
# 4) wording that mentioned Claude
js = js.replace("Bluvane needs you to be signed in to Claude with access to this app. Ask the owner to invite you as a Contributor.", "We could not connect to the Bluvane server. Please check your connection and reload.")
js = js.replace("Please sign in to Claude and reload.", "Please sign in and reload.")
js = js.replace("Bluvane signs you in through your Claude account, so it has to be opened from its Claude link.", "The sign-in script did not load. Please reload the page.")
js = js.replace("Open Bluvane from Claude", "Could not start Bluvane")

head = src.split('<style>', 1)[0].replace('</head>', '').rstrip()
html = head + '\n<link rel="stylesheet" href="style.css">\n</head>\n<body>\n' + body + '\n\n<script src="backend.js"></script>\n<script src="app.js"></script>\n</body>\n</html>\n'
open('public/style.css', 'w', encoding='utf-8').write(css)
open('public/app.js', 'w', encoding='utf-8').write(js)
open('public/index.html', 'w', encoding='utf-8').write(html)
print('built')
