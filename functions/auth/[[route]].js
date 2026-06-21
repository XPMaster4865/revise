// ══════════════════════════════════════════════════════════════════════════════
// Revise — Auth (Cloudflare Pages Function)
// KV binding required:  REVISE_KV
// Env vars required:    GOOGLE_CLIENT_ID  GOOGLE_CLIENT_SECRET
// ══════════════════════════════════════════════════════════════════════════════

export async function onRequest(context) {
  const { request, env } = context;
  const url = new URL(request.url);
  const route = url.pathname.replace(/^\/auth\/?/, '').replace(/\/$/, '');

  const map = {
    'POST:signup':                  () => handleSignup(request, env),
    'POST:signin':                  () => handleSignin(request, env),
    'POST:signout':                 () => handleSignout(request, env),
    'GET:me':                       () => handleMe(request, env),
    'GET:google':                   () => handleGoogle(request, env),
    'GET:callback':                 () => handleCallback(request, env),
    'POST:passkey/register-begin':  () => handleRegisterBegin(request, env),
    'POST:passkey/register-finish': () => handleRegisterFinish(request, env),
    'POST:passkey/login-begin':     () => handleLoginBegin(request, env),
    'POST:passkey/login-finish':    () => handleLoginFinish(request, env),
    'GET:passkeys':                 () => handleListPasskeys(request, env),
    'POST:passkeys/delete':         () => handleDeletePasskey(request, env),
  };

  const handler = map[`${request.method}:${route}`];
  if (!handler) return new Response('Not found', { status: 404 });

  try {
    return await handler();
  } catch (e) {
    console.error('[auth]', e.message, e.stack);
    return json({ error: 'Internal server error' }, 500);
  }
}

// ── UTILITIES ─────────────────────────────────────────────────────────────────

function json(data, status = 200, extra = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { 'Content-Type': 'application/json', ...extra },
  });
}

function err(msg, status = 400) { return json({ error: msg }, status); }

function randomBytes(n = 32) { return crypto.getRandomValues(new Uint8Array(n)); }

function b64url(data) {
  const bytes = data instanceof Uint8Array ? data : new Uint8Array(data);
  let s = '';
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
}

function fromB64url(str) {
  const padded = str.replace(/-/g, '+').replace(/_/g, '/');
  const pad = (4 - padded.length % 4) % 4;
  const bin = atob(padded + '='.repeat(pad));
  return new Uint8Array(bin.length).map((_, i) => bin.charCodeAt(i));
}

// ── PASSWORD HASHING (PBKDF2 via Web Crypto) ──────────────────────────────────

async function hashPassword(pw) {
  const salt = randomBytes(16);
  const key = await crypto.subtle.importKey('raw', new TextEncoder().encode(pw), 'PBKDF2', false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits(
    { name: 'PBKDF2', salt, iterations: 200_000, hash: 'SHA-256' }, key, 256
  );
  const hex = a => Array.from(new Uint8Array(a), b => b.toString(16).padStart(2, '0')).join('');
  return hex(salt) + ':' + hex(bits);
}

async function checkPassword(pw, stored) {
  const [saltHex, hashHex] = stored.split(':');
  const salt = new Uint8Array(saltHex.match(/.{2}/g).map(h => parseInt(h, 16)));
  const key = await crypto.subtle.importKey('raw', new TextEncoder().encode(pw), 'PBKDF2', false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits(
    { name: 'PBKDF2', salt, iterations: 200_000, hash: 'SHA-256' }, key, 256
  );
  const hex = a => Array.from(new Uint8Array(a), b => b.toString(16).padStart(2, '0')).join('');
  return hex(bits) === hashHex;
}

// ── SESSIONS ──────────────────────────────────────────────────────────────────

const COOKIE = 'rv_sess';
const TTL    = 60 * 60 * 24 * 30; // 30 days

function cookieSet(token) {
  return `${COOKIE}=${token}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=${TTL}`;
}
function cookieClear() {
  return `${COOKIE}=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0`;
}
function getToken(req) {
  const m = (req.headers.get('Cookie') || '').match(new RegExp(`(?:^|;\\s*)${COOKIE}=([^;]+)`));
  return m ? m[1] : null;
}

async function newSession(kv, userId, email) {
  const token = b64url(randomBytes(32));
  await kv.put(`session:${token}`, JSON.stringify({ userId, email }), { expirationTtl: TTL });
  return token;
}

async function getSession(kv, req) {
  const token = getToken(req);
  if (!token) return null;
  const raw = await kv.get(`session:${token}`);
  return raw ? JSON.parse(raw) : null;
}

async function deleteSession(kv, req) {
  const token = getToken(req);
  if (token) await kv.delete(`session:${token}`);
}

// ── EMAIL / PASSWORD ──────────────────────────────────────────────────────────

async function handleSignup(req, env) {
  const { email: rawEmail, password } = await req.json().catch(() => ({}));
  const email = (rawEmail || '').toLowerCase().trim();
  if (!email || !password) return err('Email and password are required.');
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) return err('Invalid email address.');
  if (password.length < 8) return err('Password must be at least 8 characters.');

  if (await env.REVISE_KV.get(`user:email:${email}`)) return err('An account with that email already exists.');

  const id = b64url(randomBytes(12));
  const user = { id, email, passwordHash: await hashPassword(password), createdAt: Date.now() };
  await env.REVISE_KV.put(`user:email:${email}`, JSON.stringify(user));
  await env.REVISE_KV.put(`user:id:${id}`, JSON.stringify(user));

  const token = await newSession(env.REVISE_KV, id, email);
  return json({ ok: true, user: { id, email } }, 200, { 'Set-Cookie': cookieSet(token) });
}

async function handleSignin(req, env) {
  const { email: rawEmail, password } = await req.json().catch(() => ({}));
  const email = (rawEmail || '').toLowerCase().trim();
  if (!email || !password) return err('Email and password are required.');

  const raw = await env.REVISE_KV.get(`user:email:${email}`);
  if (!raw) return err('Incorrect email or password.');

  const user = JSON.parse(raw);
  if (!user.passwordHash) return err('This account uses Google — please sign in with Google.');
  if (!await checkPassword(password, user.passwordHash)) return err('Incorrect email or password.');

  const token = await newSession(env.REVISE_KV, user.id, user.email);
  return json(
    { ok: true, user: safeUser(user) }, 200,
    { 'Set-Cookie': cookieSet(token) }
  );
}

async function handleSignout(req, env) {
  await deleteSession(env.REVISE_KV, req);
  return json({ ok: true }, 200, { 'Set-Cookie': cookieClear() });
}

async function handleMe(req, env) {
  const sess = await getSession(env.REVISE_KV, req);
  if (!sess) return json({ user: null });
  const raw = await env.REVISE_KV.get(`user:id:${sess.userId}`);
  if (!raw) return json({ user: null }, 200, { 'Set-Cookie': cookieClear() });
  const user = JSON.parse(raw);
  const passkeys = JSON.parse(await env.REVISE_KV.get(`passkeys:${user.id}`) || '[]');
  const hasGoogle = !!(await env.REVISE_KV.get(`google:user:${user.id}`));
  return json({ user: { ...safeUser(user), hasGoogle, passkeyCount: passkeys.length } });
}

function safeUser(u) {
  return { id: u.id, email: u.email, name: u.name, picture: u.picture };
}

// ── GOOGLE OAUTH ──────────────────────────────────────────────────────────────

async function handleGoogle(req, env) {
  const url = new URL(req.url);
  const state = b64url(randomBytes(16));
  await env.REVISE_KV.put(`oauth:${state}`, '1', { expirationTtl: 600 });
  const params = new URLSearchParams({
    client_id: env.GOOGLE_CLIENT_ID,
    redirect_uri: `${url.origin}/auth/callback`,
    response_type: 'code',
    scope: 'openid email profile',
    state,
    prompt: 'select_account',
  });
  return Response.redirect(`https://accounts.google.com/o/oauth2/v2/auth?${params}`, 302);
}

async function handleCallback(req, env) {
  const url = new URL(req.url);
  const code  = url.searchParams.get('code');
  const state = url.searchParams.get('state');
  const oerr  = url.searchParams.get('error');

  if (oerr) return Response.redirect(`/?auth_error=${encodeURIComponent(oerr)}`, 302);

  const valid = await env.REVISE_KV.get(`oauth:${state}`);
  if (!valid) return Response.redirect('/?auth_error=invalid_state', 302);
  await env.REVISE_KV.delete(`oauth:${state}`);

  const tokens = await fetch('https://oauth2.googleapis.com/token', {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      code, grant_type: 'authorization_code',
      client_id: env.GOOGLE_CLIENT_ID, client_secret: env.GOOGLE_CLIENT_SECRET,
      redirect_uri: `${url.origin}/auth/callback`,
    }),
  }).then(r => r.json());

  if (tokens.error) return Response.redirect(`/?auth_error=${encodeURIComponent(tokens.error)}`, 302);

  const profile = await fetch('https://www.googleapis.com/oauth2/v3/userinfo', {
    headers: { Authorization: `Bearer ${tokens.access_token}` },
  }).then(r => r.json());

  const email = profile.email.toLowerCase();
  let user;

  const existingId = await env.REVISE_KV.get(`google:sub:${profile.sub}`);
  if (existingId) {
    user = JSON.parse(await env.REVISE_KV.get(`user:id:${existingId}`));
    user.name    = profile.name;
    user.picture = profile.picture;
  } else {
    const byEmail = await env.REVISE_KV.get(`user:email:${email}`);
    if (byEmail) {
      user = JSON.parse(byEmail);
      user.name    ||= profile.name;
      user.picture ||= profile.picture;
    } else {
      user = { id: b64url(randomBytes(12)), email, name: profile.name, picture: profile.picture, createdAt: Date.now() };
    }
    await env.REVISE_KV.put(`google:sub:${profile.sub}`, user.id);
    await env.REVISE_KV.put(`google:user:${user.id}`, profile.sub);
  }

  await env.REVISE_KV.put(`user:email:${email}`, JSON.stringify(user));
  await env.REVISE_KV.put(`user:id:${user.id}`, JSON.stringify(user));

  const token = await newSession(env.REVISE_KV, user.id, user.email);
  return new Response(
    `<!DOCTYPE html><html><script>location.href='/'</script></html>`,
    { status: 200, headers: { 'Content-Type': 'text/html', 'Set-Cookie': cookieSet(token) } }
  );
}

// ── PASSKEYS (WebAuthn) ───────────────────────────────────────────────────────

// Minimal CBOR decoder — handles the exact subset used in WebAuthn
function decodeCBOR(input) {
  const d = input instanceof Uint8Array ? input : new Uint8Array(input);
  let i = 0;
  const next  = () => d[i++];
  const nextN = n => { const s = d.slice(i, i + n); i += n; return s; };
  function readLen(ai) {
    if (ai < 24) return ai;
    if (ai === 24) return next();
    if (ai === 25) return (next() << 8) | next();
    if (ai === 26) { let v = 0; for (let j = 0; j < 4; j++) v = (v << 8) | next(); return v >>> 0; }
    throw new Error('CBOR unsupported ai=' + ai);
  }
  function read() {
    const ib = next(), mt = ib >> 5, ai = ib & 0x1f, n = readLen(ai);
    if (mt === 0) return n;
    if (mt === 1) return -1 - n;
    if (mt === 2) return nextN(n);
    if (mt === 3) return new TextDecoder().decode(nextN(n));
    if (mt === 4) { const a = []; for (let j = 0; j < n; j++) a.push(read()); return a; }
    if (mt === 5) { const m = {}; for (let j = 0; j < n; j++) { const k = read(); m[k] = read(); } return m; }
    if (mt === 7) { if (ai === 20) return false; if (ai === 21) return true; if (ai === 22) return null; }
    throw new Error('CBOR unsupported mt=' + mt);
  }
  return read();
}

// Parse the 37+ byte authenticator data structure
function parseAuthData(authData) {
  const view = new DataView(authData.buffer, authData.byteOffset, authData.byteLength);
  const rpIdHash = authData.slice(0, 32);
  const flags    = authData[32];
  const counter  = view.getUint32(33, false); // big-endian
  let credentialData = null;
  if (flags & 0x40) { // AT bit — attested credential data present
    const credIdLen = view.getUint16(53, false);
    const credId       = authData.slice(55, 55 + credIdLen);
    const coseKeyBytes = authData.slice(55 + credIdLen);
    credentialData = { credId, coseKeyBytes };
  }
  return { rpIdHash, flags, counter, credentialData };
}

// Convert DER-encoded ECDSA signature → raw r||s (64 bytes)
function derToRaw(der) {
  let o = 2; // skip SEQUENCE tag + length
  if (der[o] !== 0x02) throw new Error('Bad DER sig');
  const rLen = der[o + 1]; o += 2;
  let r = der.slice(o, o + rLen); o += rLen;
  if (der[o] !== 0x02) throw new Error('Bad DER sig');
  const sLen = der[o + 1]; o += 2;
  let s = der.slice(o, o + sLen);
  // Strip 0x00 padding, left-pad to 32 bytes
  if (r[0] === 0) r = r.slice(1);
  if (s[0] === 0) s = s.slice(1);
  const raw = new Uint8Array(64);
  raw.set(r, 32 - r.length);
  raw.set(s, 64 - s.length);
  return raw;
}

async function sha256(data) {
  const input = typeof data === 'string' ? new TextEncoder().encode(data) : data;
  return new Uint8Array(await crypto.subtle.digest('SHA-256', input));
}

// ── REGISTER BEGIN ────────────────────────────────────────────────────────────

async function handleRegisterBegin(req, env) {
  const sess = await getSession(env.REVISE_KV, req);
  if (!sess) return err('Not signed in.', 401);

  const url = new URL(req.url);
  const rpId = url.hostname;

  const challenge = b64url(randomBytes(32));
  await env.REVISE_KV.put(`pk:challenge:${challenge}`, sess.userId, { expirationTtl: 300 });

  const userRaw = await env.REVISE_KV.get(`user:id:${sess.userId}`);
  const user = userRaw ? JSON.parse(userRaw) : { email: sess.email };

  const existing = JSON.parse(await env.REVISE_KV.get(`passkeys:${sess.userId}`) || '[]');

  return json({
    rp:      { id: rpId, name: 'Revise' },
    user:    { id: b64url(new TextEncoder().encode(sess.userId)), name: user.email, displayName: user.name || user.email },
    challenge,
    pubKeyCredParams: [{ type: 'public-key', alg: -7 }],
    timeout: 60_000,
    attestation: 'none',
    authenticatorSelection: { residentKey: 'preferred', userVerification: 'preferred' },
    excludeCredentials: existing.map(c => ({ type: 'public-key', id: c.id })),
  });
}

// ── REGISTER FINISH ───────────────────────────────────────────────────────────

async function handleRegisterFinish(req, env) {
  const sess = await getSession(env.REVISE_KV, req);
  if (!sess) return err('Not signed in.', 401);

  const url    = new URL(req.url);
  const rpId   = url.hostname;
  const origin = url.origin;
  const body   = await req.json().catch(() => ({}));
  const { challenge, id: credId, response: resp, name: credName } = body;

  if (!challenge || !credId || !resp) return err('Missing fields.');

  const owner = await env.REVISE_KV.get(`pk:challenge:${challenge}`);
  if (owner !== sess.userId) return err('Invalid or expired challenge.');
  await env.REVISE_KV.delete(`pk:challenge:${challenge}`);

  // Verify clientDataJSON
  const clientDataBytes = fromB64url(resp.clientDataJSON);
  const clientData = JSON.parse(new TextDecoder().decode(clientDataBytes));
  if (clientData.type      !== 'webauthn.create') return err('Wrong type.');
  if (clientData.challenge !== challenge)          return err('Challenge mismatch.');
  if (clientData.origin    !== origin)             return err('Origin mismatch.');

  // Decode attestationObject (CBOR)
  const attObj   = decodeCBOR(fromB64url(resp.attestationObject));
  const authData = attObj.authData instanceof Uint8Array ? attObj.authData : new Uint8Array(attObj.authData);
  const { rpIdHash, flags, credentialData } = parseAuthData(authData);

  // Verify rpId
  const expectedHash = await sha256(rpId);
  if (!expectedHash.every((b, i) => b === rpIdHash[i])) return err('rpId hash mismatch.');
  if (!(flags & 0x01)) return err('User presence flag not set.');
  if (!credentialData) return err('No credential data in authData.');

  const { credId: rawCredId, coseKeyBytes } = credentialData;

  // Persist
  const existing = JSON.parse(await env.REVISE_KV.get(`passkeys:${sess.userId}`) || '[]');
  existing.push({
    id:        credId,
    rawId:     b64url(rawCredId),
    publicKey: b64url(coseKeyBytes),
    counter:   0,
    name:      credName || `Passkey ${new Date().toLocaleDateString()}`,
    createdAt: Date.now(),
  });
  await env.REVISE_KV.put(`passkeys:${sess.userId}`, JSON.stringify(existing));
  await env.REVISE_KV.put(`pk:cred:${credId}`, sess.userId);

  return json({ ok: true });
}

// ── LOGIN BEGIN ───────────────────────────────────────────────────────────────

async function handleLoginBegin(req, env) {
  const url  = new URL(req.url);
  const body = await req.json().catch(() => ({}));
  const email = (body.email || '').toLowerCase().trim();

  const challenge = b64url(randomBytes(32));
  await env.REVISE_KV.put(`pk:challenge:${challenge}`, 'login', { expirationTtl: 300 });

  let allowCredentials = [];
  if (email) {
    const raw = await env.REVISE_KV.get(`user:email:${email}`);
    if (raw) {
      const user = JSON.parse(raw);
      const creds = JSON.parse(await env.REVISE_KV.get(`passkeys:${user.id}`) || '[]');
      allowCredentials = creds.map(c => ({ type: 'public-key', id: c.id }));
    }
  }

  return json({ challenge, rpId: url.hostname, timeout: 60_000, userVerification: 'preferred', allowCredentials });
}

// ── LOGIN FINISH ──────────────────────────────────────────────────────────────

async function handleLoginFinish(req, env) {
  const url    = new URL(req.url);
  const rpId   = url.hostname;
  const origin = url.origin;
  const body   = await req.json().catch(() => ({}));
  const { challenge, id: credId, response: resp } = body;

  if (!challenge || !credId || !resp) return err('Missing fields.');

  const challengeVal = await env.REVISE_KV.get(`pk:challenge:${challenge}`);
  if (challengeVal !== 'login') return err('Invalid or expired challenge.');
  await env.REVISE_KV.delete(`pk:challenge:${challenge}`);

  // Find which user owns this credential
  const userId = await env.REVISE_KV.get(`pk:cred:${credId}`);
  if (!userId) return err('Passkey not recognised.');

  const passkeys = JSON.parse(await env.REVISE_KV.get(`passkeys:${userId}`) || '[]');
  const cred = passkeys.find(c => c.id === credId);
  if (!cred) return err('Passkey not found.');

  // Verify clientDataJSON
  const clientDataBytes = fromB64url(resp.clientDataJSON);
  const clientData = JSON.parse(new TextDecoder().decode(clientDataBytes));
  if (clientData.type      !== 'webauthn.get') return err('Wrong type.');
  if (clientData.challenge !== challenge)       return err('Challenge mismatch.');
  if (clientData.origin    !== origin)          return err('Origin mismatch.');

  // Parse and verify authenticatorData
  const authData = fromB64url(resp.authenticatorData);
  const { rpIdHash, flags, counter } = parseAuthData(authData);

  const expectedHash = await sha256(rpId);
  if (!expectedHash.every((b, i) => b === rpIdHash[i])) return err('rpId hash mismatch.');
  if (!(flags & 0x01)) return err('User presence not set.');

  // Verify signature
  const clientDataHash = await sha256(clientDataBytes);
  const signedData = new Uint8Array(authData.length + 32);
  signedData.set(authData);
  signedData.set(clientDataHash, authData.length);

  const rawSig = derToRaw(fromB64url(resp.signature));

  const coseKey = decodeCBOR(fromB64url(cred.publicKey));
  const x = coseKey[-2], y = coseKey[-3];
  const cryptoKey = await crypto.subtle.importKey(
    'jwk',
    { kty: 'EC', crv: 'P-256', x: b64url(x), y: b64url(y) },
    { name: 'ECDSA', namedCurve: 'P-256' },
    false, ['verify']
  );
  const valid = await crypto.subtle.verify(
    { name: 'ECDSA', hash: 'SHA-256' }, cryptoKey, rawSig, signedData
  );
  if (!valid) return err('Signature verification failed.');

  // Counter check (prevents cloning attacks)
  if (counter > 0 && counter <= cred.counter) return err('Counter regression.');
  cred.counter = counter;
  await env.REVISE_KV.put(`passkeys:${userId}`, JSON.stringify(passkeys));

  const raw = await env.REVISE_KV.get(`user:id:${userId}`);
  if (!raw) return err('User not found.');
  const user = JSON.parse(raw);

  const token = await newSession(env.REVISE_KV, userId, user.email);
  return json({ ok: true, user: safeUser(user) }, 200, { 'Set-Cookie': cookieSet(token) });
}

// ── PASSKEY MANAGEMENT ────────────────────────────────────────────────────────

async function handleListPasskeys(req, env) {
  const sess = await getSession(env.REVISE_KV, req);
  if (!sess) return err('Not signed in.', 401);
  const all = JSON.parse(await env.REVISE_KV.get(`passkeys:${sess.userId}`) || '[]');
  return json({ passkeys: all.map(({ id, name, createdAt }) => ({ id, name, createdAt })) });
}

async function handleDeletePasskey(req, env) {
  const sess = await getSession(env.REVISE_KV, req);
  if (!sess) return err('Not signed in.', 401);
  const { id } = await req.json().catch(() => ({}));
  if (!id) return err('Missing id.');
  const all = JSON.parse(await env.REVISE_KV.get(`passkeys:${sess.userId}`) || '[]');
  await env.REVISE_KV.put(`passkeys:${sess.userId}`, JSON.stringify(all.filter(c => c.id !== id)));
  await env.REVISE_KV.delete(`pk:cred:${id}`);
  return json({ ok: true });
}
