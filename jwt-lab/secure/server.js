/*
 * SECURE JWT AUTH SERVER  —  the hardened counterpart
 * ====================================================
 * Re-implements the same API as ../vulnerable/server.js but defeats every
 * attack in ../attacks. Each mitigation is tagged `// FIX #N` mapped to the
 * attack number it stops.
 */
const express = require('express');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const cookieParser = require('cookie-parser');
const rateLimit = require('express-rate-limit');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const app = express();
app.use(express.json());
app.use(cookieParser());

const PORT = process.env.SECURE_PORT || 5000;

// FIX #2: strong secret sourced from the environment, never hardcoded.
//   A 256-bit random secret is not in any wordlist and is infeasible to brute
//   force. We fall back to a random per-process secret if the env var is unset
//   (so the lab still runs), and warn.
let SECRET = process.env.JWT_SECRET;
if (!SECRET) {
  SECRET = crypto.randomBytes(32).toString('hex');
  console.warn('[secure] JWT_SECRET not set — generated a random 256-bit secret for this run.');
}

// Issuer/audience we pin. FIX #4 (partly): claims are validated, not trusted.
const ISSUER = 'jwt-lab-secure';
const AUDIENCE = 'jwt-lab-clients';
const ACCESS_TTL = '5m';       // FIX #5: short-lived access tokens.
const REFRESH_TTL_MS = 1000 * 60 * 60 * 24; // 24h refresh lifetime.

const users = {};              // username -> { username, passwordHash, role }
const accessBlacklist = new Set();   // FIX (revocation): jti of revoked access tokens.
const refreshStore = new Map();      // jti -> { username, expiresAt }  (rotation + revocation)

(function seed() {
  users['admin'] = { username: 'admin', passwordHash: bcrypt.hashSync('SuperAdminPass!', 10), role: 'admin' };
  users['alice'] = { username: 'alice', passwordHash: bcrypt.hashSync('password1', 10), role: 'user' };
})();

// FIX #6: only NON-sensitive, authorization-relevant claims go in the token.
//   No email, no SSN, no PII. The payload is still world-readable (base64), so
//   it must never carry secrets. Role is included but the token is signed with
//   a strong key + algorithm allowlist so it cannot be tampered (see FIX #4).
function issueAccessToken(user) {
  const jti = crypto.randomUUID();
  const token = jwt.sign(
    { role: user.role },              // minimal payload
    SECRET,
    {
      algorithm: 'HS256',             // FIX #1/#3: we sign with exactly one alg
      expiresIn: ACCESS_TTL,          // FIX #5: exp enforced
      issuer: ISSUER,                 // FIX #4: iss
      audience: AUDIENCE,             // FIX #4: aud
      subject: user.username,         // sub
      jwtid: jti,                     // enables revocation
      notBefore: 0,                   // nbf
    }
  );
  return { token, jti };
}

function issueRefreshToken(user) {
  const jti = crypto.randomUUID();
  refreshStore.set(jti, { username: user.username, expiresAt: Date.now() + REFRESH_TTL_MS });
  const token = jwt.sign({ typ: 'refresh' }, SECRET, {
    algorithm: 'HS256', expiresIn: '24h', issuer: ISSUER, audience: AUDIENCE,
    subject: user.username, jwtid: jti,
  });
  return token;
}

// ---- Rate limiting on auth routes (FIX: brute force / abuse) --------------
const authLimiter = rateLimit({
  windowMs: 60 * 1000,   // 1 minute
  max: 10,               // 10 attempts / minute / IP
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'too many attempts, slow down' },
});

// ---- POST /register -------------------------------------------------------
app.post('/register', authLimiter, async (req, res) => {
  const { username, password } = req.body || {};
  if (!username || !password) return res.status(400).json({ error: 'username and password required' });
  if (password.length < 8) return res.status(400).json({ error: 'password too short' });
  if (users[username]) return res.status(409).json({ error: 'user exists' });
  users[username] = { username, passwordHash: await bcrypt.hash(password, 12), role: 'user' };
  return res.status(201).json({ message: 'registered', username });
});

// ---- POST /login ----------------------------------------------------------
app.post('/login', authLimiter, async (req, res) => {
  const { username, password } = req.body || {};
  const user = users[username];
  if (!user || !(await bcrypt.compare(password, user.passwordHash))) {
    return res.status(401).json({ error: 'invalid credentials' });
  }
  const { token: accessToken } = issueAccessToken(user);
  const refreshToken = issueRefreshToken(user);

  // FIX (storage): tokens returned as httpOnly, SameSite, Secure cookies so
  //   client-side JS (XSS) cannot read them — unlike localStorage.
  const cookieOpts = { httpOnly: true, sameSite: 'strict', secure: true, path: '/' };
  res.cookie('access_token', accessToken, { ...cookieOpts, maxAge: 5 * 60 * 1000 });
  res.cookie('refresh_token', refreshToken, { ...cookieOpts, maxAge: REFRESH_TTL_MS });

  // Also return the access token in the body so the lab's curl/attack scripts
  // can exercise the Authorization: Bearer flow. (A real SPA would rely on the
  // cookie only.)
  return res.json({ message: 'logged in', access_token: accessToken });
});

// ---- POST /refresh — refresh-token ROTATION -------------------------------
app.post('/refresh', authLimiter, (req, res) => {
  const token = req.cookies.refresh_token || (req.body && req.body.refresh_token);
  if (!token) return res.status(401).json({ error: 'missing refresh token' });
  let decoded;
  try {
    decoded = jwt.verify(token, SECRET, { algorithms: ['HS256'], issuer: ISSUER, audience: AUDIENCE });
  } catch (e) {
    return res.status(401).json({ error: 'invalid refresh token' });
  }
  const record = refreshStore.get(decoded.jti);
  if (!record || record.expiresAt < Date.now()) {
    return res.status(401).json({ error: 'refresh token revoked or expired' });
  }
  // ROTATION: invalidate the old refresh jti, issue a fresh pair.
  refreshStore.delete(decoded.jti);
  const user = users[decoded.sub];
  if (!user) return res.status(401).json({ error: 'unknown user' });
  const { token: accessToken } = issueAccessToken(user);
  const newRefresh = issueRefreshToken(user);
  const cookieOpts = { httpOnly: true, sameSite: 'strict', secure: true, path: '/' };
  res.cookie('access_token', accessToken, { ...cookieOpts, maxAge: 5 * 60 * 1000 });
  res.cookie('refresh_token', newRefresh, { ...cookieOpts, maxAge: REFRESH_TTL_MS });
  return res.json({ message: 'rotated', access_token: accessToken });
});

// ---- POST /logout — revoke -----------------------------------------------
app.post('/logout', (req, res) => {
  const auth = req.headers.authorization || '';
  const token = auth.startsWith('Bearer ') ? auth.slice(7) : (req.cookies.access_token || '');
  try {
    const decoded = jwt.verify(token, SECRET, { algorithms: ['HS256'], issuer: ISSUER, audience: AUDIENCE });
    if (decoded.jti) accessBlacklist.add(decoded.jti); // revoke access token
  } catch (_) { /* ignore */ }
  const rt = req.cookies.refresh_token;
  if (rt) { try { const d = jwt.verify(rt, SECRET, { algorithms: ['HS256'] }); refreshStore.delete(d.jti); } catch (_) {} }
  res.clearCookie('access_token'); res.clearCookie('refresh_token');
  return res.json({ message: 'logged out' });
});

// ---- Auth middleware (the heart of the fixes) -----------------------------
function authenticate(req, res, next) {
  const auth = req.headers.authorization || '';
  const token = auth.startsWith('Bearer ') ? auth.slice(7) : (req.cookies.access_token || '');
  if (!token) return res.status(401).json({ error: 'missing token' });
  try {
    const decoded = jwt.verify(token, SECRET, {
      algorithms: ['HS256'],   // FIX #1 (alg:none) + FIX #3 (RS256->HS256): strict allowlist.
      issuer: ISSUER,          // FIX #4: reject tokens not minted by us.
      audience: AUDIENCE,      // FIX #4
      clockTolerance: 5,       // small skew allowance for iat/nbf/exp
      // exp is enforced by the library automatically => FIX #5 (no replay).
    });
    if (decoded.jti && accessBlacklist.has(decoded.jti)) {   // FIX (revocation)
      return res.status(401).json({ error: 'token revoked' });
    }
    req.user = decoded;
    next();
  } catch (e) {
    return res.status(401).json({ error: 'invalid token', detail: e.message });
  }
}

app.get('/profile', authenticate, (req, res) => res.json({ message: 'profile data', user: req.user }));

app.get('/admin', authenticate, (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'admins only' });
  return res.json({ message: 'admin panel', user: req.user });
});

// Same route name as the vuln server's RSA endpoint, but hardened: it pins
// RS256 AND the public key, so an HS256-signed forgery is rejected. (FIX #3)
const PUBLIC_KEY = fs.readFileSync(path.join(__dirname, '..', 'keys', 'public.pem'), 'utf8');
app.get('/rsa-profile', (req, res) => {
  const auth = req.headers.authorization || '';
  const token = auth.startsWith('Bearer ') ? auth.slice(7) : '';
  try {
    const decoded = jwt.verify(token, PUBLIC_KEY, {
      algorithms: ['RS256'],   // FIX #3: only RS256 accepted here; HS256 forgery rejected.
      issuer: ISSUER, audience: AUDIENCE,
    });
    return res.json({ message: 'rsa-protected profile', user: decoded });
  } catch (e) {
    return res.status(401).json({ error: 'invalid token', detail: e.message });
  }
});

if (require.main === module) {
  app.listen(PORT, () => console.log(`[SECURE] server listening on http://localhost:${PORT}`));
}
module.exports = app;
