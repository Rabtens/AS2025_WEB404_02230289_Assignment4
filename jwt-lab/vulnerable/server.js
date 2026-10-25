/*
 * VULNERABLE JWT AUTH SERVER  —  FOR THE TEACHING LAB ONLY
 * =========================================================
 * This server is DELIBERATELY insecure so the attack scripts in ../attacks
 * succeed against it. Every intentional weakness is tagged `// VULN:`.
 * NEVER deploy anything resembling this. See ../secure/server.js for the fix.
 */
const express = require('express');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const app = express();
app.use(express.json());

const PORT = process.env.VULN_PORT || 4000;

// VULN #2: weak, hardcoded, guessable HMAC secret committed in source.
//          A wordlist/brute-force attack recovers it in milliseconds.
const SECRET = 'secret123';

// RSA public key is (correctly) public — but the vuln server will happily
// verify HS256 tokens with it as the HMAC key (VULN #3, algorithm confusion).
const PUBLIC_KEY = fs.readFileSync(path.join(__dirname, '..', 'keys', 'public.pem'), 'utf8');

// ---- In-memory user store -------------------------------------------------
const users = {}; // username -> { username, passwordHash, role, email, ssn }

// Seed an admin so claim-tampering / privilege escalation is demonstrable.
(function seed() {
  users['admin'] = {
    username: 'admin',
    passwordHash: bcrypt.hashSync('SuperAdminPass!', 10),
    role: 'admin',
    email: 'admin@lab.local',
    ssn: '999-00-0001',
  };
  users['alice'] = {
    username: 'alice',
    passwordHash: bcrypt.hashSync('password1', 10),
    role: 'user',
    email: 'alice@lab.local',
    ssn: '123-45-6789',
  };
})();

// ---- POST /register -------------------------------------------------------
app.post('/register', async (req, res) => {
  const { username, password, email } = req.body || {};
  if (!username || !password) return res.status(400).json({ error: 'username and password required' });
  if (users[username]) return res.status(409).json({ error: 'user exists' });
  const passwordHash = await bcrypt.hash(password, 10); // password hashing done right
  users[username] = { username, passwordHash, role: 'user', email: email || `${username}@lab.local`, ssn: '000-00-0000' };
  return res.status(201).json({ message: 'registered', username });
});

// ---- POST /login ----------------------------------------------------------
app.post('/login', async (req, res) => {
  const { username, password } = req.body || {};
  const user = users[username];
  if (!user) return res.status(401).json({ error: 'invalid credentials' });
  const ok = await bcrypt.compare(password, user.passwordHash);
  if (!ok) return res.status(401).json({ error: 'invalid credentials' });

  // VULN #4 + #6: sensitive PII (email, ssn) and the authorization-critical
  //               `role` claim are placed directly in the (only base64-encoded,
  //               NOT encrypted) payload where anyone can read/see them.
  // VULN #5: no `exp` — the token is valid forever and can be replayed.
  const payload = {
    sub: user.username,
    role: user.role,
    email: user.email,
    ssn: user.ssn,
  };
  const token = jwt.sign(payload, SECRET, { algorithm: 'HS256' }); // no expiresIn
  return res.json({ token });
});

// ---- NAIVE, DELIBERATELY BROKEN JWT VERIFIER ------------------------------
// This hand-rolled verifier reproduces the CLASSIC library flaws that modern
// hardened libraries (jsonwebtoken v9+) now refuse to exhibit. It reads the
// algorithm straight from the attacker-controlled header and dispatches on it
// with NO allowlist — which is exactly the historical vulnerability.
//   VULN #1: alg:"none" is honoured -> signature check skipped entirely.
//   VULN #3: alg is trusted, so an RS256 endpoint that passes its PUBLIC key
//            here will HMAC-verify an HS256 forgery with that public key.
// It also never checks `exp` (VULN #5).
const b64urlDecode = (s) => Buffer.from(s.replace(/-/g, '+').replace(/_/g, '/'), 'base64');
function naiveVerify(token, key) {
  const [h, p, sig] = token.split('.');
  const header = JSON.parse(b64urlDecode(h).toString('utf8'));
  const payload = JSON.parse(b64urlDecode(p).toString('utf8'));
  const signingInput = `${h}.${p}`;
  const alg = header.alg; // VULN: algorithm taken from the token header.

  if (alg === 'none') {
    return payload; // VULN #1: no signature required.
  }
  if (alg === 'HS256') {
    const expected = crypto.createHmac('sha256', key).update(signingInput).digest('base64url');
    if (expected !== sig) throw new Error('bad HMAC signature');
    return payload; // VULN #3 when `key` is actually the RSA public key.
  }
  if (alg === 'RS256') {
    const v = crypto.createVerify('RSA-SHA256');
    v.update(signingInput); v.end();
    if (!v.verify(key, b64urlDecode(sig))) throw new Error('bad RSA signature');
    return payload;
  }
  throw new Error(`unsupported alg ${alg}`);
}

// ---- Auth middleware ------------------------------------------------------
function authenticate(req, res, next) {
  const auth = req.headers.authorization || '';
  const token = auth.startsWith('Bearer ') ? auth.slice(7) : auth;
  if (!token) return res.status(401).json({ error: 'missing token' });
  try {
    const decoded = naiveVerify(token, SECRET); // HMAC key = weak secret
    req.user = decoded;
    next();
  } catch (e) {
    return res.status(401).json({ error: 'invalid token', detail: e.message });
  }
}

// A second verifier for the algorithm-confusion demo: it hands the PUBLIC KEY
// to the same naive verifier. For a genuine RS256 token that RSA-verifies; but
// because `alg` is trusted, an attacker's HS256 token is HMAC-verified with the
// public key string as the secret. (VULN #3, the classic misconfiguration.)
function authenticateRSA(req, res, next) {
  const auth = req.headers.authorization || '';
  const token = auth.startsWith('Bearer ') ? auth.slice(7) : auth;
  if (!token) return res.status(401).json({ error: 'missing token' });
  try {
    const decoded = naiveVerify(token, PUBLIC_KEY); // VULN #3: no allowlist
    req.user = decoded;
    next();
  } catch (e) {
    return res.status(401).json({ error: 'invalid token', detail: e.message });
  }
}

// ---- GET /profile (protected) --------------------------------------------
app.get('/profile', authenticate, (req, res) => {
  return res.json({ message: 'profile data', user: req.user });
});

// ---- GET /admin (protected, admin only) ----------------------------------
app.get('/admin', authenticate, (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'admins only' });
  return res.json({ message: 'TOP SECRET admin panel', secretFlag: 'LAB{priv-esc-successful}', user: req.user });
});

// ---- GET /rsa-profile (protected via RSA verifier) ------------------------
// Issues/consumes RS256 tokens; used by the algorithm-confusion attack.
app.get('/rsa-profile', authenticateRSA, (req, res) => {
  return res.json({ message: 'rsa-protected profile', user: req.user });
});

// Issue an RS256 token (so the confusion attack has a legit RS256 baseline).
app.post('/rsa-login', async (req, res) => {
  const { username, password } = req.body || {};
  const user = users[username];
  if (!user || !bcrypt.compareSync(password, user.passwordHash)) {
    return res.status(401).json({ error: 'invalid credentials' });
  }
  const PRIVATE_KEY = fs.readFileSync(path.join(__dirname, '..', 'keys', 'private.pem'), 'utf8');
  const token = jwt.sign({ sub: user.username, role: user.role }, PRIVATE_KEY, { algorithm: 'RS256' });
  return res.json({ token });
});

if (require.main === module) {
  app.listen(PORT, () => console.log(`[VULNERABLE] server listening on http://localhost:${PORT}`));
}
module.exports = app;
