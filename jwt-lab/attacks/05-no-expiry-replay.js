/*
 * ATTACK 05 — missing-expiry replay
 * ----------------------------------
 * Root cause: the vulnerable server issues tokens with NO `exp` claim, so a
 * token stolen once (logs, referrer headers, a shared machine) is valid
 * forever and can be replayed indefinitely. Against the secure server we craft
 * an otherwise-valid but EXPIRED token to prove exp is enforced.
 *
 * Run:  node attacks/05-no-expiry-replay.js
 *       TARGET=http://localhost:5000 node attacks/05-no-expiry-replay.js
 */
const jwt = require('jsonwebtoken');
const { post, getAuth, banner, show, verdict, decodeJwt, LAB_SECURE_SECRET, TARGET } = require('./_lib');

(async () => {
  banner('ATTACK 05 — missing-expiry token replay');

  const login = await post('/login', { username: 'alice', password: 'password1' });
  const token = login.body.token || login.body.access_token;
  if (!token) { show('Login failed', login); return; }
  const decoded = decodeJwt(token);
  show('Captured token', token);
  show('Claims (note presence/absence of "exp")', decoded.payload);
  show('Has exp?', decoded.payload.exp ? `yes, expires ${new Date(decoded.payload.exp * 1000).toISOString()}` : 'NO exp — valid forever');

  // Replay the captured token as-is (simulating reuse long after issuance).
  const replay = await getAuth('/profile', token);
  show(`Replay of captured token  (HTTP ${replay.status})`, replay.body);

  // Against the secure server, also demonstrate that an EXPIRED token is rejected.
  if (TARGET.includes('5000')) {
    const expired = jwt.sign(
      { role: 'user' },
      LAB_SECURE_SECRET,
      { algorithm: 'HS256', issuer: 'jwt-lab-secure', audience: 'jwt-lab-clients',
        subject: 'alice', expiresIn: -60 } // already expired 60s ago
    );
    show('Crafted EXPIRED token (exp in the past)', expired);
    const exp = await getAuth('/profile', expired);
    show(`Expired-token attempt  (HTTP ${exp.status})`, exp.body);
    const blocked = exp.status === 401;
    verdict(!blocked, blocked ? 'secure server rejected the expired token (exp enforced).'
                             : 'expired token still accepted!');
    return;
  }

  const ok = replay.status === 200;
  verdict(ok, ok ? 'token has no exp and replays successfully — reusable forever.'
               : 'replay rejected.');
})();
