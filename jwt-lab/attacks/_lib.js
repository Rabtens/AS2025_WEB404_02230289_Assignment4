/* Shared helpers for the attack scripts. Kept tiny and dependency-free. */
const TARGET = process.env.TARGET || 'http://localhost:4000';
// The secure server, when run for this lab, is started with this exact secret
// (see README "Setup & run"). Only attack #5 needs it, to craft an otherwise
// perfectly valid but EXPIRED token and prove the secure server still rejects it.
const LAB_SECURE_SECRET = process.env.JWT_SECRET || 'lab_demo_secret_change_me_0123456789abcdef';

const b64url = (buf) => Buffer.from(buf).toString('base64').replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_');
const b64urlJson = (obj) => b64url(JSON.stringify(obj));
const decodeSeg = (seg) => JSON.parse(Buffer.from(seg.replace(/-/g, '+').replace(/_/g, '/'), 'base64').toString('utf8'));

function decodeJwt(token) {
  const [h, p] = token.split('.');
  return { header: decodeSeg(h), payload: decodeSeg(p) };
}

async function post(path, body) {
  const res = await fetch(`${TARGET}${path}`, {
    method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body),
  });
  return { status: res.status, body: await res.json().catch(() => ({})) };
}

async function getAuth(path, token) {
  const res = await fetch(`${TARGET}${path}`, { headers: { authorization: `Bearer ${token}` } });
  return { status: res.status, body: await res.json().catch(() => ({})) };
}

function banner(title) {
  console.log('\n' + '='.repeat(68));
  console.log(title);
  console.log('='.repeat(68));
  console.log(`Target server : ${TARGET}`);
}

function show(label, val) {
  console.log(`\n[${label}]`);
  console.log(typeof val === 'string' ? val : JSON.stringify(val, null, 2));
}

function verdict(ok, msg) {
  console.log('\n' + (ok ? '>>> ATTACK SUCCEEDED: ' : '>>> ATTACK BLOCKED:  ') + msg);
}

module.exports = { TARGET, LAB_SECURE_SECRET, b64url, b64urlJson, decodeSeg, decodeJwt, post, getAuth, banner, show, verdict };
