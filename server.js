const express = require('express');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const app = express();
const PORT = process.env.PORT || 3000;
const CONTENT_FILE = path.join(__dirname, 'content.json');

// Render and Cloudflare sit in front of the app, so the real client IP
// arrives in a header rather than on the socket.
app.set('trust proxy', true);
app.disable('x-powered-by');

// ── Security headers ─────────────────────────────────────────────
// CSP is intentionally permissive on inline scripts/styles because the site
// uses inline handlers and inline styles throughout; it still restricts which
// external origins may load scripts, framing, fonts and network calls.
const CSP = [
  "default-src 'self'",
  "base-uri 'self'",
  "object-src 'none'",
  "script-src 'self' 'unsafe-inline'",
  "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com",
  "font-src 'self' https://fonts.gstatic.com",
  "img-src 'self' data: https:",
  "frame-src https://www.youtube.com https://www.youtube-nocookie.com https://player.vimeo.com",
  "connect-src 'self' https://formspree.io",
  "form-action 'self' https://formspree.io",
  "frame-ancestors 'self'",
  "upgrade-insecure-requests",
].join('; ');

app.use((req, res, next) => {
  res.set({
    'X-Content-Type-Options': 'nosniff',
    'X-Frame-Options': 'SAMEORIGIN',
    'Referrer-Policy': 'strict-origin-when-cross-origin',
    'Permissions-Policy': 'camera=(), microphone=(), geolocation=()',
    'Content-Security-Policy': CSP,
    'Strict-Transport-Security': 'max-age=31536000; includeSubDomains',
  });
  next();
});

// ── Keep server-side files private ───────────────────────────────
// express.static used to serve the whole folder, including server.js,
// package.json and content.json. Only the site's own assets are public now.
const PRIVATE_FILES = new Set(['server.js', 'package.json', 'package-lock.json', 'content.json']);
app.use((req, res, next) => {
  const name = path.basename(decodeURIComponent(req.path)).toLowerCase();
  if (PRIVATE_FILES.has(name)) return res.status(404).end();
  next();
});

// ── Cloudflare Access check for everything admin ─────────────────
// Cloudflare Access puts a login screen in front of /admin.html. That only
// helps if nobody can reach the server another way (the onrender.com address,
// or calling the API directly). So the server itself checks the signed token
// Access attaches to every approved visitor, and refuses admin requests
// without a valid one.
const ACCESS_TEAM = process.env.CF_ACCESS_TEAM || 'solitary-frog-dff9';
const ACCESS_AUD = process.env.CF_ACCESS_AUD || '555dc2350cc0026a38a854e59202dc6b5ed82735f6c06e2cf80d9589cd02ecd4';
const ACCESS_ISSUER = `https://${ACCESS_TEAM}.cloudflareaccess.com`;
const ACCESS_CERTS_URL = process.env.CF_ACCESS_CERTS_URL || `${ACCESS_ISSUER}/cdn-cgi/access/certs`;
const ADMIN_EMAILS = (process.env.ADMIN_EMAILS || 'nirfield13@gmail.com')
  .split(',').map(e => e.trim().toLowerCase()).filter(Boolean);

let accessKeys = new Map();   // kid -> KeyObject
let accessKeysFetchedAt = 0;

async function loadAccessKeys(force) {
  const fresh = Date.now() - accessKeysFetchedAt < 60 * 60 * 1000;
  if (!force && fresh && accessKeys.size) return;
  if (force && Date.now() - accessKeysFetchedAt < 30 * 1000) return; // don't hammer
  const res = await fetch(ACCESS_CERTS_URL);
  if (!res.ok) throw new Error('certs fetch failed: ' + res.status);
  const { keys = [] } = await res.json();
  const next = new Map();
  for (const jwk of keys) {
    if (jwk.kid && jwk.kty === 'RSA') next.set(jwk.kid, crypto.createPublicKey({ key: jwk, format: 'jwk' }));
  }
  accessKeys = next;
  accessKeysFetchedAt = Date.now();
}

function b64urlJson(part) {
  return JSON.parse(Buffer.from(part, 'base64url').toString('utf8'));
}

async function verifyAccessToken(token) {
  const parts = String(token || '').split('.');
  if (parts.length !== 3) return null;
  let header, payload;
  try { header = b64urlJson(parts[0]); payload = b64urlJson(parts[1]); } catch { return null; }
  if (header.alg !== 'RS256' || !header.kid) return null;

  await loadAccessKeys(false);
  if (!accessKeys.has(header.kid)) await loadAccessKeys(true); // keys rotate
  const key = accessKeys.get(header.kid);
  if (!key) return null;

  const ok = crypto.verify('sha256', Buffer.from(parts[0] + '.' + parts[1]), key,
                           Buffer.from(parts[2], 'base64url'));
  if (!ok) return null;

  const now = Math.floor(Date.now() / 1000);
  const aud = Array.isArray(payload.aud) ? payload.aud : [payload.aud];
  if (!aud.includes(ACCESS_AUD)) return null;
  if (payload.iss !== ACCESS_ISSUER) return null;
  if (typeof payload.exp !== 'number' || payload.exp < now - 30) return null;
  if (typeof payload.nbf === 'number' && payload.nbf > now + 30) return null;
  const email = String(payload.email || '').toLowerCase();
  if (!ADMIN_EMAILS.includes(email)) return null;
  return payload;
}

function readCookie(req, name) {
  const header = req.get('cookie') || '';
  for (const part of header.split(';')) {
    const i = part.indexOf('=');
    if (i > 0 && part.slice(0, i).trim() === name) return decodeURIComponent(part.slice(i + 1).trim());
  }
  return '';
}

function isLocalDev() {
  // Only when you run the site on your own computer with:  ACCESS_DEV=1 npm start
  // Render never sets this, so on the live site the check always runs.
  return process.env.ACCESS_DEV === '1';
}

async function requireAccess(req, res, next) {
  res.set('Cache-Control', 'no-store');
  if (isLocalDev()) return next();
  try {
    const token = req.get('cf-access-jwt-assertion') || readCookie(req, 'CF_Authorization');
    if (await verifyAccessToken(token)) return next();
  } catch (err) {
    console.error('Access check failed:', err.message);
  }
  res.status(403).set('X-Robots-Tag', 'noindex, nofollow');
  if (req.path.startsWith('/api/')) return res.json({ error: 'Not authorized' });
  res.type('text/plain').send('Forbidden');
}

// The admin page should never show up in search results.
app.use('/admin.html', (req, res, next) => {
  res.set('X-Robots-Tag', 'noindex, nofollow');
  next();
});
app.use('/admin.html', requireAccess);
app.post('/api/content', requireAccess);
app.post('/api/change-password', requireAccess);

app.use(express.json({ limit: '1mb' }));
app.use(express.static(__dirname, { dotfiles: 'ignore', index: false }));

app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'nadav-nir-sound.html'));
});

// ── Password checking ────────────────────────────────────────────
function getAdminPassword() {
  // Use environment variable if set (production), otherwise fall back to content.json (local)
  if (process.env.ADMIN_PASSWORD) return process.env.ADMIN_PASSWORD;
  const data = JSON.parse(fs.readFileSync(CONTENT_FILE, 'utf8'));
  return data.admin_password;
}

// Constant-time comparison, so response timing reveals nothing about the password.
function passwordMatches(given) {
  const expected = getAdminPassword();
  if (typeof given !== 'string' || typeof expected !== 'string' || !expected) return false;
  const a = crypto.createHash('sha256').update(given).digest();
  const b = crypto.createHash('sha256').update(expected).digest();
  return crypto.timingSafeEqual(a, b);
}

// ── Brute-force protection ───────────────────────────────────────
// At most 10 wrong passwords per IP per 15 minutes.
const WINDOW_MS = 15 * 60 * 1000;
const MAX_FAILS = 10;
const failures = new Map(); // ip -> { count, first }

function clientIp(req) {
  return req.get('cf-connecting-ip') || req.ip || 'unknown';
}
function isLockedOut(ip) {
  const f = failures.get(ip);
  if (!f) return false;
  if (Date.now() - f.first > WINDOW_MS) { failures.delete(ip); return false; }
  return f.count >= MAX_FAILS;
}
function recordFailure(ip) {
  const f = failures.get(ip);
  if (!f || Date.now() - f.first > WINDOW_MS) failures.set(ip, { count: 1, first: Date.now() });
  else f.count++;
}
setInterval(() => {
  const now = Date.now();
  for (const [ip, f] of failures) if (now - f.first > WINDOW_MS) failures.delete(ip);
}, WINDOW_MS).unref();

function checkPassword(req, res, given) {
  const ip = clientIp(req);
  if (isLockedOut(ip)) {
    res.status(429).json({ error: 'Too many attempts. Try again in 15 minutes.' });
    return false;
  }
  if (!passwordMatches(given)) {
    recordFailure(ip);
    res.status(401).json({ error: 'Wrong password' });
    return false;
  }
  failures.delete(ip);
  return true;
}

// ── API ──────────────────────────────────────────────────────────
// Read content
app.get('/api/content', (req, res) => {
  const data = JSON.parse(fs.readFileSync(CONTENT_FILE, 'utf8'));
  // Don't expose password
  const { admin_password, ...safe } = data;
  res.json(safe);
});

// Save content (password protected)
app.post('/api/content', (req, res) => {
  const { password, ...newContent } = req.body || {};
  if (!checkPassword(req, res, password)) return;
  const current = JSON.parse(fs.readFileSync(CONTENT_FILE, 'utf8'));
  const updated = { ...newContent, admin_password: current.admin_password };
  fs.writeFileSync(CONTENT_FILE, JSON.stringify(updated, null, 2), 'utf8');
  res.json({ ok: true });
});

// Change password
app.post('/api/change-password', (req, res) => {
  const { oldPassword, newPassword } = req.body || {};
  if (!checkPassword(req, res, oldPassword)) return;
  if (process.env.ADMIN_PASSWORD) {
    return res.status(400).json({ error: 'Password is managed via environment variable on the server.' });
  }
  if (typeof newPassword !== 'string' || newPassword.length < 10) {
    return res.status(400).json({ error: 'New password must be at least 10 characters.' });
  }
  const current = JSON.parse(fs.readFileSync(CONTENT_FILE, 'utf8'));
  current.admin_password = newPassword;
  fs.writeFileSync(CONTENT_FILE, JSON.stringify(current, null, 2), 'utf8');
  res.json({ ok: true });
});

app.listen(PORT, () => {
  console.log(`\n✅  Site running at:   http://localhost:${PORT}/nadav-nir-sound.html`);
  console.log(`✏️   Admin panel at:   http://localhost:${PORT}/admin.html\n`);
});
