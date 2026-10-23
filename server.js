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
app.use((req, res, next) => {
  res.set({
    'X-Content-Type-Options': 'nosniff',
    'X-Frame-Options': 'SAMEORIGIN',
    'Referrer-Policy': 'strict-origin-when-cross-origin',
    'Permissions-Policy': 'camera=(), microphone=(), geolocation=()',
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

// The admin page should never show up in search results.
app.use('/admin.html', (req, res, next) => {
  res.set('X-Robots-Tag', 'noindex, nofollow');
  next();
});

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
