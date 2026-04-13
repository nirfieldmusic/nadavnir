const express = require('express');
const fs = require('fs');
const path = require('path');
const app = express();
const PORT = process.env.PORT || 3000;
const CONTENT_FILE = path.join(__dirname, 'content.json');

app.use(express.json());
app.use(express.static(__dirname));

app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'nadav-nir-sound.html'));
});

function getAdminPassword() {
  // Use environment variable if set (production), otherwise fall back to content.json (local)
  if (process.env.ADMIN_PASSWORD) return process.env.ADMIN_PASSWORD;
  const data = JSON.parse(fs.readFileSync(CONTENT_FILE, 'utf8'));
  return data.admin_password;
}

// Read content
app.get('/api/content', (req, res) => {
  const data = JSON.parse(fs.readFileSync(CONTENT_FILE, 'utf8'));
  // Don't expose password
  const { admin_password, ...safe } = data;
  res.json(safe);
});

// Save content (password protected)
app.post('/api/content', (req, res) => {
  const { password, ...newContent } = req.body;
  if (password !== getAdminPassword()) {
    return res.status(401).json({ error: 'Wrong password' });
  }
  const current = JSON.parse(fs.readFileSync(CONTENT_FILE, 'utf8'));
  const updated = { ...newContent, admin_password: current.admin_password };
  fs.writeFileSync(CONTENT_FILE, JSON.stringify(updated, null, 2), 'utf8');
  res.json({ ok: true });
});

// Change password
app.post('/api/change-password', (req, res) => {
  const { oldPassword, newPassword } = req.body;
  if (oldPassword !== getAdminPassword()) {
    return res.status(401).json({ error: 'Wrong password' });
  }
  if (process.env.ADMIN_PASSWORD) {
    return res.status(400).json({ error: 'Password is managed via environment variable on the server.' });
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
