const express = require('express');
const fetch = require('node-fetch');
const path = require('path');
const crypto = require('crypto');

const app = express();
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// ── SESSION STORE (in-memory, sufficient for small team) ──
const sessions = new Map();

function createSession(userData) {
  const token = crypto.randomBytes(32).toString('hex');
  sessions.set(token, { ...userData, createdAt: Date.now() });
  return token;
}

function getSession(token) {
  if (!token) return null;
  const session = sessions.get(token);
  if (!session) return null;
  // Expire after 8 hours
  if (Date.now() - session.createdAt > 8 * 60 * 60 * 1000) {
    sessions.delete(token);
    return null;
  }
  return session;
}

function getSessionToken(req) {
  const cookie = req.headers.cookie || '';
  const match = cookie.match(/cp_session=([a-f0-9]+)/);
  return match ? match[1] : null;
}

// ── AUTH MIDDLEWARE ──
function requireAuth(req, res, next) {
  const session = getSession(getSessionToken(req));
  if (!session) return res.status(401).json({ error: 'Unauthorised' });
  req.user = session;
  next();
}

// ── MICROSOFT OAUTH CONFIG ──
const TENANT_ID     = process.env.MS_TENANT_ID;
const CLIENT_ID     = process.env.MS_CLIENT_ID;
const CLIENT_SECRET = process.env.MS_CLIENT_SECRET;
const REDIRECT_URI  = process.env.REDIRECT_URI || 'https://cultureplug-production.up.railway.app/auth/callback';
const ALLOWED_DOMAIN = process.env.ALLOWED_DOMAIN || 'risingballers.co.uk';

// ── AUTH ROUTES ──
app.get('/auth/login', (req, res) => {
  const state = crypto.randomBytes(16).toString('hex');
  const params = new URLSearchParams({
    client_id: CLIENT_ID,
    redirect_uri: REDIRECT_URI,
    response_mode: 'query',
    response_type: 'code',
    scope: 'openid profile email User.Read',
    state,
  });
  res.redirect(`https://login.microsoftonline.com/${TENANT_ID}/oauth2/v2.0/authorize?${params}`);
});

app.get('/auth/callback', async (req, res) => {
  const { code, error } = req.query;
  if (error || !code) return res.redirect('/?error=auth_failed');

  try {
    const tokenRes = await fetch(`https://login.microsoftonline.com/${TENANT_ID}/oauth2/v2.0/token`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        client_id: CLIENT_ID,
        client_secret: CLIENT_SECRET,
        code,
        redirect_uri: REDIRECT_URI,
        grant_type: 'authorization_code',
        scope: 'openid profile email User.Read',
      }),
    });

    const tokenData = await tokenRes.json();
    if (!tokenData.access_token) throw new Error('No access token');

    const profileRes = await fetch('https://graph.microsoft.com/v1.0/me', {
      headers: { Authorization: `Bearer ${tokenData.access_token}` },
    });
    const profile = await profileRes.json();

    const email = (profile.mail || profile.userPrincipalName || '').toLowerCase();
    if (!email.endsWith(`@${ALLOWED_DOMAIN}`)) return res.redirect('/?error=unauthorised_domain');

    const firstName = profile.givenName || profile.displayName.split(' ')[0] || 'Team';
    const sessionToken = createSession({ name: firstName, fullName: profile.displayName, email });

    res.setHeader('Set-Cookie', `cp_session=${sessionToken}; Path=/; HttpOnly; SameSite=Lax; Max-Age=28800`);
    res.redirect('/');
  } catch (err) {
    console.error('Auth error:', err);
    res.redirect('/?error=auth_error');
  }
});

app.get('/auth/logout', (req, res) => {
  const token = getSessionToken(req);
  if (token) sessions.delete(token);
  res.setHeader('Set-Cookie', 'cp_session=; Path=/; HttpOnly; Max-Age=0');
  res.redirect('/');
});

// ── USER ENDPOINT ──
app.get('/api/me', (req, res) => {
  const session = getSession(getSessionToken(req));
  if (!session) return res.json({ authenticated: false });
  res.json({ authenticated: true, name: session.name, fullName: session.fullName, email: session.email });
});

// ── CHAT (requires auth) ──
app.post('/api/chat', requireAuth, async (req, res) => {
  try {
    const response = await fetch('https://api.anthropic.com/v1/messages', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'x-api-key': process.env.ANTHROPIC_API_KEY,
        'anthropic-version': '2023-06-01'
      },
      body: JSON.stringify(req.body)
    });
    const data = await response.json();
    res.status(response.status).json(data);
  } catch (err) {
    res.status(500).json({ error: { message: err.message } });
  }
});

app.use(express.static(path.join(__dirname, 'public')));

const PORT = process.env.PORT || 3000;
app.listen(PORT, '0.0.0.0', () => console.log(`Culture Plug running on port ${PORT}`));
