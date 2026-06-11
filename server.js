const express = require('express');
const fetch = require('node-fetch');
const path = require('path');
const crypto = require('crypto');
const { Pool } = require('pg');

const app = express();
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// ── POSTGRES ──
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false },
  connectionTimeoutMillis: 5000,
  idleTimeoutMillis: 30000,
  max: 10
});

pool.query(`
  CREATE TABLE IF NOT EXISTS media_plans (
    id          SERIAL PRIMARY KEY,
    user_email  TEXT NOT NULL,
    name        TEXT NOT NULL,
    data        JSONB NOT NULL,
    created_at  TIMESTAMPTZ DEFAULT NOW(),
    updated_at  TIMESTAMPTZ DEFAULT NOW()
  );
  CREATE TABLE IF NOT EXISTS sessions (
    token       TEXT PRIMARY KEY,
    data        JSONB NOT NULL,
    created_at  TIMESTAMPTZ DEFAULT NOW()
  );
  CREATE TABLE IF NOT EXISTS usage_logs (
    id          SERIAL PRIMARY KEY,
    user_email  TEXT NOT NULL,
    user_name   TEXT,
    mode        TEXT NOT NULL,
    logged_at   TIMESTAMPTZ DEFAULT NOW()
  );
  CREATE TABLE IF NOT EXISTS conversations (
    id          SERIAL PRIMARY KEY,
    user_email  TEXT NOT NULL,
    title       TEXT NOT NULL,
    mode        TEXT NOT NULL DEFAULT 'general',
    history     JSONB NOT NULL DEFAULT '[]',
    created_at  TIMESTAMPTZ DEFAULT NOW(),
    updated_at  TIMESTAMPTZ DEFAULT NOW()
  );
  CREATE INDEX IF NOT EXISTS conversations_user_email_idx ON conversations (user_email, updated_at DESC);
`).then(() => console.log('DB tables ready'))
  .catch(err => console.error('DB init error:', err.message));

// ── SESSION STORE ──
async function createSession(userData) {
  const token = crypto.randomBytes(32).toString('hex');
  console.log('DB: inserting session...');
  await pool.query(
    'INSERT INTO sessions (token, data) VALUES ($1, $2)',
    [token, JSON.stringify({ ...userData, createdAt: Date.now() })]
  );
  console.log('DB: session inserted OK');
  return token;
}

async function getSession(token) {
  if (!token) return null;
  try {
    const result = await pool.query('SELECT data FROM sessions WHERE token = $1', [token]);
    if (!result.rows.length) return null;
    const session = result.rows[0].data;
    if (Date.now() - session.createdAt > 8 * 60 * 60 * 1000) {
      await pool.query('DELETE FROM sessions WHERE token = $1', [token]);
      return null;
    }
    return session;
  } catch (err) {
    console.error('getSession error:', err.message);
    return null;
  }
}

async function deleteSession(token) {
  await pool.query('DELETE FROM sessions WHERE token = $1', [token]);
}

function getSessionToken(req) {
  const cookie = req.headers.cookie || '';
  const match = cookie.match(/cp_session=([a-f0-9]+)/);
  return match ? match[1] : null;
}

// ── AUTH MIDDLEWARE ──
async function requireAuth(req, res, next) {
  const session = await getSession(getSessionToken(req));
  if (!session) return res.status(401).json({ error: 'Unauthorised' });
  req.user = session;
  next();
}

async function requireAdmin(req, res, next) {
  const session = await getSession(getSessionToken(req));
  if (!session) return res.redirect('/auth/login');
  if (session.email !== 'eni@risingballers.co.uk') return res.status(403).send('Forbidden');
  req.user = session;
  next();
}

async function logUsage(email, name, mode) {
  try {
    await pool.query(
      'INSERT INTO usage_logs (user_email, user_name, mode) VALUES ($1, $2, $3)',
      [email, name || '', mode]
    );
  } catch (err) {
    console.error('Usage log error:', err.message);
  }
}

// ── MICROSOFT OAUTH CONFIG ──
const TENANT_ID      = process.env.MS_TENANT_ID;
const CLIENT_ID      = process.env.MS_CLIENT_ID;
const CLIENT_SECRET  = process.env.MS_CLIENT_SECRET;
const REDIRECT_URI   = process.env.REDIRECT_URI || 'https://cultureplug-production.up.railway.app/auth/callback';
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
  console.log('CALLBACK HIT - code:', !!code, 'error:', error);
  if (error || !code) return res.redirect('/?error=auth_failed');

  try {
    console.log('STEP 1: Exchanging code for token...');
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
    console.log('STEP 2: Token status:', tokenRes.status, 'has_token:', !!tokenData.access_token, 'error:', tokenData.error);
    if (!tokenData.access_token) throw new Error(`No access token: ${tokenData.error} - ${tokenData.error_description}`);

    console.log('STEP 3: Fetching profile...');
    const profileRes = await fetch('https://graph.microsoft.com/v1.0/me', {
      headers: { Authorization: `Bearer ${tokenData.access_token}` },
    });
    const profile = await profileRes.json();

    const email = (profile.mail || profile.userPrincipalName || '').toLowerCase();
    console.log('STEP 4: Email:', email, 'allowed:', email.endsWith(`@${ALLOWED_DOMAIN}`));
    if (!email.endsWith(`@${ALLOWED_DOMAIN}`)) return res.redirect('/?error=unauthorised_domain');

    const firstName = profile.givenName || (profile.displayName || 'Team').split(' ')[0];
    console.log('STEP 5: Creating session for', firstName);
    const sessionToken = await createSession({ name: firstName, fullName: profile.displayName, email });
    console.log('STEP 6: Session created OK, sending response...');

    // Redirect to a success page that sets the cookie via JS (handles proxy cookie-stripping)
    res.redirect(`/auth/success?t=${sessionToken}`);
  } catch (err) {
    console.error('Auth error:', err.message);
    res.redirect('/?error=auth_error');
  }
});

// ── AUTH SUCCESS PAGE ──
app.get('/auth/success', (req, res) => {
  const t = req.query.t;
  if (!t || !/^[a-f0-9]{64}$/.test(t)) return res.redirect('/?error=auth_error');
  res.send(`<!DOCTYPE html><html><head><title>Signing in...</title></head><body>
<script>
  document.cookie = 'cp_session=${t}; path=/; max-age=28800; samesite=lax';
  window.location.replace('/');
</script>
<noscript><meta http-equiv="refresh" content="0;url=/"></noscript>
</body></html>`);
});

app.get('/auth/logout', async (req, res) => {
  const token = getSessionToken(req);
  if (token) await deleteSession(token);
  res.setHeader('Set-Cookie', 'cp_session=; Path=/; HttpOnly; Max-Age=0');
  res.redirect('/');
});

// ── USER ENDPOINT ──
app.get('/api/me', async (req, res) => {
  res.set('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate');
  res.set('Pragma', 'no-cache');
  res.set('Surrogate-Control', 'no-store');
  res.set('Vary', 'Cookie');
  const session = await getSession(getSessionToken(req));
  if (!session) return res.json({ authenticated: false });
  res.json({ authenticated: true, name: session.name, fullName: session.fullName, email: session.email });
});

// ── DB HEALTH CHECK ──
app.get('/api/dbcheck', async (req, res) => {
  try {
    const result = await pool.query('SELECT NOW() as time, count(*) as session_count FROM sessions');
    res.json({ ok: true, time: result.rows[0].time, sessions: result.rows[0].session_count });
  } catch (err) {
    res.json({ ok: false, error: err.message });
  }
});

// ── CHAT ──
app.post('/api/chat', requireAuth, async (req, res) => {
  try {
    const body = { ...req.body };
    const isPreMeeting = body.mode === 'pre_meeting';
    const modeLabel = body.mode || 'general';
    delete body.mode;

    if (isPreMeeting) {
      body.tools = [{ type: 'web_search_20250305', name: 'web_search' }];
    }

    const headers = {
      'Content-Type': 'application/json',
      'x-api-key': process.env.ANTHROPIC_API_KEY,
      'anthropic-version': '2023-06-01',
    };
    if (isPreMeeting) {
      headers['anthropic-beta'] = 'web-search-2025-03-05';
    }

    const response = await fetch('https://api.anthropic.com/v1/messages', {
      method: 'POST',
      headers,
      body: JSON.stringify(body),
    });

    const data = await response.json();

    // Log usage (fire and forget)
    if (req.user) logUsage(req.user.email, req.user.name, modeLabel);

    // Flatten — merge all text blocks into one
    if (data.content && Array.isArray(data.content)) {
      const textBlocks = data.content.filter(b => b.type === 'text');
      if (textBlocks.length > 0) {
        let merged = '';
        for (const block of textBlocks) {
          const t = block.text;
          if (!merged) { merged = t; continue; }
          if (t.startsWith('\n') || t.startsWith('#') || merged.endsWith('\n')) {
            merged += t;
          } else {
            merged += ' ' + t;
          }
        }
        data.content = [{ type: 'text', text: merged }];
      }
    }

    res.status(response.status).json(data);
  } catch (err) {
    res.status(500).json({ error: { message: err.message } });
  }
});

// ── MEDIA PLANS ──
app.get('/api/plans', requireAuth, async (req, res) => {
  try {
    const result = await pool.query(
      'SELECT id, name, created_at, updated_at FROM media_plans WHERE user_email = $1 ORDER BY updated_at DESC',
      [req.user.email]
    );
    res.json(result.rows);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/plans', requireAuth, async (req, res) => {
  const { name, data, id } = req.body;
  if (!name || !data) return res.status(400).json({ error: 'name and data required' });
  try {
    if (id) {
      const result = await pool.query(
        'UPDATE media_plans SET name = $1, data = $2, updated_at = NOW() WHERE id = $3 AND user_email = $4 RETURNING id, name, updated_at',
        [name, JSON.stringify(data), id, req.user.email]
      );
      if (result.rows.length === 0) return res.status(404).json({ error: 'Plan not found' });
      res.json(result.rows[0]);
    } else {
      const result = await pool.query(
        'INSERT INTO media_plans (user_email, name, data) VALUES ($1, $2, $3) RETURNING id, name, created_at',
        [req.user.email, name, JSON.stringify(data)]
      );
      res.json(result.rows[0]);
    }
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/plans/:id', requireAuth, async (req, res) => {
  try {
    const result = await pool.query(
      'SELECT * FROM media_plans WHERE id = $1 AND user_email = $2',
      [req.params.id, req.user.email]
    );
    if (result.rows.length === 0) return res.status(404).json({ error: 'Plan not found' });
    res.json(result.rows[0]);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.delete('/api/plans/:id', requireAuth, async (req, res) => {
  try {
    await pool.query(
      'DELETE FROM media_plans WHERE id = $1 AND user_email = $2',
      [req.params.id, req.user.email]
    );
    res.json({ ok: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ── MONDAY CRM SYNC ──

pool.query(`
  CREATE TABLE IF NOT EXISTS monday_cache (
    id        SERIAL PRIMARY KEY,
    data      JSONB NOT NULL,
    synced_at TIMESTAMPTZ DEFAULT NOW()
  );
`).catch(err => console.error('monday_cache init error:', err.message));

// Per-board column schemas — IDs differ between the 2026 and 2024/2025 boards
const MONDAY_BOARDS = [
  {
    id: '1353139719',
    label: '2026 Pipeline (Live)',
    cols: {
      stage:        'deal_stage',
      owner:        'deal_owner',
      dealValue:    'deal_value',
      sabValue:     'deal_actual_value',
      q1:           'numbers',
      q2:           'numbers9',
      q3:           'numbers8',
      q4:           'numbers93',
      signOffDate:  'deal_close_date',
      closeDate:    'deal_close_date',
      newOrExisting:'color_mkttct2g',
    }
  },
  {
    id: '5089413136',
    label: '2025 Pipeline (Closed)',
    cols: {
      stage:        'stage_mkkpc6ys',
      owner:        'owner_mkkpavhq',
      dealValue:    'originals_value_mkkpy6hv',
      sabValue:     'dup__of_originals_value_mkkptkzq',
      q1:           'q1_value_mkkp2qp3',
      q2:           'q2_value_mkkpcpmv',
      q3:           'q3_value_mkkpecds',
      q4:           'q4_value_mkkppnm7',
      signOffDate:  'date_mkz215e1',
      closeDate:    'close_date_mkkpvkwv',
      newOrExisting:'color_mkz2bhee',
    }
  },
  {
    id: '1756615690',
    label: '2024 Pipeline (Closed)',
    cols: {
      stage:        'stage_mkkpc6ys',
      owner:        'owner_mkkpavhq',
      dealValue:    'originals_value_mkkpy6hv',
      sabValue:     'dup__of_originals_value_mkkptkzq',
      q1:           'q1_value_mkkp2qp3',
      q2:           'q2_value_mkkpcpmv',
      q3:           'q3_value_mkkpecds',
      q4:           'q4_value_mkkppnm7',
      signOffDate:  'date_mkz215e1',
      closeDate:    'close_date_mkkpvkwv',
      newOrExisting:'color_mkz2bhee',
    }
  },
];

function parseDealName(raw) {
  // Handle "3001. Nike Campaign" format (2024/2025) and "Nike EMEA | WC27" format (2026)
  const numbered = raw.match(/^(\d+)\.\s+(.+)$/);
  if (numbered) {
    const rest = numbered[2];
    const words = rest.split(' ');
    let brandWords = [words[0]];
    if (words[1] && /^[A-Z]/.test(words[1]) && !['Jan','Feb','Mar','Apr','May','Jun','Jul','Aug','Sep','Oct','Nov','Dec','Q1','Q2','Q3','Q4'].includes(words[1])) {
      brandWords.push(words[1]);
    }
    return { dealNumber: numbered[1], brand: brandWords.join(' '), campaign: words.slice(brandWords.length).join(' ') };
  }
  // 2026 format: no number prefix — first word(s) before | or space are the brand
  const pipeIdx = raw.indexOf('|');
  if (pipeIdx > -1) {
    const brand = raw.substring(0, pipeIdx).trim().split(' ')[0];
    return { dealNumber: null, brand, campaign: raw.substring(pipeIdx + 1).trim() };
  }
  const words = raw.split(' ');
  let brandWords = [words[0]];
  if (words[1] && /^[A-Z]/.test(words[1])) brandWords.push(words[1]);
  return { dealNumber: null, brand: brandWords.join(' '), campaign: words.slice(brandWords.length).join(' ') };
}

function getMondayCol(item, colId) {
  if (!colId) return '';
  const col = item.column_values.find(c => c.id === colId);
  return col ? (col.text || '') : '';
}

function formatValue(v) {
  const n = parseFloat(v) || 0;
  if (n === 0) return null;
  return '£' + n.toLocaleString('en-GB', { maximumFractionDigits: 0 });
}

async function fetchBoardItems(apiKey, board) {
  const c = board.cols;
  const colIds = [...new Set(Object.values(c))].filter(Boolean);
  const colList = colIds.map(id => `"${id}"`).join(',');
  let allItems = [], cursor = null;
  do {
    const gql = `{ boards(ids: ${board.id}) { items_page(limit: 500${cursor ? `, cursor: "${cursor}"` : ''}) { cursor items { name column_values(ids: [${colList}]) { id text } } } } }`;
    const r = await fetch('https://api.monday.com/v2', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'Authorization': apiKey, 'API-Version': '2024-01' },
      body: JSON.stringify({ query: gql })
    });
    const d = await r.json();
    if (d.errors) throw new Error(`Board ${board.id}: ${d.errors[0].message}`);
    const page = d.data.boards[0].items_page;
    allItems = allItems.concat(page.items);
    cursor = page.cursor || null;
  } while (cursor);
  return allItems;
}

function mapDeals(items, board) {
  const c = board.cols;
  return items.map(item => {
    const { dealNumber, brand, campaign } = parseDealName(item.name);
    const dealValue = parseFloat(getMondayCol(item, c.dealValue)) || 0;
    const sabValue  = parseFloat(getMondayCol(item, c.sabValue))  || 0;
    const q1 = parseFloat(getMondayCol(item, c.q1)) || 0;
    const q2 = parseFloat(getMondayCol(item, c.q2)) || 0;
    const q3 = parseFloat(getMondayCol(item, c.q3)) || 0;
    const q4 = parseFloat(getMondayCol(item, c.q4)) || 0;
    const activeQuarters = ['Q1','Q2','Q3','Q4'].filter((_,i) => [q1,q2,q3,q4][i] > 0);
    return {
      dealNumber, brand, campaign,
      pipeline:      board.label,
      stage:         getMondayCol(item, c.stage)        || 'Unknown',
      owner:         getMondayCol(item, c.owner)        || '',
      dealValue:     formatValue(dealValue),
      includesSAB:   sabValue > 0,
      sabValue:      sabValue > 0 ? formatValue(sabValue) : null,
      activeQuarters,
      signOffDate:   getMondayCol(item, c.signOffDate)  || null,
      newOrExisting: getMondayCol(item, c.newOrExisting)|| '',
    };
  }).filter(d => d.brand);
}

app.post('/api/monday/sync', requireAuth, async (req, res) => {
  const apiKey = process.env.MONDAY_API_KEY;
  if (!apiKey) return res.status(500).json({ error: 'MONDAY_API_KEY not set in Railway env vars' });

  try {
    // Fetch all three boards in parallel
    const boardResults = await Promise.all(
      MONDAY_BOARDS.map(b => fetchBoardItems(apiKey, b).then(items => mapDeals(items, b)))
    );

    const deals = boardResults.flat();
    const counts = MONDAY_BOARDS.map((b, i) => `${b.label}: ${boardResults[i].length}`);
    console.log(`Monday sync: ${deals.length} total deals — ${counts.join(' | ')}`);

    await pool.query('DELETE FROM monday_cache');
    await pool.query('INSERT INTO monday_cache (data) VALUES ($1)', [JSON.stringify({ deals, syncedAt: new Date().toISOString() })]);

    res.json({ ok: true, count: deals.length, breakdown: counts, syncedAt: new Date().toISOString() });
  } catch (err) {
    console.error('Monday sync error:', err.message);
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/monday/data', requireAuth, async (req, res) => {
  try {
    const result = await pool.query('SELECT data, synced_at FROM monday_cache ORDER BY synced_at DESC LIMIT 1');
    if (!result.rows.length) return res.json({ deals: [], syncedAt: null });
    res.json({ ...result.rows[0].data, syncedAt: result.rows[0].synced_at });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ── ADMIN ──
app.get('/api/admin/usage', requireAdmin, async (req, res) => {
  try {
    const [totals, byMode, byUser, byDay, recent] = await Promise.all([
      pool.query(`SELECT COUNT(*) as total, COUNT(DISTINCT user_email) as users FROM usage_logs`),
      pool.query(`SELECT mode, COUNT(*) as count FROM usage_logs GROUP BY mode ORDER BY count DESC`),
      pool.query(`SELECT user_name, user_email, COUNT(*) as count, MAX(logged_at) as last_seen FROM usage_logs GROUP BY user_name, user_email ORDER BY count DESC`),
      pool.query(`SELECT DATE(logged_at) as day, COUNT(*) as count FROM usage_logs WHERE logged_at > NOW() - INTERVAL '30 days' GROUP BY day ORDER BY day ASC`),
      pool.query(`SELECT user_name, user_email, mode, logged_at FROM usage_logs ORDER BY logged_at DESC LIMIT 50`),
    ]);
    res.json({
      totals: totals.rows[0],
      byMode: byMode.rows,
      byUser: byUser.rows,
      byDay: byDay.rows,
      recent: recent.rows,
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/admin', requireAdmin, (req, res) => {
  res.send(`<!DOCTYPE html><html><head><meta charset="utf-8"><title>Culture Plug — Admin</title>
<meta name="viewport" content="width=device-width,initial-scale=1">
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=DM+Mono:wght@400;500&family=DM+Sans:wght@400;500;700&display=swap" rel="stylesheet">
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{background:#0e0e0c;color:#f0ede6;font-family:'DM Sans',sans-serif;min-height:100vh;padding:32px 40px}
h1{font-size:13px;font-family:'DM Mono',monospace;letter-spacing:2px;text-transform:uppercase;color:#c9a84c;margin-bottom:4px}
.subtitle{font-size:12px;color:#555;font-family:'DM Mono',monospace;margin-bottom:32px}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:12px;margin-bottom:32px}
.stat{background:#111;border:1px solid #1e1e1b;border-radius:8px;padding:16px}
.stat-n{font-size:32px;font-weight:700;color:#f0ede6;line-height:1}
.stat-l{font-size:10px;font-family:'DM Mono',monospace;letter-spacing:1px;text-transform:uppercase;color:#555;margin-top:4px}
.section{margin-bottom:32px}
.section-title{font-size:10px;font-family:'DM Mono',monospace;letter-spacing:2px;text-transform:uppercase;color:#444;margin-bottom:12px;padding-bottom:8px;border-bottom:1px solid #1a1a18}
table{width:100%;border-collapse:collapse;font-size:13px}
th{text-align:left;font-family:'DM Mono',monospace;font-size:9px;letter-spacing:1px;text-transform:uppercase;color:#444;padding:0 12px 8px 0}
td{padding:8px 12px 8px 0;border-bottom:1px solid #141412;color:#a8a49c}
td:first-child{color:#f0ede6}
.badge{display:inline-block;font-family:'DM Mono',monospace;font-size:9px;letter-spacing:1px;text-transform:uppercase;padding:3px 8px;border-radius:4px;background:#1a1a18;color:#888}
.bar-wrap{background:#1a1a18;border-radius:3px;height:6px;min-width:60px;flex:1}
.bar{height:6px;border-radius:3px;background:#c9a84c}
.bar-row{display:flex;align-items:center;gap:10px;padding:6px 0;border-bottom:1px solid #141412}
.bar-label{font-size:12px;color:#f0ede6;min-width:140px}
.bar-count{font-family:'DM Mono',monospace;font-size:11px;color:#555;min-width:30px;text-align:right}
.loading{color:#444;font-family:'DM Mono',monospace;font-size:11px;padding:40px 0}
.chart{display:flex;align-items:flex-end;gap:3px;height:80px;margin-bottom:4px}
.chart-bar{flex:1;background:#c9a84c22;border-radius:2px 2px 0 0;min-width:4px;position:relative;transition:background 0.1s}
.chart-bar:hover{background:#c9a84c55}
.chart-bar span{display:none;position:absolute;bottom:100%;left:50%;transform:translateX(-50%);font-size:9px;font-family:'DM Mono',monospace;color:#888;white-space:nowrap;padding-bottom:2px}
.chart-bar:hover span{display:block}
</style></head><body>
<h1>Culture Plug</h1>
<div class="subtitle">Usage Analytics — Admin Only</div>
<div id="root"><div class="loading">Loading...</div></div>
<script>
const MODE_LABELS = {
  general:'General Chat',pitch:'Pitch Brief',email:'Initial Email',brief_upload:'Upload Brief',
  persona:'Audience Persona',compare:'Audience Comparison',seasonal:'Seasonal Calendar',
  exec:'Exec Summary',objection:'Objection Handler',bulk_email:'Bulk Email',
  reach_calc:'Reach Calculator',pre_meeting:'Pre-Meeting Intel',unknown:'Unknown'
};

async function load() {
  const r = await fetch('/api/admin/usage');
  const d = await r.json();
  if(d.error){document.getElementById('root').innerHTML='<div class="loading">Error: '+d.error+'</div>';return;}

  const maxMode = Math.max(...d.byMode.map(m=>+m.count),1);
  const maxDay  = Math.max(...d.byDay.map(m=>+m.count),1);

  const chartBars = d.byDay.map(row=>{
    const h = Math.max(4, Math.round((+row.count/maxDay)*80));
    const label = new Date(row.day).toLocaleDateString('en-GB',{day:'numeric',month:'short'});
    return \`<div class="chart-bar" style="height:\${h}px"><span>\${label}: \${row.count}</span></div>\`;
  }).join('');

  const modeRows = d.byMode.map(row=>{
    const pct = Math.round(+row.count/maxMode*100);
    const label = MODE_LABELS[row.mode]||row.mode;
    return \`<div class="bar-row">
      <div class="bar-label">\${label}</div>
      <div class="bar-wrap"><div class="bar" style="width:\${pct}%"></div></div>
      <div class="bar-count">\${row.count}</div>
    </div>\`;
  }).join('');

  const userRows = d.byUser.map(row=>{
    const last = new Date(row.last_seen).toLocaleDateString('en-GB',{day:'numeric',month:'short',year:'numeric'});
    return \`<tr><td>\${row.user_name||'—'}</td><td style="color:#555">\${row.user_email}</td><td>\${row.count}</td><td style="color:#555">\${last}</td></tr>\`;
  }).join('');

  const recentRows = d.recent.map(row=>{
    const when = new Date(row.logged_at).toLocaleString('en-GB',{day:'numeric',month:'short',hour:'2-digit',minute:'2-digit'});
    const label = MODE_LABELS[row.mode]||row.mode;
    return \`<tr><td>\${row.user_name||'—'}</td><td><span class="badge">\${label}</span></td><td style="color:#555">\${when}</td></tr>\`;
  }).join('');

  document.getElementById('root').innerHTML = \`
    <div class="grid">
      <div class="stat"><div class="stat-n">\${d.totals.total}</div><div class="stat-l">Total Queries</div></div>
      <div class="stat"><div class="stat-n">\${d.totals.users}</div><div class="stat-l">Active Users</div></div>
      <div class="stat"><div class="stat-n">\${d.byMode.length}</div><div class="stat-l">Modes Used</div></div>
      <div class="stat"><div class="stat-n">\${d.byDay.length > 0 ? d.byDay[d.byDay.length-1].count : 0}</div><div class="stat-l">Queries Today</div></div>
    </div>

    <div class="section">
      <div class="section-title">Activity — Last 30 Days</div>
      <div class="chart">\${chartBars||'<div style="color:#333;font-size:11px;font-family:DM Mono,monospace">No data yet</div>'}</div>
    </div>

    <div class="section">
      <div class="section-title">Usage by Mode</div>
      \${modeRows||'<div class="loading">No data yet</div>'}
    </div>

    <div class="section">
      <div class="section-title">Team Members</div>
      <table><thead><tr><th>Name</th><th>Email</th><th>Queries</th><th>Last Active</th></tr></thead>
      <tbody>\${userRows||'<tr><td colspan="4" style="color:#333">No data yet</td></tr>'}</tbody></table>
    </div>

    <div class="section">
      <div class="section-title">Recent Activity</div>
      <table><thead><tr><th>User</th><th>Mode</th><th>Time</th></tr></thead>
      <tbody>\${recentRows||'<tr><td colspan="3" style="color:#333">No data yet</td></tr>'}</tbody></table>
    </div>
  \`;
}
load();
</script></body></html>`);
});

// ── CONVERSATIONS ──
// List user's conversations (last 90 days)
app.get('/api/conversations', requireAuth, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT id, title, mode, created_at, updated_at
       FROM conversations
       WHERE user_email = $1 AND updated_at > NOW() - INTERVAL '90 days'
       ORDER BY updated_at DESC
       LIMIT 200`,
      [req.user.email]
    );
    res.json(result.rows);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// Get single conversation with full history
app.get('/api/conversations/:id', requireAuth, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT * FROM conversations WHERE id = $1 AND user_email = $2`,
      [req.params.id, req.user.email]
    );
    if (!result.rows.length) return res.status(404).json({ error: 'Not found' });
    res.json(result.rows[0]);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// Create new conversation
app.post('/api/conversations', requireAuth, async (req, res) => {
  try {
    const { title, mode, history } = req.body;
    const result = await pool.query(
      `INSERT INTO conversations (user_email, title, mode, history)
       VALUES ($1, $2, $3, $4) RETURNING id`,
      [req.user.email, title || 'New conversation', mode || 'general', JSON.stringify(history || [])]
    );
    res.json({ id: result.rows[0].id });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// Update existing conversation
app.patch('/api/conversations/:id', requireAuth, async (req, res) => {
  try {
    const { title, history, mode } = req.body;
    await pool.query(
      `UPDATE conversations SET title = COALESCE($1, title), history = COALESCE($2, history),
       mode = COALESCE($3, mode), updated_at = NOW()
       WHERE id = $4 AND user_email = $5`,
      [title, history ? JSON.stringify(history) : null, mode, req.params.id, req.user.email]
    );
    res.json({ ok: true });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// Delete conversation
app.delete('/api/conversations/:id', requireAuth, async (req, res) => {
  try {
    await pool.query(
      `DELETE FROM conversations WHERE id = $1 AND user_email = $2`,
      [req.params.id, req.user.email]
    );
    res.json({ ok: true });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// Purge conversations older than 90 days (runs on startup)
pool.query(`DELETE FROM conversations WHERE updated_at < NOW() - INTERVAL '90 days'`)
  .catch(err => console.error('Conversation purge error:', err.message));

// ── SIGNALS (Supabase proxy) ──
app.get('/api/signals', requireAuth, async (req, res) => {
  const url = process.env.SIGNALS_SUPABASE_URL;
  const key = process.env.SIGNALS_SUPABASE_KEY;
  if (!url || !key) return res.status(500).json({ error: 'Signals not configured — add SIGNALS_SUPABASE_URL and SIGNALS_SUPABASE_KEY to Railway env vars' });

  try {
    const { priority, search, limit = 50, offset = 0 } = req.query;

    let query = `${url}/rest/v1/signals?select=id,scrape_date,channel,signal,insight,opportunity,priority,author,category,url,likes,comments,views,is_favorite,tags&order=scrape_date.desc&limit=${limit}&offset=${offset}`;

    if (priority && priority !== 'All') {
      query += `&priority=eq.${encodeURIComponent(priority)}`;
    }
    // Note: when 'All' is selected, no priority filter applied — returns everything

    if (search) {
      query += `&or=(signal.ilike.*${encodeURIComponent(search)}*,author.ilike.*${encodeURIComponent(search)}*,opportunity.ilike.*${encodeURIComponent(search)}*)`;
    }

    const r = await fetch(query, {
      headers: {
        'apikey': key,
        'Authorization': `Bearer ${key}`,
        'Content-Type': 'application/json',
        'Accept': 'application/json',
      }
    });

    const responseText = await r.text();
    console.log(`Signals API status: ${r.status}, body: ${responseText.slice(0, 300)}`);

    if (!r.ok) {
      return res.status(r.status).json({ error: `Supabase error ${r.status}: ${responseText.slice(0, 200)}` });
    }

    let data;
    try { data = JSON.parse(responseText); }
    catch(e) { return res.status(500).json({ error: `Invalid JSON from Supabase: ${responseText.slice(0, 200)}` }); }

    res.json(data);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.use(express.static(path.join(__dirname, 'public')));

// ── MONDAY BACKGROUND SYNC ──
async function backgroundMondaySync() {
  const apiKey = process.env.MONDAY_API_KEY;
  if (!apiKey) return; // silently skip if not configured

  try {
    // Check when we last synced — skip if within the last 7 days
    const result = await pool.query('SELECT synced_at FROM monday_cache ORDER BY synced_at DESC LIMIT 1');
    if (result.rows.length) {
      const lastSync = new Date(result.rows[0].synced_at);
      const daysSince = (Date.now() - lastSync.getTime()) / (1000 * 60 * 60 * 24);
      if (daysSince < 7) {
        console.log(`Monday background sync skipped — last synced ${daysSince.toFixed(1)} days ago`);
        return;
      }
    }

    console.log('Monday background sync starting...');
    const boardResults = await Promise.all(
      MONDAY_BOARDS.map(b => fetchBoardItems(apiKey, b).then(items => mapDeals(items, b)))
    );
    const deals = boardResults.flat();
    await pool.query('DELETE FROM monday_cache');
    await pool.query('INSERT INTO monday_cache (data) VALUES ($1)', [JSON.stringify({ deals, syncedAt: new Date().toISOString() })]);
    console.log(`Monday background sync complete: ${deals.length} deals cached`);
  } catch (err) {
    console.error('Monday background sync error:', err.message);
  }
}

const PORT = process.env.PORT || 3000;
app.listen(PORT, '0.0.0.0', () => {
  console.log(`Culture Plug running on port ${PORT}`);
  // Run once on startup (after a short delay to let DB settle), then every 7 days
  setTimeout(backgroundMondaySync, 10000);
  setInterval(backgroundMondaySync, 7 * 24 * 60 * 60 * 1000);
});
