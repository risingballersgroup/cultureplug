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

    // For pre_meeting, keep the Railway connection alive during slow web search
    // by sending SSE-style pings, then flush the real response at the end
    if (isPreMeeting) {
      res.setHeader('Content-Type', 'text/event-stream');
      res.setHeader('Cache-Control', 'no-cache');
      res.setHeader('X-Accel-Buffering', 'no');

      // Ping every 15s so Railway doesn't drop the connection
      const ping = setInterval(() => {
        res.write(': ping\n\n');
      }, 15000);

      const controller = new AbortController();
      const timeout = setTimeout(() => controller.abort(), 90000);

      let data;
      try {
        const response = await fetch('https://api.anthropic.com/v1/messages', {
          method: 'POST', headers, body: JSON.stringify(body), signal: controller.signal,
        });
        data = await response.json();
      } finally {
        clearTimeout(timeout);
        clearInterval(ping);
      }

      // Flatten text blocks
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

      console.log('Pre-meeting block types:', (data.content || []).map(b => b.type));

      // Send the JSON payload as a data event, then close
      res.write(`data: ${JSON.stringify(data)}\n\n`);
      res.end();
      return;
    }

    // All other modes — normal JSON response
    const response = await fetch('https://api.anthropic.com/v1/messages', {
      method: 'POST', headers, body: JSON.stringify(body),
    });
    const data = await response.json();
    res.status(response.status).json(data);

  } catch (err) {
    const isTimeout = err.name === 'AbortError';
    if (!res.headersSent) {
      res.status(isTimeout ? 504 : 500).json({
        error: { message: isTimeout ? 'Web search timed out. Please try again.' : err.message }
      });
    }
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
