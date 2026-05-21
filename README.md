# Culture Plug

Internal intelligence and media planning tool for **Rising Ballers × She's A Baller**.

**Live:** [cultureplug-production.up.railway.app](https://cultureplug-production.up.railway.app)
**Auth:** Microsoft O365 — restricted to `@risingballers.co.uk`
**Admin:** [/admin](https://cultureplug-production.up.railway.app/admin) — `eni@risingballers.co.uk` only

---

## Stack

| Layer | Technology |
|---|---|
| Server | Node 22 + Express |
| Frontend | Single-file SPA (`public/index.html`) |
| Database | PostgreSQL (Railway) |
| Auth | Microsoft OAuth 2.0 (O365) |
| AI | Anthropic Claude (claude-sonnet-4-6) |
| CRM | Monday.com GraphQL API |
| Hosting | Railway (us-west-2, auto-deploy on push) |

---

## Infrastructure

### Railway Environment Variables

| Variable | Description |
|---|---|
| `DATABASE_URL` | PostgreSQL connection string (Railway Postgres) |
| `ANTHROPIC_API_KEY` | Anthropic API key |
| `MS_TENANT_ID` | Microsoft Azure tenant ID |
| `MS_CLIENT_ID` | Azure app client ID |
| `MS_CLIENT_SECRET` | Azure app client secret |
| `REDIRECT_URI` | OAuth callback URL |
| `ALLOWED_DOMAIN` | Allowed email domain (`risingballers.co.uk`) |
| `MONDAY_API_KEY` | Monday.com personal API token |

### Database Tables

| Table | Purpose |
|---|---|
| `sessions` | Postgres-backed auth sessions (survive redeploys) |
| `media_plans` | Saved media plans per user, keyed by email |
| `monday_cache` | Cached Monday CRM deal data (synced weekly) |
| `usage_logs` | Mode-level usage analytics (email, name, mode, timestamp) |

---

## Features

### AI Chat — 11 Modes

All modes are grounded in Rising Ballers' first-party data corpus (50K+ survey respondents, 1M+ responses, 5 data sources, Jan 2023–Mar 2026 coverage) and injected with live Monday CRM context on every request.

| Mode | Description |
|---|---|
| **General Chat** | Conversational, data-grounded, handles image/file uploads |
| **Initial Email** | Short cold outreach email, reads like a human wrote it. Booking URL injected automatically from settings. |
| **Pitch Brief** | Structured brand pitch grounded in first-party data |
| **Upload Brief** | File upload (PDF, DOCX, images) + brief analysis against data corpus |
| **Audience Persona** | Named persona built from data |
| **Audience Comparison** | Side-by-side comparison of two brand audiences |
| **Seasonal Calendar** | Activation windows tied to cultural and sporting calendar |
| **Exec Summary** | Quick data snapshot |
| **Objection Handler** | Sales objection rebuttals backed by data |
| **Bulk Email** | Batch outreach generation |
| **Reach Calculator** | Follower/demographic reach calculator across RB, SAB, RB USA channels |

### Pre-Meeting Intel

Dedicated mode that generates a structured 5-section intelligence brief before a pitch or client meeting. Input: brand name. Output:

1. **Have We Worked With Them Before?** — pulls full deal history from Monday CRM (2024, 2025, 2026 pipelines), exact values, channels, owners, relationship status
2. **What's Happening With Them Right Now?** — football partnerships, financial health, recent campaigns, strategic direction (uses Claude training knowledge)
3. **Relevant Insights From Our Data** — 5 data points from the corpus most relevant to this brand's vertical and campaign objective
4. **Thought-Starters** — 3 concrete activation ideas tailored to this brand's current moment
5. **Upcoming Moments** — 4–6 sporting/cultural calendar hooks relevant to this brand in the next 12 months

**Export PDF** — renders a clean 2-page A4 PDF (dark theme, RB × SAB branding, footer on each page). Sections 1+2 on page 1, sections 3+4+5 on page 2.

**Email to Me** — generates a `mailto:` to the user's own address with the full brief as plain text.

### Media Plan Builder

Full 3-step media plan builder accessible via the **Media Plan Builder** button in the header.

**Step 1 — Ratecard:** Review and optionally override organic rates for RB, SAB, and RB USA. Paid benchmarking table (per £1,000 spend) for IG, TikTok, and YouTube formats. Unlock toggle enables rate editing.

**Step 2 — Build Plan:** Add quantities per format across channels. Live summary bar: total posts, media value, added value %, total reach, impressions, views, engagements. Paid spend integrates into summary.

**Step 3 — Client View:** Investment summary, media breakdown table, individual channel accordion, campaign notes (6 tiles: Plan, Creative, Content, Partnership, Timings, Reporting), boilerplate (Audience, Engagement, Added Value).

**Export PDF** — A4 landscape, clones Step 3 DOM, injects print CSS. Filename: `MEDIAPLAN - [RB x SAB] - [Client] - [YYMMDD]`.

**Export XLS** — Spreadsheet export of plan data.

**Save / Load Plans** — Plans saved to Postgres per user. Saves all state: client name, budget, channel selections, qty inputs, paid spend, logo, notes, boilerplate.

### Monday CRM Integration

Pulls deal data from three Monday boards simultaneously:

| Board | ID | Description |
|---|---|---|
| Pipeline | `1353139719` | Live 2026 deals |
| 2025 Pipeline | `5089413136` | Closed 2025 deals |
| 2024 Pipeline | `1756615690` | Closed 2024 deals |

Each board uses its own column ID schema (the 2026 board uses native Monday CRM IDs; 2024/2025 use custom column IDs).

**What gets synced:** deal name, stage, owner, exact deal value, SAB value, active quarters (Q1–Q4), sign-off date, new/existing flag.

**Sync schedule:** automatically on server start (10s delay) + every 7 days via `setInterval`. Manual sync available via ⚙ settings panel.

**AI injection:** synced data is formatted into a structured context block injected into every system prompt, grouped by pipeline year (2026 Live first, then 2025/2024 history). The AI is instructed on how to use it: social proof, upsell detection, repeat client identification, budget anchoring.

### Usage Analytics (Admin)

Available at `/admin` — restricted to `eni@risingballers.co.uk` server-side. Also accessible via "Usage Analytics →" link in the ⚙ settings panel (visible only when logged in as admin).

Displays:
- Total queries, active users, modes used, queries today
- 30-day activity chart
- Usage by mode (ranked bar chart)
- Team members: name, email, query count, last active
- Last 50 queries: user, mode, timestamp

---

## Auth Flow

1. User visits `/` → redirected to `/auth/login` if no session
2. `/auth/login` → redirects to Microsoft OAuth
3. Microsoft → `/auth/callback` → validates domain (`@risingballers.co.uk`), creates Postgres session
4. Session token set via client-side JS redirect (avoids proxy cookie-stripping)
5. All API endpoints protected by `requireAuth` middleware
6. `/admin` protected by `requireAdmin` middleware (email check: `eni@risingballers.co.uk`)

---

## Data Corpus

The AI system prompt includes Rising Ballers' proprietary first-party research:

- **Sprout Social (Mar 2026):** RB IG (2.99M followers), SAB IG (266K), RB USA IG (75K), RB TikTok (6.18M), SAB TikTok (135K). Combined: 9.65M followers.
- **Channel Performance (Q1 2026):** 1.27B impressions, 87M+ engagements, 152K new followers. RB TikTok: 8.9% eng rate. RB IG: 6.2% eng rate.
- Survey data: Next Wave, Women's Fandom Report, World Cup Heartbeats, RB IG Insights Master File (N=10K–50K per source)

---

## Deployment

Push to `main` on GitHub → Railway auto-deploys.

```bash
git add .
git commit -m "your message"
git push origin main
```

No build step. Railway runs `node server.js` directly.

---

## Local Development

```bash
npm install
# Set env vars in .env or export manually
node server.js
# Visit http://localhost:8080
```

Dependencies: `express`, `node-fetch`, `pg`

---

## File Structure

```
/
├── server.js          # Express server, auth, API endpoints, Monday sync
├── package.json
└── public/
    ├── index.html     # Full SPA (4,600+ lines) — all UI, styles, AI modes
    ├── favicon.ico
    ├── favicon.svg
    └── favicon.png
```

---

## Azure App Registration

The Microsoft OAuth app must have:
- **Redirect URI:** `https://cultureplug-production.up.railway.app/auth/callback`
- **Scopes:** `openid profile email User.Read`
- **Client secret:** check expiry date periodically in Azure Portal → App Registrations → Certificates & Secrets

If login loops without authenticating, check the redirect URI is listed and the client secret hasn't expired.

---

*Built by Rising Ballers Group. Internal use only.*
