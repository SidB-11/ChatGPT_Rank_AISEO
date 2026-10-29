# ChatGPT Rank (AI SEO Audit)

Live: https://chatgpt-rank.com

ChatGPT Rank is an AI-powered SEO + AI-search readiness audit tool. Users enter a website URL and instantly receive a structured, actionable report designed to improve visibility in modern AI-driven search surfaces like ChatGPT, Claude, and Google AI Overviews.

---

## What it does

### 1) Instant AI SEO audit (URL → report)
- Generates an 8-section audit with a clear overall score (out of 10)
- Breaks down scores across:
  - Technical SEO
  - Content quality
  - On-page SEO + schema
  - Performance
  - E-E-A-T (Experience, Expertise, Authority, Trust)
  - AI readiness (AI Overviews / LLM citation readiness)
  - Site architecture + content strategy

### 2) Action plan output (not generic tips)
The report includes:
- Specific wins (what’s already good)
- Prioritized issues (HIGH / MED / LOW)
- Exact fixes for each issue
- Schema recommendations and on-page improvements
- Blog topics and outlines crafted to help appear in AI answers

### 3) Lead gate + usage limits
After generating the audit, users unlock the full report by entering:
- Name
- Email

Leads are stored in a database (one row per email). Report unlocks are limited to 3 per email. This is an unverified unlock limit, not a limit on successful AI generations per verified email.

---

## Tech stack

### Frontend
- React (Vite)
- Responsive, modern landing + report UI
- Client calls serverless endpoints only (no secrets in the browser)

### Backend
- Vercel Serverless Functions

`POST /api/audit`
- Validates and normalizes the input URL
- Uses Supabase PostgreSQL to allow at most 5 new attempts per IP per rolling hour and 10 dispatched Claude attempts per UTC day across the site
- Calls Anthropic (Claude) securely using a server-side API key
- Returns a structured JSON report

`POST /api/lead`
- Saves name/email/audit URL to Supabase Postgres
- Enforces max 3 report unlocks per email

### Database
- Supabase Postgres
- `public.leads` stores:
  - `name`
  - `email` (unique)
  - `audit_url`
  - `audit_count`
  - `last_audit_at`
  - `created_at`

---

## Security and reliability notes
- No API keys are exposed to the client.
- All AI provider calls happen server-side via Vercel functions.
- Basic validation for URL/email and abuse-resistant rules (blocks localhost targets).
- `/api/audit` fails closed when the quota database is unavailable. The current email gate is not an Auth verification flow.
- CORS allowlist controlled by `ALLOWED_ORIGINS`.
- Database writes use UPSERT against a unique email constraint.

---

## API endpoints

### `POST /api/audit`
Request:
```json
{ "url": "https://example.com" }
```

The browser sends a stable `Idempotency-Key` header for each audit attempt. Browser and server-generated keys use cryptographically secure UUIDs. Reuse that key with the same URL to check or recover the same attempt without a second Claude call. A deliberate new attempt uses a new key. Older clients without the header remain supported; each request is treated as new. `GET /api/audit?url=https%3A%2F%2Fexample.com` with the same header is a read-only status/result check; the URL must match the original normalized audit URL. Results are also bound to the originating IP hash, so an IP change can prevent recovery. The successful response remains `{ "report": ... }`. Keys and raw IPs are never logged by the application.

Quota errors use HTTP 429 with a clear hourly or daily message. Database outages use HTTP 503 and do not call Anthropic. Every dispatched attempt counts against the daily limit, including provider failures and uncertain outcomes. A request recorded as dispatched is never automatically retried.

Response:
```json
{ "report": { "...": "structured audit json" } }
```

### `POST /api/lead`
Request:
```json
{
  "name": "John Doe",
  "email": "john@example.com",
  "auditUrl": "https://example.com"
}
```

Response:
```json
{ "ok": true, "auditCount": 1 }
```

If limit exceeded:
```json
{ "ok": false, "error": "Limit reached. You can generate up to 3 reports per email." }
```

---

## Environment variables

Set these in Vercel (Project Settings → Environment Variables).

### Required
- `ANTHROPIC_API_KEY`
- `ALLOWED_ORIGINS` (comma-separated)
- `SUPABASE_URL` (project API URL; server only for Phase 1)
- `SUPABASE_SERVICE_ROLE_KEY` (privileged server-only key)
- `IP_HASH_SECRET` (stable, random server-only HMAC secret for IP and request-key hashes)

Example:
```bash
ALLOWED_ORIGINS=https://chatgpt-rank.com,https://www.chatgpt-rank.com
```

### Supabase (via Vercel integration)
- `SUPABASE_POSTGRES_URL` (used server-side in `/api/lead`)

Do not use `VITE_*` names for any secret. The existing `SUPABASE_POSTGRES_URL` remains required for `/api/lead`; Phase 1 does not change that endpoint. The old in-memory `RATE_LIMIT_MAX` and `RATE_LIMIT_WINDOW_MS` settings no longer control `/api/audit`.

### Phase 1 deployment checklist

1. Check Supabase database health and available storage. Review `supabase/migrations/001_audit_attempts.sql` and back up the project before applying it. The migration adds only `public.audit_attempts` and four server-only functions; it does not alter `public.leads`.
2. Check that old Vercel deployment and preview URLs cannot still call Claude without the new limits. Protect or retire those URLs, or revoke the old Anthropic key and put a replacement only on the new deployment. This is necessary for a true site-wide cap.
3. Set the required server-only variables in the relevant Vercel environment. Keep `IP_HASH_SECRET` stable across deployments or prior idempotency keys and IP windows will no longer match.
4. Apply the reviewed SQL migration to Supabase **before** deploying the new API. Do not deploy the new API if the migration is absent: it will fail closed with 503.
5. Deploy API and frontend together. Check `POST /api/audit` with one permitted generation, same-key replay, read-only GET, hourly and daily error messages, and lead unlock. Avoid spending more production Claude attempts than needed.
6. Monitor Supabase errors, database storage, Vercel function errors, and `audit_attempts` state counts. The report JSON is stored for idempotent replay; at 10 attempts/day this is bounded to 3,650 reports/year but still needs storage monitoring. No cleanup scheduler or extra request-time write is introduced in Phase 1.

### Report payload retention

Run this bounded maintenance statement manually about once a month after reviewing a backup and the candidate count. It clears **only** successful report JSON older than 30 days. Repeat until it returns no rows. Keep the attempt rows, state, hashes, and dispatch timestamps: they are the quota and idempotency ledger. Do not delete or truncate them.

```sql
select count(*) from public.audit_attempts
where state = 'succeeded' and report is not null
  and dispatched_at < now() - interval '30 days';

with old_reports as (
  select attempt_id from public.audit_attempts
  where state = 'succeeded' and report is not null
    and dispatched_at < now() - interval '30 days'
  order by dispatched_at limit 100 for update skip locked
)
update public.audit_attempts as a set report = null
from old_reports as o where a.attempt_id = o.attempt_id
returning a.attempt_id;
```

After cleanup, replaying the same key returns HTTP 410 and never dispatches Claude. A deliberately new audit needs a new key and remains subject to current limits. Cleared JSON remains in PostgreSQL pages until normal vacuum can reclaim the space for reuse; avoid `VACUUM FULL` on the live free-plan database. This is a manual 30-day target, not automatic deletion.

Rollback: stop new generation traffic or deploy a corrected quota-enforcing build. Keep the additive migration and existing leads. Do not restore an old unrestricted `/api/audit` while its Anthropic key still works; that would remove the global safeguard. If a key is rotated, update only the intended deployment.

### Phase 1 tests

`npm test` runs mocked API tests. `tests/quota-concurrency.test.js` additionally exercises the SQL against a **disposable local PostgreSQL database** when `TEST_DATABASE_URL` points to localhost and a database whose name starts with `chatgpt_rank_test`. It refuses other database URLs, including production. Never aim this test at a Supabase project.

---

## Local development

1) Install dependencies
```bash
npm install
```

2) Run locally
```bash
npm run dev
```

Note: Serverless functions run in production on Vercel. For local function testing, you can use the Vercel CLI:
```bash
npm i -g vercel
vercel dev
```

---

## Roadmap
- User authentication (Supabase Auth)
- Pricing plans (Free / Pro) with usage tracking
- Audit history per user account
- Stripe billing and webhooks
- Admin dashboard for leads and report analytics

---

## Built by
Siddhesh Bakre

Live project: https://chatgpt-rank.com
