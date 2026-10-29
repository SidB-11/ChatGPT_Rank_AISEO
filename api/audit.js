// Vercel Serverless Function: POST /api/audit
// Keeps Anthropic API key server-side (never expose in the browser)

import { createHmac, createHash, randomUUID } from 'node:crypto';
import { isIP } from 'node:net';

function getClientIp(req) {
  // Vercel replaces forwarded IP headers on its public edge. Do not trust
  // caller-supplied forwarding headers during local development.
  const forwarded = process.env.VERCEL === '1'
    ? req.headers['x-vercel-forwarded-for'] || req.headers['x-forwarded-for']
    : undefined;
  let ip = process.env.VERCEL === '1'
    ? (Array.isArray(forwarded) ? forwarded[0] : forwarded)?.split(',')[0]?.trim()
    : req.socket?.remoteAddress;
  if (ip?.startsWith('::ffff:')) ip = ip.slice(7);
  return isIP(ip || '') ? ip : null;
}

function hash(value) {
  return createHmac('sha256', process.env.IP_HASH_SECRET).update(value).digest('hex');
}

function urlHash(value) {
  return createHash('sha256').update(value).digest('hex');
}

async function quotaRpc(name, args) {
  const endpoint = process.env.SUPABASE_URL?.replace(/\/$/, '');
  const key = process.env.SUPABASE_SERVICE_ROLE_KEY;
  const response = await fetch(`${endpoint}/rest/v1/rpc/${name}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', apikey: key, Authorization: `Bearer ${key}` },
    body: JSON.stringify(args),
    signal: AbortSignal.timeout(5000)
  });
  if (!response.ok) throw new Error('Quota service unavailable');
  return response.json();
}

function quotaUnavailable(res) {
  return res.status(503).json({ error: 'Reports are temporarily unavailable. Please try again shortly.' });
}

function attemptResponse(res, attempt) {
  switch (attempt.status) {
    case 'succeeded': return attempt.report == null
      ? res.status(410).json({ error: 'This saved report is no longer available. Start a new audit to generate another.' })
      : res.status(200).json({ report: attempt.report });
    case 'hourly_limit': return res.status(429).json({ error: 'This network has reached 5 new reports in the past hour. Please try again later.' });
    case 'daily_limit': return res.status(429).json({ error: 'Today\'s site-wide limit of 10 AI reports has been reached. Please try again after 00:00 UTC.' });
    case 'conflict': return res.status(409).json({ error: 'This request key was already used for a different audit.' });
    case 'failed': return res.status(attempt.http_status || 502).json({ error: attempt.error || 'Report generation failed. Start a new audit to try again.' });
    case 'expired': return res.status(409).json({ error: 'This audit could not start. Start a new audit to try again.' });
    case 'result_expired': return res.status(410).json({ error: 'This saved report is no longer available. Start a new audit to generate another.' });
    case 'reserved':
    case 'dispatched': return res.status(409).json({ error: 'This report is processing or its outcome is uncertain. Retry with the same request key later; no new AI request was started.' });
    default: return quotaUnavailable(res);
  }
}

function isAllowedOrigin(origin, allowed) {
  if (!origin) return true; // same-origin or non-browser
  if (!allowed || !allowed.length) return true;
  return allowed.includes(origin);
}

function normalizeAndValidateUrl(input) {
  if (typeof input !== 'string') throw new Error('Invalid URL');
  let raw = input.trim();
  if (!raw) throw new Error('URL is required');
  if (raw.length > 2048) throw new Error('URL is too long');
  if (!/^https?:\/\//i.test(raw)) raw = `https://${raw}`;

  let u;
  try { u = new URL(raw); } catch { throw new Error('Invalid URL'); }

  if (!['http:', 'https:'].includes(u.protocol)) throw new Error('URL must start with http or https');
  if (!u.hostname || !u.hostname.includes('.')) throw new Error('Invalid hostname');

  // Block obvious local targets (even though we do not fetch the site, this avoids abuse in logs/prompts)
  const h = u.hostname.toLowerCase();
  const blockedHosts = new Set(['localhost', '127.0.0.1', '0.0.0.0', '::1']);
  if (blockedHosts.has(h)) throw new Error('Localhost URLs are not allowed');

  // Strip credentials if present
  u.username = '';
  u.password = '';

  return u.toString();
}

function isObject(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function isValidReport(report) {
  if (!isObject(report) || !isObject(report.site) ||
      !Number.isFinite(report.overall_score) || !isObject(report.scores)) return false;

  // Each report tab consumes one of these top-level sections. Empty sections
  // remain valid; optional individual recommendations are not required.
  const objects = ['meta_tags', 'ai_overview', 'eeat', 'site_architecture'];
  const arrays = ['wins', 'issues', 'tech_audit', 'keywords', 'blog_content'];
  if (!objects.every(field => isObject(report[field])) ||
      !arrays.every(field => Array.isArray(report[field]) && report[field].every(isObject))) return false;

  // The UI maps these optional lists when present, so reject wrong types.
  const optionalLists = [
    [report, 'quick_wins'], [report.meta_tags, 'schemas'],
    [report.ai_overview, 'tips'], [report.ai_overview, 'query_types'],
    [report.eeat, 'improvements'], [report.site_architecture, 'issues'],
    [report.site_architecture, 'recommendations']
  ];
  return optionalLists.every(([parent, field]) => parent[field] == null || Array.isArray(parent[field])) &&
    report.blog_content.every(post => post.outline == null || Array.isArray(post.outline));
}

function buildPrompt(url) {
  // Kept same JSON schema as your original prompt.
  return `You are a senior SEO strategist and AI search expert. Analyze this website: ${url}

CRITICAL RULES:
- NEVER say ranking is impossible, difficult, challenging, or hard
- ALWAYS frame as opportunity with clear path forward
- Be 100% SPECIFIC to this URL — zero generic advice
- Return ONLY raw JSON — no markdown, no backticks, nothing else

{"site":{"url":"${url}","name":"real business name","type":"specific business type","location":"city/country or Global","tagline":"one sharp specific sentence about their SEO situation"},"overall_score":6,"scores":{"technical":6,"content":5,"onpage":4,"local":7,"performance":6,"ai_readiness":4,"eeat":5},"missed_traffic_estimate":"2,000–5,000 monthly visitors","wins":[{"title":"Specific Win","desc":"specific desc with data"},{"title":"Specific Win","desc":"specific desc"},{"title":"Specific Win","desc":"specific desc"}],"issues":[{"priority":"HIGH","title":"issue","desc":"specific what is wrong","fix":"exact actionable fix"},{"priority":"HIGH","title":"issue","desc":"specific what is wrong","fix":"exact actionable fix"},{"priority":"MED","title":"issue","desc":"specific what is wrong","fix":"exact actionable fix"},{"priority":"MED","title":"issue","desc":"specific what is wrong","fix":"exact actionable fix"},{"priority":"LOW","title":"issue","desc":"specific what is wrong","fix":"exact actionable fix"}],"tech_audit":[{"check":"HTTPS / SSL","status":"pass","note":"specific"},{"check":"Mobile Responsive","status":"pass","note":"specific"},{"check":"Page Speed","status":"warn","note":"specific"},{"check":"Core Web Vitals","status":"warn","note":"specific"},{"check":"XML Sitemap","status":"pass","note":"specific"},{"check":"Robots.txt","status":"pass","note":"specific"},{"check":"Canonical Tags","status":"warn","note":"specific"},{"check":"Structured Data","status":"fail","note":"specific"},{"check":"Broken Links","status":"warn","note":"specific"},{"check":"Image Alt Text","status":"warn","note":"specific"},{"check":"404 Error Page","status":"pass","note":"specific"},{"check":"HTTPS Redirects","status":"pass","note":"specific"},{"check":"Internal Linking","status":"warn","note":"specific"},{"check":"URL Structure","status":"pass","note":"specific"}],"meta_tags":{"title":{"current":"current title text","char_count":62,"status":"long","issue":"specific issue","suggestion":"optimized under 60 chars"},"meta_description":{"current":"current meta text","char_count":131,"status":"short","issue":"specific issue","suggestion":"optimized 150-160 chars with CTA"},"schemas":[{"type":"Organization","status":"missing","impact":"HIGH","hint":"Add JSON-LD Organization with name,logo,contact,sameAs"},{"type":"LocalBusiness","status":"missing","impact":"HIGH","hint":"Add LocalBusiness with address,phone,hours,geo"},{"type":"FAQPage","status":"missing","impact":"HIGH","hint":"Add 12-15 FAQ pairs for AI Overview eligibility"},{"type":"WebSite","status":"missing","impact":"MED","hint":"Add WebSite schema for sitelinks searchbox"},{"type":"BreadcrumbList","status":"missing","impact":"MED","hint":"Breadcrumbs on all inner pages"},{"type":"Article","status":"missing","impact":"HIGH","hint":"Add Article schema on blog posts with author,datePublished"}]} ,"keywords":[{"keyword":"specific kw","intent":"Commercial","difficulty":"High","volume":"High","priority":"HIGH"},{"keyword":"specific kw","intent":"Local","difficulty":"Med","volume":"Med","priority":"HIGH"},{"keyword":"specific kw","intent":"Informational","difficulty":"Low","volume":"Med","priority":"MED"},{"keyword":"specific kw","intent":"Commercial","difficulty":"High","volume":"High","priority":"MED"},{"keyword":"specific kw","intent":"Navigational","difficulty":"Low","volume":"Low","priority":"LOW"}],"ai_overview":{"score":3,"opportunity":"specific 2-3 sentence opportunity for this site","status":"Not optimized","tips":["specific tip 1","specific tip 2","specific tip 3","specific tip 4"],"query_types":["specific question query","specific comparison query","specific how-to query"]},"eeat":{"experience":{"score":5,"status":"Needs work","note":"specific observation"},"expertise":{"score":6,"status":"Moderate","note":"specific observation"},"authoritativeness":{"score":4,"status":"Weak","note":"specific observation"},"trustworthiness":{"score":5,"status":"Moderate","note":"specific observation"},"improvements":["specific action","specific action","specific action","specific action","specific action"]},"site_architecture":{"assessment":"2-3 specific sentences","depth_score":5,"issues":["specific issue","specific issue","specific issue"],"recommendations":["specific rec","specific rec","specific rec"]},"blog_content":[{"topic":"specific blog title for AI Overview","search_intent":"Informational","volume":"Med (1k-10k)","ai_angle":"why this wins AI Overview","outline":["H2: specific","H2: specific","H2: specific","H2: specific"]},{"topic":"specific comparison post","search_intent":"Commercial","volume":"High (10k+)","ai_angle":"comparison format wins AI Overview","outline":["H2: specific","H2: specific","H2: specific"]},{"topic":"specific how-to guide","search_intent":"Informational","volume":"Low (<1k)","ai_angle":"step-by-step gets cited by AI","outline":["H2: specific","H2: specific","H2: specific"]},{"topic":"specific location/niche guide","search_intent":"Informational","volume":"Med (1k-10k)","ai_angle":"location guides dominate AI Overviews","outline":["H2: specific","H2: specific","H2: specific"]}],"quick_wins":["specific this-week action","specific action","specific action","specific action"],"ai_tip":"one sharp AI search tip specific to this exact site and business"}`;
}

export default async function handler(req, res) {
  if (req.method !== 'POST' && req.method !== 'GET') {
    res.setHeader('Allow', 'POST, GET');
    return res.status(405).json({ error: 'Method not allowed' });
  }
  res.setHeader('Cache-Control', 'no-store');

  const origin = req.headers.origin;
  const allowedOrigins = (process.env.ALLOWED_ORIGINS || '')
    .split(',')
    .map(s => s.trim())
    .filter(Boolean);

  if (!isAllowedOrigin(origin, allowedOrigins)) {
    return res.status(403).json({ error: 'Origin not allowed' });
  }

  // CORS headers (only when an Origin is present)
  if (origin) {
    res.setHeader('Access-Control-Allow-Origin', origin);
    res.setHeader('Vary', 'Origin');
  }

  const ip = getClientIp(req);
  const apiKey = process.env.ANTHROPIC_API_KEY;
  if (!ip || !process.env.SUPABASE_URL || !process.env.SUPABASE_SERVICE_ROLE_KEY || !process.env.IP_HASH_SECRET || !apiKey) return quotaUnavailable(res);

  const suppliedKey = req.headers['idempotency-key'];
  const requestKey = suppliedKey || (req.method === 'POST' ? randomUUID() : null);
  if (typeof requestKey !== 'string' || !/^[a-zA-Z0-9_-]{16,128}$/.test(requestKey)) {
    return res.status(400).json({ error: 'Invalid or missing request key.' });
  }
  const ipHash = hash(`ip:${ip}`);
  const keyHash = hash(`request:${requestKey}`);

  if (req.method === 'GET') {
    let safeUrl;
    try { safeUrl = normalizeAndValidateUrl(req.query?.url); }
    catch { return res.status(400).json({ error: 'A valid audit URL is required for status lookup.' }); }
    try {
      const attempt = await quotaRpc('get_audit_attempt', { p_key_hash: keyHash, p_ip_hash: ipHash, p_url_hash: urlHash(safeUrl) });
      if (!attempt) return res.status(404).json({ error: 'Audit request not found.' });
      return attemptResponse(res, attempt);
    } catch { return quotaUnavailable(res); }
  }

  let attemptId;
  let dispatched = false;
  try {
    const { url } = req.body || {};
    const safeUrl = normalizeAndValidateUrl(url);
    const reservation = await quotaRpc('reserve_audit_attempt', {
      p_key_hash: keyHash,
      p_ip_hash: ipHash,
      p_url_hash: urlHash(safeUrl)
    });
    if (reservation.status !== 'reserved' || !reservation.fresh) return attemptResponse(res, reservation);
    attemptId = reservation.attempt_id;
    const claim = await quotaRpc('claim_audit_dispatch', { p_attempt_id: attemptId, p_key_hash: keyHash });
    if (claim.status !== 'claimed') return attemptResponse(res, claim);
    dispatched = true;
    const prompt = buildPrompt(safeUrl);

    const upstream = await fetch('https://api.anthropic.com/v1/messages', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'x-api-key': apiKey,
        'anthropic-version': '2023-06-01'
      },
      body: JSON.stringify({
        model: 'claude-sonnet-4-20250514',
        max_tokens: 8000,
        messages: [{ role: 'user', content: prompt }]
      }),
      signal: AbortSignal.timeout(60_000)
    });

    const text = await upstream.text();
    if (!upstream.ok) {
      const failure = { error: 'AI provider is temporarily unavailable. Please start a new audit later.', http_status: 502 };
      const result = await quotaRpc('finish_audit_attempt', { p_attempt_id: attemptId, p_key_hash: keyHash, p_report: null, p_http_status: failure.http_status, p_error: failure.error });
      return attemptResponse(res, result || {});
    }

    // Anthropic response is JSON
    let data;
    try { data = JSON.parse(text); }
    catch { throw new Error('Invalid AI response format'); }
    const rawText = Array.isArray(data?.content)
      ? data.content.find(b => b?.type === 'text')?.text
      : null;
    if (typeof rawText !== 'string') throw new Error('Invalid AI response format');
    const s = rawText.indexOf('{');
    const e = rawText.lastIndexOf('}');
    if (s === -1 || e === -1) {
      throw new Error('Invalid AI response format');
    }

    let parsed;
    try { parsed = JSON.parse(rawText.slice(s, e + 1)); }
    catch { throw new Error('Invalid AI response format'); }
    if (!isValidReport(parsed)) throw new Error('Invalid AI response format');

    const result = await quotaRpc('finish_audit_attempt', { p_attempt_id: attemptId, p_key_hash: keyHash, p_report: parsed, p_http_status: null, p_error: null });
    return attemptResponse(res, result || {});
  } catch (err) {
    if (!attemptId && ['Invalid URL', 'URL is required', 'URL is too long', 'Invalid hostname', 'Localhost URLs are not allowed', 'URL must start with http or https'].includes(err.message)) {
      return res.status(400).json({ error: err.message });
    }
    if (dispatched && err.message === 'Invalid AI response format') {
      try {
        const result = await quotaRpc('finish_audit_attempt', { p_attempt_id: attemptId, p_key_hash: keyHash, p_report: null, p_http_status: 502, p_error: 'AI returned an invalid report. Please start a new audit later.' });
        return attemptResponse(res, result || {});
      } catch { return quotaUnavailable(res); }
    }
    return quotaUnavailable(res);
  }
}
