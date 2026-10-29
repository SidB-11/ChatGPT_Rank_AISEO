import test from 'node:test';
import assert from 'node:assert/strict';
import handler from '../api/audit.js';

const originalFetch = globalThis.fetch;
const originalEnv = { ...process.env };

function mockService() {
  const attempts = new Map();
  let providerCalls = 0;
  let databaseDown = false;
  let failedRpc = null;
  let providerFails = false;
  let providerWait = null;
  let providerEnvelope = null;
  let report = {
    site: { name: 'Test site' }, overall_score: 7, scores: {},
    wins: [], issues: [], tech_audit: [], meta_tags: {}, keywords: [],
    ai_overview: {}, eeat: {}, site_architecture: {}, blog_content: []
  };
  const hour = () => Date.now() - 3_600_000;
  const day = () => new Date().toISOString().slice(0, 10);

  async function fetchMock(url, options) {
    if (String(url).includes('/rest/v1/rpc/')) {
      if (databaseDown || String(url).endsWith(`/rpc/${failedRpc}`)) throw new Error('Database unavailable');
      const name = String(url).split('/').at(-1);
      const p = JSON.parse(options.body);
      const existing = attempts.get(p.p_key_hash);
      let result;
      if (name === 'get_audit_attempt') {
        result = existing?.ip === p.p_ip_hash && existing?.url === p.p_url_hash ? existingResult(existing) : null;
      } else if (name === 'reserve_audit_attempt') {
        if (existing) {
          result = existing.ip === p.p_ip_hash && existing.url === p.p_url_hash
            ? { ...existingResult(existing), attempt_id: existing.id, fresh: false }
            : { status: 'conflict' };
        } else if ([...attempts.values()].filter(a => a.ip === p.p_ip_hash && a.created > hour()).length >= 5) {
          result = { status: 'hourly_limit' };
        } else if ([...attempts.values()].filter(a => a.day === day()).length >= 10) {
          result = { status: 'daily_limit' };
        } else {
          const entry = { id: String(attempts.size + 1), key: p.p_key_hash, ip: p.p_ip_hash,
            url: p.p_url_hash, created: Date.now(), day: day(), status: 'reserved' };
          attempts.set(p.p_key_hash, entry);
          result = { status: 'reserved', fresh: true, attempt_id: entry.id };
        }
      } else if (name === 'claim_audit_dispatch') {
        const entry = attempts.get(p.p_key_hash);
        if (entry?.id === p.p_attempt_id && entry.status === 'reserved') {
          entry.status = 'dispatched';
          result = { status: 'claimed' };
        } else result = { status: entry?.status || 'expired' };
      } else if (name === 'finish_audit_attempt') {
        const entry = attempts.get(p.p_key_hash);
        if (entry?.status === 'dispatched') {
          entry.status = p.p_report ? 'succeeded' : 'failed';
          entry.report = p.p_report;
          entry.http_status = p.p_http_status;
          entry.error = p.p_error;
        }
        result = entry ? existingResult(entry) : null;
      } else throw new Error(`Unexpected RPC ${name}`);
      return Response.json(result);
    }
    assert.equal(url, 'https://api.anthropic.com/v1/messages');
    providerCalls += 1;
    if (providerWait) await providerWait;
    return providerFails
      ? Response.json({ error: 'private upstream detail' }, { status: 500 })
      : Response.json(providerEnvelope || { content: [{ type: 'text', text: JSON.stringify(report) }] });
  }
  function existingResult(a) {
    const status = a.status === 'succeeded' && !a.report ? 'result_expired' : a.status;
    return { status, report: a.report || null, http_status: a.http_status || null, error: a.error || null };
  }
  return { fetchMock, attempts, get providerCalls() { return providerCalls; },
    get providerReport() { return report; }, set providerReport(value) { report = value; },
    set providerEnvelope(value) { providerEnvelope = value; },
    set databaseDown(v) { databaseDown = v; }, set failedRpc(v) { failedRpc = v; },
    set providerFails(v) { providerFails = v; }, set providerWait(v) { providerWait = v; } };
}

async function request(key, ip = '203.0.113.1', url = 'https://example.com', method = 'POST') {
  const headers = { 'idempotency-key': key, 'x-vercel-forwarded-for': ip };
  const req = { method, headers, body: { url }, query: { url }, socket: {} };
  const res = { headers: {}, setHeader(name, value) { this.headers[name] = value; },
    status(code) { this.statusCode = code; return this; },
    json(body) { this.body = body; return this; } };
  await handler(req, res);
  return res;
}

test.beforeEach(() => {
  process.env.VERCEL = '1';
  process.env.SUPABASE_URL = 'https://test.supabase.co';
  process.env.SUPABASE_SERVICE_ROLE_KEY = 'test-server-only-key';
  process.env.IP_HASH_SECRET = 'test-hmac-secret-with-enough-length';
  process.env.ANTHROPIC_API_KEY = 'test-anthropic-key';
});
test.afterEach(() => { globalThis.fetch = originalFetch; process.env = { ...originalEnv }; });

test('concurrent requests stop at the 10-attempt daily cap', async () => {
  const service = mockService(); globalThis.fetch = service.fetchMock;
  const results = await Promise.all(Array.from({ length: 20 }, (_, i) =>
    request(`daily-key-${String(i).padStart(12, '0')}`, `203.0.113.${i + 1}`)));
  assert.equal(results.filter(r => r.statusCode === 200).length, 10);
  assert.equal(results.filter(r => r.statusCode === 429).length, 10);
  assert.equal(service.providerCalls, 10);
  assert.match(results.find(r => r.statusCode === 429).body.error, /site-wide limit/);
});

test('direct legacy requests without a key still obey the global cap', async () => {
  const service = mockService(); globalThis.fetch = service.fetchMock;
  const results = await Promise.all(Array.from({ length: 11 }, (_, i) =>
    request(null, `198.51.100.${i + 1}`)));
  assert.equal(results.filter(r => r.statusCode === 200).length, 10);
  assert.equal(results.filter(r => r.statusCode === 429).length, 1);
  assert.equal(service.providerCalls, 10);
});

test('six new attempts from one IP allow five; replay and status are free', async () => {
  const service = mockService(); globalThis.fetch = service.fetchMock;
  const key = 'hourly-key-00000001';
  const first = await request(key);
  const replay = await request(key);
  const status = await request(key, '203.0.113.1', undefined, 'GET');
  assert.equal(first.statusCode, 200);
  assert.deepEqual(replay.body, first.body);
  assert.deepEqual(status.body, first.body);
  for (let i = 2; i <= 5; i++) assert.equal((await request(`hourly-key-0000000${i}`)).statusCode, 200);
  const blocked = await request('hourly-key-00000006');
  assert.equal(blocked.statusCode, 429);
  assert.match(blocked.body.error, /past hour/);
  assert.equal(service.providerCalls, 5);
});

test('status lookup requires the original URL and returns no report for a mismatch', async () => {
  const service = mockService(); globalThis.fetch = service.fetchMock;
  const key = 'status-url-key-000001';
  assert.equal((await request(key)).statusCode, 200);
  assert.equal((await request(key, '203.0.113.1', 'https://other.example', 'GET')).statusCode, 404);
  assert.equal((await request(key, '203.0.113.1', null, 'GET')).statusCode, 400);
  assert.equal((await request(key, '203.0.113.2', 'https://example.com', 'GET')).statusCode, 404);
  assert.equal(service.providerCalls, 1);
});

test('provider failures still spend the daily and IP attempt; replay does not retry', async () => {
  const service = mockService(); service.providerFails = true; globalThis.fetch = service.fetchMock;
  const key = 'failure-key-000001';
  const failed = await request(key);
  const replay = await request(key);
  assert.equal(failed.statusCode, 502);
  assert.deepEqual(replay.body, failed.body);
  assert.equal(service.providerCalls, 1);
  assert.equal(service.attempts.size, 1);
  assert.doesNotMatch(JSON.stringify(failed.body), /private upstream detail/);
});

test('malformed successful provider JSON is stored as a failed attempt and never replayed as a report', async () => {
  const service = mockService(); globalThis.fetch = service.fetchMock;
  service.providerReport = { site: { name: 'Incomplete' }, overall_score: 7 };
  const key = 'malformed-report-key-01';
  const failed = await request(key);
  assert.equal(failed.statusCode, 502);
  assert.ok(!('report' in failed.body));
  const attempt = [...service.attempts.values()][0];
  assert.equal(attempt.status, 'failed');
  assert.equal(attempt.report, null);
  assert.equal(attempt.day, new Date().toISOString().slice(0, 10));
  assert.equal((await request(key)).statusCode, 502);
  assert.equal(service.providerCalls, 1);
});

test('wrong report section types fail while optional content may be absent', async () => {
  const service = mockService(); globalThis.fetch = service.fetchMock;
  service.providerReport = { ...service.providerReport, issues: { title: 'Not an array' } };
  const failed = await request('wrong-report-type-key-1');
  assert.equal(failed.statusCode, 502);
  assert.equal(service.providerCalls, 1);
  service.providerReport = { ...service.providerReport, issues: [] };
  const valid = await request('valid-sparse-report-key-1', '203.0.113.2');
  assert.equal(valid.statusCode, 200);
  assert.deepEqual(valid.body.report.issues, []);
});

test('malformed provider content envelope is a definite failed generation', async () => {
  const service = mockService(); globalThis.fetch = service.fetchMock;
  service.providerEnvelope = { content: { text: 'invalid shape' } };
  const result = await request('bad-provider-shape-01');
  assert.equal(result.statusCode, 502);
  assert.equal([...service.attempts.values()][0].status, 'failed');
  assert.equal(service.providerCalls, 1);
});

test('database outage fails closed before Anthropic', async () => {
  const service = mockService(); service.databaseDown = true; globalThis.fetch = service.fetchMock;
  const result = await request('outage-key-00000001');
  assert.equal(result.statusCode, 503);
  assert.equal(service.providerCalls, 0);
  assert.match(result.body.error, /temporarily unavailable/);
});

test('missing trusted production IP fails closed before Anthropic', async () => {
  const service = mockService(); globalThis.fetch = service.fetchMock;
  const result = await request('missing-ip-key-00001', 'not-an-ip');
  assert.equal(result.statusCode, 503);
  assert.equal(service.providerCalls, 0);
});

test('dispatch authorization outage also fails closed', async () => {
  const service = mockService(); service.failedRpc = 'claim_audit_dispatch'; globalThis.fetch = service.fetchMock;
  const result = await request('claim-outage-key-0001');
  assert.equal(result.statusCode, 503);
  assert.equal(service.providerCalls, 0);
});

test('result persistence outage does not return an uncommitted report', async () => {
  const service = mockService(); service.failedRpc = 'finish_audit_attempt'; globalThis.fetch = service.fetchMock;
  const key = 'finish-outage-key-0001';
  const result = await request(key);
  assert.equal(result.statusCode, 503);
  assert.equal(service.providerCalls, 1);
  assert.equal((await request(key)).statusCode, 409);
  assert.equal((await request(key, '203.0.113.1', 'https://example.com', 'GET')).statusCode, 409);
  assert.equal(service.providerCalls, 1);
});

test('pruned report replay is explicit and never dispatches Claude again', async () => {
  const service = mockService(); globalThis.fetch = service.fetchMock;
  const key = 'pruned-result-key-01';
  assert.equal((await request(key)).statusCode, 200);
  const attempt = [...service.attempts.values()][0];
  attempt.report = null;
  assert.equal((await request(key)).statusCode, 410);
  assert.equal((await request(key, '203.0.113.1', 'https://example.com', 'GET')).statusCode, 410);
  assert.equal(service.providerCalls, 1);
});

test('concurrent replay of a processing request does not dispatch twice', async () => {
  const service = mockService(); globalThis.fetch = service.fetchMock;
  let release;
  service.providerWait = new Promise(resolve => { release = resolve; });
  const key = 'concurrent-replay-key-1';
  const first = request(key);
  for (let i = 0; i < 10 && service.providerCalls === 0; i++) await new Promise(resolve => setTimeout(resolve, 1));
  assert.equal(service.providerCalls, 1);
  const replay = await request(key);
  assert.equal(replay.statusCode, 409);
  release();
  assert.equal((await first).statusCode, 200);
  assert.equal((await request(key)).statusCode, 200);
  assert.equal(service.providerCalls, 1);
});

test('same key with different URL is rejected without another provider call', async () => {
  const service = mockService(); globalThis.fetch = service.fetchMock;
  await request('conflict-key-000001');
  const result = await request('conflict-key-000001', '203.0.113.1', 'https://other.example');
  assert.equal(result.statusCode, 409);
  assert.equal(service.providerCalls, 1);
});
