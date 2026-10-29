import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import postgres from 'postgres';

const connection = process.env.TEST_DATABASE_URL;
function isDisposableLocalDatabase(value) {
  if (!value) return false;
  try {
    const u = new URL(value);
    return ['localhost', '127.0.0.1', '::1', '[::1]'].includes(u.hostname)
      && u.pathname.slice(1).startsWith('chatgpt_rank_test');
  } catch { return false; }
}

test('real PostgreSQL quota concurrency and permissions', {
  skip: isDisposableLocalDatabase(connection) ? false : 'Requires TEST_DATABASE_URL for a disposable local chatgpt_rank_test database'
}, async () => {
  const sql = postgres(connection, { max: 20, prepare: false });
  try {
    // A plain disposable Postgres instance does not have Supabase's API roles.
    await sql.unsafe(`do $$ begin
      if not exists (select 1 from pg_roles where rolname = 'anon') then create role anon; end if;
      if not exists (select 1 from pg_roles where rolname = 'authenticated') then create role authenticated; end if;
      if not exists (select 1 from pg_roles where rolname = 'service_role') then create role service_role bypassrls; end if;
    end $$`);
    await sql`grant usage on schema public to service_role`;
    const migration = await readFile(new URL('../supabase/migrations/001_audit_attempts.sql', import.meta.url), 'utf8');
    // postgres.js rejects explicit BEGIN/COMMIT on a multi-connection pool.
    // Apply the migration on one dedicated connection, then use the pool for races.
    const migrationSql = postgres(connection, { max: 1, prepare: false });
    try { await migrationSql.unsafe(migration); }
    finally { await migrationSql.end(); }
    const h = i => i.toString(16).padStart(64, '0');
    const reserve = async (i, ip) => {
      const [row] = await sql`select public.reserve_audit_attempt(${h(i)}, ${h(ip)}, ${h(1000 + i)}) as result`;
      return row.result;
    };
    const claim = async (r, i) => {
      const [row] = await sql`select public.claim_audit_dispatch(${r.attempt_id}, ${h(i)}) as result`;
      return row.result;
    };

    const reservations = await Promise.all(Array.from({ length: 30 }, async (_, i) =>
      ({ i, result: await reserve(i + 1, i + 101) })));
    const admitted = reservations.filter(({ result }) => result.status === 'reserved');
    assert.equal(admitted.length, 10);
    assert.equal(reservations.filter(({ result }) => result.status === 'daily_limit').length, 20);
    const claims = await Promise.all(admitted.map(({ i, result }) => claim(result, i + 1)));
    assert.equal(claims.filter(c => c.status === 'claimed').length, 10);
    assert.equal((await reserve(admitted[0].i + 1, admitted[0].i + 101)).status, 'dispatched');
    assert.equal((await claim(admitted[0].result, admitted[0].i + 1)).status, 'dispatched');
    const [daily] = await sql`select count(*)::int as n from public.audit_attempts where dispatched_at >= date_trunc('day', now() at time zone 'UTC') at time zone 'UTC'`;
    assert.equal(daily.n, 10);

    await sql`truncate public.audit_attempts`;
    const ipReservations = await Promise.all(Array.from({ length: 12 }, async (_, i) =>
      ({ i, result: await reserve(i + 1, 200) })));
    const ipAdmitted = ipReservations.filter(({ result }) => result.status === 'reserved');
    assert.equal(ipAdmitted.length, 5);
    assert.equal(ipReservations.filter(({ result }) => result.status === 'hourly_limit').length, 7);
    await Promise.all(ipAdmitted.map(({ i, result }) => claim(result, i + 1)));
    const [failed] = await sql`select public.finish_audit_attempt(${ipAdmitted[0].result.attempt_id}, ${h(ipAdmitted[0].i + 1)}, ${null}::jsonb, ${502}, ${'Provider failed'}) as result`;
    assert.equal(failed.result.status, 'failed');
    assert.equal((await reserve(90, 200)).status, 'hourly_limit');

    await sql`truncate public.audit_attempts`;
    const pending = await reserve(400, 400);
    assert.equal(pending.status, 'reserved');
    const replay = await reserve(400, 400);
    assert.equal(replay.status, 'reserved');
    assert.equal(replay.fresh, false);
    assert.equal(replay.attempt_id, pending.attempt_id);
    const [conflict] = await sql`select public.reserve_audit_attempt(${h(400)}, ${h(400)}, ${h(9999)}) as result`;
    assert.equal(conflict.result.status, 'conflict');
    assert.equal((await claim(pending, 400)).status, 'claimed');
    assert.equal((await claim(pending, 400)).status, 'dispatched');
    const report = { site: { name: 'Recovered report' } };
    const [completed] = await sql`select public.finish_audit_attempt(${pending.attempt_id}, ${h(400)}, ${sql.json(report)}, ${null}, ${null}) as result`;
    assert.equal(completed.result.status, 'succeeded');
    assert.deepEqual(completed.result.report, report);
    const [completedAgain] = await sql`select public.finish_audit_attempt(${pending.attempt_id}, ${h(400)}, ${sql.json({ changed: true })}, ${null}, ${null}) as result`;
    assert.deepEqual(completedAgain.result.report, report);
    const [wrongUrl] = await sql`select public.get_audit_attempt(${h(400)}, ${h(400)}, ${h(9999)}) as result`;
    assert.equal(wrongUrl.result, null);

    const abandoned = await reserve(401, 401);
    await sql`update public.audit_attempts set reserved_until = now() - interval '1 second' where attempt_id = ${abandoned.attempt_id}`;
    assert.equal((await claim(abandoned, 401)).status, 'expired');
    assert.equal((await reserve(401, 401)).status, 'expired');
    assert.equal((await reserve(402, 401)).status, 'reserved');

    const [table] = await sql`select relrowsecurity as enabled from pg_class where oid = 'public.audit_attempts'::regclass`;
    assert.equal(table.enabled, true);
    const roles = await sql`select proname, has_function_privilege('anon', oid, 'EXECUTE') as anon,
      has_function_privilege('authenticated', oid, 'EXECUTE') as authenticated,
      has_function_privilege('service_role', oid, 'EXECUTE') as service
      from pg_proc where pronamespace = 'public'::regnamespace and proname in
      ('get_audit_attempt', 'reserve_audit_attempt', 'claim_audit_dispatch', 'finish_audit_attempt')`;
    assert.equal(roles.length, 4);
    for (const role of roles) {
      assert.equal(role.anon, false);
      assert.equal(role.authenticated, false);
      assert.equal(role.service, true);
    }
    await assert.rejects(sql.begin(async tx => {
      await tx.unsafe('set local role anon');
      await tx`select public.get_audit_attempt(${h(400)}, ${h(400)}, ${h(1400)})`;
    }), error => error.code === '42501');
    await assert.rejects(sql.begin(async tx => {
      await tx.unsafe('set local role authenticated');
      await tx`select public.reserve_audit_attempt(${h(403)}, ${h(403)}, ${h(403)})`;
    }), error => error.code === '42501');
    await sql.begin(async tx => {
      await tx.unsafe('set local role service_role');
      const [row] = await tx`select public.get_audit_attempt(${h(400)}, ${h(400)}, ${h(1400)}) as result`;
      assert.equal(row.result.status, 'succeeded');
      assert.deepEqual(row.result.report, report);
    });

    // The documented maintenance operation removes only old report payloads.
    // Ledger rows, states, and dispatch timestamps remain for quota accounting.
    const recent = await reserve(410, 410);
    assert.equal((await claim(recent, 410)).status, 'claimed');
    await sql`select public.finish_audit_attempt(${recent.attempt_id}, ${h(410)}, ${sql.json(report)}, ${null}, ${null})`;
    await sql`update public.audit_attempts set dispatched_at = now() - interval '31 days'
      where attempt_id = ${pending.attempt_id}`;
    const [cleanup] = await sql`with old_reports as (
      select attempt_id from public.audit_attempts
      where state = 'succeeded' and report is not null
        and dispatched_at < now() - interval '30 days'
      order by dispatched_at limit 100 for update skip locked
    ) update public.audit_attempts as a set report = null
      from old_reports as o where a.attempt_id = o.attempt_id
      returning a.attempt_id`;
    assert.equal(cleanup.attempt_id, pending.attempt_id);
    const [pruned] = await sql`select public.get_audit_attempt(${h(400)}, ${h(400)}, ${h(1400)}) as result`;
    assert.equal(pruned.result.status, 'result_expired');
    assert.equal((await reserve(400, 400)).status, 'result_expired');
    const [finishAfterPrune] = await sql`select public.finish_audit_attempt(${pending.attempt_id}, ${h(400)}, ${sql.json(report)}, ${null}, ${null}) as result`;
    assert.equal(finishAfterPrune.result.status, 'result_expired');
    assert.equal(finishAfterPrune.result.report, null);
    const [recentResult] = await sql`select public.get_audit_attempt(${h(410)}, ${h(410)}, ${h(1410)}) as result`;
    assert.deepEqual(recentResult.result.report, report);
    const [remainingToday] = await sql`select count(*)::int as n from public.audit_attempts
      where dispatched_at >= date_trunc('day', now() at time zone 'UTC') at time zone 'UTC'`;
    assert.equal(remainingToday.n, 1);
  } finally {
    await sql.end();
  }
});
