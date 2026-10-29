-- Phase 1: application-wide Claude attempt and per-IP limits.
-- Apply only after reviewing the target project; this file does not touch leads.
begin;

create table public.audit_attempts (
  attempt_id uuid primary key default gen_random_uuid(),
  key_hash text not null unique check (key_hash ~ '^[0-9a-f]{64}$'),
  ip_hash text not null check (ip_hash ~ '^[0-9a-f]{64}$'),
  url_hash text not null check (url_hash ~ '^[0-9a-f]{64}$'),
  created_at timestamptz not null default now(),
  reserved_until timestamptz not null,
  state text not null default 'reserved' check (state in ('reserved', 'dispatched', 'succeeded', 'failed')),
  dispatched_at timestamptz,
  report jsonb,
  http_status integer,
  error text,
  constraint audit_attempt_shape check (
    (state = 'reserved' and dispatched_at is null and report is null)
    or (state <> 'reserved' and dispatched_at is not null)
  )
);

create index audit_attempts_ip_time_idx on public.audit_attempts (ip_hash, created_at desc);
create index audit_attempts_dispatch_time_idx on public.audit_attempts (dispatched_at) where dispatched_at is not null;
create index audit_attempts_reservation_idx on public.audit_attempts (created_at, reserved_until) where state = 'reserved';

alter table public.audit_attempts enable row level security;
revoke all on public.audit_attempts from public, anon, authenticated;
grant select, insert, update on public.audit_attempts to service_role;

create function public.get_audit_attempt(p_key_hash text, p_ip_hash text, p_url_hash text)
returns jsonb language plpgsql security invoker set search_path = '' as $$
declare
  a public.audit_attempts%rowtype;
begin
  select * into a from public.audit_attempts
  where key_hash = p_key_hash and ip_hash = p_ip_hash and url_hash = p_url_hash;
  if not found then return null; end if;
  return jsonb_build_object(
    'status', case
      when a.state = 'reserved' and a.reserved_until <= clock_timestamp() then 'expired'
      when a.state = 'succeeded' and a.report is null then 'result_expired'
      else a.state end,
    'report', a.report, 'http_status', a.http_status, 'error', a.error
  );
end;
$$;

create function public.reserve_audit_attempt(p_key_hash text, p_ip_hash text, p_url_hash text)
returns jsonb language plpgsql security invoker set search_path = '' as $$
declare
  a public.audit_attempts%rowtype;
  t timestamptz;
  day_start timestamptz;
  next_day timestamptz;
  n integer;
begin
  -- One short global transaction lock serializes admission across all instances.
  perform pg_advisory_xact_lock(731204, 1);
  t := clock_timestamp();
  select * into a from public.audit_attempts where key_hash = p_key_hash;
  if found then
    if a.ip_hash <> p_ip_hash or a.url_hash <> p_url_hash then
      return jsonb_build_object('status', 'conflict');
    end if;
    return jsonb_build_object(
      'status', case
        when a.state = 'reserved' and a.reserved_until <= t then 'expired'
        when a.state = 'succeeded' and a.report is null then 'result_expired'
        else a.state end,
      'report', a.report, 'http_status', a.http_status, 'error', a.error,
      'attempt_id', a.attempt_id, 'fresh', false
    );
  end if;

  select count(*) into n from public.audit_attempts
  where ip_hash = p_ip_hash and created_at > t - interval '1 hour'
    and (state <> 'reserved' or reserved_until > t);
  if n >= 5 then return jsonb_build_object('status', 'hourly_limit'); end if;

  day_start := date_trunc('day', t at time zone 'UTC') at time zone 'UTC';
  next_day := day_start + interval '1 day';
  select count(*) into n from public.audit_attempts
  where (dispatched_at >= day_start and dispatched_at < next_day)
     or (state = 'reserved' and created_at >= day_start and created_at < next_day and reserved_until > t);
  if n >= 10 then return jsonb_build_object('status', 'daily_limit'); end if;

  insert into public.audit_attempts (key_hash, ip_hash, url_hash, created_at, reserved_until)
  values (p_key_hash, p_ip_hash, p_url_hash, t, t + interval '45 seconds')
  returning * into a;
  return jsonb_build_object('status', 'reserved', 'fresh', true, 'attempt_id', a.attempt_id);
end;
$$;

create function public.claim_audit_dispatch(p_attempt_id uuid, p_key_hash text)
returns jsonb language plpgsql security invoker set search_path = '' as $$
declare
  a public.audit_attempts%rowtype;
  t timestamptz;
  day_start timestamptz;
  next_day timestamptz;
  n integer;
begin
  perform pg_advisory_xact_lock(731204, 1);
  t := clock_timestamp();
  select * into a from public.audit_attempts
  where attempt_id = p_attempt_id and key_hash = p_key_hash for update;
  if not found then return jsonb_build_object('status', 'expired'); end if;
  if a.state <> 'reserved' then return jsonb_build_object('status', a.state); end if;
  if a.reserved_until <= t then return jsonb_build_object('status', 'expired'); end if;

  day_start := date_trunc('day', t at time zone 'UTC') at time zone 'UTC';
  next_day := day_start + interval '1 day';
  select count(*) into n from public.audit_attempts
  where attempt_id <> p_attempt_id and (
    (dispatched_at >= day_start and dispatched_at < next_day)
    or (state = 'reserved' and created_at >= day_start and created_at < next_day and reserved_until > t)
  );
  if n >= 10 then return jsonb_build_object('status', 'daily_limit'); end if;

  update public.audit_attempts set state = 'dispatched', dispatched_at = t
  where attempt_id = p_attempt_id;
  return jsonb_build_object('status', 'claimed');
end;
$$;

create function public.finish_audit_attempt(
  p_attempt_id uuid, p_key_hash text, p_report jsonb, p_http_status integer, p_error text
)
returns jsonb language plpgsql security invoker set search_path = '' as $$
declare
  a public.audit_attempts%rowtype;
begin
  update public.audit_attempts set
    state = case when p_report is null then 'failed' else 'succeeded' end,
    report = p_report,
    http_status = case when p_report is null then p_http_status else null end,
    error = case when p_report is null then p_error else null end
  where attempt_id = p_attempt_id and key_hash = p_key_hash and state = 'dispatched'
  returning * into a;
  if not found then
    select * into a from public.audit_attempts
    where attempt_id = p_attempt_id and key_hash = p_key_hash;
  end if;
  if not found then return null; end if;
  return jsonb_build_object('status',
                            case when a.state = 'succeeded' and a.report is null then 'result_expired' else a.state end,
                            'report', a.report,
                            'http_status', a.http_status, 'error', a.error);
end;
$$;

revoke all on function public.get_audit_attempt(text, text, text) from public, anon, authenticated;
revoke all on function public.reserve_audit_attempt(text, text, text) from public, anon, authenticated;
revoke all on function public.claim_audit_dispatch(uuid, text) from public, anon, authenticated;
revoke all on function public.finish_audit_attempt(uuid, text, jsonb, integer, text) from public, anon, authenticated;
grant execute on function public.get_audit_attempt(text, text, text) to service_role;
grant execute on function public.reserve_audit_attempt(text, text, text) to service_role;
grant execute on function public.claim_audit_dispatch(uuid, text) to service_role;
grant execute on function public.finish_audit_attempt(uuid, text, jsonb, integer, text) to service_role;

commit;
