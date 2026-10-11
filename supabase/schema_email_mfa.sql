-- ABVSPAIE — second facteur de connexion par code e-mail.
-- Configurez le Custom Access Token Hook décrit dans README.md avant d'activer un compte.

create schema if not exists private;
revoke all on schema private from public, anon, authenticated;
grant usage on schema private to service_role, supabase_auth_admin;

create table if not exists private.email_mfa_settings (
  user_id uuid primary key references auth.users(id) on delete cascade,
  enabled boolean not null default false,
  updated_at timestamptz not null default now()
);

create table if not exists private.email_mfa_challenges (
  session_id uuid primary key,
  user_id uuid not null references auth.users(id) on delete cascade,
  action text not null check (action in ('login', 'enroll', 'disable')),
  code_hash text not null check (code_hash ~ '^[0-9a-f]{64}$'),
  created_at timestamptz not null default now(),
  sent_at timestamptz not null default now(),
  expires_at timestamptz not null,
  attempts integer not null default 0 check (attempts between 0 and 5),
  sends_in_window integer not null default 1 check (sends_in_window between 1 and 5),
  window_started_at timestamptz not null default now()
);

create table if not exists private.email_mfa_verified_sessions (
  session_id uuid primary key,
  user_id uuid not null references auth.users(id) on delete cascade,
  verified_at timestamptz not null default now(),
  expires_at timestamptz not null
);

create table if not exists private.email_mfa_rate_limits (
  user_id uuid primary key references auth.users(id) on delete cascade,
  last_sent_at timestamptz not null,
  window_started_at timestamptz not null,
  sends_in_window integer not null default 0 check (sends_in_window between 0 and 5)
);

create index if not exists email_mfa_challenges_expiry_idx on private.email_mfa_challenges (expires_at);
create index if not exists email_mfa_verified_sessions_expiry_idx on private.email_mfa_verified_sessions (expires_at);

revoke all on all tables in schema private from public, anon, authenticated, supabase_auth_admin;
grant select on private.email_mfa_settings, private.email_mfa_verified_sessions to supabase_auth_admin;

create or replace function public.email_mfa_access_token_hook(event jsonb)
returns jsonb
language plpgsql
stable
security definer
set search_path = ''
as $$
declare
  claims jsonb := event -> 'claims';
  v_user_id uuid := (event -> 'claims' ->> 'sub')::uuid;
  v_session_id uuid := (event -> 'claims' ->> 'session_id')::uuid;
  v_enabled boolean := false;
  v_verified boolean := false;
begin
  if v_user_id is not null then
    select coalesce(s.enabled, false)
      into v_enabled
      from private.email_mfa_settings s
      where s.user_id = v_user_id;
    select exists (
      select 1 from private.email_mfa_verified_sessions s
      where s.user_id = v_user_id
        and s.session_id = v_session_id
        and s.expires_at > now()
    ) into v_verified;
  end if;
  claims := jsonb_set(claims, '{email_mfa_required}', to_jsonb(v_enabled), true);
  claims := jsonb_set(claims, '{email_mfa_verified}', to_jsonb((not v_enabled) or v_verified), true);
  return jsonb_set(event, '{claims}', claims, true);
end;
$$;

revoke all on function public.email_mfa_access_token_hook(jsonb) from public, anon, authenticated;
grant execute on function public.email_mfa_access_token_hook(jsonb) to supabase_auth_admin;

create or replace function public.start_email_mfa_challenge(
  p_user_id uuid,
  p_session_id uuid,
  p_action text,
  p_code_hash text
)
returns void
language plpgsql
security definer
set search_path = ''
as $$
declare
  v_enabled boolean := false;
  v_previous private.email_mfa_challenges%rowtype;
  v_rate_limit private.email_mfa_rate_limits%rowtype;
begin
  if coalesce(auth.jwt() ->> 'role', '') <> 'service_role'
     or p_user_id is null or p_session_id is null
     or p_action not in ('login', 'enroll', 'disable')
     or p_code_hash !~ '^[0-9a-f]{64}$' then
    raise exception 'Requête de code e-mail invalide' using errcode = '42501';
  end if;

  select coalesce(s.enabled, false) into v_enabled
    from private.email_mfa_settings s where s.user_id = p_user_id;

  if (p_action = 'login' and not v_enabled)
     or (p_action = 'enroll' and v_enabled)
     or (p_action = 'disable' and not v_enabled) then
    raise exception 'État de vérification e-mail invalide' using errcode = '42501';
  end if;

  delete from private.email_mfa_challenges where expires_at < now() - interval '1 day';
  delete from private.email_mfa_verified_sessions where expires_at < now() - interval '1 day';
  insert into private.email_mfa_rate_limits (user_id, last_sent_at, window_started_at, sends_in_window)
  values (p_user_id, now() - interval '61 seconds', now(), 0)
  on conflict (user_id) do nothing;
  select * into v_rate_limit
    from private.email_mfa_rate_limits r
    where r.user_id = p_user_id
    for update;
  if v_rate_limit.last_sent_at > now() - interval '60 seconds' then
    raise exception 'Attends une minute avant de demander un nouveau code' using errcode = 'P0001';
  end if;
  if v_rate_limit.window_started_at > now() - interval '1 hour' and v_rate_limit.sends_in_window >= 5 then
    raise exception 'Limite de cinq codes par heure atteinte' using errcode = 'P0001';
  end if;
  update private.email_mfa_rate_limits
    set last_sent_at = now(),
        window_started_at = case when v_rate_limit.window_started_at <= now() - interval '1 hour' then now() else v_rate_limit.window_started_at end,
        sends_in_window = case when v_rate_limit.window_started_at <= now() - interval '1 hour' then 1 else v_rate_limit.sends_in_window + 1 end
    where user_id = p_user_id;

  select * into v_previous from private.email_mfa_challenges c where c.session_id = p_session_id for update;
  insert into private.email_mfa_challenges
    (session_id, user_id, action, code_hash, created_at, sent_at, expires_at, attempts, sends_in_window, window_started_at)
  values
    (p_session_id, p_user_id, p_action, p_code_hash, now(), now(), now() + interval '10 minutes', 0,
      case when found and v_previous.window_started_at > now() - interval '1 hour' then v_previous.sends_in_window + 1 else 1 end,
      case when found and v_previous.window_started_at > now() - interval '1 hour' then v_previous.window_started_at else now() end)
  on conflict (session_id) do update
    set user_id = excluded.user_id,
        action = excluded.action,
        code_hash = excluded.code_hash,
        created_at = excluded.created_at,
        sent_at = excluded.sent_at,
        expires_at = excluded.expires_at,
        attempts = 0,
        sends_in_window = excluded.sends_in_window,
        window_started_at = excluded.window_started_at;
end;
$$;

create or replace function public.verify_email_mfa_challenge(
  p_user_id uuid,
  p_session_id uuid,
  p_action text,
  p_code_hash text
)
returns boolean
language plpgsql
security definer
set search_path = ''
as $$
declare
  v_challenge private.email_mfa_challenges%rowtype;
begin
  if coalesce(auth.jwt() ->> 'role', '') <> 'service_role' then
    raise exception 'Opération serveur uniquement' using errcode = '42501';
  end if;

  select * into v_challenge
    from private.email_mfa_challenges c
    where c.session_id = p_session_id
      and c.user_id = p_user_id
      and c.action = p_action
    for update;
  if not found or v_challenge.expires_at <= now() or v_challenge.attempts >= 5 then
    delete from private.email_mfa_challenges c where c.session_id = p_session_id;
    return false;
  end if;
  if v_challenge.code_hash <> p_code_hash then
    update private.email_mfa_challenges c set attempts = c.attempts + 1 where c.session_id = p_session_id;
    return false;
  end if;

  delete from private.email_mfa_challenges c where c.session_id = p_session_id;
  if p_action = 'enroll' then
    insert into private.email_mfa_settings (user_id, enabled, updated_at)
    values (p_user_id, true, now())
    on conflict (user_id) do update set enabled = true, updated_at = now();
  elsif p_action = 'disable' then
    update private.email_mfa_settings set enabled = false, updated_at = now() where user_id = p_user_id;
  end if;

  insert into private.email_mfa_verified_sessions (session_id, user_id, expires_at)
  values (p_session_id, p_user_id, now() + interval '12 hours')
  on conflict (session_id) do update set user_id = excluded.user_id, verified_at = now(), expires_at = excluded.expires_at;
  return true;
end;
$$;

revoke all on function public.start_email_mfa_challenge(uuid, uuid, text, text) from public, anon, authenticated;
revoke all on function public.verify_email_mfa_challenge(uuid, uuid, text, text) from public, anon, authenticated;
grant execute on function public.start_email_mfa_challenge(uuid, uuid, text, text) to service_role;
grant execute on function public.verify_email_mfa_challenge(uuid, uuid, text, text) to service_role;

-- Enrolled email-MFA sessions cannot use authenticated RLS-protected tables before the code is verified.
do $$
declare
  r record;
begin
  for r in
    select n.nspname, c.relname
    from pg_class c
    join pg_namespace n on n.oid = c.relnamespace
    where n.nspname = 'public'
      and c.relkind in ('r', 'p')
      and c.relrowsecurity
  loop
    execute format('drop policy if exists email_mfa_access_gate on %I.%I', r.nspname, r.relname);
    execute format(
      'create policy email_mfa_access_gate on %I.%I as restrictive for all to authenticated using (coalesce(auth.jwt() ->> ''email_mfa_verified'', ''false'') = ''true'') with check (coalesce(auth.jwt() ->> ''email_mfa_verified'', ''false'') = ''true'')',
      r.nspname, r.relname
    );
  end loop;
end
$$;

drop policy if exists email_mfa_storage_access_gate on storage.objects;
create policy email_mfa_storage_access_gate on storage.objects
  as restrictive for all to authenticated
  using (coalesce(auth.jwt() ->> 'email_mfa_verified', 'false') = 'true')
  with check (coalesce(auth.jwt() ->> 'email_mfa_verified', 'false') = 'true');

notify pgrst, 'reload schema';
