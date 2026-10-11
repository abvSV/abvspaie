-- Retire the optional email-MFA integration and restore the prior RLS behavior.
-- Disable the Customize Access Token hook in Supabase Auth before running this script.

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
  end loop;
end
$$;

drop policy if exists email_mfa_storage_access_gate on storage.objects;

drop function if exists public.email_mfa_access_token_hook(jsonb);
drop function if exists public.start_email_mfa_challenge(uuid, uuid, text, text);
drop function if exists public.verify_email_mfa_challenge(uuid, uuid, text, text);

drop table if exists private.email_mfa_verified_sessions;
drop table if exists private.email_mfa_challenges;
drop table if exists private.email_mfa_rate_limits;
drop table if exists private.email_mfa_settings;

notify pgrst, 'reload schema';
