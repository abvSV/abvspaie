-- ABVSPAIE — audit des changements de rôles et de comptes de la console super-admin.
-- À exécuter après schema_kyc.sql.

create table if not exists public.platform_admin_audit_logs (
  id          uuid primary key default gen_random_uuid(),
  actor_id    uuid not null,
  target_id   uuid not null,
  action      text not null check (action in (
    'role_change_requested',
    'role_change_succeeded',
    'role_change_failed',
    'account_change_requested',
    'account_change_succeeded',
    'account_change_failed'
  )),
  details     jsonb not null default '{}'::jsonb check (jsonb_typeof(details) = 'object'),
  created_at  timestamptz not null default now()
);

alter table public.platform_admin_audit_logs
  drop constraint if exists platform_admin_audit_logs_action_check;
alter table public.platform_admin_audit_logs
  add constraint platform_admin_audit_logs_action_check
  check (action in (
    'role_change_requested',
    'role_change_succeeded',
    'role_change_failed',
    'account_change_requested',
    'account_change_succeeded',
    'account_change_failed'
  ));

create index if not exists platform_admin_audit_logs_created_idx
  on public.platform_admin_audit_logs (created_at desc);
create index if not exists platform_admin_audit_logs_target_created_idx
  on public.platform_admin_audit_logs (target_id, created_at desc);

alter table public.platform_admin_audit_logs enable row level security;
revoke all on public.platform_admin_audit_logs from public, anon, authenticated;
grant select, insert, update on public.platform_admin_audit_logs to service_role;
