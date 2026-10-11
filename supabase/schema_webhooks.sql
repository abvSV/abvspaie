-- ABVSPAIE — endpoints de réception webhook et événements reçus.
-- À exécuter dans Supabase > SQL Editor après schema_paiements.sql.

create table if not exists public.webhook_endpoints (
  id          uuid primary key default gen_random_uuid(),
  merchant_id uuid not null references auth.users(id) on delete cascade,
  name        text not null check (char_length(name) between 2 and 80),
  endpoint_url text not null,
  is_active   boolean not null default true,
  created_at  timestamptz not null default now()
);

create table if not exists public.webhook_endpoint_secrets (
  endpoint_id       uuid primary key references public.webhook_endpoints(id) on delete cascade,
  secret_ciphertext text not null,
  secret_iv         text not null,
  secret_tag        text not null,
  created_at        timestamptz not null default now()
);

create table if not exists public.webhook_events (
  id          uuid primary key default gen_random_uuid(),
  endpoint_id uuid not null references public.webhook_endpoints(id) on delete cascade,
  merchant_id uuid not null references auth.users(id) on delete cascade,
  delivery_id text not null check (char_length(delivery_id) between 1 and 120),
  event_type  text check (event_type is null or char_length(event_type) <= 120),
  payload     jsonb not null check (jsonb_typeof(payload) = 'object'),
  received_at timestamptz not null default now(),
  unique (endpoint_id, delivery_id)
);

-- CREATE TABLE IF NOT EXISTS ne modifie pas une table créée auparavant :
-- cet index apporte aussi la contrainte d'idempotence sur les installations existantes.
create unique index if not exists webhook_events_endpoint_delivery_uidx
  on public.webhook_events (endpoint_id, delivery_id);

create index if not exists webhook_events_merchant_received_idx
  on public.webhook_events (merchant_id, received_at desc);

alter table public.webhook_endpoints enable row level security;
alter table public.webhook_endpoint_secrets enable row level security;
alter table public.webhook_events enable row level security;

drop policy if exists webhook_endpoints_select_own on public.webhook_endpoints;
create policy webhook_endpoints_select_own on public.webhook_endpoints
  for select to authenticated using (merchant_id = (select auth.uid()));

drop policy if exists webhook_events_select_own on public.webhook_events;
create policy webhook_events_select_own on public.webhook_events
  for select to authenticated using (merchant_id = (select auth.uid()));

revoke all on public.webhook_endpoints from anon, authenticated;
revoke all on public.webhook_endpoint_secrets from anon, authenticated;
revoke all on public.webhook_events from anon, authenticated;
grant select on public.webhook_endpoints to authenticated;
grant select on public.webhook_events to authenticated;
