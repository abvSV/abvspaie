-- ABVSPAIE — liens de paiement et transactions.
-- À exécuter AVANT schema.sql (qui ajoute les protections KYC / mode Live).

-- Base marchand. Le mode test est activé par défaut ; le mode Live ne doit être
-- activé qu'après intégration réelle d'un prestataire de paiement.
create table if not exists public.merchants (
  id uuid primary key references auth.users(id) on delete cascade,
  name text not null default 'Marchand',
  test_mode boolean not null default true,
  kyc_status text not null default 'none' check (kyc_status in ('none','pending','verified','rejected'))
);

alter table public.merchants add column if not exists name text not null default 'Marchand';
alter table public.merchants add column if not exists test_mode boolean not null default true;
alter table public.merchants add column if not exists kyc_status text not null default 'none'
  check (kyc_status in ('none','pending','verified','rejected'));
alter table public.merchants enable row level security;
revoke all on public.merchants from anon, authenticated;

create or replace function public.handle_new_merchant_record()
returns trigger language plpgsql security definer set search_path = '' as $$
begin
  insert into public.merchants (id, name)
  values (new.id, coalesce(nullif(trim(new.raw_user_meta_data ->> 'company'), ''), 'Marchand'))
  on conflict (id) do nothing;
  return new;
end $$;

drop trigger if exists on_auth_user_created_merchant_record on auth.users;
create trigger on_auth_user_created_merchant_record
  after insert on auth.users
  for each row execute function public.handle_new_merchant_record();

insert into public.merchants (id, name)
select id, coalesce(nullif(trim(raw_user_meta_data ->> 'company'), ''), 'Marchand')
from auth.users
on conflict (id) do nothing;

-- ───────── Liens de paiement ─────────
create table if not exists public.payment_links (
  id          uuid primary key default gen_random_uuid(),
  merchant_id uuid not null default auth.uid() references public.merchants(id) on delete cascade,
  slug        text not null unique default substr(replace(gen_random_uuid()::text, '-', ''), 1, 8),
  title       text not null check (char_length(title) between 2 and 120),
  amount      integer not null check (amount between 100 and 100000000),
  currency    text not null default 'XOF',
  mode        text not null default 'test' check (mode in ('test','live')),
  active      boolean not null default true,
  created_at  timestamptz not null default now()
);
alter table public.payment_links add column if not exists mode text not null default 'test'
  check (mode in ('test','live'));
create index if not exists payment_links_merchant_idx on public.payment_links (merchant_id, created_at desc);
alter table public.payment_links enable row level security;

drop policy if exists links_select_own on public.payment_links;
create policy links_select_own on public.payment_links for select to authenticated using (merchant_id = (select auth.uid()));
drop policy if exists links_insert_own on public.payment_links;
create policy links_insert_own on public.payment_links for insert to authenticated with check (merchant_id = (select auth.uid()));
drop policy if exists links_update_own on public.payment_links;
create policy links_update_own on public.payment_links for update to authenticated
  using (merchant_id = (select auth.uid())) with check (merchant_id = (select auth.uid()));

revoke all on public.payment_links from anon, authenticated;
grant select on public.payment_links to authenticated;
grant insert (title, amount) on public.payment_links to authenticated;
grant update (active) on public.payment_links to authenticated;

-- ───────── Transactions ─────────
create table if not exists public.transactions (
  id          uuid primary key default gen_random_uuid(),
  reference   text not null unique default 'TX-' || upper(substr(replace(gen_random_uuid()::text, '-', ''), 1, 8)),
  merchant_id uuid not null references public.merchants(id) on delete cascade,
  link_id     uuid references public.payment_links(id) on delete set null,
  amount      integer not null check (amount > 0),
  currency    text not null default 'XOF',
  mode        text not null default 'test' check (mode in ('test','live')),
  method      text not null check (method in ('Orange Money','MTN MoMo','Moov','Wave','Carte')),
  payer       text,
  status      text not null default 'pending' check (status in ('pending','succeeded','failed')),
  idempotency_key text,
  created_at  timestamptz not null default now()
);
alter table public.transactions add column if not exists mode text not null default 'test'
  check (mode in ('test','live'));
alter table public.transactions add column if not exists idempotency_key text;
create index if not exists transactions_merchant_idx on public.transactions (merchant_id, created_at desc);
create unique index if not exists tx_idempotency_key_unique
  on public.transactions (idempotency_key) where idempotency_key is not null;
alter table public.transactions enable row level security;

drop policy if exists tx_select_own on public.transactions;
create policy tx_select_own on public.transactions for select to authenticated using (merchant_id = (select auth.uid()));

-- Lecture seule pour le marchand ; les écritures passent uniquement par create_payment() ou le serveur.
revoke all on public.transactions from anon, authenticated;
grant select on public.transactions to authenticated;

-- ───────── Fonctions appelées par la page de paiement (visiteur non connecté) ─────────
create or replace function public.get_payment_link(p_slug text)
returns jsonb language sql security definer stable set search_path = '' as $$
  select jsonb_build_object('title', pl.title, 'amount', pl.amount, 'currency', pl.currency, 'mode', pl.mode, 'merchant_name', m.name)
  from public.payment_links pl join public.merchants m on m.id = pl.merchant_id
  where pl.slug = p_slug and pl.active
$$;

create or replace function public.create_payment(p_slug text, p_method text, p_phone text default null, p_idempotency_key text default null)
returns jsonb language plpgsql security definer set search_path = '' as $$
declare
  l record; v_test boolean; v_payer text; v_ref text; v_status text; v_mode text;
  v_existing record;
begin
  if p_slug is null or length(trim(p_slug)) = 0 or length(p_slug) > 128 then
    raise exception 'slug invalide';
  end if;

  if p_method is null or p_method not in ('Orange Money','MTN MoMo','Moov','Wave','Carte') then
    raise exception 'Moyen de paiement invalide';
  end if;

  if p_idempotency_key is not null
     and (length(trim(p_idempotency_key)) = 0 or length(p_idempotency_key) > 128) then
    raise exception 'Clé de requête invalide';
  end if;

  select pl.id, pl.merchant_id, pl.amount, pl.currency, pl.mode into l
    from public.payment_links pl
    where pl.slug = p_slug and pl.active
    for update;

  if not found then raise exception 'Lien introuvable'; end if;
  select mm.test_mode into v_test from public.merchants mm where mm.id = l.merchant_id;
  if not found then raise exception 'Marchand introuvable'; end if;
  v_mode := l.mode;

  if p_idempotency_key is not null then
    select tx.link_id, tx.method, tx.reference, tx.status, tx.mode
      into v_existing
      from public.transactions tx
      where tx.idempotency_key = p_idempotency_key;
    if found then
      if v_existing.link_id is distinct from l.id or v_existing.method is distinct from p_method then
        raise exception 'Clé de requête déjà utilisée';
      end if;
      return jsonb_build_object('reference', v_existing.reference, 'status', v_existing.status, 'mode', v_existing.mode);
    end if;
  end if;

  if l.mode = 'live' then
    if v_test then raise exception 'Mode Live indisponible'; end if;
    if not exists (
      select 1 from public.merchant_profiles p
      where p.user_id = l.merchant_id
        and p.live_enabled = true
        and p.kyc_status = 'verified'
    ) then
      raise exception 'live_not_enabled' using errcode = '42501';
    end if;
  end if;

  if p_method = 'Carte' then
    if l.mode = 'live' then raise exception 'Paiement par carte indisponible'; end if;
    v_payer := 'Carte';
  else
    if p_phone is null or length(trim(p_phone)) > 20 or p_phone !~ '^[0-9+() -]{8,20}$' then
      raise exception 'Numéro invalide';
    end if;
    v_payer := '••••' || right(regexp_replace(p_phone, '\D', '', 'g'), 3);
  end if;

  -- Un paiement Live reste en attente : il ne devient réussi qu'après confirmation du prestataire.
  insert into public.transactions
    (merchant_id, link_id, amount, currency, mode, method, payer, status, idempotency_key)
  values
    (l.merchant_id, l.id, l.amount, l.currency, l.mode, p_method, v_payer,
     case when l.mode = 'test' then 'succeeded' else 'pending' end,
     p_idempotency_key)
  on conflict (idempotency_key) where idempotency_key is not null do nothing
  returning reference, status into v_ref, v_status;

  if not found and p_idempotency_key is not null then
    select tx.link_id, tx.method, tx.reference, tx.status, tx.mode
      into v_existing
      from public.transactions tx
      where tx.idempotency_key = p_idempotency_key;
    if not found then
      raise exception 'Clé de requête introuvable';
    end if;
    if v_existing.link_id is distinct from l.id
       or v_existing.method is distinct from p_method
       or v_existing.mode is distinct from l.mode then
      raise exception 'Clé de requête déjà utilisée';
    end if;
    v_ref := v_existing.reference;
    v_status := v_existing.status;
    v_mode := v_existing.mode;
  end if;

  return jsonb_build_object('reference', v_ref, 'status', v_status, 'mode', v_mode);
end $$;

revoke execute on function public.get_payment_link(text), public.create_payment(text, text, text, text) from public;
grant execute on function public.get_payment_link(text), public.create_payment(text, text, text, text) to anon, authenticated;
