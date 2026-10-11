-- ABVSPAIE — liens de paiement et transactions.
-- À exécuter APRÈS schema.sql (Supabase > SQL Editor > Run).

-- Mode test : tant qu'il est à true, les paiements sont validés automatiquement (aucun argent réel).
alter table public.merchants add column if not exists test_mode boolean not null default true;

-- ───────── Liens de paiement ─────────
create table if not exists public.payment_links (
  id          uuid primary key default gen_random_uuid(),
  merchant_id uuid not null default auth.uid() references public.merchants(id) on delete cascade,
  slug        text not null unique default substr(replace(gen_random_uuid()::text, '-', ''), 1, 8),
  title       text not null check (char_length(title) between 2 and 120),
  amount      integer not null check (amount between 100 and 100000000),
  currency    text not null default 'XOF',
  active      boolean not null default true,
  created_at  timestamptz not null default now()
);
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
  method      text not null check (method in ('Orange Money','MTN MoMo','Moov','Wave','Carte')),
  payer       text,
  status      text not null default 'pending' check (status in ('pending','succeeded','failed')),
  idempotency_key text,
  created_at  timestamptz not null default now()
);
create index if not exists transactions_merchant_idx on public.transactions (merchant_id, created_at desc);
create index if not exists tx_idempotency_idx on public.transactions (idempotency_key);
alter table public.transactions enable row level security;

drop policy if exists tx_select_own on public.transactions;
create policy tx_select_own on public.transactions for select to authenticated using (merchant_id = (select auth.uid()));

-- Lecture seule pour le marchand ; les écritures passent uniquement par create_payment() ou le serveur.
revoke all on public.transactions from anon, authenticated;
grant select on public.transactions to authenticated;

-- ───────── Fonctions appelées par la page de paiement (visiteur non connecté) ─────────
create or replace function public.get_payment_link(p_slug text)
returns jsonb language sql security definer stable set search_path = '' as $$
  select jsonb_build_object('title', pl.title, 'amount', pl.amount, 'currency', pl.currency, 'merchant_name', m.name)
  from public.payment_links pl join public.merchants m on m.id = pl.merchant_id
  where pl.slug = p_slug and pl.active
$$;

create or replace function public.create_payment(p_slug text, p_method text, p_phone text default null, p_idempotency_key text default null)
returns jsonb language plpgsql security definer set search_path = '' as $$
declare
  l record; v_test boolean; v_payer text; v_ref text; v_status text;
begin
  if p_slug is null or length(trim(p_slug)) = 0 then
    raise exception 'slug invalide';
  end if;

  if p_method not in ('Orange Money','MTN MoMo','Moov','Wave','Carte') then
    raise exception 'Moyen de paiement invalide';
  end if;

  if p_idempotency_key is not null and exists (
    select 1 from public.transactions where idempotency_key = p_idempotency_key
  ) then
    raise exception 'Demande déjà traitée';
  end if;

  select pl.id, pl.merchant_id, pl.amount, pl.currency into l
    from public.payment_links pl
    where pl.slug = p_slug and pl.active
    for update;

  if not found then raise exception 'Lien introuvable'; end if;
  select mm.test_mode into v_test from public.merchants mm where mm.id = l.merchant_id;

  if p_method = 'Carte' then
    if not v_test then raise exception 'Paiement par carte indisponible'; end if;
    v_payer := 'Carte';
  else
    if p_phone is null or p_phone !~ '^[0-9+() -]{8,20}$' then raise exception 'Numéro invalide'; end if;
    v_payer := '••••' || right(regexp_replace(p_phone, '\D', '', 'g'), 3);
  end if;

  -- Mode test : réussi tout de suite. Mode réel : "pending" jusqu'à confirmation de l'opérateur (webhook).
  insert into public.transactions (merchant_id, link_id, amount, currency, method, payer, status, idempotency_key)
  values (l.merchant_id, l.id, l.amount, l.currency, p_method, v_payer,
          case when v_test then 'succeeded' else 'pending' end,
          p_idempotency_key)
  returning reference, status into v_ref, v_status;

  return jsonb_build_object('reference', v_ref, 'status', v_status);
end $$;

revoke execute on function public.get_payment_link(text), public.create_payment(text, text, text, text) from public;
grant execute on function public.get_payment_link(text), public.create_payment(text, text, text, text) to anon, authenticated;
