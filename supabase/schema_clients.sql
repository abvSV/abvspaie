-- ABVSPAIE — fiches clients et rattachement aux transactions.
-- À exécuter après schema_paiements.sql et schema.sql.

create table if not exists public.clients (
  id           uuid primary key default gen_random_uuid(),
  merchant_id  uuid not null default auth.uid() references public.merchants(id) on delete cascade,
  identity_key text not null,
  name         text not null check (char_length(name) between 1 and 120),
  email        text,
  phone        text,
  created_at   timestamptz not null default now(),
  constraint clients_identity_key_check check (
    (phone is not null and identity_key = 'phone:' || phone)
    or (phone is null and email is not null and identity_key = 'email:' || email)
  ),
  constraint clients_email_normalized_check check (
    email is null or (
      email = lower(trim(email))
      and char_length(email) <= 254
      and email ~ '^[A-Za-z0-9.!#$%&''*+/=?^_`{|}~-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$'
    )
  ),
  constraint clients_phone_normalized_check check (
    phone is null or phone ~ '^[0-9]{8,20}$'
  )
);

create unique index if not exists clients_merchant_identity_uidx
  on public.clients (merchant_id, identity_key);
create unique index if not exists clients_merchant_phone_uidx
  on public.clients (merchant_id, phone) where phone is not null;
create unique index if not exists clients_merchant_email_uidx
  on public.clients (merchant_id, email) where email is not null;
create index if not exists clients_merchant_created_idx
  on public.clients (merchant_id, created_at desc);

alter table public.transactions
  add column if not exists client_id uuid references public.clients(id) on delete set null;
create index if not exists transactions_client_created_idx
  on public.transactions (client_id, created_at desc)
  where client_id is not null;

alter table public.clients enable row level security;
drop policy if exists clients_select_own on public.clients;
create policy clients_select_own on public.clients
  for select to authenticated using (merchant_id = (select auth.uid()));
drop policy if exists clients_insert_own on public.clients;
create policy clients_insert_own on public.clients
  for insert to authenticated with check (merchant_id = (select auth.uid()));

revoke all on public.clients from anon, authenticated;
grant select on public.clients to authenticated;
grant insert (identity_key, name, email, phone) on public.clients to authenticated;

drop function if exists public.create_payment(text, text, text, text);
drop function if exists public.create_payment(text, text, text, text, text, text);

create function public.create_payment(
  p_slug text,
  p_method text,
  p_phone text default null,
  p_idempotency_key text default null,
  p_customer_name text default null,
  p_customer_email text default null
)
returns jsonb language plpgsql security definer set search_path = '' as $$
declare
  l record; v_test boolean; v_payer text; v_ref text; v_status text; v_mode text;
  v_existing record; v_phone text; v_email text; v_name text; v_identity_key text;
  v_client_id uuid;
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

  v_phone := nullif(regexp_replace(coalesce(p_phone, ''), '\D', '', 'g'), '');
  v_email := nullif(lower(trim(coalesce(p_customer_email, ''))), '');
  v_name := coalesce(nullif(trim(coalesce(p_customer_name, '')), ''), 'Client');

  if char_length(v_name) > 120 then raise exception 'Nom client invalide'; end if;
  if v_email is not null and (
    char_length(v_email) > 254
    or v_email !~ '^[A-Za-z0-9.!#$%&''*+/=?^_`{|}~-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$'
  ) then
    raise exception 'Adresse e-mail invalide';
  end if;
  if p_phone is not null and (
    length(trim(p_phone)) > 20
    or p_phone !~ '^[0-9+() -]{8,20}$'
    or v_phone is null
    or char_length(v_phone) not between 8 and 20
  ) then
    raise exception 'Numéro invalide';
  end if;
  if v_phone is null and v_email is null then
    raise exception 'Un numéro de téléphone ou une adresse e-mail est requis';
  end if;

  if p_method = 'Carte' then
    if l.mode = 'live' then raise exception 'Paiement par carte indisponible'; end if;
    v_payer := 'Carte';
  else
    if p_phone is null or length(trim(p_phone)) > 20 or p_phone !~ '^[0-9+() -]{8,20}$' then
      raise exception 'Numéro invalide';
    end if;
    v_payer := '••••' || right(v_phone, 3);
  end if;

  v_identity_key := case
    when v_phone is not null then 'phone:' || v_phone
    else 'email:' || v_email
  end;

  select c.id into v_client_id
    from public.clients c
    where c.merchant_id = l.merchant_id
      and ((v_phone is not null and c.phone = v_phone)
        or (v_email is not null and c.email = v_email))
    order by case when v_phone is not null and c.phone = v_phone then 0 else 1 end
    limit 1
    for update;

  if found then
    update public.clients
      set identity_key = case
            when coalesce(v_phone, phone) is not null then 'phone:' || coalesce(v_phone, phone)
            else 'email:' || coalesce(v_email, email)
          end,
          name = case when v_name = 'Client' then name else v_name end,
          email = coalesce(v_email, email),
          phone = coalesce(v_phone, phone)
      where id = v_client_id;
  else
    insert into public.clients (merchant_id, identity_key, name, email, phone)
    values (l.merchant_id, v_identity_key, v_name, v_email, v_phone)
    on conflict (merchant_id, identity_key) do update
      set name = case when excluded.name = 'Client' then clients.name else excluded.name end,
          email = coalesce(excluded.email, clients.email),
          phone = coalesce(excluded.phone, clients.phone)
    returning id into v_client_id;
  end if;

  insert into public.transactions
    (merchant_id, link_id, client_id, amount, currency, mode, method, payer, status, idempotency_key)
  values
    (l.merchant_id, l.id, v_client_id, l.amount, l.currency, l.mode, p_method, v_payer,
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

revoke execute on function public.create_payment(text, text, text, text, text, text) from public;
grant execute on function public.create_payment(text, text, text, text, text, text) to anon, authenticated;

notify pgrst, 'reload schema';
