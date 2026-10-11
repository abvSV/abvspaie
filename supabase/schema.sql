-- ABVSPAIE — Migration « mode Live » (étape 1)
-- À exécuter dans Supabase > SQL Editor. Additive : ne supprime ni ne modifie vos données existantes.
-- Recommandé : essayez d'abord sur une copie / un projet de test.

-- 1) Profil marchand : c'est ICI que le serveur décide si Live est autorisé.
create table if not exists public.merchant_profiles (
  user_id      uuid primary key references auth.users(id) on delete cascade,
  kyc_status   text not null default 'none' check (kyc_status in ('none','pending','verified','rejected')),
  live_enabled boolean not null default false,
  verified_at  timestamptz,
  created_at   timestamptz not null default now()
);

alter table public.merchant_profiles enable row level security;

-- L'utilisateur peut LIRE son profil, jamais l'écrire (sinon il s'activerait Live lui-même).
drop policy if exists "merchant_profiles_select_own" on public.merchant_profiles;
create policy "merchant_profiles_select_own" on public.merchant_profiles
  for select to authenticated using (user_id = auth.uid());

revoke insert, update, delete on public.merchant_profiles from anon, authenticated;

-- 2) Un profil est créé automatiquement à chaque inscription.
create or replace function public.handle_new_merchant()
returns trigger language plpgsql security definer set search_path = public as $$
begin
  insert into public.merchant_profiles (user_id) values (new.id) on conflict do nothing;
  return new;
end $$;

drop trigger if exists on_auth_user_created_merchant on auth.users;
create trigger on_auth_user_created_merchant
  after insert on auth.users
  for each row execute function public.handle_new_merchant();

-- Profils pour les comptes déjà existants.
insert into public.merchant_profiles (user_id)
select id from auth.users on conflict do nothing;

-- 3) Colonne « mode » : toutes les lignes existantes deviennent « test ».
alter table public.payment_links add column if not exists mode text not null default 'test' check (mode in ('test','live'));
alter table public.transactions  add column if not exists mode text not null default 'test' check (mode in ('test','live'));

-- 4) Garde-fou : impossible de créer un lien Live sans autorisation serveur.
create or replace function public.enforce_live_mode()
returns trigger language plpgsql security definer set search_path = public as $$
begin
  if new.mode = 'live'
     and coalesce(auth.jwt() ->> 'role', '') <> 'service_role'
     and not exists (select 1 from public.merchant_profiles p where p.user_id = auth.uid() and p.live_enabled) then
    raise exception 'live_not_enabled' using errcode = '42501';
  end if;
  return new;
end $$;

drop trigger if exists payment_links_live_guard on public.payment_links;
create trigger payment_links_live_guard
  before insert or update of mode on public.payment_links
  for each row execute function public.enforce_live_mode();

-- ───────────────────────────────────────────────────────────────
-- Pour valider une entreprise APRÈS vérification manuelle de ses documents
-- (ne l'activez qu'une fois le prestataire de paiement réellement branché) :
--
--   update public.merchant_profiles
--      set kyc_status = 'verified', live_enabled = true, verified_at = now()
--    where user_id = '<UUID de l''utilisateur>';
--
-- Pour retrouver l'UUID : Authentication > Users dans Supabase.
-- ───────────────────────────────────────────────────────────────
