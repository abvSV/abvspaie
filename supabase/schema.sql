-- ABVSPAIE — schéma initial (à exécuter dans Supabase > SQL Editor)

create table public.merchants (
  id          uuid primary key references auth.users(id) on delete cascade,
  name        text not null check (char_length(name) between 2 and 120),
  email       text not null,
  country     char(2) not null check (country in ('CI','SN','BF','ML','BJ','TG','NE','GW')),
  kyc_status  text not null default 'pending' check (kyc_status in ('pending','submitted','verified','rejected')),
  created_at  timestamptz not null default now()
);

alter table public.merchants enable row level security;

-- Un marchand ne voit et ne modifie que sa propre ligne.
create policy merchants_select_own on public.merchants
  for select to authenticated using (id = (select auth.uid()));
create policy merchants_update_own on public.merchants
  for update to authenticated using (id = (select auth.uid())) with check (id = (select auth.uid()));

-- Aucun INSERT/DELETE côté client ; seul "name" est modifiable (kyc_status, email, country : serveur uniquement).
revoke insert, delete, update on public.merchants from anon, authenticated;
grant update (name) on public.merchants to authenticated;

-- Création automatique du marchand à l'inscription (métadonnées envoyées par signUp).
create or replace function public.handle_new_user()
returns trigger language plpgsql security definer set search_path = '' as $$
begin
  insert into public.merchants (id, name, email, country)
  values (
    new.id,
    left(coalesce(nullif(trim(new.raw_user_meta_data->>'company'), ''), 'Sans nom'), 120),
    new.email,
    coalesce(nullif(new.raw_user_meta_data->>'country', ''), 'CI')
  );
  return new;
end $$;

revoke execute on function public.handle_new_user() from public, anon, authenticated;

create trigger on_auth_user_created
  after insert on auth.users
  for each row execute function public.handle_new_user();
