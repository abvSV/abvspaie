-- Create KYC merchant profiles missing for existing Supabase Auth users.
-- Safe to run more than once; existing profiles are left unchanged.
insert into public.merchant_profiles (user_id)
select u.id
from auth.users u
where not exists (
  select 1
  from public.merchant_profiles p
  where p.user_id = u.id
)
on conflict (user_id) do nothing;

select
  count(*) as auth_accounts,
  count(p.user_id) as merchant_profiles,
  count(*) filter (where p.user_id is null) as missing_profiles
from auth.users u
left join public.merchant_profiles p on p.user_id = u.id;
