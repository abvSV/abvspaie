-- ABVSPAIE — dépôt privé des justificatifs KYC.
-- À exécuter après schema.sql. Les documents exigent une session MFA de niveau AAL2.

create table if not exists public.merchant_kyc_documents (
  id            uuid primary key default gen_random_uuid(),
  merchant_id   uuid not null references auth.users(id) on delete cascade,
  document_type text not null check (document_type in ('identity', 'business', 'address', 'other')),
  storage_path  text not null unique,
  created_at    timestamptz not null default now(),
  constraint merchant_kyc_document_path_check check (
    storage_path ~ ('^' || merchant_id::text || '/[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\.(pdf|jpg|png)$')
  )
);

create index if not exists merchant_kyc_documents_owner_created_idx
  on public.merchant_kyc_documents (merchant_id, created_at desc);
alter table public.merchant_kyc_documents
  add column if not exists document_side text not null default 'front'
  check (document_side in ('front', 'back', 'supporting'));

alter table public.merchant_profiles
  add column if not exists kyc_rejection_reason text,
  add column if not exists kyc_submitted_at timestamptz,
  add column if not exists kyc_decided_at timestamptz,
  add column if not exists kyc_decided_by uuid references auth.users(id) on delete set null,
  add column if not exists kyc_full_name text,
  add column if not exists kyc_country text check (kyc_country in ('CI', 'SN', 'BF', 'ML', 'BJ', 'TG', 'NE', 'GW')),
  add column if not exists kyc_document_type text check (kyc_document_type in ('national_id', 'passport', 'driving_license'));

create table if not exists public.kyc_audit_logs (
  id          uuid primary key default gen_random_uuid(),
  merchant_id uuid not null references auth.users(id) on delete cascade,
  actor_id    uuid references auth.users(id) on delete set null,
  event_type  text not null check (event_type in ('document_uploaded', 'submitted', 'approved', 'rejected')),
  details     jsonb not null default '{}'::jsonb check (jsonb_typeof(details) = 'object'),
  created_at  timestamptz not null default now()
);

alter table public.kyc_audit_logs
  drop constraint if exists kyc_audit_logs_event_type_check;
alter table public.kyc_audit_logs
  add constraint kyc_audit_logs_event_type_check
  check (event_type in ('document_uploaded', 'submitted', 'approved', 'rejected'));

create index if not exists kyc_audit_logs_merchant_created_idx
  on public.kyc_audit_logs (merchant_id, created_at desc);
alter table public.kyc_audit_logs enable row level security;
revoke all on public.kyc_audit_logs from public, anon, authenticated;

-- Fail closed on legacy or inconsistent approvals without a complete manual-review record.
update public.merchant_profiles p
set kyc_status = 'none',
    live_enabled = false,
    verified_at = null,
    kyc_decided_at = null,
    kyc_decided_by = null,
    kyc_rejection_reason = null
where p.kyc_status = 'verified'
  and not (
    p.kyc_submitted_at is not null
    and p.kyc_decided_at is not null
    and p.kyc_decided_by is not null
    and p.verified_at is not null
    and exists (
      select 1
      from public.merchant_kyc_documents d
      where d.merchant_id = p.user_id
        and d.document_type = 'identity'
        and d.document_side = 'front'
    )
    and exists (
      select 1
      from public.kyc_audit_logs submitted
      where submitted.merchant_id = p.user_id
        and submitted.actor_id = p.user_id
        and submitted.event_type = 'submitted'
        and submitted.created_at <= p.kyc_decided_at
    )
    and exists (
      select 1
      from public.kyc_audit_logs approved
      where approved.merchant_id = p.user_id
        and approved.actor_id = p.kyc_decided_by
        and approved.event_type = 'approved'
        and approved.created_at >= p.kyc_submitted_at
        and approved.created_at <= p.kyc_decided_at
    )
  );

alter table public.merchant_kyc_documents enable row level security;
revoke all on public.merchant_kyc_documents from public, anon, authenticated;
grant select on public.merchant_kyc_documents to authenticated;
grant insert (merchant_id, document_type, document_side, storage_path) on public.merchant_kyc_documents to service_role;

drop policy if exists merchant_kyc_documents_select_guard on public.merchant_kyc_documents;
create policy merchant_kyc_documents_select_guard on public.merchant_kyc_documents
  as restrictive for select to authenticated
  using (merchant_id = (select auth.uid()) and (select auth.jwt() ->> 'aal') = 'aal2');

drop policy if exists merchant_kyc_documents_select_own on public.merchant_kyc_documents;
create policy merchant_kyc_documents_select_own on public.merchant_kyc_documents
  for select to authenticated
  using (merchant_id = (select auth.uid()) and (select auth.jwt() ->> 'aal') = 'aal2');

drop policy if exists merchant_kyc_documents_insert_guard on public.merchant_kyc_documents;
create policy merchant_kyc_documents_insert_guard on public.merchant_kyc_documents
  as restrictive for insert to authenticated
  with check (false);

drop policy if exists merchant_kyc_documents_update_guard on public.merchant_kyc_documents;
create policy merchant_kyc_documents_update_guard on public.merchant_kyc_documents
  as restrictive for update to authenticated
  using (false)
  with check (false);

drop policy if exists merchant_kyc_documents_delete_guard on public.merchant_kyc_documents;
create policy merchant_kyc_documents_delete_guard on public.merchant_kyc_documents
  as restrictive for delete to authenticated
  using (false);

create or replace function public.mark_kyc_submission_pending()
returns trigger
language plpgsql
security definer
set search_path = ''
as $$
declare
  v_count integer;
begin
  if coalesce(auth.jwt() ->> 'role', '') <> 'service_role'
     and new.merchant_id is distinct from auth.uid() then
    raise exception 'Accès au dossier KYC refusé' using errcode = '42501';
  end if;

  perform 1
    from public.merchant_profiles p
    where p.user_id = new.merchant_id
    for update;
  if not found then
    raise exception 'Profil marchand introuvable';
  end if;

  if exists (
    select 1 from public.merchant_profiles p
    where p.user_id = new.merchant_id and p.kyc_status = 'verified'
  ) then
    raise exception 'Le dossier KYC est déjà vérifié';
  end if;

  select count(*) into v_count
    from public.merchant_kyc_documents d
    where d.merchant_id = new.merchant_id;
  if v_count >= 8 then
    raise exception 'Limite de huit justificatifs atteinte';
  end if;

  return new;
end
$$;

drop trigger if exists merchant_kyc_submission_pending on public.merchant_kyc_documents;
create trigger merchant_kyc_submission_pending
  before insert on public.merchant_kyc_documents
  for each row execute function public.mark_kyc_submission_pending();
revoke execute on function public.mark_kyc_submission_pending() from public, anon, authenticated;

create or replace function public.submit_kyc(
  p_full_name text,
  p_country text,
  p_document_type text
)
returns void
language plpgsql
security definer
set search_path = ''
as $$
declare
  v_user_id uuid := auth.uid();
  v_status text;
begin
  if v_user_id is null or coalesce(auth.jwt() ->> 'aal', '') <> 'aal2' then
    raise exception 'Une session MFA est requise' using errcode = '42501';
  end if;
  if p_full_name is null or char_length(trim(p_full_name)) < 2 or char_length(trim(p_full_name)) > 120 then
    raise exception 'Nom légal invalide';
  end if;
  if p_country is null or p_country not in ('CI', 'SN', 'BF', 'ML', 'BJ', 'TG', 'NE', 'GW') then
    raise exception 'Pays non pris en charge';
  end if;
  if p_document_type is null or p_document_type not in ('national_id', 'passport', 'driving_license') then
    raise exception 'Type de pièce invalide';
  end if;

  select p.kyc_status into v_status
    from public.merchant_profiles p
    where p.user_id = v_user_id
    for update;
  if not found then
    raise exception 'Profil marchand introuvable';
  end if;
  if v_status = 'verified' then
    raise exception 'Le dossier KYC est déjà vérifié';
  end if;
  if not exists (
    select 1 from public.merchant_kyc_documents d
    where d.merchant_id = v_user_id
      and d.document_type = 'identity'
      and d.document_side = 'front'
  ) then
    raise exception 'Dépose au moins une pièce d''identité';
  end if;

  update public.merchant_profiles
    set kyc_full_name = trim(p_full_name),
        kyc_country = p_country,
        kyc_document_type = p_document_type,
        kyc_status = 'pending',
        kyc_rejection_reason = null,
        kyc_submitted_at = now(),
        kyc_decided_at = null,
        kyc_decided_by = null,
        live_enabled = false,
        verified_at = null
    where user_id = v_user_id;

  insert into public.kyc_audit_logs (merchant_id, actor_id, event_type)
  values (v_user_id, v_user_id, 'submitted');
end
$$;

revoke execute on function public.submit_kyc(text, text, text) from public, anon;
grant execute on function public.submit_kyc(text, text, text) to authenticated;

create or replace function public.log_kyc_document_upload()
returns trigger
language plpgsql
security definer
set search_path = ''
as $$
begin
  insert into public.kyc_audit_logs (merchant_id, actor_id, event_type, details)
  values (
    new.merchant_id,
    case when coalesce(auth.jwt() ->> 'role', '') = 'service_role' then null else auth.uid() end,
    'document_uploaded',
    jsonb_build_object('document_id', new.id, 'document_type', new.document_type)
  );
  return new;
end
$$;

drop trigger if exists merchant_kyc_document_uploaded on public.merchant_kyc_documents;
create trigger merchant_kyc_document_uploaded
  after insert on public.merchant_kyc_documents
  for each row execute function public.log_kyc_document_upload();
revoke execute on function public.log_kyc_document_upload() from public, anon, authenticated;

create or replace function public.decide_kyc(
  p_merchant_id uuid,
  p_decision text,
  p_reason text,
  p_admin_id uuid
)
returns void
language plpgsql
security definer
set search_path = ''
as $$
declare
  v_profile public.merchant_profiles%rowtype;
begin
  if coalesce(auth.jwt() ->> 'role', '') <> 'service_role' then
    raise exception 'Opération serveur uniquement' using errcode = '42501';
  end if;
  if p_admin_id is null or p_merchant_id = p_admin_id then
    raise exception 'Un administrateur ne peut pas examiner son propre dossier' using errcode = '42501';
  end if;
  if p_decision not in ('verified', 'rejected') then
    raise exception 'Décision KYC invalide';
  end if;
  if p_decision = 'rejected' and (p_reason is null or char_length(trim(p_reason)) < 10 or char_length(p_reason) > 1000) then
    raise exception 'Un motif de refus de 10 à 1000 caractères est obligatoire';
  end if;

  select * into v_profile
    from public.merchant_profiles p
    where p.user_id = p_merchant_id
    for update;
  if not found or v_profile.kyc_status <> 'pending' then
    raise exception 'Le dossier n''est pas en attente de décision';
  end if;

  update public.merchant_profiles
    set kyc_status = p_decision,
        kyc_rejection_reason = case when p_decision = 'rejected' then trim(p_reason) else null end,
        kyc_decided_at = now(),
        kyc_decided_by = p_admin_id,
        live_enabled = false,
        verified_at = case when p_decision = 'verified' then now() else null end
    where user_id = p_merchant_id;

  insert into public.kyc_audit_logs (merchant_id, actor_id, event_type, details)
  values (
    p_merchant_id,
    p_admin_id,
    case when p_decision = 'verified' then 'approved' else 'rejected' end,
    case when p_decision = 'rejected'
      then jsonb_build_object('reason', trim(p_reason))
      else '{}'::jsonb
    end
  );
end
$$;

revoke execute on function public.decide_kyc(uuid, text, text, uuid) from public, anon, authenticated;
grant execute on function public.decide_kyc(uuid, text, text, uuid) to service_role;

insert into storage.buckets (id, name, public, file_size_limit, allowed_mime_types)
values (
  'merchant-kyc-documents',
  'merchant-kyc-documents',
  false,
  4194304,
  array['application/pdf', 'image/jpeg', 'image/png']
)
on conflict (id) do update
  set name = excluded.name,
      public = false,
      file_size_limit = excluded.file_size_limit,
      allowed_mime_types = excluded.allowed_mime_types;

drop policy if exists merchant_kyc_storage_select_guard on storage.objects;
create policy merchant_kyc_storage_select_guard on storage.objects
  as restrictive for select to public
  using (
    bucket_id <> 'merchant-kyc-documents'
    or (
      (storage.foldername(name))[1] = (select auth.uid())::text
      and (select auth.jwt() ->> 'aal') = 'aal2'
    )
  );

drop policy if exists merchant_kyc_storage_select_own on storage.objects;
create policy merchant_kyc_storage_select_own on storage.objects
  for select to authenticated
  using (
    bucket_id = 'merchant-kyc-documents'
    and (storage.foldername(name))[1] = (select auth.uid())::text
    and (select auth.jwt() ->> 'aal') = 'aal2'
  );

drop policy if exists merchant_kyc_storage_insert_guard on storage.objects;
create policy merchant_kyc_storage_insert_guard on storage.objects
  as restrictive for insert to public
  with check (bucket_id <> 'merchant-kyc-documents');

drop policy if exists merchant_kyc_storage_insert_own on storage.objects;
create policy merchant_kyc_storage_insert_own on storage.objects
  for insert to authenticated
  with check (
    bucket_id = 'merchant-kyc-documents'
    and (storage.foldername(name))[1] = (select auth.uid())::text
    and (select auth.jwt() ->> 'aal') = 'aal2'
    and exists (
      select 1
      from public.merchant_profiles p
      where p.user_id = (select auth.uid())
        and p.kyc_status <> 'verified'
    )
  );

drop policy if exists merchant_kyc_storage_update_guard on storage.objects;
create policy merchant_kyc_storage_update_guard on storage.objects
  as restrictive for update to public
  using (bucket_id <> 'merchant-kyc-documents')
  with check (bucket_id <> 'merchant-kyc-documents');

-- Autorise uniquement le nettoyage d'un objet dont l'enregistrement de métadonnées a échoué.
drop policy if exists merchant_kyc_storage_delete_guard on storage.objects;
create policy merchant_kyc_storage_delete_guard on storage.objects
  as restrictive for delete to public
  using (
    bucket_id <> 'merchant-kyc-documents'
    or (
      (storage.foldername(name))[1] = (select auth.uid())::text
      and (select auth.jwt() ->> 'aal') = 'aal2'
      and not exists (
        select 1
        from public.merchant_kyc_documents d
        where d.storage_path = name
          and d.merchant_id = (select auth.uid())
      )
    )
  );

drop policy if exists merchant_kyc_storage_delete_orphan on storage.objects;
create policy merchant_kyc_storage_delete_orphan on storage.objects
  for delete to authenticated
  using (
    bucket_id = 'merchant-kyc-documents'
    and (storage.foldername(name))[1] = (select auth.uid())::text
    and (select auth.jwt() ->> 'aal') = 'aal2'
    and not exists (
      select 1
      from public.merchant_kyc_documents d
      where d.storage_path = name
        and d.merchant_id = (select auth.uid())
    )
  );
