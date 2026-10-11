-- Run after schema_kyc.sql when an account appears verified without a valid manual review.
-- Resets only verified profiles missing any required submission, document, or approval evidence.
begin;

with reset_profiles as (
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
    )
  returning p.user_id
)
select count(*) as invalid_verified_profiles_reset from reset_profiles;

commit;
