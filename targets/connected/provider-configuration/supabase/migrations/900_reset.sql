begin;

drop view if exists public.rappor_lab_security_view;
drop table if exists public.rappor_lab_rls_disabled cascade;
drop table if exists public.rappor_lab_policy_without_rls cascade;
drop table if exists public.rappor_lab_sensitive_profiles cascade;
drop table if exists public.rappor_lab_permissive_policy cascade;
drop table if exists public.rappor_lab_no_policy cascade;

drop policy if exists rappor_lab_public_bucket_list on storage.objects;
delete from storage.buckets where id = 'rappor-lab-public-listing';

commit;

notify pgrst, 'reload schema';
