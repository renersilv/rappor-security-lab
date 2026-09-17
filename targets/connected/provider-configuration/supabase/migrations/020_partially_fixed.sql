begin;

alter table public.rappor_lab_sensitive_profiles disable row level security;

drop policy rappor_lab_permissive_policy_owner on public.rappor_lab_permissive_policy;
create policy rappor_lab_permissive_policy_owner
on public.rappor_lab_permissive_policy
for update
to authenticated
using (true)
with check (true);

drop policy rappor_lab_no_policy_deny on public.rappor_lab_no_policy;

update storage.buckets
set public = true
where id = 'rappor-lab-public-listing';

create policy rappor_lab_public_bucket_list
on storage.objects
for select
to authenticated
using (bucket_id = 'rappor-lab-public-listing');

commit;

notify pgrst, 'reload schema';
