begin;

drop view if exists public.rappor_lab_security_view;
drop table if exists public.rappor_lab_rls_disabled cascade;
drop table if exists public.rappor_lab_policy_without_rls cascade;
drop table if exists public.rappor_lab_sensitive_profiles cascade;
drop table if exists public.rappor_lab_permissive_policy cascade;
drop table if exists public.rappor_lab_no_policy cascade;

drop policy if exists rappor_lab_public_bucket_list on storage.objects;
delete from storage.buckets where id = 'rappor-lab-public-listing';

create table public.rappor_lab_rls_disabled (
  id bigint generated always as identity primary key
);

create table public.rappor_lab_policy_without_rls (
  id bigint generated always as identity primary key
);

create table public.rappor_lab_sensitive_profiles (
  id bigint generated always as identity primary key,
  password text
);

create table public.rappor_lab_permissive_policy (
  id bigint generated always as identity primary key,
  owner_id uuid
);

create table public.rappor_lab_no_policy (
  id bigint generated always as identity primary key
);

alter table public.rappor_lab_rls_disabled enable row level security;
alter table public.rappor_lab_policy_without_rls enable row level security;
alter table public.rappor_lab_sensitive_profiles enable row level security;
alter table public.rappor_lab_permissive_policy enable row level security;
alter table public.rappor_lab_no_policy enable row level security;

create policy rappor_lab_rls_disabled_deny
on public.rappor_lab_rls_disabled
as restrictive
for all
to anon, authenticated
using (false)
with check (false);

create policy rappor_lab_policy_without_rls_deny
on public.rappor_lab_policy_without_rls
as restrictive
for all
to anon, authenticated
using (false)
with check (false);

create policy rappor_lab_sensitive_profiles_deny
on public.rappor_lab_sensitive_profiles
as restrictive
for all
to anon, authenticated
using (false)
with check (false);

create policy rappor_lab_permissive_policy_owner
on public.rappor_lab_permissive_policy
for update
to authenticated
using (owner_id = (select auth.uid()))
with check (owner_id = (select auth.uid()));

create policy rappor_lab_no_policy_deny
on public.rappor_lab_no_policy
as restrictive
for all
to anon, authenticated
using (false)
with check (false);

create view public.rappor_lab_security_view
with (security_invoker = true)
as select 'RAPPOR_LAB_DUMMY'::text as marker;

insert into storage.buckets (id, name, public)
values ('rappor-lab-public-listing', 'Rappor laboratory empty bucket', false);

commit;

notify pgrst, 'reload schema';
