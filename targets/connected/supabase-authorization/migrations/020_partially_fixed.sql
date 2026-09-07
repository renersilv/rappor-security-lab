begin;

drop policy if exists lab_public_read on public.rappor_lab_documents;
drop policy if exists lab_authenticated_read on public.rappor_lab_documents;
drop policy if exists lab_authenticated_write on public.rappor_lab_documents;

revoke all on table public.rappor_lab_documents from public, anon, authenticated;
grant select on table public.rappor_lab_documents to anon;
grant select, insert on table public.rappor_lab_documents to authenticated;

alter table public.rappor_lab_documents enable row level security;

create policy lab_public_read
on public.rappor_lab_documents
for select
to anon, authenticated
using (true);

create policy lab_authenticated_write
on public.rappor_lab_documents
for insert
to authenticated
with check (true);

commit;

notify pgrst, 'reload schema';
