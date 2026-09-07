begin;

drop policy if exists lab_public_read on public.rappor_lab_documents;
drop policy if exists lab_authenticated_read on public.rappor_lab_documents;
drop policy if exists lab_authenticated_write on public.rappor_lab_documents;

revoke all on table public.rappor_lab_documents from public, anon, authenticated;
grant select, insert on table public.rappor_lab_documents to anon, authenticated;

alter table public.rappor_lab_documents disable row level security;

commit;

notify pgrst, 'reload schema';
