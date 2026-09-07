begin;

drop table if exists public.rappor_lab_documents cascade;

create table public.rappor_lab_documents (
  id uuid primary key default gen_random_uuid(),
  marker text not null check (marker ~ '^RAPPOR_LAB_DUMMY_[A-Z0-9_-]+$'),
  created_at timestamptz not null default statement_timestamp()
);

comment on table public.rappor_lab_documents is
  'Disposable Rappor Security authorization benchmark data only.';

revoke all on table public.rappor_lab_documents from public, anon, authenticated;

insert into public.rappor_lab_documents (marker)
values ('RAPPOR_LAB_DUMMY_SEED');

commit;

notify pgrst, 'reload schema';
