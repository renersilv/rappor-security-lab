begin;

drop table if exists public.rappor_lab_documents cascade;

commit;

notify pgrst, 'reload schema';
