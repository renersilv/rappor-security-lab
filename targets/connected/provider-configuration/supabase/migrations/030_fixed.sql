begin;

select true;

commit;

notify pgrst, 'reload schema';
