-- DHS Visitor System, Phase 2 (shared database + sign-in).
-- Supabase: SQL Editor > New query > paste this whole file > Run. Run it once.

create table public.profiles (
  id uuid primary key references auth.users(id) on delete cascade,
  role text not null check (role in ('guard','admin','teacher')),
  display_name text
);

create table public.faculty (
  id bigint generated always as identity primary key,
  name text not null check (char_length(name) between 1 and 120),
  kind text not null default 'teacher' check (kind in ('teacher','office')),
  ntfy_topic text unique check (ntfy_topic ~ '^[A-Za-z0-9_-]{1,64}$'),
  profile_id uuid unique references public.profiles(id) on delete set null,   -- teacher login (optional)
  created_at timestamptz not null default now()
);

create table public.visitors (
  id bigint generated always as identity primary key,
  name text not null check (char_length(name) between 1 and 80),
  contact text check (char_length(contact) <= 20),
  purpose text not null check (purpose in ('meeting','document','parent','personal','delivery','other')),
  purpose_other text check (char_length(purpose_other) <= 80),
  faculty_id bigint references public.faculty(id) on delete set null,
  faculty_name text not null,
  time_in timestamptz not null default now(),
  time_out timestamptz,
  -- result of the ntfy request (browser sends it in Phase 2). "accepted" does not prove a phone showed it.
  ntfy_status text not null default 'pending' check (ntfy_status in ('pending','accepted','failed','notopic')),
  ntfy_error text,
  ntfy_at timestamptz,
  created_by uuid default auth.uid(),
  constraint other_needs_text check (purpose <> 'other' or char_length(btrim(coalesce(purpose_other,''))) > 0)
);
create index on public.visitors (time_in desc);

-- who is signed in?
create function public.my_role() returns text
language sql stable security definer set search_path = public as
$$ select role from public.profiles where id = auth.uid() $$;
revoke execute on function public.my_role() from public, anon;
grant execute on function public.my_role() to authenticated;

create function public.my_faculty() returns bigint
language sql stable security definer set search_path = public as
$$ select id from public.faculty where profile_id = auth.uid() limit 1 $$;
revoke execute on function public.my_faculty() from public, anon;
grant execute on function public.my_faculty() to authenticated;

-- visitor rows can only be checked out (once, with the server clock) or get their ntfy result updated
create function public.visitors_guard_update() returns trigger language plpgsql as $$
begin
  if (new.name, new.contact, new.purpose, new.purpose_other, new.faculty_name, new.time_in, new.created_by)
     is distinct from
     (old.name, old.contact, old.purpose, old.purpose_other, old.faculty_name, old.time_in, old.created_by)
     or (new.faculty_id is distinct from old.faculty_id and new.faculty_id is not null) then
    raise exception 'Visitor records can only be checked out';
  end if;
  if old.time_out is not null and new.time_out is distinct from old.time_out then
    raise exception 'Already checked out';
  end if;
  if new.time_out is not null and old.time_out is null then new.time_out := now(); end if;
  return new;
end $$;
create trigger trg_visitors_update before update on public.visitors
  for each row execute function public.visitors_guard_update();

-- access rules (Row Level Security)
alter table public.profiles enable row level security;
alter table public.faculty  enable row level security;
alter table public.visitors enable row level security;

create policy profiles_read on public.profiles for select to authenticated
  using (id = auth.uid() or public.my_role() = 'admin');

create policy faculty_read  on public.faculty for select to authenticated
  using (public.my_role() in ('guard','admin') or id = public.my_faculty());   -- a teacher sees only their own row (and own topic)
create policy faculty_write on public.faculty for all to authenticated
  using (public.my_role() = 'admin') with check (public.my_role() = 'admin');

create policy visitors_read   on public.visitors for select to authenticated
  using (public.my_role() in ('guard','admin') or faculty_id = public.my_faculty());   -- a teacher sees only visitors for them
create policy visitors_insert on public.visitors for insert to authenticated
  with check (public.my_role() in ('guard','admin') and time_out is null);
create policy visitors_update on public.visitors for update to authenticated
  using (public.my_role() in ('guard','admin')) with check (public.my_role() in ('guard','admin'));

revoke all on public.profiles, public.faculty, public.visitors from anon;
revoke insert, update, delete on public.profiles from authenticated;
revoke delete on public.visitors from authenticated;

-- RETENTION: delete visitor records older than N days (privacy: do not keep personal data forever).
-- Not callable from the website. Run by hand in the SQL Editor, e.g.:   select public.purge_old_visitors(365);
create function public.purge_old_visitors(p_days int) returns int
language plpgsql security definer set search_path = public as $$
declare n int;
begin
  if p_days < 30 then raise exception 'Keep at least 30 days'; end if;
  delete from public.visitors where time_in < now() - make_interval(days => p_days);
  get diagnostics n = row_count;
  return n;
end $$;
revoke execute on function public.purge_old_visitors(int) from public, anon, authenticated;

-- TEACHER LOGIN (optional, for teachers without a phone alert): create the user in Authentication > Users (Auto Confirm),
-- then run in the SQL Editor:   select public.link_teacher('teacher@email', 'Exact display name as shown in Faculty');
create function public.link_teacher(p_email text, p_faculty_name text) returns void
language plpgsql security definer set search_path = public as $$
declare uid uuid; fid bigint; n int;
begin
  select id into uid from auth.users where lower(email) = lower(p_email);
  if uid is null then raise exception 'No user with that email. Create it in Authentication > Users first.'; end if;
  select count(*), min(id) into n, fid from public.faculty where name = p_faculty_name;
  if n <> 1 then raise exception 'Faculty name must match exactly one row (found %)', n; end if;
  insert into public.profiles (id, role, display_name) values (uid, 'teacher', p_faculty_name)
    on conflict (id) do update set role = 'teacher', display_name = excluded.display_name;
  update public.faculty set profile_id = null where profile_id = uid;
  update public.faculty set profile_id = uid where id = fid;
end $$;
revoke execute on function public.link_teacher(text, text) from public, anon, authenticated;

-- live updates between devices
alter publication supabase_realtime add table public.visitors, public.faculty;

-- ADMIN + GUARD ACCOUNTS
-- 1) Dashboard > Authentication > Users > Add user > Create new user (tick "Auto Confirm User").
-- 2) Then run these two lines with the real emails (this file does not need to be re-run, just these lines):
--    insert into public.profiles (id, role, display_name) select id, 'admin', 'Administrator'  from auth.users where email = 'ADMIN_EMAIL';
--    insert into public.profiles (id, role, display_name) select id, 'guard', 'Security Guard' from auth.users where email = 'GUARD_EMAIL';
