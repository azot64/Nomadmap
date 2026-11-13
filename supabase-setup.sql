create table if not exists public.map_access (
  email text primary key check (email = lower(email)),
  role text not null check (role in ('editor', 'viewer')),
  enabled boolean not null default true
);

alter table public.map_access enable row level security;

drop policy if exists "Users can read their own access" on public.map_access;
create policy "Users can read their own access"
  on public.map_access
  for select
  to authenticated
  using (email = lower(coalesce(auth.jwt() ->> 'email', '')));

create or replace function public.current_map_role()
returns text
language sql
stable
security definer
set search_path = ''
as $$
  select access.role
  from public.map_access as access
  where access.enabled
    and access.email = lower(coalesce(auth.jwt() ->> 'email', ''))
  limit 1
$$;

revoke all on function public.current_map_role() from public;
grant execute on function public.current_map_role() to authenticated;

create table if not exists public.map_state (
  id integer primary key check (id = 1),
  objects jsonb not null default '[]'::jsonb,
  updated_at timestamptz not null default now()
);

insert into public.map_state (id, objects)
values (1, '[]'::jsonb)
on conflict (id) do nothing;

alter table public.map_state enable row level security;

drop policy if exists "Allowed users can view the map" on public.map_state;
create policy "Allowed users can view the map"
  on public.map_state
  for select
  to authenticated
  using (public.current_map_role() in ('editor', 'viewer'));

drop policy if exists "Editors can add map state" on public.map_state;
create policy "Editors can add map state"
  on public.map_state
  for insert
  to authenticated
  with check (public.current_map_role() = 'editor');

drop policy if exists "Editors can update map state" on public.map_state;
create policy "Editors can update map state"
  on public.map_state
  for update
  to authenticated
  using (public.current_map_role() = 'editor')
  with check (public.current_map_role() = 'editor');

grant select, insert, update on public.map_state to authenticated;
grant select on public.map_access to authenticated;

-- Upload shared-map.jpg to this private bucket after running the setup script.
insert into storage.buckets (id, name, public, file_size_limit, allowed_mime_types)
values ('map-assets', 'map-assets', false, 52428800, array['image/jpeg'])
on conflict (id) do update
set public = false,
    file_size_limit = excluded.file_size_limit,
    allowed_mime_types = excluded.allowed_mime_types;

drop policy if exists "Allowed users can read shared map background" on storage.objects;
create policy "Allowed users can read shared map background"
  on storage.objects
  for select
  to authenticated
  using (
    bucket_id = 'map-assets'
    and public.current_map_role() in ('editor', 'viewer')
  );

do $$
begin
  if not exists (
    select 1
    from pg_publication_tables
    where pubname = 'supabase_realtime'
      and schemaname = 'public'
      and tablename = 'map_state'
  ) then
    alter publication supabase_realtime add table public.map_state;
  end if;
end
$$;

-- Replace these examples with the people who should be able to use the map.
insert into public.map_access (email, role, enabled)
values
  ('sans3107sans@gmail.com', 'editor', true),
  ('viewer@example.com', 'viewer', true)
on conflict (email) do update
set role = excluded.role,
    enabled = excluded.enabled;