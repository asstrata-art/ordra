alter table medlem add column if not exists aktiv boolean not null default true;
alter table medlem add column if not exists epost text;
alter table invitasjon add column if not exists navn text;
update medlem m set epost=u.email from auth.users u where u.id=m.user_id and (m.epost is null or m.epost='');
create unique index if not exists medlem_uniq on medlem(firma_id,user_id);
create unique index if not exists invitasjon_uniq on invitasjon(firma_id,lower(epost));

create or replace function public.mine_firmaer() returns setof uuid language sql stable security definer set search_path to 'public' as $$ select firma_id from medlem where user_id = auth.uid() and aktiv $$;
create or replace function public.er_admin(fid uuid) returns boolean language sql stable security definer set search_path to 'public' as $$ select exists(select 1 from medlem where user_id=auth.uid() and firma_id=fid and aktiv and rolle in ('eier','admin')) $$;
create or replace function public.er_eier(fid uuid) returns boolean language sql stable security definer set search_path to 'public' as $$ select exists(select 1 from medlem where user_id=auth.uid() and firma_id=fid and aktiv and rolle='eier') $$;

create or replace function public.handle_new_user() returns trigger language plpgsql security definer set search_path to 'public' as $$
declare inv record; fid uuid; begin
  select * into inv from invitasjon where lower(epost)=lower(new.email) order by created_at desc limit 1;
  if found then
    insert into medlem(firma_id,user_id,rolle,navn,epost) values (inv.firma_id,new.id,case when inv.rolle in ('admin','ansatt') then inv.rolle else 'ansatt' end,inv.navn,new.email) on conflict do nothing;
    delete from invitasjon where firma_id=inv.firma_id and lower(epost)=lower(new.email);
  else
    insert into firma(navn) values (coalesce(new.raw_user_meta_data->>'firma','')) returning id into fid;
    insert into medlem(firma_id,user_id,rolle,epost) values (fid,new.id,'eier',new.email);
  end if;
  return new;
end $$;

-- Eksisterende bruker som blir invitert til et firma
create or replace function public.godta_invitasjon() returns uuid language plpgsql security definer set search_path to 'public' as $$
declare inv record; em text; begin
  em:=lower(coalesce(auth.jwt()->>'email',''));
  if auth.uid() is null or em='' then return null; end if;
  select * into inv from invitasjon where lower(epost)=em order by created_at desc limit 1;
  if not found then return null; end if;
  insert into medlem(firma_id,user_id,rolle,navn,epost) values (inv.firma_id,auth.uid(),case when inv.rolle in ('admin','ansatt') then inv.rolle else 'ansatt' end,inv.navn,em) on conflict do nothing;
  delete from invitasjon where firma_id=inv.firma_id and lower(epost)=em;
  return inv.firma_id;
end $$;
revoke all on function public.godta_invitasjon() from anon;

create or replace function public.medlem_vakt() returns trigger language plpgsql security definer set search_path to 'public' as $$
begin
  if auth.uid() is null then return new; end if;
  if new.firma_id<>old.firma_id or new.user_id<>old.user_id then raise exception 'Kan ikke flytte medlem'; end if;
  if new.rolle not in ('eier','admin','ansatt') then raise exception 'Ugyldig rolle'; end if;
  if old.rolle is distinct from new.rolle and (old.rolle='eier' or new.rolle='eier') and not er_eier(old.firma_id) then raise exception 'Bare eier kan endre eierrollen'; end if;
  if old.rolle='eier' and (new.rolle<>'eier' or not new.aktiv) and (select count(*) from medlem where firma_id=old.firma_id and rolle='eier' and aktiv)<=1 then raise exception 'Firmaet må ha minst én aktiv eier'; end if;
  return new;
end $$;
drop trigger if exists medlem_vakt on medlem;
create trigger medlem_vakt before update on medlem for each row execute function medlem_vakt();

create or replace function public.firma_vakt() returns trigger language plpgsql security definer set search_path to 'public' as $$
begin
  if auth.uid() is not null and coalesce(current_setting('ordra.plan_ok',true),'')<>'1' then new.plan:=old.plan; new.stripe_customer:=old.stripe_customer; end if;
  return new;
end $$;
drop trigger if exists firma_vakt on firma;
create trigger firma_vakt before update on firma for each row execute function firma_vakt();

drop policy if exists medlem_ins on medlem;
drop policy if exists medlem_upd on medlem;
create policy medlem_upd on medlem for update using (er_admin(firma_id)) with check (er_admin(firma_id));
drop policy if exists medlem_del on medlem;
create policy medlem_del on medlem for delete using (er_admin(firma_id) and rolle<>'eier' and user_id<>auth.uid());
drop policy if exists inv_ins on invitasjon;
create policy inv_ins on invitasjon for insert with check (er_admin(firma_id));
drop policy if exists inv_del on invitasjon;
create policy inv_del on invitasjon for delete using (er_admin(firma_id));
drop policy if exists firma_upd on firma;
create policy firma_upd on firma for update using (er_admin(id)) with check (er_admin(id));
drop policy if exists firma_ins on firma;
drop policy if exists budsjett_all on budsjett;
create policy budsjett_all on budsjett for all using (er_admin(firma_id)) with check (er_admin(firma_id));

-- Stripe-aktivering (klienten melder retur fra betaling; én cs kan bare brukes én gang)
create table if not exists stripe_aktivering (cs text primary key, firma_id uuid not null references firma(id) on delete cascade, tier text not null, at timestamptz default now());
alter table stripe_aktivering enable row level security;
create or replace function public.aktiver_plan(p_tier text, p_cs text) returns text language plpgsql security definer set search_path to 'public' as $$
declare fid uuid; begin
  if p_tier not in ('pro','ai','drift') or p_cs !~ '^cs_(live|test)_[A-Za-z0-9]{20,}$' then raise exception 'Ugyldig'; end if;
  select firma_id into fid from medlem where user_id=auth.uid() and aktiv and rolle in ('eier','admin') order by created_at desc limit 1;
  if fid is null then raise exception 'Ingen tilgang'; end if;
  insert into stripe_aktivering(cs,firma_id,tier) values (p_cs,fid,p_tier);
  perform set_config('ordra.plan_ok','1',true);
  update firma set plan=p_tier where id=fid;
  return p_tier;
end $$;
revoke all on function public.aktiver_plan(text,text) from anon;

-- Plattform-eier (Ordra): oversikt over alle firma
create table if not exists plattform_admin (epost text primary key);
alter table plattform_admin enable row level security;
insert into plattform_admin(epost) values ('asstrata@gmail.com'),('ordra.ordra@gmail.com') on conflict do nothing;
create or replace function public.er_plattform() returns boolean language sql stable security definer set search_path to 'public' as $$ select exists(select 1 from plattform_admin where lower(epost)=lower(coalesce(auth.jwt()->>'email',''))) $$;
create or replace function public.plattform_firmaer() returns table(id uuid, navn text, orgnr text, plan text, opprettet timestamptz, brukere bigint, ordre bigint, sist timestamptz, eier text) language plpgsql stable security definer set search_path to 'public' as $$
begin
  if not er_plattform() then raise exception 'Ingen tilgang'; end if;
  return query select f.id,f.navn,f.orgnr,f.plan,f.created_at,
    (select count(*) from medlem m where m.firma_id=f.id and m.aktiv),
    (select count(*) from ordre o where o.firma_id=f.id and not o.slettet),
    (select max(o.updated_at) from ordre o where o.firma_id=f.id),
    (select string_agg(m.epost,', ') from medlem m where m.firma_id=f.id and m.rolle='eier')
  from firma f order by f.created_at desc;
end $$;
create or replace function public.plattform_sett_plan(p_firma uuid, p_plan text) returns void language plpgsql security definer set search_path to 'public' as $$
begin
  if not er_plattform() then raise exception 'Ingen tilgang'; end if;
  if p_plan not in ('gratis','pro','ai','drift') then raise exception 'Ugyldig nivå'; end if;
  perform set_config('ordra.plan_ok','1',true);
  update firma set plan=p_plan where id=p_firma;
end $$;
revoke all on function public.plattform_firmaer() from anon;
revoke all on function public.plattform_sett_plan(uuid,text) from anon;

do $$ declare t text; begin
  foreach t in array array['avvik','ansatte','hms'] loop
    execute format('create table if not exists %I (id text not null, firma_id uuid not null references firma(id) on delete cascade, data jsonb not null default ''{}''::jsonb, slettet boolean not null default false, created_at timestamptz default now(), updated_at timestamptz default now(), primary key (firma_id,id))', t);
    execute format('create index if not exists %I on %I (firma_id, updated_at desc)', t||'_upd_idx', t);
    execute format('drop trigger if exists %I on %I', t||'_upd', t);
    execute format('create trigger %I before update on %I for each row execute function set_updated_at()', t||'_upd', t);
    execute format('alter table %I enable row level security', t);
    execute format('drop policy if exists %I on %I', t||'_all', t);
    execute format('create policy %I on %I for all using (firma_id in (select mine_firmaer())) with check (firma_id in (select mine_firmaer()))', t||'_all', t);
  end loop;
end $$;
select (select count(*) from pg_policies where schemaname='public') as policies, (select string_agg(epost||':'||rolle,', ') from medlem) as medlemmer;
