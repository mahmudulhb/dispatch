-- Dispatch — Supabase setup. Run once in: Supabase Dashboard → SQL Editor → New query.
-- CAPTCHA (Cloudflare Turnstile) — one-time dashboard steps:
--   1. Cloudflare → Turnstile → Add site (your domain). Copy the SITE KEY (goes in dispatch-supabase.html → TURNSTILE_SITE_KEY)
--      and the SECRET KEY (goes in Supabase, next step).
--   2. Supabase → Authentication → Sign In / Providers → turn ON "Allow anonymous sign-ins".
--   3. Supabase → Authentication → Attack Protection → enable CAPTCHA protection → provider "Cloudflare Turnstile" → paste the SECRET KEY.
-- Publishing then needs a CAPTCHA-verified (anonymous) session; this file also adds a server-side limit of 5 snippets/minute per session.
--
-- Security model: the table is locked (RLS on, no policies). The browser (anon key) can ONLY call the
-- functions below. Editing needs the secret edit-key that stays in the creator's browser; only its
-- SHA-256 hash is stored in the database.

create table if not exists public.snippets (
  id          text primary key check (id ~ '^[a-zA-Z0-9]{6}$'),   -- 6 chars: a-z A-Z 0-9
  code        text not null check (char_length(code) between 1 and 200000),
  lang        text not null default 'Plain text',
  owner_hash  text not null,
  created_at  timestamptz not null default now(),
  updated_at  timestamptz not null default now()
);

alter table public.snippets add column if not exists creator uuid default auth.uid();
alter table public.snippets enable row level security;
revoke all on public.snippets from anon, authenticated;

-- Remove older versions first (Postgres cannot change a function's return type in place). Safe to re-run.
drop function if exists public.create_snippet(text, text, text, text);
drop function if exists public.get_snippet(text);
drop function if exists public.update_snippet(text, text, text, text);

create or replace function public.create_snippet(p_id text, p_code text, p_lang text, p_hash text)
returns timestamptz language plpgsql security definer set search_path = public as $$
declare t timestamptz;
begin
  if auth.uid() is null then
    raise exception 'captcha session required' using errcode = '42501';
  end if;
  if (select count(*) from snippets where creator = auth.uid() and created_at > now() - interval '1 minute') >= 5 then
    raise exception 'rate limit' using errcode = 'RL001';
  end if;
  insert into snippets (id, code, lang, owner_hash, creator) values (p_id, p_code, p_lang, p_hash, auth.uid())
  returning created_at into t;                       -- duplicate id raises 23505; the app retries
  return t;
end $$;

create or replace function public.get_snippet(p_id text)
returns table (code text, lang text, created_at timestamptz, updated_at timestamptz)
language sql stable security definer set search_path = public as $$
  select code, lang, created_at, updated_at from snippets where id = p_id;
$$;

create or replace function public.update_snippet(p_id text, p_hash text, p_code text, p_lang text)
returns boolean language plpgsql security definer set search_path = public as $$
begin
  update snippets set code = p_code, lang = p_lang, updated_at = now()
  where id = p_id and owner_hash = p_hash;
  return found;
end $$;

revoke all on function public.create_snippet(text,text,text,text) from public;
revoke all on function public.get_snippet(text)                   from public;
revoke all on function public.update_snippet(text,text,text,text) from public;
revoke execute on function public.create_snippet(text,text,text,text) from anon;   -- publishing requires a CAPTCHA-verified session
grant  execute on function public.create_snippet(text,text,text,text) to authenticated;
grant execute on function public.get_snippet(text)                   to anon, authenticated;
grant execute on function public.update_snippet(text,text,text,text) to anon, authenticated;

-- Short links like https://dispatch.dev/aB3x9Z : host dispatch-supabase.html and rewrite
-- /<6 chars> and /embed/<6 chars> to it (e.g. Netlify `_redirects`:  /*  /dispatch-supabase.html  200),
-- then set LINK_BASE='https://dispatch.dev/' and PATH_ROUTING=true in the CONFIG block.
