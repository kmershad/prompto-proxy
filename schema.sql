-- ── PROMPTO DATABASE SCHEMA ──
-- Run this in Supabase SQL editor: supabase.com → SQL Editor → New query
-- Tables: users, usage_logs, prompt_sessions

-- ── 1. USERS ──
create table if not exists public.users (
  id            uuid primary key default gen_random_uuid(),
  email         text unique,
  created_at    timestamptz default now(),
  updated_at    timestamptz default now(),  -- tracks plan changes
  plan          text not null default 'free' check (plan in ('free', 'pro', 'team')),
  stripe_id     text,
  daily_limit   int not null default 3,
  timezone      text default 'UTC'
);

-- Auto-update updated_at on row change
create or replace function public.set_updated_at()
returns trigger language plpgsql as $$
begin new.updated_at = now(); return new; end;
$$;
create trigger users_updated_at
  before update on public.users
  for each row execute function public.set_updated_at();

-- Row-level security: users can only read their own row
alter table public.users enable row level security;
create policy "Users read own row"
  on public.users for select
  using (auth.uid() = id);

-- ── 2. USAGE LOGS ──
-- Tracks every analysis and build call per user per day
create table if not exists public.usage_logs (
  id          uuid primary key default gen_random_uuid(),
  user_id     uuid references public.users(id) on delete cascade,
  action      text not null check (action in ('analyze', 'build')),
  platform    text,                            -- 'ChatGPT', 'Claude', etc.
  created_at  timestamptz default now(),
  success     boolean default true
);

create index usage_logs_user_date on public.usage_logs (user_id, created_at);

alter table public.usage_logs enable row level security;
create policy "Users log own usage"
  on public.usage_logs for insert
  with check (auth.uid() = user_id);
create policy "Users read own usage"
  on public.usage_logs for select
  using (auth.uid() = user_id);

-- ── 3. PROMPT SESSIONS (Pro feature) ──
-- Stores prompt history for Pro users — never stored for free users
create table if not exists public.prompt_sessions (
  id              uuid primary key default gen_random_uuid(),
  user_id         uuid references public.users(id) on delete cascade,
  platform        text,
  original_prompt text not null,
  enhanced_prompt text,
  coaching_type   text,                        -- 'level', 'audience', 'format', etc.
  score_before    int,
  score_after     int,
  created_at      timestamptz default now()
);

create index prompt_sessions_user     on public.prompt_sessions (user_id, created_at desc);
create index prompt_sessions_platform on public.prompt_sessions (platform, created_at desc);

alter table public.prompt_sessions enable row level security;
create policy "Pro users manage own sessions"
  on public.prompt_sessions for all
  using (
    auth.uid() = user_id
    and exists (
      select 1 from public.users u
      where u.id = auth.uid() and u.plan in ('pro', 'team')
    )
  );

-- ── 4. HELPER VIEWS ──

-- Today's build count per user (used by proxy for server-side rate limiting)
create or replace view public.daily_builds as
select
  user_id,
  count(*) filter (where action = 'build' and success = true) as builds_today
from public.usage_logs
where created_at >= current_date
group by user_id;

-- ── 5. FUNCTIONS ──

-- Check if user is under their daily build limit
create or replace function public.can_build(p_user_id uuid)
returns boolean language sql security definer as $$
  select
    coalesce(
      (select u.daily_limit from public.users u where u.id = p_user_id),
      3  -- default free limit if user not found
    ) > coalesce(
      (select builds_today from public.daily_builds where user_id = p_user_id),
      0
    );
$$;

-- ── DONE ──
-- After running this, go to Supabase → API → copy your URL and anon key
-- Add them to the proxy's environment variables:
--   SUPABASE_URL=...
--   SUPABASE_ANON_KEY=...
