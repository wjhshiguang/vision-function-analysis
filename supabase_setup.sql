-- ============================================================
-- 视功能分析台 · 真·管理员后台（服务端鉴权）
-- 用法：Supabase 控制台 → 左侧 SQL Editor → 粘贴全部 → Run
-- 说明：本脚本创建邀请码表、授权用户表与两个服务端校验函数。
--       开启 RLS 后，页面上的 anon key 无法直接读到邀请码，
--       只能通过函数校验 —— 这是"邀请码不再明文暴露"的关键。
-- ============================================================

create extension if not exists pgcrypto;

-- 1. 邀请码表（你在控制台里增删/停用）
create table if not exists public.invite_codes (
  id          uuid primary key default gen_random_uuid(),
  code        text not null unique,
  active      boolean not null default true,
  max_uses    int not null default 1,      -- 该码最多能用几次
  used_count  int not null default 0,
  expires_at  timestamptz,                 -- 留空 = 长期有效
  note        text,                        -- 备注：发给谁了
  created_at  timestamptz not null default now()
);

-- 2. 授权用户表（谁登进来过，你在控制台里停用即踢人）
create table if not exists public.authorized_users (
  id         uuid primary key default gen_random_uuid(),
  phone      text not null unique,
  code       text,
  active     boolean not null default true,
  created_at timestamptz not null default now(),
  last_seen  timestamptz
);

-- 3. 开启行级安全（RLS）：不建任何 policy = anon 一律读不到、改不了
alter table public.invite_codes     enable row level security;
alter table public.authorized_users enable row level security;

-- 4. 兑换邀请码并登记手机号（服务端校验，客户端拿不到码表）
create or replace function public.redeem_invite(p_phone text, p_code text)
returns json
language plpgsql
security definer
set search_path = public
as $$
declare
  v_code public.invite_codes;
begin
  if p_phone is null or p_phone !~ '^1[3-9][0-9]{9}$' then
    return json_build_object('ok', false, 'msg', '手机号格式不正确');
  end if;

  select * into v_code
    from public.invite_codes
   where upper(code) = upper(trim(p_code))
   limit 1;

  if v_code is null then
    return json_build_object('ok', false, 'msg', '邀请码不存在');
  end if;
  if v_code.active is not true then
    return json_build_object('ok', false, 'msg', '邀请码已停用');
  end if;
  if v_code.expires_at is not null and v_code.expires_at < now() then
    return json_build_object('ok', false, 'msg', '邀请码已过期');
  end if;
  if v_code.used_count >= v_code.max_uses then
    return json_build_object('ok', false, 'msg', '邀请码次数已用完');
  end if;

  update public.invite_codes set used_count = used_count + 1 where id = v_code.id;

  insert into public.authorized_users (phone, code, active, last_seen)
  values (p_phone, upper(trim(p_code)), true, now())
  on conflict (phone) do update
    set active = true, last_seen = now(), code = upper(trim(p_code));

  return json_build_object('ok', true, 'msg', 'ok');
end;
$$;

-- 5. 每次打开时复查：该手机号是否仍被授权（服务端为准 → 可随时踢人）
create or replace function public.check_access(p_phone text)
returns json
language plpgsql
security definer
set search_path = public
as $$
declare
  v_active boolean;
begin
  select active into v_active from public.authorized_users where phone = p_phone;
  if v_active is true then
    update public.authorized_users set last_seen = now() where phone = p_phone;
    return json_build_object('ok', true);
  end if;
  return json_build_object('ok', false, 'msg', '账号已被停用');
end;
$$;

-- 6. 只放行这两个函数给前端（anon）调用
revoke all on function public.redeem_invite(text, text) from public;
grant execute on function public.redeem_invite(text, text) to anon, authenticated;
revoke all on function public.check_access(text) from public;
grant execute on function public.check_access(text) to anon, authenticated;

-- 7. 示例：给你自己建一个长期管理员码（可自行改码 / 加码）
insert into public.invite_codes (code, active, max_uses, note)
values ('ADMIN-XIULI', true, 999999, '管理员本人专用（长期）')
on conflict (code) do nothing;
