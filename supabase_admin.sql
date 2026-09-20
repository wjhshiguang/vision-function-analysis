-- ============================================================
-- 视功能分析台 · 页内管理员功能（第二次执行）
-- 用法：Supabase 控制台 → SQL Editor → 粘贴全部 → Run
-- 前提：已执行过 supabase_setup.sql
-- 效果：管理员登录后在侧边栏看到「管理」，可一键踢人/发码/停码；
--       普通用户完全看不到、也进不去（服务端校验，前端改不了）。
-- ============================================================

create extension if not exists pgcrypto;

-- 1. 给用户表和邀请码表加"管理员"标记
alter table public.authorized_users add column if not exists is_admin boolean not null default false;
alter table public.invite_codes     add column if not exists is_admin boolean not null default false;

-- 用管理员码（ADMIN-XIULI）兑换的人自动成为管理员
update public.invite_codes set is_admin = true where upper(code) = 'ADMIN-XIULI';

-- 2. 管理员口令与登录保护（防暴力破解）
create table if not exists public.admin_auth (
  id           int primary key default 1,
  pass_hash    text not null,
  fail_count   int not null default 0,
  locked_until timestamptz
);
-- 默认管理员密码：admin888（登录后请在「管理」里立即修改）
insert into public.admin_auth (id, pass_hash)
values (1, crypt('admin888', gen_salt('bf')))
on conflict (id) do nothing;

-- 3. 管理员会话（30 分钟有效）
create table if not exists public.admin_sessions (
  token      text primary key,
  expires_at timestamptz not null default now() + interval '30 minutes'
);

alter table public.admin_auth     enable row level security;
alter table public.admin_sessions enable row level security;

-- 4. 内部：校验会话是否有效
create or replace function public.admin_ok(p_token text)
returns boolean
language plpgsql security definer set search_path = public
as $$
begin
  if p_token is null or p_token = '' then return false; end if;
  delete from public.admin_sessions where expires_at < now();
  return exists(select 1 from public.admin_sessions where token = p_token and expires_at > now());
end;
$$;

-- 5. 管理员登录（密码正确才发票据；连错 8 次锁 15 分钟）
create or replace function public.admin_login(p_pass text)
returns json
language plpgsql security definer set search_path = public
as $$
declare
  a public.admin_auth;
  v_token text;
begin
  select * into a from public.admin_auth where id = 1;
  if a is null then
    return json_build_object('ok', false, 'msg', '管理员未初始化');
  end if;

  if a.locked_until is not null and a.locked_until > now() then
    return json_build_object('ok', false, 'msg', '尝试过多，请 15 分钟后再试');
  end if;

  if a.pass_hash = crypt(coalesce(p_pass,''), a.pass_hash) then
    v_token := replace(gen_random_uuid()::text || gen_random_uuid()::text, '-', '');
    insert into public.admin_sessions (token) values (v_token);
    update public.admin_auth set fail_count = 0, locked_until = null where id = 1;
    return json_build_object('ok', true, 'token', v_token);
  end if;

  update public.admin_auth
     set fail_count = fail_count + 1,
         locked_until = case when fail_count + 1 >= 8 then now() + interval '15 minutes' else null end
   where id = 1;
  return json_build_object('ok', false, 'msg', '管理员密码错误');
end;
$$;

-- 6. 拉取用户与邀请码（需有效票据）
create or replace function public.admin_list(p_token text)
returns json
language plpgsql security definer set search_path = public
as $$
declare
  v_users json; v_codes json;
begin
  if not public.admin_ok(p_token) then
    return json_build_object('ok', false, 'msg', '未授权或已过期，请重新输入管理员密码');
  end if;
  select coalesce(json_agg(x), '[]'::json) into v_users from (
    select phone, code, active, is_admin, created_at, last_seen
      from public.authorized_users order by created_at desc
  ) x;
  select coalesce(json_agg(y), '[]'::json) into v_codes from (
    select code, active, max_uses, used_count, expires_at, note, is_admin
      from public.invite_codes order by created_at desc
  ) y;
  return json_build_object('ok', true, 'users', v_users, 'codes', v_codes);
end;
$$;

-- 7. 停用 / 恢复用户（踢人）
create or replace function public.admin_set_user(p_token text, p_phone text, p_active boolean)
returns json
language plpgsql security definer set search_path = public
as $$
begin
  if not public.admin_ok(p_token) then
    return json_build_object('ok', false, 'msg', '未授权或已过期');
  end if;
  update public.authorized_users set active = p_active where phone = p_phone;
  return json_build_object('ok', true);
end;
$$;

-- 8. 彻底删除用户
create or replace function public.admin_del_user(p_token text, p_phone text)
returns json
language plpgsql security definer set search_path = public
as $$
begin
  if not public.admin_ok(p_token) then
    return json_build_object('ok', false, 'msg', '未授权或已过期');
  end if;
  delete from public.authorized_users where phone = p_phone;
  return json_build_object('ok', true);
end;
$$;

-- 9. 新建邀请码（发码）
create or replace function public.admin_add_code(p_token text, p_code text, p_max int, p_days int, p_note text)
returns json
language plpgsql security definer set search_path = public
as $$
begin
  if not public.admin_ok(p_token) then
    return json_build_object('ok', false, 'msg', '未授权或已过期');
  end if;
  if p_code is null or length(trim(p_code)) < 3 then
    return json_build_object('ok', false, 'msg', '邀请码太短');
  end if;
  if exists(select 1 from public.invite_codes where upper(code) = upper(trim(p_code))) then
    return json_build_object('ok', false, 'msg', '该邀请码已存在');
  end if;
  insert into public.invite_codes (code, active, max_uses, used_count, expires_at, note)
  values (upper(trim(p_code)), true,
          greatest(coalesce(p_max,1),1), 0,
          now() + (greatest(coalesce(p_days,30),1) || ' days')::interval,
          nullif(trim(coalesce(p_note,'')), ''));
  return json_build_object('ok', true);
end;
$$;

-- 10. 停用 / 启用邀请码
create or replace function public.admin_set_code(p_token text, p_code text, p_active boolean)
returns json
language plpgsql security definer set search_path = public
as $$
begin
  if not public.admin_ok(p_token) then
    return json_build_object('ok', false, 'msg', '未授权或已过期');
  end if;
  update public.invite_codes set active = p_active where upper(code) = upper(p_code);
  return json_build_object('ok', true);
end;
$$;

-- 11. 修改管理员密码
create or replace function public.admin_change_pass(p_token text, p_new text)
returns json
language plpgsql security definer set search_path = public
as $$
begin
  if not public.admin_ok(p_token) then
    return json_build_object('ok', false, 'msg', '未授权或已过期');
  end if;
  if p_new is null or length(p_new) < 6 then
    return json_build_object('ok', false, 'msg', '新密码至少 6 位');
  end if;
  update public.admin_auth set pass_hash = crypt(p_new, gen_salt('bf')), fail_count = 0, locked_until = null where id = 1;
  return json_build_object('ok', true);
end;
$$;

-- 12. 更新兑换逻辑：用管理员码兑换的人自动带管理员身份
create or replace function public.redeem_invite(p_phone text, p_code text)
returns json
language plpgsql security definer set search_path = public
as $$
declare
  v_code public.invite_codes;
begin
  if p_phone is null or p_phone !~ '^1[3-9][0-9]{9}$' then
    return json_build_object('ok', false, 'msg', '手机号格式不正确');
  end if;

  select * into v_code from public.invite_codes
   where upper(code) = upper(trim(p_code)) limit 1;

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

  insert into public.authorized_users (phone, code, active, is_admin, last_seen)
  values (p_phone, upper(trim(p_code)), true, coalesce(v_code.is_admin, false), now())
  on conflict (phone) do update
    set active = true, last_seen = now(), code = upper(trim(p_code)),
        is_admin = (public.authorized_users.is_admin or coalesce(v_code.is_admin, false));

  return json_build_object('ok', true, 'msg', 'ok');
end;
$$;

-- 13. 复查时一并返回"是否管理员"，供页面决定是否显示管理入口
create or replace function public.check_access(p_phone text)
returns json
language plpgsql security definer set search_path = public
as $$
declare
  v_active boolean; v_admin boolean;
begin
  select active, is_admin into v_active, v_admin
    from public.authorized_users where phone = p_phone;
  if v_active is true then
    update public.authorized_users set last_seen = now() where phone = p_phone;
    return json_build_object('ok', true, 'is_admin', coalesce(v_admin, false));
  end if;
  return json_build_object('ok', false, 'msg', '账号已被管理员停用');
end;
$$;

-- 14. 放行以上函数给前端调用
grant execute on function public.admin_login(text)                       to anon, authenticated;
grant execute on function public.admin_list(text)                        to anon, authenticated;
grant execute on function public.admin_set_user(text, text, boolean)     to anon, authenticated;
grant execute on function public.admin_del_user(text, text)              to anon, authenticated;
grant execute on function public.admin_add_code(text, text, int, int, text) to anon, authenticated;
grant execute on function public.admin_set_code(text, text, boolean)     to anon, authenticated;
grant execute on function public.admin_change_pass(text, text)           to anon, authenticated;
