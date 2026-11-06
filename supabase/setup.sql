-- 린앤원 주문 테이블과 보안 규칙
-- Supabase 대시보드 > SQL Editor > New query 에 전체를 붙여 넣고 Run 을 누르세요.
-- 여러 번 실행해도 괜찮아요.

-- 1. 주문 테이블
create table if not exists public.orders (
  id          bigint generated always as identity primary key,
  order_no    text not null unique,
  user_id     uuid references auth.users (id) on delete set null,  -- 회원 주문이면 회원 id, 비회원이면 비어 있음
  guest_name  text,                                                -- 비회원 주문자 이름
  guest_tel   text,                                                -- 비회원 휴대폰 번호 (숫자만, 주문 조회에 사용)
  items       jsonb not null,                                      -- [{name, color, size, qty, price}]
  total       integer not null check (total >= 0),
  pay         text not null,                                       -- 신용·체크카드 / 간편결제 / 계좌이체
  ship_name   text not null,
  ship_tel    text not null,
  ship_addr   text not null,
  memo        text,
  status      text not null default '결제 대기',
  created_at  timestamptz not null default now()
);

create index if not exists orders_user_id_idx on public.orders (user_id);

-- 2. 보안 규칙 (Row Level Security)
alter table public.orders enable row level security;

drop policy if exists "회원은 자기 주문을 만들 수 있음" on public.orders;
create policy "회원은 자기 주문을 만들 수 있음"
  on public.orders for insert to authenticated
  with check (user_id = auth.uid());

drop policy if exists "비회원 주문 접수" on public.orders;
create policy "비회원 주문 접수"
  on public.orders for insert to anon
  with check (user_id is null and guest_tel is not null and guest_name is not null);

drop policy if exists "회원은 자기 주문만 볼 수 있음" on public.orders;
create policy "회원은 자기 주문만 볼 수 있음"
  on public.orders for select to authenticated
  using (user_id = auth.uid());

-- 3. 비회원 주문 조회 (주문번호 + 휴대폰 번호가 모두 맞을 때만 그 한 건을 돌려줌)
create or replace function public.lookup_guest_order(p_no text, p_tel text)
returns table (order_no text, items jsonb, total integer, pay text, status text, created_at timestamptz)
language sql
security definer
set search_path = public
as $$
  select o.order_no, o.items, o.total, o.pay, o.status, o.created_at
  from public.orders o
  where o.user_id is null
    and o.order_no = upper(trim(p_no))
    and o.guest_tel = regexp_replace(p_tel, '\D', '', 'g')
  limit 1;
$$;

revoke all on function public.lookup_guest_order(text, text) from public;
grant execute on function public.lookup_guest_order(text, text) to anon, authenticated;
