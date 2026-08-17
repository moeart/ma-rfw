# -*- coding: utf-8 -*-
# 验证 RFWDATA 单头融合格式: 解析 + HMAC 链路
# 样例请求: GET /app/modules/login/templates/login.html?v=9.0.30(2)&htmlVersion=69068
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "lupa"))
from lupa.luajit21 import LuaRuntime
L = LuaRuntime()
base = os.path.dirname(os.path.dirname(os.path.abspath(__file__))).replace("\\", "/")
L.execute('package.path = "' + base + '/?.lua;" .. package.path')
L.execute("""
sha = require('sha256')
secret = "N9x_Ant1_r3p14y!"

-- 模拟 RFWDATA 融合值(ts.nonce.sign)
local rfwdata = "1786845452.1786845452-19-nxgqyrte.133c34f0b9a61c2bf937a36f58c804462ca0311847d8a40c2550e61ce9c05a69"

-- verify_sign 的解析正则
local t, nonce, sig = rfwdata:match("^(%d+)%.([%w%-]+)%.([%x]+)$")
_parsed = { t = t, nonce = nonce, sig = sig, ok = (t == "1786845452" and nonce == "1786845452-19-nxgqyrte") }

-- 用解析出的 t/nonce/sig 复算 HMAC(与服务器同款)
local uri = "/app/modules/login/templates/login.html?v=9.0.30(2)&htmlVersion=69068"
local bh = sha.hex("")
local expected = sha.hmac(secret, "GET|" .. uri .. "|" .. bh .. "|" .. t .. "|" .. nonce)
_hmac_ok = (expected == sig)

-- 回归: 结尾裸 "?" 的签名归一化
-- rfw.js pathQuery = new URL(url).pathname + .search; 裸 "?" 的 search 为空串,
-- 但 nginx $request_uri 保留 "?", 必须在服务端做同样归一化后才算 HMAC。
local function norm_uri(request_uri)
    local uri = request_uri
    if uri:match("%?$") then uri = uri:sub(1, -2) end
    return uri
end
_q_raw  = "/api/check/checkRightByPrivCode?"
_q_norm = norm_uri(_q_raw)
_q_ok   = (_q_norm == "/api/check/checkRightByPrivCode")
_q_sig_raw  = sha.hmac(secret, "POST|" .. _q_raw  .. "||1|n")
_q_sig_norm = sha.hmac(secret, "POST|" .. _q_norm .. "||1|n")
_q_diff = (_q_sig_raw ~= _q_sig_norm)
-- 带真实 query 的 URL 不应被改动
_q2 = norm_uri("/api/list?v=0.5&a=1")
_q2_ok = (_q2 == "/api/list?v=0.5&a=1")

-- 回归: sign-replay 持有者判定
-- check_nonce 落盘值格式 ts|method|uri; 同一 IP/方法/URL 且距首次消费 ≤ replay_relink_sec
-- 秒 → 判为同一请求二次处理(放行), 否则为真重放(拦截)。此处镜像判定语义。
local _WINDOW = 2
local function relink_match(v, method, uri, now)
    local t0, m0, u0 = v:match("^([%d]+)|(.-)|(.*)$")
    return t0 and m0 == method and u0 == uri and (now - tonumber(t0)) <= _WINDOW
end
_rl_same  = relink_match("1786854827|GET|/a/b.do?_=1", "GET", "/a/b.do?_=1", 1786854828) -- 同秒内同请求 → 放行
_rl_older = relink_match("1786854827|GET|/a/b.do?_=1", "GET", "/a/b.do?_=1", 1786854830) -- 3s 后 → 真重放
_rl_uri   = relink_match("1786854827|GET|/a/b.do?_=1", "GET", "/a/b.do?_=2", 1786854828) -- URL 不同 → 真重放
_rl_meth  = relink_match("1786854827|GET|/a/b.do?_=1", "POST", "/a/b.do?_=1", 1786854828) -- 方法不同 → 真重放
_rl_bad   = relink_match("garbage", "GET", "/x", 1786854828) -- 格式坏 → 真重放
""")
G = L.globals()
p = G._parsed
print("parse ok:", bool(p["ok"]), "-> t=%s nonce=%s sig=%s" % (p["t"], p["nonce"], p["sig"][:16] + "..."))
print("HMAC recompute == given:", bool(G._hmac_ok))
q_ok = bool(G._q_ok) and bool(G._q_diff) and bool(G._q2_ok)
print("bare-? uri normalize:", repr(str(G._q_raw)), "->", repr(str(G._q_norm)), "->",
      "OK" if q_ok else "FAIL")
print("  signed uri without '?' differs from raw (would fix sign-invalid):", bool(G._q_diff))
print("  real query url untouched:", repr(str(G._q2)), "->", "OK" if G._q2_ok else "FAIL")
rl = {
    ("relink: 同秒内同请求放行"): bool(G._rl_same),
    ("relink: 3s 后判真重放"): not bool(G._rl_older),
    ("relink: URL 不同判真重放"): not bool(G._rl_uri),
    ("relink: 方法不同判真重放"): not bool(G._rl_meth),
    ("relink: 坏格式判真重放"): not bool(G._rl_bad),
}
for name, res in rl.items():
    print(("OK  " if res else "FAIL") + " " + name)
ok = bool(G._hmac_ok) and bool(p["ok"]) and q_ok and all(rl.values())
print("ALL PASS" if ok else "SOME FAILED")
sys.exit(0 if ok else 1)
