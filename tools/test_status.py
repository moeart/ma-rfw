# -*- coding: utf-8 -*-
# status.lua 状态页冒烟测试: 在 lupa(LuaJIT2.1)里 stub ngx, 验证 render 能产出 HTML 表格。
# 用法: python tools/test_status.py
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "lupa"))
from lupa.luajit21 import LuaRuntime
L = LuaRuntime()
base = os.path.dirname(os.path.dirname(os.path.abspath(__file__))).replace("\\", "/")

L.execute('''
-- ---- stub ngx(与 nginx 内行为一致的最小实现) ----
ngx = {}
ngx.HTTP_OK = 200
ngx.time = function() return 1786845452 end
ngx.worker = {}
ngx.worker.pid = function() return 1234 end
ngx.worker.count = function() return 8 end
ngx.header = {}
ngx.say = function(s) _says[#_says + 1] = s end
ngx.exit = function(code) _exit_code = code end
_says = {}
_exit_code = nil

-- ---- 加载 status.lua ----
status = dofile("''' + base + '''/status.lua")

-- ---- 造一组计数 ----
config = {
    sweep_interval = 60,
    status_enabled = true,
    status_path = "/cgi-rfw/status",
    version = "3.0.0",
}
stats = {
    start_ts = 1786830000,
    requests = 12345, prev_requests = 0, last_rate = 42.5,
    signed_ok = 10000, cookie_ok = 2000, cookie_issued = 300,
    cookie_stale = 50, no_cookie_tracked = 100, cookie_missing = 10,
    cookie_replay = 5,
    static_ok = 7000, blocked_hit = 12, failures = 88, blocks = 3,
    backend_fail = 0, track_ips = 137, block_cache_size = 55,
    seq_cache_size = 44,
    denied = { ["sign-expired"] = 10, ["sign-invalid"] = 5, blocked = 12 },
}
sd_config = { dict_name = "rfw", key_prefix = "rfw:" }
block_log = {
    ["1.2.3.4"] = { unblock = 1786845452 + 600, ban = 1786844852, reason = "cookie-replay" },
    ["5.6.7.8"] = { unblock = 1786845452 - 100, ban = 1786844852, reason = "cookie-missing-quota" },
}

status.render(config, stats, nil, sd_config, block_log)
html = table.concat(_says)
_has_title  = html:find("MA-RFW Status", 1, true) ~= nil
_has_table  = html:find("<table>") ~= nil
_has_count  = html:find("12345", 1, true) ~= nil
_has_rate   = html:find("42.5", 1, true) ~= nil
_has_reason = html:find("sign-expired", 1, true) ~= nil
_has_version = html:find("3.0.0", 1, true) ~= nil
_has_blocks = html:find("封禁次数", 1, true) ~= nil
_has_blocksec = html:find("封禁 IP", 1, true) ~= nil
_has_block_ip = html:find("1.2.3.4", 1, true) ~= nil
_has_block_ban = html:find("2026-08-16 09:47:32", 1, true) ~= nil  -- ban 时间(os.date)
_has_block_reason = html:find("cookie-replay", 1, true) ~= nil
_has_unblocked = html:find("已解封", 1, true) ~= nil
_has_dict_info = html:find("lua_shared_dict", 1, true) ~= nil
_exit_200   = (_exit_code == 200)
_exit_code = nil
_says = {}
''')
G = L.globals()
checks = {
    ("标题"): bool(G._has_title),
    ("版本号"): bool(G._has_version),
    ("封禁次数统计"): bool(G._has_blocks),
    ("封禁 IP 区块"): bool(G._has_blocksec),
    ("封禁 IP 显示"): bool(G._has_block_ip),
    ("封禁时间显示"): bool(G._has_block_ban),
    ("封禁原因显示"): bool(G._has_block_reason),
    ("已解封状态显示"): bool(G._has_unblocked),
    ("表格存在"): bool(G._has_table),
    ("请求计数"): bool(G._has_count),
    ("速率"): bool(G._has_rate),
    ("拒绝原因"): bool(G._has_reason),
    ("后端显示 shared_dict"): bool(G._has_dict_info),
    ("exit=200"): bool(G._exit_200),
}
ok = True
for name, res in checks.items():
    print(("OK  " if res else "FAIL") + " " + name)
    if not res: ok = False
print("ALL PASS" if ok else "SOME FAILED")
sys.exit(0 if ok else 1)
