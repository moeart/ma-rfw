# -*- coding: utf-8 -*-
# 全局插件模式测试(init.lua require + access.lua 单行 check() + run() 内 $rfw_on 标记门):
#   1) init 阶段 require 必须只做初始化, 不运行请求(无 ngx.var/ngx.ctx 副作用);
#   2) access.lua 只调 check(), 无任何过滤; $rfw_on 标记由 run() 内部判断:
#      未打标记的请求在 run() 内被跳过(零开销, 状态页除外);
#   3) 状态页独立放行(任意站点可访问)。
# 用法: python tools/test_global.py
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "lupa"))
from lupa.luajit21 import LuaRuntime
L = LuaRuntime()
base = os.path.dirname(os.path.dirname(os.path.abspath(__file__))).replace("\\", "/")

L.execute('''
-- ---- stub ngx ----
ngx = {}
ngx.HTTP_OK = 200
ngx.HTTP_FORBIDDEN = 403
ngx.ERR = 0
_logs = {}
ngx.log = function(lvl, msg) _logs[#_logs + 1] = tostring(msg) end
ngx.now = function() return 1786845452.123 end
ngx.time = function() return 1786845452 end
ngx.worker = { pid = function() return 7 end, count = function() return 8 end }
ngx.timer = { at = function(delay, f) return true end }
ngx.status = 0
ngx.header = {}
_phase = "init"
ngx.get_phase = function() return _phase end
ngx.ctx = {}
_says = {}
ngx.say = function(s) _says[#_says + 1] = tostring(s) end
_exit_code = nil
ngx.exit = function(code) _exit_code = code end
ngx.socket = { tcp = function() return nil, "no socket" end }
ngx.req = {
    read_body = function() end,
    get_body_data = function() return nil end,
    get_body_file = function() return nil end,
    get_method = function() return "GET" end,
    clear_header = function() end,
    set_header = function() end,
}
_ngx_var = {}
setmetatable(_ngx_var, { __index = function() return nil end })
_ngx_var["rfw_on"] = "1"  -- 主插件 run() 内部有 $rfw_on 门, 正常流程需打标记
ngx.var = _ngx_var

-- ngx.shared.DICT mock(空表 → store=nil → deny("backend-unreachable") → 403)
ngx.shared = {}

-- dofile 重定向钩子: 兼容服务器路径写法(现已按文件位置自动推导, 不会命中, 无害)
_LOCAL_BASE = "''' + base + '''"
_orig_dofile = dofile
function dofile(path)
    local p = string.gsub(path, "^D:/BtNginxLua/replayfirewall", _LOCAL_BASE)
    return _orig_dofile(p)
end

-- 模拟 init.lua: init 阶段 require(顶层初始化, 不运行请求)
package.path = "''' + base + '''/?.lua;" .. package.path
_phase = "init"
_mod = require("ma_rfw")
_mod_ok = (type(_mod) == "table" and type(_mod.run) == "function"
    and type(_mod.check) == "function" and type(_mod.on_log) == "function")
_init_exit = _exit_code   -- require 后应仍为 nil(没在 init 阶段跑请求)

-- 模拟 access.lua 已放行后的 check(): 一律进入 run()(后端不可达→403)
_phase = "access"
ngx.ctx = {}
_ngx_var["http_host"] = "app.example.com:8001"
_ngx_var["uri"] = "/api/list"
_ngx_var["remote_addr"] = "1.2.3.4"
_exit_code = nil
_ran_matched = _mod.check()
_matched_exit = _exit_code

-- 状态页 → 独立放行, exit=200
ngx.ctx = {}
_ngx_var["http_host"] = "app.example.com"
_ngx_var["uri"] = "/cgi-rfw/status"
_says = {}
_exit_code = nil
_ran_status = _mod.check()
_status_exit = _exit_code
_status_html = table.concat(_says)

-- 状态页任何站点都可访问(独立放行)
ngx.ctx = {}
_ngx_var["http_host"] = "www.example.com"
_ngx_var["uri"] = "/cgi-rfw/status"
_says = {}
_exit_code = nil
_ran_status2 = _mod.check()
_status2_exit = _exit_code

-- 模拟 access.lua.example(仅一行 check()): $rfw_on 标记由 run() 内部判断——
-- 未打标记 → 跳过(exit=nil), 打标记 → 执行(后端不可达 → 403)
ma_rfw = _mod
_ngx_var["http_host"] = "app.example.com"
_ngx_var["uri"] = "/api/list"
_ngx_var["remote_addr"] = "5.5.5.5"
_ngx_var["rfw_on"] = nil
ngx.ctx = {}
_exit_code = nil
dofile("''' + base + '''/access.lua.example")
_gate_skip_exit = _exit_code   -- 未标记 → 应保持 nil
_ngx_var["rfw_on"] = "1"
ngx.ctx = {}
_exit_code = nil
dofile("''' + base + '''/access.lua.example")
_gate_run_exit = _exit_code    -- 已标记 → 应 403
_ngx_var["rfw_on"] = ""
''')

G = L.globals()
checks = {
    ("init 阶段 require 返回完整模块(run/check/on_log)"): bool(G["_mod_ok"]),
    ("init 阶段 require 不运行请求(exit=nil)"): G["_init_exit"] is None,
    ("匹配站点+动态路径: check() 返回 true"): bool(G["_ran_matched"]),
    ("匹配站点请求被执行(后端不可达→403)"): int(G["_matched_exit"]) == 403,
    ("状态页独立放行 exit=200"): int(G["_status_exit"]) == 200,
    ("状态页任意站点可访问"): int(G["_status2_exit"]) == 200,
    ("$rfw_on 未标记: access.lua 跳过(exit=nil)"): G["_gate_skip_exit"] is None,
    ("$rfw_on=1: access.lua 执行(exit=403)"): int(G["_gate_run_exit"]) == 403,
}
ok = True
for name, res in checks.items():
    print(("OK  " if res else "FAIL") + " " + name)
    if not res: ok = False
print("ALL PASS" if ok else "SOME FAILED")
sys.exit(0 if ok else 1)
