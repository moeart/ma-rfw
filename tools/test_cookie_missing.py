# -*- coding: utf-8 -*-
# 无 cookie 日配额测试: _RFW 是持久 cookie, 正常浏览器一天只有首次访问缺它;
# 某 IP 一天内无 cookie 请求超过 cookie_missing_max(默认 50) → 直接封禁,
# 第 51 个无 cookie 请求应 403(cookie-missing-ban), 其后请求因封禁 403。
# 用法: python tools/test_cookie_missing.py
import sys, os, shutil
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "lupa"))
from lupa.luajit21 import LuaRuntime
L = LuaRuntime()
base = os.path.dirname(os.path.dirname(os.path.abspath(__file__))).replace("\\", "/")
tmp = os.environ.get("TEMP", base + "/tools").replace("\\", "/") + "/rfw_test_missing"
shutil.rmtree(tmp, ignore_errors=True)  # 清掉上次运行残留的计数/封禁文件, 保证幂等

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

-- ngx.shared.DICT mock: 模拟带 TTL 的共享内存
local _sd = {}
ngx.shared = {
    rfw = {
        get = function(_, k)
            local e = _sd[k]
            if not e then return nil end
            if e.exp and 1786845452 > e.exp then _sd[k] = nil; return nil end
            return e.val, 0
        end,
        set = function(_, k, v, ttl)
            _sd[k] = { val = v, exp = ttl and (1786845452 + ttl) }
            return true, nil
        end,
        add = function(_, k, v, ttl)
            local e = _sd[k]
            if e and (not e.exp or 1786845452 <= e.exp) then return false, "exists" end
            _sd[k] = { val = v, exp = ttl and (1786845452 + ttl) }
            return true, nil
        end,
        delete = function(_, k)
            _sd[k] = nil
            return true
        end,
    }
}

_LOCAL_BASE = "''' + base + '''"
_orig_dofile = dofile
function dofile(path)
    local p = string.gsub(path, "^.*[/\\]replayfirewall", _LOCAL_BASE)
    if string.match(p, "config%.lua$") then
        local cfg = _orig_dofile(p)
        cfg.sign_ratio_min = 0    -- 隔离本测试: 关闭签名比例判定
        cfg.cookie_ratio_min = 0  -- 隔离本测试: 关闭 cookie 覆盖率判定
        cfg.debug = true
        return cfg
    end
    return _orig_dofile(p)
end

_ngx_var["uri"] = "/api/miss"
dofile("''' + base + '''/ma_rfw.lua")
core = _G.ma_rfw_core

-- 同一 IP 连续 55 个无 cookie 请求: 前 50 个放行, 第 51 个起 403
_ngx_var["remote_addr"] = "9.9.9.9"
_exits = {}
_ban_html = ""
for i = 1, 55 do
    _says = {}
    _exit_code = nil
    ngx.ctx = {}
    core.run()
    _exits[i] = _exit_code
    if i == 51 then _ban_html = table.concat(_says) end
end

-- 其它 IP 不受影响(1 个无 cookie 请求正常放行)
_ngx_var["remote_addr"] = "8.8.8.8"
_says = {}
_exit_code = nil
ngx.ctx = {}
core.run()
_other_exit = _exit_code
''')

G = L.globals()
exits = [G._exits[i] for i in range(1, 56)]
first50_ok = all(e is None for e in exits[0:50])
deny_at_51 = exits[50] == 403
after_51_ok = all(e == 403 for e in exits[51:55])
has_reason = "cookie-missing-ban" in G._ban_html
other_ok = G._other_exit is None

checks = [
    ("前 50 个无 cookie 请求放行(exit=nil)"), first50_ok,
    ("第 51 个请求 403(cookie-missing-ban)"), deny_at_51,
    ("403 页面含拒绝原因 cookie-missing-ban"), has_reason,
    ("第 52~55 个请求因封禁 403"), after_51_ok,
    ("其它 IP 不受影响(放行)"), other_ok,
]
ok = True
for i in range(0, len(checks), 2):
    name, res = checks[i], checks[i + 1]
    print(("OK  " if res else "FAIL") + " " + name)
    if not res: ok = False
print("ALL PASS" if ok else "SOME FAILED")
sys.exit(0 if ok else 1)
