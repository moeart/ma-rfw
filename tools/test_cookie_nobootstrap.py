# -*- coding: utf-8 -*-
# cookie_bootstrap=false(纯 JS 源)模式: 服务器零下发 Set-Cookie; 无 cookie 请求
# 只靠无 cookie 配额兜底(本测试 cookie_missing_max=3), 超限直接封禁。
# 用法: python tools/test_cookie_nobootstrap.py
import sys, os, shutil
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "lupa"))
from lupa.luajit21 import LuaRuntime
L = LuaRuntime()
base = os.path.dirname(os.path.dirname(os.path.abspath(__file__))).replace("\\", "/")
tmp = os.environ.get("TEMP", base + "/tools").replace("\\", "/") + "/rfw_test_noboot"
shutil.rmtree(tmp, ignore_errors=True)

L.execute('''
ngx = {}
ngx.HTTP_OK = 200
ngx.HTTP_FORBIDDEN = 403
ngx.ERR = 0
_logs = {}
ngx.log = function(lvl, msg) _logs[#_logs + 1] = tostring(msg) end
_now = 1786845452
ngx.now = function() return _now + 0.123 end
ngx.time = function() return _now end
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
_ngx_var["rfw_on"] = "1"
ngx.var = _ngx_var

-- ngx.shared.DICT mock: 模拟带 TTL 的共享内存
local _sd = {}
ngx.shared = {
    rfw = {
        get = function(_, k)
            local e = _sd[k]
            if not e then return nil end
            if e.exp and _now > e.exp then _sd[k] = nil; return nil end
            return e.val, 0
        end,
        set = function(_, k, v, ttl)
            _sd[k] = { val = v, exp = ttl and (_now + ttl) }
            return true, nil
        end,
        add = function(_, k, v, ttl)
            local e = _sd[k]
            if e and (not e.exp or _now <= e.exp) then return false, "exists" end
            _sd[k] = { val = v, exp = ttl and (_now + ttl) }
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
        _TEST_SECRET = cfg.secret
        cfg.sign_ratio_min = 0
        cfg.cookie_ratio_min = 0
        cfg.debug = true
        cfg.cookie_bootstrap = false  -- 纯 JS 源, 服务器零下发
        cfg.cookie_missing_max = 3    -- 收紧配额便于测试
        return cfg
    end
    return _orig_dofile(p)
end

_ngx_var["uri"] = "/api/test"
dofile("''' + base + '''/ma_rfw.lua")
core = _G.ma_rfw_core

local function run_once(cookie)
    _says = {}
    _exit_code = nil
    ngx.header = {}
    ngx.ctx = {}
    if cookie then _ngx_var["http_cookie"] = "_RFW=" .. cookie else _ngx_var["http_cookie"] = nil end
    core.run()
    return _exit_code, table.concat(_says), ngx.header["Set-Cookie"]
end

_ngx_var["remote_addr"] = "9.9.9.9"

-- 1) 无 cookie → 放行且不下发任何 Set-Cookie
_e1, _h1, _sc1 = run_once(nil)

-- 2) 继续无 cookie ×2 → 配额 3 未超, 放行且仍无 Set-Cookie
_e2, _, _sc2 = run_once(nil)
_e3, _, _sc3 = run_once(nil)

-- 3) 第 4 个无 cookie 请求 → 配额超限 → 403 cookie-missing-ban
_e4, _h4 = run_once(nil)

-- 4) 后续请求因封禁 → 403 blocked
_e5, _h5 = run_once(nil)

-- 5) 状态页应显示该封禁 IP 与原因(block_log 由 set_block 注册, 经 run() 传入 status.render)
_ngx_var["uri"] = "/cgi-rfw/status"
_says = {}; _exit_code = nil; ngx.header = {}; ngx.ctx = {}
core.run()
_e_status = _exit_code
_h_status = table.concat(_says)
_ngx_var["uri"] = "/api/test"
''')

G = L.globals()
pass_ok = G._e1 is None and G._e2 is None and G._e3 is None
no_sc = G._sc1 is None and G._sc2 is None and G._sc3 is None
quota_denied = G._e4 == 403 and "cookie-missing-ban" in G._h4
blocked_after = G._e5 == 403 and "blocked" in G._h5
status_shows_block = G._e_status == 200 and "9.9.9.9" in G._h_status and "cookie-missing-quota" in G._h_status and "封禁中" in G._h_status

checks = [
    ("无 cookie 请求放行(纯 JS 源零下发)"), pass_ok,
    ("任何请求都不回发 Set-Cookie"), no_sc,
    ("第4个无 cookie 请求 403(配额超限)"), quota_denied,
    ("配额封禁后 403(blocked)"), blocked_after,
    ("状态页显示封禁 IP/原因/状态"), status_shows_block,
]
ok = True
for i in range(0, len(checks), 2):
    name, res = checks[i], checks[i + 1]
    print(("OK  " if res else "FAIL") + " " + name)
    if not res: ok = False
print("ALL PASS" if ok else "SOME FAILED")
sys.exit(0 if ok else 1)
