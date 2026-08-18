# -*- coding: utf-8 -*-
# 模块加载 + run() 冒烟测试: 在 lupa(LuaJIT2.1)里 stub ngx, dofile 主插件,
# 验证模块能完整加载、状态页路由生效、且无前向引用泄漏到全局(捕获 Lua 作用域错误)。
# 用法: python tools/test_load.py
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
ngx.log = function(lvl, msg) end
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
setmetatable(_ngx_var, { __index = function() return "" end })
_ngx_var["rfw_on"] = "1"  -- 主插件 run() 内部有 $rfw_on 门, 正常流程需打标记
ngx.var = _ngx_var

-- ngx.shared.DICT mock(空表 → store=nil → deny("backend-unreachable") → 403)
ngx.shared = {}

-- 插件目录已改为按本文件位置自动推导(不硬编码), 测试直接 dofile 本仓库即可;
-- 保留 dofile 重定向钩子以兼容服务器路径写法(现在不会命中, 无害)
_LOCAL_BASE = "''' + base + '''"
_orig_dofile = dofile
function dofile(path)
    local p = string.gsub(path, "^.*[/\\]replayfirewall", _LOCAL_BASE)
    return _orig_dofile(p)
end

-- 加载主插件(相当于 nginx 首个请求: 执行顶层代码 + _M.run())
-- 插件本身不 return 模块(靠 _G.ma_rfw_core 缓存), dofile 返回 nil
dofile("''' + base + '''/ma_rfw.lua")
core = _G.ma_rfw_core
_core_loaded = (type(core) == "table" and type(core.run) == "function")

-- 状态页路由: uri=/cgi-rfw/status
_ngx_var["uri"] = "/cgi-rfw/status"
_says = {}
_exit_code = nil
core.run()
_status_exit = _exit_code
_status_html = table.concat(_says)

-- 普通请求: 后端不可达 → 403
_ngx_var["uri"] = "/api/list"
_says = {}
_exit_code = nil
core.run()
_deny_exit = _exit_code
_deny_html = table.concat(_says)

-- run() 内部 $rfw_on 门: 未打标记 → 跳过(exit=nil)
_ngx_var["rfw_on"] = ""
_ngx_var["uri"] = "/api/list"
_says = {}
_exit_code = nil
core.run()
_gate_skip_exit = _exit_code
_ngx_var["rfw_on"] = "1"
''')

G = L.globals()
allowed = {
    "print", "assert", "error", "ipairs", "pairs", "next", "tostring", "tonumber",
    "type", "select", "rawget", "rawset", "setmetatable", "getmetatable",
    "unpack", "require", "package", "string", "table", "math", "io", "os", "pcall",
    "xpcall", "coroutine", "bit", "jit", "dofile", "loadfile", "load", "loadstring",
    "gcinfo", "collectgarbage", "newproxy", "module", "ngx", "arg", "_VERSION",
    "utf8", "ma_rfw_core", "core", "_LOCAL_BASE", "_orig_dofile", "_ngx_var",
    "_says", "_exit_code", "_status_exit", "_status_html", "_deny_exit", "_core_loaded",
    "_deny_html", "_gate_skip_exit",
    # lupa 运行库自带的全局
    "_G", "debug", "getfenv", "python", "rawequal", "setfenv",
}
leaks = [k for k in G.keys() if k not in allowed]

checks = {
    ("模块加载成功"): bool(G["_core_loaded"]),
    ("状态页路由 exit=200"): int(G["_status_exit"]) == 200,
    ("状态页含标题"): ("MA-RFW Status" in G["_status_html"]),
    ("后端不可达 deny=403"): int(G["_deny_exit"]) == 403,
    ("deny 页面附 debug 面板(debug=true)"): ("rfw-debug" in G["_deny_html"]),
    ("debug 面板样式内嵌 HTML(<style>)"): ("#rfw-debug" in G["_deny_html"]),
    ("debug 面板注入到 <body> 内(位于 </body> 之前)"):
        (G["_deny_html"].rfind("rfw-debug") < G["_deny_html"].rfind("</body>")),
    ("run() 内 $rfw_on 门: 未打标记跳过(exit=nil)"): G["_gate_skip_exit"] is None,
    ("无全局作用域泄漏(前向引用)"): len(leaks) == 0,
}
ok = True
for name, res in checks.items():
    print(("OK  " if res else "FAIL") + " " + name)
    if not res: ok = False
if leaks:
    print("  leaked globals:", sorted(leaks))
print("ALL PASS" if ok else "SOME FAILED")
sys.exit(0 if ok else 1)
