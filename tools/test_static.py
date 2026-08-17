# -*- coding: utf-8 -*-
# is_static 分类逻辑验证(与 ma_rfw.lua 一致)
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "lupa"))
from lupa.luajit21 import LuaRuntime
L = LuaRuntime()
L.execute("""
static_ext = {
    ".html", ".htm", ".js", ".css",
    ".png", ".jpg", ".jpeg", ".gif", ".svg", ".webp", ".bmp", ".ico",
    ".woff", ".woff2", ".ttf", ".eot", ".map", ".pdf",
}
local function is_static(m, u, signed)
    if m ~= "GET" and m ~= "HEAD" then return false end
    if signed then return false end
    local ext = u:match("(%.[%w]+)$")
    if ext then
        ext = ext:lower()
        for _, e in ipairs(static_ext) do
            if ext == e then return true end
        end
    end
    return false
end
cases = {
    -- {method, uri, signed, expect_static}
    { "POST", "/api/localCheck/authority", false, false },
    { "GET",  "/api/list", false, false },
    { "GET",  "/api/config", false, false },
    { "GET",  "/files/report.pdf", false, true },
    { "GET",  "/files/report.pdf", true,  false },  -- 签名下载仍按动态严格校验
    { "GET",  "/js/app.js", false, true },
    { "GET",  "/static/css/style.css", false, true },
    { "GET",  "/images/logo.png", false, true },
    { "GET",  "/favicon.ico", false, true },
    { "GET",  "/index.html", false, true },
    { "GET",  "/some/page", false, false },
    { "GET",  "/api/data.json", false, false },
    { "POST", "/js/app.js", false, false },
    { "HEAD", "/style.css", false, true },
    { "GET",  "/", false, false },
    -- Vue 场景: 静态 html 模板(一页 5-10 个)全部应判静态
    { "GET",  "/templates/user.html", false, true },
    { "GET",  "/static/tpl/component.html", false, true },
    { "GET",  "/views/order/detail.html", false, true },
    { "GET",  "/templates/header.html", false, true },  -- ngx.var.uri 不含 ?v=2
    -- Vue history 路由跳转(无扩展名, 非 api 前缀): 按动态处理(参与比例, 靠 0.5 容差)
    { "GET",  "/order/list", false, false },
    { "GET",  "/cust/query", false, false },
    -- fetch 拉取的 .json 数据接口: 动态(受保护); 静态前缀下的图片不再被算成动态
    { "GET",  "/api/data.json", false, false },
    { "GET",  "/static/img/logo.png", false, true },
    { "GET",  "/static/css/app.css", false, true },
    { "GET",  "/static/css/app.css", true,  false },
}
results = {}
for i, c in ipairs(cases) do
    results[i] = (is_static(c[1], c[2], c[3]) == c[4])
end
""")
G = L.globals()
ok = True
for i in range(1, len(G.cases) + 1):
    c = G.cases[i]
    res = bool(G.results[i])
    mark = "OK " if res else "FAIL"
    if not res: ok = False
    print(f"{mark} {c[1]:<5} {c[2]:<50} signed={c[3]} expect_static={c[4]}")
print("ALL PASS" if ok else "SOME FAILED")
sys.exit(0 if ok else 1)
