# Replay Firewall v4.3.0 发布说明

## 发布结论

Replay Firewall v4.3.0 是面向灰度阶段的 **dynamic-only 高安全版本**。本版本不再兼容 static 密钥、旧 secret、旧三段式 Cookie 或客户端全局变量信任；默认要求复杂 WebApp 的异步和同步请求使用 RFWDATA 完成 dynamic Header Gate 校验。`dynamic_allow_cookie_fallback` 默认关闭，因此删除 RFWDATA 后不能凭 `_RFW` Cookie 绕过防火墙。

本版本使用真实 `ma_rfw.lua`、Lupa shared-dict mock、WebUI 测试、Node 前端 XHR 测试和真实生产 SAZ 会话回放完成回归：统一 Lua/SAZ/WebUI 回归 **47/47 PASS、0 FAIL、0 SKIP**；Node 异步/同步 XHR 及恶意全局变量预置测试通过。SAZ 中解析到 225 个会话，其中动态替换后的生产序列回放 217 条请求；同时覆盖首页访问、60 分钟后浏览器重启、凭证删除攻击和 static 配置拒绝。

## v4.3.0 主要变化

| 领域 | v4.3.0 行为 | 安全意义 |
|---|---|---|
| 运行模式 | `KEY_MODE` 在 Lua 中固定为 `dynamic`；配置声明 static 会直接拒绝 | 消除双模式和误配置路径 |
| Header Gate | dynamic API、Controller、`.do` 等请求默认要求 RFWDATA | 每个受保护请求绑定短期 dynamic key、请求体、URI、方法和 nonce |
| Cookie 策略 | `dynamic_allow_cookie_fallback=false`；无 RFWDATA 默认拒绝 | `_RFW` 不是 RFWDATA 的替代凭证 |
| Cookie 格式 | 移除旧三段式 Cookie 和 static 16 hex tag 兼容 | 不再接受旧版弱兼容格式 |
| 客户端全局变量 | 不读取 `window.__RFW_MODE__`、`window.__RFW_TOKEN__`；`window.__RFW__` 仅为只读诊断标记 | 页面脚本可被篡改时，不能改变服务端安全策略或注入 Token |
| WebUI | 版本显示 v4.3.0；配置保存 API 强制 dynamic-only；日志查看 API 和前端过滤 SNAP | 防止管理面重新启用 static/legacy，并避免内部快照污染日志视图 |
| 发布配置 | ZIP 包包含完整未脱敏 `config.json` 和脱敏 `config.json.example` | 按用户要求交付可直接审计的完整运行配置 |

## Dynamic-only 安全边界

服务端依次执行 dynamic key record、时间窗口、IP/UA 绑定、请求体哈希、HMAC 常量时间比较以及 nonce/replay 检查。请求方法、URI、body 或绑定信息任意改变都会使 RFWDATA 失效。客户端产生的任何全局变量都不构成安全信任边界，最终判定只在服务端 Lua 校验链完成。

同步 XHR 使用纯 JavaScript SHA-256/HMAC 路径，异步 XHR 使用 Promise 路径；两条路径都在发送前设置 RFWDATA。此前异步 Promise 中 `buf` 变量作用域错误导致签名失败后进入原始 `send()` 的问题已修复。若 key 尚未就绪或 body 无法同步序列化，在默认 RFWDATA-only profile 下直接拒绝；只有管理员显式改变兼容配置时才会出现 Cookie fallback。

## Cookie 与删除凭证行为

| 场景 | v4.3.0 预期行为 |
|---|---|
| 有效 RFWDATA，删除 `_RFW` | 允许；Header 是主凭证，Cookie 不是必需凭证 |
| 删除 RFWDATA，保留有效 `_RFW` | 默认拒绝；返回 dynamic-sign-missing 或对应 strict gate 原因 |
| 同时删除 RFWDATA 与 `_RFW` | 拒绝 |
| 伪造 `Sec-Fetch-Dest: document` 访问 Controller/`.do` | 仍要求 dynamic 凭证，不因文档头放行 |
| 旧 static Cookie、旧 secret 或旧三段式 Cookie | 拒绝 |
| 文档 GET/HEAD | 仅按精确文档路径或 Nginx 显式文档变量处理，不以 MIME 作为 access 放行条件 |
| HTML 响应 Cookie 刷新 | 仅在 access 允许、响应成功且 `Content-Type` 为 HTML 时写入；JSON、JS、图片和错误页不写入 |

`_RFW` Cookie 仍可用于 dynamic Cookie 校验和在显式配置下的兼容例外，但默认 profile 不允许它替代 RFWDATA。即使暂时开启 fallback，也必须通过 dynamic Cookie 的 HMAC、时效、序列、IP/UA 绑定和重放检查；该例外应设置明确期限并持续观察 `signed_ok` 与 `cookie_ok` 比例。

## 推荐运行配置

正式运行应以包内完整 `config.json` 为准。配置模板只用于脱敏部署和审计，v4.3.0 不再保留 static/legacy 开关字段。

```json
{
  "key_mode": "dynamic",
  "dynamic_strict_sign": true,
  "dynamic_sign_ratio_fail": true,
  "dynamic_allow_cookie_fallback": false,
  "cookie_document_require_fetch_metadata": false,
  "debug": false
}
```

`dynamic_document_paths` 必须只列出确定返回 HTML 文档的精确入口，例如 `/portal-web/`，不能覆盖整个 API 前缀。Controller、`.do`、`/api/` 和其他应用接口仍按 dynamic Header Gate 处理。`cookie_document_require_fetch_metadata=false` 只表示兼容不发送 Fetch Metadata 的合法首页客户端，不会让 API 请求凭文档头放行。

## 推荐 Nginx 部署

仓库中的 `nginx.conf.recommended` 提供完整示例。对于已知首页，可以使用 exact location 设置 `$rfw_document`，而不是在整个应用前缀上标记文档：

```nginx
location = /portal-web/ {
    set $rfw_document 1;
    access_by_lua_file /path/to/replayfirewall/ma_rfw.lua;
    header_filter_by_lua_block {
        local m = _G.ma_rfw_core
        if m and m.header_filter then m.header_filter() end
    }
    proxy_pass http://127.0.0.1:18081;
}

location /portal-web/ {
    access_by_lua_file /path/to/replayfirewall/ma_rfw.lua;
    header_filter_by_lua_block {
        local m = _G.ma_rfw_core
        if m and m.header_filter then m.header_filter() end
    }
    proxy_pass http://127.0.0.1:18081;
}
```

新增文档入口时，应同步更新 `dynamic_document_paths` 和 exact location。不要把 `/portal-web/` 的前缀 location 整体设置为文档入口，否则可能把 API 和 Controller 路径误标为文档。

## 测试与性能

统一回归入口如下：

```bash
python3 -m py_compile tools/rfw_v4_test.py
node --check rfw.js
node tools/test_rfw_js_xhr.js
python3 tools/rfw_v4_test.py \
  --config config.json \
  --saz /path/to/prod.saz \
  --json-out /tmp/rfw_v4_hardened_test.json \
  --md-out /tmp/rfw_v4_hardened_test.md
```

测试覆盖 dynamic RFWDATA 的篡改、过期、重放、错误 IP/UA、body/URI/method 绑定、删除 `_RFW`、删除 RFWDATA、同时删除两者、默认 RFWDATA-only 拒绝、Cookie HMAC/过期/序列/并发安全 GET、显式 fallback 隔离、低签名比例拒绝、static 配置拒绝、旧 Cookie 拒绝、WebUI 配置保存、v4.3.0 版本、SNAP 过滤、生产 SAZ 序列、60 分钟浏览器重启和性能基线。

统一 Lua/SAZ/WebUI 回归为 **47/47 PASS、0 FAIL、0 SKIP**。Node 测试额外验证异步和同步 XHR 均设置 RFWDATA，并预置恶意 `__RFW_MODE__=static`、`__RFW_TOKEN__` 和 `__RFW__` 后仍生成有效 RFWDATA。性能数字仅用于本地相对回归比较，不代表生产 QPS；生产环境必须保持 `lua_code_cache on`，并按并发量评估 `lua_shared_dict rfw` 容量。

## 安全与迁移说明

v4.3.0 是破坏性灰度升级，不提供 static/legacy 兼容迁移。部署前应确保实际加载的 `rfw.js`、`ma_rfw.lua`、`webui.lua` 和 `config.json` 来自同一发布包，并确认 `/cgi-rfw/token` 与 `/cgi-rfw/rfw.min.js` 的 location 不被应用 API strict 规则误拦截。完成切换后，旧 static secret、旧 Cookie 和三段式 Cookie 不再可用；如 dynamic key 已泄露，应重启或轮换 dynamic key record。

WebUI 页面版本应显示 `MA-RFW v4.3.0`。日志查看 API 和前端渲染器均过滤内部 `SNAP` 快照，但原始日志文件仍可保留 SNAP 供内部统计。发布包同时包含完整运行 `config.json`、脱敏模板、源代码、测试工具和测试报告，不包含 `.saz`、`.log` 或 `rfw_stats.json`。

> 本发布说明和测试报告只描述 RFW 层的 ALLOW/DENY；ALLOW 不等于后端业务授权成功，也不能替代 HTTPS、业务鉴权、权限控制或独立渗透测试。
