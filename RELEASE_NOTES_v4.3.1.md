# Replay Firewall v4.3.1 发布说明

## 发布结论

Replay Firewall v4.3.1 是面向灰度阶段的 **dynamic-only 高安全版本**。本版本不再兼容 static 密钥、旧 `secret`、旧三段式 Cookie 或客户端全局变量信任。默认要求复杂 WebApp 的异步和同步请求使用 RFWDATA 完成 dynamic Header Gate 校验；`dynamic_allow_cookie_fallback` 默认关闭，因此删除 RFWDATA 后不能凭 `_RFW` Cookie 绕过防火墙。

本版本使用真实 `ma_rfw.lua`、Lupa shared-dict mock、WebUI 回归、Node 前端 XHR 测试和真实生产 SAZ 会话回放完成验证。统一 Lua/SAZ/WebUI 回归为 **49/49 PASS、0 FAIL、0 SKIP**；Node 异步/同步 XHR 及恶意全局变量预置测试通过。SAZ 中解析到 225 个会话，动态替换后的生产序列回放 217 条请求，同时覆盖首页访问、60 分钟后浏览器重启、凭证删除攻击和固定字段拒绝。

## v4.3.1 主要变化

| 领域 | v4.3.1 行为 | 安全意义 |
|---|---|---|
| 运行模式 | `KEY_MODE` 在 Lua 代码头部固定为 `dynamic`；配置重新出现固定字段会直接报错 | 消除双模式和误配置路径 |
| Header Gate | dynamic API、Controller、`.do` 等请求默认要求 RFWDATA | 每个受保护请求绑定短期 dynamic key、请求体、URI、方法和 nonce |
| Cookie 策略 | `dynamic_allow_cookie_fallback=false`；无 RFWDATA 默认拒绝 | `_RFW` Cookie 不是 RFWDATA 的替代凭证 |
| Cookie fallback | 即使手工开启，也只允许已有有效 dynamic Cookie 的 GET/HEAD/OPTIONS | 同步读请求可兼容；写请求不能仅凭 Cookie 驱动 |
| Cookie 重放 | 安全方法同值最多 8 次；非安全方法使用 `cookie_replay_window` / `cookie_replay_max` | 不存在无限同值重放放行 |
| Cookie 格式 | 移除旧三段式 Cookie 和 static tag 兼容 | 不再接受旧版弱兼容格式 |
| 客户端全局变量 | 不读取 `window.__RFW_MODE__`、`window.__RFW_TOKEN__`；`window.__RFW__` 仅为只读诊断标记 | 页面脚本可被篡改时，不能改变服务端安全策略或注入 Token |
| 配置文件 | `config.json` 与 `config.json.example` 使用标准 JSON；使用 `__COMMENT_*` 中文备注字段，唯一固定选项移入代码头部 | 配置更短、更容易审计，运行时仍可正确解析 |
| WebUI | 中文优先；固定项不显示；路径字段改为回车添加标签；说明文字使用小字和鼠标悬停提示 | UI 与实际可编辑边界一致，避免误操作 |
| WebUI 日志 | 版本显示 v4.3.1；日志 API 和前端过滤 SNAP | 避免内部快照污染日志视图 |
| 发布配置 | ZIP 包含完整未脱敏运行 `config.json`、带 `__COMMENT_*` 备注字段的模板、源码、测试工具和报告 | 可直接审计和部署；包内不含生产抓包和运行日志 |

## 配置边界

下列策略已经直接写入 `ma_rfw.lua`，不再出现在 `config.json` 或 `/cgi-rfw/config` 页面：dynamic-only、RFWDATA 严格 Header Gate、签名校验启用、请求重放检测启用、IP/UA 绑定、`_RFW` Cookie 名称、Cookie Bootstrap、安全方法集合、文档重新引导开关、HMAC 标签长度、共享字典名称以及 static 扩展名表。若手工重新加入这些字段，运行时会拒绝启动，防止旧配置被静默解释成另一种安全策略。

`dynamic_allow_cookie_fallback` 不是 WebUI 配置项。它保留在标准 JSON 配置中，默认值为 `false`，只用于灰度期间确有必要的手工兼容。WebUI 保存其他配置时会保留这个手工值，但不会显示或生成它；WebUI 保存后会保留 `__COMMENT_*` 备注字段。

## Cookie fallback 的安全边界

> **结论：Cookie fallback 不是无限重放许可。默认关闭；即使显式开启，也不是“拿到 Cookie 后无限访问”。**

当 `dynamic_allow_cookie_fallback=true` 时，缺少 RFWDATA 的严格请求只有在同时满足以下条件时才会进入 Cookie 校验：请求必须是 GET、HEAD 或 OPTIONS；请求必须带有已有 `_RFW` Cookie；Cookie 必须使用当前 dynamic key 通过 HMAC 校验；Cookie 的时间戳、生命周期、IP/UA 绑定和会话序号必须有效；请求还要通过 Cookie 比例、失败计数和 IP 封禁链。POST、PUT、PATCH、DELETE 等写请求不允许走这条 Headerless Cookie 兜底链，必须携带 RFWDATA。

同一个合法 Cookie 的安全方法可以兼容页面初始化时的并发请求，但同一 SID、序号和时间戳组合最多允许 8 次。超过后返回 `cookie-replay`，计入失败链。非安全方法即使通过其他 Cookie 校验路径，也受 `cookie_replay_window` 和 `cookie_replay_max` 限制；配置中的 `cookie_replay_max=0` 不会变成无限值，而是被收紧到至少 1 次。Cookie 时间戳上限同样被限制在 1 至 3600 秒，Cookie 生命周期被限制在 60 至 604800 秒。

这意味着攻击者仅删除 RFWDATA 不能绕过 Header Gate；仅删除 `_RFW` 不能影响有效 RFWDATA；同时删除两者会被拒绝。攻击者若窃取一个合法 `_RFW`，最多只能在上述时效、绑定、方法、同值次数、比例和封禁约束内复用，且无法仅凭该 Cookie 发起写请求。Cookie fallback 仍不能替代 HTTPS、业务鉴权和账号权限控制。

## Dynamic-only 前端行为

同步 XHR 使用纯 JavaScript SHA-256/HMAC 路径，异步 XHR 使用 Promise 路径；两条路径都在发送前设置 RFWDATA。此前异步 Promise 中 `buf` 变量作用域错误导致签名失败后进入原始 `send()` 的问题已修复。若 dynamic key 尚未就绪或 body 无法同步序列化，在默认 RFWDATA-only profile 下直接拒绝；不会把未签名请求当作可信请求放行。

客户端的 `window.__RFW__` 只作为只读诊断标记，不能阻止脚本继续安装 Header Gate；`window.__RFW_MODE__` 与 `window.__RFW_TOKEN__` 不再被读取。最终安全判定只在服务端 Lua 校验链完成。

## WebUI 规范

配置页面统一采用中文优先的标签。字段下方使用小字说明，关键说明附带鼠标悬停提示。动态文档精确路径和严格 API 路径均采用与管理员白名单相同的交互：输入一项后按回车添加为标签，点击标签删除；不再要求用户手动维护逗号分隔字符串。`Cookie` 在页面、发布说明和安全报告中统一首字母大写。

配置页面不再显示唯一选项或不可编辑字段，例如密钥模式、严格签名开关、动态 Cookie 标签长度、Cookie 名称、Cookie Bootstrap、安全方法、重放检测开关和 `dynamic_allow_cookie_fallback`。固定策略由代码负责，页面只展示真正可调整的生命周期、限额、路径、重放阈值、封禁和管理员访问参数。

## 推荐配置

正式运行应以包内完整 `config.json` 为准。该文件是标准 JSON；以 `__COMMENT_*` 开头的字段是中文备注，RFW、WebUI 和测试工具会在载入后忽略这些备注，并使用 2 个空格缩进保存。核心片段如下：

```json
{
  "__COMMENT_COOKIE_FALLBACK": "Cookie fallback 只在确有同步读请求兼容需求时手工开启。",
  "dynamic_allow_cookie_fallback": false,
  "dynamic_document_paths": ["/", "/portal-web/"],
  "strict_api_paths": [],
  "cookie_replay_window": 2,
  "cookie_replay_max": 5,
  "cookie_document_require_fetch_metadata": false,
  "debug": false
}
```

`dynamic_document_paths` 只能列出确定返回 HTML 的精确入口，例如 `/portal-web/`，不能覆盖整个 API 前缀。Controller、`.do`、`/api/` 和其他应用接口仍按 dynamic Header Gate 处理。`cookie_document_require_fetch_metadata=false` 只表示兼容不发送 Fetch Metadata 的合法首页客户端，不会让 API 请求凭文档头放行。

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
  --json-out /tmp/rfw_v4_3_1_hardened_test.json \
  --md-out /tmp/rfw_v4_3_1_hardened_test.md
```

测试覆盖 dynamic RFWDATA 的篡改、过期、重放、错误 IP/UA、body/URI/method 绑定、删除 `_RFW`、删除 RFWDATA、同时删除两者、默认 RFWDATA-only 拒绝、Cookie HMAC/过期/序列/有限并发安全方法、显式 fallback 安全方法限制、低签名比例拒绝、固定字段拒绝、旧 Cookie 拒绝、标准 JSON 备注字段读取、WebUI 配置保存、路径标签 UI、v4.3.1 版本、SNAP 过滤、生产 SAZ 序列、60 分钟浏览器重启和性能基线。

统一 Lua/SAZ/WebUI 回归为 **49/49 PASS、0 FAIL、0 SKIP**。Node 测试额外验证异步和同步 XHR 均设置 RFWDATA，并预置恶意 `__RFW_MODE__=static`、`__RFW_TOKEN__` 和 `__RFW__` 后仍生成有效 RFWDATA。性能数字仅用于本地相对回归比较，不代表生产 QPS；生产环境必须保持 `lua_code_cache on`，并按并发量评估 `lua_shared_dict rfw` 容量。

## 安全与迁移说明

v4.3.1 是破坏性灰度升级，不提供 static/legacy 兼容迁移。部署前应确保实际加载的 `rfw.js`、`ma_rfw.lua`、`webui.lua` 和标准 JSON `config.json` 来自同一发布包，并确认 `/cgi-rfw/token` 与 `/cgi-rfw/rfw.min.js` 的 location 不被应用 API strict 规则误拦截。完成切换后，旧 static secret、旧 Cookie 和三段式 Cookie 不再可用；如 dynamic key 已泄露，应重启或轮换 dynamic key record。

WebUI 页面版本应显示 `MA-RFW v4.3.1`。日志查看 API 和前端渲染器均过滤内部 SNAP 快照，但原始日志文件仍可保留 SNAP 供内部统计。发布包同时包含完整运行 `config.json`、带 `__COMMENT_*` 备注字段的模板、源代码、测试工具和测试报告，不包含 `.saz`、`.log` 或 `rfw_stats.json`。

> 本发布说明和测试报告只描述 RFW 层的 ALLOW/DENY；ALLOW 不等于后端业务授权成功，也不能替代 HTTPS、业务鉴权、权限控制或独立渗透测试。
