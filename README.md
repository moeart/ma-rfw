# MA-RFW — MoeArt Replay Firewall v4.3.8

针对浏览器内嵌前端（非 SSR）的接口重放/伪造攻击防护。v4.3.8 重点修复复杂 WebApp 在后台停留半小时以上、多个同源 iframe 分别注入 `rfw.js` 后的 Token 恢复竞态：Token 获取失败或超时后，异步 XHR fail-closed，不会原样发送无签名请求。前端 `rfw.js` 对每个同源请求做 HMAC-SHA256 签名，nginx 侧 `ma_rfw.lua` 严格校验；无签名请求走行为兜底（Cookie 签名 + 会话序列号 + 相同请求指纹 + 覆盖率判定），支持按 IP 记失败并封禁。

## 特性

- HMAC-SHA256 请求签名（防篡改、防重放）
- 灰度版固定 `dynamic-only`（短时效密钥，IP+UA 绑定）；不再兼容 static 密钥
- 动态模式下 Cookie 使用动态密钥签名（非静态 secret）；Key 状态持久化到 `data/rfw_key_records.json`
- `_RFW` 动态 Cookie Token（rfw.js 定时刷新；同源上下文共享唯一刷新调度）
- 无签名请求行为分析（签名占比 + cookie 校验链）
- 相同请求指纹重放检测
- 按 IP 失败计数 → 自动封禁
- WebUI 管理面板（状态统计 / 配置 / 日志查看 + 动态密钥参数配置）；日志查看页和日志 API 默认隐藏内部 `SNAP` 快照行
- dynamic 文档使用显式 `dynamic_document_paths` 白名单，不依赖尾斜杠、Accept 或 `Sec-Fetch-Dest` 猜测
- upstream 响应的 `Content-Type` 仅在 `header_filter` 阶段确认是否发送待刷新的文档 Cookie，不参与 access 放行
- `/cgi-rfw/token` 端点（动态模式密钥发放，频率限制 + 配额控制；Nginx 重启后恢复持久化 Key）
- `/cgi-rfw/rfw.min.js` 端点（内存缓存，no-cache 头）
- 历史统计图表（拒绝趋势 + 请求量 + 原因分布）
- 零外部依赖（纯 Lua + ngx.shared.DICT）

> v4.3.8 灰度策略：运行时固定 `dynamic-only`，所有异步/同步 XHR 默认必须携带当前 MA-RFW-Data；在后台恢复、Token 超时或 Token 端点暂时失败时，业务请求 fail-closed，不会凭空 Header 发送。`dynamic_allow_cookie_fallback=false`，删除 MA-RFW-Data 后不能凭 `_RFW` Cookie 兜底。旧 static secret、旧 static Cookie 和三段式旧 Cookie 格式不再接受。客户端 `window.__RFW__`、`__RFW_MODE__` 和 `__RFW_TOKEN__` 不是安全信任边界；服务端 Header Gate 才是最终判定。

## 文件结构

| 文件 | 说明 |
| --- | --- |
| `webui.lua` | WebUI 单文件插件（状态页 / 配置页 / 日志页 + 所有 API + token 端点 + rfw.min.js 服务） |
| `ma_rfw.lua` | 主插件（访问阶段校验 + 动态密钥管理 + 后台清扫 + 日志） |
| `sha256.lua` | 纯 Lua SHA256 / HMAC-SHA256（零外部依赖） |
| `rfw.js` | 前端签名拦截器（覆盖 fetch 与 XMLHttpRequest，固定 dynamic-only） |
| `blocked.html` | 封禁/拒绝时返回的 403 页面 |
| `config.json` | 完整运行时配置（WebUI 可修改；发布包按灰度要求随包提供） |
| `config.json.example` | 配置模板（纳入 git） |
| `init.lua.example` | init 阶段加载示例（复制为 `init.lua`） |
| `access.lua.example` | access 阶段入口示例（复制为 `access.lua`） |
| `logs/` | 日志目录（自动创建，不纳入 git） |
| `data/` | 运行时 JSON 数据目录；目录保留但 `data/*.json` 不纳入 git |
| `tools/` | 语法检查、逻辑测试、HMAC 基准 |

## 依赖

- [OpenResty](https://openresty.org) ≥ 1.19+（LuaJIT 2.1+）
- `lua-cjson`（OpenResty 自带）

## 安装

### 1. 部署文件

```bash
cp -r replayfirewall /path/to/plugins/replayfirewall
cd /path/to/plugins/replayfirewall

cp config.json.example config.json
cp init.lua.example init.lua
cp access.lua.example access.lua
mkdir -p logs
```

### 2. 配置 nginx.conf

插件指令放在 `http` 块中（全局生效）：

```nginx
http {
    lua_package_path "/path/to/plugins/replayfirewall/?.lua;/path/to/plugins/moewaf/?.lua;;";
    lua_shared_dict rfw 64m;
    lua_code_cache on;

    init_by_lua_file /path/to/plugins/replayfirewall/init.lua;
    access_by_lua_file /path/to/plugins/replayfirewall/access.lua;
}
```

在要保护的 server/location 上启用 RFW 并注入前端签名脚本：

```nginx
server {
    listen 80;
    server_name example.com;

    # 启用 RFW（要保护的站点/路径打标记）
    set $rfw_on 1;

    # 外围系统无法注入 rfw.js 时，在 Nginx location 层隔离，统一由 $rfw_on 管理。
    # 将 /white_url 替换为实际精确路径或前缀；不要把它写入 config.json。
    location /white_url {
        set $rfw_on 0;
        proxy_pass http://127.0.0.1:8080;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_set_header Cookie $http_cookie;
        proxy_http_version 1.1;
        proxy_set_header Connection "";
    }

    # 前端页面注入 rfw.js。生产环境建议把实际文档入口拆成 exact location，
    # 并设置 $rfw_document 1；不要把它设置在整个 /webapp/ API 前缀上。
    location = /webapp/ {
        set $rfw_document 1;
        proxy_pass http://127.0.0.1:8080;
        proxy_set_header Host $host;
        sub_filter '</head>' '<script src="/rfw.js"></script></head>';
        sub_filter_once on;
    }

    location / {
        proxy_pass http://127.0.0.1:8080;
        proxy_set_header Host $host;
        sub_filter '</head>' '<script src="/rfw.js"></script></head>';
        sub_filter_once on;
    }

    # rfw.js 静态文件
    location = /rfw.js {
        alias /path/to/plugins/replayfirewall/rfw.js;
        add_header Cache-Control "public, max-age=31536000, immutable";
    }
}
```

> 注意：内部 `proxy_pass` 落点不要打 `set $rfw_on 1;`，否则同一请求会被处理两遍，第二遍 nonce 已消费 → 误判 `sign-replay`。
>
> 文档入口的 `$rfw_document 1` 应放在 `location = /webapp/`、`location = /` 等 exact location 中。若只配置 `dynamic_document_paths` 而不设置变量，也可以工作；变量适合作为 Nginx 路由已经确认该响应是文档时的显式标记。不要在 `location /webapp/` 这种前缀 location 上设置它，否则 API/Controller 可能被错误标记。
>
> 生产环境应使用 `lua_code_cache on;`。`off` 仅适合调试，会增加每请求的 Lua 编译和文件 I/O，并放大复杂 WebApp 首屏的时序抖动。

### 3. 验证 & 启动

```bash
nginx -t
nginx -s reload
```

### 4. 访问管理面板

浏览器打开 `http://your-server:80/cgi-rfw/status`

首次访问需确认管理员 IP 在 `config.json` 的 `admin_whitelist` 中（默认 `127.0.0.1` 和 `::1`）。面板位于反向代理后时，需在 `admin_trusted_proxies` 中添加反代 IP。

## 工作原理

### Dynamic-only 密钥策略

v4.3.8 不再通过配置切换 static/dynamic。Lua 运行时将 `KEY_MODE` 固定为 `dynamic`；`key_mode`、static 密钥、旧 `secret`、旧三段式 Cookie 和 legacy 字段都不应出现在配置文件中，若重新加入固定字段，运行时会直接报配置错误。服务端通过 `/cgi-rfw/token` 按 IP+UA 发放短时效密钥（TTL 1800s），前端使用 dynamic key 签名；Cookie 使用代码固定的 `_RFW` 名称、dynamic key 和 32 hex HMAC 标签。

### 签名请求（优先）

前端每请求生成 `MA-RFW-Data = ts.nonce.sign`，nginx 严格校验：

```
sign = HMAC-SHA256(key, METHOD|request_uri|sha256hex(body)|ts|nonce)
```

- `dynamic-only`：`key = 动态密钥`（从 `/cgi-rfw/token` 获取，per IP+UA，有 grace 过渡期）

校验链：`ts` 时效 → `nonce` 一次性（原子去重）→ `body` 哈希 → HMAC 比对（常量时间）。任一失败 → 403 + 记失败，窗口内满 `fail_max` 次封禁 IP。

dynamic-only 严格模式下，非文档请求默认要求当前 dynamic MA-RFW-Data；前端异步和同步 XHR 都必须在发送前生成 MA-RFW-Data。`dynamic_allow_cookie_fallback=false` 时，密钥未就绪或请求体无法同步序列化不会进入 Cookie 兜底，服务端直接拒绝。只有 `dynamic_document_paths` 精确匹配的 GET/HEAD，或 Nginx exact location 显式设置 `$rfw_document 1` 的请求，才可在没有 MA-RFW-Data 和没有 `_RFW` 时进入文档 bootstrap。默认兼容 Firefox、Python urllib 和旧代理链，即使缺少 `Sec-Fetch-Dest` 也能访问已配置的文档入口；API、Controller、`.do` 和常见版本 API 不接受伪造文档头。设置 `cookie_document_require_fetch_metadata=true` 后才额外要求 `Sec-Fetch-Dest: document`。

### 文档识别与 Cookie 发送时机

v4.3 将“是否允许文档 bootstrap”和“是否把待刷新的 Cookie 写入响应”拆成两个阶段。access 阶段只使用 `dynamic_document_paths` 精确路径白名单或 Nginx `$rfw_document 1` 显式标记；它不会使用 `Accept`、尾斜杠或 `Sec-Fetch-Dest` 作为安全放行条件。`/api/`、`/graphql`、`/vN/`、`Controller/`、`.do` 等路径在 Header Gate 中始终要求 dynamic MA-RFW-Data。只有管理员在配置文件中显式开启 `dynamic_allow_cookie_fallback` 时，少量同步的 GET/HEAD/OPTIONS 请求才可改由已有有效 dynamic `_RFW` Cookie 进入完整 Cookie 校验；POST/PUT/PATCH/DELETE 即使开启该项也必须携带 MA-RFW-Data。伪造文档请求头不能绕过该要求。

对于已经通过校验、需要刷新 Cookie 的安全 GET/HEAD，RFW 在 access 阶段只登记 pending Cookie。header_filter 阶段再读取 upstream 的响应状态和 `Content-Type`：仅当状态小于 400 且 MIME 为 `text/html`（允许参数，如 `text/html; charset=UTF-8`）时，才真正写出 `Set-Cookie`；JSON、JavaScript、图片、错误页不会收到文档 Cookie。**MIME 是响应写入确认，不是 access 放行依据。**

### MA-RFW-Data-only 与兼容例外

- 默认按 IP 统计签名占比，低于阈值的受保护请求进入 `sign-ratio-low` 拒绝和封禁链；静态扩展名资源不参与该比例统计。
- 带有效 dynamic MA-RFW-Data 的请求跳过 `_RFW` Cookie 校验，但仍完成 Header 的时间、nonce、body、URI、方法和绑定检查。
- 默认无 MA-RFW-Data 的受保护请求直接拒绝；仅当管理员显式开启 `dynamic_allow_cookie_fallback` 时，才对已有 dynamic `_RFW` 执行 HMAC、ts 新鲜度、会话序号、有限重放、比例和封禁检查。
- static 密钥、旧 secret、旧 Cookie 和旧三段式格式均不再进入兼容链。

### 静态资源

GET/HEAD 且扩展名在静态表 → 跳过签名/比例统计，只做封禁检查后放行。

### 前端动态启动与 Cookie 保活

dynamic-only 模式下，Token 接口使用原始 `fetch`，不会被自身的请求拦截器再次排队；密钥获取期间的业务 API 进入等待队列。同一 Window 重复加载脚本会被 `__RFW_RUNTIME__` 保护，同源主窗口与 iframe 通过内部 Token Broker 共享 in-flight Token 请求，Token 刷新 Timer 和 Cookie 刷新 Interval 各只保留一套。密钥成功后，前端按服务端时钟每 30 秒刷新一次 `_RFW` Cookie，以避免长页面加载或后台恢复时使用过期 Cookie。Key 记录同时持久化到 `data/rfw_key_records.json`。每次 Nginx reload/restart 的 `init_by_lua` 阶段会生成新的 `boot_id`；`/cgi-rfw/token` 返回该标识。前端发现 boot_id 变化后会暂停所有同源业务请求并提示“系统维护，请刷新页面。”，不再用旧 Key 连续发送请求，避免触发误拦截和 IP ban。若 Token 响应没有 `boot_id`，说明线上仍是旧 WebUI 或旧发布包，不能视为 reload 防护已部署。若服务端在恢复窗口内仍返回 `dynamic-key-missing`，响应会带 `MA-RFW-Recover: token`；`sign-expired`/`sign-invalid` 也会发送该恢复信号；同一业务请求不会被自动重复提交。

Dynamic 模式下，HMAC、时效和序号始终检查。Nginx 重启后的前 180 秒内，缺少 Key 的请求仍然返回 403，但不计入 IP 失败/封禁链，避免 shared dict 初始化期间误 ban；超过恢复宽限后，真正的缺 Key 会重新进入失败链。GET、HEAD、OPTIONS 可以在同一页面并发期间复用同一合法 Cookie，但同值安全请求最多 8 次；POST/PUT/PATCH/DELETE 会按 `cookie_replay_window` 和 `cookie_replay_max` 执行更严格的同值重放限制。已通过 HMAC 的过期 Cookie 只有安全文档 GET/HEAD 可以无感刷新；浏览器重启后 dynamic key record 完全过期时，也只有 `dynamic_document_paths` 或 exact `$rfw_document` 入口允许重新 bootstrap。API、Controller、`.do`、写请求和非文档 GET 不享受该重引导。待刷新的 Cookie 仍需等 upstream HTML 响应在 `header_filter` 中确认后才写出。设置 `cookie_document_require_fetch_metadata=true` 可进一步收紧为必须携带 `Sec-Fetch-Dest=document`。

## 配置说明（config.json）

配置文件采用标准 JSON；所有以 `__COMMENT_` 开头的字段都是中文备注，运行时、WebUI 和测试工具会在载入配置后忽略这些备注字段。WebUI 保存时使用 2 个空格缩进写回完整 JSON，不会压缩成单行。dynamic-only、MA-RFW-Data 严格校验、IP/UA 绑定、`_RFW` Cookie 名称、Cookie 安全方法、Bootstrap、重放检测开关、共享字典名称以及 HMAC 标签长度都属于代码固定策略，不再写入 `config.json`。如果手工重新加入这些固定字段，Lua 会直接报配置错误。

| 字段 | 默认值 | 说明 |
| --- | --- | --- |
| `dynamic_document_paths` | `["/", "/webapp/"]` | 文档 HTML 精确路径；WebUI 使用回车添加标签 |
| `strict_api_paths` | `[]` | 额外严格 API 前缀；WebUI 使用回车添加标签，空数组表示默认严格策略 |
| `key_ttl` / `key_grace` | 1800 / 90 | 动态密钥有效期与新旧密钥过渡期（秒）；Key 记录持久化跨 Nginx 重启 |
| `key_advance_refresh` | 30 | 动态密钥提前刷新阈值（秒） |
| `key_fetch_quota` / `key_quota_window` | 1000 / 86400 | 密钥发放配额与统计窗口 |
| `token_rate_limit` / `token_rate_window` | 10 / 60 | Token 接口频率限制与统计窗口 |
| `dynamic_allow_cookie_fallback` | `false` | 不在 WebUI 展示；仅能手工开启。开启后只允许 GET/HEAD/OPTIONS 使用已有有效 dynamic Cookie 兜底，写请求仍需 MA-RFW-Data |
| `cookie_ttl` | 86400 | Cookie 生命周期（秒） |
| `cookie_ts_max` | 300 | Cookie 签名时间戳新鲜度上限（秒） |
| `cookie_replay_window` | 2 | 非安全方法同值 Cookie 的并发宽限窗口（秒） |
| `cookie_replay_max` | 5 | 非安全方法窗口外同值 Cookie 的最大消费次数 |
| `cookie_document_require_fetch_metadata` | `false` | 文档重新引导是否额外要求 `Sec-Fetch-Dest=document` |
| `cookie_missing_max` / `cookie_missing_ttl` | 50 / 86400 | 单 IP 无 Cookie 计数上限与统计窗口 |
| `sign_window` | 60 | MA-RFW-Data 时间戳有效窗口（秒） |
| `sign_ratio_req` / `sign_ratio_min` | 10 / 0.5 | 签名比例统计起始请求数与最低比例 |
| `cookie_ratio_req` / `cookie_ratio_min` | 10 / 0.5 | Cookie 兜底比例统计起始请求数与最低比例 |
| `seq_slack` / `seq_ttl` / `seq_cache_ttl` | 10 / 86400 / 3 | Cookie 会话序号容差、保留期和内存缓存 TTL |
| `replay_threshold` / `replay_relink_sec` | 5 / 2 | 请求重放阈值与二次校验窗口；重放检测开关固定开启 |
| `fail_max` / `fail_window` | 5 / 60 | 失败计数封禁阈值与统计窗口 |
| `block_time` / `block_cache_ttl` | 600 / 60 | IP 封禁时间与封禁缓存 TTL |
| `sweep_interval` / `snap_log_interval` | 60 / 1800 | 后台清扫和 SNAP 日志落盘周期 |
| `admin_whitelist` | `[...]` | 管理面板 IP/CIDR 白名单；留空表示允许所有 |
| `admin_trusted_proxies` | `[]` | 受信反代 IP；仅当 remote_addr 在此列表时解析转发头 |
| `debug` | `false` | 调试模式；生产建议关闭 |

### API 端点

| 端点 | 方法 | 说明 |
| --- | --- | --- |
| `/cgi-rfw/token` | GET | 动态密钥发放（rate limit + quota；失败不放行受保护请求） |
| `/cgi-rfw/rfw.min.js` | GET | 前端拦截器（内存缓存，no-cache 头） |
| `/cgi-rfw/status` | GET | 管理面板状态页 |
| `/cgi-rfw/config` | GET | 管理面板配置页 |
| `/cgi-rfw/logs` | GET | 管理面板日志页 |

## 运行时数据与日志文件

`data/` 用于保存运行时 JSON：`data/rfw_key_records.json` 保存仍在有效期内的 dynamic Key 记录，`data/rfw_stats.json` 保存跨 worker 和重启的统计累计。两者都是运行时文件，不应提交 Git；仓库只保留 `data/.keep`，并通过 `.gitignore` 忽略 `data/*.json` 和根目录 `rfw_stats.json`。部署目录必须保证 `data/` 可写；如果不可写，系统仍可运行，但 Key 只能依赖 shared dict，Nginx 重启后客户端会进入自动恢复流程。

## 日志文件

日志为逐行 JSON，字段结构与 WAF（moewaf）完全同构：

```json
{"client_ip":"1.2.3.4","local_time":"2026-08-18 10:00:00","server_name":"example.com",
 "user_agent":"Mozilla/5.0 ...","attack_method":"blocked","req_url":"/api/list",
 "req_data":"...","rule_tag":"GET"}
```

- `attack_method` 取值：DENY 记录=拒绝原因（`backend-unreachable` / `sign-invalid` / `blocked` / `sign-ratio-low` 等）；另有 `SNAP`（快照）、`ERROR`、`DEBUG`
- `rule_tag`：DENY 记录为 HTTP 方法，`SNAP`/`ERROR`/`DEBUG` 为 `-`
- **业务日志**: `logs/rfw_YYYY-MM-DD.log`（原始文件保留 DENY + SNAP + ERROR 行；WebUI 日志查看页/API 过滤掉 `SNAP`）
- **错误日志**: `logs/rfw.error.log`（ERROR + debug 输出，含 `admin: rejected` 审计行）
- **SNAP 限频**: 快照行按 `snap_log_interval`（默认 30 分钟）最小间隔落盘，避免刷爆磁盘；计数器跨 worker 累计（含 `denied_total`）

## 管理面板安全

- 默认仅允许 `127.0.0.1` / `::1` 访问
- 未授权访问返回 404（nginx 风格页面），并在 error log 记录 WARN 审计行
- 反向代理部署时：将反代 IP 加入 `admin_trusted_proxies`，管理员真实 IP 加入 `admin_whitelist`

## 测试

v4.3.8 将原先分散的工具合并为单一入口。它使用真实 `ma_rfw.lua`、本地 shared-dict mock 和 `脱敏回放文件` 请求序列，不向生产发送请求；同时覆盖 dynamic-only、MA-RFW-Data 篡改/过期/重放、删除凭证攻击、Cookie 重放、显式文档路径、Controller/.do 拒绝、响应 MIME 确认、WebUI 配置、60 分钟浏览器重启、Token 端点故障时异步 XHR fail-closed 和性能基线。SAZ 的 absolute-form URL 会先转换为 Nginx 的 path+query，避免测试工具与生产 `ngx.var.uri/request_uri` 语义不一致。

```bash
cd replayfirewall_hardened_v4_3_8
python3 tools/rfw_v4_test.py \
  --config config.json \
  --saz /path/to/脱敏回放文件 \
  --json-out /tmp/rfw_v4_3_8_hardened_test.json \
  --md-out /tmp/rfw_v4_3_8_hardened_test.md
```

测试通过标准为 `failed=0`。当前 v4.3.8 dynamic-only 基线为 **59/59 PASS，0 FAIL，0 SKIP**，另有前端 Node 异步/同步 XHR、Token recovery 强制刷新、Token 故障时异步 XHR fail-closed、旧协议 fail-closed 与全局变量篡改测试通过；覆盖删除 MA-RFW-Data、删除 `_RFW`、同时删除两者、static 配置拒绝、低签名比例拒绝、WebUI v4.3.8 版本、服务端/前端 SNAP 过滤；并已在 Chromium 中使用主窗口加两个注入 `rfw.js` 的同源 iframe，按“业务轮询先恢复、页面事件后恢复”顺序验证 30/45/60/120 分钟后台停留窗口及 Token 故障场景。本地性能数字只用于回归比较，不代表生产 QPS；生产性能依赖 OpenResty、CPU、shared dict 大小和实际 WebApp 请求体。生产必须使用 `lua_code_cache on`，并通过 `init_by_lua_file` 加载 `init.lua` 以生成 reload boot_id，避免每请求重新编译 Lua 和文件 I/O。
