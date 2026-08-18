# MA-RFW — MoeArt Replay Firewall

针对浏览器内嵌前端（非 SSR）的接口重放/伪造攻击防护。前端 `rfw.js` 对每个同源请求做 HMAC-SHA256 签名，nginx 侧 `ma_rfw.lua` 严格校验；无签名请求走行为兜底（cookie 签名 + 会话序列号 + 相同请求指纹 + 覆盖率判定），支持按 IP 记失败并封禁。

## 特性

- HMAC-SHA256 请求签名（防篡改、防重放）
- `_RFW` 运动 Token（rfw.js 定时刷新，cookie 路径兜底）
- 无签名请求行为分析（签名占比 + cookie 校验链）
- 相同请求指纹重放检测
- 按 IP 失败计数 → 自动封禁
- WebUI 管理面板（状态统计 / 配置 / 日志查看）
- 历史统计图表（拒绝趋势 + 请求量 + 原因分布）
- 零外部依赖（纯 Lua + ngx.shared.DICT）

## 文件结构

| 文件 | 说明 |
| --- | --- |
| `webui.lua` | WebUI 单文件插件（状态页 / 配置页 / 日志页 + 所有 API） |
| `ma_rfw.lua` | 主插件（访问阶段校验 + 后台清扫 + 日志） |
| `sha256.lua` | 纯 Lua SHA256 / HMAC-SHA256（零外部依赖） |
| `rfw.js` | 前端签名拦截器（覆盖 fetch 与 XMLHttpRequest） |
| `blocked.html` | 封禁/拒绝时返回的 403 页面 |
| `config.json` | 运行时配置（WebUI 可修改，不纳入 git） |
| `config.json.example` | 配置模板（纳入 git） |
| `init.lua.example` | init 阶段加载示例（复制为 `init.lua`） |
| `access.lua.example` | access 阶段入口示例（复制为 `access.lua`） |
| `logs/` | 日志目录（自动创建，不纳入 git） |
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

    # 前端页面注入 rfw.js
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

### 3. 验证 & 启动

```bash
nginx -t
nginx -s reload
```

### 4. 访问管理面板

浏览器打开 `http://your-server:80/cgi-rfw/status`

首次访问需确认管理员 IP 在 `config.json` 的 `admin_whitelist` 中（默认 `127.0.0.1` 和 `::1`）。面板位于反向代理后时，需在 `admin_trusted_proxies` 中添加反代 IP。

## 工作原理

### 签名请求（优先）

前端每请求生成 `RFWDATA = ts.nonce.sign`，nginx 严格校验：

```
sign = HMAC-SHA256(secret, METHOD|request_uri|sha256hex(body)|ts|nonce)
```

校验链：`ts` 时效 → `nonce` 一次性（原子去重）→ `body` 哈希 → HMAC 比对（常量时间）。任一失败 → 403 + 记失败，窗口内满 `fail_max` 次封禁 IP。

### 无签名请求（行为兜底）

- 按 IP 统计签名占比，低于阈值 → 非浏览器 → 拦截
- 校验 `_RFW` cookie：HMAC 签名 + ts 新鲜度 + 会话序号单调 + 重放检测 + 覆盖率
- 带有效 RFWDATA 的请求完全跳过 `_RFW` cookie 校验

### 静态资源

GET/HEAD 且扩展名在静态表 → 跳过签名/比例统计，只做封禁检查后放行。

## 配置说明（config.json）

| 字段 | 默认值 | 说明 |
| --- | --- | --- |
| `secret` | - | 共享密钥，与 rfw.js 一致，泄露必须更换 |
| `shared_dict.dict_name` | `rfw` | 共享内存字典名（需与 nginx.conf 一致） |
| `sign_enabled` | `true` | 签名校验开关 |
| `sign_window` | 60 | 签名 ts 时效窗口（秒） |
| `sign_ratio_req/min` | 10 / 0.5 | 签名占比判定阈值 |
| `cookie_name` | `_RFW` | cookie 名称 |
| `cookie_ttl` | 86400 | cookie 生命周期（秒） |
| `cookie_ts_max` | 60 | cookie ts 新鲜度上限（秒） |
| `cookie_replay_window` | 2 | 同值并行宽限（秒） |
| `cookie_replay_max` | 5 | 窗口外同值可消费次数 |
| `cookie_missing_max` | 50 | 单 IP 无 cookie 日配额（0=关） |
| `fail_max / fail_window` | 5 / 60 | 惩罚阈值 |
| `block_time` | 600 | 封禁时长（秒） |
| `sweep_interval` | 60 | 后台清扫间隔（秒） |
| `snap_log_interval` | 1800 | SNAP 快照落盘最小间隔（秒，0=每次清扫都写） |
| `admin_whitelist` | `["127.0.0.1","::1"]` | 管理面板白名单（留空=允许所有） |
| `admin_trusted_proxies` | `[]` | 受信反代 IP（仅当 remote_addr 在此列表时解析 XFF） |
| `debug` | `false` | 调试模式（写入 rfw.error.log） |

## 日志文件

日志为逐行 JSON，字段结构与 WAF（moewaf）完全同构：

```json
{"client_ip":"1.2.3.4","local_time":"2026-08-18 10:00:00","server_name":"example.com",
 "user_agent":"Mozilla/5.0 ...","attack_method":"blocked","req_url":"/api/list",
 "req_data":"...","rule_tag":"GET"}
```

- `attack_method` 取值：DENY 记录=拒绝原因（`backend-unreachable` / `sign-invalid` / `blocked` / `sign-ratio-low` 等）；另有 `SNAP`（快照）、`ERROR`、`DEBUG`
- `rule_tag`：DENY 记录为 HTTP 方法，`SNAP`/`ERROR`/`DEBUG` 为 `-`
- **业务日志**: `logs/rfw_YYYY-MM-DD.log`（DENY + SNAP + ERROR 行）
- **错误日志**: `logs/rfw.error.log`（ERROR + debug 输出，含 `admin: rejected` 审计行）
- **SNAP 限频**: 快照行按 `snap_log_interval`（默认 30 分钟）最小间隔落盘，避免刷爆磁盘；计数器跨 worker 累计（含 `denied_total`）

## 管理面板安全

- 默认仅允许 `127.0.0.1` / `::1` 访问
- 未授权访问返回 404（nginx 风格页面），并在 error log 记录 WARN 审计行
- 反向代理部署时：将反代 IP 加入 `admin_trusted_proxies`，管理员真实 IP 加入 `admin_whitelist`

## 测试

```bash
python tools/check_syntax.py            # Lua 语法检查
python tools/test_load.py               # 模块加载冒烟
python tools/test_global.py             # init + access + $rfw_on 标记门
python tools/test_real_request.py       # 签名/重放链路
python tools/test_static.py             # 静态/动态分类
python tools/test_cookie_missing.py     # 无 cookie 日配额
python tools/test_cookie_replay.py      # 运动 Token 校验
python tools/bench_hmac.py              # HMAC 预计算基准
```
