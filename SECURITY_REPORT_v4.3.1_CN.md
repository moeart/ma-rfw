# Replay Firewall v4.3.1 中文安全评估报告

**报告日期：** 2026-08-19  
**报告对象：** Replay Firewall（MA-RFW）v4.3.1  
**报告类型：** 源码审计、自动化回归、生产抓包回放与部署风险评估  
**作者：** Manus AI

## 1. 执行摘要

本报告评估当前 v4.3.1 dynamic-only 代码、带中文 `__COMMENT_*` 备注字段的标准 JSON 配置、WebUI 和自动化测试结果。用户反馈该版本已经在生产环境运行正常；该反馈可作为运行状态补充证据，但不等同于独立第三方渗透测试。

v4.3.1 的核心安全结论是：**灰度版本固定 dynamic-only，RFWDATA 是默认唯一 Header 凭证；Cookie fallback 默认关闭，static 密钥、旧 `secret`、旧 Cookie 格式和客户端全局 Token 信任已移除。**此前异步 XHR Promise 中 `buf` 变量作用域错误导致签名失败后进入原始 `send()` 的问题已修复，异步和同步 XHR 均在发送前生成 RFWDATA。

当前最终本地自动化回归为 **49/49 PASS、0 FAIL、0 SKIP**；前端 Node 异步/同步 XHR 与全局变量篡改回归另行通过。生产 SAZ 回放包含 225 个会话，动态替换后的 217 条序列请求全部通过；60 分钟浏览器重启首页通过，旧 Cookie 访问 dynamic API 仍被拒绝。Firefox/urllib 首页兼容、Controller/.do 安全边界、Cookie HMAC、有限重放、配置保存、标准 JSON 备注字段和 SNAP 过滤均已覆盖。

> **部署结论：**生产 Dashboard 如果仍显示大量 Cookie 兜底、签名次数极少，不能视为正常现象。应先确认实际加载的是同一发布包中的 `rfw.js`、`ma_rfw.lua`、`webui.lua` 和 `config.json`，再清理或标记旧统计基线。正常 v4.3.1 默认运行应以 RFWDATA 为主，Cookie fallback 不参与。

## 2. 评估范围与证据

| 证据 | 内容 | 结论用途 |
|---|---|---|
| `ma_rfw.lua` | dynamic-only access 校验、RFWDATA、Cookie、重放、封禁和统计 | 核心安全逻辑 |
| `rfw.js` | fetch/XHR 拦截、dynamic Token、同步/异步 RFWDATA、Cookie 刷新 | 客户端签名链 |
| `webui.lua` | Token/config/log API、管理页、标准 JSON 备注 保存、SNAP 过滤、版本号 | 运维面和诊断链 |
| `config.json` | 本次完整运行配置，带中文注释，无旧固定字段 | 实际策略基线 |
| `config.json.example` | 与运行配置相同边界的注释模板 | 部署模板审计 |
| `prod.saz` | 225 个生产会话 | 真实请求序列回放 |
| `rfw_v4_3_1_hardened_test.json` | 49 项自动化检查 | 可复现测试证据 |
| 用户生产反馈 | 最新版本已在生产正常运行 | 上线运行状态补充证据 |

本报告没有执行独立外部渗透测试，也没有在沙箱中执行真实 OpenResty `nginx -t`。性能数据来自本地 LuaJIT/Lupa shared-dict mock，仅用于版本间回归比较，不代表生产 QPS。

## 3. 配置边界与 标准 JSON 备注

v4.3.1 的 `config.json` 和 `config.json.example` 使用标准 JSON；所有以 `__COMMENT_` 开头的字段都是中文备注，ma_rfw.lua、webui.lua 和回归工具在载入后会忽略这些字段。WebUI 保存配置时使用 2 个空格缩进写回完整 JSON，不会压缩成单行，因此管理员可以在配置文件中保留字段用途说明。

下列安全策略已直接写入 `ma_rfw.lua` 代码头部，不再写入配置文件或显示在 `/cgi-rfw/config` 页面：dynamic-only、RFWDATA 严格 Header Gate、签名校验启用、请求重放检测启用、IP/UA 绑定、`_RFW` Cookie 名称、Cookie Bootstrap、安全方法集合、文档重新引导开关、HMAC 标签长度、共享字典名称和 static 扩展名表。运行时若发现这些固定字段重新出现在配置中，会直接报配置错误，而不是静默采用旧策略。

| 配置项 | 当前值或范围 | 安全含义 |
|---|---:|---|
| `dynamic_allow_cookie_fallback` | `false` | 不在 WebUI 展示；只允许手工开启的兼容例外 |
| `dynamic_document_paths` | `/`、`/portal-web/` | 只允许精确文档入口 bootstrap |
| `strict_api_paths` | `[]` | 额外严格 API 前缀；WebUI 使用回车标签添加 |
| `key_ttl` / `key_grace` | `1800 / 90` 秒 | dynamic Key 短期有效并有限过渡 |
| `sign_window` | `60` 秒 | RFWDATA 时间窗口 |
| `cookie_ttl` | `60–604800` 秒 | Cookie 生命周期被限制在安全范围 |
| `cookie_ts_max` | `1–3600` 秒 | Cookie 签名时间戳不会被配置为无限新鲜 |
| `cookie_replay_window` | `0–30` 秒 | 非安全方法同值并发宽限窗口 |
| `cookie_replay_max` | `1–100` 次 | 非安全方法同值消费次数，0 会被收紧为 1 |
| `cookie_document_require_fetch_metadata` | `false` | 是否额外要求 `Sec-Fetch-Dest=document` |
| `seq_slack` / `seq_ttl` / `seq_cache_ttl` | `10 / 86400 / 3` | Cookie 会话序号容差、保留期和缓存 |
| `replay_threshold` / `replay_relink_sec` | `5 / 2` | 请求重放检测阈值与二次校验窗口 |
| `fail_max` / `block_time` | `5 / 600` 秒 | 失败累计后的 IP 封禁链 |
| `admin_whitelist` | 生产配置中的 IP/CIDR | 管理面板访问控制 |
| `debug` | `false` | 生产关闭详细诊断 |

## 4. Dynamic RFWDATA 校验链

对于同源异步 fetch、异步 XHR 和同步 XHR，v4.3.1 客户端均优先生成 RFWDATA。签名输入为：

```text
HTTP_METHOD | path?query | SHA256(body) | timestamp | nonce
```

服务端依次执行时间窗口、dynamic Key record、IP/UA 绑定、请求体哈希、HMAC 常量时间比较和 nonce/replay 检查。请求方法、URI、body 或绑定信息任意改变都会使 RFWDATA 失效。

同步 XHR 使用纯 JavaScript SHA-256/HMAC 路径，异步 XHR 使用 Promise 路径；两条路径都在发送前设置 RFWDATA。dynamic Key 尚未就绪或 body 无法同步序列化时，在默认 RFWDATA-only profile 下直接拒绝，不会把未签名请求当作可信请求放行。

| 场景 | 预期行为 |
|---|---|
| 异步 XHR/fetch + dynamic Key | 设置 RFWDATA 后发送 |
| 同步 XHR + GET/字符串/ArrayBuffer body | 同步设置 RFWDATA 后发送 |
| Key 未就绪或 body 无法同步处理 | 默认直接拒绝 |
| 无 RFWDATA、无 Cookie 的 Controller/.do | `dynamic-sign-missing`，403 |
| 无 RFWDATA、但有合法 `_RFW` 的 Controller/.do | 默认 `dynamic-sign-missing`，403；删除 RFWDATA 不能借 Cookie 绕过 |
| 有 RFWDATA、删除 `_RFW` | 允许；Header 是主凭证，Cookie 不是必需凭证 |
| 旧 static Cookie 或旧 `secret` | dynamic-only 模式拒绝 |

## 5. Cookie fallback 的安全边界

v4.3.1 默认 `dynamic_allow_cookie_fallback=false`，因此缺少 RFWDATA 的 Controller/API 即使带有合法 `_RFW` 也会被拒绝。若灰度期间确实存在无法改造的特殊同步请求，管理员可以在配置文件中临时开启 fallback；该字段不在 WebUI 配置页展示，避免普通保存操作扩大兼容范围。

> **Cookie fallback 不是无限重放许可。** 即使显式开启，缺少 RFWDATA 的 fallback 请求也必须是 GET、HEAD 或 OPTIONS，并且必须携带已有 dynamic `_RFW` Cookie。POST、PUT、PATCH、DELETE 等写请求始终需要 RFWDATA。

进入 Cookie 校验后，仍必须通过 dynamic HMAC、Cookie 时间戳和生命周期、IP/UA 绑定、会话序号、Cookie 比例、失败计数及 IP 封禁检查。安全 GET/HEAD/OPTIONS 允许页面初始化的同值并发，但同一 SID、序号和时间戳组合最多 8 次；超过后返回 `cookie-replay` 并计入失败链。非安全方法在其他 Cookie 校验路径中仍受 `cookie_replay_window` 和 `cookie_replay_max` 限制，配置值会被限制为正数，不能通过设为 0 获得无限消费次数。

Cookie 时间戳上限被限制为 1 至 3600 秒，Cookie 生命周期被限制为 60 至 604800 秒。攻击者若只窃取一个合法 `_RFW`，也无法凭该 Cookie 无限重放，更无法仅凭 Cookie 发起写请求；但这不替代 HTTPS、业务鉴权、账号权限和日志访问控制。

## 6. 文档入口与 API 安全

文档入口只由精确 `dynamic_document_paths` 或 Nginx exact location 的 `$rfw_document 1` 确定。`Accept`、URL 尾斜杠、MIME 和 `Sec-Fetch-Dest` 都不会单独让 API 获得文档豁免。

响应 `Content-Type: text/html` 只在 `header_filter` 阶段决定是否写出待刷新的文档 Cookie，不参与 access 放行。Controller、`.do`、`/api/`、`/graphql` 和版本 API 即使携带 `Sec-Fetch-Dest: document`，也不能因此绕过 dynamic 凭证链。

`getDevToolMd5.do` 作为 Ajax/XHR 请求使用 `Sec-Fetch-Dest: empty` 是正确行为。它的首选安全凭证应是 RFWDATA；只有显式开启 fallback 且请求方法属于 GET/HEAD/OPTIONS 时，已有有效 dynamic `_RFW` 才能进入例外链。

## 7. 重放、篡改和异常流量防护

| 检查类别 | 测试结果 | 说明 |
|---|---|---|
| RFWDATA body 篡改 | PASS | body hash 不匹配即拒绝 |
| RFWDATA URI 篡改 | PASS | 签名 URI 不匹配即拒绝 |
| RFWDATA method 篡改 | PASS | 签名方法不匹配即拒绝 |
| RFWDATA 过期 | PASS | 超出 `sign_window` 即拒绝 |
| RFWDATA nonce 重放 | PASS | nonce 原子去重 |
| Cookie HMAC 篡改 | PASS | 32 hex 标签校验失败即拒绝 |
| Cookie 过期/stale | PASS | 仅安全文档重新 bootstrap，API 不重新 bootstrap |
| Cookie 序列重放 | PASS | 安全方法最多 8 次同值并发，写请求严格序列校验 |
| Cookie fallback 方法限制 | PASS | 无 RFWDATA 的 fallback 只允许 GET/HEAD/OPTIONS |
| 相同请求重放 | PASS | 超阈值进入 request-replay 拒绝链 |
| 失败计数和 IP 封禁 | PASS | 达到 `fail_max` 后进入 `block_time` |
| 固定字段注入 | PASS | static、旧字段和唯一策略字段重新出现时拒绝 |

## 8. 自动化测试结果

最新统一测试报告为 **49/49 PASS、0 FAIL、0 SKIP**；前端 Node 异步/同步 XHR 和全局变量篡改测试另行通过。

| 测试套件 | 覆盖内容 | 结果 |
|---|---|---:|
| dynamic | 当前 Key、RFWDATA、body/URI/method 篡改、过期、重放、错误 IP/UA、固定字段拒绝 | PASS |
| Cookie | HMAC、过期、序列、有限并发安全方法、显式 fallback、低签名比例 | PASS |
| dynamic-only | static 配置拒绝、旧 `secret`/Cookie 拒绝、固定 dynamic 模式 | PASS |
| 标准 JSON 备注 | `__COMMENT_*` 备注读取、保存后缩进保留、模板解析 | PASS |
| WebUI | 中文字段、固定项隐藏、路径标签、配置保存、版本 v4.3.1、SNAP 过滤 | PASS |
| SAZ | 225 会话、217 条动态替换序列、首页、60 分钟重启、dynamic-only | PASS |
| 性能 | dynamic-only 300 条签名请求 | PASS |

关键实测数据如下：

```text
production sequence after dynamic replacement: sessions=217, denied=[]
60 minute browser restart HTML: ALLOW
60 minute browser restart API old Cookie: 403（预期）
dynamic-only 300 signed requests: 300/300 ALLOW; 10,024.3 requests/s（本地 mock）
前端异步 XHR RFWDATA: PASS
前端同步 XHR RFWDATA: PASS
```

本地性能回归约为 dynamic-only 10,024.3 requests/s；该数据只用于版本间比较，不应直接作为生产容量承诺。

## 9. WebUI 规范与 SNAP 修复

配置页面统一使用中文优先标签；字段下方使用小字说明，关键说明通过鼠标悬停提示。动态文档精确路径和严格 API 路径与管理员白名单使用同一种回车添加标签交互，点击标签即可删除。`Cookie` 在页面、发布说明和本报告中统一首字母大写。

配置页面不显示密钥模式、严格签名开关、动态 Cookie 标签长度、Cookie 名称、Cookie Bootstrap、安全方法、重放开关和 `dynamic_allow_cookie_fallback` 等唯一或不可编辑字段。固定策略由代码头部负责。

SNAP 是内部累计快照，不是用户请求拒绝事件。服务端 `/cgi-rfw/api/log` 和日志页面 JavaScript 渲染器均过滤 `attack_method == "SNAP"`；原始日志仍可保留 SNAP 供内部统计和故障诊断。WebUI 版本常量已更新为 `4.3.1`，页面品牌区域应显示 `MA-RFW v4.3.1`。

## 10. 生产部署风险与建议

| 风险 | 等级 | 说明 | 建议 |
|---|---|---|---|
| Cookie fallback 被重新开启 | 中 | 无 RFWDATA 的安全读请求可能进入有效 dynamic Cookie 校验链 | 默认保持关闭；如临时开启，设置期限并监控 `signed_ok`/`cookie_ok` |
| Cookie 被窃取 | 高 | 只能在 Cookie 有效期、IP/UA 绑定、方法和同值次数限制内复用，但仍是敏感凭证 | 全程 HTTPS；发现泄露时轮换 dynamic Key record |
| debug 被重新打开 | 高 | 403 debug panel 可能返回较详细校验诊断 | 灰度和生产保持 `false` |
| WebUI 管理面暴露 | 中 | 配置、日志和 Token 端点属于高敏感管理面 | 保持 `admin_whitelist`，反代只信任明确代理 IP，优先 HTTPS |
| 统计历史污染 | 低 | `signed_ok`、`cookie_ok` 等可能跨重启持久化 | 部署新版本后备份并记录统计基线 |
| SNAP 原始日志保留 | 低 | WebUI 已隐藏，但磁盘文件仍可能包含快照 | 按日志保留周期和访问权限保护原始日志 |

## 11. 结论

在当前代码和测试证据范围内，v4.3.1 已达到灰度高安全基线：dynamic-only、RFWDATA-only 默认策略、同步/异步 XHR 均可签名、删除 RFWDATA 或 `_RFW` 均不能绕过、static/legacy 兼容关闭、Controller/.do 不接受文档头伪造、Cookie fallback 不是无限重放、固定配置字段无法重新启用、WebUI 配置边界与运行时一致，SNAP 已隐藏并显示 v4.3.1。

该结论不表示系统可以替代 HTTPS、后端业务鉴权、账号权限控制、日志访问控制或独立渗透测试。生产上线后应重点观察三项指标：**RFWDATA 签名比例、Cookie fallback 比例、`sign-ratio-low`/`dynamic-sign-missing` 拒绝原因**。如果修复后的生产环境仍长期出现“签名 1 次、Cookie 兜底大量增加”，应立即检查实际加载的 JS/Lua 版本和统计基线，而不要把它视为正常流量。
