# MA-RFW v4.3.0 安全性评估与测试报告

**报告日期：** 2026-08-19  
**报告对象：** Replay Firewall（MA-RFW）v4.3.0  
**报告类型：** 源码审计、自动化回归、生产抓包回放与部署风险评估  
**作者：** Manus AI

## 1. 执行摘要

本报告评估的是当前 v4.3.0 dynamic-only 代码、配置模板、WebUI 和自动化测试结果。用户已反馈该版本已经在生产环境运行正常；本报告将该反馈作为生产运行状态证据之一，但不把它等同于独立第三方渗透测试。

v4.3.0 的核心安全结论是：**灰度版本固定 dynamic-only，并以 RFWDATA 作为唯一默认 Header 凭证；Cookie fallback 默认关闭，static 密钥和旧 secret 兼容已移除。**前一版本曾存在 XHR Promise 中 `buf` 变量作用域错误，导致签名失败后进入原始 `send()`，从而出现“签名仅 1 次、大量 Cookie 兜底”的异常统计。该错误已修复，异步和同步 XHR 均已加入 RFWDATA 回归测试。

当前本地自动化回归为 **47/47 PASS、0 FAIL、0 SKIP**；前端 Node 异步/同步 XHR 与全局变量篡改回归另行通过。生产 SAZ 回放包含 225 个会话，动态替换后的 217 条序列请求全部通过；60 分钟浏览器重启首页通过，旧 Cookie 直接访问 dynamic API 仍被拒绝。Firefox/urllib 首页兼容、Controller/.do 安全边界、Cookie HMAC、请求重放、WebUI 版本和 SNAP 过滤均已覆盖。

> **重要部署结论：**如果生产 Dashboard 仍显示大量 Cookie 兜底、签名次数极少，不能视为正常现象。应先确认生产实际加载的是 v4.3.0 的 `rfw.js`、`ma_rfw.lua` 和 `webui.lua`，再清理或标记旧的累计统计基线。正常的 v4.3.0 灰度运行应当是 RFWDATA-only；Cookie fallback 默认不参与。

## 2. 评估范围与证据

| 证据 | 内容 | 结论用途 |
|---|---|---|
| `ma_rfw.lua` | dynamic-only access 校验、RFWDATA、Cookie、重放、封禁和统计 | 核心安全逻辑 |
| `rfw.js` | fetch/XHR 拦截、dynamic token、同步/异步 RFWDATA、Cookie 刷新 | 客户端签名链 |
| `webui.lua` | token/config/log API、管理页、SNAP 过滤、版本号 | 运维面和诊断链 |
| `config.json` | 本次运行配置；报告不复制 secret | 实际策略基线 |
| `prod.saz` | 225 个生产会话 | 真实请求序列回放 |
| `rfw_v4_hardened_test.json` | 47 项自动化检查 | 可复现测试证据 |
| 用户生产反馈 | 最新版本已在生产正常运行 | 上线运行状态补充证据 |

本报告没有执行独立的外部渗透测试，也没有在沙箱中执行真实 OpenResty `nginx -t`；性能数据是本地 LuaJIT/Lupa shared-dict mock 的回归基线，不代表生产 QPS。

## 3. 实际安全配置基线

下表只列出安全相关字段，不包含真实密钥：

| 配置项 | 当前值 | 安全含义 |
|---|---:|---|
| `key_mode` | `dynamic` | 使用短期 dynamic key，运行时固定 dynamic-only |
| `dynamic_strict_sign` | `true` | dynamic 非文档请求进入严格凭证链 |
| `dynamic_sign_ratio_fail` | `true` | dynamic 低签名比例拒绝并计入失败/封禁链 |
| legacy secret / legacy Cookie | 已移除 | v4.3.0 不再提供 static 密钥兼容配置或旧 Cookie 回退开关 |
| `dynamic_allow_cookie_fallback` | `false` | 灰度版 RFWDATA-only；删除 RFWDATA 后不允许凭 Cookie 兜底 |
| `dynamic_cookie_tag_hex` | `32` | dynamic Cookie 使用 32 hex HMAC tag |
| `key_ttl` / `key_grace` | `1800 / 90` 秒 | dynamic key 短期有效并提供有限 grace 过渡 |
| `key_bind_ip` / `key_bind_ua` | `true / true` | dynamic key 与客户端 IP、UA 绑定 |
| `sign_window` | `60` 秒 | RFWDATA 时间窗口 |
| `cookie_ts_max` | `300` 秒 | `_RFW` Cookie 最大时间新鲜度 |
| `replay_enabled` | `true` | 开启请求重放检测 |
| `replay_threshold` | `5` | 重复请求超过阈值进入拒绝链 |
| `fail_max` / `block_time` | `5 / 600` 秒 | 60 秒内累计失败达到 5 次后封禁 600 秒 |
| `cookie_document_require_fetch_metadata` | `false` | 兼容 HTTP、Firefox、urllib 和旧代理链首页 |
| `dynamic_document_paths` | `/`、`/portal-web/` | 仅精确文档入口允许 bootstrap，不放行 API |

## 4. Dynamic RFWDATA 校验链

对于同源异步 fetch、异步 XHR 和同步 XHR，v4.3.0 的客户端行为均为 RFWDATA-only 优先。签名输入为：

```text
HTTP_METHOD | path?query | SHA256(body) | timestamp | nonce
```

服务端依次执行时间窗口、dynamic key record、IP/UA 绑定、请求体哈希、HMAC 常量时间比较和 nonce/replay 检查。请求方法、URI 或 body 任意改变，都会使签名失效。

v4.3.0 特别修复了异步 XHR 的 `buf` 作用域问题。同步 XHR 不能等待 `crypto.subtle` Promise，因此使用同一套纯 JavaScript SHA-256/HMAC 实现同步产生 RFWDATA；dynamic key 尚未就绪或 body 类型无法同步序列化时，在默认 RFWDATA-only profile 下直接拒绝，只有显式开启兼容配置才可能进入 Cookie fallback。

| 场景 | 预期行为 |
|---|---|
| 异步 XHR/fetch + dynamic key | 设置 RFWDATA 后发送 |
| 同步 XHR + GET/字符串/ArrayBuffer body | 同步设置 RFWDATA 后发送 |
| key 未就绪或 body 无法同步处理 | 默认直接拒绝；只有显式开启兼容配置才可用有效 dynamic `_RFW` fallback |
| 无 RFWDATA、无 Cookie 的 Controller/.do | `dynamic-sign-missing`，403 |
| 无 RFWDATA、但有合法 `_RFW` 的 Controller/.do | `dynamic-sign-missing`，403；默认 fallback 关闭；删除 RFWDATA 不能借 Cookie 绕过 |
| 有 RFWDATA、删除 `_RFW` | 允许；Header 是主凭证，Cookie 不是必需凭证 |
| 旧 static Cookie 或旧 secret | dynamic-only 模式拒绝 |

## 5. Cookie fallback 的安全边界

v4.3.0 默认 `dynamic_allow_cookie_fallback=false`，因此缺少 RFWDATA 的 Controller/API 即使带有合法 `_RFW` 也会被拒绝。Cookie 仍可作为独立校验链处理显式需要它的场景，但不再替代 dynamic Header。若灰度期间确实存在无法改造的特殊同步请求，才可临时显式开启 fallback，并将其作为有期限的兼容例外。

在 v4.3.0 默认配置下，上述 Cookie fallback 风险关闭；只有管理员显式重新开启兼容配置时才重新出现。若临时开启，应设置明确的灰度期限，并持续观察 `signed_ok` 与 `cookie_ok` 的比例。

`dynamic_sign_ratio_fail=true` 使 dynamic 低签名比例进入失败/封禁链。当前测试以 10 个请求为窗口、签名比例低于 50% 为触发条件；静态扩展名资源不进入该比例统计。该机制是异常检测层，不能替代每个 dynamic RFWDATA 和 Cookie 的密码学验证。

## 6. 文档入口与 API 安全

文档入口只由精确 `dynamic_document_paths` 或 Nginx exact location 的 `$rfw_document 1` 确定。`Accept`、URL 尾斜杠、MIME 和 `Sec-Fetch-Dest` 都不会单独让 API 获得文档豁免。

响应 `Content-Type: text/html` 只在 `header_filter` 阶段决定是否写出待刷新的文档 Cookie，不参与 access 放行。Controller、`.do`、`/api/`、`/graphql` 和版本 API 即使携带 `Sec-Fetch-Dest: document`，也不能因此绕过 dynamic 凭证链。

`getDevToolMd5.do` 作为 Ajax/XHR 请求使用 `Sec-Fetch-Dest: empty` 是正确行为。它的安全凭证应是 RFWDATA；默认不会因同步场景而进入 Cookie fallback，只有管理员显式开启兼容配置时才允许已有有效 dynamic `_RFW` 进入该例外链。

## 7. 重放、篡改和异常流量防护

| 检查类别 | 测试结果 | 说明 |
|---|---|---|
| RFWDATA body 篡改 | PASS | body hash 不匹配即拒绝 |
| RFWDATA URI 篡改 | PASS | 签名 URI 不匹配即拒绝 |
| RFWDATA method 篡改 | PASS | 签名方法不匹配即拒绝 |
| RFWDATA 过期 | PASS | 超出 `sign_window` 即拒绝 |
| RFWDATA nonce 重放 | PASS | nonce 原子去重 |
| Cookie HMAC 篡改 | PASS | 32 hex tag 校验失败即拒绝 |
| Cookie 过期/stale | PASS | 仅允许安全文档重 bootstrap，API 不重 bootstrap |
| Cookie 序列重放 | PASS | 安全 GET 有限宽容，写请求严格序列校验 |
| 相同请求重放 | PASS | 超阈值进入 request-replay 拒绝链 |
| 失败计数和 IP 封禁 | PASS | 达到 `fail_max` 后进入 `block_time` |
| 旧 static secret/cookie | PASS | dynamic legacy fallback 关闭 |

## 8. 自动化测试结果

最新统一测试报告为 **47/47 PASS、0 FAIL、0 SKIP**；前端 Node 异步/同步 XHR 和全局变量篡改测试另行通过。

| 测试套件 | 覆盖内容 | 结果 |
|---|---|---:|
| dynamic | 当前 key、RFWDATA、body/URI/method 篡改、过期、重放、错误 IP/UA | PASS |
| Cookie | HMAC、过期、序列、并发安全 GET、显式 fallback 隔离、低签名比例 | PASS |
| dynamic-only | static 配置拒绝、旧 secret/Cookie 拒绝、固定 dynamic 模式 | PASS |
| WebUI | dynamic-only token 策略、配置强制、版本 v4.3.0、日志 API SNAP 过滤、前端 SNAP 过滤 | PASS |
| SAZ | 225 会话、217 条动态替换序列、首页、60 分钟重启、dynamic-only | PASS |
| 性能 | dynamic-only 300 条签名请求 | PASS |

关键实测数据如下：

```text
production sequence after dynamic replacement: sessions=217, denied=[]
60 minute browser restart HTML: ALLOW
60 minute browser restart API old Cookie: 403（预期）
dynamic-only 300 signed requests: 300/300 ALLOW; 10,081.7 requests/s（本地 mock）
前端异步 XHR RFWDATA: PASS
前端同步 XHR RFWDATA: PASS
```

本次本地性能回归记录约为 dynamic-only 10,081.7 requests/s；该数据只用于版本间比较，不应直接作为生产容量承诺。

## 9. WebUI SNAP 与版本修复

SNAP 是内部累计快照，不是用户请求拒绝事件。v4.3.0 已在两个层面过滤：

1. 服务端 `/cgi-rfw/api/log` 在返回日志前解析 JSON，并移除 `attack_method == "SNAP"` 的行。
2. 日志页面的 JavaScript 渲染器再次跳过 `attack_method === 'SNAP'`，防止旧接口或缓存数据在页面显示。

原始 `logs/rfw_YYYY-MM-DD.log` 仍可保留 SNAP，用于内部统计和故障诊断；用户通过 WebUI 日志查看时不再看到 SNAP。

WebUI 版本常量已从旧值 `3.0.0` 更新为 `4.3.0`，页面品牌区域应显示：

```text
MA-RFW   v4.3.0
```

部署时必须覆盖实际 OpenResty 所加载目录中的 `webui.lua`。如果页面仍显示 `V3.0.0`，说明运行中的 WebUI 仍是旧文件、旧 worker 尚未重载，或请求命中了另一份插件目录。

## 10. 生产部署风险与建议

| 风险 | 等级 | 说明 | 建议 |
|---|---|---|---|
| Cookie fallback 被重新开启 | 中 | 只有显式打开后，无 RFWDATA 请求才可能凭有效 dynamic Cookie 进入校验链 | 灰度默认保持关闭；如临时开启必须设置期限并监控比例 |
| debug 被重新打开 | 高 | 403 debug panel 可能返回较详细的校验诊断；不适合生产 | 灰度和生产保持 `false` |
| 真实 secret 曾被共享 | 高 | 共享/附件传播后不应继续视为保密 | 立即轮换 secret；dynamic 模式也建议同步清理旧配置 |
| WebUI 管理面暴露 | 中 | 配置、日志和 token 端点属于高敏感管理面 | 保持 `admin_whitelist`，反代只信任明确配置的代理 IP，优先 HTTPS |
| 统计历史污染 | 低 | `signed_ok`、`cookie_ok` 等可能跨重启持久化 | 部署新版本后备份并重置或记录统计基线 |
| SNAP 原始日志保留 | 低 | WebUI 已隐藏，但磁盘文件仍可能包含快照 | 按日志保留周期和访问权限保护原始日志 |

v4.3.0 灰度配置已将 `debug` 设为 `false`，避免生产返回过多诊断细节。生产配置建议至少为：

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

## 11. 结论

在当前代码和测试证据范围内，v4.3.0 已达到灰度高安全基线：dynamic-only、RFWDATA-only 默认策略、同步/异步 XHR 均可签名、删除 RFWDATA 或 `_RFW` 均不能绕过、static/legacy 兼容关闭、Controller/.do 不接受文档头伪造、重放和篡改测试通过，WebUI 已隐藏 SNAP 并显示 v4.3.0。

该结论不表示系统可以替代 HTTPS、后端业务鉴权、账号权限控制、日志访问控制或独立渗透测试。生产上线后应重点观察三项指标：**RFWDATA 签名比例、Cookie fallback 比例、`sign-ratio-low`/`dynamic-sign-missing` 拒绝原因**。如果修复后的生产环境仍长期出现“签名 1 次、Cookie 兜底大量增加”，应立即检查实际加载的 JS/Lua 版本和统计基线，而不要把它视为正常流量。
