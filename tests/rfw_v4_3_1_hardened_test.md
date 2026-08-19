# RFW v4.3.1 统一测试报告

总检查 **49**；通过 **49**；失败 **0**；跳过 **0**。

| 套件 | 检查项 | 观察 | 期望 | 状态 | 说明 |
|---|---|---:|---:|---|---|
| dynamic | valid dynamic RFWDATA | `ALLOW` | `ALLOW` | **PASS** | current key + HMAC + nonce |
| dynamic | delete _RFW does not bypass valid RFWDATA | `ALLOW` | `ALLOW` | **PASS** | Header credential remains sufficient |
| dynamic | delete RFWDATA with Cookie is rejected | `403` | `403` | **PASS** | RFWDATA-only gray-release profile |
| dynamic | delete RFWDATA and _RFW is rejected | `403` | `403` | **PASS** | dynamic strict gate |
| dynamic | body tamper | `403` | `403` | **PASS** | body hash mismatch |
| dynamic | URI tamper | `403` | `403` | **PASS** | signed URI mismatch |
| dynamic | method tamper | `403` | `403` | **PASS** | signed method mismatch |
| dynamic | old static secret RFWDATA | `403` | `403` | **PASS** | legacy secret fallback disabled |
| dynamic | wrong IP/UA dynamic key | `403` | `403` | **PASS** | key record missing is strict deny |
| dynamic | dynamic Cookie valid on document | `ALLOW` | `ALLOW` | **PASS** | dynamic Cookie HMAC; API remains strict Header Gate |
| dynamic | Cookie fallback disabled by default | `403` | `403` | **PASS** | RFWDATA-only gray-release profile |
| dynamic | explicit Cookie fallback remains fully checked | `ALLOW` | `ALLOW` | **PASS** | opt-in compatibility only |
| dynamic | Cookie fallback rejects write method | `403` | `403` | **PASS** | headerless fallback is read-only |
| dynamic | Cookie fallback low sign ratio rejected | `403` | `403` | **PASS** | 10th unsigned Cookie fallback request reaches sign-ratio-low |
| dynamic | old static Cookie rejected | `403` | `403` | **PASS** | legacy Cookie fallback disabled |
| dynamic | Firefox/urllib document without Fetch Metadata | `ALLOW` | `ALLOW` | **PASS** | compatibility bootstrap; Set-Cookie=False |
| dynamic | API document metadata spoof rejected | `403` | `403` | **PASS** | common API path remains strict |
| dynamic | Controller .do without RFWDATA rejected | `403` | `403` | **PASS** | API/controller never document bootstrap |
| dynamic | Cookie fallback disabled remains strict | `403` | `403` | **PASS** | explicit RFWDATA-only mode |
| dynamic | non-whitelisted document path rejected | `403` | `403` | **PASS** | explicit dynamic_document_paths |
| dynamic | HTML document bootstrap without RFWDATA | `ALLOW` | `ALLOW` | **PASS** | document path allow; Cookie is token/JS generated=False |
| dynamic | strict Fetch Metadata rejects urllib-style document | `403` | `403` | **PASS** | opt-in strict compatibility boundary |
| dynamic | strict Fetch Metadata real document | `ALLOW` | `ALLOW` | **PASS** | Sec-Fetch-Dest=document |
| dynamic | fixed signing cannot be disabled | `ALLOW` | `ALLOW` | **PASS** | runtime rejects sign_enabled override |
| dynamic | static mode unavailable in gray release | `ALLOW` | `ALLOW` | **PASS** | Lua rejects key_mode=static |
| cookie | dynamic Cookie tamper | `403` | `403` | **PASS** | cookie-tampered |
| cookie | safe GET stale refresh | `ALLOW` | `ALLOW` | **PASS** | Set-Cookie=True |
| cookie | document refresh JSON does not emit Cookie | `ALLOW` | `ALLOW` | **PASS** | Set-Cookie=False |
| cookie | document refresh HTML emits Cookie | `ALLOW` | `ALLOW` | **PASS** | Set-Cookie=True |
| cookie | stale POST rejected | `403` | `403` | **PASS** | cookie-stale |
| cookie | safe GET same-value burst | `ALLOW` | `ALLOW` | **PASS** | 8 GETs allowed |
| cookie | safe GET ninth reuse rejected | `403` | `403` | **PASS** | fixed safe-method replay limit is 8 |
| cookie | strict POST sixth reuse | `403` | `403` | **PASS** | cookie-replay |
| cookie | expired key HTML rebootstrap | `ALLOW` | `ALLOW` | **PASS** | Set-Cookie=False |
| cookie | expired key API old Cookie denied | `403` | `403` | **PASS** | strict API does not rebootstrap |
| webui | dynamic token endpoint JSON | `200` | `200` | **PASS** | body keys=['cookie_document_require_fetch_metadata', 'cookie_fallback', 'cookie_tag_hex', 'cookie_ttl', 'dynamic_document_paths', 'dynamic_sign_ratio_fail', 'expires_in', 'key', 'key_mode', 'quota_exhausted', 'server_time', 'strict_sign'] |
| webui | token reports strict dynamic-only policy | `ALLOW` | `ALLOW` | **PASS** | dynamic-only/strict/fallback/tag |
| webui | version is v4.3.1 | `ALLOW` | `ALLOW` | **PASS** | WebUI brand version |
| webui | SNAP hidden in log renderer | `ALLOW` | `ALLOW` | **PASS** | frontend defensive filter |
| webui | SNAP filtered from log API | `ALLOW` | `ALLOW` | **PASS** | server-side log filter |
| webui | config page uses Chinese editable fields | `ALLOW` | `ALLOW` | **PASS** | visible=['strict-api-path-tags', 'document-path-tags', 'strict-api-path-input', 'document-path-input', 'cfg-cookie-document-require-fetch', 'help-text'], hidden_fixed=['cfg-key-mode', 'cfg-dynamic-strict-sign', 'cfg-dynamic-sign-ratio-fail', 'cfg-dynamic-allow-cookie-fallback', 'cfg-dynamic-cookie-tag-hex', 'cfg-cookie-name', 'cfg-cookie-bootstrap', 'cfg-cookie-safe-methods', 'cfg-replay-enabled'] |
| webui | config save keeps standard JSON remarks and indentation | `ALLOW` | `ALLOW` | **PASS** | fixed fields removed; standard JSON remarks and indentation preserved |
| webui | reject dynamic strict with sign disabled | `400` | `400` | **PASS** | configuration contradiction rejected |
| saz | production home document | `ALLOW` | `ALLOW` | **PASS** | old Cookie rebootstrap allowed; response Cookie=False |
| saz | production sequence after dynamic replacement | `ALLOW` | `ALLOW` | **PASS** | sessions=217, denied=[] |
| saz | 60 minute browser restart HTML | `ALLOW` | `ALLOW` | **PASS** | new Cookie=False |
| saz | 60 minute browser restart API old Cookie | `403` | `403` | **PASS** | strict dynamic API requires new RFWDATA |
| saz | static legacy profile not exercised | `ALLOW` | `ALLOW` | **PASS** | dynamic-only gray release |
| performance | dynamic-only 300 signed requests | `ALLOW` | `ALLOW` | **PASS** | elapsed=0.0299s, rps=10024.3, denied=0 |

## 运行边界

这是本地 Lua/OpenResty 核心模拟，不会向生产发送请求。`ALLOW` 只代表 RFW 层放行，不代表业务授权成功。v4.3.1 dynamic-only 严格模式要求非文档请求携带当前 dynamic RFWDATA；默认 `dynamic_allow_cookie_fallback=false`，仅在管理员显式开启、请求方法为 GET/HEAD/OPTIONS 且已有有效 dynamic `_RFW` Cookie 时进入有限 Cookie 兼容例外。安全方法同值最多 8 次，写请求始终需要 RFWDATA。

## 标准 JSON 备注与固定策略

测试工具验证标准 JSON 中的 `__COMMENT_*` 备注字段会被运行时忽略。dynamic-only、RFWDATA 严格校验、Cookie 名称、安全方法和重放检测开关等固定策略不写入配置；重新注入固定字段会被运行时拒绝。

## 性能说明

性能数字是本地 Lupa + Lua shared-dict mock 的相对基线，不代表生产 QPS。核心路径没有 shared-dict 全量扫描或 token rotate；每个动态请求最多一次 key record 读取和一次 HMAC 链。
