# MA-RFW v3.0.0 — MoeArt Replay Firewall

MoeArt Inc, MA-SEC Team

针对浏览器内嵌前端(非 SSR)的接口重放/伪造攻击。前端 `rfw.js` 对每个同源请求做
HMAC-SHA256 签名, nginx 侧 `ma_rfw.lua` 严格校验; 无签名请求走行为兜底
(cookie 签名 + 会话序列号 + 相同请求指纹 + 覆盖率判定), 支持按 IP 记失败并封禁。

**存储后端**: `ngx.shared.DICT`(nginx 共享内存)——零网络开销、零外部依赖、
跨 worker 共享、原子 `add()`、LRU 自动淘汰。nginx.conf 必须声明:

```nginx
lua_shared_dict rfw 64m;
```

## 文件结构

| 文件 | 说明 |
| --- | --- |
| `ma_rfw.lua` | 主插件(访问阶段校验 + 日志阶段记失败), 每个 worker 只加载一次并缓存到 `_G` |
| `config.lua` | 全部配置(密钥、阈值、状态页开关等) |
| `sha256.lua` | 纯 Lua SHA256 / HMAC-SHA256, 含 `hmac_prepare` 密钥预计算(零外部依赖) |
| `status.lua` | `/cgi-rfw/status` 状态页(HTML 表格), 缺失时主插件自动降级为纯文本提示 |
| `blocked.html` | 封禁/拒绝时返回的 403 页面 |
| `rfw.js` | 前端签名拦截器(覆盖 `fetch` 与 `XMLHttpRequest`, 同步 XHR 跳过) |
| `example/nginx-sign.conf` | nginx 部署示例(注入 `rfw.js` + 挂载插件) |
| `example/verify_backend.py` | 后端独立验签示例(可选) |
| `init.lua.example` | init 阶段加载示例(复制为 `init.lua`) |
| `access.lua.example` | access 阶段入口示例(复制为 `access.lua`) |
| `tools/` | LuaJIT21(lupa) 语法检查、逻辑测试、HMAC 基准 |

## 工作原理

### 1. 签名请求(优先)

前端每请求生成 `RFWDATA = ts.nonce.sign`, nginx 严格校验:

```
sign = HMAC-SHA256(secret, METHOD|request_uri|sha256hex(body)|ts|nonce)
```

校验链: `ts` 时效(`sign_window`) → `nonce` 一次性(ngx.shared.DICT `add` 原子去重)
→ `body` 哈希 → HMAC 比对(常量时间)。任一失败 → 403 + 记失败, 窗口内满
`fail_max` 次封禁 IP `block_time` 秒。

插件为只读校验, 通过后不修改请求: `RFWDATA` 头与 `_RFW` cookie 原样转发上游,
后端可见(需二次确认时参考 `example/verify_backend.py`)。

### 2. 无签名请求(行为兜底)

- 按 IP 统计签名占比, 低于 `sign_ratio_min` 且达到 `sign_ratio_req` → 非浏览器 → 拦截;
  比例命中是软信号: 默认只拦当前请求、不累计封禁(`sign_ratio_fail=false`),
  避免正常用户页面加载中的偶发未签名请求把 IP 拖进封禁;
- 其余(iframe/老客户端)校验 `_RFW` cookie: HMAC 签名 + **ts 新鲜度** + 单调会话序号
  (`seq_slack` 容差并行请求) + 相同请求指纹重放检测 + cookie 覆盖率判定;
- **带有效 RFWDATA 的请求完全跳过 `_RFW`**: RFWDATA 自身已具备 nonce 一次性 + ts 时效 +
  HMAC 完整性三层防重放, `_RFW` 运动 Token 只服务于无签名路径。有效签名请求不进入
  无 cookie 配额、cookie 覆盖率、ts/seq/同值次数等任何 cookie 校验(且不消费配额)。
  例外: 若 IP 已被无 cookie 配额等**硬封禁**, 封禁检查先于签名校验, 保持封禁;

### 2.1 `_RFW` 运动 Token(纯 JS 源)

- **rfw.js 是唯一签发源**: 页面内 timer 每 ~150-250ms **读后自增**重签一个新值
  (`<sig>.<sid>.<seq>.<ts_ms>`, 读当前值→`seq=max(读到的,本地)+1`→重签), 多标签页共享
  cookie jar 也不回退 seq; 需在 `visibilitychange`/`focus`/`pageshow` 时立即补刷一次
  (后台标签页定时器被浏览器降频, 回前台不补刷会带旧值);
- **服务器不再续期**: 有效 cookie 路径一律不回发 Set-Cookie; 值过期/过旧即拒, 客户端
  靠 rfw.js 下次刷新自愈;
- `cookie_bootstrap=true`(默认)时首次无 cookie 动态请求由服务器下发一次**非 HttpOnly**
  初始值供 rfw.js 读后接管——它同时是**非 JS 工具(Reqable 等, 只存 Set-Cookie 不存 JS
  写入的值)的诱饵**: 拿到一个永不刷新的值, 同值次数或 ts 超限后必被拒; `false` = 纯
  JS 源, 服务器零下发(此类工具退回无 cookie 桶, 只靠配额/比例层兜底);
- 服务器校验链(有 cookie 时): 格式+HMAC → **ts 新鲜度** `cookie_ts_max`(60s, 核心闸门,
  JS 刷新的正常值恒 <1s, 被抓值秒级后即成旧值) → 同值并行宽限 `cookie_replay_window`
  (页面加载的并行请求在同一刷新间隔内共享一个值) → 窗口外同值次数 `cookie_replay_max`
  → seq 单调 `seq_slack`(rfw.js 每秒自增 ~10, 旧值重放秒级撞线)。任一失败 403 + 记失败,
  满 `fail_max` 封禁。
- 请求完整性校验与 cookie 解耦: cookie 只负责"每请求尽量唯一的 token + ts 新鲜度",
  请求是否被修改由 `RFWDATA` 头负责(见上); 无 header 也无法验证, 只能放行。

### 3. 静态资源

`<script>/<link>/<img>` 等浏览器标签加载的请求天然无签名。判定规则:
GET/HEAD 且未带 `RFWDATA` 签名头、且扩展名在静态表 → 静态, 不参与签名/比例统计,
只做封禁检查后放行。带签名头的请求(含静态扩展名下载)一律按动态严格校验;
扩展名优先于 URI 前缀, 避免 SPA 的 js/css/图片把签名占比拉低导致误判。

## 状态页

访问 `GET /cgi-rfw/status` 返回 HTML 表格(由插件内直接拦截, 独立放行,
无需额外 location, 不参与任何校验/统计):

- **总览**: 版本号、后端类型(`lua_shared_dict`)、运行时长、请求总数、最近速率、
  签名/cookie/静态放行数、封禁命中/次数、失败累计、缓存条数等(本 worker 累计);
- **拒绝原因**: 最近窗口(清扫间隔)内各拒绝原因计数;
- **封禁 IP**: 本 worker 签发的封禁(IP、封禁时间、解封时间、剩余时长、原因:
  `fail-max` / `cookie-missing-quota` / 触发封禁的最后一个拒绝原因)。

`config.status_enabled = false` 可关闭。建议只在内网/本机访问。

## 性能优化

1. **HMAC 密钥预计算**: secret 固定时 `ipad/opad` 只在模块加载时算一次
   (`sha256.lua:hmac_prepare`), 纯 Lua 兜底路径每签名请求不再重复扩展密钥;
2. **静态分类查表化**: 扩展名集合/API 前缀预计算, `is_static` 从循环匹配降为查表;
3. **会话序号内存缓存**(`seq_cache_ttl`, 默认 3s): cookie 路径最常见的"读序号+写序号"
   不再打后端, 仅后台定时修剪并计数;
4. **热路径局部化**: `ngx.time / ngx.now / ngx.var / ngx.req / config` 常用字段与
   worker pid 一次性缓存, 减少 C 边界调用;
5. **状态计数内存自增**: 无锁、无 I/O, `/cgi-rfw/status` 直接读取, 热路径代价趋近于零。

基准(本机 LuaJIT2.1, 见 `tools/bench_hmac.py`): `hmac` 单次签名约 12.8µs,
`hmac_prepare` 约 11.5µs。纯 Lua 路径的 SHA256 计算仍占大头, 若部署了
`lua-resty-openssl` 会自动走 FFI 更快实现。

## 配置说明(节选, 详见 config.lua)

| 配置 | 默认 | 说明 |
| --- | --- | --- |
| `secret` | - | 共享密钥, 与 `rfw.js` 一致, 泄露必须更换 |
| `shared_dict.dict_name` | `rfw` | nginx 共享内存字典名(需与 nginx.conf `lua_shared_dict` 一致) |
| `shared_dict.key_prefix` | `rfw:` | 键前缀, 避免与其它模块冲突 |
| `sign_window` | 60 | 签名 ts 时效窗口(秒) |
| `sign_ratio_req/min` | 10 / 0.5 | 签名占比判定阈值 |
| `seq_slack` / `seq_ttl` / `seq_cache_ttl` | 10 / 86400 / 3 | 会话序号容差 / 保留期 / 内存缓存秒数(0=关) |
| `cookie_missing_max` / `cookie_missing_ttl` | 50 / 86400 | 单 IP 一天内无 cookie 请求配额, 超限直接封禁(0=关) / 计数窗口秒数 |
| `cookie_ts_max` | 60 | `_RFW` 出示值 ts 新鲜度上限(秒): 0=关闭 |
| `cookie_bootstrap` | true | 首次无 cookie 动态请求是否由服务器下发初始值供 rfw.js 接管; false=纯 JS 源零下发 |
| `cookie_replay_window` | 2 | 同值并行宽限(秒); 0=关闭 |
| `cookie_replay_max` | 5 | 窗口外同值可消费次数; 0=关闭 |
| `replay_enabled` / `replay_threshold` / `replay_relink_sec` | true / 5 / 2 | 相同请求重放检测与阈值 / 二次校验放行窗口秒数 |
| `fail_max` / `fail_window` / `block_time` | 5 / 60 / 600 | 惩罚参数 |
| `block_cache_ttl` | 60 | 封禁状态内存缓存 TTL(秒) |
| `sweep_interval` | 60 | 清扫/统计窗口(秒) |
| `status_enabled` / `status_path` | true / `/cgi-rfw/status` | 状态页开关与路径 |

## 运维提醒

生产必须保持 `lua_code_cache on`(见 `example/nginx-sign.conf` 顶部注释)。
若误配为 `off`, 每个请求都会重新加载插件: 窗口/封禁等内存状态全部失效、
重复注册后台定时器。排查路径:

1. nginx 配置确认 `lua_code_cache on;` 并 `nginx -s reload`;
2. 确认 `lua_shared_dict rfw 64m;` 已声明(缺失时插件返回 403 并记录错误日志);
3. 检查共享内存使用: `curl http://127.0.0.1/nginx_status` 或查看 error log。

## 部署(全局插件模式, 推荐)

与本机其它插件统一走 `init_by_lua_file` + `access_by_lua_file`:

1. 把插件文件覆盖到插件目录:
   `ma_rfw.lua / config.lua / sha256.lua / status.lua / blocked.html`;
2. nginx.conf 的 `http` 块添加:
   ```nginx
   lua_shared_dict rfw 64m;
   lua_package_path /path/to/replayfirewall/?.lua;;;
   lua_code_cache on;
   ```
3. `init.lua.example` 复制为 `init.lua`: 只 `require("ma_rfw")` 一次 ——
   init 阶段只做纯 Lua 初始化, 不碰请求上下文、不注册定时器(首个请求才惰性启动);
4. `access.lua.example` 复制为 `access.lua`: 只有一行 `ma_rfw.check()` ——
   `$rfw_on` 标记判定全部在插件 `run()` 内部完成;
5. 在要保护的位置加标记(nginx.conf): 整站 `server` 块 `set $rfw_on 1;`, 或只加在
   某个 `location` 里(如 `location /api/ { set $rfw_on 1; ... }`)。
   注意: 内部 proxy_pass 落点不要打标记, 否则同一请求会被处理两遍,
   第二遍 nonce 已被消费 → 误判 `sign-replay`;
6. 移除所有旧的 location 级 `access_by_lua_file` 直挂(残留直挂易在内部 proxy_pass 时二次触发);
7. `nginx -t && nginx -s reload`。

> 全局插件模式下, 插件模块每个 worker 只加载一次, `access.lua` 只需一行
> `ma_rfw.check()`, 生效范围由插件内部的 `$rfw_on` 标记集中控制。

## 部署(单 location 直挂, 兼容方式)

按 `example/nginx-sign.conf` 配置: 在目标 server 挂 `access_by_lua_file`, 用
`sub_filter` 向 HTML 注入 `<script src="/rfw.js">`, 保证 `rfw.js` 与 `config.lua`
的 `secret` 一致; 此模式下只处理挂了该指令的 location——且该 location 仍要打
`set $rfw_on 1;`(插件 `run()` 内部会检查标记)。

## 测试

```
python tools/check_syntax.py          # Lua 语法 + BOM 检查
python tools/test_load.py             # 模块加载/状态页路由/作用域泄漏 冒烟
python tools/test_global.py           # init.lua require + access.lua check() + $rfw_on 标记门
python tools/test_real_request.py     # 签名/重放链路
python tools/test_static.py           # 静态/动态分类
python tools/test_status.py           # 状态页渲染冒烟
python tools/test_cookie_missing.py   # 无 cookie 日配额: 超限封禁
python tools/test_cookie_replay.py    # _RFW 运动 Token: ts 新鲜度/同值次数/seq 单调
python tools/test_cookie_nobootstrap.py # 纯 JS 源(bootstrap=false): 零下发 + 配额兜底
python tools/bench_hmac.py            # HMAC 预计算基准
```

## 安全注意

- 密钥泄露即失效: 更换后需同步修改 `config.lua` 与 `rfw.js`;
- `seq_cache_ttl` 越大性能越好但重放容忍窗口越大, 生产建议 1–3 秒;
- 状态页含本 worker 计数, 建议仅内网访问;
- `lua_shared_dict` 大小建议 64m(默认), 高流量站点可按需增大。
