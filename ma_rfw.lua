-- MA-RFW (MoeArt Replay Firewall / 萌艺科技重放攻击防火墙)
-- 开发组织: 萌艺科技 MASEC 项目组 (MoeArt Inc, MA-SEC Team)
--
-- 基于请求签名的重放攻击防护模块(签名模式 + 行为兜底)。
-- 存储后端: ngx.shared.DICT (nginx 共享内存, 零网络开销, 零外部依赖)
-- nginx.conf 必须声明: lua_shared_dict rfw 64m;
--
-- 规则(优先签名校验, 无签名走行为兜底):
--   1. 请求带 RFWDATA → 严格校验: ts 时效 → nonce 一次性 → body 哈希 → HMAC 签名
--   2. 无签名请求 → 按 IP 统计签名比例, 低于阈值 → 拦截
--   3. 签名比例内的无签名请求 → 行为兜底: cookie 校验 + 重放检测
local core = _G.ma_rfw_core
if core then
    core.check()
    return
end

local _M = {}

local src = debug.getinfo(1, "S").source
local plugin_dir = (src:sub(1, 1) == "@" and src:sub(2) or src):match("^(.*)[/\\][^/\\]+$") or "."
local config = dofile(plugin_dir .. "/config.lua")
local sha = dofile(plugin_dir .. "/sha256.lua")

local status = {}
do
    local ok, mod = pcall(dofile, plugin_dir .. "/status.lua")
    if ok and type(mod) == "table" and type(mod.render) == "function" then
        status = mod
    else
        status.render = function()
            ngx.header["Content-Type"] = "text/plain; charset=utf-8"
            ngx.say("ma_rfw: status page unavailable")
            ngx.exit(ngx.HTTP_OK)
        end
    end
end

ngx.log(ngx.ERR, "ma_rfw: module loaded, plugin_dir=" .. plugin_dir)

local ngx_now  = ngx.now
local ngx_time = ngx.time
local ngx_var  = ngx.var
local ngx_req  = ngx.req
local worker_pid = (type(ngx.worker) == "table" and type(ngx.worker.pid) == "function")
    and ngx.worker.pid() or 0

-- HMAC 签名: 优先 resty.openssl.hmac(FFI), 回退 sha256.lua 纯 Lua
local sign
do
    local ok, mod = pcall(require, "resty.openssl.hmac")
    if ok then
        local secret = config.secret
        sign = function(msg)
            local m = mod.new(secret, "sha256")
            m:update(msg)
            return m:final("hex")
        end
    else
        sign = sha.hmac_prepare(config.secret)
    end
end

local COOKIE_NAME = config.cookie_name
local COOKIE_TTL  = config.cookie_ttl

local function cookie_sig(ts, nonce)
    return sign("RFW:" .. ts .. "," .. nonce):sub(1, 16)
end

local nonce_counter = 0
local function new_nonce()
    nonce_counter = nonce_counter + 1
    local t = math.floor(ngx_now() * 1000)
    return tostring(t) .. "-" .. tostring(worker_pid) .. "-" .. tostring(nonce_counter)
end

-- ===== 存储后端: ngx.shared.DICT =====
local sd_config = config.shared_dict or {}
local DICT_NAME = sd_config.dict_name or "rfw"
local MKEY_PREFIX = sd_config.key_prefix or "rfw:"

local store = ngx.shared[DICT_NAME]
if not store then
    ngx.log(ngx.ERR, "ma_rfw: ngx.shared." .. DICT_NAME .. " 不存在, " ..
        "请在 nginx.conf 添加: lua_shared_dict " .. DICT_NAME .. " 64m;")
end

local function key_for(kind, name)
    return MKEY_PREFIX .. kind .. ":" .. name
end

local function ip_key(ip)
    return ip
end

local function nonce_key(ip, nonce)
    return ip .. "|" .. nonce
end

-- ===== 状态计数 =====
local stats = {
    start_ts = os.time(),
    requests = 0,
    prev_requests = 0,
    last_rate = 0,
    signed_ok = 0,
    cookie_ok = 0,
    cookie_issued = 0,
    no_cookie_tracked = 0,
    cookie_missing = 0,
    cookie_replay = 0,
    cookie_stale = 0,
    static_ok = 0,
    blocked_hit = 0,
    failures = 0,
    blocks = 0,
    backend_fail = 0,
    track_ips = 0,
    block_cache_size = 0,
    seq_cache_size = 0,
    denied = {},
}

local PENALTY_HTML
local block_cache = {}
local block_log = {}
local initialized = false

local ratio_track = {}
local ratio_entries = 0
local sign_ratio_track = {}
local sign_ratio_entries = 0
local replay_track = {}
local replay_entries = 0
local RATIO_MAX_IP = 5000
local seq_cache = {}

local DEBUG = config.debug
local SIGN_ENABLED = config.sign_enabled
local REPLAY_ENABLED = config.replay_enabled
local BLOCK_CACHE_TTL = config.block_cache_ttl or 60
local SIGN_WINDOW = config.sign_window or 60
local SWEEP_INTERVAL = config.sweep_interval
local COOKIE_MISS_MAX = config.cookie_missing_max or 0
local MISS_TTL = config.cookie_missing_ttl or 86400
local COOKIE_TS_MAX = config.cookie_ts_max or 0
local COOKIE_BOOTSTRAP = config.cookie_bootstrap ~= false
local COOKIE_REPLAY_WINDOW = config.cookie_replay_window or 2
local COOKIE_REPLAY_MAX = config.cookie_replay_max or 5
local REPLAY_RELINK_SEC = config.replay_relink_sec or 2
local SEQ_SLACK = config.seq_slack or 10
local SEQ_TTL = config.seq_ttl or COOKIE_TTL
local SEQ_CACHE_TTL = config.seq_cache_ttl or 3

local function load_html()
    if PENALTY_HTML then return end
    local f = io.open(config.html_file, "rb")
    if f then PENALTY_HTML = f:read("*a"); f:close() end
    PENALTY_HTML = PENALTY_HTML or "<html><body><h1>403 Forbidden</h1></body></html>"
end

local detail_add, mk_detail
if DEBUG then
    detail_add = function(d, k, v) if d then d[#d + 1] = { k, v } end end
    mk_detail = function() return {} end
else
    detail_add = function() end
    mk_detail = function() return nil end
end

local function trunc(s, n)
    s = tostring(s or "")
    if #s > n then return s:sub(1, n) .. "...(" .. #s .. " bytes)" end
    return s
end

local function debug_panel(reason, detail)
    local phase = ""
    local okp, ph = pcall(ngx.get_phase)
    if okp then phase = tostring(ph) end
    local rows = {
        { "time", os.date("%Y-%m-%d %H:%M:%S", ngx_time()) },
        { "reason", tostring(reason) },
        { "phase", phase },
        { "client_ip", ngx_var.remote_addr or "" },
        { "method", ngx_req.get_method() },
        { "uri", ngx_var.uri or "" },
        { "request_uri", ngx_var.request_uri or "" },
        { "host", ngx_var.http_host or "" },
        { "http_rfwdata", trunc(ngx_var.http_rfwdata, 300) or "(nil)" },
        { "http_cookie", trunc(ngx_var.http_cookie, 500) or "(nil)" },
    }
    if detail then for i = 1, #detail do rows[#rows + 1] = detail[i] end end
    local buf = { '<div id="rfw-debug"><h3>ma_rfw debug</h3><table>' }
    for i = 1, #rows do
        local v = tostring(rows[i][2] or ""):gsub("[<>&]", { ["<"] = "&lt;", [">"] = "&gt;", ["&"] = "&amp;" })
        buf[#buf + 1] = "<tr><td class=\"k\">" .. rows[i][1] .. "</td><td>" .. v .. "</td></tr>"
    end
    buf[#buf + 1] = "</table></div>"
    return table.concat(buf)
end

local function deny(reason, detail)
    stats.denied[reason] = (stats.denied[reason] or 0) + 1
    ngx.log(ngx.ERR, "ma_rfw: deny(" .. tostring(reason) .. ") uri=" .. ngx.var.uri ..
        " ip=" .. ngx.var.remote_addr)
    load_html()
    ngx.status = ngx.HTTP_FORBIDDEN
    ngx.header["Content-Type"] = "text/html; charset=utf-8"
    if DEBUG then
        local panel = debug_panel(reason, detail)
        local pos = string.find(PENALTY_HTML, "</body>", 1, true)
        if pos then
            ngx.say(PENALTY_HTML:sub(1, pos - 1) .. panel .. PENALTY_HTML:sub(pos))
        else
            ngx.say(PENALTY_HTML .. panel)
        end
    else
        ngx.say(PENALTY_HTML)
    end
    ngx.exit(ngx.HTTP_FORBIDDEN)
end

local function set_block(ip, reason)
    local key = ip_key(ip)
    local now = ngx_time()
    local until_ts = now + config.block_time
    block_cache[key] = nil
    store:set(key_for("block", key),
        tostring(until_ts) .. "|" .. tostring(now) .. "|" .. tostring(reason or ""),
        config.block_time + 10)
    block_log[ip] = { unblock = until_ts, ban = now, reason = tostring(reason or "") }
    stats.blocks = stats.blocks + 1
end

local function is_blocked(ip)
    local key = ip_key(ip)
    local now = ngx_time()
    local c = block_cache[key]
    if c and now < c.exp then return c.blocked, c.until_ts or 0 end

    local blocked, until_ts = false, 0
    local v, _ = store:get(key_for("block", key))
    if v then
        local u, b, r = v:match("^(%d+)%|(%d+)%|(.-)$")
        if u then
            until_ts = tonumber(u)
        else
            until_ts = tonumber(v)
        end
        if until_ts then
            if until_ts > now then
                blocked = true
                block_log[ip] = {
                    unblock = until_ts,
                    ban = (b and tonumber(b)) or until_ts,
                    reason = (r and r ~= "" and r) or "unknown",
                }
            else
                store:delete(key_for("block", key))
                block_log[ip] = nil
            end
        end
    end
    block_cache[key] = { blocked = blocked, until_ts = until_ts, exp = now + BLOCK_CACHE_TTL }
    return blocked, until_ts
end

local function prune_block_log()
    local now = ngx_time()
    local oldest, oldest_ip
    for ip, e in pairs(block_log) do
        if now >= e.unblock then block_log[ip] = nil
        elseif oldest == nil or e.unblock < oldest then oldest, oldest_ip = e.unblock, ip end
    end
    local n = 0
    for _ in pairs(block_log) do n = n + 1 end
    while n > 512 and oldest_ip do
        block_log[oldest_ip] = nil
        n = n - 1
        oldest, oldest_ip = nil, nil
        for ip, e in pairs(block_log) do
            if oldest == nil or e.unblock < oldest then oldest, oldest_ip = e.unblock, ip end
        end
    end
end

local function record_failure(ip, reason)
    local key = ip_key(ip)
    local now = ngx_time()
    block_cache[key] = nil

    local path = key_for("pen", key)
    local n, first = 0, now
    local v, _ = store:get(path)
    if v then
        local a, b = v:match("^(%d+),(%d+)$")
        if a and b then first, n = tonumber(a), tonumber(b) end
    end
    if now - first > config.fail_window then n, first = 0, now end
    n = n + 1

    if n >= config.fail_max then
        set_block(ip, reason)
        store:delete(path)
    else
        store:set(path, tostring(first) .. "," .. tostring(n), config.fail_window + 10)
    end
    stats.failures = stats.failures + 1
end

local sweep
local SWEEP_SCHEDULED = false

local function schedule_sweep()
    if store then
        if not store:add("rfw_sweep_guard", 1, 86400) then return true end
    elseif SWEEP_SCHEDULED then
        return true
    end
    SWEEP_SCHEDULED = true
    return ngx.timer.at(SWEEP_INTERVAL, sweep)
end

sweep = function()
    -- 删除调度守卫键, 允许 schedule_sweep() 重新注册下一轮定时器
    if store then store:delete("rfw_sweep_guard") end
    SWEEP_SCHEDULED = false

    local req_now = stats.requests
    stats.last_rate = math.floor(((req_now - stats.prev_requests) / SWEEP_INTERVAL) * 10) / 10
    stats.prev_requests = req_now
    stats.denied = {}
    prune_block_log()

    local now = ngx_time()
    for k, c in pairs(block_cache) do
        if now >= c.exp then block_cache[k] = nil end
    end
    for k, c in pairs(seq_cache) do
        if now - c.ts >= SEQ_CACHE_TTL then seq_cache[k] = nil end
    end
    stats.track_ips = sign_ratio_entries
    stats.block_cache_size = 0
    for _ in pairs(block_cache) do stats.block_cache_size = stats.block_cache_size + 1 end
    stats.seq_cache_size = 0
    for _ in pairs(seq_cache) do stats.seq_cache_size = stats.seq_cache_size + 1 end

    ratio_track = {}; ratio_entries = 0
    replay_track = {}; replay_entries = 0
    sign_ratio_track = {}; sign_ratio_entries = 0
    schedule_sweep()
end

local function get_cookie_value(name)
    local c = ngx_var.http_cookie
    if not c then return nil end
    local last = nil
    for part in c:gmatch("[^;]+") do
        local k, v = part:match("^%s*([%w_%-]+)%s*=%s*(.*)%s*$")
        if k and v and k == name then last = v end
    end
    return last
end

local function read_seq(sid)
    local now = ngx_time()
    local c = seq_cache[sid]
    if c and now - c.ts < SEQ_CACHE_TTL then
        return c.highest, c.last_seq, c.last_ts, c.last_first, c.count
    end
    seq_cache[sid] = nil
    local v, _ = store:get(key_for("seq", sid))
    if not v then return nil end
    local a, b, ls, lt, lf, lc = v:match("^(%d+),(%d+),(%d+),(%d+),(%d+),(%d+)$")
    if a and b then
        local h = tonumber(b)
        seq_cache[sid] = { ts = now, highest = h, last_seq = tonumber(ls),
                           last_ts = tonumber(lt), last_first = tonumber(lf),
                           count = tonumber(lc) or 1 }
        return h, tonumber(ls), tonumber(lt), tonumber(lf), tonumber(lc) or 1
    end
    local a2, b2, ls2, lt2, lf2 = v:match("^(%d+),(%d+),(%d+),(%d+),(%d+)$")
    if a2 and b2 then
        local h = tonumber(b2)
        seq_cache[sid] = { ts = now, highest = h, last_seq = tonumber(ls2),
                           last_ts = tonumber(lt2), last_first = tonumber(lf2), count = 1 }
        return h, tonumber(ls2), tonumber(lt2), tonumber(lf2), 1
    end
    local a3, b3 = v:match("^(%d+),(%d+)$")
    if a3 and b3 then
        seq_cache[sid] = { ts = now, highest = tonumber(b3), last_seq = nil, last_ts = nil, last_first = nil }
        return tonumber(b3), nil, nil, nil
    end
    return nil
end

local function write_seq(sid, ts, highest, last_seq, last_ts, last_first, count)
    seq_cache[sid] = { ts = ngx_time(), highest = highest,
                       last_seq = last_seq, last_ts = last_ts,
                       last_first = last_first, count = count }
    local v = tostring(ts) .. "," .. tostring(highest)
    if last_seq ~= nil then
        v = v .. "," .. tostring(last_seq) .. "," .. tostring(last_ts)
             .. "," .. tostring(last_first) .. "," .. tostring(count or 1)
    end
    store:set(key_for("seq", sid), v, SEQ_TTL + 10)
end

local function cookie_sig2(sid, seq, ts)
    return sign("RFW:" .. sid .. "," .. seq .. "," .. ts):sub(1, 16)
end

local function set_cookie_value(sid, seq, ts)
    local v = cookie_sig2(sid, tostring(seq), tostring(ts)) .. "." .. sid .. "." ..
        tostring(seq) .. "." .. tostring(ts)
    ngx.header["Set-Cookie"] = COOKIE_NAME .. "=" .. v ..
        "; Path=/; SameSite=Lax; Max-Age=" .. tostring(COOKIE_TTL)
end

local function cookie_missing_track(ip)
    if COOKIE_MISS_MAX <= 0 then return true end
    stats.no_cookie_tracked = stats.no_cookie_tracked + 1
    local now = ngx_time()
    local key = ip_key(ip)
    local path = key_for("miss", key)
    local n, first = 0, now
    local v, _ = store:get(path)
    if v then
        local a, b = v:match("^(%d+),(%d+)$")
        if a and b then first, n = tonumber(a), tonumber(b) end
        if now - first > MISS_TTL then first, n = now, 0 end
    end
    n = n + 1
    if n > COOKIE_MISS_MAX then
        set_block(ip, "cookie-missing-quota")
        store:delete(path)
        stats.cookie_missing = stats.cookie_missing + 1
        return false
    end
    store:set(path, tostring(first) .. "," .. tostring(n), MISS_TTL + 10)
    return true
end

local function issue_cookie()
    local sid = new_nonce()
    local ts = math.floor(ngx_now() * 1000)
    write_seq(sid, ts, 1)
    set_cookie_value(sid, 1, ts)
    return sid, 1, ts
end

local function track_cookie(ip, has_ok)
    local key = ip_key(ip)
    local t = ratio_track[key]
    if not t then
        if ratio_entries >= RATIO_MAX_IP then
            ratio_track = {}; ratio_entries = 0
        end
        t = { ok = 0, total = 0 }
        ratio_track[key] = t
        ratio_entries = ratio_entries + 1
    end
    t.total = t.total + 1
    if has_ok then t.ok = t.ok + 1 end

    if t.total >= config.cookie_ratio_req
       and (t.ok / t.total) < config.cookie_ratio_min then
        local okc, tot = t.ok, t.total
        ratio_track[key] = nil
        ratio_entries = ratio_entries - 1
        if config.cookie_ratio_fail then record_failure(ip, "cookie-ratio-low") end
        return true, okc, tot
    end
    return false
end

local function get_body()
    ngx_req.read_body()
    local body = ngx_req.get_body_data()
    if not body then
        local bf = ngx_req.get_body_file()
        if bf then
            local f = io.open(bf, "rb")
            if f then body = f:read("*a"); f:close() else body = "" end
        else
            body = ""
        end
    end
    return body or ""
end

local function ct_eq(a, b)
    if type(a) ~= "string" or type(b) ~= "string" or #a ~= #b then return false end
    local r = 0
    for i = 1, #a do r = r + (a:byte(i) == b:byte(i) and 0 or 1) end
    return r == 0
end

local function signed_uri()
    local uri = ngx_var.request_uri or ""
    if uri:match("%?$") then uri = uri:sub(1, -2) end
    return uri
end

local function check_nonce(ip, nonce, method, uri)
    local key = key_for("nonce", nonce_key(ip, nonce))
    local now = ngx_time()
    local ok, _ = store:add(key, tostring(now) .. "|" .. tostring(method) .. "|" .. tostring(uri), SIGN_WINDOW + 10)
    if ok then return true end
    local v, _ = store:get(key)
    if v then
        local t0, m0, u0 = v:match("^([%d]+)|(.-)|(.*)$")
        if t0 and m0 == method and u0 == uri and (now - tonumber(t0)) <= REPLAY_RELINK_SEC then
            return true
        end
    end
    return false
end

local function track_sign_ratio(ip, has_signed)
    local key = ip_key(ip)
    local t = sign_ratio_track[key]
    if not t then
        if sign_ratio_entries >= RATIO_MAX_IP then
            sign_ratio_track = {}; sign_ratio_entries = 0
        end
        t = { ok = 0, total = 0 }
        sign_ratio_track[key] = t
        sign_ratio_entries = sign_ratio_entries + 1
    end
    t.total = t.total + 1
    if has_signed then t.ok = t.ok + 1 end

    local req = config.sign_ratio_req or 10
    local min = config.sign_ratio_min or 0.5
    if t.total >= req and (t.ok / t.total) < min then
        local okc, tot = t.ok, t.total
        sign_ratio_track[key] = nil
        sign_ratio_entries = sign_ratio_entries - 1
        if config.sign_ratio_fail then record_failure(ip, "sign-ratio-low") end
        return true, okc, tot
    end
    return false
end

local static_ext_set = {}
do
    for _, e in ipairs(config.static_ext or {}) do static_ext_set[e] = true end
end

local function is_static()
    local m = ngx_req.get_method()
    if m ~= "GET" and m ~= "HEAD" then return false end
    if ngx_var.http_rfwdata then return false end
    local u = ngx_var.uri or ""
    local ext = u:match("(%.[%w]+)$")
    if ext then return static_ext_set[ext:lower()] == true end
    return false
end

local function verify_sign()
    local ip = ngx_var.remote_addr or ""
    local raw = ngx_var.http_rfwdata
    local d = DEBUG and {} or nil
    detail_add(d, "RFWDATA", raw or "")
    detail_add(d, "method", ngx_req.get_method())
    detail_add(d, "request_uri", ngx_var.request_uri or "")
    if not raw then
        record_failure(ip, "sign-headers-missing")
        return deny("sign-headers-missing", d)
    end

    local t, nonce, sig = raw:match("^(%d+)%.([%w%-]+)%.([%x]+)$")
    detail_add(d, "parsed_ts", t or "")
    detail_add(d, "parsed_nonce", nonce or "")
    detail_add(d, "parsed_sig", sig or "")
    if not t or not nonce or not sig then
        record_failure(ip, "sign-format")
        return deny("sign-format", d)
    end

    local now = ngx_time()
    detail_add(d, "now", tostring(now))
    detail_add(d, "ts_delta", tostring(now - tonumber(t)))
    if math.abs(now - tonumber(t)) > SIGN_WINDOW then
        record_failure(ip, "sign-expired")
        return deny("sign-expired", d)
    end

    local m = ngx_req.get_method()
    local uri = signed_uri()

    if not check_nonce(ip, nonce, m, uri) then
        local v, _ = store:get(key_for("nonce", nonce_key(ip, nonce)))
        local first_seen_ts, owner_m, owner_uri = 0, "", ""
        if v then
            first_seen_ts, owner_m, owner_uri = v:match("^([%d]+)|(.-)|(.*)$")
            first_seen_ts = tonumber(first_seen_ts) or 0
        end
        detail_add(d, "first_seen_ts", tostring(first_seen_ts))
        detail_add(d, "age_s", tostring(now - first_seen_ts))
        detail_add(d, "owner_method", tostring(owner_m))
        detail_add(d, "owner_uri", tostring(owner_uri))
        record_failure(ip, "sign-replay")
        return deny("sign-replay", d)
    end

    local body = get_body()
    local bh = sha.hex(body)
    local expected = sign(m .. "|" .. uri .. "|" .. bh .. "|" .. t .. "|" .. nonce)

    detail_add(d, "signing_uri", uri)
    detail_add(d, "body_sha256", bh)
    detail_add(d, "expected_hmac", expected)
    detail_add(d, "actual_sig", sig)

    if not ct_eq(expected, sig) then
        record_failure(ip, "sign-invalid")
        return deny("sign-invalid", d)
    end

    local r, okc, tot = track_sign_ratio(ip, true)
    if r then
        detail_add(d, "signed_in_window", tostring(okc))
        detail_add(d, "total_in_window", tostring(tot))
        return deny("sign-ratio-low", d)
    end
    stats.signed_ok = stats.signed_ok + 1
    if DEBUG then ngx.log(ngx.ERR, "ma_rfw: sign ok method=" .. m .. " uri=" .. uri) end
    return nil
end

function _M.run()
    local uri = ngx_var.uri

    if config.status_enabled ~= false and uri == config.status_path then
        prune_block_log()
        return status.render(config, stats, nil, sd_config, block_log)
    end

    if (ngx_var.rfw_on or "") ~= "1" then return end

    local ctx = ngx.ctx
    if ctx then
        if ctx.rfw_running then return end
        ctx.rfw_running = true
    end
    if DEBUG then ngx.log(ngx.ERR, "ma_rfw: enter uri=" .. uri) end

    stats.requests = stats.requests + 1

    if not config.secret then return deny("no-secret") end

    if not initialized then
        initialized = true
        if not schedule_sweep() then initialized = false end
    end

    if not store then
        stats.backend_fail = (stats.backend_fail or 0) + 1
        return deny("backend-unreachable")
    end

    local ip = ngx_var.remote_addr or ""
    local blocked, buntil = is_blocked(ip)
    if blocked then
        stats.blocked_hit = stats.blocked_hit + 1
        local d = mk_detail()
        detail_add(d, "block_until_ts", tostring(buntil or 0))
        detail_add(d, "remaining_s", tostring(math.max(0, (buntil or 0) - ngx_time())))
        return deny("blocked", d)
    end

    if is_static() then
        stats.static_ok = stats.static_ok + 1
        return
    end

    if SIGN_ENABLED and ngx_var.http_rfwdata then
        return verify_sign()
    end

    if COOKIE_MISS_MAX > 0 and not get_cookie_value(COOKIE_NAME) then
        if not cookie_missing_track(ip) then
            local d = mk_detail()
            detail_add(d, "daily_missing_max", tostring(COOKIE_MISS_MAX))
            return deny("cookie-missing-ban", d)
        end
    end

    local sr, srok, srtot = track_sign_ratio(ip, false)
    if sr then
        local d = mk_detail()
        detail_add(d, "signed_in_window", tostring(srok))
        detail_add(d, "total_in_window", tostring(srtot))
        return deny("sign-ratio-low", d)
    end

    if REPLAY_ENABLED then
        local m = ngx_req.get_method()
        if m == "POST" or m == "PUT" or m == "PATCH" or m == "DELETE" then
            local body = get_body()
            local fp = sha.hex(m .. "\0" .. (ngx_var.request_uri or "") .. "\0" .. body)
            local key = ip_key(ip)
            local t = replay_track[key]
            if not t then
                if replay_entries >= RATIO_MAX_IP then
                    replay_track = {}; replay_entries = 0
                end
                t = {}
                replay_track[key] = t
                replay_entries = replay_entries + 1
            end
            t[fp] = (t[fp] or 0) + 1
            if t[fp] >= config.replay_threshold then
                replay_track[key] = nil
                replay_entries = replay_entries - 1
                record_failure(ip, "request-replay")
                local d = mk_detail()
                detail_add(d, "fingerprint_sha256", fp)
                detail_add(d, "repeat_count", tostring(t[fp]))
                detail_add(d, "threshold", tostring(config.replay_threshold))
                return deny("request-replay", d)
            end
        end
    end

    local v = get_cookie_value(COOKIE_NAME)
    if not v then
        if COOKIE_BOOTSTRAP then
            issue_cookie()
            stats.cookie_issued = stats.cookie_issued + 1
        end
        local r, okc, tot = track_cookie(ip, false)
        if r then
            local d = mk_detail()
            detail_add(d, "cookie_ok_in_window", tostring(okc))
            detail_add(d, "total_in_window", tostring(tot))
            return deny("cookie-ratio-low", d)
        end
        return
    end

    local now_ms = math.floor(ngx_now() * 1000)
    local now = ngx_time()

    local sig, sid, seqs, tss = v:match("^([%x]+)%.([%w%-]+)%.([%d]+)%.([%d]+)$")
    if sig then
        local t = tonumber(tss)
        if not t or cookie_sig2(sid, seqs, tss) ~= sig:lower() then
            record_failure(ip, "cookie-tampered")
            local d = mk_detail()
            detail_add(d, "cookie_value", v)
            detail_add(d, "sid", sid or "")
            return deny("cookie-tampered", d)
        end

        local age_ms
        if t >= 100000000000 then
            age_ms = now_ms - t
        else
            age_ms = (now - t) * 1000
        end
        if COOKIE_TS_MAX > 0 and age_ms > COOKIE_TS_MAX * 1000 then
            record_failure(ip, "cookie-stale")
            stats.cookie_stale = stats.cookie_stale + 1
            if COOKIE_BOOTSTRAP and t < 100000000000 then
                issue_cookie()
                stats.cookie_issued = stats.cookie_issued + 1
            end
            local d = mk_detail()
            detail_add(d, "sid", sid or "")
            detail_add(d, "req_ts", tss or "")
            detail_add(d, "ts_age_ms", tostring(age_ms))
            return deny("cookie-stale", d)
        end

        local seq = tonumber(seqs)
        local highest, last_seq, last_ts, last_first, last_count = read_seq(sid)
        if last_seq ~= nil and last_ts ~= nil and last_seq == seq and last_ts == t then
            if COOKIE_REPLAY_WINDOW > 0 and now_ms - last_first <= COOKIE_REPLAY_WINDOW * 1000 then
                local r, okc, tot = track_cookie(ip, true)
                if r then
                    local d = mk_detail()
                    detail_add(d, "cookie_ok_in_window", tostring(okc))
                    detail_add(d, "total_in_window", tostring(tot))
                    return deny("cookie-ratio-low", d)
                end
                stats.cookie_ok = stats.cookie_ok + 1
                return
            end
            local cnt = (last_count or 1) + 1
            if COOKIE_REPLAY_MAX > 0 and cnt > COOKIE_REPLAY_MAX then
                record_failure(ip, "cookie-replay")
                stats.cookie_replay = stats.cookie_replay + 1
                local d = mk_detail()
                detail_add(d, "sid", sid or "")
                detail_add(d, "replay_count", tostring(cnt))
                return deny("cookie-replay", d)
            end
            write_seq(sid, now, highest or 0, seq, t, last_first, cnt)
            local r, okc, tot = track_cookie(ip, true)
            if r then
                local d = mk_detail()
                detail_add(d, "cookie_ok_in_window", tostring(okc))
                detail_add(d, "total_in_window", tostring(tot))
                return deny("cookie-ratio-low", d)
            end
            stats.cookie_ok = stats.cookie_ok + 1
            return
        end

        if highest and seq < highest - SEQ_SLACK then
            record_failure(ip, "request-replay")
            local d = mk_detail()
            detail_add(d, "sid", sid or "")
            detail_add(d, "req_seq", seqs or "")
            detail_add(d, "highest_seq", tostring(highest))
            return deny("request-replay", d)
        end

        write_seq(sid, now, math.max(highest or 0, seq), seq, t, now_ms, 1)
        local r, okc, tot = track_cookie(ip, true)
        if r then
            local d = mk_detail()
            detail_add(d, "cookie_ok_in_window", tostring(okc))
            detail_add(d, "total_in_window", tostring(tot))
            return deny("cookie-ratio-low", d)
        end
        stats.cookie_ok = stats.cookie_ok + 1
        if DEBUG then ngx.log(ngx.ERR, "ma_rfw: cookie ok seq=" .. seq .. " uri=" .. uri) end
        return
    end

    local sig0, ts0, nonce0 = v:match("^([%x]+)%.([%d]+)%.([%w%-]+)$")
    if sig0 then
        local t = tonumber(ts0)
        if t and cookie_sig(ts0, nonce0) == sig0:lower() then
            issue_cookie()
            stats.cookie_issued = stats.cookie_issued + 1
            local r, okc, tot = track_cookie(ip, false)
            if r then
                local d = mk_detail()
                detail_add(d, "cookie_ok_in_window", tostring(okc))
                detail_add(d, "total_in_window", tostring(tot))
                return deny("cookie-ratio-low", d)
            end
            return
        end
        record_failure(ip, "cookie-tampered")
        local d = mk_detail()
        detail_add(d, "cookie_value", v)
        return deny("cookie-tampered", d)
    end

    record_failure(ip, "cookie-tampered")
    local d = mk_detail()
    detail_add(d, "cookie_value", v)
    return deny("cookie-tampered", d)
end

function _M.check()
    _M.run()
    return true
end

function _M.on_log()
    if not config.app_fail_enabled or not store then return end
    local status = ngx.status
    local hit = false
    for _, s in ipairs(config.app_fail_statuses or {}) do
        if status == s then hit = true; break end
    end
    if not hit then return end
    local uri = ngx.var.uri or ""
    local paths = config.app_fail_paths or {}
    if #paths > 0 then
        local matched = false
        for _, p in ipairs(paths) do
            if uri:sub(1, #p) == p then matched = true; break end
        end
        if not matched then return end
    end
    record_failure(ngx.var.remote_addr or "", "app-fail")
end

_G.ma_rfw_core = _M

local ok, phase = pcall(ngx.get_phase)
if ok and (phase == "access" or phase == "rewrite") then
    _M.check()
end

return _M
