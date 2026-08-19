-- MA-RFW (MoeArt Replay Firewall / 萌艺科技重放攻击防火墙)
-- 开发组织: 萌艺科技 MASEC 项目组 (MoeArt Inc, MA-SEC Team)
--
-- 基于请求签名的 dynamic-only 重放攻击防护模块。
-- 存储后端: ngx.shared.DICT (nginx 共享内存, 零网络开销, 零外部依赖)
-- nginx.conf 必须声明: lua_shared_dict rfw 64m;
--
-- 规则(默认 RFWDATA-only):
--   1. 请求带 RFWDATA → 严格校验: ts 时效 → nonce 一次性 → body 哈希 → HMAC 签名
--   2. 受保护请求缺少 RFWDATA → 直接拒绝；仅显式配置兼容例外时才进入 dynamic Cookie 校验
--   3. 文档 bootstrap 只由精确文档路径或 Nginx 显式变量控制
local core = _G.ma_rfw_core
if core then
    core.check()
    return
end

local _M = {}

local cjson = require("cjson")
local src = debug.getinfo(1, "S").source
local plugin_dir = (src:sub(1, 1) == "@" and src:sub(2) or src):match("^(.*)[/\\][^/\\]+$") or "."
local DATA_DIR = plugin_dir .. "/data"
local KEY_STATE_FILE = DATA_DIR .. "/rfw_key_records.json"
local STATS_FILE = DATA_DIR .. "/rfw_stats.json"
local RFW_BOOT_TS = os.time()
-- Nginx reload/restart 后给旧客户端一个短暂恢复窗口；此窗口内缺 Key 不计入封禁失败。
local RESTART_RECOVERY_GRACE = 180
local KEY_STATE_LOADED = false
local KEY_STATE_RESTORING = false
local KEY_STATE_WARNED = false
local restore_key_state
local persist_key_state
local sha = dofile(plugin_dir .. "/sha256.lua")

local config
do
    local f = io.open(plugin_dir .. "/config.json", "r")
    if not f then error("ma_rfw: config.json not found: " .. plugin_dir) end
    local content = f:read("*a"); f:close()
    config = cjson.decode(content)
    for k in pairs(config) do
        if k:sub(1, 2) == "__" then config[k] = nil end
    end
    local forbidden_config_keys = {
        "key_mode", "dynamic_strict_sign", "dynamic_sign_ratio_fail", "dynamic_cookie_tag_hex",
        "sign_enabled", "replay_enabled", "key_bind_ip", "key_bind_ua", "cookie_name",
        "cookie_bootstrap", "cookie_safe_methods", "cookie_rebootstrap_document", "static_ext",
        "secret", "dynamic_allow_legacy_secret", "dynamic_allow_legacy_cookie", "shared_dict",
    }
    for _, k in ipairs(forbidden_config_keys) do
        if config[k] ~= nil then error("ma_rfw: config field " .. k .. " is fixed in this build") end
    end
    config.html_file = plugin_dir .. "/blocked.html"
end

-- v4.3.2 dynamic-only：以下安全边界不可通过 config.json 或 WebUI 修改。
local KEY_MODE = "dynamic"
local DYN_STRICT_SIGN = true
local SIGN_ENABLED = true
local REPLAY_ENABLED = true
local KEY_BIND_IP = true
local KEY_BIND_UA = true
local DYN_COOKIE_TAG_HEX = 32
local COOKIE_TAG_HEX = DYN_COOKIE_TAG_HEX
local COOKIE_NAME = "_RFW"
local COOKIE_BOOTSTRAP = true
local COOKIE_REBOOTSTRAP_DOCUMENT = true
local COOKIE_SAFE_METHODS = { GET = true, HEAD = true, OPTIONS = true }
local COOKIE_FALLBACK_METHODS = { GET = true, HEAD = true, OPTIONS = true }
local COOKIE_SAFE_REPLAY_MAX = 8
-- Cookie 兜底是显式兼容例外，默认关闭；开启后仍受 HMAC、时效、序号、重放、比例和封禁限制。
local DYN_ALLOW_COOKIE_FALLBACK = config.dynamic_allow_cookie_fallback == true
local STRICT_API_PATHS  = type(config.strict_api_paths) == "table" and config.strict_api_paths or {}
local DYNAMIC_DOCUMENT_PATHS = type(config.dynamic_document_paths) == "table" and config.dynamic_document_paths or {}
local KEY_TTL          = config.key_ttl or 1800
local KEY_GRACE        = config.key_grace or 90
local KEY_ADVANCE      = config.key_advance_refresh or 30
local KEY_FETCH_QUOTA  = config.key_fetch_quota or 1000
local KEY_QUOTA_WINDOW = config.key_quota_window or 86400
local TOKEN_RATE_LIMIT = config.token_rate_limit or 10
local TOKEN_RATE_WINDOW= config.token_rate_window or 60

local LOG_DIR = plugin_dir .. "/logs"

local function ensure_log_dir()
    local probe = LOG_DIR .. "/.rfw"
    local fd = io.open(probe, "w")
    if fd then fd:close(); os.remove(probe); return end
    local sep = package.config:sub(1, 1)
    if sep == "\\" then
        os.execute('mkdir "' .. LOG_DIR:gsub("/", "\\") .. '"')
    else
        os.execute("mkdir -p " .. LOG_DIR)
    end
    local fd2 = io.open(probe, "w")
    if fd2 then fd2:close(); os.remove(probe) end
end

-- JSON 日志: 与 WAF (moewaf/util.lua log_record) 同一结构, 每行一个 JSON 对象:
-- {client_ip, local_time, server_name, user_agent, attack_method, req_url, req_data, rule_tag}
-- attack_method 为具体事件(DENY 记录=拒绝原因 / SNAP / ERROR / DEBUG)
local function rfw_log(tag, msg, rule_tag)
    local r = {}
    pcall(function()
        r.client_ip = ngx.var.remote_addr
        r.server_name = ngx.var.server_name
        r.user_agent = ngx.var.http_user_agent
        r.req_url = ngx.var.request_uri
    end)
    local lts
    local ok, t = pcall(ngx.localtime)
    if ok and type(t) == "string" then
        lts = t
    else
        lts = os.date("%Y-%m-%d %H:%M:%S")
    end
    local obj = {
        client_ip = r.client_ip or "-",
        local_time = lts,
        server_name = r.server_name or "-",
        user_agent = r.user_agent or "-",
        attack_method = tag,
        req_url = r.req_url or "-",
        req_data = msg or "-",
        rule_tag = rule_tag or "-",
    }
    local line
    local ok2, enc = pcall(cjson.encode, obj)
    if ok2 then
        line = enc
    else
        line = lts .. " [" .. tag .. "] " .. tostring(msg or "-")
    end
    if tag ~= "DEBUG" then
        local log_path = LOG_DIR .. "/rfw_" .. os.date("%Y-%m-%d") .. ".log"
        local fd = io.open(log_path, "a")
        if fd then
            fd:write(line .. "\n")
            fd:close()
        end
    end
    if tag == "ERROR" or tag == "DEBUG" then
        local fd = io.open(LOG_DIR .. "/rfw.error.log", "a")
        if fd then
            fd:write(line .. "\n")
            fd:close()
        end
    end
end

local function rfw_debug(msg)
    if not config.debug then return end
    rfw_log("DEBUG", msg)
end

ensure_log_dir()

local ngx_now  = ngx.now
local ngx_time = ngx.time
local ngx_var  = ngx.var
local ngx_req  = ngx.req
local worker_pid = (type(ngx.worker) == "table" and type(ngx.worker.pid) == "function")
    and ngx.worker.pid() or 0

-- HMAC 签名: 优先 resty.openssl.hmac(FFI), 回退 sha256.lua 纯 Lua
local sign_with_key
do
    local ok, mod = pcall(require, "resty.openssl.hmac")
    if ok then
        sign_with_key = function(secret, msg)
            local m = mod.new(secret, "sha256")
            m:update(msg)
            return m:final("hex")
        end
    else
        sign_with_key = function(secret, msg)
            return sha.hmac_prepare(secret)(msg)
        end
    end
end
-- ===== 动态密钥工具函数 =====
local function ua_hash_fn(ua)
    return sha.hex(ua or ""):sub(1, 16)
end

local function base64url_encode(data)
    return ngx.encode_base64(data):gsub("+", "-"):gsub("/", "_"):gsub("=", "")
end

local function generate_random_bytes(n)
    local ok, resty_random = pcall(require, "resty.random")
    if ok then return resty_random.bytes(n) end
    local f = io.open("/dev/urandom", "rb")
    if f then
        local data = f:read(n)
        f:close()
        if data and #data == n then return data end
    end
    local t = {}
    for i = 1, n do t[i] = string.char(math.random(0, 255)) end
    return table.concat(t)
end

local function generate_key_pair()
    local key    = base64url_encode(generate_random_bytes(32))
    local key_id = base64url_encode(generate_random_bytes(8))
    return key, key_id
end

-- ===== 存储后端: ngx.shared.DICT（部署名称固定） =====
local DICT_NAME = "rfw"
local MKEY_PREFIX = "rfw:"

local store = ngx.shared[DICT_NAME]
if not store then
    rfw_log("ERROR", "ngx.shared." .. DICT_NAME .. " 不存在, " ..
        "请在 nginx.conf 添加: lua_shared_dict " .. DICT_NAME .. " 64m;")
end

local function key_for(kind, name)
    return MKEY_PREFIX .. kind .. ":" .. name
end

local KEY_RECORD_PREFIX = MKEY_PREFIX .. "key:"
local QUOTA_PREFIX      = MKEY_PREFIX .. "tokencnt:"
local FREQ_PREFIX       = MKEY_PREFIX .. "tokenfreq:"

local function key_record_store_key(ip, ua_h)
    return KEY_RECORD_PREFIX .. ip .. ":" .. ua_h
end

local function get_key_record(ip, ua_h)
    if not store then return nil end
    if restore_key_state then restore_key_state() end
    local v = store:get(key_record_store_key(ip, ua_h))
    if not v then return nil end
    local ok, record = pcall(cjson.decode, v)
    if not ok or type(record) ~= "table" then return nil end
    local now = ngx_time()
    if record.current and record.current.expire and record.current.expire < now then
        if record.grace and record.grace.expire and record.grace.expire >= now then
            record.current = record.grace
        else
            record.current = nil
        end
        record.grace = nil
    end
    if record.grace and record.grace.expire and record.grace.expire < now then
        record.grace = nil
    end
    if not record.current and not record.grace then return nil end
    return record
end

local function store_key_record(ip, ua_h, record)
    if not store then return end
    store:set(key_record_store_key(ip, ua_h), cjson.encode(record), KEY_TTL + KEY_GRACE + 60)
    if persist_key_state and not KEY_STATE_RESTORING then persist_key_state() end
end

local function ensure_data_dir()
    local f = io.open(DATA_DIR .. "/.keep", "a")
    if f then f:close(); return true end
    if not KEY_STATE_WARNED then
        KEY_STATE_WARNED = true
        rfw_log("ERROR", "data 目录不可写，dynamic Key 无法持久化: " .. DATA_DIR)
    end
    return false
end

persist_key_state = function()
    if not store or KEY_STATE_RESTORING or not ensure_data_dir() then return false end
    local records = {}
    local prefix = KEY_RECORD_PREFIX
    local keys = store:get_keys(65535) or {}
    for _, k in ipairs(keys) do
        if k:sub(1, #prefix) == prefix then
            local raw = store:get(k)
            if raw then
                local ok, record = pcall(cjson.decode, raw)
                if ok and type(record) == "table" then
                    records[k:sub(#prefix + 1)] = record
                end
            end
        end
    end
    local payload = cjson.encode({ version = 1, updated_at = os.time(), records = records })
    local tmp = KEY_STATE_FILE .. ".tmp." .. tostring(os.time()) .. "." .. tostring(math.random(1, 2147483647))
    local f = io.open(tmp, "w")
    if not f then return false end
    f:write(payload); f:close()
    local ok = os.rename(tmp, KEY_STATE_FILE)
    if not ok then os.remove(tmp) end
    return ok == true
end

restore_key_state = function()
    if KEY_STATE_LOADED or not store then return end
    KEY_STATE_LOADED = true
    if not ensure_data_dir() then return end
    local f = io.open(KEY_STATE_FILE, "r")
    if not f then return end
    local content = f:read("*a"); f:close()
    local ok, payload = pcall(cjson.decode, content)
    if not ok or type(payload) ~= "table" or type(payload.records) ~= "table" then return end
    local now = ngx_time()
    KEY_STATE_RESTORING = true
    for suffix, record in pairs(payload.records) do
        if type(suffix) == "string" and type(record) == "table" then
            local ip, ua_h = suffix:match("^(.*):([%w]+)$")
            if ip and ua_h then
                if record.current and tonumber(record.current.expire or 0) < now then
                    if record.grace and tonumber(record.grace.expire or 0) >= now then
                        record.current = record.grace
                    else
                        record.current = nil
                    end
                    record.grace = nil
                elseif record.grace and tonumber(record.grace.expire or 0) < now then
                    record.grace = nil
                end
                if record.current or record.grace then
                    local ttl = KEY_TTL + KEY_GRACE + 60
                    store:set(key_record_store_key(ip, ua_h), cjson.encode(record), ttl)
                end
            end
        end
    end
    KEY_STATE_RESTORING = false
end

local function rotate_key(ip, ua_h)
    local now    = ngx_time()
    local record = get_key_record(ip, ua_h)
    if record and record.current and record.current.expire then
        local remaining = record.current.expire - now
        if remaining > KEY_ADVANCE then
            return record.current.key, record.current.expire, false
        end
    end
    local quota_key = QUOTA_PREFIX .. ip .. ":" .. ua_h
    store:add(quota_key, 0, KEY_QUOTA_WINDOW)
    local quota_count = store:incr(quota_key, 1, 0)
    if quota_count > KEY_FETCH_QUOTA then
        if record and record.current and record.current.expire and record.current.expire >= now then
            return record.current.key, record.current.expire, true
        end
        return nil, 0, true
    end
    local key, key_id = generate_key_pair()
    local new_expire  = now + KEY_TTL
    local new_record  = {}
    if record and record.current and record.current.expire and record.current.expire >= now then
        new_record.grace = record.current
    end
    new_record.current = { key = key, expire = new_expire, key_id = key_id }
    store_key_record(ip, ua_h, new_record)
    return key, new_expire, false
end

local function check_token_rate(ip, ua_h)
    if not store then return false end
    local rate_key = FREQ_PREFIX .. ip .. ":" .. ua_h
    store:add(rate_key, 0, TOKEN_RATE_WINDOW)
    local count = store:incr(rate_key, 1, 0)
    return count > TOKEN_RATE_LIMIT
end

local COOKIE_TTL  = math.max(60, math.min(604800, tonumber(config.cookie_ttl) or 86400))

local nonce_counter = 0
local function new_nonce()
    nonce_counter = nonce_counter + 1
    local t = math.floor(ngx_now() * 1000)
    return tostring(t) .. "-" .. tostring(worker_pid) .. "-" .. tostring(nonce_counter)
end



-- ===== 统计计数: 使用 shared dict 实现跨 worker 聚合 =====
local STATS_PREFIX = MKEY_PREFIX .. "stats:"

local function incr_stat(k, delta)
    if not store then return 0 end
    local v = store:incr(STATS_PREFIX .. k, delta or 1, 0)
    return v or 0
end

local function set_stat(k, val)
    if store then store:set(STATS_PREFIX .. k, val, 0) end
end

local function get_stat(k)
    if not store then return 0 end
    return store:get(STATS_PREFIX .. k) or 0
end

-- ===== 统计持久化: nginx 重启后恢复计数, 保证当日累计跨重启连续 =====
local PERSIST_KEYS = {
    "requests", "signed_ok", "cookie_ok", "cookie_issued",
    "no_cookie_tracked", "cookie_missing", "static_ok", "blocked_hit",
    "failures", "blocks", "denied_total",
}

local function persist_stats()
    if not store then return end
    local t = {}
    for _, k in ipairs(PERSIST_KEYS) do
        t[k] = get_stat(k)
    end
    t.day_key = get_stat("day_key")
    t.day_baseline = get_stat("day_baseline")
    if not ensure_data_dir() then return end
    local f = io.open(STATS_FILE, "w")
    if f then
        f:write(cjson.encode(t))
        f:close()
    end
end

local function restore_stats()
    if not store then return end
    local f = io.open(STATS_FILE, "r")
    if not f then return end
    local content = f:read("*a"); f:close()
    local ok, t = pcall(cjson.decode, content)
    if not ok or type(t) ~= "table" then return end
    for _, k in ipairs(PERSIST_KEYS) do
        local v = t[k]
        if type(v) == "number" then store:set(STATS_PREFIX .. k, v, 0) end
    end
    local dk = t.day_key
    if type(dk) == "string" and dk ~= "" then store:set(STATS_PREFIX .. "day_key", dk, 0) end
    local db = t.day_baseline
    if type(db) == "number" then store:set(STATS_PREFIX .. "day_baseline", db, 0) end
end

local function init_shared_stats()
    if not store then return end
    local is_new = store:add(STATS_PREFIX .. "start_ts", os.time(), 0)
    if is_new then restore_stats() end
    store:add(STATS_PREFIX .. "prev_requests", 0, 0)
    if is_new then
        -- 全新启动(含重启): 计数器已归零, 当日基线也从 0 开始
        local dk = get_stat("day_key")
        if dk == 0 or dk == "" then
            store:set(STATS_PREFIX .. "day_key", os.date("%Y-%m-%d"), 0)
            store:set(STATS_PREFIX .. "day_baseline", 0, 0)
        end
    else
        store:add(STATS_PREFIX .. "day_key", "", 0)
        store:add(STATS_PREFIX .. "day_baseline", 0, 0)
    end
    for _, k in ipairs({
        "requests", "signed_ok", "cookie_ok", "cookie_issued",
        "no_cookie_tracked", "cookie_missing", "cookie_replay",
        "cookie_stale", "static_ok", "blocked_hit", "failures",
        "blocks", "backend_fail", "track_ips", "block_cache_size",
        "seq_cache_size", "last_rate", "snap_log_ts", "denied_total",
    }) do
        store:add(STATS_PREFIX .. k, 0, 0)
    end
end

local function ip_key(ip)
    return ip
end

local function nonce_key(ip, nonce)
    return ip .. "|" .. nonce
end

-- ===== 状态计数 (通过 shared dict 跨 worker 聚合) =====
local stats = {}
local stats_mt = {
    __index = function(_, k)
        if k == "denied" then return {} end
        return get_stat(k)
    end,
    __newindex = function(_, k, v)
        if k == "denied" then return end
        set_stat(k, v)
    end,
}
setmetatable(stats, stats_mt)

local PENALTY_HTML
local block_cache = {}
local block_log = nil  -- 不再使用 local table, 改为扫描 shared dict

local function scan_block_log()
    if not store then return {} end
    local result = {}
    local now = ngx_time()
    local prefix = key_for("block", "")
    local keys = store:get_keys(1024)
    for _, k in ipairs(keys) do
        if k:sub(1, #prefix) == prefix then
            local ip = k:sub(#prefix + 1)
            local v = store:get(k)
            if v then
                local until_ts, ban_ts, reason = v:match("^(%d+)%|(%d+)%|(.-)$")
                if until_ts then until_ts = tonumber(until_ts) end
                if until_ts and now < until_ts then
                    result[ip] = {
                        unblock = until_ts,
                        ban = (ban_ts and tonumber(ban_ts)) or until_ts,
                        reason = (reason and reason ~= "" and reason) or "unknown",
                    }
                end
            end
        end
    end
    return result
end
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
local BLOCK_CACHE_TTL = config.block_cache_ttl or 60
local SIGN_WINDOW = config.sign_window or 60
local SWEEP_INTERVAL = config.sweep_interval
local SNAP_LOG_INTERVAL = config.snap_log_interval or 1800
local COOKIE_MISS_MAX = config.cookie_missing_max or 0
local MISS_TTL = config.cookie_missing_ttl or 86400
local COOKIE_TS_MAX = math.max(1, math.min(3600, tonumber(config.cookie_ts_max) or 300))
local COOKIE_REPLAY_WINDOW = math.max(0, math.min(30, tonumber(config.cookie_replay_window) or 2))
local COOKIE_REPLAY_MAX = math.max(1, math.min(100, tonumber(config.cookie_replay_max) or 5))
local REPLAY_RELINK_SEC = config.replay_relink_sec or 2
local SEQ_SLACK = config.seq_slack or 10
local SEQ_TTL = config.seq_ttl or COOKIE_TTL
local SEQ_CACHE_TTL = config.seq_cache_ttl or 3

-- 动态 WebApp 通常会并发发起多个幂等 GET。对这些方法仍要求
-- Cookie HMAC 正确，并允许有限的同值并发复用；同一 Cookie 的安全方法最多 8 次。
-- 状态改变请求(POST/PUT/PATCH/DELETE)继续走更严格的序号/重放策略。
-- Firefox、urllib、旧代理可能不发送 Sec-Fetch-Dest；默认兼容文档 bootstrap。
-- API 仍由 dynamic_header_required() 严格拦截。设为 true 可启用更严格的 Fetch Metadata 要求。
local COOKIE_DOCUMENT_REQUIRE_FETCH = config.cookie_document_require_fetch_metadata == true
local function cookie_safe_method(method)
    return KEY_MODE == "dynamic" and COOKIE_SAFE_METHODS[tostring(method or "GET"):upper()] == true
end
local function cookie_document_request(method)
    if KEY_MODE ~= "dynamic" or not COOKIE_REBOOTSTRAP_DOCUMENT then return false end
    method = tostring(method or "GET"):upper()
    if method ~= "GET" and method ~= "HEAD" then return false end
    local uri = ngx_var.uri or ""
    local allowed_path = ngx_var.rfw_document == "1"
    for _, path in ipairs(DYNAMIC_DOCUMENT_PATHS) do
        path = tostring(path or "")
        if path ~= "" and uri == path then allowed_path = true; break end
    end
    if not allowed_path then return false end
    if COOKIE_DOCUMENT_REQUIRE_FETCH then
        return tostring(ngx_var.http_sec_fetch_dest or ""):lower() == "document"
    end
    return true
end

local function dynamic_header_required()
    if KEY_MODE ~= "dynamic" or not DYN_STRICT_SIGN then return false end
    local method = tostring(ngx_req.get_method() or "GET"):upper()
    if method == "OPTIONS" then return false end
    local uri = ngx_var.uri or ""
    for _, prefix in ipairs(STRICT_API_PATHS) do
        prefix = tostring(prefix or "")
        if prefix ~= "" and uri:sub(1, #prefix) == prefix then return true end
    end
    -- 常见 API/Controller 路径始终严格，不能被文档白名单或请求头伪造绕过。
    if uri:match("^/api/") or uri:match("/api/") or
       uri:match("^/graphql") or uri:match("^/v%d+/") or
       uri:match("^/cgi%-bin/") or uri:match("%.do$") or
       uri:match("Controller/") then
        return true
    end
    if #STRICT_API_PATHS > 0 then return false end
    -- 默认空列表表示除显式文档白名单外，所有非文档请求严格。
    return not cookie_document_request(method)
end

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
    incr_stat("denied:" .. reason, 1)
    incr_stat("denied_total", 1)
    local data
    if detail and #detail > 0 then
        local parts = {}
        for i = 1, #detail do
            parts[#parts + 1] = detail[i][1] .. "=" .. tostring(detail[i][2])
        end
        data = table.concat(parts, " ")
        if #data > 500 then data = data:sub(1, 500) .. "..." end
    end
    rfw_log(reason, data, ngx_req.get_method())
    load_html()
    ngx.status = ngx.HTTP_FORBIDDEN
    ngx.header["Content-Type"] = "text/html; charset=utf-8"
    if reason == "dynamic-key-missing" then
        ngx.header["X-RFW-Recover"] = "token"
    end
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
    incr_stat("blocks", 1)
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
            else
                store:delete(key_for("block", key))
            end
        end
    end
    block_cache[key] = { blocked = blocked, until_ts = until_ts, exp = now + BLOCK_CACHE_TTL }
    return blocked, until_ts
end

local function prune_block_log()
    -- block_log 现在通过 scan_block_log() 从 shared dict 实时扫描
    -- 此函数仅清理 local block_cache 中的过期条目
    local now = ngx_time()
    for k, c in pairs(block_cache) do
        if now >= c.exp then block_cache[k] = nil end
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
    incr_stat("failures", 1)
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

    -- 使用 shared dict 计算全局限速率
    local req_now = get_stat("requests")
    local prev = get_stat("prev_requests")
    if prev == 0 and req_now > 0 then
        -- 首次 sweep, prev_requests 尚未初始化
        set_stat("prev_requests", req_now)
        set_stat("last_rate", 0)
    else
        local rate = math.floor(((req_now - prev) / SWEEP_INTERVAL) * 10) / 10
        set_stat("last_rate", rate)
        set_stat("prev_requests", req_now)
    end

    -- SNAP: 累计快照, 每 snap_log_interval 秒最多落盘一次 (0 = 每次 sweep 都写)
    if store then
        local snap_interval = SNAP_LOG_INTERVAL
        local last_snap = get_stat("snap_log_ts")
        if snap_interval <= 0 or (ngx_time() - last_snap) >= snap_interval then
            -- 当日累计: 跨天或重启(counter 回退)时重置基线
            local today = os.date("%Y-%m-%d")
            local day_key = get_stat("day_key")
            local baseline = get_stat("day_baseline")
            if day_key ~= today or req_now < baseline then
                if day_key == today then
                    baseline = 0
                else
                    baseline = req_now
                end
                set_stat("day_key", today)
                set_stat("day_baseline", baseline)
            end
            local requests_today = req_now - baseline
            local snap_parts = {}
            local snap_keys = {"requests","signed_ok","cookie_ok","cookie_issued",
                               "static_ok","blocked_hit","cookie_replay","cookie_stale",
                               "failures","blocks","denied_total"}
            for _, k in ipairs(snap_keys) do
                snap_parts[#snap_parts+1] = k .. "=" .. get_stat(k)
            end
            snap_parts[#snap_parts+1] = "requests_today=" .. requests_today
            rfw_log("SNAP", table.concat(snap_parts, " "))
            set_stat("snap_log_ts", ngx_time())
        end
        persist_stats()
    end

    prune_block_log()

    local now = ngx_time()
    for k, c in pairs(block_cache) do
        if now >= c.exp then block_cache[k] = nil end
    end
    for k, c in pairs(seq_cache) do
        if now - c.ts >= SEQ_CACHE_TTL then seq_cache[k] = nil end
    end
    set_stat("track_ips", sign_ratio_entries)
    local bcs = 0
    for _ in pairs(block_cache) do bcs = bcs + 1 end
    set_stat("block_cache_size", bcs)
    local scs = 0
    for _ in pairs(seq_cache) do scs = scs + 1 end
    set_stat("seq_cache_size", scs)

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

local function cookie_sig2(sid, seq, ts, key)
    if not key or key == "" then return "" end
    return sign_with_key(key, "RFW:" .. sid .. "," .. seq .. "," .. ts):sub(1, COOKIE_TAG_HEX)
end

local function set_cookie_value(sid, seq, ts, key)
    local v = cookie_sig2(sid, tostring(seq), tostring(ts), key) .. "." .. sid .. "." ..
        tostring(seq) .. "." .. tostring(ts)
    local hdr = COOKIE_NAME .. "=" .. v ..
        "; Path=/; SameSite=Lax; Max-Age=" .. tostring(COOKIE_TTL)
    ngx.ctx.rfw_pending_cookie = hdr
    -- Dynamic 文档 Cookie 只在响应确认是 text/html 后发送；这不是
    -- access 放行条件，只避免把 Cookie 发给被上游判成 JSON/错误页的响应。
    local document_cookie = KEY_MODE == "dynamic" and cookie_document_request(ngx_req.get_method())
    ngx.ctx.rfw_pending_cookie_document = document_cookie
    if not document_cookie then ngx.header["Set-Cookie"] = hdr end
end

local function cookie_missing_track(ip)
    if COOKIE_MISS_MAX <= 0 then return true end
    incr_stat("no_cookie_tracked", 1)
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
        incr_stat("cookie_missing", 1)
        return false
    end
    store:set(path, tostring(first) .. "," .. tostring(n), MISS_TTL + 10)
    return true
end

local function issue_cookie(key)
    local sid = new_nonce()
    local ts = math.floor(ngx_now() * 1000)
    write_seq(sid, ts, 1)
    set_cookie_value(sid, 1, ts, key)
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

local function check_nonce(ip, nonce, method, uri, key_id)
    local nk = key_id and (key_id .. "|" .. nonce) or nonce_key(ip, nonce)
    local key = key_for("nonce", nk)
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

local function track_sign_ratio(ip, ua, has_signed)
    local key = ip .. "|" .. (ua or "")
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
        local ratio_fail = true
        if ratio_fail then record_failure(ip, "sign-ratio-low") end
        return true, okc, tot
    end
    return false
end

local static_ext_set = {}
do
    for _, e in ipairs({
        ".html", ".htm", ".js", ".css", ".png", ".jpg", ".jpeg", ".gif", ".svg",
        ".webp", ".bmp", ".ico", ".woff", ".woff2", ".ttf", ".eot", ".map", ".pdf"
    }) do static_ext_set[e] = true end
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
    local ua = ngx_var.http_user_agent or ""
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

    local m   = ngx_req.get_method()
    local uri = signed_uri()
    local body = get_body()
    local bh   = sha.hex(body)
    local signing_input = m .. "|" .. uri .. "|" .. bh .. "|" .. t .. "|" .. nonce

    -- ===== 动态模式: 多密钥验证链 =====
    if KEY_MODE == "dynamic" then
        local ua_h   = KEY_BIND_UA and ua_hash_fn(ua) or "default"
        local bind_ip = KEY_BIND_IP and ip or "0.0.0.0"
        local key_record = get_key_record(bind_ip, ua_h)

        if not key_record then
            rfw_debug("dynamic: no key record for " .. bind_ip .. " UA=" .. ua_h)
            if dynamic_header_required() then
                -- Nginx reload/restart 期间 shared dict 可能尚未完成恢复。
                -- 这类缺 Key 不是密码学失败，短暂窗口内不能把客户端直接推入 IP 封禁。
                if ngx_time() - RFW_BOOT_TS > RESTART_RECOVERY_GRACE then
                    record_failure(ip, "dynamic-key-missing")
                else
                    incr_stat("restart_key_missing", 1)
                end
                return deny("dynamic-key-missing", d)
            end
            return "treat_as_unsigned"
        end

        -- 尝试当前密钥验签
        if key_record.current then
            local expected = sign_with_key(key_record.current.key, signing_input)
            detail_add(d, "expected_hmac", expected)
            detail_add(d, "actual_sig", sig)
            if ct_eq(expected, sig) and check_nonce(ip, nonce, m, uri, key_record.current.key_id) then
                local r, okc, tot = track_sign_ratio(ip, ua, true)
                if r then
                    detail_add(d, "signed_in_window", tostring(okc))
                    detail_add(d, "total_in_window", tostring(tot))
                    return deny("sign-ratio-low", d)
                end
                incr_stat("signed_ok", 1)
                rfw_debug("dynamic sign ok (current) method=" .. m .. " uri=" .. uri)
                return nil
            end
        end

        -- 尝试 grace 密钥验签
        if key_record.grace then
            local expected = sign_with_key(key_record.grace.key, signing_input)
            if ct_eq(expected, sig) and check_nonce(ip, nonce, m, uri, key_record.grace.key_id) then
                local r, okc, tot = track_sign_ratio(ip, ua, true)
                if r then
                    detail_add(d, "signed_in_window", tostring(okc))
                    detail_add(d, "total_in_window", tostring(tot))
                    return deny("sign-ratio-low", d)
                end
                incr_stat("signed_ok", 1)
                rfw_debug("dynamic sign ok (grace) method=" .. m .. " uri=" .. uri)
                return nil
            end
        end

        -- 当前与 grace dynamic key 均验签失败；不接受旧 secret。
        -- 验签全失败
        record_failure(ip, "sign-invalid")
        return deny("sign-invalid", d)
    end

    -- dynamic-only 不存在 static/secret 验签分支；验签全失败即拒绝。
    record_failure(ip, "sign-invalid")
    return deny("sign-invalid", d)
end

function _M.run()
    if restore_key_state then restore_key_state() end
    local uri = ngx_var.uri

    if uri:sub(1, 8) == "/cgi-rfw" then
        local f = loadfile(plugin_dir .. "/webui.lua")
        if f then
            local cgi = f()
            if cgi and cgi.run then return cgi.run() end
        end
        ngx.status = 500
        ngx.header["Content-Type"] = "text/plain; charset=utf-8"
        ngx.say("webui module not found")
        return ngx.exit(500)
    end

    if (ngx_var.rfw_on or "") ~= "1" then return end

    local ctx = ngx.ctx
    if ctx then
        if ctx.rfw_running then return end
        ctx.rfw_running = true
    end
    rfw_debug("enter uri=" .. uri)

    incr_stat("requests", 1)

    if not initialized then
        initialized = true
        init_shared_stats()
        if not schedule_sweep() then initialized = false end
    end

    if not store then
        incr_stat("backend_fail", 1)
        return deny("backend-unreachable")
    end

    local ip = ngx_var.remote_addr or ""
    local ua = ngx_var.http_user_agent or ""
    local blocked, buntil = is_blocked(ip)
    if blocked then
        incr_stat("blocked_hit", 1)
        local d = mk_detail()
        detail_add(d, "block_until_ts", tostring(buntil or 0))
        detail_add(d, "remaining_s", tostring(math.max(0, (buntil or 0) - ngx_time())))
        return deny("blocked", d)
    end

    if is_static() then
        incr_stat("static_ok", 1)
        return
    end

    if KEY_MODE == "dynamic" and DYN_STRICT_SIGN and dynamic_header_required() and not SIGN_ENABLED then
        record_failure(ip, "dynamic-sign-disabled")
        return deny("dynamic-sign-disabled")
    end
    local headerless_cookie_fallback = false
    if KEY_MODE == "dynamic" and DYN_STRICT_SIGN and dynamic_header_required() and not ngx_var.http_rfwdata then
        -- Controller/.do/API 仍不能仅凭文档头、Accept 或 MIME 放行。
        -- 但已有 dynamic _RFW Cookie 要继续进入下面的完整校验链，
        -- 以兼容少量同步 XHR；无 Cookie 仍严格拒绝。
        local fallback_method = tostring(ngx_req.get_method() or "GET"):upper()
        headerless_cookie_fallback = DYN_ALLOW_COOKIE_FALLBACK
            and COOKIE_FALLBACK_METHODS[fallback_method] == true
            and get_cookie_value(COOKIE_NAME) ~= nil
        if not headerless_cookie_fallback then
            record_failure(ip, "dynamic-sign-missing")
            return deny("dynamic-sign-missing")
        end
        rfw_debug("dynamic headerless Cookie fallback uri=" .. uri)
    end

    if SIGN_ENABLED and ngx_var.http_rfwdata then
        local result = verify_sign()
        if result ~= "treat_as_unsigned" then
            return result
        end
    end

    if COOKIE_MISS_MAX > 0 and not get_cookie_value(COOKIE_NAME) then
        if not cookie_missing_track(ip) then
            local d = mk_detail()
            detail_add(d, "daily_missing_max", tostring(COOKIE_MISS_MAX))
            return deny("cookie-missing-ban", d)
        end
    end

    local sr, srok, srtot = track_sign_ratio(ip, ua, false)
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
            if t[fp] >= (config.replay_threshold or 5) then
                replay_track[key] = nil
                replay_entries = replay_entries - 1
                record_failure(ip, "request-replay")
                local d = mk_detail()
                detail_add(d, "fingerprint_sha256", fp)
                detail_add(d, "repeat_count", tostring(t[fp]))
                detail_add(d, "threshold", tostring(config.replay_threshold or 5))
                return deny("request-replay", d)
            end
        end
    end

    local cookie_key = nil
    local cookie_key_record_missing = false
    if KEY_MODE == "dynamic" then
        local ua = ngx_var.http_user_agent or ""
        local ua_h = KEY_BIND_UA and ua_hash_fn(ua) or "default"
        local bind_ip = KEY_BIND_IP and ip or "0.0.0.0"
        local kr = get_key_record(bind_ip, ua_h)
        if kr and (kr.current or kr.grace) then
            cookie_key = (kr.current and kr.current.key) or (kr.grace and kr.grace.key)
        else
            local nk, nid = generate_key_pair()
            local ne = ngx_time() + KEY_TTL
            store_key_record(bind_ip, ua_h, { current = { key = nk, expire = ne, key_id = nid } })
            cookie_key = nk
            cookie_key_record_missing = true
        end
    end

    local v = get_cookie_value(COOKIE_NAME)
    if not v then
        if KEY_MODE == "dynamic" and cookie_document_request(ngx_req.get_method()) then
            -- Dynamic 文档只允许进入页面 bootstrap；不在 access 阶段根据
            -- Accept/URI 猜测并发 Set-Cookie。新版 rfw.js 会从 token 端点
            -- 获取 dynamic key 并在浏览器端生成 Cookie，API 仍要求 RFWDATA。
            incr_stat("cookie_bootstrap_document", 1)
            return
        end
        if COOKIE_BOOTSTRAP then
            issue_cookie(cookie_key)
            incr_stat("cookie_issued", 1)
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
        local cookie_ok = false
        if cookie_sig2(sid, seqs, tss, cookie_key) == sig:lower() then
            cookie_ok = true
        elseif KEY_MODE == "dynamic" then
            local ua = ngx_var.http_user_agent or ""
            local ua_h = KEY_BIND_UA and ua_hash_fn(ua) or "default"
            local bind_ip = KEY_BIND_IP and ip or "0.0.0.0"
            local kr = get_key_record(bind_ip, ua_h)
            if kr then
                if kr.grace and cookie_sig2(sid, seqs, tss, kr.grace.key) == sig:lower() then
                    cookie_ok = true
                end
            end
        end
        if not t or not cookie_ok then
            if t and cookie_key_record_missing and cookie_document_request(ngx_req.get_method()) then
                -- 浏览器重启后可能只保留了旧动态 Cookie，而 shared dict 中
                -- 的动态 key record 已经过期。对明确的 HTML 文档 GET/HEAD
                -- 重新 bootstrap；后续 API 仍必须使用新 Cookie 或 RFWDATA。
                -- 仅允许文档重新进入 bootstrap；不在 access 阶段发 Cookie。
                -- 浏览器随后通过 /cgi-rfw/token + rfw.js 生成新 dynamic Cookie。
                incr_stat("cookie_rebootstrap", 1)
                rfw_debug("dynamic document rebootstrap allowed uri=" .. uri)
                incr_stat("cookie_ok", 1)
                return
            end
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
        local method = ngx_req.get_method()
        local safe_method = cookie_safe_method(method)
        if COOKIE_TS_MAX > 0 and age_ms > COOKIE_TS_MAX * 1000 then
            incr_stat("cookie_stale", 1)
            local d = mk_detail()
            detail_add(d, "sid", sid or "")
            detail_add(d, "req_ts", tss or "")
            detail_add(d, "ts_age_ms", tostring(age_ms))
            if safe_method and COOKIE_BOOTSTRAP then
                -- 只对已通过 HMAC 的安全方法做无感刷新；篡改 Cookie
                -- 仍在前面直接拒绝，写操作仍严格拒绝 stale。
                issue_cookie(cookie_key)
                incr_stat("cookie_issued", 1)
                rfw_debug("stale cookie refreshed for safe method=" .. method .. " uri=" .. uri)
                incr_stat("cookie_ok", 1)
                return
            end
            record_failure(ip, "cookie-stale")
            return deny("cookie-stale", d)
        end

        local seq = tonumber(seqs)
        local highest, last_seq, last_ts, last_first, last_count = read_seq(sid)
        if last_seq ~= nil and last_ts ~= nil and last_seq == seq and last_ts == t then
            if safe_method then
                -- 安全幂等请求允许有限并发，但不能无限重放同一个 Cookie。
                local cnt = (last_count or 1) + 1
                if COOKIE_SAFE_REPLAY_MAX > 0 and cnt > COOKIE_SAFE_REPLAY_MAX then
                    record_failure(ip, "cookie-replay")
                    incr_stat("cookie_replay", 1)
                    local d = mk_detail()
                    detail_add(d, "sid", sid or "")
                    detail_add(d, "replay_count", tostring(cnt))
                    detail_add(d, "replay_limit", tostring(COOKIE_SAFE_REPLAY_MAX))
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
                incr_stat("cookie_ok", 1)
                return
            end
            if COOKIE_REPLAY_WINDOW > 0 and now_ms - last_first <= COOKIE_REPLAY_WINDOW * 1000 then
                local nseq = math.max(highest or 0, seq) + 1
                write_seq(sid, now, nseq, seq, t, last_first, last_count or 1)
                local r, okc, tot = track_cookie(ip, true)
                if r then
                    local d = mk_detail()
                    detail_add(d, "cookie_ok_in_window", tostring(okc))
                    detail_add(d, "total_in_window", tostring(tot))
                    return deny("cookie-ratio-low", d)
                end
                incr_stat("cookie_ok", 1)
                return
            end
            local cnt = (last_count or 1) + 1
            if COOKIE_REPLAY_MAX > 0 and cnt > COOKIE_REPLAY_MAX then
                record_failure(ip, "cookie-replay")
                incr_stat("cookie_replay", 1)
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
            incr_stat("cookie_ok", 1)
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
        incr_stat("cookie_ok", 1)
        rfw_debug("cookie ok seq=" .. seq .. " uri=" .. uri)
        return
    end

    -- 灰度 dynamic-only 版本不接受旧三段式 Cookie；只接受
    -- sig.sid.seq.ts 的 dynamic Cookie 格式。
    record_failure(ip, "cookie-format")
    local d = mk_detail()
    detail_add(d, "cookie_value", v)
    return deny("cookie-format", d)
end

function _M.check()
    _M.run()
    return true
end

_M.stats = stats
function _M.header_filter()
    local pc = ngx.ctx.rfw_pending_cookie
    if not pc then return end
    if ngx.ctx.rfw_pending_cookie_document then
        local ct = tostring(ngx.header["Content-Type"] or ngx.var.sent_http_content_type or ""):lower()
        local status = tonumber(ngx.status or 0) or 0
        -- MIME 只用于确认是否发送 bootstrap Cookie；不能反过来授权请求。
        if status >= 400 or not ct:find("text/html", 1, true) then return end
    end
    ngx.header["Set-Cookie"] = pc
end

_M.block_log = scan_block_log
_M.scan_block_log = scan_block_log
_M.get_key_record = get_key_record
_M.rotate_key = rotate_key
_M.ua_hash = ua_hash_fn
_M.key_for = key_for
_M.check_token_rate = check_token_rate
_M.KEY_MODE = KEY_MODE
_G.ma_rfw_core = _M

local ok, phase = pcall(ngx.get_phase)
if ok and (phase == "access" or phase == "rewrite") then
    _M.check()
end

return _M
