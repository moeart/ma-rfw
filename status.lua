-- MA-RFW (MoeArt Replay Firewall / 萌艺科技重放攻击防火墙)
-- 开发组织: 萌艺科技 MASEC 项目组 (MoeArt Inc, MA-SEC Team)
-- status.lua: GET /cgi-rfw/status 状态页
local _M = {}

local _BUILD = "2026-08-17"

local function esc(s)
    return (tostring(s):gsub("&", "&amp;"):gsub("<", "&lt;"):gsub(">", "&gt;"))
end

local function fmt_uptime(sec)
    local s = sec % 60
    local m = math.floor(sec % 3600 / 60)
    local h = math.floor(sec % 86400 / 3600)
    local d = math.floor(sec / 86400)
    return string.format("%dd %02d:%02d:%02d", d, h, m, s)
end

local function render(config, stats, _, sd_config, block_log)
    local now = ngx.time()
    local uptime = now - stats.start_ts

    local rows = {
        { "版本", config.version or "?" },
        { "后端", "lua_shared_dict(" .. tostring(sd_config and sd_config.dict_name or "rfw") .. ")" },
        { "运行时长", fmt_uptime(uptime) },
        { "启动时间", os.date("%Y-%m-%d %H:%M:%S", stats.start_ts) },
        { "本 worker", "pid=" .. tostring(ngx.worker.pid()) },
        { "请求总数", tostring(stats.requests) },
        { "最近速率(次/s)", tostring(stats.last_rate) },
        { "签名校验通过", tostring(stats.signed_ok) },
        { "cookie 兜底放行", tostring(stats.cookie_ok) },
        { "cookie 下发", tostring(stats.cookie_issued) },
        { "cookie ts 过期", tostring(stats.cookie_stale) },
        { "无 cookie 计数", tostring(stats.no_cookie_tracked) },
        { "无 cookie 封禁", tostring(stats.cookie_missing) },
        { "cookie 重放拒绝", tostring(stats.cookie_replay) },
        { "静态资源放行", tostring(stats.static_ok) },
        { "封禁命中", tostring(stats.blocked_hit) },
        { "封禁次数", tostring(stats.blocks or 0) },
        { "失败累计", tostring(stats.failures) },
        { "签名比例追踪 IP", tostring(stats.track_ips) },
        { "封禁缓存条数", tostring(stats.block_cache_size) },
        { "seq 缓存条数", tostring(stats.seq_cache_size) },
    }

    local deny_rows = {}
    for reason, n in pairs(stats.denied) do
        deny_rows[#deny_rows + 1] = { reason, n }
    end
    table.sort(deny_rows, function(a, b) return a[2] > b[2] end)

    local block_rows = {}
    local block_count = 0
    if block_log then
        for ip, e in pairs(block_log) do
            if now < e.unblock then block_count = block_count + 1 end
        end
        for ip, e in pairs(block_log) do
            local active = now < e.unblock
            local remain = math.max(0, e.unblock - now)
            block_rows[#block_rows + 1] = {
                active and "封禁中" or "已解封",
                tostring(ip),
                os.date("%Y-%m-%d %H:%M:%S", e.ban),
                os.date("%Y-%m-%d %H:%M:%S", e.unblock),
                active and fmt_uptime(remain) or "-",
                tostring(e.reason or ""),
            }
        end
        table.sort(block_rows, function(a, b)
            if a[1] == b[1] then return a[4] < b[4] end
            return a[1] < b[1]
        end)
    end

    ngx.header["Content-Type"] = "text/html; charset=utf-8"
    ngx.header["Cache-Control"] = "no-store"

    local out = {}
    out[#out + 1] = "<!DOCTYPE html><html><head><meta charset='utf-8'>"
    out[#out + 1] = "<title>MA-RFW Status</title><style>"
    out[#out + 1] = "body{font-family:monospace;margin:20px}"
    out[#out + 1] = "table{border-collapse:collapse;margin:6px 0 16px}"
    out[#out + 1] = "td,th{border:1px solid #aaa;padding:4px 12px;text-align:left}"
    out[#out + 1] = "th{background:#eee}"
    out[#out + 1] = "</style></head><body>"
    out[#out + 1] = "<h2>MA-RFW Status</h2>"

    out[#out + 1] = "<h3>总览</h3><table><tr><th>项</th><th>值</th></tr>"
    for _, r in ipairs(rows) do
        out[#out + 1] = "<tr><td>" .. esc(r[1]) .. "</td><td>" .. esc(r[2]) .. "</td></tr>"
    end
    out[#out + 1] = "</table>"

    if #deny_rows > 0 then
        out[#out + 1] = "<h3>拒绝原因</h3><table><tr><th>原因</th><th>次数</th></tr>"
        for _, r in ipairs(deny_rows) do
            out[#out + 1] = "<tr><td>" .. esc(r[1]) .. "</td><td>" .. esc(r[2]) .. "</td></tr>"
        end
        out[#out + 1] = "</table>"
    end

    out[#out + 1] = "<h3>封禁 IP(" .. block_count .. " 个)</h3><table>"
    out[#out + 1] = "<tr><th>状态</th><th>IP</th><th>封禁</th><th>解封</th><th>剩余</th><th>原因</th></tr>"
    for _, r in ipairs(block_rows) do
        out[#out + 1] = "<tr>"
        for _, c in ipairs(r) do out[#out + 1] = "<td>" .. esc(c) .. "</td>" end
        out[#out + 1] = "</tr>"
    end
    out[#out + 1] = "</table>"
    out[#out + 1] = "</body></html>"

    ngx.say(table.concat(out))
    ngx.exit(ngx.HTTP_OK)
end

_M.render = render
return _M
