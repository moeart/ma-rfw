# -*- coding: utf-8 -*-
# _RFW 运动 Token(纯 JS 源)测试: rfw.js 每 ~200ms 读后自增重签, 服务器不再续期。
#   - ts 为毫秒, 新鲜度 > cookie_ts_max(60s) → 403 cookie-stale(核心闸门)
#   - 同值并行宽限窗口(cookie_replay_window=2s)内任意重复放行; 窗口外可再消费
#     cookie_replay_max=5 次, 第 6 次 → 403 cookie-replay
#   - seq 落后最高序号 seq_slack(10) → 403 request-replay
#   - 有效 cookie 路径不再重发 Set-Cookie(值为 rfw.js 自管)
#   - 签名错误 → 403 cookie-tampered; 无 cookie(首访)→ 下发 bootstrap 供接管
# 用法: python tools/test_cookie_replay.py
import sys, os, shutil
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "lupa"))
from lupa.luajit21 import LuaRuntime
L = LuaRuntime()
base = os.path.dirname(os.path.dirname(os.path.abspath(__file__))).replace("\\", "/")
tmp = os.environ.get("TEMP", base + "/tools").replace("\\", "/") + "/rfw_test_token"
shutil.rmtree(tmp, ignore_errors=True)  # 清掉上次残留, 保证幂等

L.execute('''
-- ---- stub ngx ----
ngx = {}
ngx.HTTP_OK = 200
ngx.HTTP_FORBIDDEN = 403
ngx.ERR = 0
_logs = {}
ngx.log = function(lvl, msg) _logs[#_logs + 1] = tostring(msg) end
_now = 1786845452
ngx.now = function() return _now + 0.123 end
ngx.time = function() return _now end
ngx.worker = { pid = function() return 7 end, count = function() return 8 end }
ngx.timer = { at = function(delay, f) return true end }
ngx.status = 0
ngx.header = {}
_says = {}
ngx.say = function(s) _says[#_says + 1] = tostring(s) end
_exit_code = nil
ngx.exit = function(code) _exit_code = code end
ngx.socket = { tcp = function() return nil, "no socket" end }
ngx.req = {
    read_body = function() end,
    get_body_data = function() return nil end,
    get_body_file = function() return nil end,
    get_method = function() return "GET" end,
    clear_header = function() end,
    set_header = function() end,
}
_ngx_var = {}
setmetatable(_ngx_var, { __index = function() return nil end })
_ngx_var["rfw_on"] = "1"
ngx.var = _ngx_var

-- ngx.shared.DICT mock: 模拟带 TTL 的共享内存
local _sd = {}
ngx.shared = {
    rfw = {
        get = function(_, k)
            local e = _sd[k]
            if not e then return nil end
            if e.exp and _now > e.exp then _sd[k] = nil; return nil end
            return e.val, 0
        end,
        set = function(_, k, v, ttl)
            _sd[k] = { val = v, exp = ttl and (_now + ttl) }
            return true, nil
        end,
        add = function(_, k, v, ttl)
            local e = _sd[k]
            if e and (not e.exp or _now <= e.exp) then return false, "exists" end
            _sd[k] = { val = v, exp = ttl and (_now + ttl) }
            return true, nil
        end,
        delete = function(_, k)
            _sd[k] = nil
            return true
        end,
    }
}

_LOCAL_BASE = "''' + base + '''"
_orig_dofile = dofile
function dofile(path)
    local p = string.gsub(path, "^D:/BtNginxLua/replayfirewall", _LOCAL_BASE)
    if string.match(p, "config%.lua$") then
        local cfg = _orig_dofile(p)
        _TEST_SECRET = cfg.secret
        cfg.sign_ratio_min = 0    -- 隔离: 关闭签名比例判定
        cfg.cookie_ratio_min = 0  -- 隔离: 关闭 cookie 覆盖率判定
        cfg.debug = true
        cfg.cookie_ts_max = 60    -- ts 新鲜度 60s
        cfg.cookie_bootstrap = true
        cfg.cookie_replay_window = 2
        cfg.cookie_replay_max = 5
        cfg.cookie_missing_max = 3  -- 第 9 节: 验证配额在带 RFWDATA 时被跳过
        return cfg
    end
    return _orig_dofile(p)
end

_ngx_var["uri"] = "/api/test"
dofile("''' + base + '''/ma_rfw.lua")
core = _G.ma_rfw_core
_sha = _orig_dofile(_LOCAL_BASE .. "/sha256.lua")

local function run_once(cookie)
    _says = {}
    _exit_code = nil
    ngx.header = {}
    ngx.ctx = {}
    -- get_cookie_value 解析的是完整 Cookie 头(name=value; ...), 须带 _RFW= 前缀
    if cookie then _ngx_var["http_cookie"] = "_RFW=" .. cookie else _ngx_var["http_cookie"] = nil end
    core.run()
    return _exit_code, table.concat(_says), ngx.header["Set-Cookie"]
end

local function ms_now()
    return math.floor((_now + 0.123) * 1000)
end

_ngx_var["remote_addr"] = "9.9.9.9"

-- 1) 无 cookie → 下发 bootstrap(ts 为毫秒), 抓取值
local e1, _, sc = run_once(nil)
_issued_cookie = sc:match("^_RFW=([^;]+)")
local sig_, sid_, seq_, ts_ = _issued_cookie:match("^([%x]+)%.([%w%-]+)%.([%d]+)%.([%d]+)$")
_issued_sid = sid_
_issued_seq = seq_
_issued_ts  = ts_
_e1 = e1
_sc1 = sc

-- 2) 出示该值(首次) → 放行; 有效路径不得再重发 Set-Cookie
_e2, _h2, _sc2 = run_once(_issued_cookie)

-- 3) 同值立即再出示(页面并行共享同一值)→ 宽限窗口内放行
_e3, _h3 = run_once(_issued_cookie)

-- 4) 窗口外重复 ×4(值共第 2~5 次出示)→ 计数 2..5 未超限, 放行
_now = _now + 3
_exs_pass = {}
for i = 1, 4 do
    _now = _now + 1
    local ec = run_once(_issued_cookie)
    _exs_pass[i] = ec
end

-- 5) 第 6 次窗口外重复 → 计数超限 → 403 cookie-replay
_now = _now + 1
_e5, _h5 = run_once(_issued_cookie)

-- 6) 值未刷新, ts 距今超过 60s → 403 cookie-stale(新鲜度闸门); 毫秒级值不重发
_now = math.floor(_issued_ts / 1000) + 61
_e6, _h6, _sc6 = run_once(_issued_cookie)

-- 6b) 旧部署遗留的秒级 ts 值且已过旧 → 403 cookie-stale 并重发 bootstrap(驱逐 HttpOnly 影子)
local tsec = tostring(_now - 120)
local sigsec = _sha.hmac(_TEST_SECRET, "RFW:legacy1,1," .. tsec):sub(1, 16)
_e6b, _h6b, _sc6b = run_once(sigsec .. ".legacy1.1." .. tsec)

-- 6c) 用刚重发的 bootstrap 值 → 放行(rfw.js 接管链自愈)
_reissued_cookie = _sc6b and _sc6b:match("^_RFW=([^;]+)")
_e6c, _h6c, _sc6c = run_once(_reissued_cookie)

-- 7) 换 IP 验证 seq 单调: 出示远新序号(推进)→ 放行; 再出示落后序号 → request-replay
_ngx_var["remote_addr"] = "9.9.9.10"
local tm = ms_now()
local sig100 = _sha.hmac(_TEST_SECRET, "RFW:" .. _issued_sid .. ",100," .. tm):sub(1, 16)
_e7, _h7 = run_once(sig100 .. "." .. _issued_sid .. ".100." .. tm)
local sig50 = _sha.hmac(_TEST_SECRET, "RFW:" .. _issued_sid .. ",50," .. tm):sub(1, 16)
_e8, _h8 = run_once(sig50 .. "." .. _issued_sid .. ".50." .. tm)

-- 8) 伪造签名 → 403 cookie-tampered
_e9, _h9 = run_once("deadbeef" .. "." .. _issued_sid .. ".1." .. _issued_ts)

-- 9) 带有效 RFWDATA 的请求完全跳过 _RFW 校验(option A):
--    valid RFWDATA → verify_sign 通过 → 放行, 不碰 cookie 配额/ts/seq/同值次数。
--    注意: 若 IP 已被无 cookie 配额封禁(硬封禁, 先恶意后签名), 封禁检查在签名之前,
--    保持封禁——合法签名客户端本不会触发配额, 该顺序属预期。
_ngx_var["remote_addr"] = "9.9.9.12"
_ngx_var["request_uri"] = "/api/test"
_nonce_n = 0
local function make_rfwdata()
    _nonce_n = _nonce_n + 1
    local nonce = "sgn-a" .. _nonce_n
    local bh = _sha.hex("")
    local ts = tostring(_now)
    local sig = _sha.hmac(_TEST_SECRET, "GET|/api/test|" .. bh .. "|" .. ts .. "|" .. nonce)
    return ts .. "." .. nonce .. "." .. sig
end

-- 9a) 无 cookie + 有效 RFWDATA ×5 → 全部放行(若计入配额, 第 3 次即超)
_sgn_ok = {}
for i = 1, 5 do
    _ngx_var["http_rfwdata"] = make_rfwdata()
    _sgn_ok[i] = run_once(nil)
end

-- 9b) 有效 RFWDATA + 伪造 cookie → 放行(cookie-tampered 不触发)
_ngx_var["http_cookie"] = "_RFW=deadbeef." .. _issued_sid .. ".1." .. _issued_ts
_ngx_var["http_rfwdata"] = make_rfwdata()
_e12, _h12 = run_once(nil)

-- 9c) 有效 RFWDATA + 过期旧 cookie → 放行(cookie-stale 不触发)
_ngx_var["http_cookie"] = "_RFW=" .. _issued_cookie
_ngx_var["http_rfwdata"] = make_rfwdata()
_e13, _h13 = run_once(nil)

-- 9d) 上述签名请求未消费无 cookie 配额: 随后未签名无 cookie 请求前 3 个放行, 第 4 个 403
_ngx_var["http_rfwdata"] = nil
_ngx_var["http_cookie"] = nil
_miss_r = {}
for i = 1, 3 do
    _miss_r[i] = run_once(nil)
end
_e10, _h10 = run_once(nil)
''')

G = L.globals()
first_ok = G._e1 is None and G._issued_cookie is not None and G._sc1 is not None
# bootstrap ts 应为毫秒(>1e11)
ts_ms = G._issued_ts is not None and int(G._issued_ts) > 100000000000
consume_ok = G._e2 is None and G._e3 is None
no_reissue = G._sc2 is None                     # 有效路径不再重发 Set-Cookie
beyond_ok = all(G._exs_pass[i] is None for i in range(1, 5))
count_denied = G._e5 == 403 and "cookie-replay" in G._h5 and "replay_count" in G._h5
stale_denied = G._e6 == 403 and "cookie-stale" in G._h6 and "ts_age_ms" in G._h6
stale_no_reissue = G._sc6 is None                     # 毫秒级旧值不重发
legacy_stale_reissue = G._e6b == 403 and "cookie-stale" in G._h6b and G._sc6b is not None
reissued_works = G._e6c is None and G._sc6c is None
seq_advance_ok = G._e7 is None
seq_replay_denied = G._e8 == 403 and "request-replay" in G._h8
tampered_denied = G._e9 == 403 and "cookie-tampered" in G._h9
quota_3_pass = all(G._miss_r[i] is None for i in range(1, 4))
quota_exceeded = G._e10 == 403 and "cookie-missing-ban" in G._h10
signed_bypass_ok = all(G._sgn_ok[i] is None for i in range(1, 6))  # 签名无 cookie ×5 不触发配额
signed_skips_tampered = G._e12 is None             # 有效 RFWDATA 跳过 cookie 篡改校验
signed_skips_stale = G._e13 is None                # 有效 RFWDATA 跳过 ts 新鲜度校验
signed_no_quota_consumed = quota_3_pass and quota_exceeded  # 签名请求未消费配额, 未签名仍从 0 计
if not signed_skips_tampered: print("DBG e12=", G._e12, " h12=", G._h12[:400])
if not signed_skips_stale: print("DBG e13=", G._e13, " h13=", G._h13[:400])

checks = [
    ("无 cookie 下发 bootstrap(ms 级 ts)"), first_ok and ts_ms,
    ("首次出示有效值放行"), consume_ok,
    ("并行宽限窗口内同值重复放行"), G._e3 is None,
    ("有效路径不再重发 Set-Cookie"), no_reissue,
    ("窗口外重复×4(共5次) 放行"), beyond_ok,
    ("第6次窗口外重复 403(计数超限)"), count_denied,
    ("ts 超过 60s 403(cookie-stale)"), stale_denied,
    ("毫秒级旧值不重发 bootstrap"), stale_no_reissue,
    ("秒级旧值 stale 重发 bootstrap(驱逐 HttpOnly 影子)"), legacy_stale_reissue,
    ("重发的 bootstrap 值可继续用"), reissued_works,
    ("新序号推进放行"), seq_advance_ok,
    ("落后序号 403(request-replay)"), seq_replay_denied,
    ("伪造签名 403(cookie-tampered)"), tampered_denied,
    ("无 cookie 配额: 前3放行第4拒"), quota_3_pass and quota_exceeded,
    ("有效 RFWDATA 完全跳过 _RFW(含配额)"), signed_bypass_ok,
    ("有效 RFWDATA 跳过 cookie 篡改校验"), signed_skips_tampered,
    ("有效 RFWDATA 跳过 ts 新鲜度校验"), signed_skips_stale,
    ("签名请求不消费无 cookie 配额"), signed_no_quota_consumed,
]
ok = True
for i in range(0, len(checks), 2):
    name, res = checks[i], checks[i + 1]
    print(("OK  " if res else "FAIL") + " " + name)
    if not res: ok = False
print("ALL PASS" if ok else "SOME FAILED")
sys.exit(0 if ok else 1)
