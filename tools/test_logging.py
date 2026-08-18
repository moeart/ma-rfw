# -*- coding: utf-8 -*-
# JSON 日志结构 + SNAP 限频功能测试:
#   1) 所有日志行均为 JSON, 与 WAF (moewaf/util.lua log_record) 同构 8 字段:
#      client_ip / local_time / server_name / user_agent /
#      attack_method / req_url / req_data / rule_tag
#   2) ERROR → rfw.error.log, 普通记录 → rfw_YYYY-MM-DD.log
#   3) SNAP 按 snap_log_interval 限频(默认 1800s): 间隔内重复 sweep 不再落盘
#   4) denied_total 累计计数
#
# 本机无 lupa.luajit21 二进制时, 回退到系统 lupa (lua54) + 纯 Lua cjson/bit shim,
# 仅用于本地验证; 服务器 (OpenResty LuaJIT) 上行为与 LuaJIT 测试完全一致。
# 用法: python tools/test_logging.py
import sys, os, re, json, glob, datetime

try:
    from lupa.luajit21 import LuaRuntime
except ImportError:
    sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "lupa"))
    from lupa import LuaRuntime

base = os.path.dirname(os.path.dirname(os.path.abspath(__file__))).replace("\\", "/")
LOG_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "logs")
DAILY_NAME = "rfw_%s.log" % datetime.date.today().strftime("%Y-%m-%d")
MWAF_DIR = os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "moewaf")).replace("\\", "/")

def clean_logs():
    for pat in ("rfw_*.log", "rfw.error.log"):
        for p in glob.glob(os.path.join(LOG_DIR, pat)):
            try: os.remove(p)
            except OSError: pass

def read_lines(name):
    p = os.path.join(LOG_DIR, name)
    if not os.path.exists(p): return []
    with open(p, "r", encoding="utf-8") as f:
        return [l for l in f.read().split("\n") if l.strip()]

def parse_json_lines(lines):
    out = []
    for l in lines:
        try: out.append(json.loads(l))
        except Exception: out.append(None)
    return out

checks = []
def check(name, ok):
    checks.append((name, bool(ok)))
    print(("OK  " if ok else "FAIL") + " " + name)

SHIM_LUA = r'''
-- ---- pure-Lua shims: only when system lupa (no luajit21) ----
if unpack == nil then unpack = table.unpack end

-- bit shim for sha256.lua (minimal LuaJIT bit implementation)
if type(bit) ~= "table" then
  local function b32(a) a = a % 0x100000000; if a < 0 then a = a + 0x100000000 end return a end
  bit = {}
  function bit.band(a,b) a=b32(a); b=b32(b); local r=0; local sa=1
    for i=1,32 do if (a%2)==1 and (b%2)==1 then r=r+sa end; a=(a-(a%2))/2; b=(b-(b%2))/2; sa=sa*2 end return r end
  function bit.bor(a,b) a=b32(a); b=b32(b); local r=0; local sa=1
    for i=1,32 do if (a%2)==1 or (b%2)==1 then r=r+sa end; a=(a-(a%2))/2; b=(b-(b%2))/2; sa=sa*2 end return r end
  function bit.bxor(a,b) a=b32(a); b=b32(b); local r=0; local sa=1
    for i=1,32 do if (a%2)~=(b%2) then r=r+sa end; a=(a-(a%2))/2; b=(b-(b%2))/2; sa=sa*2 end return r end
  function bit.bnot(a) a=b32(a); local r=0; local sa=1
    for i=1,32 do if (a%2)==0 then r=r+sa end; a=(a-(a%2))/2; sa=sa*2 end return r end
  function bit.lshift(a,n) a=b32(a); local r=0; for i=0,31-n do
    if (a%(2^(i+1)))>=2^i then r=r+2^(i+n) end end return r end
  function bit.rshift(a,n) a=b32(a); local r=0; for i=0,31-n do
    if (a%(2^(i+n+1)))>=2^(i+n) then r=r+2^i end end return r end
  function bit.tobit(a) return b32(a) end
  package.preload["bit"] = function() return bit end
end

-- cjson shim (encode/decode for log-line scenarios)
if package.preload["cjson"] == nil then
  local cjson = {}
  local function esc(s)
    return (s:gsub('[%z\1-\31\\"]', function(c)
      if c == '\\' then return '\\\\' end
      if c == '"' then return '\\"' end
      return string.format('\\u%04x', c:byte())
    end))
  end
  local function is_array(t)
    local n = 0
    for k in pairs(t) do
      if type(k) ~= "number" or k < 1 or k > #t or k ~= math.floor(k) then return false end
      n = n + 1
    end
    return n == #t
  end
  local function encode_value(v)
    local t = type(v)
    if t == "nil" then return "null" end
    if t == "boolean" then return v and "true" or "false" end
    if t == "number" then
      if v ~= v or v == math.huge or v == -math.huge then return "null" end
      if v == math.floor(v) and math.abs(v) < 1e15 then return string.format("%d", v) end
      return string.format("%.17g", v)
    end
    if t == "string" then return '"' .. esc(v) .. '"' end
    if t == "table" then
      if is_array(v) then
        local parts = {}
        for i = 1, #v do parts[i] = encode_value(v[i]) end
        return "[" .. table.concat(parts, ",") .. "]"
      end
      local parts = {}
      for k, val in pairs(v) do
        if type(k) == "string" then parts[#parts+1] = '"' .. esc(k) .. '":' .. encode_value(val) end
      end
      return "{" .. table.concat(parts, ",") .. "}"
    end
    error("cjson: cannot encode " .. tostring(t))
  end
  local function dec(s)
    local pos = 1
    local err = function(m) error("cjson.decode: " .. m .. " at " .. pos) end
    local function skip()
      while true do
        local c = s:sub(pos, pos)
        if c == " " or c == "\t" or c == "\n" or c == "\r" then pos = pos + 1 else break end
      end
    end
    local function pstr()
      pos = pos + 1
      local out = {}
      while true do
        local c = s:sub(pos, pos)
        if c == "" then err("unterminated string") end
        if c == '"' then pos = pos + 1 return table.concat(out) end
        if c == "\\" then
          local e = s:sub(pos+1, pos+1)
          if e == "u" then
            local cp = tonumber(s:sub(pos+2, pos+5), 16)
            if cp < 0x80 then out[#out+1] = string.char(cp)
            elseif cp < 0x800 then out[#out+1] = string.char(0xC0+math.floor(cp/64), 0x80+cp%64)
            else out[#out+1] = string.char(0xE0+math.floor(cp/4096), 0x80+(math.floor(cp/64)%64), 0x80+cp%64) end
            pos = pos + 6
          else
            local m = {['"']='"', ["\\"]="\\", ["/"]="/", b="\b", f="\f", n="\n", r="\r", t="\t"}
            if not m[e] then err("bad escape") end
            out[#out+1] = m[e]
            pos = pos + 2
          end
        else
          out[#out+1] = c
          pos = pos + 1
        end
      end
    end
    local pval
    local function pobj()
      pos = pos + 1
      local o = {}
      skip()
      if s:sub(pos,pos) == "}" then pos = pos + 1 return o end
      while true do
        skip()
        if s:sub(pos,pos) ~= '"' then err("expected key") end
        local k = pstr()
        skip()
        if s:sub(pos,pos) ~= ":" then err("expected :") end
        pos = pos + 1
        o[k] = pval()
        skip()
        local c = s:sub(pos,pos)
        if c == "," then pos = pos + 1
        elseif c == "}" then pos = pos + 1 return o
        else err("expected , or }") end
      end
    end
    local function parr()
      pos = pos + 1
      local a = {}
      local n = 0
      skip()
      if s:sub(pos,pos) == "]" then pos = pos + 1 return a end
      while true do
        n = n + 1
        a[n] = pval()
        skip()
        local c = s:sub(pos,pos)
        if c == "," then pos = pos + 1
        elseif c == "]" then pos = pos + 1 return a
        else err("expected , or ]") end
      end
    end
    pval = function()
      skip()
      local c = s:sub(pos,pos)
      if c == "{" then return pobj() end
      if c == "[" then return parr() end
      if c == '"' then return pstr() end
      if s:sub(pos,pos+3) == "true" then pos = pos + 4 return true end
      if s:sub(pos,pos+4) == "false" then pos = pos + 5 return false end
      if s:sub(pos,pos+3) == "null" then pos = pos + 4 return nil end
      local m = s:match("^%-?%d+%.?%d*[eE][%+%-]?%d+", pos)
      if m then pos = pos + #m return tonumber(m) end
      m = s:match("^%-?%d+%.?%d*", pos)
      if m then pos = pos + #m return tonumber(m) end
      err("unexpected char")
    end
    local v = pval()
    skip()
    if s:sub(pos,pos) ~= "" then err("trailing data") end
    return v
  end
  cjson.encode = encode_value
  cjson.decode = dec
  package.preload["cjson"] = function() return cjson end
end
'''

STUB = r'''
-- ---- stub ngx (same style as tools/test_global.py) ----
ngx = {}
ngx.HTTP_OK = 200
ngx.HTTP_FORBIDDEN = 403
ngx.ERR = 0
ngx.WARN = 0
ngx.log = function(lvl, msg) end
ngx.now = function() return _clock end
ngx.time = function() return _clock end
ngx.localtime = function() return os.date("%Y-%m-%d %H:%M:%S", _clock) end
ngx.worker = { pid = function() return 7 end, count = function() return 8 end }
_timers = {}
ngx.timer = { at = function(delay, f) _timers[#_timers + 1] = f return true, nil end }
ngx.status = 0
ngx.header = {}
_says = {}
ngx.say = function(s) _says[#_says + 1] = tostring(s) end
_exit_code = nil
ngx.exit = function(code) _exit_code = code end
ngx.socket = { tcp = function() return nil, "no socket" end }
ngx.re = {
  find = function() return nil end,
  match = function() return nil end,
  gmatch = function() return function() end end,
  sub = function(s) return s end,
  gsub = function(s) return s end,
}
ngx.req = {
  read_body = function() end,
  get_body_data = function() return nil end,
  get_body_file = function() return nil end,
  get_method = function() return "GET" end,
  clear_header = function() end,
  set_header = function() end,
  get_headers = function() return {} end,
}
_ngx_var = {}
setmetatable(_ngx_var, { __index = function() return nil end })
_ngx_var["rfw_on"] = "1"
ngx.var = _ngx_var

-- ngx.shared.DICT stub
function _mk_shared(tbl)
  local data = {}
  for k, v in pairs(tbl) do data[k] = v end
  local sd = {}
  function sd:get(k) return data[k] end
  function sd:set(k, v, ttl) data[k] = v end
  function sd:add(k, v, ttl)
    if data[k] ~= nil then return nil, "exists" end
    data[k] = v
    return true
  end
  function sd:incr(k, delta, init)
    local cur = data[k]
    if cur == nil then cur = init or 0 end
    local nv = (tonumber(cur) or 0) + (delta or 1)
    data[k] = nv
    return nv
  end
  function sd:get_keys(maxn)
    local out = {}
    for k in pairs(data) do out[#out+1] = k end
    return out
  end
  function sd:delete(k) data[k] = nil end
  function sd:data() return data end
  return sd
end
'''

def run_lua(scenario):
    L = LuaRuntime()
    L.globals()["_clock"] = 1786845452
    L.execute(SHIM_LUA)
    L.execute(STUB + "\n" + scenario)
    return L

# ============================================================
# Scenario A: no shared dict -> ERROR log at load + deny JSON
# ============================================================
clean_logs()
A = run_lua("""
ngx.shared = {}
dofile("@@BASE@@/ma_rfw.lua")
_core = _G.ma_rfw_core
_core_ok = (type(_core) == "table" and type(_core.run) == "function")

_ngx_var["http_host"] = "app.example.com"
_ngx_var["uri"] = "/api/list"
_ngx_var["request_uri"] = "/api/list"
_ngx_var["remote_addr"] = "5.5.5.5"
_ngx_var["server_name"] = "app.example.com"
_ngx_var["http_user_agent"] = "test-agent/1.0"
_ngx_var["http_cookie"] = nil
_ngx_var["http_rfwdata"] = nil
_phase = "access"
_exit_code = nil
_core.check()
_deny_exit = _exit_code
""".replace("@@BASE@@", base).replace("@@MWAF@@", MWAF_DIR).replace("@@BASE@@", base).replace("@@MWAF@@", MWAF_DIR))
check("A: module loads (no shared dict)", bool(A.globals()["_core_ok"]))
check("A: backend unreachable -> 403", int(A.globals()["_deny_exit"]) == 403)

err_objs = [o for o in parse_json_lines(read_lines("rfw.error.log")) if o]
check("A: rfw.error.log exists with JSON lines", len(err_objs) >= 1)
if err_objs:
    e = err_objs[0]
    check("A: ERROR line attack_method=ERROR", e.get("attack_method") == "ERROR")
    check("A: ERROR line req_data mentions shared dict", "lua_shared_dict" in str(e.get("req_data", "")))
    check("A: ERROR line has all 8 fields", {"client_ip","local_time","server_name","user_agent",
                                             "attack_method","req_url","req_data","rule_tag"} <= set(e.keys()))

daily_deny = [o for o in parse_json_lines(read_lines(DAILY_NAME))
              if o and o.get("attack_method") == "backend-unreachable"]
check("A: daily log has JSON DENY line", len(daily_deny) >= 1)
if daily_deny:
    d = daily_deny[0]
    check("A: DENY line 8 fields match WAF structure", {"client_ip","local_time","server_name","user_agent",
                                                        "attack_method","req_url","req_data","rule_tag"} == set(d.keys()))
    check("A: DENY attack_method=backend-unreachable", d.get("attack_method") == "backend-unreachable")
    check("A: DENY client_ip=5.5.5.5", d.get("client_ip") == "5.5.5.5")
    check("A: DENY req_url=/api/list", d.get("req_url") == "/api/list")
    check("A: DENY server_name=app.example.com", d.get("server_name") == "app.example.com")
    check("A: DENY rule_tag=GET", d.get("rule_tag") == "GET")

# ============================================================
# Scenario B: with shared dict -> blocked deny + SNAP throttle
# ============================================================
clean_logs()
B = run_lua("""
ngx.shared = { rfw = _mk_shared({}) }
dofile("@@BASE@@/ma_rfw.lua")
_core = _G.ma_rfw_core
_core_ok = (type(_core) == "table" and type(_core.run) == "function")

_rfw_sd = ngx.shared.rfw
_rfw_sd:set("rfw:block:9.9.9.9", tostring(_clock + 600) .. "|" .. tostring(_clock - 100) .. "|test-block", 610)

_ngx_var["http_host"] = "app.example.com"
_ngx_var["uri"] = "/api/list"
_ngx_var["request_uri"] = "/api/list"
_ngx_var["remote_addr"] = "9.9.9.9"
_ngx_var["server_name"] = "app.example.com"
_ngx_var["http_user_agent"] = "blocked-agent"
_ngx_var["http_cookie"] = nil
_ngx_var["http_rfwdata"] = nil
_phase = "access"
_exit_code = nil
_core.check()
_deny_exit = _exit_code
_denied_total_after_deny = _rfw_sd:get("rfw:stats:denied_total")

_sweep = _timers[1]
_sweep()

_sweep2 = _timers[#_timers]
_sweep2()
""".replace("@@BASE@@", base).replace("@@MWAF@@", MWAF_DIR).replace("@@BASE@@", base).replace("@@MWAF@@", MWAF_DIR))
G = B.globals()
check("B: module loads (with shared dict)", bool(G["_core_ok"]))
check("B: blocked request -> 403", int(G["_deny_exit"]) == 403)
check("B: denied_total cumulative=1", int(G["_denied_total_after_deny"] or 0) == 1)

snap_objs = [o for o in parse_json_lines(read_lines(DAILY_NAME)) if o and o.get("attack_method") == "SNAP"]
check("B: two sweeps write only 1 SNAP (throttle works)", len(snap_objs) == 1)
if snap_objs:
    s = snap_objs[0]
    m = re.search(r"denied_total=(\d+)", str(s.get("req_data", "")))
    check("B: SNAP req_data contains denied_total=1", m and int(m.group(1)) == 1)
    m2 = re.search(r"requests=(\d+)", str(s.get("req_data", "")))
    check("B: SNAP req_data contains requests=1", m2 and int(m2.group(1)) == 1)

B.execute("""
_rfw_sd:set("rfw:stats:snap_log_ts", _clock - 2000)
_sweep3 = _timers[#_timers]
_sweep3()
""")
snap_objs2 = [o for o in parse_json_lines(read_lines(DAILY_NAME)) if o and o.get("attack_method") == "SNAP"]
check("B: backdated snap_log_ts -> second SNAP written", len(snap_objs2) == 2)

deny_objs = [o for o in parse_json_lines(read_lines(DAILY_NAME)) if o and o.get("attack_method") == "blocked"]
check("B: daily log contains blocked DENY record", len(deny_objs) == 1)
if deny_objs:
    d = deny_objs[0]
    check("B: blocked record client_ip=9.9.9.9", d.get("client_ip") == "9.9.9.9")
    check("B: blocked record rule_tag=GET", d.get("rule_tag") == "GET")

# ============================================================
# Scenario C: both webui.lua load (syntax + no top-level side effects)
# ============================================================
C = run_lua("""
ngx.shared = { rfw = _mk_shared({}) }
_wui = dofile("@@BASE@@/webui.lua")
""".replace("@@BASE@@", base))
wui = C.globals()["_wui"]
check("C: RFW webui.lua loads", bool(wui) and callable(getattr(wui, "run", None)))

if os.path.exists(os.path.join(MWAF_DIR, "webui.lua")):
    C2 = run_lua("""
package.path = "@@MWAF@@/?.lua;" .. package.path
ngx.shared = { waf = _mk_shared({}) }
_orig_dofile = dofile
function dofile(path)
    local p = string.gsub(path, "^.*[/\\\\]moewaf", "@@MWAF@@")
    return _orig_dofile(p)
end
dofile("@@MWAF@@/webui.lua")
_wui2 = dofile("@@MWAF@@/webui.lua")
""".replace("@@BASE@@", base).replace("@@MWAF@@", MWAF_DIR))
    wui2 = C2.globals()["_wui2"]
    check("C: WAF webui.lua loads", bool(wui2) and callable(getattr(wui2, "run", None)))
else:
    check("C: WAF webui.lua loads", False)

# clean up test logs
clean_logs()
if os.path.isdir(LOG_DIR):
    try: os.rmdir(LOG_DIR)
    except OSError: pass

ok = all(o for _, o in checks)
print("ALL PASS" if ok else "SOME FAILED")
sys.exit(0 if ok else 1)
