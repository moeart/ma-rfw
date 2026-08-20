#!/usr/bin/env python3
"""RFW v4 unified local test tool.

It loads the real ma_rfw.lua in a simulated Nginx/OpenResty runtime. The tool
never sends traffic to production. It supports:
  * dynamic/static policy separation and strict fallback tests;
  * MA-RFW-Data and _RFW tamper/replay/expiry tests;
  * WebUI /cgi-rfw/token response tests;
  * optional prod.saz request-sequence replay;
  * lightweight throughput baselines.

Usage:
  python3 tools/rfw_v4_test.py --config config.json --saz /path/to/prod.saz \
      --json-out v4_test.json --md-out v4_test.md
"""
from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import os
import re
import shutil
import time
import zipfile
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

try:
    from lupa.luajit21 import LuaRuntime
except ImportError:
    from lupa import LuaRuntime

BASE_NOW = 1787110000.0
TEST_IP = "198.51.100.20"
TEST_UA = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/128.0"

# Self-contained pure-Lua compatibility layer. OpenResty normally supplies
# bit/cjson; local CI must not require an OpenResty installation.
LUA_SHIMS = r'''
if unpack == nil then unpack = table.unpack end
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
  local function enc(v)
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
      local parts = {}
      if is_array(v) then
        for i = 1, #v do parts[i] = enc(v[i]) end
        return "[" .. table.concat(parts, ",") .. "]"
      end
      for k, val in pairs(v) do
        if type(k) == "string" then parts[#parts+1] = '"' .. esc(k) .. '":' .. enc(val) end
      end
      return "{" .. table.concat(parts, ",") .. "}"
    end
    error("cjson encode unsupported type " .. t)
  end
  local function dec(s)
    local pos = 1
    local function err(m) error("cjson decode: " .. m .. " at " .. pos) end
    local function skip() while s:sub(pos,pos):match("[%s]") do pos = pos + 1 end end
    local parse_value
    local function parse_string()
      pos = pos + 1; local out = {}
      while true do
        local c = s:sub(pos,pos)
        if c == "" then err("unterminated string") end
        if c == '"' then pos = pos + 1; return table.concat(out) end
        if c == "\\" then
          local e = s:sub(pos+1,pos+1)
          local map = {['"']='"', ['\\']='\\', ['/']='/', b='\b', f='\f', n='\n', r='\r', t='\t'}
          if e == "u" then
            local cp = tonumber(s:sub(pos+2,pos+5),16); if not cp then err("bad unicode") end
            if cp < 0x80 then out[#out+1] = string.char(cp)
            elseif cp < 0x800 then out[#out+1] = string.char(0xC0+math.floor(cp/64),0x80+cp%64)
            else out[#out+1] = string.char(0xE0+math.floor(cp/4096),0x80+(math.floor(cp/64)%64),0x80+cp%64) end
            pos = pos + 6
          else
            if not map[e] then err("bad escape") end
            out[#out+1] = map[e]; pos = pos + 2
          end
        else out[#out+1] = c; pos = pos + 1 end
      end
    end
    local function parse_object()
      pos = pos + 1; local o = {}; skip(); if s:sub(pos,pos) == "}" then pos=pos+1; return o end
      while true do
        skip(); if s:sub(pos,pos) ~= '"' then err("expected key") end
        local k = parse_string(); skip(); if s:sub(pos,pos) ~= ":" then err("expected colon") end
        pos = pos + 1; o[k] = parse_value(); skip()
        local c=s:sub(pos,pos); if c=="," then pos=pos+1 elseif c=="}" then pos=pos+1; return o else err("expected object separator") end
      end
    end
    local function parse_array()
      pos = pos + 1; local a = {}; local n=0; skip(); if s:sub(pos,pos)=="]" then pos=pos+1; return a end
      while true do
        n=n+1; a[n]=parse_value(); skip(); local c=s:sub(pos,pos)
        if c=="," then pos=pos+1 elseif c=="]" then pos=pos+1; return a else err("expected array separator") end
      end
    end
    parse_value = function()
      skip(); local c=s:sub(pos,pos)
      if c=="{" then return parse_object() end; if c=="[" then return parse_array() end
      if c=='"' then return parse_string() end
      if s:sub(pos,pos+3)=="true" then pos=pos+4; return true end
      if s:sub(pos,pos+4)=="false" then pos=pos+5; return false end
      if s:sub(pos,pos+3)=="null" then pos=pos+4; return nil end
      local m=s:match("^%-?%d+%.?%d*[eE][%+%-]?%d+",pos) or s:match("^%-?%d+%.?%d*",pos)
      if m then pos=pos+#m; return tonumber(m) end
      err("unexpected token")
    end
    local v=parse_value(); skip(); if s:sub(pos,pos)~="" then err("trailing data") end; return v
  end
  cjson.encode=enc; cjson.decode=dec; package.preload["cjson"]=function() return cjson end
end
'''

@dataclass
class Check:
    suite: str
    name: str
    observed: str
    expected: str
    status: str
    detail: str = ""


def hmac_hex(key: str, data: str) -> str:
    return hmac.new(key.encode(), data.encode(), hashlib.sha256).hexdigest()


def cookie_value(key: str, sid: str, seq: int, ts_ms: int, tag_hex: int) -> str:
    sig = hmac_hex(key, f"RFW:{sid},{seq},{ts_ms}")[:tag_hex]
    return f"{sig}.{sid}.{seq}.{ts_ms}"

def nginx_request_uri(uri: str) -> str:
    """Convert SAZ absolute-form or origin-form target to Nginx request_uri."""
    p = urlsplit(uri or "/")
    path = p.path or "/"
    return path + (("?" + p.query) if p.query else "")


def rfwd_value(key: str, method: str, uri: str, body: bytes, ts: int, nonce: str) -> str:
    bh = hashlib.sha256(body).hexdigest()
    sig = hmac_hex(key, f"{method}|{uri}|{bh}|{ts}|{nonce}")
    return f"{ts}.{nonce}.{sig}"


class Harness:
    def __init__(self, repo: Path, config_path: Path, mode: str, overrides: dict[str, Any] | None = None, data_seed: bytes | None = None):
        self.repo = repo
        if mode != "dynamic":
            raise ValueError("gray-release build is dynamic-only")
        self.mode = mode
        self.work = Path("/tmp") / f"rfw_v4_{os.getpid()}_{mode}_{time.time_ns()}"
        self.work.mkdir(parents=True)
        for f in ("ma_rfw.lua", "sha256.lua", "blocked.html", "webui.lua"):
            shutil.copy2(repo / f, self.work / f)
        (self.work / "data").mkdir()
        keep = repo / "data" / ".keep"
        if keep.is_file(): shutil.copy2(keep, self.work / "data" / ".keep")
        if data_seed is not None:
            (self.work / "data" / "rfw_key_records.json").write_bytes(data_seed)
        cfg = json.loads(config_path.read_text(encoding="utf-8"))
        cfg.update({"debug": False, "sign_ratio_req": 100000, "cookie_ratio_req": 100000, "token_rate_limit": 100000, "key_fetch_quota": 100000})
        if overrides: cfg.update(overrides)
        self.cfg = cfg
        (self.work / "config.json").write_text(json.dumps(cfg, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        self.lua = LuaRuntime()
        self.lua.execute(LUA_SHIMS)
        self.lua.execute(r'''
ngx = {}
ngx.HTTP_OK=200; ngx.HTTP_FORBIDDEN=403; ngx.ERR=0; ngx.WARN=1
ngx.worker={pid=function() return 41 end}
ngx.timer={at=function() return true end}
ngx.localtime=function() return os.date("%Y-%m-%d %H:%M:%S", _now) end
ngx.status=0; ngx.header={}; ngx.ctx={}; _says={}; _exit_code=nil; _body_data=nil
ngx.say=function(s) _says[#_says+1]=tostring(s) end
ngx.exit=function(code) _exit_code=code end
ngx.log=function() end
ngx.req={
  read_body=function() end,
  get_body_data=function() return _body_data end,
  get_body_file=function() return nil end,
  get_method=function() return "GET" end,
  get_headers=function() return {} end,
}
function ngx.encode_base64(s)
  local a="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"; local out={}
  for i=1,#s,3 do
    local x=s:byte(i)*65536+(s:byte(i+1) or 0)*256+(s:byte(i+2) or 0); local n=math.min(3,#s-i+1)
    out[#out+1]=a:sub(math.floor(x/262144)%64+1,math.floor(x/262144)%64+1)
    out[#out+1]=a:sub(math.floor(x/4096)%64+1,math.floor(x/4096)%64+1)
    out[#out+1]=n>=2 and a:sub(math.floor(x/64)%64+1,math.floor(x/64)%64+1) or "="
    out[#out+1]=n>=3 and a:sub(x%64+1,x%64+1) or "="
  end
  return table.concat(out)
end
_now=1787110000; ngx.now=function() return _now end; ngx.time=function() return math.floor(_now) end
_ngx_var={}; setmetatable(_ngx_var,{__index=function() return nil end}); ngx.var=_ngx_var
local sd={}
local function alive(e) return e and (not e.exp or _now<=e.exp) end
ngx.shared={rfw={
  get=function(_,k) local e=sd[k]; if not alive(e) then sd[k]=nil; return nil end; return e.val,0 end,
  set=function(_,k,v,ttl) sd[k]={val=v,exp=(ttl and ttl>0) and (_now+ttl) or nil}; return true,nil end,
  add=function(_,k,v,ttl) if alive(sd[k]) then return false,"exists" end; sd[k]={val=v,exp=(ttl and ttl>0) and (_now+ttl) or nil}; return true,nil end,
  incr=function(_,k,d,init) local e=sd[k]; if not alive(e) then e={val=init or 0}; sd[k]=e end; e.val=tonumber(e.val)+(d or 1); return e.val,nil end,
  delete=function(_,k) sd[k]=nil; return true end,
  get_keys=function() local a={}; for k,e in pairs(sd) do if alive(e) then a[#a+1]=k end end; return a end,
}}
''')
        self.lua.execute(f'dofile("{self.work / "ma_rfw.lua"}")\ncore=_G.ma_rfw_core')
        self.run_lua = self.lua.eval(r'''
function(method,uri,body,cookie,rfwd,now,ip,ua,accept,dest,rfw_on,response_ct)
  _says={}; _exit_code=nil; ngx.status=0; ngx.header={}; ngx.ctx={}; _now=now or _now
  _ngx_var["rfw_on"]=rfw_on or "1"; _ngx_var["uri"]=(uri or "/"):gsub("%?.*$",""); _ngx_var["request_uri"]=uri or "/"
  _ngx_var["remote_addr"]=ip or "198.51.100.20"; _ngx_var["http_user_agent"]=ua or ""
  _ngx_var["http_cookie"]=cookie and ("_RFW="..cookie) or nil; _ngx_var["http_ma_rfw_data"]=rfwd
  _ngx_var["http_accept"]=accept or "application/json"; _ngx_var["http_sec_fetch_dest"]=dest or "empty"; _body_data=body
  ngx.req.get_method=function() return method or "GET" end
  if response_ct then ngx.header["Content-Type"] = response_ct end
  core.run(); if core.header_filter then core.header_filter() end
  return _exit_code,table.concat(_says),ngx.header["Set-Cookie"],ngx.header["MA-RFW-Recover"]
end
''')
        self.rotate_lua = self.lua.eval('function(ip,uh) return core.rotate_key(ip,uh) end')
        self.ua_hash_lua = self.lua.eval('function(ua) return core.ua_hash(ua) end')
        self.stat_lua = self.lua.eval('function(k) return core.stats[k] end')

    def close(self):
        shutil.rmtree(self.work, ignore_errors=True)

    def key(self, ip=TEST_IP, ua=TEST_UA):
        k, _, _ = self.rotate_lua(ip, self.ua_hash_lua(ua)); return str(k)

    def stat(self, name: str):
        return self.stat_lua(name)

    def run(self, method="GET", uri="/api/test", body=b"", cookie=None, rfwd=None,
            now=BASE_NOW, ip=TEST_IP, ua=TEST_UA, accept="application/json", dest="empty", rfw_on="1", response_ct=None):
        body_s = body.decode("utf-8", errors="strict") if body else None
        return self.run_lua(method, uri, body_s, cookie, rfwd, float(now), ip, ua, accept, dest, rfw_on, response_ct)


def add(out, suite, name, observed, expected, detail=""):
    o = "ALLOW" if observed is None else str(observed)
    e = "ALLOW" if expected is None else str(expected)
    out.append(Check(suite, name, o, e, "PASS" if o == e else "FAIL", detail))


def api_headers(key, method, uri, body, ts, nonce):
    return rfwd_value(key, method, uri, body, ts, nonce)


def run_core_tests(repo: Path, config_path: Path, out: list[Check]):
    # Dynamic strict contract.
    cfg_for_paths = json.loads(config_path.read_text(encoding="utf-8"))
    doc_path = (cfg_for_paths.get("dynamic_document_paths") or ["/"])[0]
    h = Harness(repo, config_path, "dynamic", {"fail_max": 100000})
    dyn_key = h.key(); req_uri="/api/audit?x=1"; body=b""
    good = api_headers(dyn_key,"GET",req_uri,body,int(BASE_NOW),"dyn-good")
    add(out,"dynamic","valid dynamic MA-RFW-Data",h.run(uri=req_uri,rfwd=good)[0],None,"current key + HMAC + nonce")
    add(out,"dynamic","delete _RFW does not bypass valid MA-RFW-Data",h.run(uri=req_uri,rfwd=good,cookie=None)[0],None,"Header credential remains sufficient")
    valid_cookie = cookie_value(dyn_key,"delete-rfwd-cookie",1,int(BASE_NOW*1000),32)
    add(out,"dynamic","delete MA-RFW-Data with Cookie is rejected",h.run(uri=req_uri,cookie=valid_cookie)[0],403,"MA-RFW-Data-only gray-release profile")
    add(out,"dynamic","delete MA-RFW-Data and _RFW is rejected",h.run(uri=req_uri)[0],403,"dynamic strict gate")
    add(out,"dynamic","body tamper",h.run(uri=req_uri,body=b'{"x":1}',rfwd=good)[0],403,"body hash mismatch")
    add(out,"dynamic","URI tamper",h.run(uri="/api/other?x=1",rfwd=good)[0],403,"signed URI mismatch")
    add(out,"dynamic","method tamper",h.run(method="POST",uri=req_uri,rfwd=good)[0],403,"signed method mismatch")
    old = api_headers("legacy-static-secret","GET",req_uri,body,int(BASE_NOW),"dyn-old")
    add(out,"dynamic","old static secret MA-RFW-Data",h.run(uri=req_uri,rfwd=old)[0],403,"legacy secret fallback disabled")
    other_key = h.key("198.51.100.21","Other-UA/1.0")
    stolen = api_headers(other_key,"GET",req_uri,body,int(BASE_NOW),"dyn-other")
    add(out,"dynamic","wrong IP/UA dynamic key",h.run(uri=req_uri,rfwd=stolen,ip="198.51.100.22",ua="Victim-UA/1.0")[0],403,"key record missing is strict deny")
    add(out,"dynamic","dynamic Cookie valid on document",h.run(uri=doc_path,cookie=cookie_value(dyn_key,"dyn-sid",1,int(BASE_NOW*1000),32),accept="text/html",dest="document")[0],None,"dynamic Cookie HMAC; API remains strict Header Gate")
    sync_cookie = cookie_value(dyn_key,"sync-sid",1,int(BASE_NOW*1000),32)
    add(out,"dynamic","Cookie fallback disabled by default",h.run(uri="/webapp/portal/DataDictController/getDevToolMd5.do",cookie=sync_cookie,accept="application/json",dest="empty")[0],403,"MA-RFW-Data-only gray-release profile")
    fallback_h = Harness(repo, config_path, "dynamic", {"dynamic_allow_cookie_fallback": True, "fail_max": 100000})
    fallback_key = fallback_h.key(); fallback_cookie = cookie_value(fallback_key,"sync-fallback",1,int(BASE_NOW*1000),32)
    add(out,"dynamic","explicit Cookie fallback remains fully checked",fallback_h.run(uri="/webapp/portal/DataDictController/getDevToolMd5.do",cookie=fallback_cookie,accept="application/json",dest="empty")[0],None,"opt-in compatibility only")
    add(out,"dynamic","Cookie fallback rejects write method",fallback_h.run(method="POST",uri="/webapp/portal/DataDictController/getDevToolMd5.do",body=b"{}",cookie=fallback_cookie,accept="application/json",dest="empty")[0],403,"headerless fallback is read-only")
    fallback_h.close()
    ratio_h = Harness(repo, config_path, "dynamic", {"sign_ratio_req": 10, "sign_ratio_min": 0.5, "dynamic_allow_cookie_fallback": True, "fail_max": 100000})
    ratio_key = ratio_h.key(); ratio_cookie = cookie_value(ratio_key,"ratio-sid",1,int(BASE_NOW*1000),32)
    ratio_codes = [ratio_h.run(uri="/webapp/portal/DataDictController/getDevToolMd5.do",cookie=ratio_cookie,accept="application/json",dest="empty",now=BASE_NOW+i)[0] for i in range(1, 11)]
    add(out,"dynamic","Cookie fallback low sign ratio rejected",ratio_codes[-1],403,"10th unsigned Cookie fallback request reaches sign-ratio-low")
    ratio_h.close()
    old_cookie = cookie_value("legacy-static-secret","old-sid",1,int(BASE_NOW*1000),16)
    add(out,"dynamic","old static Cookie rejected",h.run(uri=req_uri,cookie=old_cookie)[0],403,"legacy Cookie fallback disabled")
    fake_doc = h.run(uri=doc_path,cookie=None,accept="text/html,application/xhtml+xml",dest="empty")
    add(out,"dynamic","Firefox/urllib document without Fetch Metadata",fake_doc[0],None,"compatibility bootstrap; Set-Cookie="+str(bool(fake_doc[2])))
    api_spoof = h.run(uri="/api/audit",cookie=None,accept="text/html",dest="document")
    add(out,"dynamic","API document metadata spoof rejected",api_spoof[0],403,"common API path remains strict")
    controller = h.run(uri="/webapp/portal/DataDictController/getDevToolMd5.do",cookie=None,accept="text/html",dest="empty")
    add(out,"dynamic","Controller .do without MA-RFW-Data rejected",controller[0],403,"API/controller never document bootstrap")
    no_cookie_fallback = Harness(repo, config_path, "dynamic", {"dynamic_allow_cookie_fallback": False, "fail_max": 100000})
    no_cookie_fallback_key = no_cookie_fallback.key()
    no_cookie_fallback_cookie = cookie_value(no_cookie_fallback_key,"sync-disabled",1,int(BASE_NOW*1000),32)
    add(out,"dynamic","Cookie fallback disabled remains strict",no_cookie_fallback.run(uri="/webapp/portal/DataDictController/getDevToolMd5.do",cookie=no_cookie_fallback_cookie,accept="application/json",dest="empty")[0],403,"explicit MA-RFW-Data-only mode")
    no_cookie_fallback.close()
    unknown_doc = h.run(uri="/webapp/index",cookie=None,accept="text/html",dest="empty")
    add(out,"dynamic","non-whitelisted document path rejected",unknown_doc[0],403,"explicit dynamic_document_paths")
    doc = h.run(uri=doc_path,cookie=None,accept="text/html,application/xhtml+xml",dest="document",response_ct="text/html; charset=UTF-8")
    add(out,"dynamic","HTML document bootstrap without MA-RFW-Data",doc[0],None,"document path allow; Cookie is token/JS generated="+str(bool(doc[2])))
    h.close()
    strict_doc = Harness(repo, config_path, "dynamic", {"cookie_document_require_fetch_metadata": True, "fail_max": 100000})
    strict_fake = strict_doc.run(uri=doc_path,cookie=None,accept="text/html",dest="empty")
    add(out,"dynamic","strict Fetch Metadata rejects urllib-style document",strict_fake[0],403,"opt-in strict compatibility boundary")
    strict_real = strict_doc.run(uri=doc_path,cookie=None,accept="text/html",dest="document")
    add(out,"dynamic","strict Fetch Metadata real document",strict_real[0],None,"Sec-Fetch-Dest=document")
    strict_doc.close()
    try:
        Harness(repo, config_path, "dynamic", {"sign_enabled": False, "fail_max": 100000})
        sign_disabled_rejected = False
    except Exception:
        sign_disabled_rejected = True
    add(out,"dynamic","fixed signing cannot be disabled",None if sign_disabled_rejected else 500,None,"runtime rejects sign_enabled override")

    try:
        Harness(repo, config_path, "dynamic", {"key_mode": "static"})
        static_rejected = False
    except Exception:
        static_rejected = True
    add(out,"dynamic","static mode unavailable in gray release",None if static_rejected else 500,None,"Lua rejects key_mode=static")

    restart_src = Harness(repo, config_path, "dynamic", {"fail_max": 100000})
    restart_key = restart_src.key()
    restart_seed = (restart_src.work / "data" / "rfw_key_records.json").read_bytes()
    restart_src.close()
    restart_dst = Harness(repo, config_path, "dynamic", {"fail_max": 100000}, data_seed=restart_seed)
    restart_hdr = rfwd_value(restart_key, "GET", "/api/restart-persist", b"", int(BASE_NOW + 1), "restart-persist")
    add(out,"dynamic","dynamic Key survives new worker restart",restart_dst.run(uri="/api/restart-persist",rfwd=restart_hdr,now=BASE_NOW+1)[0],None,"persistent data/rfw_key_records.json")
    restart_dst.close()

    missing = Harness(repo, config_path, "dynamic", {"fail_max": 2})
    missing_hdr = rfwd_value("not-the-current-key", "GET", "/api/restart-missing", b"", int(BASE_NOW + 1), "restart-missing")
    missing_results = [missing.run(uri="/api/restart-missing",rfwd=missing_hdr,now=BASE_NOW+1+i) for i in range(3)]
    first_codes = [x[0] for x in missing_results]
    add(out,"dynamic","restart missing Key denied without ban during grace",first_codes[-1],403,"failures="+str(missing.stat("failures")))
    add(out,"dynamic","missing Key requests automatic token recovery",missing_results[-1][3],"token","MA-RFW-Recover response marker")
    add(out,"dynamic","missing Key enters failure chain after grace",missing.run(uri="/api/restart-missing",rfwd=missing_hdr,now=BASE_NOW+181)[0],403,"failures="+str(missing.stat("failures")))
    missing.close()


def run_cookie_tests(repo: Path, config_path: Path, out: list[Check]):
    cfg_for_paths = json.loads(config_path.read_text(encoding="utf-8"))
    doc_path = (cfg_for_paths.get("dynamic_document_paths") or ["/"])[0]
    # Cookie behavior is tested with the explicit compatibility fallback enabled;
    # Strict Header Gate remains fixed and is never disabled in the gray release.
    h = Harness(repo, config_path, "dynamic", {"dynamic_allow_cookie_fallback": True, "cookie_ts_max": 60})
    key=h.key(); ck=cookie_value(key,"cookie-sid",1,int(BASE_NOW*1000),32); uri="/api/cookie"
    add(out,"cookie","dynamic Cookie tamper",h.run(uri=uri,cookie="0"*32+ck[32:])[0],403,"cookie-tampered")
    stale=cookie_value(key,"stale-sid",1,int((BASE_NOW-120)*1000),32)
    st=h.run(uri=uri,cookie=stale); add(out,"cookie","safe GET stale refresh",st[0],None,"Set-Cookie="+str(bool(st[2])))
    stale_doc=cookie_value(key,"stale-doc",1,int((BASE_NOW-600)*1000),32)
    json_refresh=h.run(uri=doc_path,cookie=stale_doc,response_ct="application/json",accept="application/json",dest="empty")
    add(out,"cookie","document refresh JSON does not emit Cookie",json_refresh[0],None,"Set-Cookie="+str(bool(json_refresh[2])))
    html_refresh=h.run(uri=doc_path,cookie=stale_doc,response_ct="text/html; charset=UTF-8",accept="text/html",dest="empty")
    add(out,"cookie","document refresh HTML emits Cookie",html_refresh[0],None,"Set-Cookie="+str(bool(html_refresh[2])))
    post=h.run(method="POST",uri=uri,body=b"{}",cookie=stale); add(out,"cookie","stale POST rejected",post[0],403,"cookie-stale")
    dup=cookie_value(key,"dup-sid",1,int(BASE_NOW*1000),32)
    codes=[h.run(uri=uri,cookie=dup,now=BASE_NOW+i*3)[0] for i in range(8)]
    add(out,"cookie","safe GET same-value burst",403 if any(x==403 for x in codes) else None,None,"8 GETs allowed")
    ninth=h.run(uri=uri,cookie=dup,now=BASE_NOW+24)[0]
    add(out,"cookie","safe GET ninth reuse rejected",ninth,403,"fixed safe-method replay limit is 8")
    post_cookie=cookie_value(key,"post-sid",1,int(BASE_NOW*1000),32); h.run(method="POST",uri=uri,body=b"{}",cookie=post_cookie)
    post_codes=[h.run(method="POST",uri=uri,body=b"{}",cookie=post_cookie,now=BASE_NOW+i*3)[0] for i in range(1,6)]
    add(out,"cookie","strict POST sixth reuse",post_codes[-1],403,"cookie-replay")
    h.close()

    h = Harness(repo, config_path, "dynamic", {"key_ttl":30,"key_grace":5})
    key=h.key(); old=cookie_value(key,"reboot-sid",1,int(BASE_NOW*1000),32)
    doc=h.run(uri=doc_path,cookie=old,now=BASE_NOW+40,accept="text/html",dest="document")
    add(out,"cookie","expired key HTML rebootstrap",doc[0],None,"Set-Cookie="+str(bool(doc[2])))
    api=h.run(uri="/api/after-reboot",cookie=old,now=BASE_NOW+41)
    add(out,"cookie","expired key API old Cookie denied",api[0],403,"strict API does not rebootstrap")
    h.close()


def run_webui_test(repo: Path, config_path: Path, out: list[Check]):
    h=Harness(repo,config_path,"dynamic")
    public_block=(repo/"blocked.html").read_text(encoding="utf-8")
    add(out,"webui","public block page hides firewall internals",None if "防火墙" in public_block and "重放攻击防火墙" not in public_block and "短时间内请求过于频繁" not in public_block and "请求内容未通过完整性校验" not in public_block and "查看技术细节" not in public_block else 500,None,"generic public wording")
    debug_h=Harness(repo,config_path,"dynamic",{"debug":True})
    debug_result=debug_h.run(uri="/api/debug-panel")
    add(out,"webui","debug-only technical panel remains opt-in",None if debug_result[0]==403 and "id=\"rfw-debug\"" in debug_result[1] else 500,None,"debug=true panel injection")
    debug_h.close()
    result=h.run(uri="/cgi-rfw/token",now=BASE_NOW)
    try: data=json.loads(result[1])
    except Exception: data={}
    add(out,"webui","dynamic token endpoint JSON",result[0],200,"body keys="+str(sorted(data.keys())))
    add(out,"webui","token reports strict dynamic-only policy and boot_id",None if data.get("key_mode")=="dynamic" and data.get("strict_sign") is True and data.get("dynamic_sign_ratio_fail") is True and "legacy_secret_fallback" not in data and "legacy_cookie_fallback" not in data and data.get("cookie_fallback") is False and data.get("cookie_tag_hex")==32 and data.get("cookie_document_require_fetch_metadata") is False and isinstance(data.get("boot_id"), str) and len(data.get("boot_id")) > 0 and data.get("rfw_version")=="4.3.6" and data.get("rfw_protocol")=="MA-RFW-1" else 500,None,"dynamic-only/strict/fallback/tag/boot_id/version/protocol")
    page=h.run(uri="/cgi-rfw/config",ip="127.0.0.1")
    add(out,"webui","version is v4.3.6",None if "<span>v4.3.6</span>" in page[1] and "3.0.0" not in page[1] else 500,None,"WebUI brand version")
    log_page=h.run(uri="/cgi-rfw/logs",ip="127.0.0.1")
    add(out,"webui","SNAP hidden in log renderer",None if "o.attack_method==='SNAP'" in log_page[1] else 500,None,"frontend defensive filter")
    log_dir=h.work/"logs"; log_dir.mkdir(exist_ok=True)
    log_name="rfw_"+time.strftime("%Y-%m-%d")+".log"
    (log_dir/log_name).write_text(json.dumps({"attack_method":"SNAP","local_time":"2026-08-19 00:00:00"})+"\n"+json.dumps({"attack_method":"cookie-tampered","req_url":"/"})+"\n",encoding="utf-8")
    h.lua.execute('function set_log_args(f) _ngx_var["arg_file"]=f; _ngx_var["arg_lines"]="100" end')
    h.lua.eval("set_log_args")(log_name)
    log_result=h.run(uri="/cgi-rfw/api/log",ip="127.0.0.1")
    try: log_json=json.loads(log_result[1])
    except Exception: log_json={}
    log_lines=log_json.get("lines",[]) if isinstance(log_json,dict) else []
    add(out,"webui","SNAP filtered from log API",None if log_result[0]==200 and len(log_lines)==1 and all('SNAP' not in x for x in log_lines) else 500,None,"server-side log filter")
    required_ids=["strict-api-path-tags","document-path-tags","strict-api-path-input","document-path-input","cfg-cookie-document-require-fetch","help-text"]
    hidden_ids=["cfg-key-mode","cfg-dynamic-strict-sign","cfg-dynamic-sign-ratio-fail","cfg-dynamic-allow-cookie-fallback","cfg-dynamic-cookie-tag-hex","cfg-cookie-name","cfg-cookie-bootstrap","cfg-cookie-safe-methods","cfg-replay-enabled"]
    add(out,"webui","config page uses Chinese editable fields",None if all(x in page[1] for x in required_ids) and all(x not in page[1] for x in hidden_ids) and "Cookie" in page[1] else 500,None,"visible="+str(required_ids)+", hidden_fixed="+str(hidden_ids))
    save_body=json.dumps({"key_mode":"static","secret":"attacker-secret","dynamic_strict_sign":False,"dynamic_sign_ratio_fail":False,"dynamic_allow_legacy_secret":True,"dynamic_allow_legacy_cookie":True,"dynamic_allow_cookie_fallback":True,"strict_api_paths":["/api/"],"dynamic_document_paths":["/","/webapp/"],"dynamic_cookie_tag_hex":31,"cookie_document_require_fetch_metadata":True})
    saved=h.run(method="POST",uri="/cgi-rfw/api/config",body=save_body.encode(),ip="127.0.0.1")
    saved_json={}
    try: saved_json=json.loads(saved[1])
    except Exception: pass
    persisted_text=(h.work/"config.json").read_text()
    persisted=json.loads(persisted_text)
    fixed_keys=["key_mode","secret","dynamic_strict_sign","dynamic_sign_ratio_fail","dynamic_cookie_tag_hex","sign_enabled","replay_enabled","key_bind_ip","key_bind_ua","cookie_name","cookie_bootstrap","cookie_safe_methods","cookie_rebootstrap_document","static_ext","dynamic_allow_legacy_secret","dynamic_allow_legacy_cookie"]
    first_order=list(persisted.keys())
    order_keys=["__COMMENT_CONFIG_FORMAT","__COMMENT_RELEASE","__COMMENT_DYNAMIC_DOCUMENT_PATHS","dynamic_document_paths","__COMMENT_STRICT_API_PATHS","strict_api_paths","__COMMENT_DYNAMIC_KEY","key_ttl"]
    first_order_ok=all(k in first_order for k in order_keys) and first_order[:len(order_keys)]==order_keys
    saved_again=h.run(method="POST",uri="/cgi-rfw/api/config",body=save_body.encode(),ip="127.0.0.1")
    persisted_again_text=(h.work/"config.json").read_text()
    persisted_again=json.loads(persisted_again_text)
    second_order=list(persisted_again.keys())
    add(out,"webui","config save keeps standard JSON remarks, indentation and stable schema order",None if saved_json.get("success") is True and saved_again[0]==200 and all(k not in persisted for k in fixed_keys) and persisted.get("strict_api_paths")==["/api/"] and persisted.get("dynamic_document_paths")==["/","/webapp/"] and persisted.get("dynamic_allow_cookie_fallback") is True and "__COMMENT_CONFIG_FORMAT" in persisted and "__COMMENT_RELEASE" in persisted and first_order_ok and second_order==first_order and "//" not in persisted_text and "\n  \"" in persisted_text and persisted_text==persisted_again_text else 500,None,"fixed fields removed; standard JSON remarks and indentation preserved across repeated saves")
    bad_body=json.dumps({"sign_enabled":False})
    bad=h.run(method="POST",uri="/cgi-rfw/api/config",body=bad_body.encode(),ip="127.0.0.1")
    add(out,"webui","reject dynamic strict with sign disabled",bad[0],400,"configuration contradiction rejected")
    h.close()


def parse_saz(path: Path):
    with zipfile.ZipFile(path) as z:
        names=set(z.namelist()); sessions=[]
        for name in sorted(names):
            m=re.search(r"raw/(\d+)_c\.txt$",name)
            if not m: continue
            sid=int(m.group(1)); raw=z.read(name)
            sep=b"\r\n\r\n" if b"\r\n\r\n" in raw else b"\n\n"
            head, body=(raw.split(sep,1)+[b""])[:2] if sep in raw else (raw,b"")
            lines=head.decode("iso-8859-1",errors="replace").splitlines(); request_line=lines[0] if lines else ""
            headers={}
            for line in lines[1:]:
                if ":" in line:
                    k,v=line.split(":",1); headers[k.strip().lower()]=v.strip()
            parts=request_line.split(" ",2); method=parts[0] if parts else "GET"; uri=parts[1] if len(parts)>1 else "/"
            response_ct=None
            response_name=next((n for n in names if re.search(rf"raw/{sid:03d}_s\.txt$", n)), None)
            if response_name:
                response_raw=z.read(response_name)
                response_sep=b"\r\n\r\n" if b"\r\n\r\n" in response_raw else b"\n\n"
                response_head=response_raw.split(response_sep,1)[0] if response_sep in response_raw else response_raw
                for response_line in response_head.decode("iso-8859-1",errors="replace").splitlines()[1:]:
                    if ":" in response_line:
                        k,v=response_line.split(":",1)
                        if k.strip().lower()=="content-type": response_ct=v.strip(); break
            sessions.append({"sid":sid,"method":method,"uri":uri,"headers":headers,"body":body,"response_ct":response_ct})
        return sessions


def is_static_uri(uri: str):
    return bool(re.search(r"\.(html?|js|css|png|jpe?g|gif|svg|webp|bmp|ico|woff2?|ttf|eot|map|pdf)$", urlsplit(uri).path, re.I))


def run_saz_test(repo: Path, config_path: Path, saz: Path, out: list[Check]):
    if not saz or not saz.exists():
        out.append(Check("saz","prod.saz available","SKIP","PASS","SKIP","not supplied")); return
    sessions=parse_saz(saz)
    cfg_for_paths=json.loads(config_path.read_text(encoding="utf-8"))
    document_paths=set(cfg_for_paths.get("dynamic_document_paths") or ["/"])
    home=next((x for x in sessions if x["method"]=="GET" and urlsplit(x["uri"]).path in document_paths),None)
    if not home:
        out.append(Check("saz","production home found","FAIL","PASS","FAIL","no configured document path session: "+str(sorted(document_paths)))); return
    cookie_header=home["headers"].get("cookie",""); m=re.search(r"(?:^|;)\s*_RFW=([^;]+)",cookie_header); old_cookie=m.group(1) if m else None
    m_ts=re.search(r"\.([0-9]{12,})$", old_cookie or "")
    base=(int(m_ts.group(1))/1000.0+0.25) if m_ts else BASE_NOW
    h=Harness(repo,config_path,"dynamic")
    acc=home["headers"].get("accept","text/html"); dest=home["headers"].get("sec-fetch-dest","document")
    home_path=nginx_request_uri(home["uri"])
    home_result=h.run(method="GET",uri=home_path,cookie=old_cookie,now=base,accept=acc,dest=dest,response_ct=home.get("response_ct") or "text/html")
    add(out,"saz","production home document",home_result[0],None,"old Cookie rebootstrap allowed; response Cookie="+str(bool(home_result[2])))
    dyn_key=h.key(); dyn_cookie=cookie_value(dyn_key,"saz-sid",1,int(base*1000),32); denied=[]; exercised=0
    nonce=0
    for r in sessions:
        if r["sid"] <= home["sid"] or r["method"]=="CONNECT" or r["uri"].startswith("/cgi-rfw"):
            continue
        uri=nginx_request_uri(r["uri"]); now=base+(r["sid"]-home["sid"])*0.01; body=r["body"]
        if is_static_uri(uri) and r["method"] in ("GET","HEAD"):
            header=None
        else:
            nonce += 1; header=rfwd_value(dyn_key,r["method"],uri,body,int(now),f"saz-{r['sid']}-{nonce}")
        result=h.run(method=r["method"],uri=uri,body=body,cookie=dyn_cookie,rfwd=header,now=now,
                     accept=r["headers"].get("accept","application/json"),dest=r["headers"].get("sec-fetch-dest","empty"),response_ct=r.get("response_ct"))
        exercised += 1
        if result[0]==403: denied.append((r["sid"],r["method"],uri))
    add(out,"saz","production sequence after dynamic replacement",403 if denied else None,None,f"sessions={exercised}, denied={denied[:3]}")
    restart=h.run(method="GET",uri=home_path,cookie=dyn_cookie,now=base+3600,accept="text/html",dest="document",response_ct=home.get("response_ct") or "text/html")
    add(out,"saz","60 minute browser restart HTML",restart[0],None,"new Cookie="+str(bool(restart[2])))
    api=h.run(method="GET",uri="/webapp/api/restart",cookie=dyn_cookie,now=base+3601,accept="application/json",dest="empty")
    add(out,"saz","60 minute browser restart API old Cookie",api[0],403,"strict dynamic API requires new MA-RFW-Data")
    h.close()
    add(out,"saz","static legacy profile not exercised",None,None,"dynamic-only gray release")


def run_performance(repo: Path, config_path: Path, out: list[Check], n=300):
    h=Harness(repo,config_path,"dynamic"); key=h.key(); start=time.perf_counter(); denied=0
    for i in range(n):
        uri=f"/api/perf/{i}"; hdr=rfwd_value(key,"GET",uri,b"",int(BASE_NOW+i*0.001),f"perf-dynamic-{i}")
        if h.run(uri=uri,rfwd=hdr,now=BASE_NOW+i*0.001)[0]==403: denied+=1
    elapsed=time.perf_counter()-start; rps=n/elapsed if elapsed else 0
    add(out,"performance",f"dynamic-only {n} signed requests",None if denied==0 else 403,None,f"elapsed={elapsed:.4f}s, rps={rps:.1f}, denied={denied}")
    h.close()


def main():
    ap=argparse.ArgumentParser(); ap.add_argument("--repo",default=str(Path(__file__).resolve().parents[1])); ap.add_argument("--config",default=None); ap.add_argument("--saz",default=None); ap.add_argument("--json-out",default="v4_test.json"); ap.add_argument("--md-out",default="v4_test.md")
    args=ap.parse_args(); repo=Path(args.repo).resolve(); cfg=Path(args.config).resolve() if args.config else repo/"config.json"; saz=Path(args.saz).resolve() if args.saz else None
    checks=[]
    run_core_tests(repo,cfg,checks); run_cookie_tests(repo,cfg,checks); run_webui_test(repo,cfg,checks); run_saz_test(repo,cfg,saz,checks); run_performance(repo,cfg,checks)
    summary={"total":len(checks),"passed":sum(x.status=="PASS" for x in checks),"failed":sum(x.status=="FAIL" for x in checks),"skipped":sum(x.status=="SKIP" for x in checks),"checks":[asdict(x) for x in checks],"config":str(cfg),"saz":str(saz) if saz else None}
    Path(args.json_out).write_text(json.dumps(summary,ensure_ascii=False,indent=2),encoding="utf-8")
    lines=["# RFW v4.3.6 统一测试报告","",f"总检查 **{summary['total']}**；通过 **{summary['passed']}**；失败 **{summary['failed']}**；跳过 **{summary['skipped']}**。","","| 套件 | 检查项 | 观察 | 期望 | 状态 | 说明 |","|---|---|---:|---:|---|---|"]
    for x in checks: lines.append(f"| {x.suite} | {x.name} | `{x.observed}` | `{x.expected}` | **{x.status}** | {x.detail} |")
    lines += ["","## 运行边界","","这是本地 Lua/OpenResty 核心模拟，不会向生产发送请求。`ALLOW` 只代表 RFW 层放行，不代表业务授权成功。v4.3.6 dynamic-only 严格模式要求非文档请求携带当前 dynamic MA-RFW-Data；默认 `dynamic_allow_cookie_fallback=false`，仅在管理员显式开启、请求方法为 GET/HEAD/OPTIONS 且已有有效 dynamic `_RFW` Cookie 时进入有限 Cookie 兼容例外。安全方法同值最多 8 次，写请求始终需要 MA-RFW-Data。","", "## 标准 JSON 备注与固定策略","","测试工具验证标准 JSON 中的 `__COMMENT_*` 备注字段会被运行时忽略。dynamic-only、MA-RFW-Data 严格校验、Cookie 名称、安全方法和重放检测开关等固定策略不写入配置；重新注入固定字段会被运行时拒绝。","", "## 性能说明","","性能数字是本地 Lupa + Lua shared-dict mock 的相对基线，不代表生产 QPS。核心路径没有 shared-dict 全量扫描或 token rotate；每个动态请求最多一次 key record 读取和一次 HMAC 链。"]
    Path(args.md_out).write_text("\n".join(lines)+"\n",encoding="utf-8")
    print(json.dumps(summary,ensure_ascii=False,indent=2)); return 0 if summary["failed"]==0 else 1

if __name__=="__main__": raise SystemExit(main())
