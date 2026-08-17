# -*- coding: utf-8 -*-
# HMAC 预计算基准: 验证 hmac_prepare 输出与 hmac 一致, 并对比每请求签名开销。
# 纯 Lua HMAC 是签名热路径的主要开销(每签名请求 1 次), 本脚本量化优化幅度。
# 用法: python tools/bench_hmac.py
import sys, os, time
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "lupa"))
from lupa.luajit21 import LuaRuntime
L = LuaRuntime()
base = os.path.dirname(os.path.dirname(os.path.abspath(__file__))).replace("\\", "/")
L.execute('package.path = "' + base + '/?.lua;" .. package.path')
L.execute("""
sha = require('sha256')
secret = "N9x_Ant1_r3p14y!"
N = 20000
msg = "GET|/api/list?x=1|e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855|1786845452|1786845452-19-nxgqyrte"

-- 正确性: 预计算版本与原始 hmac 输出必须一致
_prep = sha.hmac_prepare(secret)
_a = sha.hmac(secret, msg)
_b = _prep(msg)
_consistent = (_a == _b)

-- 原始 hmac(每次调用都重建 ipad/opad)
local t0 = os.clock()
for i = 1, N do
    sha.hmac(secret, msg)
end
_t_old = os.clock() - t0

-- 预计算版本(密钥扩展只算一次)
local t0 = os.clock()
for i = 1, N do
    _prep(msg)
end
_t_new = os.clock() - t0

-- 附: 每次请求被省掉的 "IP 字符串→sha256" 开销(memcached 后端直接拿 IP 做键)
local t0 = os.clock()
for i = 1, N do
    sha.hex("192.168.1.100")
end
_t_ipsha = os.clock() - t0
""")
G = L.globals()
N = int(G.N)
print("consistency (hmac == hmac_prepare):", bool(G._consistent))
old, new = float(G._t_old), float(G._t_new)
print("old hmac         : %.1f ns/op  (%d ops in %.3fs)" % (old / N * 1e9, N, old))
print("hmac_prepare     : %.1f ns/op  (%d ops in %.3fs)" % (new / N * 1e9, N, new))
print("sha256(ip 字符串) : %.1f ns/op (原每请求 2 次, memcached 后端已移除)" % (float(G._t_ipsha) / N * 1e9))
if old > 0:
    print("speedup          : %.2fx" % (old / new))
ok = bool(G._consistent)
print("ALL PASS" if ok else "SOME FAILED")
sys.exit(0 if ok else 1)
