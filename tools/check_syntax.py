# -*- coding: utf-8 -*-
# Lua 语法 + BOM 检查(用 lupa 的 LuaJIT2.1, 与服务器 OpenResty 同版本)
# 用法: python tools/check_syntax.py [file1 file2 ...]
import sys, os

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "lupa"))
from lupa.luajit21 import LuaRuntime

base = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
files = sys.argv[1:] or ["ma_rfw.lua", "config.lua", "sha256.lua", "status.lua"]
L = LuaRuntime()
ok = True
for f in files:
    path = os.path.join(base, f)
    if not os.path.exists(path):
        print(f, ": MISSING"); ok = False; continue
    src = open(path, "rb").read()
    if src[:3] == b"\xef\xbb\xbf":
        print(f, ": HAS BOM"); ok = False
    try:
        L.compile(src)
        print(f, ": syntax OK")
    except Exception as e:
        print(f, ": SYNTAX ERROR ->", e); ok = False
sys.exit(0 if ok else 1)
