# -*- coding: utf-8 -*-
# 生成工作区算法的新鲜签名, 输出 "ts nonce sign" 供 curl 使用
# 用法: gen_sign.py <method> <uri>
import sys, os, time, hmac, hashlib, random

SECRET = b"N9x_Ant1_r3p14y!"

def main():
    method = sys.argv[1] if len(sys.argv) > 1 else "GET"
    uri = sys.argv[2] if len(sys.argv) > 2 else "/"
    ts = str(int(time.time()))
    nonce = "%s-%s-%s" % (ts, random.randint(0, 9), "".join(random.choice("abcdefghijklmnopqrstuvwxyz0123456789") for _ in range(8)))
    bh = hashlib.sha256(b"").hexdigest()
    data = "%s|%s|%s|%s|%s" % (method, uri, bh, ts, nonce)
    sign = hmac.new(SECRET, data.encode("utf-8"), hashlib.sha256).hexdigest()
    print("%s %s %s" % (ts, nonce, sign))

if __name__ == "__main__":
    main()
