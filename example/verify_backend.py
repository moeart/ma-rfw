# -*- coding: utf-8 -*-
"""MA-RFW 后端独立验签示例(可选): 前端 rfw.js 每请求签名, 单头融合格式:

    RFWDATA = <ts>.<nonce>.<sign>
    sign    = HMAC-SHA256(secret, METHOD|URI|sha256hex(body)|ts|nonce)

ma_rfw.lua 校验通过后不修改请求, RFWDATA 头原样转发上游, 后端应用可见。
本示例适用于:
  * 后端存在独立验签需求(如不经 nginx 的调用路径, 或需要对 RFWDATA 二次确认)。
"""
import hashlib
import hmac
import time

SECRET = "N9x_Ant1_r3p14y!"   # 与 config.lua 的 secret 一致
TS_WINDOW = 60                # 与 config.lua 的 sign_window 一致
SEEN_NONCES = {}              # 示例用内存去重; 生产请用 Redis SET NX 或 DB 唯一索引


def verify_request(headers, method, uri, body):
    raw = headers.get("RFWDATA")
    if not raw:
        return False, "missing-header"

    parts = raw.split(".")
    if len(parts) != 3 or not parts[0].isdigit() or len(parts[2]) != 64:
        return False, "bad-format"
    t, nonce, sign = parts

    now = int(time.time())
    if now - int(t) > TS_WINDOW or int(t) - now > TS_WINDOW:
        return False, "timestamp"

    # 拼接顺序必须与 ma_rfw.lua / rfw.js 完全一致
    body_hash = hashlib.sha256(body).hexdigest()
    expect = hmac.new(SECRET.encode("utf-8"),
                      ("%s|%s|%s|%s|%s" % (method, uri, body_hash, t, nonce)).encode("utf-8"),
                      hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expect, sign):
        return False, "signature-mismatch"

    # nonce 去重(防重放): 必须在签名校验通过之后再查重
    if nonce in SEEN_NONCES:
        return False, "nonce-replay"
    SEEN_NONCES[nonce] = now
    return True, "ok"


# 使用示例(在业务 handler 入口调用, headers/body 为原始值):
#   ok, reason = verify_request(request.headers, request.method, request.path, request.get_data())
#   if not ok: return 403
