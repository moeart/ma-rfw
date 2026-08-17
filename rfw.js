/*
 * rfw.js - 前端每请求签名拦截器(与 nginx ma_rfw.lua 配套)
 * 覆盖 fetch 与 XMLHttpRequest(axios 底层也是它们)
 * 只对同源请求签名; 同步 XHR 跳过(异步拿不到哈希)
 *
 * 签名格式(与 nginx 端完全一致):
 *   sign = HMAC-SHA256(secret, method + "|" + path?query + "|" + sha256hex(body) + "|" + ts + "|" + nonce)
 *   body 为空时 sha256hex("")
 * 发送时以单头融合: RFWDATA = ts + "." + nonce + "." + sign
 * nginx 验证通过后转发上游前移除 RFWDATA 头(上游看不到本插件)
 *
 * _RFW cookie 运动 Token(rfw.js 是唯一签发源, 服务器不再续期):
 *   _RFW = <sig>.<sid>.<seq>.<ts_ms>
 *   sig  = HMAC-SHA256(secret, "RFW:"+sid+","+seq+","+ts) 前 16 hex(小写)
 *   本文件加载后每 ~200ms 读后自增重签一次(读当前值 → seq = max(读到, 本地)+1),
 *   多标签页共享 cookie jar 也不回退 seq; 后台标签页定时器被降频, 故在
 *   pageshow/visibilitychange/focus 时立即补刷, 避免回前台第一请求带旧值。
 *   sid 优先续用 cookie 里现有的, 没有则生成并存 localStorage。
 *
 * 部署:
 *   1. 修改全局 app.js, 在文件最顶部加:
 *        document.write('<script src="/rfw.js"></script>');  或
 *        (function(){var s=document.createElement('script');s.src='/rfw.js';document.head.appendChild(s)})();
 *   2. 同源 iframe 由 nginx sub_filter 注入 <script src="/rfw.js"></script>
 *   3. SECRET 必须与 config.lua 的 secret 一致; 泄露后需更换并同步改两边
 *   4. 服务器升级到"运动 Token"机制前先让本文件全量缓存生效(cookie_ts_max=0 可临时过渡)
 */
(function () {
  if (window.__RFW__) return;
  window.__RFW__ = { loaded: true };

  var SECRET = "N9x_Ant1_r3p14y!"; // 与 config.lua secret 一致
  // 单头融合: RFWDATA = ts.nonce.sign(与 nginx ma_rfw.lua 一致)
  var H_DATA = "RFWDATA";

  var enc = new TextEncoder();
  var counter = 0;

  // crypto.subtle 只在 HTTPS 安全上下文存在; 否则用纯 JS SHA-256/HMAC 回退,
  // 保证签名与 cookie 刷新在任何部署(http 内网/本地联调)都能跑, 与服务器一致。
  var useSubtle = !!(window.crypto && window.crypto.subtle);
  if (window.console) {
    console.log("[rfw.js] loaded, crypto.subtle=" + useSubtle +
      (useSubtle ? "" : " (使用纯 JS HMAC 回退)"));
  }

  // ---- 纯 JS SHA-256 / HMAC-SHA256 ----
  var K256 = [
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
    0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
    0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
    0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
    0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
    0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
  ];
  var H256 = [0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19];
  function rotr256(x, n) { return ((x >>> n) | (x << (32 - n))) >>> 0; }
  function sha256(msg) { // msg: Uint8Array → Uint8Array(32)
    var ml = msg.length;
    var m = new Uint8Array((ml + 9 + 63) & ~63);
    m.set(msg);
    m[ml] = 0x80;
    var bits = ml * 8;
    var dv = new DataView(m.buffer);
    dv.setUint32(m.length - 8, Math.floor(bits / 0x100000000));
    dv.setUint32(m.length - 4, bits >>> 0);
    var h = H256.slice(), w = new Int32Array(64);
    for (var i = 0; i < m.length; i += 64) {
      for (var t = 0; t < 16; t++) w[t] = dv.getInt32(i + t * 4);
      for (var t = 16; t < 64; t++) {
        var x = w[t - 15], y = w[t - 2];
        w[t] = (w[t - 16] + (rotr256(x, 7) ^ rotr256(x, 18) ^ (x >>> 3)) +
          w[t - 7] + (rotr256(y, 17) ^ rotr256(y, 19) ^ (y >>> 10))) | 0;
      }
      var a = h[0], b = h[1], c = h[2], d = h[3], e = h[4], f = h[5], g = h[6], hh = h[7];
      for (var t = 0; t < 64; t++) {
        var s1 = rotr256(e, 6) ^ rotr256(e, 11) ^ rotr256(e, 25);
        var ch = (e & f) ^ (~e & g);
        var t1 = (hh + s1 + ch + K256[t] + w[t]) | 0;
        var s0 = rotr256(a, 2) ^ rotr256(a, 13) ^ rotr256(a, 22);
        var maj = (a & b) ^ (a & c) ^ (b & c);
        var t2 = (s0 + maj) | 0;
        hh = g; g = f; f = e; e = (d + t1) | 0;
        d = c; c = b; b = a; a = (t1 + t2) | 0;
      }
      h[0] = (h[0] + a) | 0; h[1] = (h[1] + b) | 0; h[2] = (h[2] + c) | 0; h[3] = (h[3] + d) | 0;
      h[4] = (h[4] + e) | 0; h[5] = (h[5] + f) | 0; h[6] = (h[6] + g) | 0; h[7] = (h[7] + hh) | 0;
    }
    var out = new Uint8Array(32);
    for (var i = 0; i < 8; i++) {
      out[i * 4] = (h[i] >>> 24) & 0xff; out[i * 4 + 1] = (h[i] >>> 16) & 0xff;
      out[i * 4 + 2] = (h[i] >>> 8) & 0xff; out[i * 4 + 3] = h[i] & 0xff;
    }
    return out;
  }
  function hmacSha256(key, msg) { // 均 Uint8Array → Uint8Array(32)
    if (key.length > 64) key = sha256(key);
    var ipad = new Uint8Array(64), opad = new Uint8Array(64);
    for (var i = 0; i < 64; i++) {
      var k = i < key.length ? key[i] : 0;
      ipad[i] = (k ^ 0x36) & 0xff; opad[i] = (k ^ 0x5c) & 0xff;
    }
    var inner = new Uint8Array(64 + msg.length);
    inner.set(ipad); inner.set(msg, 64);
    var outer = new Uint8Array(96);
    outer.set(opad); outer.set(sha256(inner), 64);
    return sha256(outer);
  }

  function hex(buf) {
    var u = new Uint8Array(buf), out = "";
    for (var i = 0; i < u.length; i++) {
      out += (u[i] < 16 ? "0" : "") + u[i].toString(16);
    }
    return out;
  }

  var keyP = useSubtle ?
    crypto.subtle.importKey("raw", enc.encode(SECRET),
      { name: "HMAC", hash: "SHA-256" }, false, ["sign"]) : null;

  function hmacHex(data) {
    if (useSubtle) {
      return keyP.then(function (k) {
        return crypto.subtle.sign("HMAC", k, enc.encode(data));
      }).then(hex);
    }
    return Promise.resolve(hex(hmacSha256(enc.encode(SECRET), enc.encode(data))));
  }

  function sha256Hex(buf) {
    if (useSubtle) {
      return crypto.subtle.digest("SHA-256", buf).then(hex);
    }
    return Promise.resolve(hex(sha256(new Uint8Array(buf))));
  }

  function newNonce() {
    counter = (counter + 1) % 0xfffffff;
    return Math.floor(Date.now() / 1000) + "-" + counter + "-" +
      Math.random().toString(36).slice(2, 10);
  }

  // 统一成 nginx request_uri 形式: 与浏览器同款解析(相对地址按 document.baseURI 解析,
  // 它不含 #fragment, 也覆盖 <base> 标签), 保证签名串 == 浏览器实际请求行
  function pathQuery(url) {
    try {
      var base = (typeof document !== "undefined" && document.baseURI) || location.href;
      var u = new URL(url, base);
      return u.pathname + u.search;
    } catch (e) {
      return "/";
    }
  }

  function isSameOrigin(url) {
    var m = /^[a-z][a-z0-9+.-]*:\/\/([^/]+)/i.exec(url);
    if (!m) return true; // 相对地址 = 同源
    try {
      var host = m[1];
      return host === location.host || host === location.hostname ||
        (host.split(":")[0] === location.hostname);
    } catch (e) { return false; }
  }

  // 签名并返回头
  function sign(method, url, bodyBuf) {
    var ts = Math.floor(Date.now() / 1000);
    var nonce = newNonce();
    var b = bodyBuf || new ArrayBuffer(0);
    return sha256Hex(b).then(function (bh) {
      var data = method + "|" + pathQuery(url) + "|" + bh + "|" + ts + "|" + nonce;
      return hmacHex(data).then(function (sig) {
        return { ts: String(ts), nonce: nonce, sign: sig };
      });
    });
  }

  // ---- fetch 包装 ----
  if (typeof window.fetch === "function") {
    var _fetch = window.fetch;
    window.fetch = function (input, init) {
      init = init || {};
      var method = String(init.method || (input && input.method) || "GET").toUpperCase();
      var url = typeof input === "string" ? input : input.url;

      var bodyBuf = null;
      var p;
      var hasBody = (init.body != null) || (input && input.body != null);
      if (!hasBody) {
        p = Promise.resolve(new ArrayBuffer(0));
      } else if (typeof init.body === "string") {
        bodyBuf = enc.encode(init.body).buffer;
        p = Promise.resolve(bodyBuf);
      } else if (init.body instanceof ArrayBuffer || (typeof ArrayBuffer !== "undefined" &&
        ArrayBuffer.isView(init.body))) {
        bodyBuf = init.body.buffer;
        p = Promise.resolve(bodyBuf);
      } else if (typeof input === "object" && input && typeof input.clone === "function" &&
        input.body) {
        // input 是带 body 的 Request → clone 读取, 原 request 不被消费
        p = input.clone().arrayBuffer().then(function (b) { bodyBuf = b; });
      } else if (init.body != null) {
        // Blob / FormData / URLSearchParams 等: 读副本算哈希, 原 body 照发
        p = new Response(init.body).arrayBuffer().then(function (b) { bodyBuf = b; });
      } else {
        p = Promise.resolve(new ArrayBuffer(0));
      }

      if (!isSameOrigin(url)) return _fetch.apply(this, arguments);

      return p.then(function () {
        return sign(method, url, bodyBuf);
      }).then(function (r) {
        var h = new Headers(init.headers);
        h.set(H_DATA, r.ts + "." + r.nonce + "." + r.sign);
        init.method = method;
        init.headers = h;
        return _fetch.call(this, input, init);
      }).catch(function () {
        return _fetch.apply(this, arguments); // 出错时降级为原样发送
      });
    };
  }

  // ---- XMLHttpRequest 包装 ----
  if (typeof XMLHttpRequest !== "undefined") {
    var _open = XMLHttpRequest.prototype.open;
    var _send = XMLHttpRequest.prototype.send;
    XMLHttpRequest.prototype.open = function (method, url, async, user, pass) {
      this._rfwMeta = { method: String(method || "GET").toUpperCase(), url: url };
      this._rfwAsync = (async !== false);
      return _open.apply(this, arguments);
    };
    XMLHttpRequest.prototype.send = function (body) {
      var x = this;
      var meta = x._rfwMeta || { method: "GET", url: "" };
      if (meta.url && !isSameOrigin(meta.url)) return _send.apply(this, arguments);
      if (x._rfwAsync === false) return _send.apply(this, arguments); // 同步 XHR 跳过

      var p;
      if (body == null) {
        p = Promise.resolve(new ArrayBuffer(0));
      } else if (typeof body === "string") {
        p = Promise.resolve(enc.encode(body).buffer);
      } else if (body instanceof ArrayBuffer || (typeof ArrayBuffer !== "undefined" &&
        ArrayBuffer.isView(body))) {
        p = Promise.resolve(body.buffer);
      } else {
        p = new Response(body).arrayBuffer();
      }

      p.then(function (buf) {
        return sign(meta.method, meta.url, buf);
      }).then(function (r) {
        try { x.setRequestHeader(H_DATA, r.ts + "." + r.nonce + "." + r.sign); } catch (e) {}
        _send.call(x, body);
      }).catch(function () {
        _send.call(x, body); // 出错时降级为原样发送
      });
    };
  }

  // ---- _RFW 运动 Token(cookie 自刷新) ----
  // 值格式 _RFW = <sig>.<sid>.<seq>.<ts_ms>(与 nginx ma_rfw.lua cookie_sig2 一致)
  var C_NAME = "_RFW";
  var tokenBusy = false; // 防止异步重签交叉(异步 HMAC)
  var tokenSeq = 0;      // 本页内存兜底(读到不 cookie 时也单调)
  var tokenSid = null;
  var tokenLogged = false;

  function getCookie(name) {
    var m = new RegExp("(?:^|;\\s*)" + name + "=([^;]*)").exec(document.cookie);
    return m ? m[1] : null;
  }

  function parseRfw(v) {
    var m = /^([0-9a-f]{16})\.([\w-]+)\.(\d+)\.(\d+)$/i.exec(v || "");
    return m ? { sid: m[2], seq: parseInt(m[3], 10), ts: m[4] } : null;
  }

  function refreshToken() {
    if (tokenBusy) return;
    tokenBusy = true;
    // 任何同步异常都不能把 tokenBusy 钉死(否则 timer 永久空转 → cookie 不刷新)
    try {
      var prev = parseRfw(getCookie(C_NAME));
      var sid = (prev && prev.sid) || tokenSid;
      if (!sid) {
        try { sid = localStorage.getItem("rfw_sid") || ""; } catch (e) { sid = ""; }
      }
      if (!sid) {
        sid = "j" + Math.random().toString(36).slice(2, 12) + "-" + Date.now().toString(36);
        try { localStorage.setItem("rfw_sid", sid); } catch (e) {}
      }
      tokenSid = sid;
      // 读后自增: 续用 jar 里的最大序号(多标签页共享 cookie 也不回退)
      var seq = Math.max(prev ? prev.seq : 0, tokenSeq) + 1;
      tokenSeq = seq;
      var ts = Date.now(); // 毫秒
      var data = "RFW:" + sid + "," + seq + "," + ts;
      hmacHex(data).then(function (sig) {
        var v = sig.slice(0, 16) + "." + sid + "." + seq + "." + ts;
        // 同 name + Path=/ + SameSite=Lax 覆盖服务器 bootstrap 值(非 HttpOnly 可读)。
        // 注意: 若 jar 里还留着旧服务器下的 HttpOnly _RFW, JS 无法覆盖它, 会写成一个
        // 同名新值; 服务器取"最后一个"匹配值 + stale 时下发 bootstrap 驱逐, 会自愈。
        document.cookie = C_NAME + "=" + v + "; Path=/; SameSite=Lax; Max-Age=86400";
        if (!tokenLogged) {
          tokenLogged = true;
          if (window.console) console.log("[rfw.js] cookie token 刷新已启动", v);
        }
        tokenBusy = false;
      }).catch(function () { tokenBusy = false; });
    } catch (e) {
      tokenBusy = false;
    }
  }

  if (typeof document !== "undefined") {
    refreshToken();
    setInterval(refreshToken, 200);
    // 后台标签页定时器被降频到 ~1/min → 回前台/回页面立即补刷一次
    ["pageshow", "visibilitychange", "focus"].forEach(function (ev) {
      window.addEventListener(ev, refreshToken, false);
    });
  }
})();
