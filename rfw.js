/*
 * rfw.js - 前端每请求签名拦截器(与 nginx ma_rfw.lua 配套)
 * 覆盖 fetch 与 XMLHttpRequest(axios 底层也是它们)
 * 只对同源请求签名; 同步 XHR 优先使用纯 JS 同步 SHA-256/HMAC，
 * 只有密钥未就绪或请求体无法同步序列化时才由服务端 dynamic Cookie fallback 兜底。
 *
 * 灰度发布固定为 dynamic-only：短期密钥只从 /cgi-rfw/token 获取并定时轮换。
 * 不信任任何 window 全局变量选择安全模式或提供密钥；客户端变量只能影响
 * 脚本可用性，不能改变服务端 Header Gate 的安全结论。
 *
 * 签名格式(与 nginx 端完全一致):
 *   sign = HMAC-SHA256(secret, method + "|" + path?query + "|" + sha256hex(body) + "|" + ts + "|" + nonce)
 *   body 为空时 sha256hex("")
 * 发送时以单头融合: MA-RFW-Data = ts + "." + nonce + "." + sign
 *
 * 部署:
 *   通过 /cgi-rfw/rfw.min.js 加载；服务端只提供 dynamic-only 脚本和 token 端点：
 *     <script src="/cgi-rfw/rfw.min.js?v4.3.12"></script>
 *
 *   dynamic key 不写入静态文件，也不放入 window 全局变量。
 */
(function () {
  // 运行时去重只用于避免重复注入造成多个拦截器/Token 请求，不是安全边界。
  // 即使攻击者预置此标记，服务端 dynamic-only Header Gate 仍会拒绝未签名请求。
  try {
    if (window.__RFW_RUNTIME__) return;
    Object.defineProperty(window, "__RFW_RUNTIME__", {
      value: true, writable: false, configurable: false, enumerable: false
    });
  } catch (e) {}

  // 同源 iframe 与主窗口共享 Token 请求和刷新调度；跨源窗口自动退化为本地实例。
  var tokenBroker = null;
  try {
    var brokerRoot = (window.top && window.top.location.origin === window.location.origin) ? window.top : window;
    tokenBroker = brokerRoot.__RFW_TOKEN_BROKER__;
    if (!tokenBroker) {
      tokenBroker = { promise: null, timePromise: null, lastData: null, lastExpiresAt: 0, refreshTimer: null, refreshFn: null, bootId: null, reloadLocked: false, maintenanceNotified: false };
      Object.defineProperty(brokerRoot, "__RFW_TOKEN_BROKER__", {
        value: tokenBroker, writable: false, configurable: false, enumerable: false
      });
    }
  } catch (e) { tokenBroker = null; }

  // 仅作为诊断标记，不用它决定安全策略；攻击者预置/篡改
  // window.__RFW__ 不能改变服务端 Header Gate 的安全结论。
  try {
    Object.defineProperty(window, "__RFW__", {
      value: Object.freeze({ loaded: true, version: "4.3.12" }),
      writable: false, configurable: false, enumerable: false
    });
  } catch (e) {}

  var H_DATA = "MA-RFW-Data";
  var enc = new TextEncoder();
  var counter = 0;
  var useSubtle = !!(window.crypto && window.crypto.subtle);
  if (window.console) {
    console.log("[rfw.js] loaded, crypto.subtle=" + useSubtle +
      (useSubtle ? "" : " (使用纯 JS HMAC 回退)"));
  }

  // ============================================================
  // 纯 JS SHA-256 / HMAC-SHA256 (crypto.subtle 不可用时回退)
  // ============================================================
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
  function sha256(msg) {
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
  function hmacSha256(key, msg) {
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

  function sha256Hex(buf) {
    if (useSubtle) {
      return crypto.subtle.digest("SHA-256", buf).then(hex);
    }
    return Promise.resolve(hex(sha256(new Uint8Array(buf))));
  }

  // 同步 XHR 不能等待 crypto.subtle Promise，因此使用同一套纯 JS
  // SHA-256/HMAC 实现同步生成 MA-RFW-Data。仅用于少量同步请求。
  function makeSignSync(secretStr, method, url, bodyBuf, clockOffset) {
    var ts = Math.floor(Date.now() / 1000) + (clockOffset || 0);
    var nonce = newNonce();
    var b = bodyBuf || new ArrayBuffer(0);
    var bh = hex(sha256(new Uint8Array(b)));
    var data = method + "|" + pathQuery(url) + "|" + bh + "|" + ts + "|" + nonce;
    var sig = hex(hmacSha256(enc.encode(secretStr), enc.encode(data)));
    return { ts: String(ts), nonce: nonce, sign: sig };
  }

  function newNonce() {
    counter = (counter + 1) % 0xfffffff;
    return Math.floor(Date.now() / 1000) + "-" + counter + "-" +
      Math.random().toString(36).slice(2, 10);
  }

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
    if (!m) return true;
    try {
      var host = m[1];
      return host === location.host || host === location.hostname ||
        (host.split(":")[0] === location.hostname);
    } catch (e) { return false; }
  }

  // ============================================================
  // 通用: HMAC with key (Uint8Array key → Promise<hex>)
  // ============================================================
  function hmacHexWith(keyBytes, data) {
    if (useSubtle) {
      return crypto.subtle.importKey("raw", keyBytes,
        { name: "HMAC", hash: "SHA-256" }, false, ["sign"])
        .then(function (k) {
          return crypto.subtle.sign("HMAC", k, enc.encode(data));
        }).then(hex);
    }
    return Promise.resolve(hex(hmacSha256(keyBytes, enc.encode(data))));
  }

  // ============================================================
  // 签名方法: method + url + bodyBuf → { ts, nonce, sign }
  // ============================================================
  function makeSign(secretStr, method, url, bodyBuf, clockOffset) {
    var ts = Math.floor(Date.now() / 1000) + (clockOffset || 0);
    var nonce = newNonce();
    var b = bodyBuf || new ArrayBuffer(0);
    var keyBytes = enc.encode(secretStr);
    return sha256Hex(b).then(function (bh) {
      var data = method + "|" + pathQuery(url) + "|" + bh + "|" + ts + "|" + nonce;
      return hmacHexWith(keyBytes, data).then(function (sig) {
        return { ts: String(ts), nonce: nonce, sign: sig };
      });
    });
  }

  // ============================================================
  // 拦截器安装: fetch + XMLHttpRequest
  //   getPendingPromise() 返回一个 Promise, 在密钥就绪时 resolve
  //   getSecret() → 当前密钥字符串
  //   getClockOffset() → 时钟偏移
  //   isReady() → 密钥是否就绪(ready=true 后才放行请求)
  // ============================================================
  function installInterceptors(getPendingPromise, getSecret, getClockOffset, isReady) {
    function copyFetchInit(init) {
      var out = {};
      init = init || {};
      for (var k in init) {
        if (Object.prototype.hasOwnProperty.call(init, k) && k !== "_rfwRetried") out[k] = init[k];
      }
      return out;
    }

    function makeRetryFetchInit(input, init, method, headers, bodyBuf, hasBody) {
      var out = copyFetchInit(init);
      out.method = method;
      out.headers = headers;
      // 第一次请求继续使用业务提供的 body；重试时才由调用方填入已快照的
      // ArrayBuffer，以避免 Request body 在第一次 fetch 后已被消费。
      return out;
    }

    function retryFetchOnce(self, input, init, method, url, bodyBuf, hasBody) {
      return repairRfwAfterRecover().then(function () {
        var secret = getSecret();
        if (!secret || !isReady()) throw new Error("RFW_TOKEN_NOT_READY");
        return makeSign(secret, method, url, bodyBuf, getClockOffset());
      }).then(function (r) {
        var h = new Headers(init.headers || (input && input.headers) || undefined);
        h.set(H_DATA, r.ts + "." + r.nonce + "." + r.sign);
        var retryInit = makeRetryFetchInit(input, init, method, h, bodyBuf, hasBody);
        if (hasBody) retryInit.body = bodyBuf.slice ? bodyBuf.slice(0) : bodyBuf;
        retryInit._rfwRetried = true;
        return _fetch.call(self, input, retryInit);
      });
    }

    // ---- fetch ----
    if (typeof window.fetch === "function") {
      var _fetch = window.fetch;
      window.fetch = function (input, init) {
        init = init || {};
        var method = String(init.method || (input && input.method) || "GET").toUpperCase();
        var url = typeof input === "string" ? input : input.url;

        if (!isSameOrigin(url)) return _fetch.apply(this, arguments);

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
          p = input.clone().arrayBuffer().then(function (b) { bodyBuf = b; });
        } else if (init.body != null) {
          p = new Response(init.body).arrayBuffer().then(function (b) { bodyBuf = b; });
        } else {
          p = Promise.resolve(new ArrayBuffer(0));
        }

        var self = this;
        return p.then(function () {
          if (!isReady()) return getPendingPromise();
          return null;
        }).then(function () {
          var secret = getSecret();
          if (!secret || !isReady()) return Promise.reject(new Error("RFW_TOKEN_NOT_READY"));
          return makeSign(secret, method, url, bodyBuf, getClockOffset()).then(function (r) {
            var h = new Headers(init.headers || (input && input.headers) || undefined);
            h.set(H_DATA, r.ts + "." + r.nonce + "." + r.sign);
            var signedInit = makeRetryFetchInit(input, init, method, h, bodyBuf, hasBody);
            return _fetch.call(self, input, signedInit).then(function (response) {
              if (!signedInit._rfwRetried && responseAuthorizesResign(response)) {
                // 第一次 403 未交给业务调用方；只可由服务端的 access 阶段
                // 明确授权后，校时/换 Key 并按原 method/url/body/headers 重生一次。
                return retryFetchOnce(self, input, init, method, url, bodyBuf, hasBody);
              }
              if (responseRequestsRecovery(response)) requestTokenRecovery();
              return response;
            });
          });
        }).catch(function (e) {
          return Promise.reject(e);
        });
      };
    }

    // ---- XMLHttpRequest ----
    if (typeof XMLHttpRequest !== "undefined") {
      var _open = XMLHttpRequest.prototype.open;
      var _send = XMLHttpRequest.prototype.send;
      var _setRequestHeader = XMLHttpRequest.prototype.setRequestHeader;
      var _addEventListener = XMLHttpRequest.prototype.addEventListener;
      var _removeEventListener = XMLHttpRequest.prototype.removeEventListener;
      var xhrHasEventTarget = typeof _addEventListener === "function";
      var XHR_GATED_EVENTS = ["readystatechange", "load", "loadend", "error", "timeout", "abort"];

      function isXhrGatedEvent(type) {
        return XHR_GATED_EVENTS.indexOf(String(type)) >= 0;
      }

      function callXhrUserHandler(x, type, event) {
        var handler = x._rfwUserHandlers && x._rfwUserHandlers[type];
        if (typeof handler === "function") {
          try { handler.call(x, event); } catch (e) { setTimeout(function () { throw e; }, 0); }
        }
        var list = x._rfwUserEvents && x._rfwUserEvents[type];
        if (list) {
          var copy = list.slice();
          for (var i = 0; i < copy.length; i++) {
            try { copy[i].listener.call(x, event); } catch (e2) { setTimeout(function () { throw e2; }, 0); }
          }
        }
      }

      function suppressNativeXhrEvent(event) {
        try { if (event) event.__rfwSuppressed = true; } catch (e0) {}
        try { if (event && event.stopImmediatePropagation) event.stopImmediatePropagation(); } catch (e) {}
        try { if (event && event.preventDefault) event.preventDefault(); } catch (e2) {}
      }

      function setXhrRfwHeader(x, value) {
        x._rfwApplyingHeaders = true;
        try { _setRequestHeader.call(x, H_DATA, value); } finally { x._rfwApplyingHeaders = false; }
      }

      function replayXhrOnce(x) {
        var meta = x._rfwMeta || {};
        return repairRfwAfterRecover().then(function () {
          var secret = getSecret();
          if (!secret || !isReady()) throw new Error("RFW_TOKEN_NOT_READY");
          var body = x._rfwBody;
          var p;
          if (body == null) p = Promise.resolve(new ArrayBuffer(0));
          else if (typeof body === "string") p = Promise.resolve(enc.encode(body).buffer);
          else if (body instanceof ArrayBuffer) p = Promise.resolve(body);
          else if (typeof ArrayBuffer !== "undefined" && ArrayBuffer.isView(body)) p = Promise.resolve(body.buffer);
          else p = new Response(body).arrayBuffer();
          return p.then(function (buf) {
            return makeSign(secret, meta.method, meta.url, buf, getClockOffset());
          });
        }).then(function (r) {
          // 服务端已保证第一次请求停在 access 阶段；重新 open 时浏览器会清空
          // 请求头，因此仅恢复业务头，并以新的 MA-RFW-Data 覆盖旧签名。
          _open.call(x, meta.method, meta.url, meta.async, meta.user, meta.pass);
          x._rfwApplyingHeaders = true;
          try {
            var headers = x._rfwRequestHeaders || [];
            for (var i = 0; i < headers.length; i++) {
              if (headers[i][0].toLowerCase() !== H_DATA.toLowerCase()) _setRequestHeader.call(x, headers[i][0], headers[i][1]);
            }
            _setRequestHeader.call(x, H_DATA, r.ts + "." + r.nonce + "." + r.sign);
          } finally { x._rfwApplyingHeaders = false; }
          x._rfwRetried = true;
          x._rfwRetrying = false;
          _send.call(x, x._rfwBody);
        }).catch(function () {
          // 修复失败时没有第二个 HTTP 响应可交付。以受控错误事件通知业务，
          // 仍绝不把无签名请求发送给服务端。
          x._rfwRetrying = false;
          callXhrUserHandler(x, "error", new Event("error"));
          callXhrUserHandler(x, "loadend", new Event("loadend"));
        });
      }

      function onNativeXhrEvent(x, event) {
        var type = event && event.type;
        if (!type) return;
        if (x._rfwRetrying) {
          suppressNativeXhrEvent(event);
          return;
        }
        var xhrRecoveryResponse = { status: x.status, headers: { get: function (name) { return x.getResponseHeader(name); } } };
        if ((type === "load" || (type === "readystatechange" && x.readyState === 4)) &&
            x._rfwAsync !== false && !x._rfwRetried &&
            responseAuthorizesResign(xhrRecoveryResponse)) {
          x._rfwRetrying = true;
          suppressNativeXhrEvent(event);
          replayXhrOnce(x);
          return;
        }
        if (type === "load" && responseRequestsRecovery(xhrRecoveryResponse)) {
          // 旧服务端仅有 Recover 头时仍刷新后续请求所用 Token，但绝不对
          // 当前请求重放；请求重生只接受新服务端显式 Retry 授权。
          requestTokenRecovery();
        }
        callXhrUserHandler(x, type, event);
      }

      function installXhrEventGate(x) {
        if (x._rfwEventGateInstalled) return;
        // 最小化测试/旧兼容实现可能没有 EventTarget 接口；此时无法拦截
        // 已完成响应，维持原有发送逻辑即可。真实浏览器均具备该接口。
        if (!xhrHasEventTarget) return;
        x._rfwEventGateInstalled = true;
        x._rfwUserEvents = {};
        x._rfwUserHandlers = {};
        for (var i = 0; i < XHR_GATED_EVENTS.length; i++) {
          (function (eventType) {
            x._rfwAddingInternal = true;
            _addEventListener.call(x, eventType, function (event) { onNativeXhrEvent(x, event); });
            x._rfwAddingInternal = false;
          })(XHR_GATED_EVENTS[i]);
        }
      }

      for (var gatedIndex = 0; gatedIndex < XHR_GATED_EVENTS.length; gatedIndex++) {
        (function (eventType) {
          var prop = "on" + eventType;
          var descriptor = Object.getOwnPropertyDescriptor(XMLHttpRequest.prototype, prop);
          if (descriptor && descriptor.configurable === false) return;
          Object.defineProperty(XMLHttpRequest.prototype, prop, {
            configurable: true,
            enumerable: descriptor ? descriptor.enumerable : true,
            get: function () {
              return this._rfwUserHandlers ? this._rfwUserHandlers[eventType] || null : (descriptor && descriptor.get ? descriptor.get.call(this) : null);
            },
            set: function (handler) {
              if (this._rfwUserHandlers) { this._rfwUserHandlers[eventType] = handler; return; }
              if (descriptor && descriptor.set) descriptor.set.call(this, handler);
            }
          });
        })(XHR_GATED_EVENTS[gatedIndex]);
      }

      XMLHttpRequest.prototype.open = function (method, url, async, user, pass) {
        this._rfwMeta = { method: String(method || "GET").toUpperCase(), url: url, async: async !== false, user: user, pass: pass };
        this._rfwAsync = (async !== false);
        this._rfwRetried = false;
        this._rfwRetrying = false;
        this._rfwRequestHeaders = [];
        installXhrEventGate(this);
        return _open.apply(this, arguments);
      };
      XMLHttpRequest.prototype.setRequestHeader = function (name, value) {
        if (!this._rfwApplyingHeaders) {
          this._rfwRequestHeaders = this._rfwRequestHeaders || [];
          this._rfwRequestHeaders.push([String(name), String(value)]);
        }
        return _setRequestHeader.apply(this, arguments);
      };
      if (xhrHasEventTarget) {
        XMLHttpRequest.prototype.addEventListener = function (type, listener, options) {
          if (isXhrGatedEvent(type) && !this._rfwAddingInternal) {
            var list = this._rfwUserEvents && this._rfwUserEvents[type];
            if (list) list.push({ listener: listener, options: options });
            return;
          }
          return _addEventListener.apply(this, arguments);
        };
        if (_removeEventListener) {
          XMLHttpRequest.prototype.removeEventListener = function (type, listener, options) {
            if (isXhrGatedEvent(type) && !this._rfwAddingInternal) {
              var list = this._rfwUserEvents && this._rfwUserEvents[type];
              if (list) {
                for (var i = list.length - 1; i >= 0; i--) {
                  if (list[i].listener === listener) list.splice(i, 1);
                }
              }
              return;
            }
            return _removeEventListener.apply(this, arguments);
          };
        }
      }
      XMLHttpRequest.prototype.send = function (body) {
        var x = this;
        var meta = x._rfwMeta || { method: "GET", url: "" };
        if (meta.url && !isSameOrigin(meta.url)) return _send.apply(this, arguments);
        if (isReloadLocked()) return;
        x._rfwBody = body;
        if (x._rfwAsync === false) {
          // 同步 XHR 不能等待异步 crypto.subtle，但 GET/字符串/二进制
          // 请求体可以用纯 JS 同步 HMAC 生成 MA-RFW-Data。若 dynamic key
          // 尚未就绪或 body 类型无法同步序列化，则直接阻止本次发送；
          // 不把未签名请求交给服务端触发连续 403。
          try {
            var syncSecret = getSecret();
            if (!syncSecret || !isReady()) {
              fetchAndApplyToken();
              return;
            }
            if (syncSecret && isReady()) {
              var syncBuf;
              if (body == null) {
                syncBuf = new ArrayBuffer(0);
              } else if (typeof body === "string") {
                syncBuf = enc.encode(body).buffer;
              } else if (body instanceof ArrayBuffer) {
                syncBuf = body;
              } else if (typeof ArrayBuffer !== "undefined" && ArrayBuffer.isView(body)) {
                syncBuf = body.buffer;
              } else {
                syncBuf = null;
              }
              if (syncBuf !== null) {
                var syncSign = makeSignSync(syncSecret, meta.method, meta.url, syncBuf, getClockOffset());
                setXhrRfwHeader(x, syncSign.ts + "." + syncSign.nonce + "." + syncSign.sign);
              }
            }
          } catch (e) {}
          return _send.apply(this, arguments);
        }

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
          if (!isReady()) {
            return getPendingPromise().then(function () { return buf; });
          }
          return buf;
        }).then(function (buf) {
          var secret = getSecret();
          // dynamic-only 必须 fail-closed。Token 获取超时、失败或被
          // 维护锁定后，绝不能把异步 XHR 原样交给原生 send，否则会
          // 形成 dynamic-sign-missing → IP blocked 的连续拒绝链。
          if (!secret || !isReady()) {
            if (window.console) console.warn("[rfw.js] 异步 XHR 未获取到有效 Token，已阻止发送");
            return;
          }
          return makeSign(secret, meta.method, meta.url, buf, getClockOffset()).then(function (r) {
            try { setXhrRfwHeader(x, r.ts + "." + r.nonce + "." + r.sign); } catch (e) {}
            _send.call(x, body);
          });
        }).catch(function () {
          return;
        });
      };
    }
  }

  // ============================================================
  // 模式分支
  // ============================================================
  // 灰度发布固定 dynamic-only；不读取 window.__RFW_MODE__ 或
  // window.__RFW_TOKEN__。这些全局变量均不属于安全信任边界。
  // ==========================================================
  // 动态模式: 从 /cgi-rfw/token 获取短期密钥
  // ==========================================================
  var dynKey       = null;   // 当前密钥字符串
  var dynClockOff  = 0;      // 服务端时间偏移
  var dynExpiresAt = 0;      // 密钥到期时间戳(ms)
  var dynReady     = false;  // 是否已获取过密钥(含 null)
  var dynNoKey     = false;  // 当前是否处于无密钥退避状态
  var pendingQueue = [];     // 密钥获取期间排队的请求 resolve 函数
  var retryTimer   = null;
  var tokenInFlight = null;
  var lastRecoveryAt = 0;
  // 必须在安装 fetch 拦截器之前保存原始 fetch。否则启动时获取
  // /cgi-rfw/token 会进入“等待 token 才发送 token 请求”的死锁。
  var rawFetch = window.fetch;
  // 软件发布号和协议版本都属于发布兼容性边界；任一不一致时都要求
  // 刷新页面，避免旧缓存脚本继续解释已更新的服务端实现。
  var CLIENT_VERSION = "4.3.12";
  var CLIENT_PROTOCOL = "MA-RFW-1";
  var serverVersion = tokenBroker && tokenBroker.version ? tokenBroker.version : null;
  var serverProtocol = tokenBroker && tokenBroker.protocol ? tokenBroker.protocol : null;
  var serverBootId = tokenBroker && tokenBroker.bootId ? tokenBroker.bootId : null;
  var reloadLocked = false;
  var reloadDialogShown = false;

  function showMaintenancePrompt() {
    if (tokenBroker) {
      if (tokenBroker.maintenanceNotified) return;
      tokenBroker.maintenanceNotified = true;
    } else {
      if (reloadDialogShown) return;
      reloadDialogShown = true;
    }
    var msg = "系统维护，请刷新页面。";
    try {
      var promptWindow = (typeof brokerRoot !== "undefined" && brokerRoot && typeof brokerRoot.alert === "function") ? brokerRoot : window;
      if (typeof promptWindow.alert === "function") promptWindow.alert(msg);
      else if (window.console) window.console.warn("[rfw.js] " + msg);
    } catch (e) {}
  }

  function lockForServerReload(signal) {
    if (isReloadLocked()) return;
    reloadLocked = true;
    if (tokenBroker) tokenBroker.reloadLocked = true;
    dynKey = null;
    dynReady = false;
    dynNoKey = true;
    if (retryTimer) { clearTimeout(retryTimer); retryTimer = null; }
    pendingQueue = [];
    showMaintenancePrompt();
    if (window.console) window.console.warn("[rfw.js] protocol/server signal requires page refresh: " + signal);
  }

  function applyProtocolSignal(data) {
    var nextVersion = data && data.rfw_version ? String(data.rfw_version) : "";
    var nextProtocol = data && data.rfw_protocol ? String(data.rfw_protocol) : "";
    if (nextProtocol && nextProtocol !== CLIENT_PROTOCOL) {
      lockForServerReload("protocol=" + nextProtocol);
      return false;
    }
    if (nextVersion && nextVersion !== CLIENT_VERSION) {
      lockForServerReload("version=" + nextVersion);
      return false;
    }
    if (nextVersion) serverVersion = nextVersion;
    if (nextProtocol) serverProtocol = nextProtocol;
    if (tokenBroker) {
      if (nextVersion) tokenBroker.version = nextVersion;
      if (nextProtocol) tokenBroker.protocol = nextProtocol;
    }
    return true;
  }

  function applyBootSignal(data) {
    var next = data && data.boot_id ? String(data.boot_id) : "";
    if (!next) return;
    // 同协议的新 Token 代表服务器已完成 reload；直接切换到新 Key，
    // 不把正常的 boot_id 轮换误判为需要用户刷新。
    serverBootId = next;
    if (tokenBroker) tokenBroker.bootId = next;
  }

  function isReloadLocked() { return reloadLocked || !!(tokenBroker && tokenBroker.reloadLocked); }

  function syncTokenFromBroker() {
    if (!tokenBroker || !tokenBroker.lastData || !tokenBroker.lastData.key) return false;
    if (tokenBroker.lastExpiresAt <= Date.now() + 30000) return false;
    // Broker 只共享同源页面已成功取得的 Token 响应；每个脚本闭包仍持有
    // 自己的 dynKey。iframe 先恢复后，主框架必须在下一次签名前套用该
    // 已验证响应，不能继续用本地“尚未过期”的旧 Key 造成 sign-invalid。
    if (!dynReady || dynKey !== tokenBroker.lastData.key) {
      applyTokenData(tokenBroker.lastData);
      return true;
    }
    return false;
  }

  function brokerRefreshPending() {
    // requestTokenRecovery 会先清空 lastData，再创建共享 Token 请求。
    // 在该窗口里任何同源上下文都必须等待该请求完成，不能抢先签发旧 Key。
    return !!(tokenBroker && tokenBroker.promise && !tokenBroker.lastData);
  }

  function requestTokenRecovery(force) {
    if (isReloadLocked()) return Promise.reject(new Error("RFW_RELOAD_REQUIRED"));
    var now = Date.now();
    if (!force && now - lastRecoveryAt < 1000) return tokenInFlight || Promise.resolve(null);
    lastRecoveryAt = now;
    dynKey = null;
    dynReady = false;
    dynNoKey = false;
    if (retryTimer) { clearTimeout(retryTimer); retryTimer = null; }
    // MA-RFW-Recover 表示当前签名对应的 Key 已被服务端拒绝；
    // 必须丢弃同源 Broker 的 lastData，否则 fetchAndApplyToken()
    // 会命中仍在 TTL 内的旧缓存，造成“刷新 Token 后仍连续 403”。
    if (tokenBroker) {
      tokenBroker.lastData = null;
      tokenBroker.lastExpiresAt = 0;
    }
    return fetchAndApplyToken();
  }

  function responseRequestsRecovery(response) {
    try {
      return response && response.status === 403 && response.headers &&
        response.headers.get("MA-RFW-Recover") === "token";
    } catch (e) { return false; }
  }

  function responseAuthorizesResign(response) {
    try {
      return response && response.status === 403 && response.headers &&
        response.headers.get("MA-RFW-Recover") === "token" &&
        response.headers.get("MA-RFW-Retry") === "resign";
    } catch (e) { return false; }
  }

  function applyTimeData(data) {
    if (!data || typeof data.server_time !== "number") return false;
    if (!applyProtocolSignal(data)) return false;
    applyBootSignal(data);
    dynClockOff = Math.floor(data.server_time) - Math.floor(Date.now() / 1000);
    return !isReloadLocked();
  }

  function fetchServerTime() {
    if (isReloadLocked()) return Promise.reject(new Error("RFW_RELOAD_REQUIRED"));
    if (tokenBroker && tokenBroker.timePromise) {
      return tokenBroker.timePromise.then(function (data) {
        applyTimeData(data);
        return data;
      });
    }
    var request = rawFetch("/cgi-rfw/time?t=" + Date.now(), {
      method: "GET",
      credentials: "same-origin",
      cache: "no-store"
    }).then(function (r) {
      if (!r.ok) throw new Error("HTTP " + r.status);
      return r.json();
    });
    if (tokenBroker) {
      tokenBroker.timePromise = request;
      request.then(function () {
        if (tokenBroker.timePromise === request) tokenBroker.timePromise = null;
      }, function () {
        if (tokenBroker.timePromise === request) tokenBroker.timePromise = null;
      });
    }
    return request.then(function (data) {
      applyTimeData(data);
      return data;
    });
  }

  function repairRfwAfterRecover() {
    // 客户端时间仅用于定位偏移；服务端仍以自己的时间、Key、HMAC 和 nonce
    // 独立验签。time 端点不发 Key、不消耗 Key 配额，随后才强制换取 Token。
    return fetchServerTime().catch(function () { return null; }).then(function () {
      return requestTokenRecovery(true);
    }).then(function (data) {
      if (!data || !data.key || !dynReady || !dynKey || Date.now() > dynExpiresAt - 30000) {
        throw new Error("RFW_TOKEN_NOT_READY");
      }
      return data;
    });
  }

  var DYN_COOKIE_NAME = "_RFW";
  var DYN_COOKIE_TTL = 86400;
  var DYN_COOKIE_TAG_HEX = 32;
  var DYN_COOKIE_REFRESH_MS = 30000;
  var dynCookieTimer = null;
  var dynCookieSeq = 0;

  function getCookie(name) {
    var m = new RegExp("(?:^|;\\s*)" + name + "=([^;]*)").exec(document.cookie || "");
    return m ? m[1] : null;
  }

  function parseDynamicCookie(v) {
    var m = new RegExp("^([0-9a-f]{" + DYN_COOKIE_TAG_HEX + "})\\.([\\w-]+)\\.(\\d+)\\.(\\d+)$", "i").exec(v || "");
    return m ? { sid: m[2], seq: parseInt(m[3], 10), ts: parseInt(m[4], 10) } : null;
  }

  function refreshDynamicCookie(force) {
    if (!dynKey || typeof document === "undefined") return;
    try {
      var prev = parseDynamicCookie(getCookie(DYN_COOKIE_NAME));
      var now = Date.now();
      if (!force && prev && (now - prev.ts) < DYN_COOKIE_REFRESH_MS) return;
      var sid = (prev && prev.sid) || "";
      if (!sid) {
        try { sid = localStorage.getItem("rfw_sid") || ""; } catch (e) { sid = ""; }
      }
      if (!sid) {
        sid = "j" + Math.random().toString(36).slice(2, 12) + "-" + now.toString(36);
        try { localStorage.setItem("rfw_sid", sid); } catch (e) {}
      }
      var seq = Math.max(prev ? prev.seq : 0, dynCookieSeq) + 1;
      dynCookieSeq = seq;
      // token 接口返回 server_time 后，使用服务端时钟签发 Cookie ts。
      var ts = now + dynClockOff * 1000;
      hmacHexWith(enc.encode(dynKey), "RFW:" + sid + "," + seq + "," + ts).then(function (sig) {
        document.cookie = DYN_COOKIE_NAME + "=" + sig.slice(0, DYN_COOKIE_TAG_HEX) + "." + sid + "." + seq + "." + ts +
          "; Path=/; SameSite=Lax; Max-Age=" + DYN_COOKIE_TTL;
      }).catch(function () {});
    } catch (e) {}
  }

  function startDynamicCookieRefresh() {
    if (typeof document === "undefined") return;
    refreshDynamicCookie(true);
    if (tokenBroker) {
      tokenBroker.cookieRefreshFn = function () { refreshDynamicCookie(false); };
      if (!tokenBroker.cookieTimer) {
        tokenBroker.cookieTimer = setInterval(function () {
          if (tokenBroker.cookieRefreshFn) tokenBroker.cookieRefreshFn();
        }, DYN_COOKIE_REFRESH_MS);
      }
      return;
    }
    if (!dynCookieTimer) {
      dynCookieTimer = setInterval(function () { refreshDynamicCookie(false); }, DYN_COOKIE_REFRESH_MS);
    }
  }

  function flushQueue() {
    var q = pendingQueue;
    pendingQueue = [];
    for (var i = 0; i < q.length; i++) {
      try { q[i](); } catch (e) {}
    }
  }

  function enterNoKeyMode() {
    if (isReloadLocked()) return;
    dynNoKey  = true;
    dynKey    = null;
    dynReady  = false;
    pendingQueue = [];
    // Token 暂时不可用时仍严格停止未签名业务请求，但这是可恢复的
    // 运行状态，不应冒充协议不兼容并要求用户刷新页面。
    if (retryTimer) clearTimeout(retryTimer);
    retryTimer = setTimeout(function () {
      retryTimer = null;
      dynNoKey = false;
      dynReady = false;
      fetchAndApplyToken();
    }, 5 * 60 * 1000);
    if (window.console) console.log("[rfw.js] 进入无签名模式, 5 分钟后重试");
  }

  function applyTokenData(data) {
    if (!data) return;
    if (!applyProtocolSignal(data)) return;
    applyBootSignal(data);
    if (isReloadLocked()) return;
    if (!data.key) {
      enterNoKeyMode();
      return;
    }
    dynKey       = data.key;
    var expiresIn = data.expires_in || 1800;
    dynExpiresAt = Date.now() + expiresIn * 1000;
    dynClockOff  = (data.server_time || Math.floor(Date.now() / 1000)) - Math.floor(Date.now() / 1000);
    dynNoKey     = false;
    dynReady     = true;
    DYN_COOKIE_TTL = data.cookie_ttl || DYN_COOKIE_TTL;
    DYN_COOKIE_TAG_HEX = Math.max(16, Math.min(64, data.cookie_tag_hex || DYN_COOKIE_TAG_HEX));
    if (retryTimer) { clearTimeout(retryTimer); retryTimer = null; }
    startDynamicCookieRefresh();
    flushQueue();
    if (tokenBroker) {
      if (tokenBroker.refreshTimer) clearTimeout(tokenBroker.refreshTimer);
      tokenBroker.refreshFn = fetchAndApplyToken;
      tokenBroker.refreshTimer = setTimeout(function () {
        tokenBroker.refreshTimer = null;
        if (tokenBroker.refreshFn) tokenBroker.refreshFn();
      }, Math.max((expiresIn - 30) * 1000, 5000));
    } else {
      setTimeout(fetchAndApplyToken, Math.max((expiresIn - 30) * 1000, 5000));
    }
    if (window.console) console.log("[rfw.js] token 获取成功, expires_in=" + expiresIn + "s, clock_offset=" + dynClockOff + "s");
  }

  function fetchAndApplyToken() {
    if (isReloadLocked()) return Promise.reject(new Error("RFW_RELOAD_REQUIRED"));
    if (tokenInFlight) return tokenInFlight;
    if (tokenBroker && tokenBroker.promise) {
      tokenInFlight = tokenBroker.promise.then(function (data) {
        applyTokenData(data);
        return data;
      }).then(function (data) {
        tokenInFlight = null;
        return data;
      });
      return tokenInFlight;
    }
    if (tokenBroker && tokenBroker.lastData && tokenBroker.lastExpiresAt > Date.now() + 30000) {
      applyTokenData(tokenBroker.lastData);
      return Promise.resolve(tokenBroker.lastData);
    }
    var request = rawFetch("/cgi-rfw/token?t=" + Date.now(), {
      method: "GET",
      credentials: "same-origin",
      cache: "no-store"
    }).then(function (r) {
      if (!r.ok) throw new Error("HTTP " + r.status);
      return r.json();
    }).then(function (data) {
      if (tokenBroker) {
        tokenBroker.lastData = data;
        tokenBroker.lastExpiresAt = Date.now() + (data.expires_in || 1800) * 1000;
      }
      return data;
    }).catch(function (e) {
      if (window.console) window.console.log("[rfw.js] token 获取失败:", e.message || e);
      enterNoKeyMode();
      return null;
    });
    if (tokenBroker) {
      tokenBroker.promise = request;
      request.then(function () {
        if (tokenBroker.promise === request) tokenBroker.promise = null;
      });
    }
    tokenInFlight = request.then(function (data) {
      applyTokenData(data);
      tokenInFlight = null;
      return data;
    });
    return tokenInFlight;
  }

  installInterceptors(
    function () {
      if (isReloadLocked()) return Promise.reject(new Error("RFW_RELOAD_REQUIRED"));
      return new Promise(function (resolve) {
        var resolved = false;
        var timer = setTimeout(function () {
          if (resolved) return;
          resolved = true;
          if (isReloadLocked()) return;
          if (window.console) console.warn("[rfw.js] 密钥获取超时(5s)，停止未签名业务请求");
          if (!dynReady) {
            dynNoKey = true;
            dynKey   = null;
            // 保持未就绪状态。fetch 会拒绝，XHR 会直接停止；二者都不
            // 可以带着空 Header 触发 dynamic-sign-missing。
            dynReady = false;
            if (retryTimer) clearTimeout(retryTimer);
            retryTimer = setTimeout(function () {
              retryTimer = null;
              dynNoKey = false;
              dynReady = false;
              fetchAndApplyToken();
            }, 5 * 60 * 1000);
          }
          resolve();
        }, 5000);
          pendingQueue.push(function () {
            if (resolved) return;
            resolved = true;
            clearTimeout(timer);
            resolve();
          });
          // 后台挂起可能冻结 refreshTimer；业务请求恢复时主动拉取
          // 新 Token，不能只等待一个已经被冻结的定时器。
          fetchAndApplyToken();
      });
    },
    function () {
      syncTokenFromBroker();
      return (dynNoKey || isReloadLocked() || brokerRefreshPending()) ? null : dynKey;
    },
    function () { return dynClockOff; },
    function () {
      syncTokenFromBroker();
      return dynReady && !isReloadLocked() && !brokerRefreshPending() && !!dynKey && Date.now() <= dynExpiresAt - 30000;
    }
  );

  // 自动恢复: 页面可见/focus 时重新取 token
  ["pageshow", "visibilitychange", "focus"].forEach(function (ev) {
    window.addEventListener(ev, function () {
      if (isReloadLocked()) return;
      if (!dynKey || Date.now() > dynExpiresAt - 30000) {
        dynReady = false;
        dynNoKey = false;
        if (retryTimer) { clearTimeout(retryTimer); retryTimer = null; }
        fetchAndApplyToken();
      }
    }, false);
  });

  // 启动
  fetchAndApplyToken();
})();
