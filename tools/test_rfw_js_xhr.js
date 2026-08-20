const fs = require('fs');
const path = require('path');
const vm = require('vm');

class MockXHR {
  constructor() { this.headers = {}; this.sent = false; }
  open(method, url, async) { this.method = method; this.url = url; this.async = async; }
  setRequestHeader(name, value) { this.headers[name] = String(value); }
  send(body) { this.body = body; this.sent = true; }
}

function makeContext(options = {}) {
  const tokenResponses = options.tokenResponses || [{
    key: 'dynamic-test-key', expires_in: 1800,
    server_time: Math.floor(Date.now() / 1000),
    cookie_ttl: 86400, cookie_tag_hex: 32, boot_id: 'boot-a', rfw_version: '4.3.6', rfw_protocol: 'MA-RFW-1'
  }];
  let tokenIndex = 0;
  const calls = options.calls || { token: 0, business: 0 };
  const listeners = {};
  const window = {
    // 模拟攻击者在 RFW 脚本加载前篡改客户端全局变量。
    __RFW__: { loaded: true, forged: true },
    __RFW_MODE__: 'static',
    __RFW_TOKEN__: 'forged-static-secret',
    fetch: function (url, init) {
      if (String(url).indexOf('/cgi-rfw/token') === 0) {
        calls.token++;
        const token = tokenResponses[Math.min(tokenIndex++, tokenResponses.length - 1)];
        return Promise.resolve({ ok: true, json: () => Promise.resolve(token) });
      }
      calls.business++;
      if (typeof options.businessResponse === 'function') {
        return Promise.resolve(options.businessResponse({ url: String(url), init }));
      }
      return Promise.resolve(options.businessResponse || { ok: true, headers: { get() { return null; } } });
    },
    addEventListener: function (name, fn) {
      (listeners[name] || (listeners[name] = [])).push(fn);
    },
    dispatchEvent: function (name) {
      for (const fn of (listeners[name] || [])) fn();
    },
    alert: function (message) { calls.alert = message; },
    console: { log() {}, warn() {} }
  };
  window.location = { origin: 'http://localhost', href: 'http://localhost/webapp/' };
  window.top = options.topWindow || window;
  const context = {
    window, XMLHttpRequest: MockXHR,
    document: { cookie: '', baseURI: 'http://localhost/webapp/' },
    location: window.location,
    TextEncoder, URL, Headers, Response, ArrayBuffer, Uint8Array, DataView,
    Promise, Math, Date,
    setInterval: function () { return 1; }, clearInterval: function () {},
    setTimeout: function (fn, delay) {
      if (delay != null && delay < 100) Promise.resolve().then(fn);
      return 1;
    },
    clearTimeout: function () {},
    crypto: {}, console: window.console
  };
  vm.createContext(context);
  vm.runInContext(
    fs.readFileSync(path.join(__dirname, '..', 'rfw.js'), 'utf8'),
    context,
    { filename: 'rfw.js' }
  );
  context.calls = calls;
  context.reloadSource = fs.readFileSync(path.join(__dirname, '..', 'rfw.js'), 'utf8');
  return context;
}

(async () => {
  const context = makeContext();
  await new Promise(resolve => setImmediate(resolve));
  await new Promise(resolve => setImmediate(resolve));

  for (const asyncValue of [true, false]) {
    const x = new context.XMLHttpRequest();
    x.open('GET', '/webapp/portal/DataDictController/getDevToolMd5.do', asyncValue);
    x.send(null);
    if (asyncValue) {
      await new Promise(resolve => setImmediate(resolve));
      await new Promise(resolve => setImmediate(resolve));
    }
    const value = x.headers['MA-RFW-Data'];
    if (!value) throw new Error('MA-RFW-Data missing for async=' + asyncValue);
    if (!/^\d+\.[\w-]+\.[0-9a-f]{64}$/.test(value)) {
      throw new Error('invalid MA-RFW-Data for async=' + asyncValue);
    }
    if (!x.sent) throw new Error('native XHR send was not called');
  }
  if (context.window.__RFW_MODE__ !== 'static') throw new Error('test fixture changed unexpectedly');

  // 同一 Window 重复加载脚本时不得重复安装拦截器或重复获取 Token。
  vm.runInContext(context.reloadSource, context, { filename: 'rfw-duplicate.js' });
  await new Promise(resolve => setImmediate(resolve));
  if (context.calls.token !== 1) throw new Error('duplicate script caused extra Token request: ' + context.calls.token);

  // 同源 iframe 与主窗口共享 Broker；两份脚本只允许发出一个 Token 请求。
  const sharedCalls = { token: 0, business: 0 };
  const topWindow = { location: { origin: 'http://localhost' } };
  const main = makeContext({ calls: sharedCalls, topWindow });
  const frame = makeContext({ calls: sharedCalls, topWindow });
  await new Promise(resolve => setImmediate(resolve));
  await new Promise(resolve => setImmediate(resolve));
  if (sharedCalls.token !== 1) throw new Error('same-origin Broker did not deduplicate Token requests: ' + sharedCalls.token);

  // 同协议 boot_id 变化必须自动切换新 Token，不需要手动刷新。
  const bootCalls = { token: 0, business: 0 };
  const boot = makeContext({
    calls: bootCalls,
    tokenResponses: [
      { key: 'key-a', expires_in: 1, server_time: Math.floor(Date.now() / 1000), cookie_ttl: 86400, cookie_tag_hex: 32, boot_id: 'boot-a', rfw_version: '4.3.6', rfw_protocol: 'MA-RFW-1' },
      { key: 'key-b', expires_in: 1800, server_time: Math.floor(Date.now() / 1000), cookie_ttl: 86400, cookie_tag_hex: 32, boot_id: 'boot-b', rfw_version: '4.3.6', rfw_protocol: 'MA-RFW-1' }
    ]
  });
  await new Promise(resolve => setImmediate(resolve));
  boot.window.dispatchEvent('focus');
  await new Promise(resolve => setImmediate(resolve));
  await new Promise(resolve => setImmediate(resolve));
  let blocked = false;
  try { await boot.window.fetch('/webapp/api-after-reload', { method: 'GET' }); } catch (e) { blocked = true; }
  if (blocked || bootCalls.business !== 1 || bootCalls.token !== 2 || bootCalls.alert) {
    throw new Error('same-protocol boot_id auto-refresh failed: ' + JSON.stringify(bootCalls));
  }

  // recovery 403 必须清空 Broker 旧缓存并真正获取第二个 Token。
  const recoveryCalls = { token: 0, business: 0 };
  const recovery = makeContext({
    calls: recoveryCalls,
    tokenResponses: [
      { key: 'recovery-old-key', expires_in: 1800, server_time: Math.floor(Date.now() / 1000), cookie_ttl: 86400, cookie_tag_hex: 32, boot_id: 'boot-a', rfw_version: '4.3.6', rfw_protocol: 'MA-RFW-1' },
      { key: 'recovery-new-key', expires_in: 1800, server_time: Math.floor(Date.now() / 1000), cookie_ttl: 86400, cookie_tag_hex: 32, boot_id: 'boot-b', rfw_version: '4.3.6', rfw_protocol: 'MA-RFW-1' }
    ],
    businessResponse: () => ({ ok: false, status: 403, headers: { get(name) { return name === 'MA-RFW-Recover' ? 'token' : null; } } })
  });
  await new Promise(resolve => setImmediate(resolve));
  await recovery.window.fetch('/webapp/recovery-first', { method: 'GET' });
  await new Promise(resolve => setImmediate(resolve));
  await new Promise(resolve => setImmediate(resolve));
  await recovery.window.fetch('/webapp/recovery-second', { method: 'GET' });
  await new Promise(resolve => setImmediate(resolve));
  if (recoveryCalls.token !== 2 || recoveryCalls.business !== 2) {
    throw new Error('MA-RFW-Recover did not force fresh Token: ' + JSON.stringify(recoveryCalls));
  }

  // 旧服务端协议/版本必须 fail-closed，并只显示通用维护提示。
  const oldCalls = { token: 0, business: 0 };
  const old = makeContext({
    calls: oldCalls,
    tokenResponses: [{ key: 'old-key', expires_in: 1800, server_time: Math.floor(Date.now() / 1000), cookie_ttl: 86400, cookie_tag_hex: 32, boot_id: 'old-boot', rfw_version: '4.3.4', rfw_protocol: 'MA-RFW-1' }]
  });
  await new Promise(resolve => setImmediate(resolve));
  let oldBlocked = false;
  try { await old.window.fetch('/webapp/api-old-server', { method: 'GET' }); } catch (e) { oldBlocked = true; }
  if (!oldBlocked || oldCalls.business !== 0 || oldCalls.token !== 1 || oldCalls.alert !== '系统维护，请刷新页面。') {
    throw new Error('old server protocol guard failed: ' + JSON.stringify(oldCalls));
  }
  console.log('PASS dynamic async/sync XHR, duplicate-load Token dedupe, same-origin Broker, boot auto-refresh, and old-protocol fail-closed');
})().catch(err => { console.error(err); process.exit(1); });
