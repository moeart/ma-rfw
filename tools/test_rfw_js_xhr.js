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
    cookie_ttl: 86400, cookie_tag_hex: 32, boot_id: 'boot-a'
  }];
  let tokenIndex = 0;
  const calls = options.calls || { token: 0, business: 0 };
  const listeners = {};
  const window = {
    // 模拟攻击者在 RFW 脚本加载前篡改客户端全局变量。
    __RFW__: { loaded: true, forged: true },
    __RFW_MODE__: 'static',
    __RFW_TOKEN__: 'forged-static-secret',
    fetch: function (url) {
      if (String(url).indexOf('/cgi-rfw/token') === 0) {
        calls.token++;
        const token = tokenResponses[Math.min(tokenIndex++, tokenResponses.length - 1)];
        return Promise.resolve({ ok: true, json: () => Promise.resolve(token) });
      }
      calls.business++;
      return Promise.resolve({ ok: true, headers: { get() { return null; } } });
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

  // boot_id 变化必须锁定业务请求，且不再把请求交给原始 fetch。
  const bootCalls = { token: 0, business: 0 };
  const boot = makeContext({
    calls: bootCalls,
    tokenResponses: [
      { key: 'key-a', expires_in: 1, server_time: Math.floor(Date.now() / 1000), cookie_ttl: 86400, cookie_tag_hex: 32, boot_id: 'boot-a' },
      { key: 'key-b', expires_in: 1800, server_time: Math.floor(Date.now() / 1000), cookie_ttl: 86400, cookie_tag_hex: 32, boot_id: 'boot-b' }
    ]
  });
  await new Promise(resolve => setImmediate(resolve));
  boot.window.dispatchEvent('focus');
  await new Promise(resolve => setImmediate(resolve));
  await new Promise(resolve => setImmediate(resolve));
  let blocked = false;
  try { await boot.window.fetch('/webapp/api-after-reload', { method: 'GET' }); } catch (e) { blocked = true; }
  if (!blocked || bootCalls.business !== 0 || bootCalls.token !== 2 || bootCalls.alert.indexOf('服务器已重启') < 0) {
    throw new Error('boot_id reload lock failed: ' + JSON.stringify(bootCalls));
  }
  console.log('PASS dynamic async/sync XHR, duplicate-load Token dedupe, same-origin Broker, and boot reload lock');
})().catch(err => { console.error(err); process.exit(1); });
