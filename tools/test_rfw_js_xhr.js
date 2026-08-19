const fs = require('fs');
const path = require('path');
const vm = require('vm');

class MockXHR {
  constructor() { this.headers = {}; this.sent = false; }
  open(method, url, async) { this.method = method; this.url = url; this.async = async; }
  setRequestHeader(name, value) { this.headers[name] = String(value); }
  send(body) { this.body = body; this.sent = true; }
}

function makeContext() {
  const token = {
    key: 'dynamic-test-key', expires_in: 1800,
    server_time: Math.floor(Date.now() / 1000),
    cookie_ttl: 86400, cookie_tag_hex: 32
  };
  const window = {
    // 模拟攻击者在 RFW 脚本加载前篡改客户端全局变量。
    __RFW__: { loaded: true, forged: true },
    __RFW_MODE__: 'static',
    __RFW_TOKEN__: 'forged-static-secret',
    fetch: function () {
      return Promise.resolve({ ok: true, json: () => Promise.resolve(token) });
    },
    addEventListener: function () {},
    console: { log() {}, warn() {} }
  };
  const context = {
    window, XMLHttpRequest: MockXHR,
    document: { cookie: '', baseURI: 'http://localhost/portal-web/' },
    location: { href: 'http://localhost/portal-web/', host: 'localhost', hostname: 'localhost' },
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
  return context;
}

(async () => {
  const context = makeContext();
  await new Promise(resolve => setImmediate(resolve));
  await new Promise(resolve => setImmediate(resolve));

  for (const asyncValue of [true, false]) {
    const x = new context.XMLHttpRequest();
    x.open('GET', '/portal-web/portal/DataDictController/getDevToolMd5.do', asyncValue);
    x.send(null);
    if (asyncValue) {
      await new Promise(resolve => setImmediate(resolve));
      await new Promise(resolve => setImmediate(resolve));
    }
    const value = x.headers.RFWDATA;
    if (!value) throw new Error('RFWDATA missing for async=' + asyncValue);
    if (!/^\d+\.[\w-]+\.[0-9a-f]{64}$/.test(value)) {
      throw new Error('invalid RFWDATA for async=' + asyncValue);
    }
    if (!x.sent) throw new Error('native XHR send was not called');
  }
  if (context.window.__RFW_MODE__ !== 'static') throw new Error('test fixture changed unexpectedly');
  console.log('PASS dynamic async and sync XHR RFWDATA with forged globals ignored');
})().catch(err => { console.error(err); process.exit(1); });
