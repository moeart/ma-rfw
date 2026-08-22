const fs = require('fs');
const path = require('path');
const vm = require('vm');
const nodeCrypto = require('crypto');

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
    cookie_ttl: 86400, cookie_tag_hex: 32, boot_id: 'boot-a', rfw_version: '4.3.12', rfw_protocol: 'MA-RFW-1'
  }];
  let tokenIndex = 0;
  const calls = options.calls || { token: 0, time: 0, business: 0 };
  if (typeof calls.time !== 'number') calls.time = 0;
  const listeners = {};
  const timers = [];
  const window = {
    // 模拟攻击者在 RFW 脚本加载前篡改客户端全局变量。
    __RFW__: { loaded: true, forged: true },
    __RFW_MODE__: 'static',
    __RFW_TOKEN__: 'forged-static-secret',
    fetch: function (url, init) {
      if (String(url).indexOf('/cgi-rfw/token') === 0) {
        calls.token++;
        if (options.tokenFailure) {
          return Promise.resolve({ ok: false, status: 503, json: () => Promise.reject(new Error('token unavailable')) });
        }
        const token = tokenResponses[Math.min(tokenIndex++, tokenResponses.length - 1)];
        return Promise.resolve({ ok: true, json: () => Promise.resolve(token) });
      }
      if (String(url).indexOf('/cgi-rfw/time') === 0) {
        calls.time++;
        const time = options.timeResponse || {
          server_time: Math.floor(Date.now() / 1000), boot_id: 'boot-a',
          rfw_version: '4.3.12', rfw_protocol: 'MA-RFW-1'
        };
        return Promise.resolve({ ok: true, json: () => Promise.resolve(time) });
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
    alert: function (message) { calls.alert = message; calls.alerts = (calls.alerts || 0) + 1; },
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
      const timer = { fn, delay: delay == null ? 0 : delay };
      timers.push(timer);
      if (timer.delay < 100) Promise.resolve().then(fn);
      return timers.length;
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
  context.runTimers = function (limit) {
    const pending = timers.splice(0, timers.length);
    for (const timer of pending) {
      if (timer.delay <= limit) timer.fn();
      else timers.push(timer);
    }
  };
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
      { key: 'key-a', expires_in: 1, server_time: Math.floor(Date.now() / 1000), cookie_ttl: 86400, cookie_tag_hex: 32, boot_id: 'boot-a', rfw_version: '4.3.12', rfw_protocol: 'MA-RFW-1' },
      { key: 'key-b', expires_in: 1800, server_time: Math.floor(Date.now() / 1000), cookie_ttl: 86400, cookie_tag_hex: 32, boot_id: 'boot-b', rfw_version: '4.3.12', rfw_protocol: 'MA-RFW-1' }
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
      { key: 'recovery-old-key', expires_in: 1800, server_time: Math.floor(Date.now() / 1000), cookie_ttl: 86400, cookie_tag_hex: 32, boot_id: 'boot-a', rfw_version: '4.3.12', rfw_protocol: 'MA-RFW-1' },
      { key: 'recovery-new-key', expires_in: 1800, server_time: Math.floor(Date.now() / 1000), cookie_ttl: 86400, cookie_tag_hex: 32, boot_id: 'boot-b', rfw_version: '4.3.12', rfw_protocol: 'MA-RFW-1' }
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

  // 同源 iframe 先恢复时，新的 Token 响应存在顶层 Broker；主框架的
  // dynKey 闭包不能继续以“本地尚未过期”为由签发旧 Key。主框架下一次
  // 请求必须同步 Broker 最新 Key，且不再额外请求 Token。
  const iframeFirstCalls = { token: 0, time: 0, business: 0 };
  const iframeFirstTop = { location: { origin: 'http://localhost' } };
  let mainSignedData = null;
  const mainAfterIframe = makeContext({
    calls: iframeFirstCalls,
    topWindow: iframeFirstTop,
    tokenResponses: [
      { key: 'iframe-first-old-key', expires_in: 1800, server_time: Math.floor(Date.now() / 1000), cookie_ttl: 86400, cookie_tag_hex: 32, boot_id: 'boot-a', rfw_version: '4.3.12', rfw_protocol: 'MA-RFW-1' }
    ],
    businessResponse: ({ init }) => {
      mainSignedData = init.headers.get('MA-RFW-Data');
      return { status: 200, headers: { get() { return null; } } };
    }
  });
  await new Promise(resolve => setImmediate(resolve));
  const iframeFirst = makeContext({
    calls: iframeFirstCalls,
    topWindow: iframeFirstTop,
    tokenResponses: [
      { key: 'iframe-first-new-key', expires_in: 1800, server_time: Math.floor(Date.now() / 1000), cookie_ttl: 86400, cookie_tag_hex: 32, boot_id: 'boot-b', rfw_version: '4.3.12', rfw_protocol: 'MA-RFW-1' }
    ],
    timeResponse: { server_time: Math.floor(Date.now() / 1000), boot_id: 'boot-b', rfw_version: '4.3.12', rfw_protocol: 'MA-RFW-1' },
    businessResponse: ({ init }) => {
      if (init._rfwRetried) return { status: 200, headers: { get() { return null; } } };
      return { status: 403, headers: { get(name) { return name === 'MA-RFW-Recover' ? 'token' : (name === 'MA-RFW-Retry' ? 'resign' : null); } } };
    }
  });
  await new Promise(resolve => setImmediate(resolve));
  const iframeResponse = await iframeFirst.window.fetch('/webapp/iframe-first-recovery', { method: 'GET' });
  if (iframeResponse.status !== 200) throw new Error('iframe-first recovery did not complete');
  await mainAfterIframe.window.fetch('/webapp/main-after-iframe', { method: 'GET' });
  const [brokerTs, brokerNonce, brokerSig] = String(mainSignedData || '').split('.');
  const emptyBodyHash = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855';
  const brokerInput = `GET|/webapp/main-after-iframe|${emptyBodyHash}|${brokerTs}|${brokerNonce}`;
  const expectedBrokerSig = nodeCrypto.createHmac('sha256', 'iframe-first-new-key').update(brokerInput).digest('hex');
  if (!mainSignedData || brokerSig !== expectedBrokerSig || iframeFirstCalls.token !== 2) {
    throw new Error('main frame did not synchronize new Broker Token after iframe recovery: ' + JSON.stringify({ calls: iframeFirstCalls, mainSignedData }));
  }

  // 服务端明确 MA-RFW-Retry: resign 时，首次 403 必须只留在拦截器内：
  // 校时、强制换 Token、重新签名后，业务 fetch 只能拿到第二次响应。
  const resignCalls = { token: 0, time: 0, business: 0 };
  let firstRetryData = null;
  const resign = makeContext({
    calls: resignCalls,
    tokenResponses: [
      { key: 'resign-old-key', expires_in: 1800, server_time: Math.floor(Date.now() / 1000), cookie_ttl: 86400, cookie_tag_hex: 32, boot_id: 'boot-a', rfw_version: '4.3.12', rfw_protocol: 'MA-RFW-1' },
      { key: 'resign-new-key', expires_in: 1800, server_time: Math.floor(Date.now() / 1000), cookie_ttl: 86400, cookie_tag_hex: 32, boot_id: 'boot-b', rfw_version: '4.3.12', rfw_protocol: 'MA-RFW-1' }
    ],
    timeResponse: { server_time: Math.floor(Date.now() / 1000), boot_id: 'boot-b', rfw_version: '4.3.12', rfw_protocol: 'MA-RFW-1' },
    businessResponse: ({ init }) => {
      if (resignCalls.business === 1) {
        firstRetryData = init.headers.get('MA-RFW-Data');
        return { status: 403, headers: { get(name) { return name === 'MA-RFW-Recover' ? 'token' : (name === 'MA-RFW-Retry' ? 'resign' : null); } } };
      }
      if (init._rfwRetried !== true) throw new Error('authorized retry did not carry one-shot marker');
      const retryData = init.headers.get('MA-RFW-Data');
      if (!retryData || retryData === firstRetryData) throw new Error('authorized retry reused original MA-RFW-Data');
      return { status: 200, headers: { get() { return null; } } };
    }
  });
  await new Promise(resolve => setImmediate(resolve));
  const resignResponse = await resign.window.fetch('/webapp/resign-once', { method: 'POST', body: '{"approved":true}' });
  if (resignResponse.status !== 200 || resignCalls.business !== 2 || resignCalls.time !== 1 || resignCalls.token !== 2) {
    throw new Error('authorized 403 was not repaired and replayed exactly once: ' + JSON.stringify(resignCalls));
  }

  // 缺少服务端授权头的 403 代表攻击/策略拒绝，绝不能校时、换 Token 或重放。
  const attackCalls = { token: 0, time: 0, business: 0 };
  const attack = makeContext({
    calls: attackCalls,
    businessResponse: () => ({ status: 403, headers: { get() { return null; } } })
  });
  await new Promise(resolve => setImmediate(resolve));
  const attackResponse = await attack.window.fetch('/webapp/attack-deny', { method: 'GET' });
  if (attackResponse.status !== 403 || attackCalls.business !== 1 || attackCalls.time !== 0 || attackCalls.token !== 1) {
    throw new Error('unauthorized 403 unexpectedly triggered repair/replay: ' + JSON.stringify(attackCalls));
  }

  // 后台挂起导致本地 Token 过期时，业务 fetch 必须先获取新 Token。
  const expiredCalls = { token: 0, business: 0 };
  const expired = makeContext({
    calls: expiredCalls,
    tokenResponses: [
      { key: 'expired-old-key', expires_in: 1, server_time: Math.floor(Date.now() / 1000), cookie_ttl: 86400, cookie_tag_hex: 32, boot_id: 'boot-a', rfw_version: '4.3.12', rfw_protocol: 'MA-RFW-1' },
      { key: 'expired-new-key', expires_in: 1800, server_time: Math.floor(Date.now() / 1000), cookie_ttl: 86400, cookie_tag_hex: 32, boot_id: 'boot-b', rfw_version: '4.3.12', rfw_protocol: 'MA-RFW-1' }
    ]
  });
  await new Promise(resolve => setImmediate(resolve));
  const savedDateNow = Date.now;
  const resumeNow = savedDateNow() + 5000;
  expired.Date.now = () => resumeNow;
  await expired.window.fetch('/webapp/background-expired', { method: 'GET' });
  await new Promise(resolve => setImmediate(resolve));
  await new Promise(resolve => setImmediate(resolve));
  expired.Date.now = savedDateNow;
  if (expiredCalls.token !== 2 || expiredCalls.business !== 1) {
    throw new Error('background-expired token gate failed: ' + JSON.stringify(expiredCalls));
  }

  // 真实 Chromium 多 iframe 场景发现：Token 503 后，异步 XHR 必须在
  // 5 秒等待门禁超时后 fail-closed；绝不能原样调用原生 send 形成
  // dynamic-sign-missing。这里直接断言 native MockXHR.sent 始终为 false。
  const outageCalls = { token: 0, business: 0 };
  const outage = makeContext({ calls: outageCalls, tokenFailure: true });
  await new Promise(resolve => setImmediate(resolve));
  const outageXhr = new outage.XMLHttpRequest();
  outageXhr.open('GET', '/webapp/portal/SecurityCacheController/getServiceFrontend.do', true);
  outageXhr.send(null);
  await new Promise(resolve => setImmediate(resolve));
  outage.runTimers(5000);
  await new Promise(resolve => setImmediate(resolve));
  await new Promise(resolve => setImmediate(resolve));
  if (outageXhr.sent || outageCalls.business !== 0 || outageCalls.token < 2 || outageCalls.alerts) {
    throw new Error('token-outage async XHR was not fail-closed: ' + JSON.stringify({ calls: outageCalls, sent: outageXhr.sent }));
  }

  // 软件发布号不一致也属于发布兼容性边界，必须在业务请求前 fail-closed。
  const versionCalls = { token: 0, business: 0 };
  const versionTop = { location: { origin: 'http://localhost' } };
  const versionMain = makeContext({
    calls: versionCalls, topWindow: versionTop,
    tokenResponses: [{ key: 'same-protocol-key', expires_in: 1800, server_time: Math.floor(Date.now() / 1000), cookie_ttl: 86400, cookie_tag_hex: 32, boot_id: 'boot-a', rfw_version: '4.3.11', rfw_protocol: 'MA-RFW-1' }]
  });
  await new Promise(resolve => setImmediate(resolve));
  let versionBlocked = false;
  try { await versionMain.window.fetch('/webapp/version-mismatch', { method: 'GET' }); } catch (e) { versionBlocked = true; }
  if (!versionBlocked || versionCalls.business !== 0 || versionCalls.alerts !== 1 || versionCalls.token !== 1) {
    throw new Error('software version mismatch did not fail-closed: ' + JSON.stringify(versionCalls));
  }

  // 真正的协议失配仍必须 fail-closed；同源主框架与 iframe 合计只可提示一次。
  const protocolCalls = { token: 0, business: 0 };
  const protocolTop = { location: { origin: 'http://localhost' } };
  const protocolMain = makeContext({
    calls: protocolCalls, topWindow: protocolTop,
    tokenResponses: [{ key: 'bad-protocol-key', expires_in: 1800, server_time: Math.floor(Date.now() / 1000), cookie_ttl: 86400, cookie_tag_hex: 32, boot_id: 'boot-a', rfw_version: '4.3.12', rfw_protocol: 'MA-RFW-2' }]
  });
  const protocolFrame = makeContext({ calls: protocolCalls, topWindow: protocolTop });
  await new Promise(resolve => setImmediate(resolve));
  let protocolBlocked = false;
  try { await protocolMain.window.fetch('/webapp/protocol-mismatch', { method: 'GET' }); } catch (e) { protocolBlocked = true; }
  if (!protocolBlocked || protocolCalls.business !== 0 || protocolCalls.alerts !== 1 || protocolCalls.token !== 1) {
    throw new Error('protocol mismatch did not fail-closed with one shared alert: ' + JSON.stringify(protocolCalls));
  }

  // 旧协议必须 fail-closed，并只显示通用维护提示。
  const oldCalls = { token: 0, business: 0 };
  const old = makeContext({
    calls: oldCalls,
    tokenResponses: [{ key: 'old-key', expires_in: 1800, server_time: Math.floor(Date.now() / 1000), cookie_ttl: 86400, cookie_tag_hex: 32, boot_id: 'old-boot', rfw_version: '4.3.12', rfw_protocol: 'MA-RFW-0' }]
  });
  await new Promise(resolve => setImmediate(resolve));
  let oldBlocked = false;
  try { await old.window.fetch('/webapp/api-old-server', { method: 'GET' }); } catch (e) { oldBlocked = true; }
  if (!oldBlocked || oldCalls.business !== 0 || oldCalls.token !== 1 || oldCalls.alert !== '系统维护，请刷新页面。') {
    throw new Error('old protocol guard failed: ' + JSON.stringify(oldCalls));
  }
  console.log('PASS dynamic async/sync XHR, authorized one-shot fetch resign, iframe-first Broker Token synchronization, unauthorized 403 no-retry, Token-outage XHR fail-closed, duplicate-load Token dedupe, same-origin Broker, boot auto-refresh, and old-protocol fail-closed');
})().catch(err => { console.error(err); process.exit(1); });
