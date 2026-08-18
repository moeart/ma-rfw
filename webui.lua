local cjson = require("cjson")
local io = require("io")

local _M = {}

local VERSION = "3.0.0"
local PROJECT = "MA-RFW"
local BRAND_COLOR = "#8b5cf6"

local src = debug.getinfo(1, "S").source
local plugin_dir = (src:sub(1, 1) == "@" and src:sub(2) or src):match("^(.*)[/\\][^/\\]+$") or "."

local config
do
    local f = io.open(plugin_dir .. "/config.json", "r")
    if not f then error("webui: config.json not found: " .. plugin_dir) end
    local content = f:read("*a"); f:close()
    config = cjson.decode(content)
    for k in pairs(config) do
        if k:sub(1, 3) == "___" then config[k] = nil end
    end
end

-- ============================================================
-- Utility
-- ============================================================

local function ip_to_num(ip)
    local a,b,c,d = ip:match("^(%d+)%.(%d+)%.(%d+)%.(%d+)$")
    if not a then return nil end
    a,b,c,d = tonumber(a),tonumber(b),tonumber(c),tonumber(d)
    if a>255 or b>255 or c>255 or d>255 then return nil end
    return (a*256+b)*65536 + c*256 + d
end

local function match_ip(ip, entry)
    if ip == entry then return true end
    local host = entry:match("^(.-)/%d+$")
    local n = tonumber(entry:match("/(%d+)$"))
    if host and n and n>=0 and n<=32 then
        local ipn, netn = ip_to_num(ip), ip_to_num(host)
        if ipn and netn then
            return math.floor(ipn / 2^(32-n)) == math.floor(netn / 2^(32-n))
        end
    end
    return false
end

local function ip_in_list(ip, list)
    if not list then return false end
    for _, entry in ipairs(list) do
        if entry ~= "" then
            if match_ip(ip, entry) then return true end
        end
    end
    return false
end

local function get_admin_ip()
    local remote = ngx.var.remote_addr or ""
    local trusted = config.admin_trusted_proxies
    if trusted and #trusted > 0 then
        local xff = ngx.req.get_headers()["X-Forwarded-For"]
        if xff then
            local first = xff:match("^([^,]+)")
            if first then first = first:match("^%s*(.-)%s*$") end
            if first and ip_in_list(remote, trusted) then
                return first
            end
        end
        local xri = ngx.req.get_headers()["X-Real-Ip"]
        if xri and ip_in_list(remote, trusted) then
            return xri
        end
    end
    return remote
end

local function admin_check()
    local wl = config.admin_whitelist
    if not wl or #wl == 0 then return true end
    return ip_in_list(get_admin_ip(), wl)
end

local function json_response(obj, status)
    ngx.status = status or 200
    ngx.header["Content-Type"] = "application/json; charset=utf-8"
    ngx.header["Cache-Control"] = "no-store, no-cache, must-revalidate"
    ngx.header["Pragma"] = "no-cache"
    ngx.say(cjson.encode(obj))
    ngx.exit(status or 200)
end

local function html_response(html)
    ngx.status = 200
    ngx.header["Content-Type"] = "text/html; charset=utf-8"
    ngx.header["Cache-Control"] = "no-store, no-cache, must-revalidate"
    ngx.header["Pragma"] = "no-cache"
    ngx.say(html)
    ngx.exit(200)
end

local function get_store()
    local dict_name = (config.shared_dict or {}).dict_name or "rfw"
    return ngx.shared[dict_name]
end

local function get_rfw_stats()
    local core = _G.ma_rfw_core
    if core then
        local store = get_store()
        if store then
            local prefix = "rfw:stats:"
            local stats = {}
            local keys = store:get_keys(512)
            for _, k in ipairs(keys) do
                if k:sub(1, #prefix) == prefix then
                    local name = k:sub(#prefix + 1)
                    if name:sub(1, 7) ~= "denied:" then
                        stats[name] = store:get(k) or 0
                    end
                end
            end
            stats.denied = {}
            for _, k in ipairs(keys) do
                if k:sub(1, #(prefix .. "denied:")) == prefix .. "denied:" then
                    local reason = k:sub(#(prefix .. "denied:") + 1)
                    stats.denied[reason] = (store:get(k) or 0)
                end
            end
            stats.start_ts = store:get(prefix .. "start_ts") or os.time()
            return stats
        end
        if core.stats then return core.stats end
    end
    return {
        requests = 0, signed_ok = 0, cookie_ok = 0, cookie_issued = 0,
        cookie_stale = 0, no_cookie_tracked = 0, cookie_missing = 0,
        cookie_replay = 0, static_ok = 0, blocked_hit = 0, blocks = 0,
        failures = 0, start_ts = os.time(), last_rate = 0, denied = {},
        block_cache_size = 0, seq_cache_size = 0, track_ips = 0,
        backend_fail = 0
    }
end

local function get_block_log()
    local core = _G.ma_rfw_core
    if core and core.scan_block_log then return core.scan_block_log() end
    if core and core.block_log then
        if type(core.block_log) == "function" then return core.block_log() end
        return core.block_log
    end
    return {}
end

local function fmt_uptime(sec)
    sec = sec or 0
    local d = math.floor(sec / 86400)
    local h = math.floor(sec % 86400 / 3600)
    local m = math.floor(sec % 3600 / 60)
    local s = sec % 60
    return string.format("%dd %02d:%02d:%02d", d, h, m, s)
end

-- ============================================================
-- HTML Templates
-- ============================================================

local CSS = [[
<style>
*{margin:0;padding:0;box-sizing:border-box}
:root{
  --brand:]] .. BRAND_COLOR .. [[;
  --brand-light:#f5f3ff;
  --bg:#f8fafc;
  --card:#ffffff;
  --text:#1e293b;
  --text2:#64748b;
  --border:#e2e8f0;
  --success:#10b981;
  --danger:#ef4444;
  --warning:#f59e0b;
  --radius:12px;
  --shadow:0 1px 3px rgba(0,0,0,.08),0 1px 2px rgba(0,0,0,.06)
}
body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;background:var(--bg);color:var(--text);line-height:1.6}
a{color:var(--brand);text-decoration:none}
nav{position:fixed;top:0;left:0;right:0;height:56px;background:#fff;border-bottom:1px solid var(--border);display:flex;align-items:center;padding:0 24px;z-index:100;box-shadow:0 1px 3px rgba(0,0,0,.05)}
nav .brand{font-size:18px;font-weight:700;color:var(--brand);margin-right:32px;white-space:nowrap}
nav .brand span{font-size:12px;font-weight:400;color:var(--text2);margin-left:8px}
nav .nav-links{display:flex;gap:4px}
nav .nav-links a{padding:8px 16px;border-radius:8px;color:var(--text2);font-size:14px;font-weight:500;transition:all .15s}
nav .nav-links a:hover{background:var(--brand-light);color:var(--brand)}
nav .nav-links a.active{background:var(--brand);color:#fff}
main{max-width:1200px;margin:0 auto;padding:72px 24px 40px}
.metrics{display:grid;grid-template-columns:repeat(4,1fr);gap:16px;margin-bottom:24px}
.metric-card{background:var(--card);border-radius:var(--radius);padding:20px 24px;box-shadow:var(--shadow);border:1px solid var(--border)}
.metric-card .label{font-size:13px;color:var(--text2);margin-bottom:4px}
.metric-card .value{font-size:28px;font-weight:700}
.metric-card.purple .value{color:var(--brand)}
.metric-card.green .value{color:var(--success)}
.metric-card.red .value{color:var(--danger)}
.metric-card.yellow .value{color:var(--warning)}
.charts{display:grid;grid-template-columns:1fr 1fr;gap:16px;margin-bottom:24px}
.chart-card{background:var(--card);border-radius:var(--radius);padding:20px;box-shadow:var(--shadow);border:1px solid var(--border)}
.chart-card h3{font-size:15px;font-weight:600;margin-bottom:12px;color:var(--text)}
.chart-box{width:100%;height:300px}
.section{background:var(--card);border-radius:var(--radius);padding:24px;box-shadow:var(--shadow);border:1px solid var(--border);margin-bottom:24px}
.section h3{font-size:15px;font-weight:600;margin-bottom:16px;color:var(--text)}
.detail-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(160px,1fr));gap:12px}
.detail-item{display:flex;justify-content:space-between;padding:10px 14px;background:var(--bg);border-radius:8px;font-size:13px}
.detail-item .k{color:var(--text2)}
.detail-item .v{font-weight:600}
table{width:100%;border-collapse:collapse;font-size:13px}
th{text-align:left;padding:10px 14px;background:var(--bg);font-weight:600;color:var(--text2);border-bottom:1px solid var(--border)}
td{padding:10px 14px;border-bottom:1px solid var(--border)}
tr:last-child td{border-bottom:none}
.tag{display:inline-block;padding:2px 8px;border-radius:4px;font-size:12px;font-weight:500}
.tag-green{background:#d1fae5;color:#065f46}
.tag-red{background:#fee2e2;color:#991b1b}
.tag-yellow{background:#fef3c7;color:#92400e}
.form-group{margin-bottom:20px}
.form-group label{display:block;font-size:13px;font-weight:600;color:var(--text2);margin-bottom:6px}
.form-row{display:grid;grid-template-columns:1fr 1fr;gap:16px}
input[type=text],input[type=number],select{width:100%;padding:10px 14px;border:1px solid var(--border);border-radius:8px;font-size:14px;background:var(--card);color:var(--text);transition:border-color .15s}
input:focus,select:focus{outline:none;border-color:var(--brand);box-shadow:0 0 0 3px rgba(139,92,246,.1)}
.switch-row{display:flex;flex-wrap:wrap;gap:8px 24px}
.switch-item{display:flex;align-items:center;gap:8px;font-size:14px;min-width:180px}
.switch-item input[type=checkbox]{width:18px;height:18px;accent-color:var(--brand)}
.btn{padding:10px 24px;border:none;border-radius:8px;font-size:14px;font-weight:600;cursor:pointer;transition:all .15s}
.btn-primary{background:var(--brand);color:#fff}
.btn-primary:hover{opacity:.9}
.btn-secondary{background:var(--bg);color:var(--text);border:1px solid var(--border)}
.btn-secondary:hover{background:var(--border)}
.btn-group{display:flex;gap:12px;margin-top:24px}
.tag-list{display:flex;flex-wrap:wrap;gap:6px;margin-bottom:8px}
.tag-list .tag{cursor:pointer;padding:4px 10px;font-size:12px}
.tag-list .tag:hover{opacity:.7}
.toast{position:fixed;bottom:24px;right:24px;padding:14px 20px;border-radius:8px;color:#fff;font-size:14px;font-weight:500;z-index:200;transform:translateY(100px);opacity:0;transition:all .3s}
.toast.show{transform:translateY(0);opacity:1}
.toast-ok{background:var(--success)}
.toast-err{background:var(--danger)}
@media(max-width:768px){
  .metrics{grid-template-columns:repeat(2,1fr)}
  .charts{grid-template-columns:1fr}
  .form-row{grid-template-columns:1fr}
  nav .brand span{display:none}
}
@media(max-width:480px){
  .metrics{grid-template-columns:1fr}
}
</style>
]]

local NAV = [[
<nav>
  <div class="brand">]] .. PROJECT .. [[<span>v]] .. VERSION .. [[</span></div>
  <div class="nav-links">
    <a href="/cgi-rfw/status" id="nav-status">状态</a>
    <a href="/cgi-rfw/config" id="nav-config">配置</a>
    <a href="/cgi-rfw/logs" id="nav-logs">日志</a>
  </div>
</nav>
]]

local SHARED_JS = [[
<script>
function toast(msg,ok){
  var d=document.createElement('div');
  d.className='toast '+(ok?'toast-ok':'toast-err');
  d.textContent=msg;
  document.body.appendChild(d);
  requestAnimationFrame(function(){d.classList.add('show')});
  setTimeout(function(){d.classList.remove('show');setTimeout(function(){d.remove()},300)},3000);
}
</script>
]]

-- ============================================================
-- Status Page
-- ============================================================

local STATUS_HTML = [[<!DOCTYPE html>
<html lang="zh-CN"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>]] .. PROJECT .. [[ - 状态</title>
<script src="https://cdn.jsdelivr.net/npm/echarts@5/dist/echarts.min.js"></script>
]] .. CSS .. [[
</head><body>
]] .. NAV .. [[
<main>
  <div class="metrics">
    <div class="metric-card purple"><div class="label">请求总数</div><div class="value" id="m-total">-</div></div>
    <div class="metric-card green"><div class="label">签名校验通过</div><div class="value" id="m-signed">-</div></div>
    <div class="metric-card yellow"><div class="label">cookie 兜底放行</div><div class="value" id="m-cookie">-</div></div>
    <div class="metric-card red"><div class="label">封禁命中</div><div class="value" id="m-blocked">-</div></div>
  </div>
  <div class="charts">
    <div class="chart-card"><h3>请求处理分布</h3><div class="chart-box" id="chart-pie"></div></div>
    <div class="chart-card"><h3>拒绝原因分布</h3><div class="chart-box" id="chart-deny"></div></div>
  </div>
  <div class="section">
    <h3>拒绝原因明细</h3>
    <div class="detail-grid" id="deny-details"></div>
  </div>
  <div class="section">
    <h3>封禁 IP</h3>
    <table>
      <thead><tr><th>状态</th><th>IP</th><th>封禁时间</th><th>解封时间</th><th>剩余</th><th>原因</th></tr></thead>
      <tbody id="block-table"><tr><td colspan="6" style="text-align:center;color:var(--text2)">无封禁记录</td></tr></tbody>
    </table>
  </div>
  <div class="section">
    <h3>系统信息</h3>
    <div class="detail-grid" id="sys-info"></div>
  </div>
  <div class="section" id="history-section" style="margin-top:24px;border-top:2px solid var(--border);padding-top:24px">
    <h3 style="margin-bottom:12px">历史统计 <span style="font-size:12px;color:var(--text2);font-weight:normal">来自日志文件</span></h3>
    <div style="display:flex;gap:8px;margin-bottom:16px;flex-wrap:wrap">
      <button class="btn btn-secondary hist-btn" data-days="1">今天</button>
      <button class="btn btn-primary hist-btn" data-days="7">近 7 天</button>
      <button class="btn btn-secondary hist-btn" data-days="30">近 30 天</button>
      <span id="hist-status" style="font-size:12px;color:var(--text2);line-height:36px;margin-left:8px"></span>
    </div>
    <div style="display:flex;gap:16px;flex-wrap:wrap;margin-bottom:16px">
      <div id="hist-trend" style="flex:2;min-width:300px;height:220px;border:1px solid var(--border);border-radius:8px;padding:8px"></div>
      <div id="hist-pie" style="flex:1;min-width:200px;height:220px;border:1px solid var(--border);border-radius:8px;padding:8px"></div>
    </div>
    <div id="hist-top-ips" style="font-size:13px"></div>
  </div>
</main>
]] .. SHARED_JS .. [[
<script>
var pieChart,denyChart;
function initCharts(){
  pieChart=echarts.init(document.getElementById('chart-pie'));
  denyChart=echarts.init(document.getElementById('chart-deny'));
  window.addEventListener('resize',function(){pieChart.resize();denyChart.resize()});
}
function fmt(n){return n==null?'-':n.toLocaleString()}
function fmtTime(ts){if(!ts)return'-';var d=new Date(ts*1000);return d.toLocaleString()}
function renderPie(s){
  var d=[
    {value:s.signed_ok||0,name:'签名校验通过'},
    {value:s.cookie_ok||0,name:'cookie 兜底放行'},
    {value:s.static_ok||0,name:'静态资源放行'},
    {value:s.blocked_hit||0,name:'封禁命中'},
    {value:s.cookie_stale||0,name:'cookie ts 过期'},
    {value:s.cookie_replay||0,name:'cookie 重放拒绝'},
    {value:s.cookie_missing||0,name:'无 cookie 封禁'}
  ].filter(function(x){return x.value>0});
  if(!d.length){pieChart.setOption({title:{text:'暂无数据',left:'center',top:'center',textStyle:{color:'#94a3b8',fontSize:14}}});return}
  pieChart.setOption({
    tooltip:{trigger:'item',formatter:'{b}: {c} ({d}%)'},
    color:['#8b5cf6','#3b82f6','#06b6d4','#ef4444','#f59e0b','#ec4899','#f97316'],
    series:[{type:'pie',radius:['40%','70%'],avoidLabelOverlap:true,
      itemStyle:{borderRadius:6,borderColor:'#fff',borderWidth:2},
      label:{show:true,formatter:'{b}\n{d}%',fontSize:12},
      data:d}]
  });
}
function renderDeny(denied){
  var items=[];for(var k in denied)items.push({value:denied[k],name:k});
  items.sort(function(a,b){return b.value-a.value});
  if(!items.length){denyChart.setOption({title:{text:'暂无拒绝记录',left:'center',top:'center',textStyle:{color:'#94a3b8',fontSize:14}}});return}
  denyChart.setOption({
    tooltip:{trigger:'item',formatter:'{b}: {c} ({d}%)'},
    color:['#ef4444','#f97316','#f59e0b','#ec4899','#8b5cf6'],
    series:[{type:'pie',radius:['40%','70%'],
      itemStyle:{borderRadius:6,borderColor:'#fff',borderWidth:2},
      label:{show:true,formatter:'{b}\n{d}%',fontSize:12},
      data:items}]
  });
}
function renderDenyDetails(denied){
  var items=[];for(var k in denied){var v=denied[k];items.push([k,v])}
  items.sort(function(a,b){return b[1]-a[1]});
  var h='';items.forEach(function(i){
    h+='<div class="detail-item"><span class="k">'+i[0]+'</span><span class="v">'+fmt(i[1])+'</span></div>';
  });
  if(!h)h='<div style="color:var(--text2);font-size:13px">暂无拒绝记录</div>';
  document.getElementById('deny-details').innerHTML=h;
}
function renderBlocks(bl){
  var now=Math.floor(Date.now()/1000);var rows='';var count=0;
  for(var ip in bl){var e=bl[ip];if(now<e.unblock)count++}
  if(count===0){document.getElementById('block-table').innerHTML='<tr><td colspan="6" style="text-align:center;color:var(--text2)">无封禁记录</td></tr>';return}
  for(var ip2 in bl){
    var e2=bl[ip2];var active=now<e2.unblock;var remain=Math.max(0,e2.unblock-now);
    rows+='<tr><td><span class="tag '+(active?'tag-red':'tag-green')+'">'+(active?'封禁中':'已解封')+'</span></td>';
    rows+='<td>'+ip2+'</td><td>'+fmtTime(e2.ban)+'</td><td>'+fmtTime(e2.unblock)+'</td>';
    rows+='<td>'+(active?fmtUptime2(remain):'-')+'</td><td>'+(e2.reason||'')+'</td></tr>';
  }
  document.getElementById('block-table').innerHTML=rows;
}
function fmtUptime2(s){var d=Math.floor(s/86400),h=Math.floor(s%86400/3600),m=Math.floor(s%3600/60),ss=s%60;return d+'d '+pad2(h)+':'+pad2(m)+':'+pad2(ss)}
function pad2(n){return n<10?'0'+n:''+n}
function renderSys(s){
  var now=Math.floor(Date.now()/1000);var up=now-(s.start_ts||now);
  var items=[
    ['运行时长',fmtUptime2(up)],['最近速率',fmt(s.last_rate)+' 次/s'],
    ['cookie 下发',fmt(s.cookie_issued)],['无 cookie 计数',fmt(s.no_cookie_tracked)],
    ['封禁次数',fmt(s.blocks)],['失败累计',fmt(s.failures)],
    ['签名比例追踪 IP',fmt(s.track_ips)],['封禁缓存条数',fmt(s.block_cache_size)]
  ];
  var h='';items.forEach(function(i){
    h+='<div class="detail-item"><span class="k">'+i[0]+'</span><span class="v">'+i[1]+'</span></div>';
  });
  document.getElementById('sys-info').innerHTML=h;
}
function refresh(){
  fetch('/cgi-rfw/api/stats?t='+Date.now()).then(function(r){return r.json()}).then(function(d){
    var s=d.stats||{};var bl=d.block_log||{};
    document.getElementById('m-total').textContent=fmt(s.requests);
    document.getElementById('m-signed').textContent=fmt(s.signed_ok);
    document.getElementById('m-cookie').textContent=fmt(s.cookie_ok);
    document.getElementById('m-blocked').textContent=fmt(s.blocked_hit);
    renderPie(s);renderDeny(s.denied||{});renderDenyDetails(s.denied||{});renderBlocks(bl);renderSys(s);
  }).catch(function(){});
}
document.getElementById('nav-status').classList.add('active');
// --- History ---
var histTrendChart=null,histPieChart=null;
function initHistCharts(){
  if(typeof echarts==='undefined')return;
  histTrendChart=echarts.init(document.getElementById('hist-trend'));
  histPieChart=echarts.init(document.getElementById('hist-pie'));
  window.addEventListener('resize',function(){histTrendChart&&histTrendChart.resize();histPieChart&&histPieChart.resize()});
}
function loadHistory(days){
  document.querySelectorAll('.hist-btn').forEach(function(b){
    b.className=b.getAttribute('data-days')==days?'btn btn-primary hist-btn':'btn btn-secondary hist-btn';
  });
  fetch('/cgi-rfw/api/history?days='+days+'&t='+Date.now()).then(function(r){return r.json()}).then(function(d){
    document.getElementById('hist-status').textContent='截至 '+d.totals.denied+' 次拒绝';
    if(!histTrendChart||!histPieChart){initHistCharts()}
    if(histTrendChart){
      var dates=[],denied=[],reqVol=[];
      (Array.isArray(d.days)?d.days:[]).forEach(function(dd){
        dates.push(dd.date);
        denied.push(dd.denied_total);
        var snaps=dd.snapshots||[];
        var totalReq=0;
        for(var k=1;k<snaps.length;k++){
          if(snaps[k].requests&&snaps[k-1].requests){
            totalReq+=snaps[k].requests-snaps[k-1].requests;
          }
        }
        reqVol.push(totalReq);
      });
      histTrendChart.setOption({tooltip:{trigger:'axis'},legend:{data:['拒绝量','请求量'],textStyle:{fontSize:11}},grid:{left:50,right:16,top:30,bottom:24},xAxis:{type:'category',data:dates,axisLabel:{fontSize:10}},yAxis:[{type:'value',name:'拒绝',axisLabel:{fontSize:10}},{type:'value',name:'请求',axisLabel:{fontSize:10}}],series:[{name:'拒绝量',type:'bar',data:denied,itemStyle:{color:'#e74c3c'}},{name:'请求量',type:'line',yAxisIndex:1,data:reqVol,smooth:true,itemStyle:{color:'#3498db'}}]});
    }
    if(histPieChart){
      var pieData=[];for(var r in d.totals.denied_by_reason){pieData.push({name:r,value:d.totals.denied_by_reason[r]})}
      histPieChart.setOption({tooltip:{trigger:'item',formatter:'{b}: {c} ({d}%)'},series:[{type:'pie',radius:['35%','65%'],data:pieData,label:{fontSize:11}}]});
    }
    var ipHtml='<table style="width:100%;border-collapse:collapse;font-size:13px"><tr style="border-bottom:1px solid var(--border)"><th style="text-align:left;padding:6px">IP</th><th style="text-align:right;padding:6px">次数</th></tr>';
    (Array.isArray(d.totals.top_ips)?d.totals.top_ips:[]).forEach(function(r){ipHtml+='<tr style="border-bottom:1px solid var(--border)"><td style="padding:6px">'+r[0]+'</td><td style="text-align:right;padding:6px">'+r[1]+'</td></tr>'});
    ipHtml+='</table>';
    document.getElementById('hist-top-ips').innerHTML=ipHtml;
  }).catch(function(e){document.getElementById('hist-status').textContent='加载失败: '+e.message});
}
document.querySelectorAll('.hist-btn').forEach(function(b){b.addEventListener('click',function(){loadHistory(this.getAttribute('data-days'))})});
initHistCharts();loadHistory(7);
initCharts();refresh();setInterval(refresh,10000);
</script>
</body></html>]]

-- ============================================================
-- Config Page
-- ============================================================

local CONFIG_HTML = [[<!DOCTYPE html>
<html lang="zh-CN"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>]] .. PROJECT .. [[ - 配置</title>
]] .. CSS .. [[
</head><body>
]] .. NAV .. [[
<main>
  <div class="section">
    <h3>签名校验</h3>
    <div class="form-row">
      <div class="form-group">
        <label>签名开关</label>
        <select id="cfg-sign-enabled"><option value="true">启用</option><option value="false">禁用</option></select>
      </div>
      <div class="form-group">
        <label>签名时窗 (秒)</label>
        <input type="number" id="cfg-sign-window" value="60">
      </div>
    </div>
    <div class="form-row">
      <div class="form-group">
        <label>签名比例-请求数阈值</label>
        <input type="number" id="cfg-sign-ratio-req" value="10">
      </div>
      <div class="form-group">
        <label>签名比例-最低比例</label>
        <input type="text" id="cfg-sign-ratio-min" value="0.5">
      </div>
    </div>
  </div>

  <div class="section">
    <h3>Cookie 配置</h3>
    <div class="form-row">
      <div class="form-group">
        <label>Cookie 名称</label>
        <input type="text" id="cfg-cookie-name" value="_RFW">
      </div>
      <div class="form-group">
        <label>Cookie TTL (秒)</label>
        <input type="number" id="cfg-cookie-ttl" value="86400">
      </div>
    </div>
    <div class="form-row">
      <div class="form-group">
        <label>Cookie ts 上限 (秒)</label>
        <input type="number" id="cfg-cookie-ts-max" value="60">
      </div>
      <div class="form-group">
        <label>Cookie Bootstrap</label>
        <select id="cfg-cookie-bootstrap"><option value="true">启用</option><option value="false">禁用</option></select>
      </div>
    </div>
    <div class="form-row">
      <div class="form-group">
        <label>同值并行宽限 (秒)</label>
        <input type="number" id="cfg-cookie-replay-window" value="2">
      </div>
      <div class="form-group">
        <label>同值可消费次数</label>
        <input type="number" id="cfg-cookie-replay-max" value="5">
      </div>
    </div>
    <div class="form-row">
      <div class="form-group">
        <label>无 cookie 日配额 (0=关闭)</label>
        <input type="number" id="cfg-cookie-missing-max" value="50">
      </div>
      <div class="form-group">
        <label>无 cookie 计数窗口 (秒)</label>
        <input type="number" id="cfg-cookie-missing-ttl" value="86400">
      </div>
    </div>
  </div>

  <div class="section">
    <h3>会话序号</h3>
    <div class="form-row">
      <div class="form-group">
        <label>序号容差 (seq_slack)</label>
        <input type="number" id="cfg-seq-slack" value="10">
      </div>
      <div class="form-group">
        <label>序号保留期 (秒)</label>
        <input type="number" id="cfg-seq-ttl" value="86400">
      </div>
    </div>
    <div class="form-row">
      <div class="form-group">
        <label>序号内存缓存 TTL (秒)</label>
        <input type="number" id="cfg-seq-cache-ttl" value="3">
      </div>
      <div class="form-group"></div>
    </div>
  </div>

  <div class="section">
    <h3>重放检测</h3>
    <div class="form-row">
      <div class="form-group">
        <label>重放检测开关</label>
        <select id="cfg-replay-enabled"><option value="true">启用</option><option value="false">禁用</option></select>
      </div>
      <div class="form-group">
        <label>重放阈值</label>
        <input type="number" id="cfg-replay-threshold" value="5">
      </div>
    </div>
    <div class="form-row">
      <div class="form-group">
        <label>二次校验放行窗口 (秒)</label>
        <input type="number" id="cfg-replay-relink-sec" value="2">
      </div>
      <div class="form-group"></div>
    </div>
  </div>

  <div class="section">
    <h3>封禁参数</h3>
    <div class="form-row">
      <div class="form-group">
        <label>失败次数上限</label>
        <input type="number" id="cfg-fail-max" value="5">
      </div>
      <div class="form-group">
        <label>失败窗口 (秒)</label>
        <input type="number" id="cfg-fail-window" value="60">
      </div>
    </div>
    <div class="form-row">
      <div class="form-group">
        <label>封禁时长 (秒)</label>
        <input type="number" id="cfg-block-time" value="600">
      </div>
      <div class="form-group">
        <label>封禁缓存 TTL (秒)</label>
        <input type="number" id="cfg-block-cache-ttl" value="60">
      </div>
    </div>
  </div>

  <div class="section">
    <h3>其他设置</h3>
    <div class="form-row">
      <div class="form-group">
        <label>调试模式</label>
        <select id="cfg-debug"><option value="false">关闭</option><option value="true">开启</option></select>
      </div>
      <div class="form-group">
        <label>清扫间隔 (秒)</label>
        <input type="number" id="cfg-sweep-interval" value="60">
      </div>
    </div>
    <div class="form-row">
      <div class="form-group">
        <label>SNAP 日志间隔 (秒, 0=每次清扫)</label>
        <input type="number" id="cfg-snap-log-interval" value="1800">
      </div>
      <div class="form-group"></div>
    </div>
  </div>

  <div class="section">
    <h3>管理员白名单</h3>
    <p style="font-size:13px;color:var(--text2);margin-bottom:12px">允许访问此管理面板的 IP 地址（支持 CIDR），留空则允许所有</p>
    <div class="tag-list" id="whitelist-tags"></div>
    <div style="display:flex;gap:8px">
      <input type="text" id="wl-input" placeholder="输入 IP 或 CIDR，回车添加" style="flex:1">
      <button class="btn btn-secondary" onclick="addWl()">添加</button>
    </div>
  </div>

  <div class="section">
    <h3>受信任反向代理</h3>
    <p style="font-size:13px;color:var(--text2);margin-bottom:12px">面板位于反向代理后时，必须把反代 IP 加入此列表，否则管理员会被 404 拦截。仅当 direct IP 在此列表时才解析 X-Forwarded-For / X-Real-Ip 头部。</p>
    <div class="tag-list" id="tp-tags"></div>
    <div style="display:flex;gap:8px">
      <input type="text" id="tp-input" placeholder="输入反代 IP 或 CIDR，回车添加" style="flex:1">
      <button class="btn btn-secondary" onclick="addTp()">添加</button>
    </div>
  </div>

  <div class="btn-group">
    <button class="btn btn-primary" onclick="saveConfig()">保存配置</button>
  </div>
</main>
]] .. SHARED_JS .. [[
<script>
var wlData=[];
function renderWl(){
  var c=document.getElementById('whitelist-tags');c.innerHTML='';
  wlData.forEach(function(ip,i){
    var s=document.createElement('span');s.className='tag';s.textContent=ip;
    s.style.background='var(--brand-light)';s.style.color='var(--brand)';
    s.onclick=function(){wlData.splice(i,1);renderWl()};
    c.appendChild(s);
  });
}
function addWl(){
  var inp=document.getElementById('wl-input');var v=inp.value.trim();
  if(v&&wlData.indexOf(v)===-1){wlData.push(v);renderWl()}
  inp.value='';
}
document.getElementById('wl-input').addEventListener('keydown',function(e){if(e.key==='Enter'){e.preventDefault();addWl()}});
var tpData=[];
function renderTp(){
  var c=document.getElementById('tp-tags');c.innerHTML='';
  tpData.forEach(function(ip,i){
    var s=document.createElement('span');s.className='tag';s.textContent=ip;
    s.style.background='var(--brand-light)';s.style.color='var(--brand)';
    s.onclick=function(){tpData.splice(i,1);renderTp()};
    c.appendChild(s);
  });
}
function addTp(){
  var inp=document.getElementById('tp-input');var v=inp.value.trim();
  if(v&&tpData.indexOf(v)===-1){tpData.push(v);renderTp()}
  inp.value='';
}
document.getElementById('tp-input').addEventListener('keydown',function(e){if(e.key==='Enter'){e.preventDefault();addTp()}});
function setVal(id,val){var el=document.getElementById(id);if(el)el.value=val==null?'':String(val)}
function getVal(id){var el=document.getElementById(id);return el?el.value:null}
function setBool(id,val){var el=document.getElementById(id);if(el)el.value=val?'true':'false'}
function loadConfig(){
  fetch('/cgi-rfw/api/config').then(function(r){return r.json()}).then(function(c){
    setBool('cfg-sign-enabled',c.sign_enabled);setVal('cfg-sign-window',c.sign_window);
    setVal('cfg-sign-ratio-req',c.sign_ratio_req);setVal('cfg-sign-ratio-min',c.sign_ratio_min);
    setVal('cfg-cookie-name',c.cookie_name);setVal('cfg-cookie-ttl',c.cookie_ttl);
    setVal('cfg-cookie-ts-max',c.cookie_ts_max);setBool('cfg-cookie-bootstrap',c.cookie_bootstrap);
    setVal('cfg-cookie-replay-window',c.cookie_replay_window);setVal('cfg-cookie-replay-max',c.cookie_replay_max);
    setVal('cfg-cookie-missing-max',c.cookie_missing_max);setVal('cfg-cookie-missing-ttl',c.cookie_missing_ttl);
    setVal('cfg-seq-slack',c.seq_slack);setVal('cfg-seq-ttl',c.seq_ttl);setVal('cfg-seq-cache-ttl',c.seq_cache_ttl);
    setBool('cfg-replay-enabled',c.replay_enabled);setVal('cfg-replay-threshold',c.replay_threshold);
    setVal('cfg-replay-relink-sec',c.replay_relink_sec);
    setVal('cfg-fail-max',c.fail_max);setVal('cfg-fail-window',c.fail_window);
    setVal('cfg-block-time',c.block_time);setVal('cfg-block-cache-ttl',c.block_cache_ttl);
    setBool('cfg-debug',c.debug);setVal('cfg-sweep-interval',c.sweep_interval);
    setVal('cfg-snap-log-interval',c.snap_log_interval==null?1800:c.snap_log_interval);
    wlData=Array.isArray(c.admin_whitelist)?c.admin_whitelist:[];renderWl();
    tpData=Array.isArray(c.admin_trusted_proxies)?c.admin_trusted_proxies:[];renderTp();
  }).catch(function(e){toast('加载配置失败: '+e.message,false)});
}
function saveConfig(){
  var cfg={};
  cfg.sign_enabled=getVal('cfg-sign-enabled')==='true';
  cfg.sign_window=parseInt(getVal('cfg-sign-window'))||60;
  cfg.sign_ratio_req=parseInt(getVal('cfg-sign-ratio-req'))||10;
  cfg.sign_ratio_min=parseFloat(getVal('cfg-sign-ratio-min'))||0.5;
  cfg.cookie_name=getVal('cfg-cookie-name')||'_RFW';
  cfg.cookie_ttl=parseInt(getVal('cfg-cookie-ttl'))||86400;
  cfg.cookie_ts_max=parseInt(getVal('cfg-cookie-ts-max'))||60;
  cfg.cookie_bootstrap=getVal('cfg-cookie-bootstrap')==='true';
  cfg.cookie_replay_window=parseInt(getVal('cfg-cookie-replay-window'))||2;
  cfg.cookie_replay_max=parseInt(getVal('cfg-cookie-replay-max'))||5;
  cfg.cookie_missing_max=parseInt(getVal('cfg-cookie-missing-max'))||50;
  cfg.cookie_missing_ttl=parseInt(getVal('cfg-cookie-missing-ttl'))||86400;
  cfg.seq_slack=parseInt(getVal('cfg-seq-slack'))||10;
  cfg.seq_ttl=parseInt(getVal('cfg-seq-ttl'))||86400;
  cfg.seq_cache_ttl=parseInt(getVal('cfg-seq-cache-ttl'))||3;
  cfg.replay_enabled=getVal('cfg-replay-enabled')==='true';
  cfg.replay_threshold=parseInt(getVal('cfg-replay-threshold'))||5;
  cfg.replay_relink_sec=parseInt(getVal('cfg-replay-relink-sec'))||2;
  cfg.fail_max=parseInt(getVal('cfg-fail-max'))||5;
  cfg.fail_window=parseInt(getVal('cfg-fail-window'))||60;
  cfg.block_time=parseInt(getVal('cfg-block-time'))||600;
  cfg.block_cache_ttl=parseInt(getVal('cfg-block-cache-ttl'))||60;
  cfg.debug=getVal('cfg-debug')==='true';
  cfg.sweep_interval=parseInt(getVal('cfg-sweep-interval'))||60;
  var slgi=parseInt(getVal('cfg-snap-log-interval'));
  cfg.snap_log_interval=(isNaN(slgi)||slgi<0)?1800:slgi;
  cfg.admin_whitelist=wlData;
  cfg.admin_trusted_proxies=tpData;
  fetch('/cgi-rfw/api/config',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(cfg)})
    .then(function(r){return r.json()}).then(function(d){
      if(d.success)toast('配置已保存，重启 Nginx 后生效',true);
      else toast('保存失败: '+(d.message||''),false);
    }).catch(function(e){toast('保存失败: '+e.message,false)});
}
document.getElementById('nav-config').classList.add('active');
loadConfig();
</script>
</body></html>]]

local LOGS_HTML = [[<!DOCTYPE html>
<html lang="zh-CN"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>]] .. PROJECT .. [[ - 日志</title>
]] .. CSS .. [[
</head><body>
]] .. NAV .. [[
<main>
  <div class="section">
    <div style="display:flex;gap:12px;align-items:center;flex-wrap:wrap;margin-bottom:16px">
      <select id="log-days" style="padding:8px;border:1px solid var(--border);border-radius:6px">
        <option value="7">近 7 天</option><option value="14">近 14 天</option><option value="30" selected>近 30 天</option><option value="90">近 90 天</option>
      </select>
      <button class="btn btn-secondary" onclick="loadFiles()">刷新</button>
      <span style="font-size:13px;color:var(--text2)" id="log-status"></span>
    </div>
    <div style="display:flex;gap:16px;flex-wrap:wrap">
      <div style="min-width:220px;max-width:300px;flex:1">
        <div id="file-list" style="border:1px solid var(--border);border-radius:8px;max-height:60vh;overflow-y:auto"></div>
      </div>
      <div style="flex:2;min-width:300px">
        <div style="display:flex;gap:8px;align-items:center;margin-bottom:8px;flex-wrap:wrap">
          <input type="text" id="log-filter" placeholder="过滤关键词..." style="flex:1;min-width:120px;padding:8px;border:1px solid var(--border);border-radius:6px">
          <select id="log-lines" style="padding:8px;border:1px solid var(--border);border-radius:6px">
            <option value="100">100 行</option><option value="200" selected>200 行</option><option value="500">500 行</option><option value="1000">1000 行</option>
          </select>
          <label style="font-size:13px;display:flex;align-items:center;gap:4px"><input type="checkbox" id="log-auto"> 自动刷新</label>
        </div>
        <div id="log-content" style="background:var(--bg);border:1px solid var(--border);border-radius:8px;padding:12px;font-size:12px;max-height:55vh;overflow:auto">选择左侧日志文件查看内容</div>
      </div>
    </div>
  </div>
  <p style="font-size:12px;color:var(--text2);margin-top:12px">日志为逐行 JSON（与 WAF 同构，表格自动解析）；SNAP 快照按 snap_log_interval 间隔落盘。</p>
</main>
]] .. SHARED_JS .. [==[
<script>
document.getElementById('nav-logs').classList.add('active');
var currentFile=null,autoTimer=null;
function loadFiles(){
  var days=document.getElementById('log-days').value;
  fetch('/cgi-rfw/api/logs?days='+days+'&t='+Date.now()).then(function(r){return r.json()}).then(function(d){
    var el=document.getElementById('file-list');el.innerHTML='';
    if(!Array.isArray(d.files)||d.files.length===0){el.innerHTML='<div style="padding:16px;color:var(--text2);font-size:13px">无日志文件</div>';return}
    d.files.forEach(function(f){
      var row=document.createElement('div');
      row.style.cssText='padding:10px 14px;cursor:pointer;border-bottom:1px solid var(--border);display:flex;justify-content:space-between;align-items:center;font-size:13px;transition:background .15s';
      row.onmouseover=function(){row.style.background='var(--brand-light)'};
      row.onmouseout=function(){row.style.background=''};
      var name=document.createElement('span');name.textContent=f.name;
      var size=document.createElement('span');size.style.cssText='color:var(--text2);font-size:12px';
      size.textContent=f.size>1048576?(f.size/1048576).toFixed(1)+' MB':(f.size/1024).toFixed(1)+' KB';
      row.appendChild(name);row.appendChild(size);
      row.onclick=function(){currentFile=f.name;document.querySelectorAll('#file-list>div').forEach(function(r){r.style.background=''});row.style.background='var(--brand-light)';loadContent()};
      el.appendChild(row);
    });
  }).catch(function(e){document.getElementById('log-status').textContent='加载失败: '+e.message});
}
function escHtml(s){return String(s==null?'':s).replace(/[&<>"']/g,function(c){return {'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]})}
var LOG_COLS=[['local_time','时间'],['client_ip','客户端 IP'],['server_name','主机'],['attack_method','事件'],['req_url','URL'],['req_data','数据'],['rule_tag','规则/方法'],['user_agent','UA']];
function renderLogTable(el,lines){
  if(!Array.isArray(lines)||lines.length===0){el.innerHTML='<div style="color:var(--text2);font-size:13px;padding:4px">无日志内容</div>';return}
  var h='<table style="border-collapse:collapse;font-size:12px;width:100%;white-space:nowrap">';
  h+='<thead><tr>'+LOG_COLS.map(function(c){return '<th style="text-align:left;padding:6px 8px;background:var(--bg);border:1px solid var(--border);color:var(--text2);position:sticky;top:0;z-index:1">'+escHtml(c[1])+'</th>'}).join('')+'</tr></thead><tbody>';
  lines.forEach(function(line){
    var o;try{o=JSON.parse(line)}catch(e){o=null}
    if(o&&typeof o==='object'&&!Array.isArray(o)){
      h+='<tr>'+LOG_COLS.map(function(c){
        var v=o[c[0]];
        var full=(v==null)?'-':String(v);
        var s=full;if(s.length>160)s=s.slice(0,160)+'…';
        return '<td style="padding:6px 8px;border:1px solid var(--border);max-width:360px;overflow:hidden;text-overflow:ellipsis" title="'+escHtml(full)+'">'+escHtml(s)+'</td>';
      }).join('')+'</tr>';
    }else{
      var raw=String(line);if(raw.length>320)raw=raw.slice(0,320)+'…';
      h+='<tr><td colspan="8" style="padding:6px 8px;border:1px solid var(--border);font-family:Consolas,monospace" title="'+escHtml(line)+'">'+escHtml(raw)+'</td></tr>';
    }
  });
  h+='</tbody></table>';
  el.innerHTML=h;
  el.scrollTop=el.scrollHeight;
}
function loadContent(){
  if(!currentFile)return;
  var lines=document.getElementById('log-lines').value;
  var filter=document.getElementById('log-filter').value;
  var url='/cgi-rfw/api/log?file='+encodeURIComponent(currentFile)+'&lines='+lines+'&t='+Date.now();
  if(filter)url+='&filter='+encodeURIComponent(filter);
  fetch(url).then(function(r){return r.json()}).then(function(d){
    var el=document.getElementById('log-content');
    renderLogTable(el,d.lines);
    document.getElementById('log-status').textContent=d.file+' ('+d.count+' 行'+(d.truncated?' 已截断':'')+')';
  }).catch(function(e){document.getElementById('log-content').innerHTML='<div style="color:var(--danger);font-size:13px">加载失败: '+escHtml(e.message)+'</div>'});
}
document.getElementById('log-filter').addEventListener('keydown',function(e){if(e.key==='Enter'){e.preventDefault();loadContent()}});
document.getElementById('log-auto').addEventListener('change',function(){
  if(this.checked){autoTimer=setInterval(loadContent,5000)}else{clearInterval(autoTimer);autoTimer=null}
});
loadFiles();
</script>
</body></html>]==]

-- ============================================================
-- API Handlers
-- ============================================================

local function handle_api_stats()
    local stats = get_rfw_stats()
    local block_log = get_block_log()
    local bl_clean = {}
    local now = ngx.time()
    for ip, entry in pairs(block_log) do
        if now < entry.unblock then
            bl_clean[ip] = {
                unblock = entry.unblock,
                ban = entry.ban,
                reason = entry.reason or ""
            }
        end
    end
    return json_response({stats = stats, block_log = bl_clean})
end

local function handle_api_config_get()
    return json_response(config)
end

local function handle_api_config_save()
    ngx.req.read_body()
    local body = ngx.req.get_body_data()
    if not body then return json_response({success = false, message = "请求体为空"}, 400) end

    local ok, data = pcall(cjson.decode, body)
    if not ok or type(data) ~= "table" then
        return json_response({success = false, message = "JSON 解析失败"}, 400)
    end

    -- 合并: 用前端数据覆盖当前配置, 保留 secret/shared_dict 等前端不发送的字段
    for k, v in pairs(data) do
        config[k] = v
    end

    local json_path = plugin_dir .. "/config.json"
    local f = io.open(json_path, "w")
    if not f then return json_response({success = false, message = "写入配置文件失败"}, 500) end
    f:write(cjson.encode(config))
    f:close()
    return json_response({success = true, message = "配置已保存，重启 Nginx 后生效"})
end

local function handle_check(ip)
    if not ip or ip == "" then
        return json_response({error = "invalid_ip", message = "IP 地址不能为空"})
    end

    local result = {ip = ip, blocked = false, reason = nil, detail = nil}

    local store = get_store()
    if store then
        local dict_name = (config.shared_dict or {}).dict_name or "rfw"
        local prefix = (config.shared_dict or {}).key_prefix or "rfw:"
        local block_key = prefix .. "block:" .. ip
        local v = store:get(block_key)
        if v then
            local until_ts, ban_ts, reason = v:match("^(%d+)%|(%d+)%|(.-)$")
            if until_ts then until_ts = tonumber(until_ts) end
            if until_ts and until_ts > ngx.time() then
                result.blocked = true
                result.reason = "blocked"
                result.detail = "因 " .. (reason or "unknown") .. " 封禁，剩余 " .. (until_ts - ngx.time()) .. " 秒"
                return json_response(result)
            end
        end
    end

    local bl = get_block_log()
    local entry = bl[ip]
    if entry and entry.unblock and entry.unblock > ngx.time() then
        result.blocked = true
        result.reason = "blocked"
        result.detail = "因 " .. (entry.reason or "unknown") .. " 封禁，剩余 " .. (entry.unblock - ngx.time()) .. " 秒"
        return json_response(result)
    end

    return json_response(result)
end

-- ============================================================
-- Log Viewing
-- ============================================================

local LOG_DIR_RFW = plugin_dir .. "/logs"

local function file_ok(name)
    if not name or name == "" then return false end
    return name:match("^rfw_%d%d%d%d%-%d%d%-%d%d%.log$") ~= nil
        or name == "rfw.error.log"
end

local function read_tail_lines(path, max_bytes)
    max_bytes = max_bytes or 4 * 1024 * 1024
    local f = io.open(path, "r")
    if not f then return {}, 0, false end
    f:seek("end")
    local size = f:seek()
    local read_size = math.min(size, max_bytes)
    f:seek("cur", -read_size)
    local data = f:read(read_size)
    f:close()
    if not data then return {}, 0, false end
    local truncated = size > max_bytes
    local first_nl = data:find("\n", 1, true)
    if first_nl and truncated then data = data:sub(first_nl + 1) end
    local lines = {}
    for line in (data .. "\n"):gmatch("(.-)\n") do
        if line ~= "" then lines[#lines + 1] = line end
    end
    return lines, size, truncated
end

local function list_log_files(days)
    days = math.min(tonumber(days) or 30, 90)
    local files = {}
    local now = os.time()
    for i = 0, days - 1 do
        local t = now - i * 86400
        local name = string.format("rfw_%s.log", os.date("%Y-%m-%d", t))
        local path = LOG_DIR_RFW .. "/" .. name
        local f = io.open(path, "r")
        if f then
            f:seek("end")
            local sz = f:seek()
            f:close()
            files[#files + 1] = {name = name, size = sz}
        end
    end
    local err_path = LOG_DIR_RFW .. "/rfw.error.log"
    local f = io.open(err_path, "r")
    if f then
        f:seek("end")
        local sz = f:seek()
        f:close()
        files[#files + 1] = {name = "rfw.error.log", size = sz}
    end
    return files
end

local function handle_api_logs()
    local days = tonumber(ngx.var.arg_days) or 30
    local files = list_log_files(days)
    return json_response({files = files})
end

local function handle_api_log()
    local file = ngx.var.arg_file
    if not file_ok(file) then
        return json_response({error = "invalid_file"}, 400)
    end
    local lines_val = tonumber(ngx.var.arg_lines) or 200
    lines_val = math.min(math.max(lines_val, 1), 1000)
    local filter = ngx.var.arg_filter
    local path = LOG_DIR_RFW .. "/" .. file
    local lines, size, truncated = read_tail_lines(path, 4 * 1024 * 1024)
    if filter and filter ~= "" then
        local filtered = {}
        local flt = filter:lower()
        for _, line in ipairs(lines) do
            if line:lower():find(flt, 1, true) then
                filtered[#filtered + 1] = line
            end
        end
        lines = filtered
    end
    local count = #lines
    if count > lines_val then
        local trimmed = {}
        for i = count - lines_val + 1, count do
            trimmed[#trimmed + 1] = lines[i]
        end
        lines = trimmed
    end
    return json_response({file = file, lines = lines, count = count, truncated = truncated})
end

local function handle_api_history()
    local days = tonumber(ngx.var.arg_days) or 7
    days = math.min(math.max(days, 1), 31)
    local log_dir = plugin_dir .. "/logs"
    local now = os.time()
    local day_results = {}
    local totals_denied = 0
    local totals_blocks = 0
    local totals_by_reason = {}
    local totals_ip_count = {}
    for i = days - 1, 0, -1 do
        local t = now - i * 86400
        local fname = string.format("rfw_%s.log", os.date("%Y-%m-%d", t))
        local fpath = log_dir .. "/" .. fname
        local f = io.open(fpath, "r")
        local day_obj = {date = os.date("%Y-%m-%d", t), found = false,
                         denied_total = 0, denied_by_reason = {},
                         blocks = 0, top_ips = {}, snapshots = {}}
        if f then
            day_obj.found = true
            local ip_count = {}
            local data = f:read("*a")
            f:close()
            if data and data ~= "" then
                for line in (data .. "\n"):gmatch("(.-)\n") do
                    if line ~= "" then
                        local parsed = false
                        local jok, obj = pcall(cjson.decode, line)
                        if jok and type(obj) == "table" then
                            parsed = true
                            local tag = obj.attack_method
                            if tag == "SNAP" then
                                local snap = {ts = obj.local_time or ""}
                                for k, v in tostring(obj.req_data or ""):gmatch("(%w+)=(%d+)") do
                                    snap[k] = tonumber(v)
                                end
                                day_obj.snapshots[#day_obj.snapshots+1] = snap
                            elseif tag ~= "ERROR" and tag ~= "DEBUG" then
                                day_obj.denied_total = day_obj.denied_total + 1
                                day_obj.denied_by_reason[tag] = (day_obj.denied_by_reason[tag] or 0) + 1
                                local ip = obj.client_ip
                                if ip and ip ~= "-" then ip_count[ip] = (ip_count[ip] or 0) + 1 end
                            end
                        end
                        if not parsed then
                            local ts, tag = line:match("^(%d%d%d%d%-%d%d%-%d%d %d%d:%d%d:%d%d) %[(%w+)%]")
                            if tag == "DENY" then
                                day_obj.denied_total = day_obj.denied_total + 1
                                local reason = line:match("reason=(%S+)") or "unknown"
                                day_obj.denied_by_reason[reason] = (day_obj.denied_by_reason[reason] or 0) + 1
                                local ip = line:match("ip=(%S+)") or ""
                                if ip ~= "" then ip_count[ip] = (ip_count[ip] or 0) + 1 end
                            elseif tag == "SNAP" then
                                local snap = {ts = ts}
                                for k, v in line:gmatch("(%w+)=(%d+)") do snap[k] = tonumber(v) end
                                day_obj.snapshots[#day_obj.snapshots+1] = snap
                            end
                        end
                    end
                end
            end
            local sorted_ips = {}
            for ip, cnt in pairs(ip_count) do sorted_ips[#sorted_ips+1] = {ip, cnt} end
            table.sort(sorted_ips, function(a,b) return a[2] > b[2] end)
            local top_n = {}
            for j = 1, math.min(10, #sorted_ips) do top_n[j] = sorted_ips[j] end
            day_obj.top_ips = top_n
            totals_denied = totals_denied + day_obj.denied_total
            for r, c in pairs(day_obj.denied_by_reason) do
                totals_by_reason[r] = (totals_by_reason[r] or 0) + c
            end
            for ip, c in pairs(ip_count) do
                totals_ip_count[ip] = (totals_ip_count[ip] or 0) + c
            end
        end
        day_results[#day_results+1] = day_obj
    end
    local sorted_totals_ips = {}
    for ip, cnt in pairs(totals_ip_count) do sorted_totals_ips[#sorted_totals_ips+1] = {ip, cnt} end
    table.sort(sorted_totals_ips, function(a,b) return a[2] > b[2] end)
    local top_totals_ips = {}
    for j = 1, math.min(10, #sorted_totals_ips) do top_totals_ips[j] = sorted_totals_ips[j] end
    local last_snap = nil
    for i = #day_results, 1, -1 do
        if day_results[i].found and #day_results[i].snapshots > 0 then
            last_snap = day_results[i].snapshots[#day_results[i].snapshots]
            break
        end
    end
    return json_response({
        unit = "rfw",
        days = day_results,
        totals = {
            denied = totals_denied,
            blocks = totals_blocks,
            denied_by_reason = totals_by_reason,
            top_ips = top_totals_ips,
            last_snapshot = last_snap,
            truncated = false
        }
    })
end

-- ============================================================
-- Router
-- ============================================================

function _M.run()
    local uri = ngx.var.uri

    if not admin_check() then
        ngx.log(ngx.WARN, "admin: rejected ip=", get_admin_ip(),
                            " remote=", ngx.var.remote_addr,
                            " uri=", ngx.var.uri)
        ngx.status = 404
        ngx.header["Content-Type"] = "text/html; charset=utf-8"
        ngx.say("<html><head><title>404 Not Found</title></head>" ..
                "<body><center><h1>404 Not Found</h1></center>" ..
                "<hr><center>nginx</center></body></html>")
        return ngx.exit(404)
    end

    if uri == "/cgi-rfw" or uri == "/cgi-rfw/" then
        return ngx.redirect("/cgi-rfw/status")
    elseif uri == "/cgi-rfw/api/stats" then
        return handle_api_stats()
    elseif uri == "/cgi-rfw/status" then
        return html_response(STATUS_HTML)
    elseif uri == "/cgi-rfw/config" then
        return html_response(CONFIG_HTML)
    elseif uri == "/cgi-rfw/api/config" then
        local method = ngx.req.get_method()
        if method == "GET" then
            return handle_api_config_get()
        elseif method == "POST" then
            return handle_api_config_save()
        else
            return json_response({error = "method_not_allowed"}, 405)
        end
    elseif uri == "/cgi-rfw/logs" then
        return html_response(LOGS_HTML)
    elseif uri == "/cgi-rfw/api/logs" then
        return handle_api_logs()
    elseif uri == "/cgi-rfw/api/log" then
        return handle_api_log()
    elseif uri == "/cgi-rfw/api/history" then
        return handle_api_history()
    elseif uri:match("^/cgi%-rfw/check/(.+)$") then
        local ip = uri:match("^/cgi%-rfw/check/(.+)$")
        return handle_check(ip)
    else
        return ngx.redirect("/cgi-rfw/status")
    end
end

return _M
