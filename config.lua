-- MA-RFW (MoeArt Replay Firewall / 萌艺科技重放攻击防火墙)
-- 开发组织: 萌艺科技 MASEC 项目组 (MoeArt Inc, MA-SEC Team)
--
-- 存储后端: ngx.shared.DICT (nginx 共享内存)
-- nginx.conf 必须声明: lua_shared_dict rfw 64m;
local src = debug.getinfo(1, "S").source
local plugin_dir = (src:sub(1, 1) == "@" and src:sub(2) or src):match("^(.*)[/\\][^/\\]+$") or "."

return {
    -- 共享密钥(用于请求签名/cookie 签名)
    secret = "N9x_Ant1_r3p14y!",

    plugin_dir = plugin_dir,
    version = "3.0.0",

    -- nginx.conf 必须声明: lua_shared_dict rfw 64m;
    shared_dict = {
        dict_name = "rfw",
        key_prefix = "rfw:",
    },

    html_file = plugin_dir .. "/blocked.html",

    -- cookie 配置
    cookie_name = "_RFW",
    cookie_ttl = 86400,
    cookie_ts_max = 60,
    cookie_bootstrap = true,
    cookie_replay_window = 2,
    cookie_replay_max = 5,

    -- 会话序号
    seq_slack = 10,
    seq_ttl = 86400,
    seq_cache_ttl = 3,

    -- 签名校验
    sign_enabled = true,
    sign_window = 60,
    sign_ratio_req = 10,
    sign_ratio_min = 0.5,
    sign_ratio_fail = false,

    -- 静态资源扩展名
    static_ext = {
        ".html", ".htm", ".js", ".css",
        ".png", ".jpg", ".jpeg", ".gif", ".svg", ".webp", ".bmp", ".ico",
        ".woff", ".woff2", ".ttf", ".eot", ".map", ".pdf",
    },

    -- 覆盖率判定
    cookie_ratio_req = 10,
    cookie_ratio_min = 0.5,
    cookie_ratio_fail = false,

    -- 无 cookie 日配额(0 = 关闭)
    cookie_missing_max = 50,
    cookie_missing_ttl = 86400,

    -- 重放检测
    replay_enabled = true,
    replay_threshold = 5,
    replay_relink_sec = 2,

    -- 惩罚: 窗口内失败 fail_max 次 → 封禁 block_time 秒
    fail_max = 5,
    fail_window = 60,
    block_time = 600,
    block_cache_ttl = 60,

    -- 状态页
    status_enabled = true,
    status_path = "/cgi-rfw/status",

    -- 后台清扫间隔(秒)
    sweep_interval = 60,

    -- 调试
    debug = false,
}
