-- MA-RFW (MoeArt Replay Firewall / 萌艺科技重放攻击防火墙)
-- 开发组织: 萌艺科技 MASEC 项目组 (MoeArt Inc, MA-SEC Team)
-- sha256.lua — 纯 Lua 实现 SHA256 / HMAC-SHA256 (零外部依赖)
-- 依赖: 仅 LuaJIT 内建 bit 库(nginx 的 LuaJIT 自带)
-- 返回: { hex = sha256_hex(msg), hmac = hmac_sha256_hex(secret, msg) }
local bit = bit

local K = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
}

local function ror(x, n)
    return bit.bor(bit.rshift(x, n), bit.lshift(x, 32 - n))
end

local function pad(msg)
    local bitlen = #msg * 8
    local padded = msg .. "\128"
    padded = padded .. string.rep("\0", (56 - (#padded % 64)) % 64)
    -- 64-bit 大端总比特数(低 64 位); #msg*8 对 <512MB 的消息高 32 位为 0
    local hi = math.floor(bitlen / 0x100000000)
    local lo = bitlen % 0x100000000
    padded = padded .. string.char(
        math.floor(hi / 0x1000000) % 0x100,
        math.floor(hi / 0x10000) % 0x100,
        math.floor(hi / 0x100) % 0x100,
        hi % 0x100,
        math.floor(lo / 0x1000000) % 0x100,
        math.floor(lo / 0x10000) % 0x100,
        math.floor(lo / 0x100) % 0x100,
        lo % 0x100)
    return padded
end

-- 返回 32 字节二进制摘要
local function sha256_bytes(msg)
    local padded = pad(msg)
    local H = { 0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
                0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19 }
    local w = {}

    for i = 1, #padded, 64 do
        for j = 0, 15 do
            local b = i + j * 4
            w[j + 1] = bit.bor(
                bit.lshift(padded:byte(b), 24),
                bit.lshift(padded:byte(b + 1), 16),
                bit.lshift(padded:byte(b + 2), 8),
                padded:byte(b + 3))
        end
        for j = 17, 64 do
            local x = w[j - 15]
            local s0 = bit.bxor(ror(x, 7), ror(x, 18), bit.rshift(x, 3))
            local y = w[j - 2]
            local s1 = bit.bxor(ror(y, 17), ror(y, 19), bit.rshift(y, 10))
            w[j] = (w[j - 16] + s0 + w[j - 7] + s1) % 0x100000000
        end

        local a, b, c, d, e, f, g, h = H[1], H[2], H[3], H[4], H[5], H[6], H[7], H[8]
        for j = 1, 64 do
            local S1 = bit.bxor(ror(e, 6), ror(e, 11), ror(e, 25))
            local ch = bit.bxor(bit.band(e, f), bit.band(bit.bnot(e), g))
            local temp1 = (h + S1 + ch + K[j] + w[j]) % 0x100000000
            local S0 = bit.bxor(ror(a, 2), ror(a, 13), ror(a, 22))
            local maj = bit.bxor(bit.band(a, b), bit.band(a, c), bit.band(b, c))
            local temp2 = (S0 + maj) % 0x100000000
            h = g; g = f; f = e
            e = (d + temp1) % 0x100000000
            d = c; c = b; b = a
            a = (temp1 + temp2) % 0x100000000
        end

        H[1] = (H[1] + a) % 0x100000000
        H[2] = (H[2] + b) % 0x100000000
        H[3] = (H[3] + c) % 0x100000000
        H[4] = (H[4] + d) % 0x100000000
        H[5] = (H[5] + e) % 0x100000000
        H[6] = (H[6] + f) % 0x100000000
        H[7] = (H[7] + g) % 0x100000000
        H[8] = (H[8] + h) % 0x100000000
    end

    local out = {}
    for i = 1, 8 do
        local x = H[i] % 0x100000000
        out[#out + 1] = string.char(
            math.floor(x / 0x1000000) % 0x100,
            math.floor(x / 0x10000) % 0x100,
            math.floor(x / 0x100) % 0x100,
            x % 0x100)
    end
    return table.concat(out)
end

local function sha256_hex(msg)
    return (sha256_bytes(msg):gsub(".", function(c)
        return string.format("%02x", c:byte())
    end))
end

-- HMAC-SHA256, 返回 hex 小写
local function hmac_sha256_hex(secret, msg)
    local key = secret
    if #key > 64 then key = sha256_bytes(key) end

    local ipad, opad = {}, {}
    for i = 1, 64 do ipad[i] = 0x36; opad[i] = 0x5c end
    for i = 1, #key do
        local b = key:byte(i)
        ipad[i] = bit.bxor(b, 0x36)
        opad[i] = bit.bxor(b, 0x5c)
    end

    local inner = sha256_bytes(string.char(unpack(ipad)) .. msg)
    return sha256_hex(string.char(unpack(opad)) .. inner)
end

-- HMAC 密钥预计算(性能优化): secret 固定时, ipad/opad 只需算一次。
-- 返回 sign(msg) -> hex 的函数, 结果与 hmac_sha256_hex(secret, msg) 完全一致,
-- 但每次签名省掉 64 字节 ipad/opad 构造与异或循环(签名热路径每请求省 ~2 次该开销)。
-- ma_rfw.lua 在模块加载时只调用一次, 之后每个请求的 HMAC 不再重复扩展密钥。
local function hmac_prepare(secret)
    local key = secret
    if #key > 64 then key = sha256_bytes(key) end

    local ipad, opad = {}, {}
    for i = 1, 64 do ipad[i] = 0x36; opad[i] = 0x5c end
    for i = 1, #key do
        local b = key:byte(i)
        ipad[i] = bit.bxor(b, 0x36)
        opad[i] = bit.bxor(b, 0x5c)
    end
    local ipad_s = string.char(unpack(ipad))
    local opad_s = string.char(unpack(opad))
    return function(msg)
        return sha256_hex(opad_s .. sha256_bytes(ipad_s .. msg))
    end
end

return {
    hex = sha256_hex,
    hmac = hmac_sha256_hex,
    hmac_prepare = hmac_prepare,
}
