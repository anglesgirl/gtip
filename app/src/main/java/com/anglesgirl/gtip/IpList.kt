package com.anglesgirl.gtip

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.io.BufferedReader
import java.io.InputStreamReader
import java.net.HttpURLConnection
import java.net.InetAddress
import java.net.URL

/**
 * IP 列表来源：CIDR 段展开（照原版 GoogleTranslate_IPFinder 的 scan_ranges）
 * + 在线拉取（gtdb）+ 手动粘贴。
 */
object IpList {

    /**
     * 原版扫描范围（GWS 前缀，来自原项目 core/constants.py scan_ranges）。
     * 默认启用：142.250.0.0/15（13 万 IPv4）+ 4 个 GWS IPv6 /112 段（各 6.5 万）
     * = 393216 个，与原版默认一致。
     */
    val scanRanges = listOf(
        "142.250.0.0/15",              // GWS IPv4 主段
        "2001:4860:4802:32::/112",     // GWS v6
        "2607:f8b0:4000:80a::/112",    // GWS v6
        "2607:f8b0:4005:801::/112",    // GWS v6
        "2a00:1450:4010:c0d::/112",    // GWS v6（用户截图中原版正在扫的段）
        "2404:6800:4005:800::/56",     // GWS v6 香港 hkg（2404:6800:4005:806::200e 实测域名 hkg12s11-in-x0e）
    )

    /**
     * 按地区分组扫描（GWS IPv6，官方 Public DNS 地理位置段）：
     * - 香港 hkg：2404:6800:4005::/48（实测活跃 :806::200e，PTR hkg12s11-in-x0e）
     * - 日本：kix 关西 2404:6800:400a:1xxx::/61-/62 + nrt 成田 2404:6800:400b:c0xx::/60-/62
     * - 新加坡 sin：2404:6800:4003::/48
     * 单独选地区 = 只扫该地区段；选"全部" = 扫上面 scanRanges 全集。
     */
    val regionRanges: LinkedHashMap<String, List<String>> = linkedMapOf(
        "香港" to listOf("2404:6800:4005:800::/56"),
        "日本" to listOf(
            "2404:6800:400a:1000::/62",
            "2404:6800:400a:1004::/62",
            "2404:6800:400a:1008::/61",
            "2404:6800:400b:c000::/62",
            "2404:6800:400b:c004::/62",
            "2404:6800:400b:c010::/60",
        ),
        "新加坡" to listOf("2404:6800:4003::/48"),
    )

    /** 快速模式：每个段最多采样这么多地址。 */
    const val QUICK_PER_SEG = 4096

    /** 完整模式下各段展开后的总地址数（393216）。 */
    val fullCount: Int = scanRanges.sumOf { segmentSize(it) }

    /** 快速模式下总地址数。 */
    val quickCount: Int = scanRanges.sumOf { minOf(segmentSize(it), QUICK_PER_SEG) }

    /** 按 CIDR 展开地址列表；maxHosts 限制时做均匀采样。 */
    fun expandCidr(cidr: String, maxHosts: Int): List<String> {
        val slash = cidr.indexOf('/')
        if (slash <= 0) return emptyList()
        val net = cidr.substring(0, slash)
        val prefix = cidr.substring(slash + 1).toIntOrNull() ?: return emptyList()
        return if (net.contains(":")) expandV6(net, prefix, maxHosts) else expandV4(net, prefix, maxHosts)
    }

    private fun segmentSize(cidr: String): Int {
        val slash = cidr.indexOf('/')
        val prefix = cidr.substring(slash + 1).toIntOrNull() ?: return 0
        val hostBits = if (cidr.contains(":")) 128 - prefix else 32 - prefix
        if (hostBits >= 62) return Int.MAX_VALUE
        return 1 shl hostBits
    }

    /** IPv4 CIDR 展开（a.b.c.d/n），host 位最多 31。 */
    private fun expandV4(net: String, prefix: Int, max: Int): List<String> {
        val parts = net.split(".").map { it.toInt() }
        if (parts.size != 4) return emptyList()
        val base = parts.fold(0L) { acc, p -> (acc shl 8) or p.toLong() }
        val hostBits = 32 - prefix
        if (hostBits < 0 || hostBits > 31) return emptyList()
        val total = 1L shl hostBits
        // /32：唯一地址；/31：RFC 3021 两个地址均可用
        if (total <= 2L) {
            return (0 until total).map { i ->
                val v = base + i
                "${(v shr 24) and 0xff}.${(v shr 16) and 0xff}.${(v shr 8) and 0xff}.${v and 0xff}"
            }
        }
        // 跳过网络地址（base+0）与广播地址（base+total-1），只采样可用主机
        val usable = total - 2
        val step = if (usable > max) usable / max else 1L
        val out = ArrayList<String>(minOf(usable, max.toLong()).toInt())
        var i = 1L
        while (i < total - 1) {
            val v = base + i
            out.add("${(v shr 24) and 0xff}.${(v shr 16) and 0xff}.${(v shr 8) and 0xff}.${v and 0xff}")
            i += step
        }
        return out
    }

    /**
     * IPv6 CIDR 展开：支持 /112（最后 16 位可变）与 /64（最后 64 位，采样）。
     * 网络部分按 "xxxx:...::" 形式拼接后缀。
     */
    private fun expandV6(net: String, prefix: Int, max: Int): List<String> {
        val hostBits = 128 - prefix
        if (hostBits < 0 || hostBits > 80) return emptyList()
        if (hostBits <= 64) {
            val total = if (hostBits >= 63) Long.MAX_VALUE else 1L shl hostBits
            val step = if (total > max) total / max else 1L
            val base = net.removeSuffix("::")
            val out = ArrayList<String>(minOf(total, max.toLong()).toInt())
            var n = 0L
            while (n < total && out.size < max) {
                out.add(suffixV6(base, hostBits, n))
                n += step
            }
            return out
        }
        // /56..:/63（hostBits 65..72）：高 (hostBits-64) 位作为子段循环，
        // 每个子段内用固定"活跃后缀"采样。例：2404:6800:4005:800::/56 → 256 个子段。
        // 为什么用固定后缀：谷歌活跃地址是 ::200e/::200d 这类低 64 位值
        // （用户实测 hkg12s11-in-x0e 的 PTR = 2404:6800:4005:806::200e），
        // 等差大跳采样全落在 ::0:0:0:0 子网地址上，一个都 ping 不通。
        val subBits = hostBits - 64            // 8 → 256 个子段
        val subs = 1L shl subBits
        val perSub = (max / subs).coerceAtLeast(1)
        // 低 64 位活跃后缀候选（覆盖常见主机位；不足 perSub 时再补等差）
        val suffixes = longArrayOf(
            0x1L, 0x100L, 0x200L, 0x1000L, 0x2000L, 0x200eL, 0x200dL, 0x2010L,
            0x2020L, 0x3000L, 0x4000L, 0x5000L, 0x8000L, 0xa000L, 0xc000L, 0xe000L,
        )
        val out = ArrayList<String>(minOf(max, (subs * perSub).toInt()))
        val base = net.removeSuffix("::")
        for (sub in 0 until subs) {
            if (out.size >= max) break
            // 子段号拼进 base 的最后一个 hextet（如 :80 → :80XX）
            val subHex = sub.toString(16)
            val subBase = "$base$subHex"
            var i = 0
            while (i < perSub) {
                if (out.size >= max) break
                val n = if (i < suffixes.size) suffixes[i] else 0x200eL + i.toLong() * 0x100L
                out.add(suffixV6(subBase, 64, n))
                i++
            }
        }
        return out
    }

    private fun suffixV6(base: String, hostBits: Int, v: Long): String {
        return when {
            hostBits <= 16 -> "$base::${v.toString(16)}"
            hostBits <= 32 -> "$base::${(v ushr 16).toString(16)}:${(v and 0xffff).toString(16)}"
            hostBits <= 48 -> "$base::${(v ushr 32).toString(16)}:${((v ushr 16) and 0xffff).toString(16)}:${(v and 0xffff).toString(16)}"
            else -> "$base::${(v ushr 48).toString(16)}:${((v ushr 32) and 0xffff).toString(16)}:${((v ushr 16) and 0xffff).toString(16)}:${(v and 0xffff).toString(16)}"
        }
    }

    /** 校验 IP 文本（IPv4 / IPv6，含 [IPv6] 形式）。 */
    fun isValidIp(text: String): Boolean {
        val t = text.trim().removePrefix("[").removeSuffix("]")
        if (t.isEmpty()) return false
        return try {
            InetAddress.getByName(t).hostAddress != null
        } catch (_: Exception) {
            false
        }
    }

    private val IP4 = Regex("^(25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]?\\d)(\\.(25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]?\\d)){3}$")

    private val CIDR4 = Regex("^(25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]?\\d)(\\.(25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]?\\d)){3}/(3[0-2]|[12]?\\d)$")
    private val CIDR6 = Regex("^[0-9a-fA-F:.]+/\\d{1,3}$")

    /**
     * 中国 IPv4 CIDR 段列表（在线拉取，17mon/china_ip_list 纯真库合并段，
     * 约 7000+ 条，覆盖全中国 IPv4；每段采样 1 个 IP 即可全境覆盖）。
     */
    val chinaCidrUrls = listOf(
        "https://ghproxy.net/https://raw.githubusercontent.com/17mon/china_ip_list/master/china_ip_list.txt",
        "https://raw.githubusercontent.com/17mon/china_ip_list/master/china_ip_list.txt",
        "https://ghproxy.net/https://raw.githubusercontent.com/gaoyifan/china-operator-ip/master/chunzhen/cn.txt",
    )

    /**
     * 内置云厂商 CIDR 段（assets/cloud_cidrs.txt）：
     * 阿里云(AS45102/37963)、腾讯云(AS45090/132203)、火山引擎(AS137718/150436)、
     * 华为云(AS55990)、百度云(AS55967)、UCloud(AS134763)。
     * 用户手里 121.43.177.34 之类"能通 Google 的特殊 IP"大多落在这些段里。
     */
    fun loadCloudCidrs(context: android.content.Context): List<String> {
        return try {
            context.assets.open("cloud_cidrs.txt").bufferedReader().use { r ->
                r.readLines().asSequence()
                    .map { it.trim() }
                    .filter { it.isNotEmpty() && it.contains('/') }
                    .distinct()
                    .toList()
            }
        } catch (_: Exception) {
            emptyList()
        }
    }

    /** 拉取中国 CIDR 列表（第一个成功即返回，去重，只保留合法 CIDR）。 */
    suspend fun fetchChinaCidrs(): List<String> = withContext(Dispatchers.IO) {
        for (url in chinaCidrUrls) {
            try {
                val conn = URL(url).openConnection() as HttpURLConnection
                conn.connectTimeout = 8000
                conn.readTimeout = 15000
                conn.instanceFollowRedirects = true
                conn.setRequestProperty("User-Agent", "Mozilla/5.0")
                if (conn.responseCode in 200..299) {
                    val lines = BufferedReader(InputStreamReader(conn.inputStream)).use { r ->
                        r.readLines()
                    }
                    val cidrs = lines.asSequence()
                        .map { it.trim() }
                        .mapNotNull { line ->
                            // 兼容纯列表（每行一个 CIDR）与"运营商 名称 CIDR"行
                            line.split(Regex("[\\s,，]+")).lastOrNull { it.contains('/') }
                        }
                        .filter { it.matches(CIDR4) || it.matches(CIDR6) }
                        .distinct()
                        .toList()
                    if (cidrs.isNotEmpty()) return@withContext cidrs
                }
            } catch (_: Exception) {
            }
        }
        emptyList()
    }

    /** 内置精选 IPv4（gtdb 数据节选，在线拉取失败时的兜底）。 */
    val builtin: Set<String> by lazy {
        """
34.1.15.24
64.233.161.17
64.233.162.122
64.233.164.6
64.233.167.83
74.125.24.100
108.177.97.102
108.177.97.131
108.177.97.137
108.177.97.142
108.177.97.154
108.177.97.158
108.177.119.119
108.177.122.113
108.177.122.138
108.177.125.100
142.250.4.14
142.250.4.90
142.250.4.94
142.250.4.98
142.250.4.100
142.250.4.101
142.250.4.102
142.250.4.103
142.250.4.105
142.250.4.108
142.250.4.110
142.250.4.115
142.250.4.116
142.250.4.120
142.250.4.131
142.250.4.137
142.250.4.138
142.250.4.142
142.250.4.147
142.250.4.148
142.250.4.150
142.250.4.156
142.250.4.160
142.250.4.169
142.250.4.172
142.250.4.174
142.250.4.175
142.250.4.177
142.250.4.178
142.250.4.180
142.250.4.187
142.250.4.189
142.250.4.190
142.250.4.191
142.250.4.193
142.250.4.196
142.250.4.198
142.250.4.199
142.250.4.201
142.250.4.202
142.250.4.203
142.250.4.204
142.250.4.205
142.250.4.207
142.250.4.208
142.250.4.209
142.250.4.210
142.250.4.211
142.250.4.212
142.250.4.214
142.250.4.215
142.250.4.216
142.250.4.218
142.250.4.219
142.250.4.220
142.250.4.221
142.250.4.222
142.250.4.223
142.250.4.224
142.250.4.225
142.250.4.226
142.250.4.227
142.250.4.228
142.250.4.229
142.250.4.230
142.250.4.231
142.250.4.232
142.250.4.233
142.250.4.234
142.250.4.235
142.250.4.236
142.250.4.238
142.250.4.239
142.250.4.240
142.250.4.241
142.250.4.242
142.250.4.243
142.250.4.244
142.250.4.245
142.250.4.246
142.250.4.247
142.250.4.248
142.250.4.249
142.250.4.250
142.250.4.251
142.250.4.252
142.250.4.253
142.250.4.254
142.250.4.255
172.217.15.74
172.217.161.26
172.217.161.27
172.217.161.46
172.217.162.28
172.217.194.138
216.58.203.194
216.58.215.14
216.58.215.26
216.58.215.78
216.58.215.110
216.58.215.126
216.58.215.142
216.58.215.158
216.58.215.174
216.58.215.190
216.58.215.206
216.58.215.222
216.58.215.238
216.58.215.254
216.58.217.174
216.58.217.190
216.58.217.206
216.58.217.222
216.58.217.238
142.250.68.46
142.250.68.62
142.250.68.78
142.250.68.94
142.250.68.110
142.250.68.126
142.250.68.142
142.250.68.158
142.250.68.174
142.250.68.190
142.250.68.206
142.250.68.222
142.250.68.238
142.250.69.14
142.250.69.30
142.250.69.46
142.250.69.62
142.250.69.78
142.250.69.94
142.250.69.110
142.250.69.126
142.250.69.142
142.250.69.158
142.250.69.174
142.250.69.190
142.250.69.206
142.250.69.222
142.250.69.238
142.250.70.14
142.250.70.30
142.250.70.46
142.250.70.62
142.250.70.78
142.250.70.94
142.250.70.110
142.250.70.126
142.250.70.142
142.250.70.158
142.250.70.174
142.250.70.190
142.250.70.206
142.250.70.222
142.250.70.238
142.250.71.14
142.250.71.30
142.250.71.46
142.250.71.62
142.250.71.78
142.250.71.94
142.250.71.110
142.250.71.126
142.250.71.142
142.250.71.158
142.250.71.174
142.250.71.190
142.250.71.206
142.250.71.222
142.250.71.238
""".trimIndent().lineSequence().map { it.trim() }.filter {
            it.isNotEmpty() && it.matches(IP4)
        }.toSet()
    }

    /** 在线 IPv4 库（原版 ONLINE_SERVICES，含 ghproxy 镜像）。 */
    val onlineUrls = listOf(
        "https://ghproxy.net/https://raw.githubusercontent.com/GoodCoder666/gtdb/main/src/ip.txt",
        "https://raw.githubusercontent.com/GoodCoder666/gtdb/main/src/ip.txt",
    )

    /** 拉取在线 IP 列表（第一个成功即返回；只保留合法 IPv4/IPv6）。 */
    suspend fun fetchOnline(): List<String> = withContext(Dispatchers.IO) {
        for (url in onlineUrls) {
            try {
                val conn = URL(url).openConnection() as HttpURLConnection
                conn.connectTimeout = 8000
                conn.readTimeout = 8000
                conn.instanceFollowRedirects = true
                conn.setRequestProperty("User-Agent", "Mozilla/5.0")
                if (conn.responseCode in 200..299) {
                    val lines = BufferedReader(InputStreamReader(conn.inputStream)).use { r ->
                        r.readLines()
                    }
                    val ips = lines.map { it.trim() }
                        .filter { isValidIp(it) }
                    if (ips.isNotEmpty()) return@withContext ips
                }
            } catch (_: Exception) {
            }
        }
        emptyList()
    }

    /** 解析用户粘贴的文本（支持逗号/空格/换行分隔，IPv4 与 IPv6 均可）。 */
    fun parseManual(text: String): List<String> =
        text.split(Regex("[,\\s，]+")).map { it.trim() }
            .filter { isValidIp(it) }
}
