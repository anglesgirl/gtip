package com.anglesgirl.gtip

import android.content.ClipData
import android.content.ClipboardManager
import android.os.Bundle
import android.util.Base64
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.Button
import android.widget.EditText
import android.widget.TextView
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import androidx.core.view.ViewCompat
import androidx.core.view.WindowCompat
import androidx.core.view.WindowInsetsCompat
import androidx.core.view.updatePadding
import androidx.recyclerview.widget.LinearLayoutManager
import androidx.recyclerview.widget.RecyclerView
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import org.json.JSONObject
import java.io.File
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.util.concurrent.ConcurrentLinkedQueue
import java.util.concurrent.Executors
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicInteger
import javax.net.ssl.TrustManagerFactory

/**
 * 谷歌翻译 IP 扫描（Android 版）：先 TCP ping 筛活，再对活 IP 做 HTTP/3 测速。
 *
 * 测速 = 域名匹配：UDP 连接候选 IP，QUIC SNI/TLS 证书/HTTP3 :authority 全部用
 * translate.googleapis.com，完成 H3 握手并拿到 200 响应才保留为可用 IP。
 * （与原版/业界做法一致：IP 只是连接目标，域名身份贯穿全链路。）
 *
 * 扫描范围照原版 GoogleTranslate_IPFinder：GWS 前缀 CIDR 段展开
 * （142.250.0.0/15 + 4 个 IPv6 /112 段，完整模式 393216 个；快速模式每段采样 4096）。
 */
class MainActivity : AppCompatActivity() {

    companion object {
        private const val HOST = "translate.googleapis.com"
        private const val PATH = "/translate_a/element.js"
        private const val PORT = 443
        private const val PING_TIMEOUT_MS = 1200L
        private const val H3_TIMEOUT_MS = 2000L
        private const val PING_CONCURRENCY = 96
        private const val H3_CONCURRENCY = 32
    }

    private lateinit var tvStatus: TextView
    private lateinit var tvCount: TextView
    private lateinit var etManual: EditText
    private lateinit var btnStart: Button
    private lateinit var btnMode: Button
    private lateinit var btnRegion: Button
    private lateinit var btnProto: Button
    private lateinit var btnFetch: Button
    private lateinit var btnCopyAll: Button
    private lateinit var btnClear: Button
    private lateinit var rvResults: RecyclerView

    private val adapter = ResultAdapter()
    private val results = mutableListOf<ResultRow>()

    /** 待测队列（CIDR 展开后的全部地址）。 */
    private val pending = mutableListOf<String>()
    private var quickMode = true
    /** 地区选择：0=全部（scanRanges 全集），其余按 IpList.regionRanges 键名。 */
    private var regionIdx = 0
    private val regionNames = listOf("全部") + IpList.regionRanges.keys.toList()

    /** 测法：0=H3（QUIC 判定） 1=TCP（TLS+HTTP 判定） 2=混合（H3 失败自动补 TCP）。 */
    private var protoMode = 0
    private val protoNames = arrayOf("H3", "TCP", "混合")
    private val protoHints = arrayOf(
        "HTTP/3 QUIC 域名匹配测速（原判定标准）",
        "TCP 443 + TLS + HTTP 测速（支持无 H3 的国内特殊 IP）",
        "先 H3，失败的 IP 自动补一轮 TCP"
    )

    private val done = AtomicInteger(0)
    private val ok = AtomicInteger(0)
    private val running = AtomicBoolean(false)
    private var h3Total = 0
    private var tcpTotal = 0
    private var scanJob: Job? = null
    private lateinit var caBundlePath: String
    private val pingPool = Executors.newFixedThreadPool(PING_CONCURRENCY) { r ->
        Thread(r, "tcp-ping").apply { isDaemon = true }
    }
    private val h3Pool = Executors.newFixedThreadPool(H3_CONCURRENCY) { r ->
        Thread(r, "h3-scan").apply { isDaemon = true }
    }
    private val scope = CoroutineScope(Dispatchers.Main)

    data class ResultRow(
        val ip: String,
        val ms: Long,
        val status: Int,
        val bytes: Int,
        val err: String,
        val proto: String
    )

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        WindowCompat.setDecorFitsSystemWindows(window, false)
        setContentView(R.layout.activity_main)
        ViewCompat.setOnApplyWindowInsetsListener(findViewById(android.R.id.content)) { v, insets ->
            val bars = insets.getInsets(WindowInsetsCompat.Type.systemBars())
            v.updatePadding(top = bars.top, bottom = bars.bottom)
            insets
        }

        tvStatus = findViewById(R.id.tvStatus)
        tvCount = findViewById(R.id.tvCount)
        etManual = findViewById(R.id.etManual)
        btnStart = findViewById(R.id.btnStart)
        btnFetch = findViewById(R.id.btnFetch)
        btnCopyAll = findViewById(R.id.btnCopyAll)
        btnClear = findViewById(R.id.btnClear)
        rvResults = findViewById(R.id.rvResults)
        rvResults.layoutManager = LinearLayoutManager(this)
        rvResults.adapter = adapter

        // 导出系统 CA bundle（native 证书校验用），一次性
        caBundlePath = exportSystemCas()

        btnStart.setOnClickListener { toggleScan() }
        btnMode = findViewById(R.id.btnMode)
        btnMode.setOnClickListener {
            quickMode = !quickMode
            rebuildPending()
            updateCount()
        }
        btnRegion = findViewById(R.id.btnRegion)
        btnRegion.text = "范围：${regionNames[regionIdx]}（点按切换）"
        btnRegion.setOnClickListener {
            regionIdx = (regionIdx + 1) % regionNames.size
            btnRegion.text = "范围：${regionNames[regionIdx]}（点按切换）"
            rebuildPending()
            updateCount()
        }
        btnProto = findViewById(R.id.btnProto)
        btnProto.text = "测法：${protoNames[protoMode]}（点按切换）"
        btnProto.setOnClickListener {
            protoMode = (protoMode + 1) % protoNames.size
            btnProto.text = "测法：${protoNames[protoMode]}（点按切换）"
            Toast.makeText(this, "测法 ${protoNames[protoMode]}：${protoHints[protoMode]}", Toast.LENGTH_SHORT).show()
        }
        btnFetch.setOnClickListener { fetchOnlineIps() }
        findViewById<Button>(R.id.btnChina).setOnClickListener { loadChinaIps() }
        btnCopyAll.setOnClickListener { copyAllOk() }
        btnClear.setOnClickListener {
            results.clear()
            adapter.notifyDataSetChanged()
            updateCount()
        }
        findViewById<Button>(R.id.btnAddManual).setOnClickListener { addManualIps() }
        findViewById<Button>(R.id.btnTest).setOnClickListener { testSingleIp() }

        // 按原版扫描范围展开待测列表（默认快速模式），需在 btnMode 初始化之后
        rebuildPending()

        updateCount()
    }

    /** 按当前模式+地区展开扫描范围（CIDR 段）。 */
    private fun rebuildPending() {
        val maxPerSeg = if (quickMode) IpList.QUICK_PER_SEG else Int.MAX_VALUE
        val ranges = if (regionIdx == 0) {
            IpList.scanRanges
        } else {
            IpList.regionRanges[regionNames[regionIdx]] ?: IpList.scanRanges
        }
        val list = ranges.flatMap { IpList.expandCidr(it, maxPerSeg) }
        synchronized(pending) {
            pending.clear()
            pending.addAll(list)
        }
        btnMode.text = if (quickMode) "模式：快速（${list.size} 个）" else "模式：完整（${list.size} 个）"
    }

    override fun onDestroy() {
        running.set(false)
        scanJob?.cancel()
        pingPool.shutdownNow()
        h3Pool.shutdownNow()
        super.onDestroy()
    }

    /** 把 Android 系统信任库（所有 CA）导出为 PEM bundle 文件。 */
    private fun exportSystemCas(): String {
        return try {
            val tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm())
            tmf.init(null as java.security.KeyStore?)
            val managers = tmf.trustManagers
            val sb = StringBuilder()
            for (m in managers) {
                if (m is javax.net.ssl.X509TrustManager) {
                    for (cert in m.acceptedIssuers) {
                        sb.append("-----BEGIN CERTIFICATE-----\n")
                        sb.append(Base64.encodeToString(cert.encoded, Base64.NO_WRAP))
                        sb.append("\n-----END CERTIFICATE-----\n")
                    }
                }
            }
            val f = File(cacheDir, "ca-bundle.pem")
            f.writeText(sb.toString())
            f.absolutePath
        } catch (_: Exception) {
            ""
        }
    }

    private fun toggleScan() {
        if (running.get()) {
            running.set(false)
            scanJob?.cancel()
            btnStart.text = "▶ 开始扫描"
            tvStatus.text = "已停止"
            return
        }
        if (pending.isEmpty()) {
            Toast.makeText(this, "没有可扫描的 IP：请先拉取在线列表或手动添加", Toast.LENGTH_LONG).show()
            return
        }
        results.clear()
        adapter.notifyDataSetChanged()
        done.set(0)
        ok.set(0)
        running.set(true)
        btnStart.text = "⏹ 停止"
        tvStatus.text = "阶段 1/2：TCP ping 筛活…"
        updateCount()
        scanJob = scope.launch {
            withContext(Dispatchers.Default) {
                // 阶段 1：TCP ping 筛选存活 IP
                val alive = pingAll(pending)
                if (!running.get()) return@withContext
                // 阶段 2：按当前测法分发
                when (protoMode) {
                    0 -> h3TestAll(alive)
                    1 -> tcpTestAll(alive)
                    else -> hybridTestAll(alive)
                }
                running.set(false)
            }
            btnStart.text = "▶ 开始扫描"
            tvStatus.text = if (ok.get() > 0) {
                "✅ 完成：找到 ${ok.get()} 个可用 IP"
            } else {
                "完成：未找到可用 IP（可换个网络/时段重试）"
            }
            updateCount()
        }
    }

    /** 阶段 1：高并发 TCP ping，返回存活 IP 列表。 */
    private fun pingAll(all: List<String>): List<String> {
        val queue = ConcurrentLinkedQueue(all)
        val alive = ConcurrentLinkedQueue<String>()
        val donePing = AtomicInteger(0)
        val futures = (1..PING_CONCURRENCY).map {
            pingPool.submit {
                while (running.get()) {
                    val ip = queue.poll() ?: break
                    val raw = runCatching {
                        QuicNative.tcpPing(ip, PORT, PING_TIMEOUT_MS)
                    }.getOrNull()
                    val (isOk, _) = QuicNative.parseResult(raw)
                    if (isOk) alive.add(ip)
                    val d = donePing.incrementAndGet()
                    scope.launch {
                        tvStatus.text = "阶段 1/2：TCP ping $d/${all.size}（存活 ${alive.size}）"
                    }
                }
            }
        }
        futures.forEach { it.get() }
        return alive.toList()
    }

    /** 阶段 2：对存活 IP 做 HTTP/3 测速，结果进列表。 */
    private fun h3TestAll(alive: List<String>) {
        if (alive.isEmpty()) {
            scope.launch { tvStatus.text = "阶段 1 无存活 IP，跳过 H3 测速" }
            return
        }
        h3Total = alive.size
        val queue = ConcurrentLinkedQueue(alive)
        val futures = (1..H3_CONCURRENCY).map {
            h3Pool.submit {
                while (running.get()) {
                    val ip = queue.poll() ?: break
                    testOne(ip)
                }
            }
        }
        futures.forEach { it.get() }
    }

    /** 单个 IP 的 HTTP/3 测速。 */
    private fun testOne(ip: String, onFail: ((String) -> Unit)? = null) {
        val raw = runCatching {
            QuicNative.test(ip, HOST, PORT, PATH, H3_TIMEOUT_MS, caBundlePath)
        }.getOrNull()
        val row = try {
            val j = raw?.let { JSONObject(it) }
            if (j != null && j.optBoolean("ok")) {
                ok.incrementAndGet()
                ResultRow(ip, j.optLong("ms"), j.optInt("status"), j.optInt("bytes"), "", "H3")
            } else {
                val err = j?.optString("err") ?: "native-fail"
                onFail?.invoke(ip)
                ResultRow(ip, -1, 0, 0, "H3:$err", "H3")
            }
        } catch (_: Exception) {
            onFail?.invoke(ip)
            ResultRow(ip, -1, 0, 0, "H3:parse-fail", "H3")
        }
        val d = done.incrementAndGet()
        scope.launch {
            synchronized(results) {
                results.add(row)
                results.sortWith(compareBy<ResultRow> { it.ms < 0 }.thenBy { it.ms })
            }
            adapter.notifyDataSetChanged()
            tvStatus.text = "阶段 2/2：H3 测速 $d/$h3Total（可用 ${ok.get()}）"
        }
    }

    /** 对存活 IP 列表做 TCP 测速（TCP 443 + TLS + HTTP 域名匹配）。 */
    private fun tcpTestAll(alive: List<String>) {
        if (alive.isEmpty()) {
            scope.launch { tvStatus.text = "阶段 1 无存活 IP，跳过 TCP 测速" }
            return
        }
        tcpTotal = alive.size
        val queue = ConcurrentLinkedQueue(alive)
        val futures = (1..H3_CONCURRENCY).map {
            h3Pool.submit {
                while (running.get()) {
                    val ip = queue.poll() ?: break
                    tcpOne(ip)
                }
            }
        }
        futures.forEach { it.get() }
    }

    /** 单个 IP 的 TCP 测速。 */
    private fun tcpOne(ip: String) {
        val raw = runCatching { TcpProbe.test(ip, 2500L) }.getOrNull()
        val row = try {
            val j = raw?.let { JSONObject(it) }
            if (j != null && j.optBoolean("ok")) {
                ok.incrementAndGet()
                ResultRow(ip, j.optLong("http", -1), 0, 0, "", "TCP")
            } else {
                ResultRow(ip, -1, 0, 0, "TCP:${j?.optString("err") ?: "fail"}", "TCP")
            }
        } catch (_: Exception) {
            ResultRow(ip, -1, 0, 0, "TCP:parse-fail", "TCP")
        }
        val d = done.incrementAndGet()
        scope.launch {
            synchronized(results) {
                results.add(row)
                results.sortWith(compareBy<ResultRow> { it.ms < 0 }.thenBy { it.ms })
            }
            adapter.notifyDataSetChanged()
            tvStatus.text = "阶段 2/2：TCP 测速 $d/$tcpTotal（可用 ${ok.get()}）"
        }
    }

    /** 混合测法：先 H3，H3 失败的 IP 自动补一轮 TCP。 */
    private fun hybridTestAll(alive: List<String>) {
        if (alive.isEmpty()) {
            scope.launch { tvStatus.text = "阶段 1 无存活 IP" }
            return
        }
        val h3Fail = ConcurrentLinkedQueue<String>()
        h3Total = alive.size
        val q1 = ConcurrentLinkedQueue(alive)
        val f1 = (1..H3_CONCURRENCY).map {
            h3Pool.submit {
                while (running.get()) {
                    val ip = q1.poll() ?: break
                    testOne(ip) { h3Fail.add(it) }
                }
            }
        }
        f1.forEach { it.get() }
        if (!running.get()) return
        val tcpList = h3Fail.toList()
        if (tcpList.isEmpty()) {
            scope.launch { tvStatus.text = "H3 全部命中，无需 TCP 补测（可用 ${ok.get()}）" }
            return
        }
        scope.launch { tvStatus.text = "H3 完成：${tcpList.size} 个失败，补 TCP 测速…（可用 ${ok.get()}）" }
        tcpTestAll(tcpList)
    }

    private fun fetchOnlineIps() {
        scope.launch {
            tvStatus.text = "拉取在线 IP 列表…"
            val ips = IpList.fetchOnline()
            if (ips.isEmpty()) {
                tvStatus.text = "在线拉取失败（网络受限时可继续用内置 GWS 段扫描）"
                Toast.makeText(this@MainActivity, "拉取失败，可重试", Toast.LENGTH_SHORT).show()
            } else {
                synchronized(pending) {
                    pending.addAll(ips)
                }
                tvStatus.text = "已追加 ${ips.size} 个在线 IP（当前待测 ${pending.size} 个）"
                Toast.makeText(this@MainActivity, "已追加 ${ips.size} 个在线 IP", Toast.LENGTH_SHORT).show()
            }
            updateCount()
        }
    }

    /** 加载内置云厂商 CIDR（阿里/腾讯/火山/华为/百度/UCloud）→ 每段采样 1 个 IP → 替换待测队列。 */
    private fun loadChinaIps() {
        if (running.get()) {
            Toast.makeText(this, "先停止当前扫描", Toast.LENGTH_SHORT).show()
            return
        }
        val cidrs = IpList.loadCloudCidrs(this)
        if (cidrs.isEmpty()) {
            tvStatus.text = "内置云厂商 IP 段加载失败"
            Toast.makeText(this, "内置资源缺失", Toast.LENGTH_SHORT).show()
            return
        }
        scope.launch {
            tvStatus.text = "展开 ${cidrs.size} 个云厂商 IP 段…"
            val ips = withContext(Dispatchers.Default) {
                cidrs.flatMap { IpList.expandCidr(it, 1) }
            }
            synchronized(pending) {
                pending.clear()
                pending.addAll(ips)
            }
            tvStatus.text = "已加载云厂商段 ${cidrs.size} 个（采样 ${ips.size} 个 IP），点开始扫描"
            Toast.makeText(this@MainActivity, "云厂商段 ${cidrs.size} 个，采样 ${ips.size} 个 IP", Toast.LENGTH_LONG).show()
            updateCount()
        }
    }

    private fun addManualIps() {
        val ips = IpList.parseManual(etManual.text.toString())
        if (ips.isEmpty()) {
            Toast.makeText(this, "没有识别到合法 IP（支持 IPv4/IPv6，一行一个或逗号分隔）", Toast.LENGTH_SHORT).show()
            return
        }
        synchronized(pending) {
            pending.addAll(ips)
        }
        etManual.text.clear()
        tvStatus.text = "已添加 ${ips.size} 个 IP（当前待测 ${pending.size} 个）"
        updateCount()
    }

    /** 单 IP 调试：对输入框中的 IP 同时测 H3 与 TCP，显示两份完整 JSON（含握手诊断）。 */
    private fun testSingleIp() {
        val ip = etManual.text.toString().trim()
        if (ip.isEmpty() || !IpList.isValidIp(ip)) {
            Toast.makeText(this, "请输入单个合法 IP（IPv4/IPv6）", Toast.LENGTH_SHORT).show()
            return
        }
        tvStatus.text = "单测 $ip（H3 + TCP）…"
        scope.launch {
            val (h3, tcp) = withContext(Dispatchers.Default) {
                val a = runCatching { QuicNative.test(ip, HOST, PORT, PATH, 3000L, caBundlePath) }.getOrNull()
                val b = runCatching { TcpProbe.test(ip, 3000L) }.getOrNull()
                a to b
            }
            val out = "H3 : ${h3 ?: "native 无返回"}\nTCP: ${tcp ?: "fail"}"
            tvStatus.text = out
            Toast.makeText(this@MainActivity, out, Toast.LENGTH_LONG).show()
        }
    }

    private fun copyAllOk() {
        val lines = synchronized(results) { results.filter { it.ms >= 0 } }
            .sortedBy { it.ms }
            .map { it.ip }
        if (lines.isEmpty()) {
            Toast.makeText(this, "还没有可用 IP", Toast.LENGTH_SHORT).show()
            return
        }
        val cm = getSystemService(CLIPBOARD_SERVICE) as ClipboardManager
        cm.setPrimaryClip(ClipData.newPlainText("gt-ips", lines.joinToString("\n")))
        Toast.makeText(this, "已复制 ${lines.size} 个可用 IP", Toast.LENGTH_SHORT).show()
    }

    private fun updateCount() {
        val mode = if (quickMode) "快速" else "完整"
        tvCount.text = "待测 ${pending.size} 个 IP（GWS 段·$mode 模式）｜ 可用 ${ok.get()} 个"
    }

    class VH(v: View) : RecyclerView.ViewHolder(v) {
        val tvIp: TextView = v.findViewById(R.id.tvItemIp)
        val tvMs: TextView = v.findViewById(R.id.tvItemMs)
    }

    inner class ResultAdapter : RecyclerView.Adapter<VH>() {
        override fun onCreateViewHolder(parent: ViewGroup, viewType: Int): VH {
            val v = LayoutInflater.from(parent.context)
                .inflate(R.layout.item_result, parent, false)
            return VH(v)
        }

        override fun getItemCount(): Int = synchronized(results) { results.size }

        override fun onBindViewHolder(holder: VH, position: Int) {
            val r = synchronized(results) { results[position] }
            holder.tvIp.text = r.ip
            holder.tvMs.text = if (r.ms >= 0) "${r.proto} · ${r.ms} ms" else "✗ ${r.err}"
            holder.tvMs.setTextColor(
                if (r.ms >= 0) getColor(R.color.g_ok) else getColor(R.color.g_bad)
            )
            holder.itemView.setOnClickListener {
                if (r.ms >= 0) {
                    val cm = getSystemService(CLIPBOARD_SERVICE) as ClipboardManager
                    cm.setPrimaryClip(ClipData.newPlainText("gt-ip", r.ip))
                    Toast.makeText(this@MainActivity, "已复制 ${r.ip}", Toast.LENGTH_SHORT).show()
                }
            }
        }
    }
}
