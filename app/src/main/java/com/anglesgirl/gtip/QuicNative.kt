package com.anglesgirl.gtip

import org.json.JSONObject

/**
 * 与 Rust（quiche HTTP/3）JNI 桥接。
 */
object QuicNative {

    init {
        System.loadLibrary("gtip_quic")
    }

    /**
     * HTTP/3 测速（域名匹配）：UDP 连接候选 IP，QUIC SNI/证书/HTTP3 :authority 全部用
     * translate.googleapis.com，完成握手且拿到 200 才算可用。
     *
     * @param caBundle Android 系统信任库导出的 CA PEM bundle 路径（缓存文件）
     * @return JSON {"ok":true,"ms":..,"status":..,"bytes":..} 或 {"ok":false,"err":".."}
     */
    external fun test(
        ip: String,
        host: String,
        port: Int,
        path: String,
        timeoutMs: Long,
        caBundle: String
    ): String

    /**
     * TCP 快速连通性（ping 替代）：能连上目标 IP:port 即认为主机"活着"。
     * @return JSON {"ok":true,"ms":..} 或 {"ok":false,"err":".."}
     */
    external fun tcpPing(ip: String, port: Int, timeoutMs: Long): String

    /** 解析 native 返回 JSON 的便捷封装。 */
    fun parseResult(raw: String?): Pair<Boolean, String> {
        return try {
            val j = raw?.let { JSONObject(it) }
            if (j != null && j.optBoolean("ok")) {
                true to "ok"
            } else {
                false to (j?.optString("err") ?: "native-fail")
            }
        } catch (_: Exception) {
            false to "parse-fail"
        }
    }
}
