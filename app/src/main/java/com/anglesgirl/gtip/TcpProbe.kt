package com.anglesgirl.gtip

import java.io.BufferedReader
import java.io.InputStreamReader
import java.net.InetSocketAddress
import javax.net.ssl.SNIHostName
import javax.net.ssl.SSLSocket
import javax.net.ssl.SSLSocketFactory

/**
 * TCP 模式探测：TCP 443 连接 → TLS 握手（SNI + 证书主机名校验均用 translate.googleapis.com）
 * → HTTP/1.1 GET。与 H3 模式同一套"域名匹配"语义：IP 只是连接目标，域名身份贯穿全链路。
 *
 * 适用场景：国内云厂商段上只开 TCP/443（无 QUIC）的特殊 IP——H3 测不出来，但走
 * TCP+TLS 确实能联通 Google 翻译。endpointIdentificationAlgorithm="HTTPS" 保证证书链
 * 与主机名必须匹配 translate.googleapis.com，防止把任意 HTTPS 服务误判为可用。
 *
 * 返回 JSON：
 *   {"ok":true,"tcp":<ms>,"tls":<ms>,"http":<ms>,"status":"HTTP/1.1 200 OK","code":"200"}
 *   {"ok":false,"ms":<ms>,"err":"..."}
 */
object TcpProbe {
    const val HOST = "translate.googleapis.com"
    const val PORT = 443
    const val PATH = "/translate_a/element.js"

    fun test(ip: String, timeoutMs: Long = 2500L): String {
        val t0 = System.currentTimeMillis()
        var ssl: SSLSocket? = null
        return try {
            ssl = SSLSocketFactory.getDefault().createSocket() as SSLSocket
            // 1) TCP 连接（含超时，IP 直连）
            ssl.connect(InetSocketAddress(ip, PORT), timeoutMs.toInt())
            val tcpMs = System.currentTimeMillis() - t0
            // 2) TLS：SNI + 证书主机名校验（域名匹配；API 24+ 原生支持，minSdk 26 直接可用）
            val params = ssl.sslParameters
            params.serverNames = listOf(SNIHostName(HOST))
            params.endpointIdentificationAlgorithm = "HTTPS"
            ssl.sslParameters = params
            ssl.soTimeout = 2000
            ssl.startHandshake()
            val tlsMs = System.currentTimeMillis() - t0
            // 3) HTTP/1.1 请求（Google 边缘一般支持，足够判定"能联通"）
            val os = ssl.outputStream
            os.write(
                ("GET $PATH HTTP/1.1\r\n" +
                        "Host: $HOST\r\n" +
                        "Connection: close\r\n" +
                        "User-Agent: GTIP/1.0\r\n\r\n").toByteArray()
            )
            os.flush()
            val reader = BufferedReader(InputStreamReader(ssl.inputStream))
            val status = reader.readLine()
            val httpMs = System.currentTimeMillis() - t0
            val code = status?.substringAfter(' ')?.substringBefore(' ') ?: "-"
            "{\"ok\":true,\"tcp\":$tcpMs,\"tls\":$tlsMs,\"http\":$httpMs,\"status\":\"${status?.trim()}\",\"code\":\"$code\"}"
        } catch (e: Exception) {
            val ms = System.currentTimeMillis() - t0
            val msg = e.message?.replace("\"", "'") ?: e.javaClass.simpleName
            "{\"ok\":false,\"ms\":$ms,\"err\":\"${e.javaClass.simpleName}: $msg\"}"
        } finally {
            runCatching { ssl?.close() }
        }
    }
}
