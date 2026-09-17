use jni::objects::{JClass, JString};
use jni::sys::{jint, jlong, jstring};
use jni::JNIEnv;
use quiche::h3::NameValue;
use serde_json::json;
use std::io;
use std::net::{SocketAddr, TcpStream, UdpSocket};
use std::time::{Duration, Instant};

/// 对单个候选 IP 执行 HTTP/3（QUIC）测速：
/// - UDP 连接目标 = 候选 IP（"指定扫描的 IP"）
/// - QUIC SNI / TLS 证书校验 / HTTP/3 :authority = translate.googleapis.com（"用谷歌翻译的域名"）
///   等价于：把该域名解析固定到候选 IP 后，用标准 HTTP/3 访问 translate.googleapis.com
/// - 能完成 QUIC 握手 + 证书域名匹配 + HTTP/3 GET 200 => 可用
///
/// ca_bundle: Android 系统信任库导出的 CA PEM bundle 文件路径（Kotlin 侧用
/// TrustManagerFactory 生成到 cacheDir），保证证书链校验可用。
/// 返回 JSON：{"ok":true,"ms":..,"status":..,"bytes":..} 或 {"ok":false,"err":"timeout|refused|tls|ca|other"}
#[no_mangle]
pub extern "system" fn Java_com_anglesgirl_gtip_QuicNative_test(
    mut env: JNIEnv,
    _class: JClass,
    ip: JString,
    host: JString,
    port: jint,
    path: JString,
    timeout_ms: jlong,
    ca_bundle: JString,
) -> jstring {
    let ip: String = env
        .get_string(&ip)
        .map(|s| s.into())
        .unwrap_or_default();
    let host: String = env
        .get_string(&host)
        .map(|s| s.into())
        .unwrap_or_default();
    let path: String = env
        .get_string(&path)
        .map(|s| s.into())
        .unwrap_or_default();
    let ca: String = env
        .get_string(&ca_bundle)
        .map(|s| s.into())
        .unwrap_or_default();
    let timeout = Duration::from_millis(timeout_ms.max(200) as u64);

    let mut db = Db::default();
    let result = match test_one(&ip, &host, port as u16, &path, timeout, &ca, &mut db) {
        Ok((ms, status, bytes)) => json!({
            "ok": true, "ms": ms, "status": status, "bytes": bytes,
            "dbg": {"est": db.est, "sent": db.sent, "recv": db.recv, "closed": db.closed, "peer_err": db.peer_err, "stat": db.stat}
        }),
        Err(e) => json!({
            "ok": false, "err": e,
            "dbg": {"est": db.est, "sent": db.sent, "recv": db.recv, "closed": db.closed, "peer_err": db.peer_err, "stat": db.stat}
        }),
    };
    let out = result.to_string();
    let out = env.new_string(out).expect("new_string");
    out.into_raw()
}

/// TCP 快速连通性测试（ping 替代）：connect 目标 IP:443，能连上即"活着"。
/// 返回 JSON：{"ok":true,"ms":..} 或 {"ok":false,"err":"timeout|refused|other"}
#[no_mangle]
pub extern "system" fn Java_com_anglesgirl_gtip_QuicNative_tcpPing(
    mut env: JNIEnv,
    _class: JClass,
    ip: JString,
    port: jint,
    timeout_ms: jlong,
) -> jstring {
    let ip: String = env
        .get_string(&ip)
        .map(|s| s.into())
        .unwrap_or_default();
    let timeout = Duration::from_millis(timeout_ms.max(100) as u64);

    let result = match tcp_ping(&ip, port as u16, timeout) {
        Ok(ms) => json!({"ok": true, "ms": ms}),
        Err(e) => json!({"ok": false, "err": e}),
    };
    let out = result.to_string();
    let out = env.new_string(out).expect("new_string");
    out.into_raw()
}

fn tcp_ping(ip: &str, port: u16, timeout: Duration) -> Result<u64, &'static str> {
    let start = Instant::now();
    let ip_addr: std::net::IpAddr = ip.parse().map_err(|_| "bad-ip")?;
    let peer = SocketAddr::new(ip_addr, port);
    let stream = TcpStream::connect_timeout(&peer, timeout).map_err(|e| map_io_err(&e))?;
    let _ = stream.set_nodelay(true);
    Ok(start.elapsed().as_millis() as u64)
}

type TestResult = Result<(u64, u16, usize), &'static str>;

/// 诊断信息（随 JSON 返回，用于定位握手失败原因）。
#[derive(Default)]
struct Db {
    est: bool,
    sent: usize,
    recv: usize,
    closed: bool,
    peer_err: Option<u64>,
    stat: String,
}

fn test_one(ip: &str, host: &str, port: u16, path: &str, timeout: Duration, ca_bundle: &str, db: &mut Db) -> TestResult {
    let start = Instant::now();
    let deadline = start + timeout;

    let ip_addr: std::net::IpAddr = ip.parse().map_err(|_| "bad-ip")?;
    let peer = SocketAddr::new(ip_addr, port);

    let socket = UdpSocket::bind(if peer.is_ipv4() { "0.0.0.0:0" } else { "[::]:0" })
        .map_err(|_| "bind")?;
    socket.connect(peer).map_err(|e| map_io_err(&e))?;
    socket
        .set_read_timeout(Some(Duration::from_millis(40)))
        .map_err(|_| "cfg")?;
    socket
        .set_write_timeout(Some(Duration::from_millis(500)))
        .map_err(|_| "cfg")?;
    let local = socket.local_addr().map_err(|_| "cfg")?;

    let mut config = quiche::Config::new(quiche::PROTOCOL_VERSION).map_err(|_| "cfg")?;
    // 注意：set_application_protos 传"裸协议名"（内部自动编码成 wire 格式），
    // 不能带长度前缀——之前传 b"\x03h3" 被当成协议名 "\x03h3" 编码，
    // 服务器解析不出 "h3" → alert 120 no_application_protocol。
    // （若用 wire 格式则应调用 set_application_protos_wire_format(b"\x03h3")）
    config
        .set_application_protos(&[b"h3"])
        .map_err(|_| "cfg")?;
    config.verify_peer(true);
    // 关键：quiche 默认 transport parameters 全为 0（initial_max_data /
    // initial_max_streams_bidi / initial_max_stream_data_* 都是 0）。
    // Google 服务器会以 PROTOCOL_VIOLATION 拒绝"流参数全 0"的客户端
    // （等于声明自己无法接收任何流，HTTP/3 无法工作）。必须设置实际数值，
    // 与 Chrome/quiche 官方 http3-client 示例一致。
    config.set_initial_max_data(10_000_000);
    config.set_initial_max_stream_data_bidi_local(1_000_000);
    config.set_initial_max_stream_data_bidi_remote(1_000_000);
    config.set_initial_max_stream_data_uni(1_000_000);
    config.set_initial_max_streams_bidi(100);
    config.set_initial_max_streams_uni(100);
    config.set_max_idle_timeout(5_000);
    // 证书链校验：优先用 Kotlin 导出的系统 CA bundle（最可靠），
    // 失败时回退 Android 系统 CA 目录（部分 ROM 可用）。
    if ca_bundle.is_empty() || config.load_verify_locations_from_file(ca_bundle).is_err() {
        let dir_ok = config
            .load_verify_locations_from_directory("/system/etc/security/cacerts")
            .is_ok()
            || config
                .load_verify_locations_from_directory("/apex/com.android.conscrypt/cacerts")
                .is_ok();
        if !dir_ok {
            return Err("ca");
        }
    }

    let h3_config = quiche::h3::Config::new().map_err(|_| "cfg")?;

    let scid_bytes = rand_scid();
    let scid = quiche::ConnectionId::from_ref(&scid_bytes);
    // 关键：不能直接用 quiche::connect()——它内部 Connection::new(..., None, ...)
    // 导致客户端 Initial 包的 DCID 为空（0 字节）。标准 QUIC 客户端（Chrome/curl）
    // 都用 8~20 字节随机 DCID；Google 服务器会直接丢弃空 DCID 的 Initial 包，
    // 表现为"永远收不到任何响应 → timeout"，而 Chrome 却能正常 H3 连接。
    // 这里用本地 vendor 的 quiche 扩展 connect_with_dcid 显式带随机 DCID，
    // set_host_name 仍由该函数内部调用（保持 SNI+证书域名校验语义）。
    let dcid_bytes = rand_scid();
    let dcid = quiche::ConnectionId::from_ref(&dcid_bytes);
    let mut conn = quiche::connect_with_dcid(Some(host), &scid, &dcid, local, peer, &mut config)
        .map_err(|_| "tls")?;

    let mut out = vec![0u8; 65535];
    let mut in_buf = vec![0u8; 65535];
    let mut h3_conn: Option<quiche::h3::Connection> = None;
    let mut stream_id: Option<u64> = None;
    let mut status: u16 = 0;
    let mut bytes: usize = 0;
    let mut request_sent = false;

    loop {
        if Instant::now() > deadline {
            fill_db(&conn, db, status, bytes);
            return Err("timeout");
        }

        // 1) 发送所有待发数据
        loop {
            match conn.send(&mut out) {
                Ok((len, _)) if len > 0 => {
                    db.sent += len;
                    if socket.send(&out[..len]).is_err() {
                        fill_db(&conn, db, status, bytes);
                        return Err("refused");
                    }
                }
                Ok(_) => break,
                Err(quiche::Error::Done) => break,
                Err(e) => {
                    fill_db(&conn, db, status, bytes);
                    return Err(map_quiche_err(&e));
                }
            }
        }

        // 2) 驱动重传/保活定时器
        if let Some(t) = conn.timeout() {
            if t <= Duration::from_millis(0) {
                conn.on_timeout();
            }
        }

        // 3) 读取 UDP 数据交给 QUIC
        loop {
            match socket.recv_from(&mut in_buf) {
                Ok((len, from)) => {
                    db.recv += len;
                    let info = quiche::RecvInfo { from, to: local };
                    match conn.recv(&mut in_buf[..len], info) {
                        Ok(_) => {}
                        Err(quiche::Error::Done) => {}
                        Err(e) => {
                            fill_db(&conn, db, status, bytes);
                            return Err(map_quiche_err(&e));
                        }
                    }
                }
                Err(e)
                    if e.kind() == io::ErrorKind::WouldBlock
                        || e.kind() == io::ErrorKind::TimedOut =>
                {
                    break;
                }
                Err(e) => {
                    fill_db(&conn, db, status, bytes);
                    return Err(map_io_err(&e));
                }
            }
            if Instant::now() > deadline {
                fill_db(&conn, db, status, bytes);
                return Err("timeout");
            }
        }

        // 4) 握手完成后建立 HTTP/3 并发起请求
        if h3_conn.is_none() && conn.is_established() {
            db.est = true;
            match quiche::h3::Connection::with_transport(&mut conn, &h3_config) {
                Ok(mut h3) => {
                    let headers = [
                        quiche::h3::Header::new(b":method", b"GET"),
                        quiche::h3::Header::new(b":scheme", b"https"),
                        quiche::h3::Header::new(b":authority", host.as_bytes()),
                        quiche::h3::Header::new(b":path", path.as_bytes()),
                        quiche::h3::Header::new(b"user-agent", b"gtip/0.1"),
                        quiche::h3::Header::new(b"accept", b"*/*"),
                    ];
                    match h3.send_request(&mut conn, &headers, true) {
                        Ok(id) => {
                            stream_id = Some(id);
                            request_sent = true;
                        }
                        Err(e) => {
                            fill_db(&conn, db, status, bytes);
                            return Err(map_h3_err(&e));
                        }
                    }
                    h3_conn = Some(h3);
                }
                Err(e) => {
                    fill_db(&conn, db, status, bytes);
                    return Err(map_h3_err(&e));
                }
            }
        }

        // 5) 处理 HTTP/3 事件
        if let Some(h3) = h3_conn.as_mut() {
            loop {
                match h3.poll(&mut conn) {
                    Ok((_, quiche::h3::Event::Headers { list, .. })) => {
                        for h in list.iter() {
                            if h.name() == b":status" {
                                if let Ok(s) = std::str::from_utf8(h.value()) {
                                    if let Ok(n) = s.trim().parse::<u16>() {
                                        status = n;
                                    }
                                }
                            }
                        }
                    }
                    Ok((_, quiche::h3::Event::Data)) => {
                        if let Some(sid) = stream_id {
                            let mut b = [0u8; 4096];
                            loop {
                                match h3.recv_body(&mut conn, sid, &mut b) {
                                    Ok(n) => bytes += n,
                                    Err(quiche::h3::Error::Done) => break,
                                    Err(_) => break,
                                }
                            }
                        }
                    }
                    Ok((_, quiche::h3::Event::Finished)) => break,
                    Ok((_, quiche::h3::Event::Reset(_))) => return Err("reset"),
                    Ok((_, quiche::h3::Event::GoAway)) => break,
                    Ok((_, quiche::h3::Event::PriorityUpdate { .. })) => {}
                    Err(quiche::h3::Error::Done) => break,
                    Err(e) => return Err(map_h3_err(&e)),
                }
            }
        }

        // 6) 收尾判定
        if request_sent {
            if status == 200 {
                let _ = drain_once(&mut conn, &socket, &mut in_buf, local);
                fill_db(&conn, db, status, bytes);
                return Ok((start.elapsed().as_millis() as u64, status, bytes));
            }
            if status != 0 {
                fill_db(&conn, db, status, bytes);
                return Err("non200");
            }
            if let Some(sid) = stream_id {
                if conn.stream_finished(sid) {
                    fill_db(&conn, db, status, bytes);
                    return if status == 200 {
                        Ok((start.elapsed().as_millis() as u64, status, bytes))
                    } else {
                        Err(if status == 0 { "no-resp" } else { "non200" })
                    };
                }
            }
        }

        if conn.is_timed_out() || conn.is_closed() {
            fill_db(&conn, db, status, bytes);
            return Err("timeout");
        }
    }
}

fn fill_db(conn: &quiche::Connection, db: &mut Db, status: u16, bytes: usize) {
    db.est = conn.is_established();
    db.closed = conn.is_closed();
    if let Some(e) = conn.peer_error() {
        db.peer_err = Some(e.error_code);
        let reason = String::from_utf8_lossy(&e.reason);
        db.stat = format!("peer_close code={} reason={:?}", e.error_code, reason);
    } else {
        let s = conn.stats();
        db.stat = format!(
            "st={} sent={} recv={} lost={}{}",
            status,
            s.sent,
            s.recv,
            s.lost,
            if bytes > 0 { format!(" body={}", bytes) } else { String::new() }
        );
    }
}

/// 收尾时再尝试读一次，避免漏掉最后的响应数据。
fn drain_once(
    conn: &mut quiche::Connection,
    socket: &UdpSocket,
    buf: &mut [u8],
    local: SocketAddr,
) {
    if let Ok((len, from)) = socket.recv_from(buf) {
        let info = quiche::RecvInfo { from, to: local };
        let _ = conn.recv(&mut buf[..len], info);
    }
}

fn map_io_err(e: &io::Error) -> &'static str {
    match e.kind() {
        io::ErrorKind::ConnectionRefused
        | io::ErrorKind::ConnectionReset
        | io::ErrorKind::NotConnected => "refused",
        io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock => "timeout",
        _ => "other",
    }
}

fn map_quiche_err(e: &quiche::Error) -> &'static str {
    match e {
        quiche::Error::Done => "timeout",
        quiche::Error::InvalidState => "invalid",
        quiche::Error::CryptoFail | quiche::Error::TlsFail => "tls",
        quiche::Error::FinalSize | quiche::Error::StreamReset(_) => "reset",
        _ => "other",
    }
}

fn map_h3_err(e: &quiche::h3::Error) -> &'static str {
    match e {
        quiche::h3::Error::Done => "timeout",
        quiche::h3::Error::InternalError => "other",
        quiche::h3::Error::StreamCreationError => "other",
        quiche::h3::Error::MissingSettings => "tls",
        quiche::h3::Error::IdError => "other",
        quiche::h3::Error::ExcessiveLoad => "other",
        _ => "other",
    }
}

fn rand_scid() -> [u8; 16] {
    let mut b = [0u8; 16];
    let t = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let bytes = t.to_le_bytes();
    for (i, chunk) in b.chunks_mut(8).enumerate() {
        let src = bytes[i * 2 % bytes.len()..].iter().copied().take(8);
        for (dst, s) in chunk.iter_mut().zip(src) {
            *dst = s;
        }
    }
    b
}
