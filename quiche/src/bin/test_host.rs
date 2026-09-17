// 独立 host 测试二进制：验证 quiche 客户端代码逻辑（与 Android JNI 版相同逻辑）
// 用法: test_host <ip> [host] [port] [timeout_ms]
use quiche::h3::NameValue;
use std::io;
use std::net::{SocketAddr, UdpSocket};
use std::time::{Duration, Instant};

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        eprintln!("usage: test_host <ip> [host] [port] [timeout_ms]");
        std::process::exit(1);
    }
    let ip = args[1].clone();
    let host = args.get(2).cloned().unwrap_or_else(|| "translate.googleapis.com".to_string());
    let port: u16 = args.get(3).and_then(|s| s.parse().ok()).unwrap_or(443);
    let timeout = Duration::from_millis(args.get(4).and_then(|s| s.parse().ok()).unwrap_or(3000));

    match test_one(&ip, &host, port, "/translate_a/element.js", timeout, "/etc/ssl/certs/ca-certificates.crt") {
        Ok((ms, status, bytes)) => println!("OK ms={} status={} bytes={}", ms, status, bytes),
        Err(e) => println!("FAIL {}", e),
    }
}

fn test_one(ip: &str, host: &str, port: u16, path: &str, timeout: Duration, ca_file: &str) -> Result<(u64, u16, usize), &'static str> {
    let start = Instant::now();
    let deadline = start + timeout;

    let ip_addr: std::net::IpAddr = ip.parse().map_err(|_| "bad-ip")?;
    let peer = SocketAddr::new(ip_addr, port);

    let socket = UdpSocket::bind(if peer.is_ipv4() { "0.0.0.0:0" } else { "[::]:0" })
        .map_err(|_| "bind")?;
    socket.connect(peer).map_err(|e| map_io_err(&e))?;
    socket.set_read_timeout(Some(Duration::from_millis(40))).map_err(|_| "cfg")?;
    socket.set_write_timeout(Some(Duration::from_millis(500))).map_err(|_| "cfg")?;
    let local = socket.local_addr().map_err(|_| "cfg")?;

    let mut config = quiche::Config::new(quiche::PROTOCOL_VERSION).map_err(|_| "cfg")?;
    config.set_application_protos(&[b"h3"]).map_err(|_| "cfg")?;
    config.verify_peer(true);
    config.set_max_idle_timeout(5_000);
    config.set_initial_max_data(10_000_000);
    config.set_initial_max_stream_data_bidi_local(1_000_000);
    config.set_initial_max_stream_data_bidi_remote(1_000_000);
    config.set_initial_max_stream_data_uni(1_000_000);
    config.set_initial_max_streams_bidi(100);
    config.set_initial_max_streams_uni(100);
    if !ca_file.is_empty() && config.load_verify_locations_from_file(ca_file).is_err() {
        eprintln!("[warn] ca load failed");
    }

    let h3_config = quiche::h3::Config::new().map_err(|_| "cfg")?;
    let scid_bytes = rand_scid();
    let scid = quiche::ConnectionId::from_ref(&scid_bytes);
    let dcid_bytes = rand_scid();
    let dcid = quiche::ConnectionId::from_ref(&dcid_bytes);
    let mut conn = quiche::connect_with_dcid(Some(host), &scid, &dcid, local, peer, &mut config).map_err(|_| "tls")?;

    let mut out = vec![0u8; 65535];
    let mut in_buf = vec![0u8; 65535];
    let mut h3_conn: Option<quiche::h3::Connection> = None;
    let mut stream_id: Option<u64> = None;
    let mut status: u16 = 0;
    let mut bytes: usize = 0;
    let mut request_sent = false;
    let mut sent_total = 0usize;

    loop {
        if Instant::now() > deadline {
            eprintln!("[debug] deadline hit: est={} sent={} recv_total={}", conn.is_established(), sent_total, conn.stats().recv);
            return Err("timeout");
        }

        loop {
            match conn.send(&mut out) {
                Ok((len, _)) if len > 0 => {
                    sent_total += len;
                    if socket.send(&out[..len]).is_err() { return Err("refused"); }
                }
                Ok(_) => break,
                Err(quiche::Error::Done) => break,
                Err(e) => return Err(map_quiche_err(&e)),
            }
        }

        if let Some(t) = conn.timeout() {
            if t <= Duration::from_millis(0) { conn.on_timeout(); }
        }

        loop {
            match socket.recv_from(&mut in_buf) {
                Ok((len, from)) => {
                    let info = quiche::RecvInfo { from, to: local };
                    match conn.recv(&mut in_buf[..len], info) {
                        Ok(_) => {}
                        Err(quiche::Error::Done) => {}
                        Err(e) => {
                            eprintln!("[debug] recv err: {:?}", e);
                            return Err(map_quiche_err(&e));
                        }
                    }
                }
                Err(e) if e.kind() == io::ErrorKind::WouldBlock || e.kind() == io::ErrorKind::TimedOut => break,
                Err(e) => return Err(map_io_err(&e)),
            }
            if Instant::now() > deadline { return Err("timeout"); }
        }

        if h3_conn.is_none() && conn.is_established() {
            eprintln!("[debug] QUIC established at {}ms", start.elapsed().as_millis());
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
                        Ok(id) => { stream_id = Some(id); request_sent = true; }
                        Err(e) => { eprintln!("[debug] send_request err {:?}", e); return Err(map_h3_err(&e)); }
                    }
                    h3_conn = Some(h3);
                }
                Err(e) => { eprintln!("[debug] with_transport err {:?}", e); return Err(map_h3_err(&e)); }
            }
        }

        if let Some(h3) = h3_conn.as_mut() {
            loop {
                match h3.poll(&mut conn) {
                    Ok((_, quiche::h3::Event::Headers { list, .. })) => {
                        for h in list.iter() {
                            if h.name() == b":status" {
                                if let Ok(s) = std::str::from_utf8(h.value()) {
                                    if let Ok(n) = s.trim().parse::<u16>() { status = n; }
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

        if request_sent {
            if status == 200 {
                return Ok((start.elapsed().as_millis() as u64, status, bytes));
            }
            if status != 0 { return Err("non200"); }
            if let Some(sid) = stream_id {
                if conn.stream_finished(sid) {
                    return if status == 200 { Ok((start.elapsed().as_millis() as u64, status, bytes)) }
                    else { Err(if status == 0 { "no-resp" } else { "non200" }) };
                }
            }
        }

        if conn.is_timed_out() || conn.is_closed() {
            return Err("timeout");
        }
    }
}

fn map_io_err(e: &io::Error) -> &'static str {
    match e.kind() {
        io::ErrorKind::ConnectionRefused | io::ErrorKind::ConnectionReset | io::ErrorKind::NotConnected => "refused",
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
    let t = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_nanos();
    let bytes = t.to_le_bytes();
    for (i, chunk) in b.chunks_mut(8).enumerate() {
        let src = bytes[i * 2 % bytes.len()..].iter().copied().take(8);
        for (dst, s) in chunk.iter_mut().zip(src) { *dst = s; }
    }
    b
}
