use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::watch;

use xray_lite_rs::config::{
    parse_uuid, ClientConfig, HttpUpgradeSettings, InboundConfig, InboundSettings, PortSpec,
    StreamSettings, WsSettings, XhttpSettings, XrayConfig,
};
use xray_lite_rs::protocol::trojan_password_hash;
use xray_lite_rs::{run_server, HotReloadRegistry};

async fn spawn_tcp_echo_server() -> std::net::SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((mut s, _)) = listener.accept().await {
            tokio::spawn(async move {
                let mut buf = [0u8; 4096];
                loop {
                    match s.read(&mut buf).await {
                        Ok(0) | Err(_) => break,
                        Ok(n) => {
                            if s.write_all(&buf[..n]).await.is_err() {
                                break;
                            }
                        }
                    }
                }
            });
        }
    });
    addr
}

fn free_local_port() -> u16 {
    let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    l.local_addr().unwrap().port()
}

fn build_vless_tcp_request(uuid: &[u8; 16], target: std::net::SocketAddr) -> Vec<u8> {
    let mut out = Vec::new();
    out.push(0x00); // version
    out.extend_from_slice(uuid);
    out.push(0x00); // addons len
    out.push(0x01); // CMD_TCP
    out.extend_from_slice(&target.port().to_be_bytes());
    match target {
        std::net::SocketAddr::V4(v4) => {
            out.push(0x01);
            out.extend_from_slice(&v4.ip().octets());
        }
        std::net::SocketAddr::V6(v6) => {
            out.push(0x03);
            out.extend_from_slice(&v6.ip().octets());
        }
    }
    out
}

#[tokio::test]
async fn vless_over_httpupgrade_and_hot_reload() {
    let echo_addr = spawn_tcp_echo_server().await;
    let listen_port = free_local_port();
    let uuid_str = "b831381d-6324-4d53-ad4f-8cda48b30811";
    let uuid2_str = "11111111-2222-3333-4444-555555555555";

    let mut cfg = XrayConfig {
        log: None,
        inbounds: vec![InboundConfig {
            tag: "vless-hu".to_string(),
            listen: "127.0.0.1".to_string(),
            port: PortSpec::Num(listen_port),
            protocol: "vless".to_string(),
            settings: InboundSettings {
                clients: vec![ClientConfig {
                    id: uuid_str.to_string(),
                    password: String::new(),
                    email: "u1".to_string(),
                    flow: String::new(),
                    level: 0,
                }],
                decryption: Some("none".to_string()),
                fallbacks: vec![],
            },
            stream_settings: Some(StreamSettings {
                network: "httpupgrade".to_string(),
                security: "none".to_string(),
                httpupgrade_settings: Some(HttpUpgradeSettings {
                    accept_proxy_protocol: false,
                    path: "/hu".to_string(),
                    host: String::new(),
                    headers: Default::default(),
                }),
                ..Default::default()
            }),
        }],
        outbounds: vec![],
        // Allow localhost in test by providing empty routing rules (disables private-IP block).
        routing: Some(Default::default()),
        policy: None,
    };

    let registry = HotReloadRegistry::new();
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let srv_reg = registry.clone();
    let srv_cfg = cfg.clone();
    let srv = tokio::spawn(async move {
        let _ = run_server(srv_cfg, srv_reg, shutdown_rx).await;
    });

    tokio::time::sleep(std::time::Duration::from_millis(80)).await;

    // Connect with user 1 via HTTPUpgrade
    let mut s = TcpStream::connect(("127.0.0.1", listen_port)).await.unwrap();
    let req = "GET /hu HTTP/1.1\r\nHost: example.com\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n";
    s.write_all(req.as_bytes()).await.unwrap();

    let mut resp_buf = [0u8; 256];
    let n = s.read(&mut resp_buf).await.unwrap();
    assert!(std::str::from_utf8(&resp_buf[..n]).unwrap().contains("101 Switching Protocols"));

    let mut vless_req = build_vless_tcp_request(&parse_uuid(uuid_str).unwrap(), echo_addr);
    vless_req.extend_from_slice(b"hello-httpupgrade");
    s.write_all(&vless_req).await.unwrap();

    let mut vless_resp = [0u8; 2];
    s.read_exact(&mut vless_resp).await.unwrap();
    assert_eq!(vless_resp, [0x00, 0x00]);

    let mut echo = [0u8; 17];
    s.read_exact(&mut echo).await.unwrap();
    assert_eq!(&echo, b"hello-httpupgrade");

    // Hot-reload: add user 2 without closing connection `s`
    cfg.inbounds[0].settings.clients.push(ClientConfig {
        id: uuid2_str.to_string(),
        password: String::new(),
        email: "u2".to_string(),
        flow: String::new(),
        level: 0,
    });
    assert_eq!(registry.apply_config(&cfg), 2);

    // Existing connection `s` still works after hot-reload!
    s.write_all(b"still-alive").await.unwrap();
    let mut echo2 = [0u8; 11];
    s.read_exact(&mut echo2).await.unwrap();
    assert_eq!(&echo2, b"still-alive");

    // New user 2 can now connect!
    let mut s2 = TcpStream::connect(("127.0.0.1", listen_port)).await.unwrap();
    s2.write_all(req.as_bytes()).await.unwrap();
    let _ = s2.read(&mut resp_buf).await.unwrap();
    let mut vless_req2 = build_vless_tcp_request(&parse_uuid(uuid2_str).unwrap(), echo_addr);
    vless_req2.extend_from_slice(b"user2-ok");
    s2.write_all(&vless_req2).await.unwrap();
    s2.read_exact(&mut vless_resp).await.unwrap();
    let mut echo3 = [0u8; 8];
    s2.read_exact(&mut echo3).await.unwrap();
    assert_eq!(&echo3, b"user2-ok");

    let _ = shutdown_tx.send(true);
    drop(s);
    drop(s2);
    srv.await.unwrap();
}

#[tokio::test]
async fn trojan_tcp_and_ws_handshake() {
    let echo_addr = spawn_tcp_echo_server().await;
    let trojan_port = free_local_port();
    let ws_port = free_local_port();
    let pass = "super-secret-trojan";
    let uuid_str = "b831381d-6324-4d53-ad4f-8cda48b30811";

    let cfg = XrayConfig {
        log: None,
        inbounds: vec![
            InboundConfig {
                tag: "trojan-tcp".to_string(),
                listen: "127.0.0.1".to_string(),
                port: PortSpec::Num(trojan_port),
                protocol: "trojan".to_string(),
                settings: InboundSettings {
                    clients: vec![ClientConfig {
                        id: String::new(),
                        password: pass.to_string(),
                        email: "t1".to_string(),
                        flow: String::new(),
                        level: 0,
                    }],
                    decryption: None,
                    fallbacks: vec![],
                },
                stream_settings: None,
            },
            InboundConfig {
                tag: "vless-ws".to_string(),
                listen: "127.0.0.1".to_string(),
                port: PortSpec::Num(ws_port),
                protocol: "vless".to_string(),
                settings: InboundSettings {
                    clients: vec![ClientConfig {
                        id: uuid_str.to_string(),
                        password: String::new(),
                        email: "w1".to_string(),
                        flow: String::new(),
                        level: 0,
                    }],
                    decryption: None,
                    fallbacks: vec![],
                },
                stream_settings: Some(StreamSettings {
                    network: "ws".to_string(),
                    security: "none".to_string(),
                    ws_settings: Some(WsSettings {
                        accept_proxy_protocol: false,
                        path: "/ws".to_string(),
                        host: String::new(),
                        headers: Default::default(),
                    }),
                    ..Default::default()
                }),
            },
        ],
        outbounds: vec![],
        routing: Some(Default::default()),
        policy: None,
    };

    let registry = HotReloadRegistry::new();
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let srv = tokio::spawn(async move {
        let _ = run_server(cfg, registry, shutdown_rx).await;
    });

    tokio::time::sleep(std::time::Duration::from_millis(80)).await;

    // 1. Test Trojan TCP end-to-end
    let mut ts = TcpStream::connect(("127.0.0.1", trojan_port)).await.unwrap();
    let mut tr_req = Vec::new();
    tr_req.extend_from_slice(&trojan_password_hash(pass));
    tr_req.extend_from_slice(b"\r\n");
    tr_req.push(0x01); // CMD_TCP
    tr_req.push(0x01); // IPv4
    if let std::net::SocketAddr::V4(v4) = echo_addr {
        tr_req.extend_from_slice(&v4.ip().octets());
        tr_req.extend_from_slice(&v4.port().to_be_bytes());
    }
    tr_req.extend_from_slice(b"\r\n");
    tr_req.extend_from_slice(b"hello-trojan");
    ts.write_all(&tr_req).await.unwrap();

    let mut tr_echo = [0u8; 12];
    ts.read_exact(&mut tr_echo).await.unwrap();
    assert_eq!(&tr_echo, b"hello-trojan");

    // 2. Test WebSocket upgrade handshake
    let mut ws = TcpStream::connect(("127.0.0.1", ws_port)).await.unwrap();
    let ws_req = "GET /ws?ed=2048 HTTP/1.1\r\nHost: example.com\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n";
    ws.write_all(ws_req.as_bytes()).await.unwrap();
    let mut resp = [0u8; 256];
    let n = ws.read(&mut resp).await.unwrap();
    let resp_str = std::str::from_utf8(&resp[..n]).unwrap();
    assert!(resp_str.contains("101 Switching Protocols"));
    assert!(resp_str.contains("s3pPLMBiTxaQ9kYGzzhZRbK+xOo="));

    let _ = Arc::new(shutdown_tx).send(true);
    drop(ts);
    drop(ws);
    srv.await.unwrap();
}


#[tokio::test]
async fn vless_over_xhttp_packet_up_and_stream_down() {
    let echo_addr = spawn_tcp_echo_server().await;
    let xhttp_port = free_local_port();
    let uuid = "b831381d-6324-4d53-ad4f-8cda48b30811";

    let cfg = XrayConfig {
        log: None,
        inbounds: vec![InboundConfig {
            tag: "vless-xhttp".to_string(),
            listen: "127.0.0.1".to_string(),
            port: PortSpec::Num(xhttp_port),
            protocol: "vless".to_string(),
            settings: InboundSettings {
                clients: vec![ClientConfig {
                    id: uuid.to_string(),
                    password: String::new(),
                    email: "xhttp-user".to_string(),
                    flow: String::new(),
                    level: 0,
                }],
                decryption: Some("none".to_string()),
                fallbacks: vec![],
            },
            stream_settings: Some(StreamSettings {
                network: "xhttp".to_string(),
                security: "none".to_string(),
                xhttp_settings: Some(XhttpSettings {
                    path: "/xhttp".to_string(),
                    mode: "auto".to_string(),
                    ..Default::default()
                }),
                ..Default::default()
            }),
        }],
        outbounds: vec![],
        routing: Some(Default::default()),
        policy: None,
    };

    let registry = HotReloadRegistry::new();
    let (tx, rx) = watch::channel(false);
    let srv = tokio::spawn(run_server(cfg, registry, rx));
    tokio::time::sleep(Duration::from_millis(80)).await;

    // 1. Open GET /xhttp/sess1 (stream-down)
    let mut down = TcpStream::connect(("127.0.0.1", xhttp_port)).await.unwrap();
    down.write_all(b"GET /xhttp/sess1 HTTP/1.1\r\nHost: localhost\r\n\r\n")
        .await
        .unwrap();

    // Read HTTP/1.1 200 OK headers
    let mut hdr_buf = Vec::new();
    let mut b = [0u8; 1];
    while !hdr_buf.ends_with(b"\r\n\r\n") {
        down.read_exact(&mut b).await.unwrap();
        hdr_buf.push(b[0]);
    }
    let hdr_str = String::from_utf8_lossy(&hdr_buf);
    assert!(hdr_str.starts_with("HTTP/1.1 200 OK"));
    assert!(hdr_str.contains("X-Accel-Buffering: no"));

    // 2. Send VLESS header + payload via POST /xhttp/sess1/0 (packet-up)
    let uuid_bytes = xray_lite_rs::config::parse_uuid(uuid).unwrap();
    let mut vless_pkt = build_vless_tcp_request(&uuid_bytes, echo_addr);
    vless_pkt.extend_from_slice(b"hello-xhttp");

    let mut up = TcpStream::connect(("127.0.0.1", xhttp_port)).await.unwrap();
    let post_req = format!(
        "POST /xhttp/sess1/0 HTTP/1.1\r\nHost: localhost\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        vless_pkt.len()
    );
    up.write_all(post_req.as_bytes()).await.unwrap();
    up.write_all(&vless_pkt).await.unwrap();

    let mut post_resp = String::new();
    up.read_to_string(&mut post_resp).await.unwrap();
    assert!(post_resp.starts_with("HTTP/1.1 200 OK"));

    // 3. Read chunked HTTP/1.1 response carrying VLESS response [0x00, 0x00] + "hello-xhttp"
    let mut collected = Vec::new();
    let mut tmp = [0u8; 256];
    while collected.windows(11).position(|w| w == b"hello-xhttp").is_none() {
        let n = tokio::time::timeout(Duration::from_secs(3), down.read(&mut tmp))
            .await
            .unwrap()
            .unwrap();
        assert!(n > 0);
        collected.extend_from_slice(&tmp[..n]);
    }
    assert!(collected.windows(11).any(|w| w == b"hello-xhttp"));

    let _ = tx.send(true);
    let _ = srv.await;
}


#[tokio::test]
async fn vless_xudp_mux_udp_echo() {
    let udp_echo = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let echo_addr = udp_echo.local_addr().unwrap();
    tokio::spawn(async move {
        let mut buf = [0u8; 2048];
        while let Ok((n, src)) = udp_echo.recv_from(&mut buf).await {
            let _ = udp_echo.send_to(&buf[..n], src).await;
        }
    });

    let port = free_local_port();
    let uuid = "b831381d-6324-4d53-ad4f-8cda48b30811";
    let uuid_bytes = parse_uuid(uuid).unwrap();

    let cfg = XrayConfig {
        log: None,
        inbounds: vec![InboundConfig {
            tag: "vless-xudp".to_string(),
            listen: "127.0.0.1".to_string(),
            port: PortSpec::Num(port),
            protocol: "vless".to_string(),
            settings: InboundSettings {
                clients: vec![ClientConfig {
                    id: uuid.to_string(),
                    password: String::new(),
                    email: "gamer".to_string(),
                    flow: String::new(),
                    level: 0,
                }],
                decryption: Some("none".to_string()),
                fallbacks: vec![],
            },
            stream_settings: None,
        }],
        outbounds: vec![],
        routing: Some(Default::default()),
        policy: None,
    };

    let registry = HotReloadRegistry::new();
    let (tx, rx) = watch::channel(false);
    let srv = tokio::spawn(run_server(cfg, registry, rx));
    tokio::time::sleep(Duration::from_millis(80)).await;

    let mut conn = TcpStream::connect(("127.0.0.1", port)).await.unwrap();

    // VLESS header with CMD_MUX (0x03) and NO target address (exact Xray-core XUDP format)
    let mut hdr = Vec::with_capacity(19);
    hdr.push(0x00); // version 0
    hdr.extend_from_slice(&uuid_bytes);
    hdr.push(0x00); // addons len 0
    hdr.push(0x03); // CMD_MUX
    conn.write_all(&hdr).await.unwrap();

    // XUDP STATUS_NEW frame (sid=0, status=1, opt=1, net=2 UDP, PortThenAddr, 8B GlobalID) + payload
    let mut meta = Vec::new();
    meta.extend_from_slice(&0u16.to_be_bytes());
    meta.push(0x01); // New
    meta.push(0x01); // OptionData
    meta.push(0x02); // UDP
    meta.extend_from_slice(&echo_addr.port().to_be_bytes());
    meta.push(0x01); // IPv4
    meta.extend_from_slice(&[127, 0, 0, 1]);
    meta.extend_from_slice(&[1, 2, 3, 4, 5, 6, 7, 8]); // GlobalID

    let mut frame = Vec::new();
    frame.extend_from_slice(&(meta.len() as u16).to_be_bytes());
    frame.extend_from_slice(&meta);
    frame.extend_from_slice(&9u16.to_be_bytes());
    frame.extend_from_slice(b"game-pkt1");
    conn.write_all(&frame).await.unwrap();

    // Read VLESS response header [0x00, 0x00]
    let mut vless_resp = [0u8; 2];
    tokio::time::timeout(Duration::from_secs(3), conn.read_exact(&mut vless_resp))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(vless_resp, [0x00, 0x00]);

    // Read XUDP response frame carrying source address + echoed payload
    let resp_frame = tokio::time::timeout(
        Duration::from_secs(3),
        xray_lite_rs::protocol::mux::read_mux_frame(&mut conn),
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(resp_frame.session_id, 0);
    assert_eq!(resp_frame.status, 0x02); // Keep
    assert_eq!(resp_frame.network, 0x02); // UDP
    assert_eq!(resp_frame.payload, b"game-pkt1");

    let _ = tx.send(true);
    let _ = srv.await;
}
