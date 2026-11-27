use std::net::SocketAddr;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::watch;

use ws_rs::config::ListenRule;
use ws_rs::proxy::{run_server, single_rule_config};

async fn spawn_ssh_like_echo() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((mut s, _)) = listener.accept().await {
            tokio::spawn(async move {
                let _ = s.write_all(b"SSH-2.0-Dropbear_Test\r\n").await;
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

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

#[tokio::test]
async fn http_upgrade_with_key_and_early_data_and_raw_passthrough() {
    let target = spawn_ssh_like_echo().await;
    let listen_port = free_port();

    let cfg = single_rule_config(ListenRule {
        listen_host: "127.0.0.1".to_string(),
        listen_port,
        target_host: "127.0.0.1".to_string(),
        target_port: target.port(),
    });

    let (tx, rx) = watch::channel(false);
    let srv = tokio::spawn(run_server(cfg, rx));
    tokio::time::sleep(Duration::from_millis(60)).await;

    // 1. Standard Nginx / WebSocket upgrade with Sec-WebSocket-Key + early data
    let mut s = TcpStream::connect(("127.0.0.1", listen_port)).await.unwrap();
    let req = "GET /newbiestoressh HTTP/1.1\r\n\
               Host: example.com\r\n\
               Upgrade: websocket\r\n\
               Connection: upgrade\r\n\
               Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n\
               EARLY_SSH_DATA";
    s.write_all(req.as_bytes()).await.unwrap();

    let mut collected = Vec::new();
    let mut tmp = [0u8; 512];
    while !collected
        .windows(14)
        .any(|w| w == b"EARLY_SSH_DATA")
    {
        let n = tokio::time::timeout(Duration::from_secs(2), s.read(&mut tmp))
            .await
            .unwrap()
            .unwrap();
        assert!(n > 0);
        collected.extend_from_slice(&tmp[..n]);
    }
    let text = String::from_utf8_lossy(&collected);
    assert!(text.starts_with("HTTP/1.1 101 Switching Protocols\r\n"));
    assert!(text.contains("Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo="));
    assert!(text.contains("SSH-2.0-Dropbear_Test\r\n"));
    assert!(text.contains("EARLY_SSH_DATA"));
    drop(s);

    // 2. Raw non-HTTP TCP passthrough
    let mut raw = TcpStream::connect(("127.0.0.1", listen_port)).await.unwrap();
    raw.write_all(b"SSH-2.0-Client\r\n").await.unwrap();
    let mut raw_buf = Vec::new();
    while !raw_buf.windows(16).any(|w| w == b"SSH-2.0-Client\r\n") {
        let n = tokio::time::timeout(Duration::from_secs(2), raw.read(&mut tmp))
            .await
            .unwrap()
            .unwrap();
        assert!(n > 0);
        raw_buf.extend_from_slice(&tmp[..n]);
    }
    let raw_text = String::from_utf8_lossy(&raw_buf);
    assert!(!raw_text.contains("101 Switching Protocols"));
    assert!(raw_text.contains("SSH-2.0-Dropbear_Test\r\n"));
    assert!(raw_text.contains("SSH-2.0-Client\r\n"));
    drop(raw);

    let _ = tx.send(true);
    let _ = srv.await;
}
