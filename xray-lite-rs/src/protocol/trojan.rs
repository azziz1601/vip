use std::io;
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

use crate::address::{encode_socks5_addr, read_socks5_addr, TargetAddr};
use crate::log_debug;
use crate::outbound::{bind_udp_for, dial_tcp, relay_tcp, relay_tcp_with_stats, resolve_udp_target};
use crate::protocol::InboundRuntime;
use crate::transport::BoxedStream;

const CMD_TCP: u8 = 0x01;
const CMD_UDP: u8 = 0x03;
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
const UDP_IDLE_TIMEOUT: Duration = Duration::from_secs(90);

pub async fn handle_trojan(
    mut stream: BoxedStream,
    runtime: &InboundRuntime,
    peer_desc: &str,
) -> io::Result<()> {
    // 1. Read 56-byte lowercase hex SHA-224 password hash + CRLF (58 bytes total).
    let mut head = [0u8; 58];
    let mut filled = 0usize;
    let read_res = timeout(HANDSHAKE_TIMEOUT, async {
        while filled < 58 {
            let n = stream.read(&mut head[filled..]).await?;
            if n == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "EOF reading Trojan header",
                ));
            }
            filled += n;
            if filled >= 4
                && runtime.fallbacks.first().is_some()
                && !is_hex_prefix(&head[..filled.min(56)])
            {
                return Ok(false);
            }
        }
        Ok(true)
    })
    .await
    .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "Trojan header timeout"))??;

    let mut key = [0u8; 56];
    let auth_ok = if read_res && head[56] == b'\r' && head[57] == b'\n' {
        key.copy_from_slice(&head[..56]);
        let users = runtime.users.read().unwrap_or_else(|e| e.into_inner());
        users.trojan_keys.get(&key).cloned()
    } else {
        None
    };

    let Some(email) = auth_ok else {
        if let Some(fb) = runtime.fallbacks.first() {
            let dest = fb.dest.to_target_string();
            log_debug!(
                "[{}] Trojan auth failed ({}), forwarding to fallback {}",
                runtime.tag,
                peer_desc,
                dest
            );
            if let Ok(mut fb_stream) = TcpStream::connect(&dest).await {
                let _ = fb_stream.write_all(&head[..filled]).await;
                let _ = relay_tcp(&mut stream, &mut fb_stream).await;
                return Ok(());
            }
        }
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "Trojan invalid password",
        ));
    };

    // 2. Read command (1B) + SOCKS5 address + CRLF (2B) under timeout.
    let (cmd, target) = timeout(HANDSHAKE_TIMEOUT, async {
        let cmd = stream.read_u8().await?;
        let target = read_socks5_addr(&mut stream).await?;
        let mut crlf = [0u8; 2];
        stream.read_exact(&mut crlf).await?;
        if crlf != [b'\r', b'\n'] {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Trojan missing CRLF after address",
            ));
        }
        Ok((cmd, target))
    })
    .await
    .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "Trojan request timeout"))??;

    log_debug!(
        "[{}] Trojan user='{}' ({}) cmd={} -> {}",
        runtime.tag,
        email,
        peer_desc,
        cmd,
        target
    );

    let counters = runtime.stats.counters_for(&email);
    let net_label = if cmd == CMD_UDP { "udp" } else { "tcp" };
    runtime
        .access_log
        .log_accepted(peer_desc, net_label, &target.to_string(), &runtime.tag, &email);

    match cmd {
        CMD_TCP => {
            let mut outbound = dial_tcp(&target, runtime.block_private).await?;
            relay_tcp_with_stats(
                &mut stream,
                &mut outbound,
                counters,
                runtime.block_bittorrent,
                runtime.conn_idle,
            )
            .await
        }
        CMD_UDP => {
            let first_remote = resolve_udp_target(&target, runtime.block_private).await?;
            let udp = Arc::new(bind_udp_for(first_remote).await?);
            let udp_recv = Arc::clone(&udp);
            let block_private = runtime.block_private;

            let (mut client_r, mut client_w) = tokio::io::split(stream);

            let up_counters = counters.clone();
            let mut up = tokio::spawn(async move {
                let mut pkt_buf = Vec::new();
                loop {
                    let pkt_target =
                        match timeout(UDP_IDLE_TIMEOUT, read_socks5_addr(&mut client_r)).await {
                            Ok(Ok(a)) => a,
                            _ => break,
                        };
                    let pkt_len = match client_r.read_u16().await {
                        Ok(l) => l as usize,
                        Err(_) => break,
                    };
                    let mut sep = [0u8; 2];
                    if client_r.read_exact(&mut sep).await.is_err() || sep != [b'\r', b'\n'] {
                        break;
                    }
                    pkt_buf.resize(pkt_len, 0);
                    if pkt_len > 0 && client_r.read_exact(&mut pkt_buf).await.is_err() {
                        break;
                    }
                    if let Ok(dest) = resolve_udp_target(&pkt_target, block_private).await {
                        if udp.send_to(&pkt_buf, dest).await.is_ok() {
                            if let Some(c) = &up_counters {
                                c.add_uplink(pkt_len as u64);
                            }
                        }
                    }
                }
            });

            let down_counters = counters;
            let mut down = tokio::spawn(async move {
                let mut recv_buf = vec![0u8; 8192];
                let mut out_frame = Vec::with_capacity(2048);
                loop {
                    let (n, src) =
                        match timeout(UDP_IDLE_TIMEOUT, udp_recv.recv_from(&mut recv_buf)).await {
                            Ok(Ok(pair)) => pair,
                            _ => break,
                        };
                    if let Some(c) = &down_counters {
                        c.add_downlink(n as u64);
                    }
                    if n > u16::MAX as usize {
                        continue;
                    }
                    out_frame.clear();
                    encode_socks5_addr(&TargetAddr::from_socket_addr(src), &mut out_frame);
                    out_frame.extend_from_slice(&(n as u16).to_be_bytes());
                    out_frame.extend_from_slice(b"\r\n");
                    out_frame.extend_from_slice(&recv_buf[..n]);
                    if client_w.write_all(&out_frame).await.is_err() {
                        break;
                    }
                }
            });

            tokio::select! {
                _ = &mut up => { down.abort(); }
                _ = &mut down => { up.abort(); }
            }
            Ok(())
        }
        other => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("unsupported Trojan command 0x{other:02x}"),
        )),
    }
}

fn is_hex_prefix(bytes: &[u8]) -> bool {
    bytes.iter().all(|b| b.is_ascii_hexdigit())
}
