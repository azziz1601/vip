use std::io;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::time::timeout;

use crate::address::{read_vless_vmess_addr, TargetAddr, TargetHost};
use crate::log_debug;
use crate::outbound::{bind_udp_for, dial_tcp, relay_tcp_with_stats, resolve_udp_target};
use crate::protocol::{mux, InboundRuntime};
use crate::transport::BoxedStream;

const VLESS_VERSION: u8 = 0x00;
const CMD_TCP: u8 = 0x01;
const CMD_UDP: u8 = 0x02;
const CMD_MUX: u8 = 0x03;
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
const UDP_IDLE_TIMEOUT: Duration = Duration::from_secs(90);

pub async fn handle_vless(
    mut stream: BoxedStream,
    runtime: &InboundRuntime,
    peer_desc: &str,
) -> io::Result<()> {
    // Parse entire VLESS header under one strict 10s handshake timeout.
    let (email, cmd, target) = timeout(HANDSHAKE_TIMEOUT, async {
        let mut head = [0u8; 18];
        stream.read_exact(&mut head).await?;

        let version = head[0];
        if version != VLESS_VERSION {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("unsupported VLESS version {version}"),
            ));
        }

        let mut uuid = [0u8; 16];
        uuid.copy_from_slice(&head[1..17]);

        let email = {
            let users = runtime.users.read().unwrap_or_else(|e| e.into_inner());
            users.vless_ids.get(&uuid).cloned()
        };

        let Some(email) = email else {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "VLESS invalid user UUID",
            ));
        };

        let addons_len = head[17] as usize;
        if addons_len > 0 {
            let mut addons = vec![0u8; addons_len];
            stream.read_exact(&mut addons).await?;
        }

        let cmd = stream.read_u8().await?;
        let target = if cmd == CMD_MUX {
            TargetAddr {
                host: TargetHost::Domain("v1.mux.cool".to_string()),
                port: 0,
            }
        } else {
            read_vless_vmess_addr(&mut stream).await?
        };
        Ok((email, cmd, target))
    })
    .await
    .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "VLESS header timeout"))??;

    log_debug!(
        "[{}] VLESS user='{}' ({}) cmd={} -> {}",
        runtime.tag,
        email,
        peer_desc,
        cmd,
        target
    );

    let counters = runtime.stats.counters_for(&email);
    if cmd != CMD_MUX {
        let net_label = if cmd == CMD_UDP { "udp" } else { "tcp" };
        runtime
            .access_log
            .log_accepted(peer_desc, net_label, &target.to_string(), &runtime.tag, &email);
    }

    match cmd {
        CMD_TCP => {
            let mut outbound = dial_tcp(&target, runtime.block_private).await?;
            stream.write_all(&[VLESS_VERSION, 0x00]).await?;
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
            let remote_addr = resolve_udp_target(&target, runtime.block_private).await?;
            let udp = bind_udp_for(remote_addr).await?;
            stream.write_all(&[VLESS_VERSION, 0x00]).await?;

            let (mut client_r, mut client_w) = tokio::io::split(stream);
            let udp_send = std::sync::Arc::new(udp);
            let udp_recv = std::sync::Arc::clone(&udp_send);

            let up_counters = counters.clone();
            let mut up = tokio::spawn(async move {
                let mut len_buf = [0u8; 2];
                let mut pkt_buf = Vec::new();
                loop {
                    match timeout(UDP_IDLE_TIMEOUT, client_r.read_exact(&mut len_buf)).await {
                        Ok(Ok(_)) => {}
                        _ => break,
                    }
                    let pkt_len = u16::from_be_bytes(len_buf) as usize;
                    pkt_buf.resize(pkt_len, 0);
                    if pkt_len > 0 && client_r.read_exact(&mut pkt_buf).await.is_err() {
                        break;
                    }
                    if udp_send.send_to(&pkt_buf, remote_addr).await.is_err() {
                        break;
                    }
                    if let Some(c) = &up_counters {
                        c.add_uplink(pkt_len as u64);
                    }
                }
            });

            let down_counters = counters;
            let mut down = tokio::spawn(async move {
                let mut recv_buf = vec![0u8; 8192];
                let mut out_frame = Vec::with_capacity(2048);
                loop {
                    let n = match timeout(UDP_IDLE_TIMEOUT, udp_recv.recv_from(&mut recv_buf)).await
                    {
                        Ok(Ok((n, _))) => n,
                        _ => break,
                    };
                    if let Some(c) = &down_counters {
                        c.add_downlink(n as u64);
                    }
                    if n > u16::MAX as usize {
                        continue;
                    }
                    out_frame.clear();
                    out_frame.extend_from_slice(&(n as u16).to_be_bytes());
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
        CMD_MUX => {
            stream.write_all(&[VLESS_VERSION, 0x00]).await?;
            mux::handle_mux(stream, runtime, peer_desc, &email).await
        }
        other => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("unsupported VLESS command 0x{other:02x}"),
        )),
    }
}
