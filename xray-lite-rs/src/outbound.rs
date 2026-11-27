use std::io;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use socket2::{SockRef, TcpKeepalive};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::{TcpStream, UdpSocket};
use tokio::time::timeout;

use crate::address::{is_private_ip, TargetAddr};
use crate::stats::UserTraffic;

const DIAL_TIMEOUT: Duration = Duration::from_secs(10);
const TCP_KEEPALIVE_IDLE: Duration = Duration::from_secs(60);
const TCP_KEEPALIVE_INTERVAL: Duration = Duration::from_secs(15);
const BITTORRENT_HANDSHAKE_PREFIX: &[u8; 20] = b"\x13BitTorrent protocol";

/// Detects standard BitTorrent peer wire protocol handshake on the first TCP payload chunk.
#[inline]
pub fn is_bittorrent_handshake(buf: &[u8]) -> bool {
    buf.len() >= BITTORRENT_HANDSHAKE_PREFIX.len()
        && &buf[..BITTORRENT_HANDSHAKE_PREFIX.len()] == BITTORRENT_HANDSHAKE_PREFIX
}

/// Applies `TCP_NODELAY` and kernel TCP keepalive (60s idle / 15s interval) so dead mobile
/// connections are automatically reaped instead of lingering for hours as zombie sockets.
pub fn configure_tcp_socket(stream: &TcpStream) {
    let _ = stream.set_nodelay(true);
    let keepalive = TcpKeepalive::new()
        .with_time(TCP_KEEPALIVE_IDLE)
        .with_interval(TCP_KEEPALIVE_INTERVAL);
    let _ = SockRef::from(stream).set_tcp_keepalive(&keepalive);
}

/// Connects directly to `target` (Freedom outbound) with optional private-IP SSRF protection.
pub async fn dial_tcp(target: &TargetAddr, block_private: bool) -> io::Result<TcpStream> {
    let addr = timeout(DIAL_TIMEOUT, target.resolve())
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "DNS resolve timeout"))??;

    if block_private && is_private_ip(addr.ip()) {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!("blocked connection to private IP {addr}"),
        ));
    }

    let stream = timeout(DIAL_TIMEOUT, TcpStream::connect(addr))
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "TCP connect timeout"))??;

    configure_tcp_socket(&stream);
    Ok(stream)
}

/// Resolves a UDP target address with optional private-IP protection.
pub async fn resolve_udp_target(target: &TargetAddr, block_private: bool) -> io::Result<SocketAddr> {
    let addr = timeout(DIAL_TIMEOUT, target.resolve())
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "DNS resolve timeout"))??;

    if block_private && is_private_ip(addr.ip()) {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!("blocked UDP packet to private IP {addr}"),
        ));
    }
    Ok(addr)
}

/// Binds an ephemeral local UDP socket matching the IP family of `remote`.
pub async fn bind_udp_for(remote: SocketAddr) -> io::Result<UdpSocket> {
    let bind_addr = match remote {
        SocketAddr::V4(_) => SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0)),
        SocketAddr::V6(_) => SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, 0, 0, 0)),
    };
    UdpSocket::bind(bind_addr).await
}

/// Relays TCP streams bidirectionally without traffic accounting (used for fallbacks).
pub async fn relay_tcp<S: AsyncRead + AsyncWrite + Unpin>(
    client: &mut S,
    target: &mut TcpStream,
) -> io::Result<()> {
    let _ = tokio::io::copy_bidirectional(client, target).await;
    Ok(())
}

/// Relays TCP streams bidirectionally while updating real-time per-user uplink/downlink
/// atomic byte counters on every chunk, optionally blocking BitTorrent handshakes,
/// and enforcing `conn_idle` so silent zombie TCP streams are reaped automatically.
pub async fn relay_tcp_with_stats<S: AsyncRead + AsyncWrite + Unpin>(
    client: &mut S,
    target: &mut TcpStream,
    stats: Option<Arc<UserTraffic>>,
    block_bittorrent: bool,
    conn_idle: Duration,
) -> io::Result<()> {
    let active = Arc::new(AtomicBool::new(false));
    let mut counted_target = CountingOutbound {
        inner: target,
        counters: stats,
        check_bt: block_bittorrent,
        active: Arc::clone(&active),
    };
    let mut tick = tokio::time::interval(conn_idle);
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    tick.tick().await;
    tokio::select! {
        _ = tokio::io::copy_bidirectional(client, &mut counted_target) => {}
        _ = async {
            loop {
                tick.tick().await;
                if !active.swap(false, Ordering::Relaxed) {
                    break;
                }
            }
        } => {}
    }
    Ok(())
}

struct CountingOutbound<'a> {
    inner: &'a mut TcpStream,
    counters: Option<Arc<UserTraffic>>,
    check_bt: bool,
    active: Arc<AtomicBool>,
}

impl AsyncRead for CountingOutbound<'_> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let before = buf.filled().len();
        let res = Pin::new(&mut *self.inner).poll_read(cx, buf);
        if let Poll::Ready(Ok(())) = &res {
            let delta = buf.filled().len().saturating_sub(before);
            if delta > 0 {
                self.active.store(true, Ordering::Relaxed);
                if let Some(c) = &self.counters {
                    c.add_downlink(delta as u64);
                }
            }
        }
        res
    }
}

impl AsyncWrite for CountingOutbound<'_> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        if self.check_bt {
            self.check_bt = false;
            if is_bittorrent_handshake(buf) {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "blocked BitTorrent protocol",
                )));
            }
        }
        let res = Pin::new(&mut *self.inner).poll_write(cx, buf);
        if let Poll::Ready(Ok(n)) = &res {
            if *n > 0 {
                self.active.store(true, Ordering::Relaxed);
                if let Some(c) = &self.counters {
                    c.add_uplink(*n as u64);
                }
            }
        }
        res
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut *self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut *self.inner).poll_shutdown(cx)
    }
}
