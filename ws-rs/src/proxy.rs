use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use socket2::{Domain, Protocol, SockAddr, SockRef, Socket, TcpKeepalive, Type};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{watch, Semaphore};
use tokio::time::timeout;

use crate::config::{ListenRule, WsConfig};
use crate::ws_proto::{build_101_response, find_header_end, looks_like_http, parse_http_headers};

const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
const DIAL_TIMEOUT: Duration = Duration::from_secs(10);
const MAX_HTTP_HEADER_BYTES: usize = 16 * 1024;
const ACCEPT_ERROR_BACKOFF: Duration = Duration::from_millis(50);
const TCP_KEEPALIVE_IDLE: Duration = Duration::from_secs(60);
const TCP_KEEPALIVE_INTERVAL: Duration = Duration::from_secs(15);

pub fn configure_tcp_socket(stream: &TcpStream) {
    let _ = stream.set_nodelay(true);
    let keepalive = TcpKeepalive::new()
        .with_time(TCP_KEEPALIVE_IDLE)
        .with_interval(TCP_KEEPALIVE_INTERVAL);
    let _ = SockRef::from(stream).set_tcp_keepalive(&keepalive);
}

pub fn bind_tcp_listener(addr: SocketAddr) -> io::Result<TcpListener> {
    let domain = match addr {
        SocketAddr::V4(_) => Domain::IPV4,
        SocketAddr::V6(_) => Domain::IPV6,
    };
    let sock = Socket::new(domain, Type::STREAM, Some(Protocol::TCP))?;
    sock.set_reuse_address(true)?;
    sock.set_nonblocking(true)?;
    sock.bind(&SockAddr::from(addr))?;
    sock.listen(1024)?;
    let std_listener: std::net::TcpListener = sock.into();
    TcpListener::from_std(std_listener)
}

/// Runs all configured `listen` rules until `shutdown_rx` signals `true`.
pub async fn run_server(
    cfg: WsConfig,
    mut shutdown_rx: watch::Receiver<bool>,
) -> Result<(), String> {
    let slots = Arc::new(Semaphore::new(cfg.max_connections.max(1)));
    let mut tasks = Vec::with_capacity(cfg.listen.len());

    for rule in cfg.listen {
        let bind_str = if rule.listen_host.contains(':') && !rule.listen_host.starts_with('[') {
            format!("[{}]:{}", rule.listen_host, rule.listen_port)
        } else {
            format!("{}:{}", rule.listen_host, rule.listen_port)
        };
        let addr: SocketAddr = bind_str
            .parse()
            .map_err(|e| format!("invalid listen address '{bind_str}': {e}"))?;
        let listener = bind_tcp_listener(addr)
            .map_err(|e| format!("failed to bind '{addr}': {e}"))?;

        eprintln!(
            "[ws-rs] listening on {} -> {}:{}",
            listener.local_addr().unwrap_or(addr),
            rule.target_host,
            rule.target_port
        );

        let target_addr = if rule.target_host.contains(':') && !rule.target_host.starts_with('[') {
            format!("[{}]:{}", rule.target_host, rule.target_port)
        } else {
            format!("{}:{}", rule.target_host, rule.target_port)
        };
        let target_addr = Arc::new(target_addr);
        let verbose = cfg.verbose;
        let idle_timeout = cfg.idle_timeout;
        let slots = Arc::clone(&slots);
        let mut task_shutdown = shutdown_rx.clone();

        let task = tokio::spawn(async move {
            loop {
                let accept_res = tokio::select! {
                    biased;
                    _ = task_shutdown.changed() => break,
                    res = listener.accept() => res,
                };
                match accept_res {
                    Ok((client, peer)) => match Arc::clone(&slots).try_acquire_owned() {
                        Ok(permit) => {
                            configure_tcp_socket(&client);
                            let target = Arc::clone(&target_addr);
                            tokio::spawn(async move {
                                let _permit = permit;
                                if let Err(e) =
                                    handle_client(client, peer, &target, idle_timeout, verbose)
                                        .await
                                {
                                    if verbose >= 2 {
                                        eprintln!("[ws-rs] {peer} -> {target} closed: {e}");
                                    }
                                }
                            });
                        }
                        Err(_) => {
                            if verbose >= 1 {
                                eprintln!("[ws-rs] max connections reached, dropping {peer}");
                            }
                            drop(client);
                        }
                    },
                    Err(e) => {
                        eprintln!("[ws-rs] accept error: {e}");
                        tokio::select! {
                            biased;
                            _ = task_shutdown.changed() => break,
                            _ = tokio::time::sleep(ACCEPT_ERROR_BACKOFF) => {}
                        }
                    }
                }
            }
        });
        tasks.push(task);
    }

    let _ = shutdown_rx.changed().await;
    for t in tasks {
        let _ = t.await;
    }
    Ok(())
}

async fn handle_client(
    mut client: TcpStream,
    peer: SocketAddr,
    target_addr: &str,
    idle_timeout: Duration,
    verbose: u8,
) -> io::Result<()> {
    let mut buf = Vec::with_capacity(1024);
    let mut tmp = [0u8; 2048];

    // 1. Read initial bytes (either HTTP Upgrade header ending in \r\n\r\n, or raw TCP payload).
    let (is_http, header_end) = timeout(HANDSHAKE_TIMEOUT, async {
        loop {
            let n = client.read(&mut tmp).await?;
            if n == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "EOF before handshake",
                ));
            }
            buf.extend_from_slice(&tmp[..n]);

            if buf.len() >= 4 && !looks_like_http(&buf) {
                return Ok((false, 0));
            }
            if let Some(pos) = find_header_end(&buf) {
                return Ok((true, pos));
            }
            if buf.len() > MAX_HTTP_HEADER_BYTES {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "HTTP header too large",
                ));
            }
        }
    })
    .await
    .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "handshake timeout"))??;

    // 2. Dial target backend (Dropbear SSH / OpenVPN).
    let mut target = timeout(DIAL_TIMEOUT, TcpStream::connect(target_addr))
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "target dial timeout"))??;
    configure_tcp_socket(&target);

    if is_http {
        let parsed = parse_http_headers(&buf[..header_end]);
        let resp = build_101_response(parsed.ws_key.as_deref());
        client.write_all(&resp).await?;

        if verbose >= 1 {
            let src = parsed
                .real_ip
                .unwrap_or_else(|| peer.ip().to_string());
            eprintln!("[ws-rs] {src} upgraded -> {target_addr}");
        }

        // Handle [split] double-header payloads (e.g. BMOVE/CONNECT followed by GET Upgrade)
        // as well as early-data bytes sent immediately after \r\n\r\n.
        let mut leftover = buf[(header_end + 4)..].to_vec();
        if !parsed.has_upgrade {
            if leftover.is_empty() {
                if let Ok(Ok(n)) = timeout(Duration::from_millis(120), client.read(&mut tmp)).await {
                    if n > 0 {
                        leftover.extend_from_slice(&tmp[..n]);
                    }
                }
            }
            if looks_like_http(&leftover) {
                while find_header_end(&leftover).is_none() && leftover.len() <= MAX_HTTP_HEADER_BYTES {
                    match timeout(HANDSHAKE_TIMEOUT, client.read(&mut tmp)).await {
                        Ok(Ok(0)) | Err(_) => break,
                        Ok(Ok(n)) => leftover.extend_from_slice(&tmp[..n]),
                        Ok(Err(e)) => return Err(e),
                    }
                }
                if let Some(pos2) = find_header_end(&leftover) {
                    let parsed2 = parse_http_headers(&leftover[..pos2]);
                    if parsed2.ws_key.is_some() {
                        let resp2 = build_101_response(parsed2.ws_key.as_deref());
                        client.write_all(&resp2).await?;
                    }
                    leftover = leftover[(pos2 + 4)..].to_vec();
                }
            }
        }
        if !leftover.is_empty() {
            target.write_all(&leftover).await?;
        }
    } else {
        if verbose >= 1 {
            eprintln!("[ws-rs] {peer} raw passthrough -> {target_addr}");
        }
        target.write_all(&buf).await?;
    }

    // Drop header buffer before entering long-lived relay loop to minimize per-connection RAM.
    drop(buf);

    // 3. Bidirectional TCP relay with idle watchdog.
    relay_with_idle_timeout(&mut client, &mut target, idle_timeout).await
}

async fn relay_with_idle_timeout(
    client: &mut TcpStream,
    target: &mut TcpStream,
    idle_timeout: Duration,
) -> io::Result<()> {
    let active = Arc::new(AtomicBool::new(false));
    let mut tracked_target = ActivityStream {
        inner: target,
        active: Arc::clone(&active),
    };
    let mut tick = tokio::time::interval(idle_timeout);
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    tick.tick().await;

    tokio::select! {
        _ = tokio::io::copy_bidirectional(client, &mut tracked_target) => {}
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

struct ActivityStream<'a> {
    inner: &'a mut TcpStream,
    active: Arc<AtomicBool>,
}

impl AsyncRead for ActivityStream<'_> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let before = buf.filled().len();
        let res = Pin::new(&mut *self.inner).poll_read(cx, buf);
        if let Poll::Ready(Ok(())) = &res {
            if buf.filled().len() > before {
                self.active.store(true, Ordering::Relaxed);
            }
        }
        res
    }
}

impl AsyncWrite for ActivityStream<'_> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let res = Pin::new(&mut *self.inner).poll_write(cx, buf);
        if let Poll::Ready(Ok(n)) = &res {
            if *n > 0 {
                self.active.store(true, Ordering::Relaxed);
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

/// Helper used by tests to build a single-rule server config quickly.
pub fn single_rule_config(rule: ListenRule) -> WsConfig {
    WsConfig {
        listen: vec![rule],
        ..WsConfig::default()
    }
}
