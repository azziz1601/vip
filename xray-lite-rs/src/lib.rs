pub mod address;
pub mod api_client;
pub mod config;
pub mod logger;
pub mod outbound;
pub mod protocol;
pub mod proxy_protocol;
pub mod stats;
pub mod transport;

use std::collections::HashMap;
use std::io;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::{Arc, RwLock};
use std::time::Duration;

use socket2::{Domain, Protocol, SockAddr, Socket, Type};
use tokio::net::TcpListener;
use tokio::sync::{watch, Semaphore};
use tokio_rustls::TlsAcceptor;

use crate::config::{
    is_unix_listen, GrpcSettings, HttpUpgradeSettings, InboundConfig, StreamSettings, WsSettings,
    XrayConfig,
};
use crate::outbound::configure_tcp_socket;
use crate::protocol::{handle_stream, InboundProtocol, InboundRuntime, InboundUsers};
use crate::proxy_protocol::consume_proxy_protocol;
use crate::stats::{serve_stats_api_connection, AccessLogger, DynamicBlocklist, StatsRegistry};
use crate::transport::grpc::serve_grpc_connection;
use crate::transport::httpupgrade::accept_httpupgrade;
use crate::transport::websocket::accept_websocket;
use crate::transport::xhttp::{serve_xhttp_connection, XhttpHub};
use crate::transport::{build_tls_acceptor, BoxedStream};

const ACCEPT_ERROR_BACKOFF: Duration = Duration::from_millis(50);
pub const DEFAULT_MAX_CONNECTIONS: usize = 4096;

/// Holds references to all active inbounds' user tables so `SIGHUP` can hot-reload users
/// without restarting listeners or dropping active connections.
#[derive(Clone, Default)]
pub struct HotReloadRegistry {
    by_key: Arc<RwLock<HashMap<String, (InboundProtocol, Arc<RwLock<InboundUsers>>)>>>,
}

impl HotReloadRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn register(&self, key: String, protocol: InboundProtocol, users: Arc<RwLock<InboundUsers>>) {
        let mut map = self.by_key.write().unwrap_or_else(|e| e.into_inner());
        map.insert(key, (protocol, users));
    }

    /// Applies updated client lists from a newly parsed `XrayConfig`.
    /// Returns the total number of active users across updated inbounds.
    pub fn apply_config(&self, cfg: &XrayConfig) -> usize {
        let map = self.by_key.read().unwrap_or_else(|e| e.into_inner());
        let mut total_users = 0usize;
        for (idx, inbound) in cfg.inbounds.iter().enumerate() {
            let key = inbound_key(idx, inbound);
            if let Some((proto, users_lock)) = map.get(&key) {
                let new_users = InboundUsers::from_clients(*proto, &inbound.settings.clients);
                let count = new_users.count(*proto);
                total_users += count;
                let mut guard = users_lock.write().unwrap_or_else(|e| e.into_inner());
                *guard = new_users;
                log_info!(
                    "[{}] hot-reloaded {} user(s)",
                    if inbound.tag.is_empty() { &key } else { &inbound.tag },
                    count
                );
            }
        }
        total_users
    }

    pub fn reload_from_file(&self, path: &PathBuf) -> Result<usize, String> {
        let new_cfg = XrayConfig::from_file(path)?;
        Ok(self.apply_config(&new_cfg))
    }
}

fn inbound_key(idx: usize, cfg: &InboundConfig) -> String {
    if !cfg.tag.is_empty() {
        cfg.tag.clone()
    } else {
        format!("inbound-{idx}")
    }
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

#[derive(Clone)]
struct TransportConfig {
    network: String,
    accept_proxy_protocol: bool,
    tls: Option<TlsAcceptor>,
    ws: WsSettings,
    httpupgrade: HttpUpgradeSettings,
    grpc: GrpcSettings,
    xhttp_hub: Option<Arc<XhttpHub>>,
}

impl TransportConfig {
    fn from_stream_settings(ss: Option<&StreamSettings>) -> Result<Self, String> {
        let ss = ss.cloned().unwrap_or_default();
        let network = if ss.network.trim().is_empty() {
            "tcp".to_string()
        } else {
            ss.network.to_ascii_lowercase()
        };
        let is_grpc = network == "grpc" || network == "gun";
        let accept_proxy_protocol = ss.accept_proxy_protocol();

        let tls = if ss.security.eq_ignore_ascii_case("tls") {
            let tls_cfg = ss
                .tls_settings
                .as_ref()
                .ok_or_else(|| "security=tls requires tlsSettings".to_string())?;
            Some(build_tls_acceptor(tls_cfg, is_grpc)?)
        } else {
            None
        };

        let xhttp_hub = if network == "xhttp" || network == "splithttp" {
            Some(XhttpHub::new(ss.xhttp_settings.unwrap_or_default()))
        } else {
            None
        };

        Ok(Self {
            network,
            accept_proxy_protocol,
            tls,
            ws: ss.ws_settings.unwrap_or_default(),
            httpupgrade: ss.httpupgrade_settings.unwrap_or_default(),
            grpc: ss.grpc_settings.unwrap_or_default(),
            xhttp_hub,
        })
    }
}

/// Starts all configured inbounds with the default global concurrency limit (`4096`).
pub async fn run_server(
    cfg: XrayConfig,
    registry: HotReloadRegistry,
    shutdown_rx: watch::Receiver<bool>,
) -> Result<(), String> {
    run_server_with_limit(cfg, registry, shutdown_rx, DEFAULT_MAX_CONNECTIONS).await
}

/// Starts all configured inbounds and runs until `shutdown_rx` triggers, enforcing
/// a global connection limit to protect low-spec VPS from FD/RAM exhaustion.
pub async fn run_server_with_limit(
    cfg: XrayConfig,
    registry: HotReloadRegistry,
    mut shutdown_rx: watch::Receiver<bool>,
    max_connections: usize,
) -> Result<(), String> {
    let block_private = cfg.block_private_ips();
    let block_bittorrent = cfg.block_bittorrent();
    let conn_idle = cfg.conn_idle_timeout();
    let stats_registry = StatsRegistry::new();
    let blocklist = DynamicBlocklist::new();
    if let Some(err_path) = cfg.error_log_path() {
        if let Err(e) = crate::logger::set_error_file(err_path) {
            log_warn!("{} (continuing with stderr only)", e);
        }
    }
    let access_log = match cfg.access_log_path() {
        Some(path) => match AccessLogger::open(path) {
            Ok(logger) => {
                log_info!("access log enabled: {}", path);
                logger
            }
            Err(e) => {
                log_warn!("{} (continuing without access log)", e);
                AccessLogger::disabled()
            }
        },
        None => AccessLogger::disabled(),
    };

    let conn_slots = Arc::new(Semaphore::new(max_connections.max(1)));
    let mut tasks = Vec::with_capacity(cfg.inbounds.len());

    for (idx, inbound) in cfg.inbounds.iter().enumerate() {
        let key = inbound_key(idx, inbound);
        let proto_lower = inbound.protocol.to_ascii_lowercase();

        // Serve Xray-compatible gRPC StatsService on `dokodemo-door` API inbound (e.g. 127.0.0.1:10000).
        if proto_lower == "dokodemo-door" {
            let port = inbound.port.as_u16()?;
            let bind_str = if inbound.listen.contains(':') && !inbound.listen.starts_with('[') {
                format!("[{}]:{}", inbound.listen, port)
            } else {
                format!("{}:{}", inbound.listen, port)
            };
            let addr: SocketAddr = bind_str
                .parse()
                .map_err(|e| format!("invalid API listen address '{bind_str}': {e}"))?;
            let listener = bind_tcp_listener(addr)
                .map_err(|e| format!("failed to bind StatsService API '{addr}': {e}"))?;
            log_info!(
                "[{}] listening on {} (gRPC StatsService + RoutingService API)",
                key,
                listener.local_addr().unwrap_or(addr)
            );
            let mut task_shutdown = shutdown_rx.clone();
            let stats = stats_registry.clone();
            let bl = blocklist.clone();
            let task = tokio::spawn(async move {
                loop {
                    let accept_res = tokio::select! {
                        biased;
                        _ = task_shutdown.changed() => break,
                        res = listener.accept() => res,
                    };
                    match accept_res {
                        Ok((stream, _peer)) => {
                            configure_tcp_socket(&stream);
                            let st = stats.clone();
                            let bl = bl.clone();
                            tokio::spawn(async move {
                                let _ = serve_stats_api_connection(stream, st, bl).await;
                            });
                        }
                        Err(e) => {
                            log_error!("StatsService accept error: {} (backing off 50ms)", e);
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
            continue;
        }

        // Skip unsupported non-core inbounds (e.g. shadowsocks) gracefully without failing startup.
        if InboundProtocol::parse(&proto_lower).is_none() {
            log_warn!(
                "[{}] skipping unsupported inbound protocol '{}' (listen={})",
                key,
                inbound.protocol,
                inbound.listen
            );
            continue;
        }

        let runtime = Arc::new(InboundRuntime::from_config(
            inbound,
            block_private,
            block_bittorrent,
            conn_idle,
            stats_registry.clone(),
            access_log.clone(),
        )?);
        let user_count = runtime
            .users
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .count(runtime.protocol);
        registry.register(key.clone(), runtime.protocol, Arc::clone(&runtime.users));

        let transport = Arc::new(TransportConfig::from_stream_settings(
            inbound.stream_settings.as_ref(),
        )?);

        if is_unix_listen(&inbound.listen) {
            #[cfg(unix)]
            {
                let sock_path = inbound.listen.clone();
                if sock_path.starts_with('/') {
                    let _ = std::fs::remove_file(&sock_path);
                }
                let listener = tokio::net::UnixListener::bind(&sock_path)
                    .map_err(|e| format!("failed to bind Unix socket '{sock_path}': {e}"))?;
                log_info!(
                    "[{}] listening on unix:{} (proto={}, net={}, tls={}, users={})",
                    key,
                    sock_path,
                    inbound.protocol,
                    transport.network,
                    transport.tls.is_some(),
                    user_count
                );
                let mut task_shutdown = shutdown_rx.clone();
                let slots = Arc::clone(&conn_slots);
                let bl = blocklist.clone();
                let task = tokio::spawn(async move {
                    loop {
                        let accept_res = tokio::select! {
                            biased;
                            _ = task_shutdown.changed() => break,
                            res = listener.accept() => res,
                        };
                        match accept_res {
                            Ok((stream, _)) => match Arc::clone(&slots).try_acquire_owned() {
                                Ok(permit) => {
                                    let rt = Arc::clone(&runtime);
                                    let tr = Arc::clone(&transport);
                                    let bl = bl.clone();
                                    tokio::spawn(async move {
                                        let _permit = permit;
                                        handle_raw_connection(
                                            Box::new(stream),
                                            "unix".to_string(),
                                            rt,
                                            tr,
                                            bl,
                                        )
                                        .await;
                                    });
                                }
                                Err(_) => {
                                    log_warn!("max connections ({}) reached; rejecting unix client", max_connections);
                                    drop(stream);
                                }
                            },
                            Err(e) => {
                                log_error!("unix accept error: {} (backing off 50ms)", e);
                                tokio::select! {
                                    biased;
                                    _ = task_shutdown.changed() => break,
                                    _ = tokio::time::sleep(ACCEPT_ERROR_BACKOFF) => {}
                                }
                            }
                        }
                    }
                    if sock_path.starts_with('/') {
                        let _ = std::fs::remove_file(&sock_path);
                    }
                });
                tasks.push(task);
            }
            #[cfg(not(unix))]
            {
                return Err(format!(
                    "Unix domain socket '{}' is only supported on Unix systems",
                    inbound.listen
                ));
            }
        } else {
            let port = inbound.port.as_u16()?;
            let bind_str = if inbound.listen.contains(':') && !inbound.listen.starts_with('[') {
                format!("[{}]:{}", inbound.listen, port)
            } else {
                format!("{}:{}", inbound.listen, port)
            };
            let addr: SocketAddr = bind_str
                .parse()
                .map_err(|e| format!("invalid listen address '{bind_str}': {e}"))?;
            let listener = bind_tcp_listener(addr)
                .map_err(|e| format!("failed to bind TCP '{addr}': {e}"))?;
            log_info!(
                "[{}] listening on {} (proto={}, net={}, tls={}, proxy_proto={}, users={})",
                key,
                listener.local_addr().unwrap_or(addr),
                inbound.protocol,
                transport.network,
                transport.tls.is_some(),
                transport.accept_proxy_protocol,
                user_count
            );

            let mut task_shutdown = shutdown_rx.clone();
            let slots = Arc::clone(&conn_slots);
            let bl = blocklist.clone();
            let task = tokio::spawn(async move {
                loop {
                    let accept_res = tokio::select! {
                        biased;
                        _ = task_shutdown.changed() => break,
                        res = listener.accept() => res,
                    };
                    match accept_res {
                        Ok((stream, peer)) => match Arc::clone(&slots).try_acquire_owned() {
                            Ok(permit) => {
                                configure_tcp_socket(&stream);
                                let rt = Arc::clone(&runtime);
                                let tr = Arc::clone(&transport);
                                let bl = bl.clone();
                                tokio::spawn(async move {
                                    let _permit = permit;
                                    handle_raw_connection(
                                        Box::new(stream),
                                        peer.to_string(),
                                        rt,
                                        tr,
                                        bl,
                                    )
                                    .await;
                                });
                            }
                            Err(_) => {
                                log_warn!(
                                    "max connections ({}) reached; rejecting {}",
                                    max_connections,
                                    peer
                                );
                                drop(stream);
                            }
                        },
                        Err(e) => {
                            log_error!("TCP accept error: {} (backing off 50ms)", e);
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
    }

    let _ = shutdown_rx.changed().await;
    for t in tasks {
        let _ = t.await;
    }
    Ok(())
}

async fn handle_raw_connection(
    mut stream: BoxedStream,
    mut peer_desc: String,
    runtime: Arc<InboundRuntime>,
    transport: Arc<TransportConfig>,
    blocklist: DynamicBlocklist,
) {
    if blocklist.is_blocked(&runtime.tag, &peer_desc) {
        log_debug!("[{}] ({}): rejected by dynamic source IP block", runtime.tag, peer_desc);
        return;
    }
    // 1. Optional HAProxy/Nginx PROXY protocol v1/v2 (with 5s timeout).
    if transport.accept_proxy_protocol {
        match tokio::time::timeout(Duration::from_secs(5), consume_proxy_protocol(stream)).await {
            Ok(Ok((real_addr, wrapped))) => {
                if let Some(addr) = real_addr {
                    peer_desc = addr.to_string();
                }
                stream = Box::new(wrapped);
            }
            Ok(Err(e)) => {
                log_debug!("[{}] ({}): PROXY protocol error: {}", runtime.tag, peer_desc, e);
                return;
            }
            Err(_) => {
                log_debug!("[{}] ({}): PROXY protocol timeout", runtime.tag, peer_desc);
                return;
            }
        }
    }

    // 2. Optional TLS handshake (10s timeout).
    if let Some(tls) = &transport.tls {
        match tokio::time::timeout(Duration::from_secs(10), tls.accept(stream)).await {
            Ok(Ok(tls_stream)) => {
                stream = Box::new(tls_stream);
            }
            Ok(Err(e)) => {
                log_debug!("[{}] ({}): TLS handshake error: {}", runtime.tag, peer_desc, e);
                return;
            }
            Err(_) => {
                log_debug!("[{}] ({}): TLS handshake timeout", runtime.tag, peer_desc);
                return;
            }
        }
    }

    // 3. Transport layer dispatch.
    match transport.network.as_str() {
        "tcp" | "raw" => {
            if blocklist.is_blocked(&runtime.tag, &peer_desc) {
                log_debug!("[{}] ({}): rejected by dynamic source IP block", runtime.tag, peer_desc);
                return;
            }
            handle_stream(stream, runtime, peer_desc).await;
        }
        "ws" | "websocket" => match accept_websocket(stream, &transport.ws).await {
            Ok((ws_stream, forwarded_ip)) => {
                if let Some(ip) = forwarded_ip {
                    peer_desc = ip;
                }
                if blocklist.is_blocked(&runtime.tag, &peer_desc) {
                    log_debug!("[{}] ({}): rejected by dynamic source IP block", runtime.tag, peer_desc);
                    return;
                }
                handle_stream(Box::new(ws_stream), runtime, peer_desc).await;
            }
            Err(e) => {
                log_debug!("[{}] ({}): WS handshake failed: {}", runtime.tag, peer_desc, e);
            }
        },
        "httpupgrade" => match accept_httpupgrade(stream, &transport.httpupgrade).await {
            Ok((hu_stream, forwarded_ip)) => {
                if let Some(ip) = forwarded_ip {
                    peer_desc = ip;
                }
                if blocklist.is_blocked(&runtime.tag, &peer_desc) {
                    log_debug!("[{}] ({}): rejected by dynamic source IP block", runtime.tag, peer_desc);
                    return;
                }
                handle_stream(Box::new(hu_stream), runtime, peer_desc).await;
            }
            Err(e) => {
                log_debug!(
                    "[{}] ({}): HTTPUpgrade handshake failed: {}",
                    runtime.tag,
                    peer_desc,
                    e
                );
            }
        },
        "grpc" | "gun" => {
            let rt = Arc::clone(&runtime);
            let peer = peer_desc.clone();
            let bl = blocklist.clone();
            if let Err(e) = serve_grpc_connection(
                stream,
                transport.grpc.clone(),
                move |s, forwarded_ip| {
                    let rt = Arc::clone(&rt);
                    let bl = bl.clone();
                    let peer = forwarded_ip.unwrap_or_else(|| peer.clone());
                    async move {
                        if bl.is_blocked(&rt.tag, &peer) {
                            log_debug!("[{}] ({}): rejected by dynamic source IP block", rt.tag, peer);
                            return;
                        }
                        handle_stream(s, rt, peer).await;
                    }
                },
            )
            .await
            {
                log_debug!("[{}] ({}): gRPC error: {}", runtime.tag, peer_desc, e);
            }
        }
        "xhttp" | "splithttp" => {
            let Some(hub) = transport.xhttp_hub.as_ref().map(Arc::clone) else {
                log_error!("[{}] xhttp hub not initialized", runtime.tag);
                return;
            };
            let rt = Arc::clone(&runtime);
            let peer = peer_desc.clone();
            let bl = blocklist.clone();
            if let Err(e) = serve_xhttp_connection(stream, hub, move |s, forwarded_ip| {
                let rt = Arc::clone(&rt);
                let bl = bl.clone();
                let peer = forwarded_ip.unwrap_or_else(|| peer.clone());
                async move {
                    if bl.is_blocked(&rt.tag, &peer) {
                        log_debug!("[{}] ({}): rejected by dynamic source IP block", rt.tag, peer);
                        return;
                    }
                    handle_stream(s, rt, peer).await;
                }
            })
            .await
            {
                log_debug!("[{}] ({}): XHTTP error: {}", runtime.tag, peer_desc, e);
            }
        }
        other => {
            log_error!("[{}] unsupported transport '{}'", runtime.tag, other);
        }
    }
}
