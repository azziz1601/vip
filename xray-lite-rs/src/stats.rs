use std::collections::HashMap;
use std::fs::OpenOptions;
use std::io::{self, BufWriter, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::{self, RecvTimeoutError, SyncSender};
use std::sync::{Arc, RwLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use bytes::{Buf, BufMut, Bytes, BytesMut};
use h2::server;
use http::{HeaderMap, HeaderValue, Response, StatusCode};
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncWrite};

use crate::{log_debug, log_info};

const MAX_GRPC_API_REQ_BYTES: usize = 64 * 1024;

/// Lock-free per-user traffic byte counters.
#[derive(Default)]
pub struct UserTraffic {
    pub uplink: AtomicU64,
    pub downlink: AtomicU64,
}

impl UserTraffic {
    #[inline]
    pub fn add_uplink(&self, n: u64) {
        if n > 0 {
            self.uplink.fetch_add(n, Ordering::Relaxed);
        }
    }

    #[inline]
    pub fn add_downlink(&self, n: u64) {
        if n > 0 {
            self.downlink.fetch_add(n, Ordering::Relaxed);
        }
    }
}

/// Shared registry of per-user uplink/downlink byte counters, exposed via Xray-compatible
/// gRPC `StatsService` (`QueryStats` / `GetStats`).
#[derive(Clone, Default)]
pub struct StatsRegistry {
    users: Arc<RwLock<HashMap<String, Arc<UserTraffic>>>>,
}

impl StatsRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    /// Returns (or lazily creates) the atomic traffic counters for `email`.
    /// Returns `None` if `email` is empty.
    pub fn counters_for(&self, email: &str) -> Option<Arc<UserTraffic>> {
        if email.is_empty() {
            return None;
        }
        {
            let map = self.users.read().unwrap_or_else(|e| e.into_inner());
            if let Some(c) = map.get(email) {
                return Some(Arc::clone(c));
            }
        }
        let mut map = self.users.write().unwrap_or_else(|e| e.into_inner());
        Some(Arc::clone(
            map.entry(email.to_string())
                .or_insert_with(|| Arc::new(UserTraffic::default())),
        ))
    }

    /// Queries all stats whose name contains `pattern` (empty pattern matches all).
    /// When `reset` is true, atomically resets returned counters to 0.
    pub fn query_stats(&self, pattern: &str, reset: bool) -> Vec<(String, i64)> {
        let map = self.users.read().unwrap_or_else(|e| e.into_inner());
        let mut out = Vec::new();
        for (email, counters) in map.iter() {
            let up_name = format!("user>>>{email}>>>traffic>>>uplink");
            if pattern.is_empty() || up_name.contains(pattern) {
                let val = if reset {
                    counters.uplink.swap(0, Ordering::Relaxed)
                } else {
                    counters.uplink.load(Ordering::Relaxed)
                };
                if val > 0 {
                    out.push((up_name, val.min(i64::MAX as u64) as i64));
                }
            }

            let down_name = format!("user>>>{email}>>>traffic>>>downlink");
            if pattern.is_empty() || down_name.contains(pattern) {
                let val = if reset {
                    counters.downlink.swap(0, Ordering::Relaxed)
                } else {
                    counters.downlink.load(Ordering::Relaxed)
                };
                if val > 0 {
                    out.push((down_name, val.min(i64::MAX as u64) as i64));
                }
            }
        }
        out
    }

    /// Fetches a single stat by exact Xray stat name (`user>>><email>>>>traffic>>>{uplink|downlink}`).
    pub fn get_stat(&self, name: &str, reset: bool) -> Option<(String, i64)> {
        let mut parts = name.split(">>>");
        let scope = parts.next()?;
        let email = parts.next()?;
        let metric = parts.next()?;
        let dir = parts.next()?;
        if scope != "user" || metric != "traffic" || email.is_empty() {
            return None;
        }
        let map = self.users.read().unwrap_or_else(|e| e.into_inner());
        let counters = map.get(email)?;
        let val = match dir {
            "uplink" => {
                if reset {
                    counters.uplink.swap(0, Ordering::Relaxed)
                } else {
                    counters.uplink.load(Ordering::Relaxed)
                }
            }
            "downlink" => {
                if reset {
                    counters.downlink.swap(0, Ordering::Relaxed)
                } else {
                    counters.downlink.load(Ordering::Relaxed)
                }
            }
            _ => return None,
        };
        Some((name.to_string(), val.min(i64::MAX as u64) as i64))
    }
}

/// IPv4/IPv6 CIDR matcher for dynamic `xray api sib` source IP blocking.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IpNet {
    V4 { net: u32, mask: u32 },
    V6 { net: u128, mask: u128 },
}

impl IpNet {
    pub fn parse(raw: &str) -> Option<Self> {
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            return None;
        }
        if let Some((ip_str, prefix_str)) = trimmed.split_once('/') {
            let ip: IpAddr = ip_str.trim().parse().ok()?;
            let prefix: u32 = prefix_str.trim().parse().ok()?;
            match ip {
                IpAddr::V4(v4) if prefix <= 32 => {
                    let mask = if prefix == 0 {
                        0
                    } else {
                        u32::MAX.checked_shl(32 - prefix).unwrap_or(0)
                    };
                    Some(Self::V4 {
                        net: u32::from(v4) & mask,
                        mask,
                    })
                }
                IpAddr::V6(v6) if prefix <= 128 => {
                    let mask = if prefix == 0 {
                        0
                    } else {
                        u128::MAX.checked_shl(128 - prefix).unwrap_or(0)
                    };
                    Some(Self::V6 {
                        net: u128::from(v6) & mask,
                        mask,
                    })
                }
                _ => None,
            }
        } else {
            let ip: IpAddr = trimmed.parse().ok()?;
            match ip {
                IpAddr::V4(v4) => Some(Self::V4 {
                    net: u32::from(v4),
                    mask: u32::MAX,
                }),
                IpAddr::V6(v6) => Some(Self::V6 {
                    net: u128::from(v6),
                    mask: u128::MAX,
                }),
            }
        }
    }

    #[inline]
    pub fn contains(&self, ip: IpAddr) -> bool {
        match (*self, ip) {
            (Self::V4 { net, mask }, IpAddr::V4(v4)) => (u32::from(v4) & mask) == net,
            (Self::V6 { net, mask }, IpAddr::V6(v6)) => (u128::from(v6) & mask) == net,
            (Self::V4 { net, mask }, IpAddr::V6(v6)) => {
                if let Some(v4) = v6.to_ipv4_mapped() {
                    (u32::from(v4) & mask) == net
                } else {
                    false
                }
            }
            (Self::V6 { net, mask }, IpAddr::V4(v4)) => {
                let mapped = v4.to_ipv6_mapped();
                (u128::from(mapped) & mask) == net
            }
        }
    }
}

#[derive(Debug, Clone)]
struct DynamicBlockRule {
    inbound_tag: String,
    outbound_tag: String,
    nets: Vec<IpNet>,
}

/// Thread-safe dynamic source-IP blocklist controlled via `xray api sib` / `RoutingService`.
#[derive(Clone, Default)]
pub struct DynamicBlocklist {
    rules: Arc<RwLock<HashMap<String, Vec<DynamicBlockRule>>>>,
    has_rules: Arc<AtomicBool>,
}

impl DynamicBlocklist {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add_rule(&self, rule_tag: &str, inbound_tag: &str, outbound_tag: &str, raw_ips: &[String]) {
        let nets: Vec<IpNet> = raw_ips.iter().filter_map(|s| IpNet::parse(s)).collect();
        if nets.is_empty() {
            return;
        }
        let tag = if rule_tag.is_empty() {
            "sourceIpBlock".to_string()
        } else {
            rule_tag.to_string()
        };
        let count = nets.len();
        let mut map = self.rules.write().unwrap_or_else(|e| e.into_inner());
        map.entry(tag.clone()).or_default().push(DynamicBlockRule {
            inbound_tag: inbound_tag.to_string(),
            outbound_tag: outbound_tag.to_string(),
            nets,
        });
        self.has_rules.store(true, Ordering::Release);
        log_info!(
            "[api] RoutingService AddRule tag='{}' inbound='{}' outbound='{}' ips={}",
            tag,
            inbound_tag,
            outbound_tag,
            count
        );
    }

    pub fn remove_rule(&self, rule_tag: &str) -> bool {
        let mut map = self.rules.write().unwrap_or_else(|e| e.into_inner());
        let removed = map.remove(rule_tag).is_some();
        self.has_rules.store(!map.is_empty(), Ordering::Release);
        log_info!(
            "[api] RoutingService RemoveRule tag='{}' removed={}",
            rule_tag,
            removed
        );
        removed
    }

    /// Returns `true` if `peer_desc` matches any active blocking rule for `inbound_tag`.
    pub fn is_blocked(&self, inbound_tag: &str, peer_desc: &str) -> bool {
        if !self.has_rules.load(Ordering::Acquire) {
            return false;
        }
        let map = self.rules.read().unwrap_or_else(|e| e.into_inner());
        if map.is_empty() {
            return false;
        }
        let Some(ip) = parse_peer_ip(peer_desc) else {
            return false;
        };
        for rules in map.values() {
            for r in rules {
                let is_block = r.outbound_tag.is_empty()
                    || r.outbound_tag.eq_ignore_ascii_case("blocked")
                    || r.outbound_tag.eq_ignore_ascii_case("block")
                    || r.outbound_tag.eq_ignore_ascii_case("blackhole");
                if !is_block {
                    continue;
                }
                if !r.inbound_tag.is_empty() && r.inbound_tag != inbound_tag {
                    continue;
                }
                if r.nets.iter().any(|net| net.contains(ip)) {
                    return true;
                }
            }
        }
        false
    }
}

pub fn parse_peer_ip(peer_desc: &str) -> Option<IpAddr> {
    let trimmed = peer_desc.trim();
    let stripped = trimmed
        .strip_prefix("tcp:")
        .or_else(|| trimmed.strip_prefix("udp:"))
        .unwrap_or(trimmed);
    if let Ok(ip) = stripped.parse::<IpAddr>() {
        return Some(ip);
    }
    if let Ok(sa) = stripped.parse::<SocketAddr>() {
        return Some(sa.ip());
    }
    // Handle raw IPv4:port or [IPv6]:port fallback
    if let Some(v4) = stripped.split(':').next() {
        if let Ok(ip) = v4.parse::<Ipv4Addr>() {
            return Some(IpAddr::V4(ip));
        }
    }
    if let Some(rest) = stripped.strip_prefix('[') {
        if let Some(v6) = rest.split(']').next() {
            if let Ok(ip) = v6.parse::<Ipv6Addr>() {
                return Some(IpAddr::V6(ip));
            }
        }
    }
    None
}

/// Xray-compatible access logger writing to `log.access` (e.g. `/var/log/xray/access.log`)
/// using `O_APPEND` so external log truncation (`echo -n > /var/log/xray/access.log`) stays safe.
#[derive(Clone, Default)]
pub struct AccessLogger {
    tx: Option<SyncSender<String>>,
}

impl AccessLogger {
    pub fn disabled() -> Self {
        Self { tx: None }
    }

    pub fn open(path: &str) -> Result<Self, String> {
        let trimmed = path.trim();
        if trimmed.is_empty() || trimmed.eq_ignore_ascii_case("none") {
            return Ok(Self::disabled());
        }
        let p = Path::new(trimmed);
        if let Some(parent) = p.parent() {
            if !parent.as_os_str().is_empty() {
                let _ = std::fs::create_dir_all(parent);
            }
        }
        let f = OpenOptions::new()
            .create(true)
            .append(true)
            .open(p)
            .map_err(|e| format!("failed to open access log '{trimmed}': {e}"))?;
        let (tx, rx) = mpsc::sync_channel::<String>(2048);
        let _ = std::thread::Builder::new()
            .name("xray-access-log".to_string())
            .spawn(move || {
                let mut writer = BufWriter::with_capacity(8192, f);
                let mut dirty = false;
                loop {
                    match rx.recv_timeout(Duration::from_millis(250)) {
                        Ok(line) => {
                            let _ = writer.write_all(line.as_bytes());
                            dirty = true;
                            while let Ok(more) = rx.try_recv() {
                                let _ = writer.write_all(more.as_bytes());
                            }
                        }
                        Err(RecvTimeoutError::Timeout) => {
                            if dirty {
                                let _ = writer.flush();
                                dirty = false;
                            }
                        }
                        Err(RecvTimeoutError::Disconnected) => {
                            if dirty {
                                let _ = writer.flush();
                            }
                            break;
                        }
                    }
                }
            });
        Ok(Self { tx: Some(tx) })
    }

    /// Formats a line compatible with Xray-core & VPS scripts (`cekws`, `cekvless`, `cektr`, `limit-ip`):
    /// `YYYY/MM/DD HH:MM:SS tcp:<ip>:<port> accepted <net>:<target> [<tag>] email: <email>`
    pub fn log_accepted(
        &self,
        peer_desc: &str,
        net: &str,
        target: &str,
        tag: &str,
        email: &str,
    ) {
        let Some(tx) = &self.tx else {
            return;
        };
        let line = format_access_line(peer_desc, net, target, tag, email);
        let _ = tx.try_send(line);
    }
}

pub fn format_access_line(
    peer_desc: &str,
    net: &str,
    target: &str,
    tag: &str,
    email: &str,
) -> String {
    let ts = format_utc_timestamp();
    let peer_field = normalize_peer_field(peer_desc);
    if email.is_empty() {
        format!("{ts} {peer_field} accepted {net}:{target} [{tag}]\n")
    } else {
        format!("{ts} {peer_field} accepted {net}:{target} [{tag}] email: {email}\n")
    }
}

fn normalize_peer_field(peer_desc: &str) -> String {
    let trimmed = peer_desc.trim();
    let stripped = trimmed
        .strip_prefix("tcp:")
        .or_else(|| trimmed.strip_prefix("udp:"))
        .unwrap_or(trimmed);
    if stripped.is_empty() || stripped == "unix" {
        return "tcp:127.0.0.1:0".to_string();
    }
    if !stripped.contains(':') {
        format!("tcp:{stripped}:0")
    } else {
        format!("tcp:{stripped}")
    }
}

fn format_utc_timestamp() -> String {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let days = (secs / 86_400) as i64;
    let rem = secs % 86_400;
    let hour = rem / 3600;
    let min = (rem % 3600) / 60;
    let sec = rem % 60;
    let (year, month, day) = civil_from_days(days);
    format!("{year:04}/{month:02}/{day:02} {hour:02}:{min:02}:{sec:02}")
}

/// Howard Hinnant's civil-from-days algorithm (days since 1970-01-01).
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let y = (yoe as i64) + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = y + if m <= 2 { 1 } else { 0 };
    (year, m as u32, d as u32)
}

/// Serves an HTTP/2 gRPC connection for Xray's `StatsService` (`QueryStats` / `GetStats`)
/// and `RoutingService` (`AddRule` / `RemoveRule` for `xray api sib`).
pub async fn serve_stats_api_connection<S>(
    stream: S,
    stats: StatsRegistry,
    blocklist: DynamicBlocklist,
) -> io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let mut h2_conn = server::handshake(stream)
        .await
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("api h2 handshake: {e}")))?;

    while let Some(next) = h2_conn.accept().await {
        let (req, mut respond) = match next {
            Ok(pair) => pair,
            Err(e) => {
                log_debug!("API h2 accept error: {}", e);
                break;
            }
        };

        let path = req.uri().path().to_string();
        let stats = stats.clone();
        let blocklist = blocklist.clone();
        tokio::spawn(async move {
            let mut body = req.into_body();
            let mut raw = BytesMut::new();
            while let Some(chunk_res) = body.data().await {
                match chunk_res {
                    Ok(chunk) => {
                        let _ = body.flow_control().release_capacity(chunk.len());
                        if raw.len() + chunk.len() > MAX_GRPC_API_REQ_BYTES {
                            send_grpc_error(&mut respond, "8", "request too large");
                            return;
                        }
                        raw.extend_from_slice(&chunk);
                    }
                    Err(_) => return,
                }
            }

            if raw.len() < 5 {
                send_grpc_error(&mut respond, "3", "truncated gRPC frame");
                return;
            }
            let _compressed = raw[0];
            let msg_len = u32::from_be_bytes([raw[1], raw[2], raw[3], raw[4]]) as usize;
            if raw.len() < 5 + msg_len {
                send_grpc_error(&mut respond, "3", "incomplete gRPC payload");
                return;
            }
            let payload = &raw[5..5 + msg_len];

            let resp_proto = match path.as_str() {
                "/xray.app.stats.command.StatsService/QueryStats" => {
                    let (pattern, reset) = decode_stats_request(payload);
                    let items = stats.query_stats(&pattern, reset);
                    encode_query_stats_response(&items)
                }
                "/xray.app.stats.command.StatsService/GetStats" => {
                    let (name, reset) = decode_stats_request(payload);
                    let item = stats.get_stat(&name, reset);
                    encode_get_stats_response(item.as_ref())
                }
                "/xray.app.router.command.RoutingService/AddRule" => {
                    match decode_add_rule_request(payload) {
                        Some(rule) => {
                            blocklist.add_rule(
                                &rule.ruletag,
                                &rule.inbound,
                                &rule.outbound,
                                &rule.source_ips,
                            );
                            Vec::new()
                        }
                        None => {
                            send_grpc_error(&mut respond, "3", "invalid AddRuleRequest payload");
                            return;
                        }
                    }
                }
                "/xray.app.router.command.RoutingService/RemoveRule" => {
                    let tag = decode_remove_rule_request(payload);
                    if !tag.is_empty() {
                        blocklist.remove_rule(&tag);
                    }
                    Vec::new()
                }
                _ => {
                    send_grpc_error(&mut respond, "12", "unimplemented RPC");
                    return;
                }
            };

            let mut frame = BytesMut::with_capacity(5 + resp_proto.len());
            frame.put_u8(0);
            frame.put_u32(resp_proto.len() as u32);
            frame.put_slice(&resp_proto);

            let resp = Response::builder()
                .status(StatusCode::OK)
                .header("content-type", "application/grpc")
                .body(())
                .unwrap();

            if let Ok(mut send) = respond.send_response(resp, false) {
                let _ = send_all_bytes(&mut send, frame.freeze()).await;
                let mut trailers = HeaderMap::new();
                trailers.insert("grpc-status", HeaderValue::from_static("0"));
                let _ = send.send_trailers(trailers);
            }
        });
    }

    Ok(())
}

fn send_grpc_error(respond: &mut server::SendResponse<Bytes>, code: &'static str, msg: &'static str) {
    let resp = Response::builder()
        .status(StatusCode::OK)
        .header("content-type", "application/grpc")
        .header("grpc-status", code)
        .header("grpc-message", msg)
        .body(())
        .unwrap();
    let _ = respond.send_response(resp, true);
}

async fn send_all_bytes(send: &mut h2::SendStream<Bytes>, mut data: Bytes) -> io::Result<()> {
    while !data.is_empty() {
        send.reserve_capacity(data.len());
        let cap = std::future::poll_fn(|cx| send.poll_capacity(cx))
            .await
            .ok_or_else(|| io::Error::new(io::ErrorKind::BrokenPipe, "h2 stream closed"))?
            .map_err(|e| io::Error::new(io::ErrorKind::BrokenPipe, format!("h2 capacity: {e}")))?;
        let chunk = data.split_to(cap.min(data.len()));
        send.send_data(chunk, false)
            .map_err(|e| io::Error::new(io::ErrorKind::BrokenPipe, format!("h2 send: {e}")))?;
    }
    Ok(())
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SibRulePayload {
    pub ruletag: String,
    pub inbound: String,
    pub outbound: String,
    pub source_ips: Vec<String>,
}

/// Encodes `AddRuleRequest { TypedMessage config = 1; bool shouldAppend = 2; }`
/// embedding a JSON `SibRulePayload` inside `TypedMessage { type = "xray-lite.sib", value = json }`.
pub fn encode_add_rule_request(
    ruletag: &str,
    inbound: &str,
    outbound: &str,
    source_ips: &[String],
) -> Vec<u8> {
    let payload = SibRulePayload {
        ruletag: ruletag.to_string(),
        inbound: inbound.to_string(),
        outbound: outbound.to_string(),
        source_ips: source_ips.to_vec(),
    };
    let json = serde_json::to_vec(&payload).unwrap_or_default();
    let type_name = b"xray-lite.sib";

    let mut typed = Vec::with_capacity(type_name.len() + json.len() + 16);
    typed.push(0x0A); // TypedMessage.type = 1
    write_varint(&mut typed, type_name.len() as u64);
    typed.extend_from_slice(type_name);
    typed.push(0x12); // TypedMessage.value = 2
    write_varint(&mut typed, json.len() as u64);
    typed.extend_from_slice(&json);

    let mut req = Vec::with_capacity(typed.len() + 12);
    req.push(0x0A); // AddRuleRequest.config = 1
    write_varint(&mut req, typed.len() as u64);
    req.extend_from_slice(&typed);
    req.push(0x10); // AddRuleRequest.shouldAppend = 2
    req.push(1);
    req
}

pub fn decode_add_rule_request(mut data: &[u8]) -> Option<SibRulePayload> {
    while !data.is_empty() {
        let tag = read_varint(&mut data)?;
        let field_num = tag >> 3;
        let wire_type = tag & 0x07;
        match (field_num, wire_type) {
            (1, 2) => {
                let len = read_varint(&mut data)? as usize;
                if data.len() < len {
                    return None;
                }
                let mut typed = &data[..len];
                data.advance(len);
                // Extract TypedMessage.value (field 2)
                while !typed.is_empty() {
                    let ttag = read_varint(&mut typed)?;
                    let tfield = ttag >> 3;
                    let twire = ttag & 0x07;
                    if tfield == 2 && twire == 2 {
                        let vlen = read_varint(&mut typed)? as usize;
                        if typed.len() < vlen {
                            return None;
                        }
                        if let Ok(parsed) = serde_json::from_slice::<SibRulePayload>(&typed[..vlen]) {
                            return Some(parsed);
                        }
                        typed.advance(vlen);
                    } else {
                        skip_field(&mut typed, twire)?;
                    }
                }
            }
            _ => skip_field(&mut data, wire_type)?,
        }
    }
    None
}

/// Encodes `RemoveRuleRequest { string ruleTag = 1; }`.
pub fn encode_remove_rule_request(rule_tag: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(rule_tag.len() + 8);
    if !rule_tag.is_empty() {
        out.push(0x0A);
        write_varint(&mut out, rule_tag.len() as u64);
        out.extend_from_slice(rule_tag.as_bytes());
    }
    out
}

/// Decodes `RemoveRuleRequest { string ruleTag = 1; }`.
pub fn decode_remove_rule_request(data: &[u8]) -> String {
    decode_stats_request(data).0
}

/// Encodes `QueryStatsRequest` / `GetStatsRequest { string field1 = 1; bool reset = 2; }`.
pub fn encode_stats_request(text: &str, reset: bool) -> Vec<u8> {
    let mut out = Vec::with_capacity(text.len() + 12);
    if !text.is_empty() {
        out.push(0x0A);
        write_varint(&mut out, text.len() as u64);
        out.extend_from_slice(text.as_bytes());
    }
    if reset {
        out.push(0x10);
        out.push(1);
    }
    out
}

/// Decodes protobuf `QueryStatsRequest { string pattern = 1; bool reset = 2; }`
/// (identical wire layout to `GetStatsRequest { string name = 1; bool reset = 2; }`).
pub fn decode_stats_request(mut data: &[u8]) -> (String, bool) {
    let mut text = String::new();
    let mut reset = false;

    while !data.is_empty() {
        let Some(tag) = read_varint(&mut data) else {
            break;
        };
        let field_num = tag >> 3;
        let wire_type = tag & 0x07;
        match (field_num, wire_type) {
            (1, 2) => {
                let Some(len) = read_varint(&mut data) else {
                    break;
                };
                let len = len as usize;
                if data.len() < len {
                    break;
                }
                if let Ok(s) = std::str::from_utf8(&data[..len]) {
                    text = s.to_string();
                }
                data.advance(len);
            }
            (2, 0) => {
                if let Some(v) = read_varint(&mut data) {
                    reset = v != 0;
                } else {
                    break;
                }
            }
            _ => {
                if skip_field(&mut data, wire_type).is_none() {
                    break;
                }
            }
        }
    }

    (text, reset)
}

/// Decodes `QueryStatsResponse { repeated Stat stat = 1; }` or `GetStatsResponse { Stat stat = 1; }`.
pub fn decode_query_stats_response(mut data: &[u8]) -> Vec<(String, i64)> {
    let mut out = Vec::new();
    while !data.is_empty() {
        let Some(tag) = read_varint(&mut data) else {
            break;
        };
        let field_num = tag >> 3;
        let wire_type = tag & 0x07;
        if field_num == 1 && wire_type == 2 {
            let Some(len) = read_varint(&mut data) else {
                break;
            };
            let len = len as usize;
            if data.len() < len {
                break;
            }
            if let Some(stat) = decode_stat(&data[..len]) {
                out.push(stat);
            }
            data.advance(len);
        } else if skip_field(&mut data, wire_type).is_none() {
            break;
        }
    }
    out
}

fn decode_stat(mut data: &[u8]) -> Option<(String, i64)> {
    let mut name = String::new();
    let mut value = 0i64;
    while !data.is_empty() {
        let tag = read_varint(&mut data)?;
        let field_num = tag >> 3;
        let wire_type = tag & 0x07;
        match (field_num, wire_type) {
            (1, 2) => {
                let len = read_varint(&mut data)? as usize;
                if data.len() < len {
                    return None;
                }
                if let Ok(s) = std::str::from_utf8(&data[..len]) {
                    name = s.to_string();
                }
                data.advance(len);
            }
            (2, 0) => {
                value = read_varint(&mut data)? as i64;
            }
            _ => skip_field(&mut data, wire_type)?,
        }
    }
    if name.is_empty() {
        None
    } else {
        Some((name, value))
    }
}

/// Encodes `QueryStatsResponse { repeated Stat stat = 1; }`.
pub fn encode_query_stats_response(items: &[(String, i64)]) -> Vec<u8> {
    let mut out = Vec::new();
    for (name, value) in items {
        let stat_bytes = encode_stat(name, *value);
        out.push(0x0A); // field 1, wire type 2
        write_varint(&mut out, stat_bytes.len() as u64);
        out.extend_from_slice(&stat_bytes);
    }
    out
}

/// Encodes `GetStatsResponse { Stat stat = 1; }`.
pub fn encode_get_stats_response(item: Option<&(String, i64)>) -> Vec<u8> {
    let mut out = Vec::new();
    if let Some((name, value)) = item {
        let stat_bytes = encode_stat(name, *value);
        out.push(0x0A); // field 1, wire type 2
        write_varint(&mut out, stat_bytes.len() as u64);
        out.extend_from_slice(&stat_bytes);
    }
    out
}

fn encode_stat(name: &str, value: i64) -> Vec<u8> {
    let mut out = Vec::with_capacity(name.len() + 16);
    if !name.is_empty() {
        out.push(0x0A); // field 1 (string name), wire type 2
        write_varint(&mut out, name.len() as u64);
        out.extend_from_slice(name.as_bytes());
    }
    if value != 0 {
        out.push(0x10); // field 2 (int64 value), wire type 0
        write_varint(&mut out, value as u64);
    }
    out
}

fn skip_field(data: &mut &[u8], wire_type: u64) -> Option<()> {
    match wire_type {
        0 => {
            read_varint(data)?;
            Some(())
        }
        1 => {
            if data.len() < 8 {
                return None;
            }
            data.advance(8);
            Some(())
        }
        2 => {
            let len = read_varint(data)? as usize;
            if data.len() < len {
                return None;
            }
            data.advance(len);
            Some(())
        }
        5 => {
            if data.len() < 4 {
                return None;
            }
            data.advance(4);
            Some(())
        }
        _ => None,
    }
}

fn read_varint(data: &mut &[u8]) -> Option<u64> {
    let mut result = 0u64;
    let mut shift = 0u32;
    while !data.is_empty() && shift < 64 {
        let b = data[0];
        data.advance(1);
        result |= ((b & 0x7F) as u64) << shift;
        if b & 0x80 == 0 {
            return Some(result);
        }
        shift += 7;
    }
    None
}

fn write_varint(out: &mut Vec<u8>, mut v: u64) {
    loop {
        let mut b = (v & 0x7F) as u8;
        v >>= 7;
        if v != 0 {
            b |= 0x80;
        }
        out.push(b);
        if v == 0 {
            break;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stats_query_and_reset_roundtrip() {
        let reg = StatsRegistry::new();
        let c = reg.counters_for("alice").unwrap();
        c.add_uplink(1200);
        c.add_downlink(3400);

        let all = reg.query_stats("user>>>", false);
        assert_eq!(all.len(), 2);

        let dl = reg.query_stats(">>>traffic>>>downlink", true);
        assert_eq!(dl, vec![("user>>>alice>>>traffic>>>downlink".to_string(), 3400)]);

        let dl_after = reg.query_stats(">>>traffic>>>downlink", false);
        assert!(dl_after.is_empty());
        let ul_after = reg.query_stats("user>>>", false);
        assert_eq!(ul_after, vec![("user>>>alice>>>traffic>>>uplink".to_string(), 1200)]);
    }

    #[test]
    fn protobuf_stats_codec_matches_xray() {
        let req = encode_stats_request("user>>>", true);
        let (pat, reset) = decode_stats_request(&req);
        assert_eq!(pat, "user>>>");
        assert!(reset);

        let resp = encode_query_stats_response(&[
            ("user>>>bob>>>traffic>>>downlink".to_string(), 4096),
        ]);
        let decoded = decode_query_stats_response(&resp);
        assert_eq!(decoded, vec![("user>>>bob>>>traffic>>>downlink".to_string(), 4096)]);
    }

    #[test]
    fn dynamic_blocklist_sib_add_match_and_remove() {
        let bl = DynamicBlocklist::new();
        let encoded = encode_add_rule_request(
            "multilogin",
            "",
            "blocked",
            &["114.122.10.5".to_string(), "103.55.1.0/24".to_string()],
        );
        let decoded = decode_add_rule_request(&encoded).unwrap();
        bl.add_rule(&decoded.ruletag, &decoded.inbound, &decoded.outbound, &decoded.source_ips);

        assert!(bl.is_blocked("vless-ws", "114.122.10.5:51234"));
        assert!(bl.is_blocked("vmess-ws", "103.55.1.99"));
        assert!(!bl.is_blocked("vless-ws", "114.122.10.6:51234"));

        let rm = encode_remove_rule_request("multilogin");
        let rm_tag = decode_remove_rule_request(&rm);
        assert!(bl.remove_rule(&rm_tag));
        assert!(!bl.is_blocked("vless-ws", "114.122.10.5:51234"));
    }

    #[test]
    fn access_log_line_matches_vps_script_awk_cut_fields() {
        let line = format_access_line("114.122.10.5", "tcp", "example.com:443", "vless-ws", "alice");
        let fields: Vec<&str> = line.split_whitespace().collect();
        assert_eq!(fields[1].len(), 8);
        assert_eq!(&fields[1][2..3], ":");
        assert_eq!(fields[2], "tcp:114.122.10.5:0");
        let ip = fields[2].replace("tcp:", "");
        assert_eq!(ip.split(':').next().unwrap(), "114.122.10.5");
        assert!(line.contains("email: alice"));
    }
}
