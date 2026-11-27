use std::collections::HashMap;
use std::fs;
use std::path::Path;
use std::time::Duration;

use serde::Deserialize;

use crate::logger::LogLevel;

/// Standard Xray-core compatible JSON configuration.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct XrayConfig {
    #[serde(default)]
    pub log: Option<LogConfig>,
    #[serde(default)]
    pub inbounds: Vec<InboundConfig>,
    #[serde(default)]
    pub outbounds: Vec<OutboundConfig>,
    #[serde(default)]
    pub routing: Option<RoutingConfig>,
    #[serde(default)]
    pub policy: Option<PolicyConfig>,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LogConfig {
    #[serde(default = "default_loglevel")]
    pub loglevel: String,
    #[serde(default)]
    pub access: String,
    #[serde(default)]
    pub error: String,
}

fn default_loglevel() -> String {
    "warning".to_string()
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct InboundConfig {
    #[serde(default)]
    pub tag: String,
    #[serde(default = "default_listen")]
    pub listen: String,
    #[serde(default)]
    pub port: PortSpec,
    pub protocol: String,
    #[serde(default)]
    pub settings: InboundSettings,
    #[serde(default)]
    pub stream_settings: Option<StreamSettings>,
}

fn default_listen() -> String {
    "0.0.0.0".to_string()
}

/// Xray allows `port` as integer (`443`) or string (`"443"`) or omitted for Unix sockets.
#[derive(Debug, Clone, Deserialize)]
#[serde(untagged)]
pub enum PortSpec {
    Num(u16),
    Str(String),
}

impl Default for PortSpec {
    fn default() -> Self {
        Self::Num(0)
    }
}

impl PortSpec {
    pub fn as_u16(&self) -> Result<u16, String> {
        match self {
            Self::Num(p) => Ok(*p),
            Self::Str(s) => s
                .trim()
                .parse::<u16>()
                .map_err(|_| format!("invalid port '{s}'")),
        }
    }
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct InboundSettings {
    #[serde(default)]
    pub clients: Vec<ClientConfig>,
    #[serde(default)]
    pub decryption: Option<String>,
    #[serde(default)]
    pub fallbacks: Vec<FallbackConfig>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ClientConfig {
    /// UUID for VLESS / VMess.
    #[serde(default)]
    pub id: String,
    /// Password for Trojan.
    #[serde(default)]
    pub password: String,
    #[serde(default)]
    pub email: String,
    #[serde(default)]
    pub flow: String,
    #[serde(default)]
    pub level: u32,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FallbackConfig {
    #[serde(default)]
    pub alpn: String,
    #[serde(default)]
    pub path: String,
    pub dest: DestSpec,
    #[serde(default)]
    pub xver: u8,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(untagged)]
pub enum DestSpec {
    Port(u16),
    Addr(String),
}

impl DestSpec {
    pub fn to_target_string(&self) -> String {
        match self {
            Self::Port(p) => format!("127.0.0.1:{p}"),
            Self::Addr(s) => {
                if s.contains(':') || s.starts_with('/') {
                    s.clone()
                } else {
                    format!("127.0.0.1:{s}")
                }
            }
        }
    }
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StreamSettings {
    #[serde(default = "default_network")]
    pub network: String,
    #[serde(default = "default_security")]
    pub security: String,
    #[serde(default)]
    pub tls_settings: Option<TlsSettings>,
    #[serde(default)]
    pub tcp_settings: Option<TcpSettings>,
    #[serde(default)]
    pub ws_settings: Option<WsSettings>,
    #[serde(default)]
    pub httpupgrade_settings: Option<HttpUpgradeSettings>,
    #[serde(default)]
    pub grpc_settings: Option<GrpcSettings>,
    #[serde(default, alias = "splithttpSettings")]
    pub xhttp_settings: Option<XhttpSettings>,
    #[serde(default)]
    pub sockopt: Option<SockoptSettings>,
}

fn default_network() -> String {
    "tcp".to_string()
}

fn default_security() -> String {
    "none".to_string()
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TlsSettings {
    #[serde(default)]
    pub server_name: String,
    #[serde(default)]
    pub alpn: Vec<String>,
    #[serde(default)]
    pub certificates: Vec<CertificateConfig>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CertificateConfig {
    pub certificate_file: String,
    pub key_file: String,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TcpSettings {
    #[serde(default)]
    pub accept_proxy_protocol: bool,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WsSettings {
    #[serde(default)]
    pub accept_proxy_protocol: bool,
    #[serde(default = "default_root_path")]
    pub path: String,
    #[serde(default)]
    pub host: String,
    #[serde(default)]
    pub headers: HashMap<String, String>,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HttpUpgradeSettings {
    #[serde(default)]
    pub accept_proxy_protocol: bool,
    #[serde(default = "default_root_path")]
    pub path: String,
    #[serde(default)]
    pub host: String,
    #[serde(default)]
    pub headers: HashMap<String, String>,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GrpcSettings {
    #[serde(default)]
    pub service_name: String,
    #[serde(default)]
    pub accept_proxy_protocol: bool,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct XhttpSettings {
    #[serde(default)]
    pub accept_proxy_protocol: bool,
    #[serde(default = "default_root_path")]
    pub path: String,
    #[serde(default)]
    pub host: String,
    #[serde(default)]
    pub mode: String,
    #[serde(default)]
    pub no_sse_header: bool,
    #[serde(default)]
    pub sc_max_each_post_bytes: Option<usize>,
    #[serde(default)]
    pub sc_max_buffered_posts: Option<usize>,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SockoptSettings {
    #[serde(default)]
    pub accept_proxy_protocol: bool,
}

fn default_root_path() -> String {
    "/".to_string()
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OutboundConfig {
    #[serde(default)]
    pub tag: String,
    pub protocol: String,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RoutingConfig {
    #[serde(default)]
    pub rules: Vec<RoutingRule>,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RoutingRule {
    #[serde(default)]
    pub ip: Vec<String>,
    #[serde(default)]
    pub protocol: Vec<String>,
    #[serde(default)]
    pub outbound_tag: String,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PolicyConfig {
    #[serde(default)]
    pub levels: HashMap<String, PolicyLevelConfig>,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PolicyLevelConfig {
    #[serde(default)]
    pub handshake: Option<u64>,
    #[serde(default)]
    pub conn_idle: Option<u64>,
}

impl StreamSettings {
    pub fn accept_proxy_protocol(&self) -> bool {
        if self
            .sockopt
            .as_ref()
            .map(|s| s.accept_proxy_protocol)
            .unwrap_or(false)
        {
            return true;
        }
        match self.network.to_ascii_lowercase().as_str() {
            "tcp" | "raw" => self
                .tcp_settings
                .as_ref()
                .map(|t| t.accept_proxy_protocol)
                .unwrap_or(false),
            "ws" | "websocket" => self
                .ws_settings
                .as_ref()
                .map(|w| w.accept_proxy_protocol)
                .unwrap_or(false),
            "httpupgrade" => self
                .httpupgrade_settings
                .as_ref()
                .map(|h| h.accept_proxy_protocol)
                .unwrap_or(false),
            "grpc" | "gun" => self
                .grpc_settings
                .as_ref()
                .map(|g| g.accept_proxy_protocol)
                .unwrap_or(false),
            "xhttp" | "splithttp" => self
                .xhttp_settings
                .as_ref()
                .map(|x| x.accept_proxy_protocol)
                .unwrap_or(false),
            _ => false,
        }
    }
}

impl XrayConfig {
    pub fn from_file(path: &Path) -> Result<Self, String> {
        let raw = fs::read_to_string(path)
            .map_err(|e| format!("failed to read config '{}': {e}", path.display()))?;
        Self::from_str_jsonc(&raw, &path.display().to_string())
    }

    pub fn from_str_jsonc(raw: &str, source_label: &str) -> Result<Self, String> {
        let cleaned = strip_json_comments(raw);
        // Deserialize via serde_json::Value first so duplicate top-level keys
        // (common in VPS auto-script config.json files) follow Go/Xray last-key-wins semantics.
        let val: serde_json::Value = serde_json::from_str(&cleaned)
            .map_err(|e| format!("invalid JSON in '{source_label}': {e}"))?;
        let cfg: XrayConfig = serde_json::from_value(val)
            .map_err(|e| format!("invalid Xray config in '{source_label}': {e}"))?;
        cfg.validate()?;
        Ok(cfg)
    }

    pub fn log_level(&self) -> LogLevel {
        self.log
            .as_ref()
            .map(|l| LogLevel::parse(&l.loglevel))
            .unwrap_or(LogLevel::Warning)
    }

    pub fn access_log_path(&self) -> Option<&str> {
        let p = self.log.as_ref()?.access.trim();
        if p.is_empty() || p.eq_ignore_ascii_case("none") {
            None
        } else {
            Some(p)
        }
    }

    pub fn error_log_path(&self) -> Option<&str> {
        let p = self.log.as_ref()?.error.trim();
        if p.is_empty() || p.eq_ignore_ascii_case("none") {
            None
        } else {
            Some(p)
        }
    }

    pub fn conn_idle_timeout(&self) -> Duration {
        let secs = self
            .policy
            .as_ref()
            .and_then(|p| p.levels.get("0"))
            .and_then(|l| l.conn_idle)
            .unwrap_or(300)
            .max(10);
        Duration::from_secs(secs)
    }

    pub fn block_bittorrent(&self) -> bool {
        let Some(routing) = &self.routing else {
            return false;
        };
        for rule in &routing.rules {
            let is_block = rule.outbound_tag.eq_ignore_ascii_case("blocked")
                || rule.outbound_tag.eq_ignore_ascii_case("block")
                || rule.outbound_tag.eq_ignore_ascii_case("blackhole");
            if is_block
                && rule
                    .protocol
                    .iter()
                    .any(|p| p.eq_ignore_ascii_case("bittorrent"))
            {
                return true;
            }
        }
        false
    }

    pub fn block_private_ips(&self) -> bool {
        // Default to true if no routing specified, or if routing blocks geoip:private / RFC1918 CIDRs.
        let Some(routing) = &self.routing else {
            return true;
        };
        for rule in &routing.rules {
            let is_block = rule.outbound_tag.eq_ignore_ascii_case("blocked")
                || rule.outbound_tag.eq_ignore_ascii_case("block")
                || rule.outbound_tag.eq_ignore_ascii_case("blackhole");
            if !is_block {
                continue;
            }
            if rule.ip.iter().any(|ip| {
                matches!(
                    ip.as_str(),
                    "geoip:private"
                        | "10.0.0.0/8"
                        | "127.0.0.0/8"
                        | "172.16.0.0/12"
                        | "192.168.0.0/16"
                        | "::1/128"
                        | "fc00::/7"
                        | "fe80::/10"
                )
            }) {
                return true;
            }
        }
        false
    }

    pub fn validate(&self) -> Result<(), String> {
        if self.inbounds.is_empty() {
            return Err("config has no inbounds".to_string());
        }
        let mut active_proxy_inbounds = 0usize;
        for (idx, inbound) in self.inbounds.iter().enumerate() {
            let proto = inbound.protocol.to_ascii_lowercase();
            match proto.as_str() {
                "vless" | "vmess" | "trojan" => {
                    active_proxy_inbounds += 1;
                }
                "dokodemo-door" => {
                    // Accepted for Xray StatsService API listener (e.g. tag="api" on 127.0.0.1:10000).
                    if !is_unix_listen(&inbound.listen) {
                        let port = inbound.port.as_u16()?;
                        if port == 0 {
                            return Err(format!(
                                "inbound[{idx}] ('{}'): port must be > 0 for dokodemo-door",
                                inbound.tag
                            ));
                        }
                    }
                    continue;
                }
                "shadowsocks" => {
                    // Gracefully skipped at runtime so standard VPS config.json files remain drop-in compatible.
                    continue;
                }
                _ => {
                    return Err(format!(
                        "inbound[{idx}] ('{}'): unsupported protocol '{}' (supported: vless, vmess, trojan, dokodemo-door[api])",
                        inbound.tag, inbound.protocol
                    ));
                }
            }
            if !is_unix_listen(&inbound.listen) {
                let port = inbound.port.as_u16()?;
                if port == 0 {
                    return Err(format!(
                        "inbound[{idx}] ('{}'): port must be > 0 for TCP listen '{}'",
                        inbound.tag, inbound.listen
                    ));
                }
            }
            if let Some(ss) = &inbound.stream_settings {
                let net = ss.network.to_ascii_lowercase();
                if !matches!(
                    net.as_str(),
                    "" | "tcp" | "raw" | "ws" | "websocket" | "httpupgrade" | "grpc" | "gun" | "xhttp" | "splithttp"
                ) {
                    return Err(format!(
                        "inbound[{idx}] ('{}'): unsupported network '{}'",
                        inbound.tag, ss.network
                    ));
                }
                let sec = ss.security.to_ascii_lowercase();
                if !matches!(sec.as_str(), "" | "none" | "tls") {
                    return Err(format!(
                        "inbound[{idx}] ('{}'): unsupported security '{}' (supported: none, tls)",
                        inbound.tag, ss.security
                    ));
                }
                if sec == "tls" {
                    let certs = ss
                        .tls_settings
                        .as_ref()
                        .map(|t| t.certificates.len())
                        .unwrap_or(0);
                    if certs == 0 {
                        return Err(format!(
                            "inbound[{idx}] ('{}'): security=tls requires tlsSettings.certificates",
                            inbound.tag
                        ));
                    }
                }
            }
        }
        if active_proxy_inbounds == 0 {
            return Err("config has no supported proxy inbounds (vless, vmess, trojan)".to_string());
        }
        Ok(())
    }
}

pub fn is_unix_listen(listen: &str) -> bool {
    listen.starts_with('/') || listen.starts_with('@')
}

/// Strips `//` line comments, `#` line comments (used by Xray VPS auto-scripts for markers like
/// `#vless`, `### user exp`, `#& user exp`, `#! user exp`), and `/* ... */` block comments
/// while preserving string literals untouched.
pub fn strip_json_comments(input: &str) -> String {
    let bytes = input.as_bytes();
    let mut out = String::with_capacity(input.len());
    let mut i = 0;
    let mut in_string = false;
    let mut escaped = false;

    while i < bytes.len() {
        let c = bytes[i];
        if in_string {
            out.push(c as char);
            if escaped {
                escaped = false;
            } else if c == b'\\' {
                escaped = true;
            } else if c == b'"' {
                in_string = false;
            }
            i += 1;
            continue;
        }

        if c == b'"' {
            in_string = true;
            out.push('"');
            i += 1;
        } else if c == b'#' {
            i += 1;
            while i < bytes.len() && bytes[i] != b'\n' {
                i += 1;
            }
        } else if c == b'/' && i + 1 < bytes.len() && bytes[i + 1] == b'/' {
            i += 2;
            while i < bytes.len() && bytes[i] != b'\n' {
                i += 1;
            }
        } else if c == b'/' && i + 1 < bytes.len() && bytes[i + 1] == b'*' {
            i += 2;
            while i + 1 < bytes.len() && !(bytes[i] == b'*' && bytes[i + 1] == b'/') {
                if bytes[i] == b'\n' {
                    out.push('\n');
                }
                i += 1;
            }
            i = (i + 2).min(bytes.len());
        } else {
            out.push(c as char);
            i += 1;
        }
    }
    out
}

/// Parses a standard UUID string (`xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx`) into 16 bytes.
pub fn parse_uuid(s: &str) -> Option<[u8; 16]> {
    let hex: String = s.chars().filter(|&c| c != '-').collect();
    if hex.len() != 32 {
        return None;
    }
    let mut out = [0u8; 16];
    for (i, chunk) in hex.as_bytes().chunks_exact(2).enumerate() {
        let hi = hex_nibble(chunk[0])?;
        let lo = hex_nibble(chunk[1])?;
        out[i] = (hi << 4) | lo;
    }
    Some(out)
}

fn hex_nibble(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_xray_jsonc_config() {
        let raw = r#"
        {
            // Comment like standard Xray config
            "log": { "loglevel": "info", "access": "/var/log/xray/access.log" },
            "inbounds": [
                {
                    "tag": "vless-ws",
                    "listen": "127.0.0.1",
                    "port": 10001,
                    "protocol": "vless",
                    "settings": {
                        "clients": [
                            { "id": "b831381d-6324-4d53-ad4f-8cda48b30811", "email": "user1" }
                        ],
                        "decryption": "none"
                    },
                    "streamSettings": {
                        "network": "ws",
                        "security": "none",
                        "wsSettings": {
                            "acceptProxyProtocol": true,
                            "path": "/vless"
                        }
                    }
                }
            ]
        }
        "#;
        let cfg = XrayConfig::from_str_jsonc(raw, "test").unwrap();
        assert_eq!(cfg.inbounds.len(), 1);
        assert_eq!(cfg.access_log_path(), Some("/var/log/xray/access.log"));
        assert!(cfg.inbounds[0].stream_settings.as_ref().unwrap().accept_proxy_protocol());
    }

    #[test]
    fn parses_vps_autoscript_config_with_hash_markers_and_duplicate_keys() {
        let raw = r#"
        {
          "log": {
            "loglevel": "warning",
            "error": "/var/log/xray/error.log",
            "access": "/var/log/xray/access.log"
          },
          "api": { "services": ["StatsService"], "tag": "api" },
          "stats": {},
          "inbounds": [
            {
              "listen": "127.0.0.1",
              "port": 10000,
              "protocol": "dokodemo-door",
              "settings": { "address": "127.0.0.1" },
              "tag": "api"
            },
            {
              "listen": "127.0.0.1",
              "port": "10001",
              "protocol": "vless",
              "settings": {
                "decryption": "none",
                "clients": [
                  {
                    "id": "1d1c1d94-6987-4658-a4dc-8821a30fe7e0"
#vless
#& alice 2027-01-01
                  },{"id": "b831381d-6324-4d53-ad4f-8cda48b30811","email": "alice"
                  }
                ]
              },
              "streamSettings": {
                "network": "ws",
                "wsSettings": { "path": "/vless" }
              }
            },
            {
              "listen": "127.0.0.1",
              "port": "10004",
              "protocol": "shadowsocks",
              "settings": {
                "clients": [
                  { "method": "aes-128-gcm", "password": "secret"
#ssws
                  }
                ]
              },
              "streamSettings": { "network": "ws", "wsSettings": { "path": "/ss-ws" } }
            }
          ],
          "routing": {
            "rules": [
              {
                "type": "field",
                "ip": ["10.0.0.0/8", "192.168.0.0/16"],
                "outboundTag": "blocked"
              }
            ]
          },
          "stats": {},
          "api": { "services": ["StatsService"], "tag": "api" }
        }
        "#;
        let cfg = XrayConfig::from_str_jsonc(raw, "vip-config").unwrap();
        assert_eq!(cfg.inbounds.len(), 3);
        assert_eq!(cfg.inbounds[1].settings.clients.len(), 2);
        assert_eq!(cfg.inbounds[1].settings.clients[1].email, "alice");
        assert!(cfg.block_private_ips());
    }

    #[test]
    fn parses_uuid_bytes() {
        let u = parse_uuid("b831381d-6324-4d53-ad4f-8cda48b30811").unwrap();
        assert_eq!(u[0], 0xb8);
        assert_eq!(u[15], 0x11);
    }
}
