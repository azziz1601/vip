pub mod mux;
pub mod trojan;
pub mod vless;
pub mod vmess;

use std::collections::HashMap;
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};

use aes::cipher::KeyInit as AesKeyInit;
use aes::Aes128;
use sha2::{Digest, Sha224};

use crate::config::{parse_uuid, ClientConfig, FallbackConfig, InboundConfig};
use crate::log_warn;
use crate::protocol::vmess::{derive_auth_id_key, derive_cmd_key, VmessUser};
use crate::stats::{AccessLogger, StatsRegistry};
use crate::transport::BoxedStream;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InboundProtocol {
    Vless,
    Vmess,
    Trojan,
}

impl InboundProtocol {
    pub fn parse(s: &str) -> Option<Self> {
        match s.to_ascii_lowercase().as_str() {
            "vless" => Some(Self::Vless),
            "vmess" => Some(Self::Vmess),
            "trojan" => Some(Self::Trojan),
            _ => None,
        }
    }
}

/// Hot-reloadable user store for a single inbound.
#[derive(Default)]
pub struct InboundUsers {
    pub vless_ids: HashMap<[u8; 16], String>,
    pub trojan_keys: HashMap<[u8; 56], String>,
    pub vmess_users: Vec<VmessUser>,
}

impl InboundUsers {
    pub fn from_clients(protocol: InboundProtocol, clients: &[ClientConfig]) -> Self {
        let mut store = Self::default();
        for c in clients {
            match protocol {
                InboundProtocol::Vless => {
                    if let Some(uuid) = parse_uuid(&c.id) {
                        store.vless_ids.insert(uuid, c.email.clone());
                    } else if !c.id.is_empty() {
                        log_warn!("ignoring invalid VLESS UUID '{}'", c.id);
                    }
                }
                InboundProtocol::Vmess => {
                    if let Some(uuid) = parse_uuid(&c.id) {
                        let cmd_key = derive_cmd_key(&uuid);
                        let auth_id_key = derive_auth_id_key(&cmd_key);
                        let auth_id_cipher = Aes128::new((&auth_id_key).into());
                        store.vmess_users.push(VmessUser {
                            uuid,
                            cmd_key,
                            auth_id_cipher,
                            email: c.email.clone(),
                        });
                    } else if !c.id.is_empty() {
                        log_warn!("ignoring invalid VMess UUID '{}'", c.id);
                    }
                }
                InboundProtocol::Trojan => {
                    if !c.password.is_empty() {
                        let key = trojan_password_hash(&c.password);
                        store.trojan_keys.insert(key, c.email.clone());
                    }
                }
            }
        }
        store
    }

    pub fn count(&self, protocol: InboundProtocol) -> usize {
        match protocol {
            InboundProtocol::Vless => self.vless_ids.len(),
            InboundProtocol::Vmess => self.vmess_users.len(),
            InboundProtocol::Trojan => self.trojan_keys.len(),
        }
    }
}

/// Computes lowercase hex SHA-224 of a Trojan password (56 ASCII bytes).
pub fn trojan_password_hash(password: &str) -> [u8; 56] {
    let digest = Sha224::digest(password.as_bytes());
    let mut out = [0u8; 56];
    const HEX: &[u8; 16] = b"0123456789abcdef";
    for (i, &b) in digest.iter().enumerate() {
        out[i * 2] = HEX[(b >> 4) as usize];
        out[i * 2 + 1] = HEX[(b & 0x0F) as usize];
    }
    out
}

/// Anti-replay cache for VMess AEAD AuthIDs (120-second window).
pub struct ReplayCache {
    seen: Mutex<HashMap<[u8; 16], Instant>>,
}

impl ReplayCache {
    pub fn new() -> Self {
        Self {
            seen: Mutex::new(HashMap::with_capacity(256)),
        }
    }

    /// Returns `true` if `auth_id` is fresh (not seen within the last 120s), `false` on replay.
    pub fn check_and_insert(&self, auth_id: [u8; 16]) -> bool {
        let now = Instant::now();
        let ttl = Duration::from_secs(120);
        let mut guard = self.seen.lock().unwrap_or_else(|e| e.into_inner());
        if guard.len() > 2048 {
            guard.retain(|_, &mut ts| now.duration_since(ts) < ttl);
        }
        if let Some(&ts) = guard.get(&auth_id) {
            if now.duration_since(ts) < ttl {
                return false;
            }
        }
        guard.insert(auth_id, now);
        true
    }
}

impl Default for ReplayCache {
    fn default() -> Self {
        Self::new()
    }
}

/// Shared runtime state passed into each inbound connection handler.
pub struct InboundRuntime {
    pub tag: String,
    pub protocol: InboundProtocol,
    pub users: Arc<RwLock<InboundUsers>>,
    pub replay_cache: Arc<ReplayCache>,
    pub fallbacks: Vec<FallbackConfig>,
    pub block_private: bool,
    pub block_bittorrent: bool,
    pub conn_idle: Duration,
    pub stats: StatsRegistry,
    pub access_log: AccessLogger,
}

impl InboundRuntime {
    pub fn from_config(
        cfg: &InboundConfig,
        block_private: bool,
        block_bittorrent: bool,
        conn_idle: Duration,
        stats: StatsRegistry,
        access_log: AccessLogger,
    ) -> Result<Self, String> {
        let protocol = InboundProtocol::parse(&cfg.protocol)
            .ok_or_else(|| format!("unsupported protocol '{}'", cfg.protocol))?;
        let users = InboundUsers::from_clients(protocol, &cfg.settings.clients);
        Ok(Self {
            tag: cfg.tag.clone(),
            protocol,
            users: Arc::new(RwLock::new(users)),
            replay_cache: Arc::new(ReplayCache::new()),
            fallbacks: cfg.settings.fallbacks.clone(),
            block_private,
            block_bittorrent,
            conn_idle,
            stats,
            access_log,
        })
    }
}

/// Dispatches an accepted, transport-unwrapped stream to VLESS, VMess AEAD, or Trojan.
pub async fn handle_stream(stream: BoxedStream, runtime: Arc<InboundRuntime>, peer_desc: String) {
    let res = match runtime.protocol {
        InboundProtocol::Vless => vless::handle_vless(stream, &runtime, &peer_desc).await,
        InboundProtocol::Vmess => vmess::handle_vmess(stream, &runtime, &peer_desc).await,
        InboundProtocol::Trojan => trojan::handle_trojan(stream, &runtime, &peer_desc).await,
    };

    if let Err(e) = res {
        crate::log_debug!("[{}] ({}): session ended: {}", runtime.tag, peer_desc, e);
    }
}
