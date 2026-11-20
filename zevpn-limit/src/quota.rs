use crate::config::{
    remove_user_from_db, remove_user_from_xray_config, write_atomic, FileStamp, Protocol,
    UserCache, UserEntry,
};
use crate::telegram::TelegramNotifier;
use crate::xray::XrayStatsClient;
use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::{Path, PathBuf};
use tokio::process::Command;

/// Flush an individual user's usage file immediately once 1 MiB of un-flushed traffic accrues.
const FLUSH_DELTA_THRESHOLD: u64 = 1_048_576;

struct UsageState {
    bytes: u64,
    dirty_bytes: u64,
    disk_stamp: Option<FileStamp>,
    path: PathBuf,
}

/// Keeps per-user byte counters in RAM and flushes periodically to `/etc/limit/<proto>/<user>`,
/// drastically reducing VPS disk I/O while preserving accuracy across manual resets and restarts.
pub struct UsageStore {
    entries: HashMap<(Protocol, String), UsageState>,
}

impl UsageStore {
    pub fn new() -> Self {
        Self {
            entries: HashMap::new(),
        }
    }

    pub fn add_delta(&mut self, entry: &UserEntry, delta: u64, dry_run: bool) -> u64 {
        let key = (entry.protocol, entry.username.clone());
        let state = self.entries.entry(key).or_insert_with(|| {
            let disk_val = read_u64_file(&entry.usage_path).unwrap_or(0);
            let stamp = FileStamp::of(&entry.usage_path);
            UsageState {
                bytes: disk_val,
                dirty_bytes: 0,
                disk_stamp: stamp,
                path: entry.usage_path.clone(),
            }
        });

        state.bytes = state.bytes.saturating_add(delta);
        state.dirty_bytes = state.dirty_bytes.saturating_add(delta);
        let current = state.bytes;

        if !dry_run && state.dirty_bytes >= FLUSH_DELTA_THRESHOLD {
            flush_single(state);
        }

        current
    }

    pub fn current_bytes(&mut self, entry: &UserEntry) -> Option<u64> {
        let key = (entry.protocol, entry.username.clone());
        if let Some(state) = self.entries.get(&key) {
            return Some(state.bytes);
        }
        let disk_val = read_u64_file(&entry.usage_path)?;
        let stamp = FileStamp::of(&entry.usage_path);
        self.entries.insert(
            key,
            UsageState {
                bytes: disk_val,
                dirty_bytes: 0,
                disk_stamp: stamp,
                path: entry.usage_path.clone(),
            },
        );
        Some(disk_val)
    }

    pub fn flush_all(&mut self, dry_run: bool) {
        if dry_run {
            return;
        }
        for state in self.entries.values_mut() {
            if state.dirty_bytes > 0 {
                flush_single(state);
            }
        }
    }

    pub fn remove(&mut self, protocol: Protocol, username: &str) {
        self.entries.remove(&(protocol, username.to_owned()));
    }

    pub fn retain_active(&mut self, users: &[UserEntry]) {
        let active: HashSet<(Protocol, &str)> = users
            .iter()
            .map(|u| (u.protocol, u.username.as_str()))
            .collect();
        self.entries
            .retain(|(p, u), _| active.contains(&(*p, u.as_str())));
    }
}

fn flush_single(state: &mut UsageState) {
    // Respect external edits (e.g. admin resetting usage via CLI menu) by rebasing dirty delta.
    let current_stamp = FileStamp::of(&state.path);
    if current_stamp != state.disk_stamp {
        if let Some(ext_bytes) = read_u64_file(&state.path) {
            state.bytes = ext_bytes.saturating_add(state.dirty_bytes);
        }
    }

    if let Err(err) = write_atomic(&state.path, &format!("{}\n", state.bytes)) {
        eprintln!(
            "[WARN] failed to flush usage to {}: {err}",
            state.path.display()
        );
    } else {
        state.dirty_bytes = 0;
        state.disk_stamp = FileStamp::of(&state.path);
    }
}

/// Formats bytes using the same ceiling-division units as the original bash `con()` helper.
pub fn format_bytes(bytes: u64) -> String {
    if bytes < 1024 {
        format!("{bytes}B")
    } else if bytes < 1_048_576 {
        format!("{}KB", (bytes + 1023) / 1024)
    } else if bytes < 1_073_741_824 {
        format!("{}MB", (bytes + 1_048_575) / 1_048_576)
    } else {
        format!("{}GB", (bytes + 1_073_741_823) / 1_073_741_824)
    }
}

pub fn ensure_usage_dirs(dry_run: bool) {
    if dry_run {
        return;
    }
    for proto in Protocol::ALL {
        let dir = proto.usage_dir();
        if !dir.exists() {
            let _ = fs::create_dir_all(&dir);
        }
    }
}

pub async fn run_cycle(
    xray_client: &mut XrayStatsClient,
    user_cache: &mut UserCache,
    usage_store: &mut UsageStore,
    notifier: &TelegramNotifier,
    xray_config: &Path,
    count_uplink: bool,
    dry_run: bool,
) -> Result<(), String> {
    let (users_slice, config_changed) = user_cache.refresh(xray_config)?;
    if users_slice.is_empty() {
        if config_changed {
            usage_store.retain_active(&[]);
        }
        return Ok(());
    }

    // Clone lightweight metadata only when we need to mutate user_cache later.
    let users: Vec<UserEntry> = users_slice.to_vec();
    if config_changed {
        usage_store.retain_active(&users);
    }

    // 1) Fetch traffic deltas for all users in a single gRPC call.
    let deltas = xray_client
        .query_user_traffic(count_uplink, !dry_run)
        .await?;

    // 2) Accumulate traffic in RAM and enforce quota only for active users (or all on config reload).
    let mut need_restart = false;

    for entry in &users {
        let delta = deltas.get(&entry.username).copied().unwrap_or(0);
        if delta == 0 && !config_changed {
            continue;
        }

        let usage_bytes = if delta > 0 {
            usage_store.add_delta(entry, delta, dry_run)
        } else {
            match usage_store.current_bytes(entry) {
                Some(v) => v,
                None => continue,
            }
        };

        let Some(limit_bytes) = read_quota_limit(&entry.limit_path) else {
            continue;
        };

        if usage_bytes > limit_bytes {
            eprintln!(
                "[INFO] quota exceeded: proto={} user={} usage={} limit={}",
                entry.protocol.name(),
                entry.username,
                format_bytes(usage_bytes),
                format_bytes(limit_bytes)
            );

            if dry_run {
                continue;
            }

            if let Err(err) = remove_user_from_xray_config(
                xray_config,
                entry.protocol,
                &entry.username,
                entry.exp.as_deref(),
            ) {
                eprintln!("[WARN] failed to remove {} from xray config: {err}", entry.username);
            }

            if let Err(err) =
                remove_user_from_db(entry.protocol, &entry.username, entry.exp.as_deref())
            {
                eprintln!("[WARN] failed to remove {} from protocol db: {err}", entry.username);
            }

            notifier
                .notify_quota_exceeded(entry.protocol, &entry.username, limit_bytes, usage_bytes)
                .await;

            for path in entry.protocol.cleanup_paths(&entry.username) {
                if path.exists() {
                    let _ = fs::remove_file(&path);
                }
            }

            usage_store.remove(entry.protocol, &entry.username);
            user_cache.invalidate();
            need_restart = true;
        }
    }

    if need_restart && !dry_run {
        eprintln!("[INFO] restarting xray service after quota enforcement");
        match Command::new("systemctl")
            .args(["restart", "xray"])
            .status()
            .await
        {
            Ok(status) if !status.success() => {
                eprintln!(
                    "[WARN] systemctl restart xray exited with code {:?}",
                    status.code()
                );
            }
            Err(err) => {
                eprintln!("[WARN] failed to invoke systemctl restart xray: {err}");
            }
            Ok(_) => {}
        }
    }

    Ok(())
}

fn read_u64_file(path: &Path) -> Option<u64> {
    let raw = fs::read_to_string(path).ok()?;
    raw.trim().parse::<u64>().ok()
}

/// Mirrors the bash guard `if [[ ${#checkLimit} -gt 1 ]]`.
fn read_quota_limit(path: &Path) -> Option<u64> {
    let raw = fs::read_to_string(path).ok()?;
    let trimmed = raw.trim();
    if trimmed.len() <= 1 {
        return None;
    }
    let val = trimmed.parse::<u64>().ok()?;
    if val == 0 {
        None
    } else {
        Some(val)
    }
}
