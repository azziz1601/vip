use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::SystemTime;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Protocol {
    Vmess,
    Vless,
    Trojan,
    Shadowsocks,
}

impl Protocol {
    pub const ALL: [Protocol; 4] = [
        Protocol::Vmess,
        Protocol::Vless,
        Protocol::Trojan,
        Protocol::Shadowsocks,
    ];

    pub fn name(self) -> &'static str {
        match self {
            Protocol::Vmess => "vmess",
            Protocol::Vless => "vless",
            Protocol::Trojan => "trojan",
            Protocol::Shadowsocks => "shadowsocks",
        }
    }

    pub fn display_name(self) -> &'static str {
        match self {
            Protocol::Vmess => "VMESS",
            Protocol::Vless => "VLESS",
            Protocol::Trojan => "TROJAN",
            Protocol::Shadowsocks => "SHADOWSOCKS",
        }
    }

    pub fn config_marker(self) -> &'static str {
        match self {
            Protocol::Vmess => "###",
            Protocol::Vless => "#&",
            Protocol::Trojan => "#!",
            Protocol::Shadowsocks => "#!#",
        }
    }

    pub fn db_marker(self) -> &'static str {
        match self {
            Protocol::Vmess => "###",
            Protocol::Vless => "#&",
            Protocol::Trojan => "#!",
            Protocol::Shadowsocks => "###",
        }
    }

    pub fn db_path(self) -> PathBuf {
        let name = self.name();
        PathBuf::from(format!("/etc/{name}/.{name}.db"))
    }

    pub fn usage_dir(self) -> PathBuf {
        PathBuf::from(format!("/etc/limit/{}", self.name()))
    }

    pub fn cleanup_paths(self, user: &str) -> [PathBuf; 6] {
        let name = self.name();
        let html_file = match self {
            Protocol::Shadowsocks => format!("/var/www/html/sodosokws-{user}.txt"),
            _ => format!("/var/www/html/{name}-{user}.txt"),
        };

        [
            PathBuf::from(format!("/etc/limit/{name}/{user}")),
            PathBuf::from(format!("/etc/limit/{name}/quota/{user}")),
            PathBuf::from(format!("/etc/{name}/{user}")),
            PathBuf::from(format!("/etc/kyt/limit/{name}/ip/{user}")),
            PathBuf::from(format!("/etc/funny/limit/{name}/ip/{user}")),
            PathBuf::from(html_file),
        ]
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FileStamp {
    pub modified: Option<SystemTime>,
    pub len: u64,
}

impl FileStamp {
    pub fn of(path: &Path) -> Option<Self> {
        let meta = fs::metadata(path).ok()?;
        Some(Self {
            modified: meta.modified().ok(),
            len: meta.len(),
        })
    }
}

#[derive(Debug, Clone)]
pub struct UserEntry {
    pub protocol: Protocol,
    pub username: String,
    pub exp: Option<String>,
    pub usage_path: PathBuf,
    pub limit_path: PathBuf,
}

impl UserEntry {
    fn new(protocol: Protocol, username: String, exp: Option<String>) -> Self {
        let name = protocol.name();
        let usage_path = PathBuf::from(format!("/etc/limit/{name}/{username}"));
        let limit_path = PathBuf::from(format!("/etc/{name}/{username}"));
        Self {
            protocol,
            username,
            exp,
            usage_path,
            limit_path,
        }
    }
}

/// Caches parsed users from `/etc/xray/config.json` and `.shadowsocks.db`,
/// re-reading disk only when file `mtime` or size changes.
pub struct UserCache {
    xray_stamp: Option<FileStamp>,
    ss_db_stamp: Option<FileStamp>,
    users: Vec<UserEntry>,
    loaded_once: bool,
}

impl UserCache {
    pub fn new() -> Self {
        Self {
            xray_stamp: None,
            ss_db_stamp: None,
            users: Vec::new(),
            loaded_once: false,
        }
    }

    pub fn invalidate(&mut self) {
        self.loaded_once = false;
    }

    /// Returns `(users, reloaded)`.
    pub fn refresh(&mut self, xray_config: &Path) -> Result<(&[UserEntry], bool), String> {
        let ss_db = Protocol::Shadowsocks.db_path();
        let cur_xray = FileStamp::of(xray_config);
        let cur_ss = FileStamp::of(&ss_db);

        if self.loaded_once && cur_xray == self.xray_stamp && cur_ss == self.ss_db_stamp {
            return Ok((&self.users, false));
        }

        self.users = parse_users(xray_config, &ss_db)?;
        self.xray_stamp = cur_xray;
        self.ss_db_stamp = cur_ss;
        self.loaded_once = true;
        Ok((&self.users, true))
    }
}

fn parse_users(xray_config: &Path, ss_db: &Path) -> Result<Vec<UserEntry>, String> {
    let mut users = Vec::new();
    let mut seen: HashSet<(Protocol, String)> = HashSet::new();

    if xray_config.exists() {
        let content = fs::read_to_string(xray_config)
            .map_err(|e| format!("failed to read {}: {e}", xray_config.display()))?;

        for line in content.lines() {
            let trimmed = line.trim_start();
            // Check "#!#" before "#!" so Shadowsocks isn't misread as Trojan.
            let matched = if trimmed.starts_with("### ") {
                Some(Protocol::Vmess)
            } else if trimmed.starts_with("#& ") {
                Some(Protocol::Vless)
            } else if trimmed.starts_with("#!# ") {
                Some(Protocol::Shadowsocks)
            } else if trimmed.starts_with("#! ") {
                Some(Protocol::Trojan)
            } else {
                None
            };

            if let Some(protocol) = matched {
                let mut parts = trimmed.split_whitespace();
                let _marker = parts.next();
                if let Some(username) = parts.next() {
                    let exp = parts.next().map(ToOwned::to_owned);
                    if seen.insert((protocol, username.to_owned())) {
                        users.push(UserEntry::new(protocol, username.to_owned(), exp));
                    }
                }
            }
        }
    }

    if ss_db.exists() {
        if let Ok(content) = fs::read_to_string(ss_db) {
            for line in content.lines() {
                let trimmed = line.trim_start();
                if trimmed.starts_with("### ") {
                    let mut parts = trimmed.split_whitespace();
                    let _marker = parts.next();
                    if let Some(username) = parts.next() {
                        let exp = parts.next().map(ToOwned::to_owned);
                        if seen.insert((Protocol::Shadowsocks, username.to_owned())) {
                            users.push(UserEntry::new(
                                Protocol::Shadowsocks,
                                username.to_owned(),
                                exp,
                            ));
                        }
                    }
                }
            }
        }
    }

    Ok(users)
}

pub fn remove_user_from_xray_config(
    xray_config: &Path,
    protocol: Protocol,
    username: &str,
    exp: Option<&str>,
) -> Result<bool, String> {
    let content = fs::read_to_string(xray_config)
        .map_err(|e| format!("failed to read {}: {e}", xray_config.display()))?;

    let prefix = match exp {
        Some(e) if !e.is_empty() => format!("{} {} {}", protocol.config_marker(), username, e),
        _ => format!("{} {} ", protocol.config_marker(), username),
    };

    let mut out = String::with_capacity(content.len());
    let mut skipping = false;
    let mut removed_any = false;

    for line in content.lines() {
        if !skipping {
            let matches_start = if exp.is_some() {
                line == prefix || line.starts_with(&format!("{prefix} "))
            } else {
                line.starts_with(&prefix)
            };

            if matches_start {
                skipping = true;
                removed_any = true;
                continue;
            }
            out.push_str(line);
            out.push('\n');
        } else if line.trim_start().starts_with("},{") {
            skipping = false;
        }
    }

    if removed_any {
        write_atomic(xray_config, &out)?;
    }

    Ok(removed_any)
}

pub fn remove_user_from_db(
    protocol: Protocol,
    username: &str,
    exp: Option<&str>,
) -> Result<(), String> {
    let db_path = protocol.db_path();
    if !db_path.exists() {
        return Ok(());
    }

    let content = fs::read_to_string(&db_path)
        .map_err(|e| format!("failed to read {}: {e}", db_path.display()))?;

    let prefix = match exp {
        Some(e) if !e.is_empty() => format!("{} {} {}", protocol.db_marker(), username, e),
        _ => format!("{} {} ", protocol.db_marker(), username),
    };

    let mut out = String::with_capacity(content.len());
    let mut changed = false;

    for line in content.lines() {
        let is_match = if exp.is_some() {
            line == prefix || line.starts_with(&format!("{prefix} "))
        } else {
            line.starts_with(&prefix)
        };

        if is_match {
            changed = true;
            continue;
        }
        out.push_str(line);
        out.push('\n');
    }

    if changed {
        write_atomic(&db_path, &out)?;
    }

    Ok(())
}

pub fn write_atomic(path: &Path, content: &str) -> Result<(), String> {
    let tmp_name = format!(
        ".{}.tmp.{}",
        path.file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("zevpn"),
        std::process::id()
    );
    let tmp_path = path.with_file_name(tmp_name);
    fs::write(&tmp_path, content)
        .map_err(|e| format!("failed to write temp file {}: {e}", tmp_path.display()))?;
    if let Err(err) = fs::rename(&tmp_path, path) {
        let _ = fs::remove_file(&tmp_path);
        return Err(format!("failed to replace {}: {err}", path.display()));
    }
    Ok(())
}
