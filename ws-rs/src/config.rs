use std::fs;
use std::path::Path;
use std::time::Duration;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ListenRule {
    pub listen_host: String,
    pub listen_port: u16,
    pub target_host: String,
    pub target_port: u16,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WsConfig {
    pub verbose: u8,
    pub idle_timeout: Duration,
    pub max_connections: usize,
    pub listen: Vec<ListenRule>,
}

impl Default for WsConfig {
    fn default() -> Self {
        Self {
            verbose: 0,
            idle_timeout: Duration::from_secs(300),
            max_connections: 4096,
            listen: Vec::new(),
        }
    }
}

#[derive(Default)]
struct PartialRule {
    listen_host: Option<String>,
    listen_port: Option<u16>,
    target_host: Option<String>,
    target_port: Option<u16>,
}

impl PartialRule {
    fn is_empty(&self) -> bool {
        self.listen_host.is_none()
            && self.listen_port.is_none()
            && self.target_host.is_none()
            && self.target_port.is_none()
    }

    fn finish(self, index: usize) -> Result<ListenRule, String> {
        let listen_port = self
            .listen_port
            .ok_or_else(|| format!("listen[{index}]: missing 'listen_port'"))?;
        let target_port = self
            .target_port
            .ok_or_else(|| format!("listen[{index}]: missing 'target_port'"))?;
        if listen_port == 0 {
            return Err(format!("listen[{index}]: listen_port must be > 0"));
        }
        if target_port == 0 {
            return Err(format!("listen[{index}]: target_port must be > 0"));
        }
        Ok(ListenRule {
            listen_host: self.listen_host.unwrap_or_else(|| "0.0.0.0".to_string()),
            listen_port,
            target_host: self.target_host.unwrap_or_else(|| "127.0.0.1".to_string()),
            target_port,
        })
    }
}

impl WsConfig {
    pub fn from_file(path: &Path) -> Result<Self, String> {
        let raw = fs::read_to_string(path)
            .map_err(|e| format!("failed to read config '{}': {e}", path.display()))?;
        Self::parse_yaml(&raw)
    }

    /// Parses standard `tun.conf` YAML format without external YAML dependencies.
    pub fn parse_yaml(raw: &str) -> Result<Self, String> {
        let mut cfg = WsConfig::default();
        let mut in_listen = false;
        let mut current: Option<PartialRule> = None;

        for (line_idx, raw_line) in raw.lines().enumerate() {
            let line_no = line_idx + 1;
            let clean = strip_comment(raw_line).trim();
            if clean.is_empty() {
                continue;
            }

            if let Some(rest) = clean.strip_prefix('-') {
                in_listen = true;
                if let Some(prev) = current.take() {
                    if !prev.is_empty() {
                        cfg.listen.push(prev.finish(cfg.listen.len())?);
                    }
                }
                let mut rule = PartialRule::default();
                let after_dash = rest.trim();
                if !after_dash.is_empty() {
                    apply_rule_kv(&mut rule, after_dash, line_no)?;
                }
                current = Some(rule);
                continue;
            }

            let Some((k_raw, v_raw)) = clean.split_once(':') else {
                return Err(format!("line {line_no}: expected 'key: value', got '{clean}'"));
            };
            let key = k_raw.trim();
            let val = unquote(v_raw.trim());

            match key {
                "verbose" => {
                    in_listen = false;
                    cfg.verbose = val
                        .parse::<u8>()
                        .map_err(|_| format!("line {line_no}: invalid verbose '{val}'"))?;
                }
                "idle_timeout" => {
                    in_listen = false;
                    let secs = val
                        .parse::<u64>()
                        .map_err(|_| format!("line {line_no}: invalid idle_timeout '{val}'"))?;
                    cfg.idle_timeout = Duration::from_secs(secs.max(10));
                }
                "max_connections" => {
                    in_listen = false;
                    let max_c = val
                        .parse::<usize>()
                        .map_err(|_| format!("line {line_no}: invalid max_connections '{val}'"))?;
                    cfg.max_connections = max_c.max(1);
                }
                "listen" => {
                    in_listen = true;
                }
                "listen_host" | "listen_port" | "target_host" | "target_port" if in_listen => {
                    let rule = current.get_or_insert_with(PartialRule::default);
                    apply_rule_kv(rule, clean, line_no)?;
                }
                _ => {
                    // Ignore unknown optional keys for forward compatibility with ws-epro configs.
                }
            }
        }

        if let Some(prev) = current.take() {
            if !prev.is_empty() {
                cfg.listen.push(prev.finish(cfg.listen.len())?);
            }
        }

        if cfg.listen.is_empty() {
            return Err("config has no 'listen' entries".to_string());
        }

        Ok(cfg)
    }
}

fn apply_rule_kv(rule: &mut PartialRule, kv: &str, line_no: usize) -> Result<(), String> {
    let Some((k_raw, v_raw)) = kv.split_once(':') else {
        return Err(format!("line {line_no}: expected 'key: value', got '{kv}'"));
    };
    let key = k_raw.trim();
    let val = unquote(v_raw.trim());
    match key {
        "listen_host" => rule.listen_host = Some(val.to_string()),
        "target_host" => rule.target_host = Some(val.to_string()),
        "listen_port" => {
            rule.listen_port = Some(
                val.parse::<u16>()
                    .map_err(|_| format!("line {line_no}: invalid listen_port '{val}'"))?,
            );
        }
        "target_port" => {
            rule.target_port = Some(
                val.parse::<u16>()
                    .map_err(|_| format!("line {line_no}: invalid target_port '{val}'"))?,
            );
        }
        _ => {}
    }
    Ok(())
}

fn strip_comment(line: &str) -> &str {
    let mut in_single = false;
    let mut in_double = false;
    for (i, ch) in line.char_indices() {
        match ch {
            '\'' if !in_double => in_single = !in_single,
            '"' if !in_single => in_double = !in_double,
            '#' if !in_single && !in_double => return &line[..i],
            _ => {}
        }
    }
    line
}

fn unquote(s: &str) -> &str {
    if s.len() >= 2
        && ((s.starts_with('"') && s.ends_with('"')) || (s.starts_with('\'') && s.ends_with('\'')))
    {
        &s[1..s.len() - 1]
    } else {
        s
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_standard_vip_tun_conf() {
        let raw = r#"
## verbose level 0=info, 1=verbose, 2=very verbose
verbose: 0
listen:

# // SSH
- target_host: 127.0.0.1
  target_port: 143
  listen_port: 10015

# // OpenVPN
- target_host: 127.0.0.1
  target_port: 1194
  listen_port: 10012
"#;
        let cfg = WsConfig::parse_yaml(raw).unwrap();
        assert_eq!(cfg.verbose, 0);
        assert_eq!(cfg.listen.len(), 2);
        assert_eq!(
            cfg.listen[0],
            ListenRule {
                listen_host: "0.0.0.0".to_string(),
                listen_port: 10015,
                target_host: "127.0.0.1".to_string(),
                target_port: 143,
            }
        );
        assert_eq!(
            cfg.listen[1],
            ListenRule {
                listen_host: "0.0.0.0".to_string(),
                listen_port: 10012,
                target_host: "127.0.0.1".to_string(),
                target_port: 1194,
            }
        );
    }
}
