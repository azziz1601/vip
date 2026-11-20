use crate::config::Protocol;
use crate::quota::format_bytes;
use std::fs;
use std::path::{Path, PathBuf};
use tokio::process::Command;

pub struct TelegramNotifier {
    bot_db_path: PathBuf,
}

struct BotCredentials {
    token: String,
    chat_id: String,
}

impl TelegramNotifier {
    pub fn new(bot_db_path: PathBuf) -> Self {
        Self { bot_db_path }
    }

    /// Sends quota-exceeded alert asynchronously using system `curl` (zero TLS/HTTP bloat in binary).
    pub async fn notify_quota_exceeded(
        &self,
        protocol: Protocol,
        username: &str,
        limit_bytes: u64,
        usage_bytes: u64,
    ) {
        let Some(creds) = read_bot_db(&self.bot_db_path) else {
            return;
        };

        let limit_str = format_bytes(limit_bytes);
        let usage_str = format_bytes(usage_bytes);
        let proto_label = protocol.display_name();

        let text = format!(
            "\n<code>────────────────────</code>\n\
             <b>⚠️NOTIF QUOTA HABIS XRAY {proto_label}⚠️</b>\n\
             <code>────────────────────</code>\n\
             <code>Username   : </code><code>{username}</code>\n\
             <code>Limit Quota: </code><code>{limit_str}</code>\n\
             <code>Usage      : </code><code>{usage_str}</code>\n\
             <code>────────────────────</code>"
        );

        let url = format!("https://api.telegram.org/bot{}/sendMessage", creds.token);

        match Command::new("curl")
            .args([
                "--silent",
                "--show-error",
                "--max-time",
                "10",
                "--output",
                "/dev/null",
                "--data-urlencode",
                &format!("chat_id={}", creds.chat_id),
                "--data-urlencode",
                "disable_web_page_preview=1",
                "--data-urlencode",
                "parse_mode=html",
                "--data-urlencode",
                &format!("text={text}"),
                &url,
            ])
            .status()
            .await
        {
            Ok(status) if !status.success() => {
                eprintln!(
                    "[WARN] telegram notification failed for user={username} (curl exit {:?})",
                    status.code()
                );
            }
            Err(err) => {
                eprintln!("[WARN] failed to execute curl for user={username}: {err}");
            }
            Ok(_) => {}
        }
    }
}

fn read_bot_db(path: &Path) -> Option<BotCredentials> {
    let content = fs::read_to_string(path).ok()?;
    for line in content.lines() {
        if let Some(rest) = line.strip_prefix("#bot# ") {
            let mut parts = rest.split_whitespace();
            let token = parts.next()?.trim();
            let chat_id = parts.next()?.trim();
            if !token.is_empty() && !chat_id.is_empty() {
                return Some(BotCredentials {
                    token: token.to_owned(),
                    chat_id: chat_id.to_owned(),
                });
            }
        }
    }
    None
}
