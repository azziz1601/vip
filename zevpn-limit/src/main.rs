mod config;
mod quota;
mod telegram;
mod xray;

use config::UserCache;
use quota::UsageStore;
use std::env;
use std::path::PathBuf;
use std::process;
use std::time::Duration;
use telegram::TelegramNotifier;
use tokio::runtime::Builder;
use tokio::time::{self, MissedTickBehavior};
use xray::XrayStatsClient;

struct Args {
    xray_api: String,
    xray_config: PathBuf,
    bot_db: PathBuf,
    interval: u64,
    flush_interval: u64,
    count_uplink: bool,
    dry_run: bool,
}

impl Args {
    fn parse() -> Self {
        let mut args = Self {
            xray_api: env::var("ZEVPN_XRAY_API")
                .unwrap_or_else(|_| "http://127.0.0.1:10000".to_owned()),
            xray_config: env::var("ZEVPN_XRAY_CONFIG")
                .map(PathBuf::from)
                .unwrap_or_else(|_| PathBuf::from("/etc/xray/config.json")),
            bot_db: env::var("ZEVPN_BOT_DB")
                .map(PathBuf::from)
                .unwrap_or_else(|_| PathBuf::from("/etc/bot/.bot.db")),
            interval: env::var("ZEVPN_INTERVAL")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(5),
            flush_interval: env::var("ZEVPN_FLUSH_INTERVAL")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(30),
            count_uplink: matches!(
                env::var("ZEVPN_COUNT_UPLINK").as_deref(),
                Ok("1" | "true" | "TRUE" | "yes")
            ),
            dry_run: false,
        };

        let mut iter = env::args().skip(1);
        while let Some(arg) = iter.next() {
            match arg.as_str() {
                "--xray-api" => {
                    args.xray_api = next_val(&mut iter, "--xray-api");
                }
                "--xray-config" => {
                    args.xray_config = PathBuf::from(next_val(&mut iter, "--xray-config"));
                }
                "--bot-db" => {
                    args.bot_db = PathBuf::from(next_val(&mut iter, "--bot-db"));
                }
                "--interval" => {
                    let v = next_val(&mut iter, "--interval");
                    args.interval = v.parse().unwrap_or_else(|_| {
                        eprintln!("invalid --interval value: {v}");
                        process::exit(2);
                    });
                }
                "--flush-interval" => {
                    let v = next_val(&mut iter, "--flush-interval");
                    args.flush_interval = v.parse().unwrap_or_else(|_| {
                        eprintln!("invalid --flush-interval value: {v}");
                        process::exit(2);
                    });
                }
                "--count-uplink" => args.count_uplink = true,
                "--dry-run" => args.dry_run = true,
                "-V" | "--version" => {
                    println!("zevpn-limit {}", env!("CARGO_PKG_VERSION"));
                    process::exit(0);
                }
                "-h" | "--help" => {
                    print_help();
                    process::exit(0);
                }
                other => {
                    eprintln!("unknown argument: {other}\n");
                    print_help();
                    process::exit(2);
                }
            }
        }

        args
    }
}

fn next_val(iter: &mut impl Iterator<Item = String>, flag: &str) -> String {
    iter.next().unwrap_or_else(|| {
        eprintln!("missing value for {flag}");
        process::exit(2);
    })
}

fn print_help() {
    println!(
        "zevpn-limit {} — Lightweight Xray quota limit daemon\n\n\
         USAGE:\n\
         \tzevpn-limit [OPTIONS]\n\n\
         OPTIONS:\n\
         \t--xray-api <URL>         Xray gRPC endpoint [default: http://127.0.0.1:10000]\n\
         \t--xray-config <PATH>     Xray config.json path [default: /etc/xray/config.json]\n\
         \t--bot-db <PATH>          Telegram bot db path [default: /etc/bot/.bot.db]\n\
         \t--interval <SECS>        Polling interval in seconds [default: 5]\n\
         \t--flush-interval <SECS>  Disk flush interval in seconds [default: 30]\n\
         \t--count-uplink           Count uplink + downlink traffic\n\
         \t--dry-run                Log actions without modifying files or restarting Xray\n\
         \t-V, --version            Print version\n\
         \t-h, --help               Print help",
        env!("CARGO_PKG_VERSION")
    );
}

fn main() {
    let args = Args::parse();

    let rt = Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap_or_else(|e| {
            eprintln!("[ERROR] failed to initialize tokio runtime: {e}");
            process::exit(1);
        });

    rt.block_on(async_main(args));
}

async fn async_main(args: Args) {
    eprintln!(
        "[INFO] starting zevpn-limit v{} api={} interval={}s flush={}s uplink={} dry_run={}",
        env!("CARGO_PKG_VERSION"),
        args.xray_api,
        args.interval,
        args.flush_interval,
        args.count_uplink,
        args.dry_run
    );

    quota::ensure_usage_dirs(args.dry_run);

    let mut xray_client = XrayStatsClient::new(args.xray_api);
    let mut user_cache = UserCache::new();
    let mut usage_store = UsageStore::new();
    let notifier = TelegramNotifier::new(args.bot_db);

    let mut poll_ticker = time::interval(Duration::from_secs(args.interval.max(1)));
    poll_ticker.set_missed_tick_behavior(MissedTickBehavior::Skip);

    let mut flush_ticker = time::interval(Duration::from_secs(args.flush_interval.max(5)));
    flush_ticker.set_missed_tick_behavior(MissedTickBehavior::Skip);
    // Skip the immediate t=0 flush tick.
    flush_ticker.tick().await;

    loop {
        tokio::select! {
            _ = poll_ticker.tick() => {
                if let Err(err) = quota::run_cycle(
                    &mut xray_client,
                    &mut user_cache,
                    &mut usage_store,
                    &notifier,
                    &args.xray_config,
                    args.count_uplink,
                    args.dry_run,
                ).await {
                    eprintln!("[ERROR] quota cycle failed: {err}");
                }
            }
            _ = flush_ticker.tick() => {
                usage_store.flush_all(args.dry_run);
            }
            _ = shutdown_signal() => {
                eprintln!("[INFO] shutdown signal received; flushing pending usage to disk");
                usage_store.flush_all(args.dry_run);
                break;
            }
        }
    }
}

async fn shutdown_signal() {
    let ctrl_c = async {
        let _ = tokio::signal::ctrl_c().await;
    };

    #[cfg(unix)]
    let terminate = async {
        if let Ok(mut sig) =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        {
            sig.recv().await;
        }
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {}
        _ = terminate => {}
    }
}
