use std::path::PathBuf;
use std::process;

use tokio::sync::watch;

use ws_rs::config::WsConfig;
use ws_rs::proxy::run_server;

const VERSION: &str = env!("CARGO_PKG_VERSION");

fn print_usage() {
    eprintln!("ws-rs v{VERSION} (static Rust HTTP-Upgrade / WebSocket-to-TCP bridge)");
    eprintln!("Usage: ws -f <config.conf>");
    eprintln!("Options:");
    eprintln!("  -f, --config <path>   Path to tun.conf YAML config file");
    eprintln!("  -v, --version         Print version and exit");
    eprintln!("  -h, --help            Show this help message");
}

fn main() {
    let mut args = std::env::args().skip(1);
    let mut config_path: Option<PathBuf> = None;

    while let Some(arg) = args.next() {
        match arg.as_str() {
            "-f" | "--config" => {
                let Some(p) = args.next() else {
                    eprintln!("error: missing path after {arg}");
                    process::exit(2);
                };
                config_path = Some(PathBuf::from(p));
            }
            "-v" | "--version" => {
                println!("ws-rs v{VERSION}");
                return;
            }
            "-h" | "--help" => {
                print_usage();
                return;
            }
            other => {
                eprintln!("error: unknown argument '{other}'");
                print_usage();
                process::exit(2);
            }
        }
    }

    let Some(path) = config_path else {
        print_usage();
        process::exit(2);
    };

    let cfg = match WsConfig::from_file(&path) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("[ws-rs] config error: {e}");
            process::exit(1);
        }
    };

    // Match Tokio runtime threads to actual vCPU count (zero extra thread overhead on 1-vCPU VPS).
    let cpus = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1);
    let rt = if cpus <= 1 {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
    } else {
        tokio::runtime::Builder::new_multi_thread()
            .worker_threads(cpus)
            .enable_all()
            .build()
    }
    .expect("failed to build tokio runtime");

    rt.block_on(async move {
        let (shutdown_tx, shutdown_rx) = watch::channel(false);

        tokio::spawn(async move {
            #[cfg(unix)]
            {
                use tokio::signal::unix::{signal, SignalKind};
                let mut sigterm = signal(SignalKind::terminate()).ok();
                tokio::select! {
                    _ = tokio::signal::ctrl_c() => {}
                    _ = async {
                        if let Some(ref mut s) = sigterm {
                            s.recv().await;
                        } else {
                            std::future::pending::<()>().await;
                        }
                    } => {}
                }
            }
            #[cfg(not(unix))]
            {
                let _ = tokio::signal::ctrl_c().await;
            }
            let _ = shutdown_tx.send(true);
        });

        if let Err(e) = run_server(cfg, shutdown_rx).await {
            eprintln!("[ws-rs] fatal: {e}");
            process::exit(1);
        }
    });
}
