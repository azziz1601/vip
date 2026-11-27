use std::path::PathBuf;
use std::process::ExitCode;

use tokio::sync::watch;

use xray_lite_rs::config::XrayConfig;
use xray_lite_rs::{
    log_error, log_info, log_warn, logger, run_server_with_limit, HotReloadRegistry,
    DEFAULT_MAX_CONNECTIONS,
};

const VERSION: &str = env!("CARGO_PKG_VERSION");

struct CliArgs {
    config_path: PathBuf,
    test_only: bool,
    show_version: bool,
    show_help: bool,
    threads: Option<usize>,
    max_connections: usize,
}

fn parse_cli() -> Result<CliArgs, String> {
    let args: Vec<String> = std::env::args().collect();
    let mut config_path = PathBuf::from("config.json");
    let mut test_only = false;
    let mut show_version = false;
    let mut show_help = false;
    let mut threads = None;
    let mut max_connections = DEFAULT_MAX_CONNECTIONS;

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "run" => {} // Compatible with `xray run -c config.json`
            "-c" | "--config" | "-config" => {
                i += 1;
                if i >= args.len() {
                    return Err("-c/--config requires a file path".to_string());
                }
                config_path = PathBuf::from(&args[i]);
            }
            "-t" | "--test" | "-test" => {
                test_only = true;
            }
            "-v" | "--version" | "version" => {
                show_version = true;
            }
            "-h" | "--help" | "help" => {
                show_help = true;
            }
            "--threads" => {
                i += 1;
                if i >= args.len() {
                    return Err("--threads requires a number".to_string());
                }
                let n: usize = args[i]
                    .parse()
                    .map_err(|_| format!("invalid --threads '{}'", args[i]))?;
                if n == 0 {
                    return Err("--threads must be > 0".to_string());
                }
                threads = Some(n);
            }
            "--max-connections" => {
                i += 1;
                if i >= args.len() {
                    return Err("--max-connections requires a number".to_string());
                }
                let n: usize = args[i]
                    .parse()
                    .map_err(|_| format!("invalid --max-connections '{}'", args[i]))?;
                if n == 0 {
                    return Err("--max-connections must be > 0".to_string());
                }
                max_connections = n;
            }
            other => {
                return Err(format!("unknown argument: {other}"));
            }
        }
        i += 1;
    }

    Ok(CliArgs {
        config_path,
        test_only,
        show_version,
        show_help,
        threads,
        max_connections,
    })
}

fn print_help() {
    println!(
        "xray-lite {VERSION} (High-performance Rust Xray-core compatible server)\n\
         Usage:\n\
         \x20 xray-lite [run] -c <config.json> [-t|--test] [--threads <N>] [--max-connections <N>]\n\
         \x20 xray-lite --version | --help\n\n\
         Signals (Unix):\n\
         \x20 SIGHUP         Hot-reload client lists from config.json without dropping active connections\n\
         \x20 SIGINT/SIGTERM Graceful shutdown"
    );
}

fn main() -> ExitCode {
    let raw_args: Vec<String> = std::env::args().collect();
    if raw_args.get(1).map(String::as_str) == Some("api") {
        return match xray_lite_rs::api_client::run_api_cli(&raw_args[2..]) {
            Ok(()) => ExitCode::SUCCESS,
            Err(e) => {
                eprintln!("Error: {e}");
                ExitCode::FAILURE
            }
        };
    }

    let cli = match parse_cli() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Error: {e}");
            print_help();
            return ExitCode::FAILURE;
        }
    };

    if cli.show_help {
        print_help();
        return ExitCode::SUCCESS;
    }
    if cli.show_version {
        println!("xray-lite {VERSION} (VLESS, VMess AEAD, Trojan | TCP/TLS/WS/HTTPUpgrade/gRPC/XHTTP)");
        return ExitCode::SUCCESS;
    }

    // Install ring crypto provider for rustls before any TLS initialization.
    let _ = tokio_rustls::rustls::crypto::ring::default_provider().install_default();

    let cfg = match XrayConfig::from_file(&cli.config_path) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Config error: {e}");
            return ExitCode::FAILURE;
        }
    };

    if cli.test_only {
        println!("Configuration OK ({} inbound(s))", cfg.inbounds.len());
        return ExitCode::SUCCESS;
    }

    logger::set_level(cfg.log_level());
    log_info!("starting xray-lite {}", VERSION);

    let num_threads = cli.threads.unwrap_or_else(|| {
        std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(1)
    });

    let runtime = if num_threads <= 1 {
        log_info!("runtime: current_thread (optimized for 1 vCPU)");
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
    } else {
        log_info!("runtime: multi_thread ({} workers)", num_threads);
        tokio::runtime::Builder::new_multi_thread()
            .worker_threads(num_threads)
            .enable_all()
            .build()
    };

    let runtime = match runtime {
        Ok(rt) => rt,
        Err(e) => {
            log_error!("failed to build tokio runtime: {}", e);
            return ExitCode::FAILURE;
        }
    };

    let config_path = cli.config_path;
    let max_connections = cli.max_connections;

    let res = runtime.block_on(async move {
        let registry = HotReloadRegistry::new();
        let (shutdown_tx, shutdown_rx) = watch::channel(false);

        // SIGHUP hot-reload task (Unix)
        #[cfg(unix)]
        {
            let reload_reg = registry.clone();
            let reload_path = config_path.clone();
            let mut reload_shutdown = shutdown_rx.clone();
            tokio::spawn(async move {
                if let Ok(mut sighup) =
                    tokio::signal::unix::signal(tokio::signal::unix::SignalKind::hangup())
                {
                    loop {
                        tokio::select! {
                            biased;
                            _ = reload_shutdown.changed() => break,
                            Some(()) = sighup.recv() => {
                                log_info!("SIGHUP received, hot-reloading users from {}", reload_path.display());
                                match reload_reg.reload_from_file(&reload_path) {
                                    Ok(n) => log_info!("hot-reload succeeded ({} total user(s) active)", n),
                                    Err(e) => log_warn!("hot-reload rejected (keeping previous users): {}", e),
                                }
                            }
                        }
                    }
                }
            });
        }

        tokio::spawn(async move {
            wait_for_shutdown_signal().await;
            log_info!("shutdown requested");
            let _ = shutdown_tx.send(true);
        });

        run_server_with_limit(cfg, registry, shutdown_rx, max_connections).await
    });

    match res {
        Ok(()) => {
            log_info!("exiting cleanly");
            ExitCode::SUCCESS
        }
        Err(e) => {
            log_error!("fatal error: {}", e);
            ExitCode::FAILURE
        }
    }
}

async fn wait_for_shutdown_signal() {
    let ctrl_c = async {
        let _ = tokio::signal::ctrl_c().await;
    };

    #[cfg(unix)]
    let terminate = async {
        if let Ok(mut sig) =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        {
            sig.recv().await;
        } else {
            std::future::pending::<()>().await;
        }
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {}
        _ = terminate => {}
    }
}
