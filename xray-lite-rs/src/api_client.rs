use std::io::{self, Read};
use std::time::Duration;

use bytes::{BufMut, BytesMut};
use h2::client;
use http::{Method, Request};
use tokio::net::TcpStream;
use tokio::time::timeout;

use crate::stats::{
    decode_query_stats_response, encode_add_rule_request, encode_remove_rule_request,
    encode_stats_request,
};

/// Executes `xray api <subcommand> [args...]` compatible with Xray-core CLI.
/// Supported subcommands: `sib`, `rmrules`, `statsquery`, `stats`.
pub fn run_api_cli(args: &[String]) -> Result<(), String> {
    if args.is_empty() || matches!(args[0].as_str(), "-h" | "--help" | "help") {
        print_api_help();
        return Ok(());
    }

    let sub = args[0].as_str();
    let rest = &args[1..];

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("failed to build tokio runtime: {e}"))?;

    match sub {
        "sib" => rt.block_on(cmd_sib(rest)),
        "rmrules" => rt.block_on(cmd_rmrules(rest)),
        "statsquery" => rt.block_on(cmd_statsquery(rest)),
        "stats" => rt.block_on(cmd_stats(rest)),
        other => Err(format!(
            "unsupported api subcommand '{other}' (supported: sib, rmrules, statsquery, stats)"
        )),
    }
}

fn print_api_help() {
    println!(
        "Usage: xray api <subcommand> [options]\n\
         Subcommands:\n\
         \x20 sib        Block connections by source IP (--server, -outbound, -inbound, -ruletag, -reset <ip...>)\n\
         \x20 rmrules    Remove dynamic routing rules by tag (--server <ruletag...>)\n\
         \x20 statsquery Query traffic statistics (--server, -pattern, -reset)\n\
         \x20 stats      Get single traffic statistic (--server, -name, -reset)"
    );
}

/// Parses Go-style flags (`-flag=val`, `--flag=val`, `-flag val`, `--flag val`, `-bool`).
fn split_flag(arg: &str) -> Option<(&str, Option<&str>)> {
    if !arg.starts_with('-') || arg == "-" || arg == "--" {
        return None;
    }
    let trimmed = arg.trim_start_matches('-');
    if let Some((k, v)) = trimmed.split_once('=') {
        Some((k, Some(v)))
    } else {
        Some((trimmed, None))
    }
}

async fn cmd_sib(args: &[String]) -> Result<(), String> {
    let mut server = "127.0.0.1:8080".to_string();
    let mut timeout_secs: u64 = 3;
    let mut inbound = String::new();
    let mut outbound = "blocked".to_string();
    let mut ruletag = "sourceIpBlock".to_string();
    let mut reset = false;
    let mut ips: Vec<String> = Vec::new();

    let mut i = 0;
    while i < args.len() {
        let arg = &args[i];
        if let Some((k, inline_v)) = split_flag(arg) {
            match k {
                "s" | "server" => {
                    server = take_val(k, inline_v, args, &mut i)?;
                }
                "t" | "timeout" => {
                    let v = take_val(k, inline_v, args, &mut i)?;
                    timeout_secs = v
                        .parse::<u64>()
                        .map_err(|_| format!("invalid -timeout '{v}'"))?;
                }
                "inbound" => {
                    inbound = take_val(k, inline_v, args, &mut i)?;
                }
                "outbound" => {
                    outbound = take_val(k, inline_v, args, &mut i)?;
                }
                "ruletag" => {
                    ruletag = take_val(k, inline_v, args, &mut i)?;
                }
                "reset" => {
                    reset = inline_v
                        .map(|v| v != "false" && v != "0")
                        .unwrap_or(true);
                }
                _ => {
                    return Err(format!("unknown flag for 'api sib': {arg}"));
                }
            }
        } else {
            ips.push(arg.clone());
        }
        i += 1;
    }

    if ips.is_empty() {
        // Mirror Xray-core: read whitespace/newline-separated IPs from stdin if none passed on CLI.
        let mut buf = String::new();
        let _ = io::stdin().read_to_string(&mut buf);
        for tok in buf.split_whitespace() {
            if !tok.is_empty() {
                ips.push(tok.to_string());
            }
        }
    }

    let dur = Duration::from_secs(timeout_secs.max(1));

    if reset {
        let rm_req = encode_remove_rule_request(&ruletag);
        grpc_unary(
            &server,
            "/xray.app.router.command.RoutingService/RemoveRule",
            &rm_req,
            dur,
        )
        .await?;
        println!("{{}}");
    }

    if !ips.is_empty() {
        let add_req = encode_add_rule_request(&ruletag, &inbound, &outbound, &ips);
        grpc_unary(
            &server,
            "/xray.app.router.command.RoutingService/AddRule",
            &add_req,
            dur,
        )
        .await?;
        println!("{{}}");
    }

    Ok(())
}

async fn cmd_rmrules(args: &[String]) -> Result<(), String> {
    let mut server = "127.0.0.1:8080".to_string();
    let mut timeout_secs: u64 = 3;
    let mut tags: Vec<String> = Vec::new();

    let mut i = 0;
    while i < args.len() {
        let arg = &args[i];
        if let Some((k, inline_v)) = split_flag(arg) {
            match k {
                "s" | "server" => server = take_val(k, inline_v, args, &mut i)?,
                "t" | "timeout" => {
                    let v = take_val(k, inline_v, args, &mut i)?;
                    timeout_secs = v
                        .parse::<u64>()
                        .map_err(|_| format!("invalid -timeout '{v}'"))?;
                }
                _ => return Err(format!("unknown flag for 'api rmrules': {arg}")),
            }
        } else {
            tags.push(arg.clone());
        }
        i += 1;
    }

    let dur = Duration::from_secs(timeout_secs.max(1));
    for tag in &tags {
        let rm_req = encode_remove_rule_request(tag);
        grpc_unary(
            &server,
            "/xray.app.router.command.RoutingService/RemoveRule",
            &rm_req,
            dur,
        )
        .await?;
        println!("{{}}");
    }
    Ok(())
}

async fn cmd_statsquery(args: &[String]) -> Result<(), String> {
    let mut server = "127.0.0.1:8080".to_string();
    let mut timeout_secs: u64 = 3;
    let mut pattern = String::new();
    let mut reset = false;

    let mut i = 0;
    while i < args.len() {
        let arg = &args[i];
        if let Some((k, inline_v)) = split_flag(arg) {
            match k {
                "s" | "server" => server = take_val(k, inline_v, args, &mut i)?,
                "t" | "timeout" => {
                    let v = take_val(k, inline_v, args, &mut i)?;
                    timeout_secs = v
                        .parse::<u64>()
                        .map_err(|_| format!("invalid -timeout '{v}'"))?;
                }
                "pattern" => pattern = take_val(k, inline_v, args, &mut i)?,
                "reset" => {
                    reset = inline_v
                        .map(|v| v != "false" && v != "0")
                        .unwrap_or(true);
                }
                _ => return Err(format!("unknown flag for 'api statsquery': {arg}")),
            }
        }
        i += 1;
    }

    let req = encode_stats_request(&pattern, reset);
    let resp_bytes = grpc_unary(
        &server,
        "/xray.app.stats.command.StatsService/QueryStats",
        &req,
        Duration::from_secs(timeout_secs.max(1)),
    )
    .await?;

    let stats = decode_query_stats_response(&resp_bytes);
    let json_items: Vec<serde_json::Value> = stats
        .into_iter()
        .map(|(name, value)| {
            serde_json::json!({
                "name": name,
                "value": value
            })
        })
        .collect();
    let out = serde_json::json!({ "stat": json_items });
    println!("{}", serde_json::to_string_pretty(&out).unwrap_or_else(|_| "{}".to_string()));
    Ok(())
}

async fn cmd_stats(args: &[String]) -> Result<(), String> {
    let mut server = "127.0.0.1:8080".to_string();
    let mut timeout_secs: u64 = 3;
    let mut name = String::new();
    let mut reset = false;

    let mut i = 0;
    while i < args.len() {
        let arg = &args[i];
        if let Some((k, inline_v)) = split_flag(arg) {
            match k {
                "s" | "server" => server = take_val(k, inline_v, args, &mut i)?,
                "t" | "timeout" => {
                    let v = take_val(k, inline_v, args, &mut i)?;
                    timeout_secs = v
                        .parse::<u64>()
                        .map_err(|_| format!("invalid -timeout '{v}'"))?;
                }
                "name" => name = take_val(k, inline_v, args, &mut i)?,
                "reset" => {
                    reset = inline_v
                        .map(|v| v != "false" && v != "0")
                        .unwrap_or(true);
                }
                _ => return Err(format!("unknown flag for 'api stats': {arg}")),
            }
        }
        i += 1;
    }

    let req = encode_stats_request(&name, reset);
    let resp_bytes = grpc_unary(
        &server,
        "/xray.app.stats.command.StatsService/GetStats",
        &req,
        Duration::from_secs(timeout_secs.max(1)),
    )
    .await?;

    let stats = decode_query_stats_response(&resp_bytes);
    if let Some((n, v)) = stats.into_iter().next() {
        let out = serde_json::json!({ "stat": { "name": n, "value": v } });
        println!("{}", serde_json::to_string_pretty(&out).unwrap_or_else(|_| "{}".to_string()));
    } else {
        println!("{{}}");
    }
    Ok(())
}

fn take_val(
    flag: &str,
    inline_v: Option<&str>,
    args: &[String],
    idx: &mut usize,
) -> Result<String, String> {
    if let Some(v) = inline_v {
        return Ok(v.to_string());
    }
    *idx += 1;
    if *idx >= args.len() {
        return Err(format!("-{flag} requires a value"));
    }
    Ok(args[*idx].clone())
}

async fn grpc_unary(
    server: &str,
    path: &str,
    payload: &[u8],
    dur: Duration,
) -> Result<Vec<u8>, String> {
    timeout(dur, async move {
        let tcp = TcpStream::connect(server)
            .await
            .map_err(|e| format!("failed to connect to API server '{server}': {e}"))?;
        let (mut send_req, conn) = client::handshake(tcp)
            .await
            .map_err(|e| format!("h2 handshake failed: {e}"))?;

        tokio::spawn(async move {
            let _ = conn.await;
        });

        let req = Request::builder()
            .method(Method::POST)
            .uri(format!("http://{server}{path}"))
            .header("content-type", "application/grpc")
            .header("te", "trailers")
            .body(())
            .map_err(|e| format!("request build error: {e}"))?;

        let (resp_fut, mut send_stream) = send_req
            .send_request(req, false)
            .map_err(|e| format!("h2 send_request error: {e}"))?;

        let mut frame = BytesMut::with_capacity(5 + payload.len());
        frame.put_u8(0);
        frame.put_u32(payload.len() as u32);
        frame.put_slice(payload);
        send_stream
            .send_data(frame.freeze(), true)
            .map_err(|e| format!("h2 send_data error: {e}"))?;

        let resp = resp_fut
            .await
            .map_err(|e| format!("h2 response error: {e}"))?;

        if let Some(status) = resp.headers().get("grpc-status") {
            if status != "0" {
                let msg = resp
                    .headers()
                    .get("grpc-message")
                    .and_then(|v| v.to_str().ok())
                    .unwrap_or("gRPC error");
                return Err(format!("gRPC status {}: {}", status.to_str().unwrap_or("?"), msg));
            }
        }

        let mut body = resp.into_body();
        let mut raw = BytesMut::new();
        while let Some(chunk_res) = body.data().await {
            let chunk = chunk_res.map_err(|e| format!("h2 read error: {e}"))?;
            let _ = body.flow_control().release_capacity(chunk.len());
            raw.extend_from_slice(&chunk);
        }
        if let Ok(Some(trailers)) = body.trailers().await {
            if let Some(status) = trailers.get("grpc-status") {
                if status != "0" {
                    let msg = trailers
                        .get("grpc-message")
                        .and_then(|v| v.to_str().ok())
                        .unwrap_or("gRPC error");
                    return Err(format!(
                        "gRPC status {}: {}",
                        status.to_str().unwrap_or("?"),
                        msg
                    ));
                }
            }
        }

        if raw.len() < 5 {
            return Ok(Vec::new());
        }
        let msg_len = u32::from_be_bytes([raw[1], raw[2], raw[3], raw[4]]) as usize;
        if raw.len() < 5 + msg_len {
            return Err("truncated gRPC response frame".to_string());
        }
        Ok(raw[5..5 + msg_len].to_vec())
    })
    .await
    .map_err(|_| format!("API request to '{server}' timed out"))?
}
