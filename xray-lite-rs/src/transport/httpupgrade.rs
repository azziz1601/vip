use std::io;
use std::time::Duration;

use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use sha1::{Digest, Sha1};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::time::timeout;

use crate::config::HttpUpgradeSettings;
use crate::proxy_protocol::PrefixedStream;
use crate::transport::normalize_path;

const MAX_HTTP_HEADER_BYTES: usize = 12_288;
const WS_GUID: &str = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

/// Performs Xray HTTPUpgrade handshake (`HTTP/1.1 101 Switching Protocols`) and returns a raw stream
/// preserving any trailing early-data bytes after `\r\n\r\n`.
pub async fn accept_httpupgrade<S: AsyncRead + AsyncWrite + Unpin>(
    mut stream: S,
    cfg: &HttpUpgradeSettings,
) -> io::Result<(PrefixedStream<S>, Option<String>)> {
    let mut buf = Vec::with_capacity(1024);
    let mut tmp = [0u8; 1024];

    let header_end = timeout(Duration::from_secs(5), async {
        loop {
            let n = stream.read(&mut tmp).await?;
            if n == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "EOF during HTTPUpgrade handshake",
                ));
            }
            buf.extend_from_slice(&tmp[..n]);
            if let Some(pos) = find_header_end(&buf) {
                return Ok(pos);
            }
            if buf.len() > MAX_HTTP_HEADER_BYTES {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "HTTPUpgrade header too large",
                ));
            }
        }
    })
    .await
    .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "HTTPUpgrade handshake timeout"))??;

    let header_str = std::str::from_utf8(&buf[..header_end]).map_err(|_| {
        io::Error::new(io::ErrorKind::InvalidData, "invalid UTF-8 in HTTPUpgrade header")
    })?;

    let mut lines = header_str.split("\r\n");
    let req_line = lines.next().ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidData, "missing HTTP request line")
    })?;
    let mut req_parts = req_line.split_whitespace();
    let _method = req_parts.next();
    let raw_target = req_parts.next().unwrap_or("/");
    let req_path = raw_target.split('?').next().unwrap_or(raw_target);

    let expected_path = normalize_path(&cfg.path);
    if req_path != expected_path {
        let _ = stream
            .write_all(b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
            .await;
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!("HTTPUpgrade bad path '{req_path}' (expected '{expected_path}')"),
        ));
    }

    let mut host = "";
    let mut connection = "";
    let mut upgrade = "";
    let mut ws_key = "";
    let mut forwarded_ip: Option<String> = None;

    for line in lines {
        if let Some((k, v)) = line.split_once(':') {
            let v = v.trim();
            if k.eq_ignore_ascii_case("host") {
                host = v;
            } else if k.eq_ignore_ascii_case("connection") {
                connection = v;
            } else if k.eq_ignore_ascii_case("upgrade") {
                upgrade = v;
            } else if k.eq_ignore_ascii_case("sec-websocket-key") {
                ws_key = v;
            } else if k.eq_ignore_ascii_case("x-forwarded-for") && forwarded_ip.is_none() {
                if let Some(first) = v.split(',').next().map(str::trim).filter(|ip| !ip.is_empty()) {
                    forwarded_ip = Some(first.to_string());
                }
            } else if k.eq_ignore_ascii_case("x-real-ip") && forwarded_ip.is_none() && !v.is_empty() {
                forwarded_ip = Some(v.to_string());
            }
        }
    }

    if !cfg.host.is_empty() {
        let host_no_port = host.split(':').next().unwrap_or(host);
        if !host_no_port.eq_ignore_ascii_case(&cfg.host) {
            let _ = stream
                .write_all(b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
                .await;
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!("HTTPUpgrade bad host '{host}'"),
            ));
        }
    }

    if !connection.to_ascii_lowercase().contains("upgrade")
        || !upgrade.eq_ignore_ascii_case("websocket")
    {
        let _ = stream
            .write_all(b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
            .await;
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "unrecognized HTTPUpgrade request",
        ));
    }

    let mut resp = String::from(
        "HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n",
    );
    if !ws_key.is_empty() {
        let mut sha1 = Sha1::new();
        sha1.update(ws_key.as_bytes());
        sha1.update(WS_GUID.as_bytes());
        let accept = STANDARD.encode(sha1.finalize());
        resp.push_str(&format!("Sec-WebSocket-Accept: {accept}\r\n"));
    }
    resp.push_str("\r\n");

    stream.write_all(resp.as_bytes()).await?;
    stream.flush().await?;

    let leftover = buf[(header_end + 4)..].to_vec();
    Ok((PrefixedStream::new(leftover, stream), forwarded_ip))
}

pub(crate) fn find_header_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n")
}
