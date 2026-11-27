use std::io;
use std::time::Duration;

use base64::engine::general_purpose::{STANDARD, URL_SAFE, URL_SAFE_NO_PAD};
use base64::Engine;
use sha1::{Digest, Sha1};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader, DuplexStream};
use tokio::time::timeout;

use crate::config::WsSettings;
use crate::proxy_protocol::PrefixedStream;
use crate::transport::httpupgrade::find_header_end;
use crate::transport::normalize_path;

const MAX_HTTP_HEADER_BYTES: usize = 12_288;
const WS_GUID: &str = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
/// Cap single WebSocket frame size to 512 KB to prevent memory amplification attacks on low-RAM VPS.
const WS_MAX_FRAME_LEN: usize = 512 * 1024;
/// Compact 16 KB duplex buffer (4x lower RAM per connection than 64 KB while keeping full throughput).
const WS_DUPLEX_BUF: usize = 16 * 1024;
const WS_SHRINK_THRESHOLD: usize = 32 * 1024;

/// Accepts an RFC 6455 WebSocket connection with Xray early-data (`Sec-WebSocket-Protocol` base64)
/// support, returning a clean `DuplexStream` carrying raw binary payload bytes.
pub async fn accept_websocket<S: AsyncRead + AsyncWrite + Unpin + Send + 'static>(
    mut stream: S,
    cfg: &WsSettings,
) -> io::Result<(DuplexStream, Option<String>)> {
    let mut buf = Vec::with_capacity(1024);
    let mut tmp = [0u8; 1024];

    let header_end = timeout(Duration::from_secs(5), async {
        loop {
            let n = stream.read(&mut tmp).await?;
            if n == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "EOF during WebSocket handshake",
                ));
            }
            buf.extend_from_slice(&tmp[..n]);
            if let Some(pos) = find_header_end(&buf) {
                return Ok(pos);
            }
            if buf.len() > MAX_HTTP_HEADER_BYTES {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "WebSocket header too large",
                ));
            }
        }
    })
    .await
    .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "WebSocket handshake timeout"))??;

    let header_str = std::str::from_utf8(&buf[..header_end]).map_err(|_| {
        io::Error::new(io::ErrorKind::InvalidData, "invalid UTF-8 in WS header")
    })?;

    let mut lines = header_str.split("\r\n");
    let req_line = lines
        .next()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "missing HTTP request line"))?;
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
            format!("WebSocket bad path '{req_path}' (expected '{expected_path}')"),
        ));
    }

    let mut host = "";
    let mut ws_key = "";
    let mut ws_early_data_hdr = "";
    let mut forwarded_ip: Option<String> = None;

    for line in lines {
        if let Some((k, v)) = line.split_once(':') {
            let v = v.trim();
            if k.eq_ignore_ascii_case("host") {
                host = v;
            } else if k.eq_ignore_ascii_case("sec-websocket-key") {
                ws_key = v;
            } else if k.eq_ignore_ascii_case("sec-websocket-protocol") {
                ws_early_data_hdr = v;
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
                format!("WebSocket bad host '{host}'"),
            ));
        }
    }

    if ws_key.is_empty() {
        let _ = stream
            .write_all(b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
            .await;
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "missing Sec-WebSocket-Key",
        ));
    }

    let early_data = if !ws_early_data_hdr.is_empty() {
        decode_early_data(ws_early_data_hdr)
    } else {
        None
    };

    let mut sha1 = Sha1::new();
    sha1.update(ws_key.as_bytes());
    sha1.update(WS_GUID.as_bytes());
    let accept = STANDARD.encode(sha1.finalize());

    let resp = format!(
        "HTTP/1.1 101 Switching Protocols\r\n\
         Upgrade: websocket\r\n\
         Connection: Upgrade\r\n\
         Sec-WebSocket-Accept: {accept}\r\n\r\n"
    );
    stream.write_all(resp.as_bytes()).await?;
    stream.flush().await?;

    let leftover = buf[(header_end + 4)..].to_vec();
    let ws_wire = PrefixedStream::new(leftover, stream);

    let (app_side, pump_side) = tokio::io::duplex(WS_DUPLEX_BUF);
    tokio::spawn(run_ws_pump(ws_wire, pump_side, early_data));
    Ok((app_side, forwarded_ip))
}

fn decode_early_data(hdr: &str) -> Option<Vec<u8>> {
    let trimmed = hdr.trim();
    URL_SAFE_NO_PAD
        .decode(trimmed)
        .or_else(|_| URL_SAFE.decode(trimmed))
        .or_else(|_| STANDARD.decode(trimmed))
        .ok()
}

async fn run_ws_pump<S: AsyncRead + AsyncWrite + Unpin + Send + 'static>(
    wire: S,
    app: DuplexStream,
    early_data: Option<Vec<u8>>,
) {
    let (wire_r_raw, mut wire_w) = tokio::io::split(wire);
    let mut wire_r = BufReader::with_capacity(16 * 1024, wire_r_raw);
    let (mut app_r, mut app_w) = tokio::io::split(app);
    let (ctrl_tx, mut ctrl_rx) = tokio::sync::mpsc::channel::<Vec<u8>>(16);

    // Reader task: WS frames -> app_w
    let mut read_task = tokio::spawn(async move {
        if let Some(ed) = early_data {
            if !ed.is_empty() && app_w.write_all(&ed).await.is_err() {
                return;
            }
        }
        let mut payload = Vec::with_capacity(4096);
        loop {
            let mut h2 = [0u8; 2];
            if wire_r.read_exact(&mut h2).await.is_err() {
                break;
            }
            let opcode = h2[0] & 0x0F;
            let masked = (h2[1] & 0x80) != 0;
            let len7 = (h2[1] & 0x7F) as usize;

            let frame_len = match len7 {
                0..=125 => len7,
                126 => {
                    let mut b = [0u8; 2];
                    if wire_r.read_exact(&mut b).await.is_err() {
                        break;
                    }
                    u16::from_be_bytes(b) as usize
                }
                127 => {
                    let mut b = [0u8; 8];
                    if wire_r.read_exact(&mut b).await.is_err() {
                        break;
                    }
                    u64::from_be_bytes(b) as usize
                }
                _ => break,
            };

            if frame_len > WS_MAX_FRAME_LEN {
                break;
            }

            let mut mask_key = [0u8; 4];
            if masked && wire_r.read_exact(&mut mask_key).await.is_err() {
                break;
            }

            payload.resize(frame_len, 0);
            if frame_len > 0 && wire_r.read_exact(&mut payload).await.is_err() {
                break;
            }

            if masked {
                for (i, b) in payload.iter_mut().enumerate() {
                    *b ^= mask_key[i & 3];
                }
            }

            match opcode {
                0x00..=0x02 => {
                    if !payload.is_empty() && app_w.write_all(&payload).await.is_err() {
                        break;
                    }
                }
                0x08 => {
                    let _ = ctrl_tx.try_send(build_ws_frame(0x08, &[]));
                    break;
                }
                0x09 => {
                    let _ = ctrl_tx.try_send(build_ws_frame(0x0A, &payload));
                }
                0x0A => {}
                _ => break,
            }

            // Reclaim memory if a large frame temporarily grew the buffer.
            if payload.capacity() > WS_SHRINK_THRESHOLD {
                payload.clear();
                payload.shrink_to(16 * 1024);
            }
        }
        let _ = app_w.shutdown().await;
    });

    // Writer task: app_r + control frames -> wire_w (zero-copy 10B headroom framing)
    let mut write_task = tokio::spawn(async move {
        const HEADROOM: usize = 10;
        let mut buf = vec![0u8; HEADROOM + 16 * 1024];
        loop {
            tokio::select! {
                biased;
                Some(ctrl_frame) = ctrl_rx.recv() => {
                    if wire_w.write_all(&ctrl_frame).await.is_err() {
                        break;
                    }
                }
                res = app_r.read(&mut buf[HEADROOM..]) => {
                    match res {
                        Ok(0) => {
                            let close = build_ws_frame(0x08, &[]);
                            let _ = wire_w.write_all(&close).await;
                            break;
                        }
                        Ok(n) => {
                            let start = write_ws_header_before(&mut buf, HEADROOM, 0x02, n);
                            if wire_w.write_all(&buf[start..HEADROOM + n]).await.is_err() {
                                break;
                            }
                        }
                        Err(_) => break,
                    }
                }
            }
        }
        let _ = wire_w.shutdown().await;
    });

    // Abort the sibling half when either direction terminates so zombie tasks never linger.
    tokio::select! {
        _ = &mut read_task => { write_task.abort(); }
        _ = &mut write_task => { read_task.abort(); }
    }
}

/// Builds an unmasked server-to-client RFC 6455 WebSocket frame.
pub(crate) fn build_ws_frame(opcode: u8, payload: &[u8]) -> Vec<u8> {
    let len = payload.len();
    let header_len = if len <= 125 {
        2
    } else if len <= 65535 {
        4
    } else {
        10
    };
    let mut out = Vec::with_capacity(header_len + len);
    out.push(0x80 | (opcode & 0x0F));
    if len <= 125 {
        out.push(len as u8);
    } else if len <= 65535 {
        out.push(126);
        out.extend_from_slice(&(len as u16).to_be_bytes());
    } else {
        out.push(127);
        out.extend_from_slice(&(len as u64).to_be_bytes());
    }
    out.extend_from_slice(payload);
    out
}

/// Writes an unmasked RFC 6455 header directly before `payload_start` and returns the frame start index.
#[inline]
fn write_ws_header_before(buf: &mut [u8], payload_start: usize, opcode: u8, len: usize) -> usize {
    if len <= 125 {
        let start = payload_start - 2;
        buf[start] = 0x80 | (opcode & 0x0F);
        buf[start + 1] = len as u8;
        start
    } else if len <= 65535 {
        let start = payload_start - 4;
        buf[start] = 0x80 | (opcode & 0x0F);
        buf[start + 1] = 126;
        buf[start + 2..start + 4].copy_from_slice(&(len as u16).to_be_bytes());
        start
    } else {
        let start = payload_start - 10;
        buf[start] = 0x80 | (opcode & 0x0F);
        buf[start + 1] = 127;
        buf[start + 2..start + 10].copy_from_slice(&(len as u64).to_be_bytes());
        start
    }
}
