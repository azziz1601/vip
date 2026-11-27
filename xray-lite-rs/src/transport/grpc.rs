use std::future::Future;
use std::io;

use bytes::{Buf, BufMut, Bytes, BytesMut};
use h2::server;
use http::{HeaderMap, HeaderValue, Response, StatusCode};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, DuplexStream};

use crate::config::GrpcSettings;
use crate::log_debug;
use crate::transport::BoxedStream;

const GRPC_DUPLEX_BUF: usize = 16 * 1024;
const GRPC_MAX_MSG_LEN: usize = 512 * 1024;

/// Serves an HTTP/2 connection carrying Xray gRPC Gun streams (`/{serviceName}/Tun` and `/TunMulti`),
/// invoking `on_stream` concurrently for every accepted tunnel stream.
pub async fn serve_grpc_connection<S, F, Fut>(
    stream: S,
    cfg: GrpcSettings,
    on_stream: F,
) -> io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    F: Fn(BoxedStream, Option<String>) -> Fut + Send + Sync + 'static,
    Fut: Future<Output = ()> + Send + 'static,
{
    let mut h2_conn = server::handshake(stream)
        .await
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("h2 handshake: {e}")))?;

    let svc = cfg.service_name.trim_matches('/').to_string();
    let on_stream = std::sync::Arc::new(on_stream);

    while let Some(next) = h2_conn.accept().await {
        let (req, mut respond) = match next {
            Ok(pair) => pair,
            Err(e) => {
                log_debug!("gRPC h2 accept error: {}", e);
                break;
            }
        };

        let path = req.uri().path();
        let path_ok = if svc.is_empty() {
            path.ends_with("/Tun") || path.ends_with("/TunMulti")
        } else {
            path == format!("/{svc}/Tun") || path == format!("/{svc}/TunMulti")
        };

        if !path_ok {
            let resp = Response::builder()
                .status(StatusCode::NOT_FOUND)
                .body(())
                .unwrap();
            let _ = respond.send_response(resp, true);
            continue;
        }

        let resp = Response::builder()
            .status(StatusCode::OK)
            .header("content-type", "application/grpc")
            .body(())
            .unwrap();

        let send_stream = match respond.send_response(resp, false) {
            Ok(s) => s,
            Err(e) => {
                log_debug!("gRPC send_response error: {}", e);
                continue;
            }
        };

        let forwarded_ip = req
            .headers()
            .get("x-forwarded-for")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.split(',').next())
            .map(str::trim)
            .filter(|v| !v.is_empty())
            .map(str::to_string)
            .or_else(|| {
                req.headers()
                    .get("x-real-ip")
                    .and_then(|v| v.to_str().ok())
                    .map(str::trim)
                    .filter(|v| !v.is_empty())
                    .map(str::to_string)
            });
        let recv_stream = req.into_body();
        let (app_side, pump_side) = tokio::io::duplex(GRPC_DUPLEX_BUF);

        tokio::spawn(run_grpc_stream_pump(recv_stream, send_stream, pump_side));

        let cb = std::sync::Arc::clone(&on_stream);
        tokio::spawn(async move {
            cb(Box::new(app_side), forwarded_ip).await;
        });
    }

    Ok(())
}

async fn run_grpc_stream_pump(
    mut recv: h2::RecvStream,
    mut send: h2::SendStream<Bytes>,
    app: DuplexStream,
) {
    let (mut app_r, mut app_w) = tokio::io::split(app);

    // Uplink: HTTP/2 gRPC Hunk / MultiHunk frames -> app_w
    let mut up_task = tokio::spawn(async move {
        let mut buf = BytesMut::with_capacity(8192);
        while let Some(chunk_res) = recv.data().await {
            let chunk = match chunk_res {
                Ok(c) => c,
                Err(_) => break,
            };
            let chunk_len = chunk.len();
            if chunk_len > 0 {
                let _ = recv.flow_control().release_capacity(chunk_len);
                buf.extend_from_slice(&chunk);
            }

            // Parse complete 5-byte gRPC frames: [compressed: 1B][len: 4B BE][protobuf Hunk/MultiHunk]
            while buf.len() >= 5 {
                let msg_len = u32::from_be_bytes([buf[1], buf[2], buf[3], buf[4]]) as usize;
                if msg_len > GRPC_MAX_MSG_LEN {
                    return;
                }
                if buf.len() < 5 + msg_len {
                    break;
                }
                buf.advance(5);
                let msg = buf.split_to(msg_len);
                let mut offset = 0usize;
                while let Some((payload, next_off)) = decode_protobuf_hunk_at(&msg, offset) {
                    offset = next_off;
                    if !payload.is_empty() && app_w.write_all(payload).await.is_err() {
                        return;
                    }
                }
            }
        }
        let _ = app_w.shutdown().await;
    });

    // Downlink: app_r -> HTTP/2 gRPC Hunk frames
    let mut down_task = tokio::spawn(async move {
        let mut read_buf = vec![0u8; 16 * 1024];
        loop {
            match app_r.read(&mut read_buf).await {
                Ok(0) => {
                    let mut trailers = HeaderMap::new();
                    trailers.insert("grpc-status", HeaderValue::from_static("0"));
                    let _ = send.send_trailers(trailers);
                    break;
                }
                Ok(n) => {
                    let frame = encode_grpc_hunk(&read_buf[..n]);
                    if send_all_h2(&mut send, frame).await.is_err() {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
    });

    // Abort sibling half when either direction ends to prevent zombie h2 tasks.
    tokio::select! {
        _ = &mut up_task => { down_task.abort(); }
        _ = &mut down_task => { up_task.abort(); }
    }
}

async fn send_all_h2(send: &mut h2::SendStream<Bytes>, mut data: Bytes) -> io::Result<()> {
    while !data.is_empty() {
        send.reserve_capacity(data.len());
        let cap = match std::future::poll_fn(|cx| send.poll_capacity(cx)).await {
            Some(Ok(c)) => c,
            Some(Err(e)) => return Err(io::Error::new(io::ErrorKind::BrokenPipe, e.to_string())),
            None => {
                return Err(io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    "h2 send stream closed",
                ));
            }
        };
        let to_send = cap.min(data.len());
        let chunk = data.split_to(to_send);
        send.send_data(chunk, false)
            .map_err(|e| io::Error::new(io::ErrorKind::BrokenPipe, e.to_string()))?;
    }
    Ok(())
}

/// Encodes raw bytes as a 5-byte gRPC frame containing protobuf `Hunk { bytes data = 1; }`.
pub(crate) fn encode_grpc_hunk(data: &[u8]) -> Bytes {
    let mut varint = [0u8; 10];
    let vlen = encode_varint(data.len() as u64, &mut varint);
    let proto_len = 1 + vlen + data.len();

    let mut out = BytesMut::with_capacity(5 + proto_len);
    out.put_u8(0x00); // uncompressed
    out.put_u32(proto_len as u32);
    out.put_u8(0x0A); // protobuf field 1, wire type 2 (length-delimited)
    out.put_slice(&varint[..vlen]);
    out.put_slice(data);
    out.freeze()
}

/// Decodes one `bytes data = 1` field from a `Hunk` or `MultiHunk` protobuf message starting at `offset`.
pub(crate) fn decode_protobuf_hunk_at(msg: &[u8], offset: usize) -> Option<(&[u8], usize)> {
    if offset >= msg.len() {
        return None;
    }
    if msg[offset] != 0x0A {
        return None;
    }
    let (len, consumed) = decode_varint(&msg[offset + 1..])?;
    let start = offset + 1 + consumed;
    let end = start.checked_add(len as usize)?;
    if end > msg.len() {
        return None;
    }
    Some((&msg[start..end], end))
}

fn encode_varint(mut v: u64, out: &mut [u8; 10]) -> usize {
    let mut i = 0;
    while v >= 0x80 {
        out[i] = ((v as u8) & 0x7F) | 0x80;
        v >>= 7;
        i += 1;
    }
    out[i] = v as u8;
    i + 1
}

fn decode_varint(buf: &[u8]) -> Option<(u64, usize)> {
    let mut val = 0u64;
    let mut shift = 0u32;
    for (i, &b) in buf.iter().enumerate().take(10) {
        val |= ((b & 0x7F) as u64) << shift;
        if (b & 0x80) == 0 {
            return Some((val, i + 1));
        }
        shift += 7;
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_grpc_hunk_and_multihunk() {
        let payload = b"hello-xray-grpc";
        let frame = encode_grpc_hunk(payload);
        assert_eq!(frame[0], 0x00);
        let msg_len = u32::from_be_bytes([frame[1], frame[2], frame[3], frame[4]]) as usize;
        assert_eq!(msg_len, frame.len() - 5);
        let (decoded, next) = decode_protobuf_hunk_at(&frame[5..], 0).unwrap();
        assert_eq!(decoded, payload);
        assert_eq!(next, msg_len);
    }
}
