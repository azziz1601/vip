use std::cmp::Reverse;
use std::collections::{BinaryHeap, HashMap};
use std::future::Future;
use std::io;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bytes::{Buf, Bytes, BytesMut};
use h2::server;
use http::{Response, StatusCode};
use rand::Rng;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, DuplexStream};
use tokio::sync::mpsc;
use tokio::time::timeout;

use crate::config::XhttpSettings;
use crate::log_debug;
use crate::proxy_protocol::PrefixedStream;
use crate::transport::httpupgrade::find_header_end;
use crate::transport::BoxedStream;

const H2_PREFACE: &[u8; 24] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
const XHTTP_DUPLEX_BUF: usize = 16 * 1024;
const MAX_HTTP1_HEADER_BYTES: usize = 16 * 1024;
const DEFAULT_MAX_EACH_POST_BYTES: usize = 1_000_000;
const DEFAULT_MAX_BUFFERED_POSTS: usize = 30;
const ORPHAN_SESSION_TTL: Duration = Duration::from_secs(30);
const HTTP1_READ_TIMEOUT: Duration = Duration::from_secs(30);

enum UploadItem {
    Packet { seq: u64, data: Vec<u8> },
    StreamChunk(Vec<u8>),
    StreamEof,
}

struct XhttpSession {
    tx: mpsc::Sender<UploadItem>,
    rx: Mutex<Option<mpsc::Receiver<UploadItem>>>,
    connected: AtomicBool,
    stream_up_taken: AtomicBool,
}

/// Per-inbound XHTTP (SplitHTTP) session hub shared across all HTTP/1.1 & HTTP/2 connections.
pub struct XhttpHub {
    cfg: XhttpSettings,
    base_path: String,
    base_path_trimmed: String,
    max_each_post: usize,
    max_buffered_posts: usize,
    sessions: Mutex<HashMap<String, Arc<XhttpSession>>>,
}

impl XhttpHub {
    pub fn new(cfg: XhttpSettings) -> Arc<Self> {
        let mut p = cfg.path.trim().to_string();
        if !p.starts_with('/') {
            p.insert(0, '/');
        }
        if !p.ends_with('/') {
            p.push('/');
        }
        let trimmed = if p == "/" {
            "/".to_string()
        } else {
            p.trim_end_matches('/').to_string()
        };
        let max_each_post = cfg
            .sc_max_each_post_bytes
            .filter(|&v| v > 0)
            .unwrap_or(DEFAULT_MAX_EACH_POST_BYTES);
        let max_buffered_posts = cfg
            .sc_max_buffered_posts
            .filter(|&v| v > 0)
            .unwrap_or(DEFAULT_MAX_BUFFERED_POSTS);

        Arc::new(Self {
            cfg,
            base_path: p,
            base_path_trimmed: trimmed,
            max_each_post,
            max_buffered_posts,
            sessions: Mutex::new(HashMap::new()),
        })
    }

    fn matches_host(&self, host: &str) -> bool {
        if self.cfg.host.is_empty() {
            return true;
        }
        let host_no_port = host.split(':').next().unwrap_or(host);
        host_no_port.eq_ignore_ascii_case(&self.cfg.host)
    }

    /// Validates request path and extracts `(session_id, seq_str)` following Xray-core's
    /// default path placement (`{base_path}{session_id}/{seq}`).
    pub fn extract_meta(&self, raw_path: &str) -> Option<(String, String)> {
        let path_only = raw_path.split('?').next().unwrap_or(raw_path);
        let rest = if let Some(r) = path_only.strip_prefix(&self.base_path) {
            r
        } else if path_only == self.base_path_trimmed {
            ""
        } else {
            return None;
        };

        if rest.is_empty() {
            return Some((String::new(), String::new()));
        }
        let mut parts = rest.split('/');
        let session_id = parts.next().unwrap_or("").to_string();
        let seq_str = parts.next().unwrap_or("").to_string();
        Some((session_id, seq_str))
    }

    fn mode_allows(&self, target: &str) -> bool {
        let m = self.cfg.mode.trim();
        m.is_empty() || m.eq_ignore_ascii_case("auto") || m.eq_ignore_ascii_case(target)
    }

    fn upsert_session(self: &Arc<Self>, session_id: &str) -> Arc<XhttpSession> {
        {
            let map = self.sessions.lock().unwrap_or_else(|e| e.into_inner());
            if let Some(s) = map.get(session_id) {
                return Arc::clone(s);
            }
        }
        let (tx, rx) = mpsc::channel(self.max_buffered_posts.max(16));
        let session = Arc::new(XhttpSession {
            tx,
            rx: Mutex::new(Some(rx)),
            connected: AtomicBool::new(false),
            stream_up_taken: AtomicBool::new(false),
        });
        {
            let mut map = self.sessions.lock().unwrap_or_else(|e| e.into_inner());
            if let Some(existing) = map.get(session_id) {
                return Arc::clone(existing);
            }
            map.insert(session_id.to_string(), Arc::clone(&session));
        }

        // Reap orphaned sessions if GET stream-down never arrives within 30s.
        let hub = Arc::clone(self);
        let sid = session_id.to_string();
        let sess_ref = Arc::clone(&session);
        tokio::spawn(async move {
            tokio::time::sleep(ORPHAN_SESSION_TTL).await;
            if !sess_ref.connected.load(Ordering::Acquire) {
                hub.remove_session(&sid);
            }
        });

        session
    }

    fn remove_session(&self, session_id: &str) {
        let mut map = self.sessions.lock().unwrap_or_else(|e| e.into_inner());
        map.remove(session_id);
    }

    fn random_padding(&self) -> String {
        let len = rand::thread_rng().gen_range(100..=500);
        "X".repeat(len)
    }
}

/// Auto-detects HTTP/2 (`h2` / `h2c`) vs HTTP/1.1 on an accepted XHTTP connection and serves
/// `stream-one`, `stream-up`, and `packet-up` + `stream-down` modes.
pub async fn serve_xhttp_connection<S, F, Fut>(
    mut stream: S,
    hub: Arc<XhttpHub>,
    on_stream: F,
) -> io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    F: Fn(BoxedStream, Option<String>) -> Fut + Send + Sync + 'static,
    Fut: Future<Output = ()> + Send + 'static,
{
    let mut peek = [0u8; 24];
    let n = timeout(Duration::from_secs(10), stream.read(&mut peek))
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "XHTTP initial read timeout"))??;
    if n == 0 {
        return Ok(());
    }

    let is_h2 = (n >= 4 && &peek[..4] == b"PRI ")
        || (n == 24 && &peek == H2_PREFACE);
    let prefixed = PrefixedStream::new(peek[..n].to_vec(), stream);

    if is_h2 {
        serve_xhttp_h2(prefixed, hub, Arc::new(on_stream)).await
    } else {
        serve_xhttp_h1(prefixed, hub, Arc::new(on_stream)).await
    }
}

async fn serve_xhttp_h2<S, F, Fut>(
    stream: S,
    hub: Arc<XhttpHub>,
    on_stream: Arc<F>,
) -> io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    F: Fn(BoxedStream, Option<String>) -> Fut + Send + Sync + 'static,
    Fut: Future<Output = ()> + Send + 'static,
{
    let mut h2_conn = server::handshake(stream)
        .await
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("XHTTP h2 handshake: {e}")))?;

    while let Some(next) = h2_conn.accept().await {
        let (req, mut respond) = match next {
            Ok(pair) => pair,
            Err(e) => {
                log_debug!("XHTTP h2 accept error: {}", e);
                break;
            }
        };

        let hub = Arc::clone(&hub);
        let on_stream = Arc::clone(&on_stream);

        tokio::spawn(async move {
            let method = req.method().as_str().to_ascii_uppercase();
            let host = req
                .headers()
                .get("host")
                .and_then(|v| v.to_str().ok())
                .or_else(|| req.uri().authority().map(|a| a.as_str()))
                .unwrap_or("");
            if !hub.matches_host(host) {
                send_h2_status(&mut respond, StatusCode::NOT_FOUND, &hub);
                return;
            }

            let raw_path = req
                .uri()
                .path_and_query()
                .map(|pq| pq.as_str())
                .unwrap_or(req.uri().path());
            let Some((session_id, seq_str)) = hub.extract_meta(raw_path) else {
                send_h2_status(&mut respond, StatusCode::NOT_FOUND, &hub);
                return;
            };

            // CORS preflight
            if method == "OPTIONS" && req.headers().contains_key("access-control-request-method") {
                send_h2_status(&mut respond, StatusCode::OK, &hub);
                return;
            }

            let forwarded_ip = extract_forwarded_ip_h2(req.headers());
            let is_uplink = match method.as_str() {
                "GET" => !seq_str.is_empty(),
                _ => true,
            };

            if is_uplink && !session_id.is_empty() {
                let session = hub.upsert_session(&session_id);
                if seq_str.is_empty() {
                    // stream-up
                    if !hub.mode_allows("stream-up") {
                        send_h2_status(&mut respond, StatusCode::BAD_REQUEST, &hub);
                        return;
                    }
                    if session.stream_up_taken.swap(true, Ordering::AcqRel) {
                        send_h2_status(&mut respond, StatusCode::CONFLICT, &hub);
                        return;
                    }
                    let resp = Response::builder()
                        .status(StatusCode::OK)
                        .header("x-padding", hub.random_padding())
                        .header("x-accel-buffering", "no")
                        .header("cache-control", "no-store")
                        .body(())
                        .unwrap();
                    let _send = respond.send_response(resp, false);

                    let mut body = req.into_body();
                    while let Some(chunk_res) = body.data().await {
                        match chunk_res {
                            Ok(chunk) => {
                                let _ = body.flow_control().release_capacity(chunk.len());
                                if !chunk.is_empty()
                                    && session
                                        .tx
                                        .send(UploadItem::StreamChunk(chunk.to_vec()))
                                        .await
                                        .is_err()
                                {
                                    break;
                                }
                            }
                            Err(_) => break,
                        }
                    }
                    let _ = session.tx.send(UploadItem::StreamEof).await;
                    return;
                }

                // packet-up
                if !hub.mode_allows("packet-up") {
                    send_h2_status(&mut respond, StatusCode::BAD_REQUEST, &hub);
                    return;
                }
                let Ok(seq) = seq_str.parse::<u64>() else {
                    send_h2_status(&mut respond, StatusCode::BAD_REQUEST, &hub);
                    return;
                };
                let mut body = req.into_body();
                let mut payload = Vec::new();
                while let Some(chunk_res) = body.data().await {
                    match chunk_res {
                        Ok(chunk) => {
                            let _ = body.flow_control().release_capacity(chunk.len());
                            if payload.len() + chunk.len() > hub.max_each_post {
                                send_h2_status(&mut respond, StatusCode::PAYLOAD_TOO_LARGE, &hub);
                                return;
                            }
                            payload.extend_from_slice(&chunk);
                        }
                        Err(_) => {
                            send_h2_status(&mut respond, StatusCode::BAD_REQUEST, &hub);
                            return;
                        }
                    }
                }
                if session
                    .tx
                    .send(UploadItem::Packet { seq, data: payload })
                    .await
                    .is_err()
                {
                    send_h2_status(&mut respond, StatusCode::INTERNAL_SERVER_ERROR, &hub);
                    return;
                }
                send_h2_status(&mut respond, StatusCode::OK, &hub);
            } else if method == "GET" || session_id.is_empty() {
                // stream-down (session_id != "") or stream-one (session_id == "")
                if session_id.is_empty()
                    && !hub.mode_allows("stream-one")
                    && !hub.mode_allows("stream-up")
                {
                    send_h2_status(&mut respond, StatusCode::BAD_REQUEST, &hub);
                    return;
                }

                let mut rb = Response::builder()
                    .status(StatusCode::OK)
                    .header("x-padding", hub.random_padding())
                    .header("x-accel-buffering", "no")
                    .header("cache-control", "no-store");
                if !hub.cfg.no_sse_header {
                    rb = rb.header("content-type", "text/event-stream");
                }
                let resp = rb.body(()).unwrap();
                let send_stream = match respond.send_response(resp, false) {
                    Ok(s) => s,
                    Err(_) => return,
                };

                let (app_side, pump_side) = tokio::io::duplex(XHTTP_DUPLEX_BUF);

                if session_id.is_empty() {
                    // stream-one: request body -> app, app -> response body
                    let recv_stream = req.into_body();
                    tokio::spawn(run_h2_stream_one_pump(recv_stream, send_stream, pump_side));
                } else {
                    // stream-down: UploadQueue -> app, app -> response body
                    let session = hub.upsert_session(&session_id);
                    session.connected.store(true, Ordering::Release);
                    let rx_opt = session
                        .rx
                        .lock()
                        .unwrap_or_else(|e| e.into_inner())
                        .take();
                    let Some(rx) = rx_opt else {
                        return;
                    };
                    let hub_cleanup = Arc::clone(&hub);
                    let sid_cleanup = session_id.clone();
                    let max_buf = hub.max_buffered_posts;
                    tokio::spawn(async move {
                        run_h2_stream_down_pump(rx, send_stream, pump_side, max_buf).await;
                        hub_cleanup.remove_session(&sid_cleanup);
                    });
                }

                on_stream(Box::new(app_side), forwarded_ip).await;
            } else {
                send_h2_status(&mut respond, StatusCode::METHOD_NOT_ALLOWED, &hub);
            }
        });
    }

    Ok(())
}

async fn run_h2_stream_one_pump(
    mut recv: h2::RecvStream,
    mut send: h2::SendStream<Bytes>,
    app: DuplexStream,
) {
    let (mut app_r, mut app_w) = tokio::io::split(app);

    let mut up = tokio::spawn(async move {
        while let Some(chunk_res) = recv.data().await {
            let Ok(chunk) = chunk_res else { break };
            let _ = recv.flow_control().release_capacity(chunk.len());
            if !chunk.is_empty() && app_w.write_all(&chunk).await.is_err() {
                break;
            }
        }
        let _ = app_w.shutdown().await;
    });

    let mut down = tokio::spawn(async move {
        let mut buf = vec![0u8; 8192];
        loop {
            match app_r.read(&mut buf).await {
                Ok(0) => break,
                Ok(n) => {
                    if send_h2_all(&mut send, Bytes::copy_from_slice(&buf[..n]))
                        .await
                        .is_err()
                    {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
        let _ = send.send_data(Bytes::new(), true);
    });

    tokio::select! {
        _ = &mut up => { down.abort(); }
        _ = &mut down => { up.abort(); }
    }
}

async fn run_h2_stream_down_pump(
    rx: mpsc::Receiver<UploadItem>,
    mut send: h2::SendStream<Bytes>,
    app: DuplexStream,
    max_buffered_posts: usize,
) {
    let (mut app_r, app_w) = tokio::io::split(app);

    let mut up = tokio::spawn(pump_upload_queue_to_writer(rx, app_w, max_buffered_posts));

    let mut down = tokio::spawn(async move {
        let mut buf = vec![0u8; 8192];
        loop {
            match app_r.read(&mut buf).await {
                Ok(0) => break,
                Ok(n) => {
                    if send_h2_all(&mut send, Bytes::copy_from_slice(&buf[..n]))
                        .await
                        .is_err()
                    {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
        let _ = send.send_data(Bytes::new(), true);
    });

    tokio::select! {
        _ = &mut up => { down.abort(); }
        _ = &mut down => { up.abort(); }
    }
}

async fn pump_upload_queue_to_writer<W: AsyncWrite + Unpin>(
    mut rx: mpsc::Receiver<UploadItem>,
    mut writer: W,
    max_buffered_posts: usize,
) {
    let mut heap: BinaryHeap<Reverse<(u64, Vec<u8>)>> = BinaryHeap::new();
    let mut next_seq: u64 = 0;

    while let Some(item) = rx.recv().await {
        match item {
            UploadItem::StreamChunk(data) => {
                if !data.is_empty() && writer.write_all(&data).await.is_err() {
                    break;
                }
            }
            UploadItem::StreamEof => break,
            UploadItem::Packet { seq, data } => {
                if seq < next_seq {
                    continue; // duplicate/stale packet
                }
                if seq == next_seq {
                    if !data.is_empty() && writer.write_all(&data).await.is_err() {
                        break;
                    }
                    next_seq += 1;
                    while let Some(Reverse((s, _))) = heap.peek() {
                        if *s == next_seq {
                            let Reverse((_, d)) = heap.pop().unwrap();
                            if !d.is_empty() && writer.write_all(&d).await.is_err() {
                                let _ = writer.shutdown().await;
                                return;
                            }
                            next_seq += 1;
                        } else if *s < next_seq {
                            heap.pop();
                        } else {
                            break;
                        }
                    }
                } else {
                    if heap.len() >= max_buffered_posts {
                        // Bounded reassembly buffer to protect low-RAM VPS.
                        break;
                    }
                    heap.push(Reverse((seq, data)));
                }
            }
        }
    }
    let _ = writer.shutdown().await;
}

/// Lightweight HTTP/1.1 XHTTP server supporting keep-alive `packet-up` POSTs,
/// `stream-up` POSTs, `stream-down` GETs, and `stream-one` POSTs (e.g. behind Nginx `proxy_pass`).
async fn serve_xhttp_h1<S, F, Fut>(
    mut stream: S,
    hub: Arc<XhttpHub>,
    on_stream: Arc<F>,
) -> io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    F: Fn(BoxedStream, Option<String>) -> Fut + Send + Sync + 'static,
    Fut: Future<Output = ()> + Send + 'static,
{
    let mut buf = BytesMut::with_capacity(4096);
    let mut tmp = [0u8; 4096];

    loop {
        // Read next HTTP/1.1 request header.
        let header_end = loop {
            if let Some(pos) = find_header_end(&buf) {
                break pos;
            }
            if buf.len() > MAX_HTTP1_HEADER_BYTES {
                let _ = write_h1_status(&mut stream, 431, "Request Header Fields Too Large", &hub, true).await;
                return Ok(());
            }
            let n = match timeout(HTTP1_READ_TIMEOUT, stream.read(&mut tmp)).await {
                Ok(Ok(0)) => return Ok(()),
                Ok(Ok(n)) => n,
                _ => return Ok(()),
            };
            buf.extend_from_slice(&tmp[..n]);
        };

        let header_bytes = buf.split_to(header_end + 4);
        let Ok(header_str) = std::str::from_utf8(&header_bytes[..header_end]) else {
            let _ = write_h1_status(&mut stream, 400, "Bad Request", &hub, true).await;
            return Ok(());
        };

        let mut lines = header_str.split("\r\n");
        let Some(req_line) = lines.next() else {
            return Ok(());
        };
        let mut parts = req_line.split_whitespace();
        let method = parts.next().unwrap_or("").to_ascii_uppercase();
        let raw_target = parts.next().unwrap_or("/");

        let mut host = "";
        let mut content_length: Option<usize> = None;
        let mut is_chunked = false;
        let mut conn_close = false;
        let mut has_cors_req_method = false;
        let mut forwarded_ip: Option<String> = None;

        for line in lines {
            if let Some((k, v)) = line.split_once(':') {
                let v = v.trim();
                if k.eq_ignore_ascii_case("host") {
                    host = v;
                } else if k.eq_ignore_ascii_case("content-length") {
                    content_length = v.parse::<usize>().ok();
                } else if k.eq_ignore_ascii_case("transfer-encoding") {
                    if v.to_ascii_lowercase().contains("chunked") {
                        is_chunked = true;
                    }
                } else if k.eq_ignore_ascii_case("connection") {
                    if v.to_ascii_lowercase().contains("close") {
                        conn_close = true;
                    }
                } else if k.eq_ignore_ascii_case("access-control-request-method") && !v.is_empty() {
                    has_cors_req_method = true;
                } else if k.eq_ignore_ascii_case("x-forwarded-for") && forwarded_ip.is_none() {
                    if let Some(first) = v.split(',').next().map(str::trim).filter(|ip| !ip.is_empty()) {
                        forwarded_ip = Some(first.to_string());
                    }
                } else if k.eq_ignore_ascii_case("x-real-ip") && forwarded_ip.is_none() && !v.is_empty() {
                    forwarded_ip = Some(v.to_string());
                }
            }
        }

        if !hub.matches_host(host) {
            let _ = write_h1_status(&mut stream, 404, "Not Found", &hub, true).await;
            return Ok(());
        }

        let Some((session_id, seq_str)) = hub.extract_meta(raw_target) else {
            let _ = write_h1_status(&mut stream, 404, "Not Found", &hub, true).await;
            return Ok(());
        };

        if method == "OPTIONS" && has_cors_req_method {
            let _ = write_h1_status(&mut stream, 200, "OK", &hub, conn_close).await;
            if conn_close {
                return Ok(());
            }
            continue;
        }

        let is_uplink = match method.as_str() {
            "GET" => !seq_str.is_empty(),
            _ => true,
        };

        if is_uplink && !session_id.is_empty() {
            let session = hub.upsert_session(&session_id);
            if seq_str.is_empty() {
                // stream-up over HTTP/1.1 (takes ownership of connection until EOF)
                if !hub.mode_allows("stream-up") {
                    let _ = write_h1_status(&mut stream, 400, "Bad Request", &hub, true).await;
                    return Ok(());
                }
                if session.stream_up_taken.swap(true, Ordering::AcqRel) {
                    let _ = write_h1_status(&mut stream, 409, "Conflict", &hub, true).await;
                    return Ok(());
                }
                let hdr = format!(
                    "HTTP/1.1 200 OK\r\nX-Padding: {}\r\nX-Accel-Buffering: no\r\nCache-Control: no-store\r\nTransfer-Encoding: chunked\r\n\r\n",
                    hub.random_padding()
                );
                let _ = stream.write_all(hdr.as_bytes()).await;
                let _ = stream.flush().await;
                stream_h1_body_to_session(&mut stream, &mut buf, is_chunked, content_length, &session).await;
                let _ = session.tx.send(UploadItem::StreamEof).await;
                let _ = stream.write_all(b"0\r\n\r\n").await;
                return Ok(());
            }

            // packet-up over HTTP/1.1 (supports keep-alive pipelining!)
            if !hub.mode_allows("packet-up") {
                let _ = write_h1_status(&mut stream, 400, "Bad Request", &hub, true).await;
                return Ok(());
            }
            let Ok(seq) = seq_str.parse::<u64>() else {
                let _ = write_h1_status(&mut stream, 400, "Bad Request", &hub, true).await;
                return Ok(());
            };
            let payload = match read_h1_body(
                &mut stream,
                &mut buf,
                is_chunked,
                content_length,
                hub.max_each_post,
            )
            .await
            {
                Ok(p) => p,
                Err(e) if e.kind() == io::ErrorKind::InvalidData => {
                    let _ = write_h1_status(&mut stream, 413, "Payload Too Large", &hub, true).await;
                    return Ok(());
                }
                Err(_) => {
                    let _ = write_h1_status(&mut stream, 400, "Bad Request", &hub, true).await;
                    return Ok(());
                }
            };

            if session
                .tx
                .send(UploadItem::Packet { seq, data: payload })
                .await
                .is_err()
            {
                let _ = write_h1_status(&mut stream, 500, "Internal Server Error", &hub, true).await;
                return Ok(());
            }
            let _ = write_h1_status(&mut stream, 200, "OK", &hub, conn_close).await;
            if conn_close {
                return Ok(());
            }
            continue;
        } else if method == "GET" || session_id.is_empty() {
            // stream-down or stream-one over HTTP/1.1 (takes ownership of connection)
            if session_id.is_empty()
                && !hub.mode_allows("stream-one")
                && !hub.mode_allows("stream-up")
            {
                let _ = write_h1_status(&mut stream, 400, "Bad Request", &hub, true).await;
                return Ok(());
            }

            let sse_hdr = if hub.cfg.no_sse_header {
                ""
            } else {
                "Content-Type: text/event-stream\r\n"
            };
            let hdr = format!(
                "HTTP/1.1 200 OK\r\n\
                 X-Padding: {}\r\n\
                 X-Accel-Buffering: no\r\n\
                 Cache-Control: no-store\r\n\
                 {sse_hdr}\
                 Transfer-Encoding: chunked\r\n\r\n",
                hub.random_padding()
            );
            stream.write_all(hdr.as_bytes()).await?;
            stream.flush().await?;

            let (app_side, pump_side) = tokio::io::duplex(XHTTP_DUPLEX_BUF);
            let (mut wire_r, mut wire_w) = tokio::io::split(stream);
            let (mut app_r, mut app_w) = tokio::io::split(app_side);

            if session_id.is_empty() {
                // stream-one over HTTP/1.1
                let mut up = tokio::spawn(async move {
                    if is_chunked {
                        let _ = stream_h1_chunked_to_writer(&mut wire_r, &mut buf, &mut app_w).await;
                    } else if let Some(cl) = content_length {
                        let mut rem = cl;
                        if !buf.is_empty() {
                            let take = rem.min(buf.len());
                            if app_w.write_all(&buf.split_to(take)).await.is_err() {
                                return;
                            }
                            rem -= take;
                        }
                        let mut t = vec![0u8; 8192];
                        while rem > 0 {
                            let to_read = rem.min(t.len());
                            match wire_r.read(&mut t[..to_read]).await {
                                Ok(0) | Err(_) => break,
                                Ok(n) => {
                                    if app_w.write_all(&t[..n]).await.is_err() {
                                        break;
                                    }
                                    rem -= n;
                                }
                            }
                        }
                    } else {
                        if !buf.is_empty() && app_w.write_all(&buf).await.is_err() {
                            return;
                        }
                        let _ = tokio::io::copy(&mut wire_r, &mut app_w).await;
                    }
                    let _ = app_w.shutdown().await;
                });

                let mut down = tokio::spawn(async move {
                    let mut out = vec![0u8; 8192];
                    loop {
                        match app_r.read(&mut out).await {
                            Ok(0) | Err(_) => break,
                            Ok(n) => {
                                if write_h1_chunk(&mut wire_w, &out[..n]).await.is_err() {
                                    break;
                                }
                            }
                        }
                    }
                    let _ = wire_w.write_all(b"0\r\n\r\n").await;
                    let _ = wire_w.flush().await;
                });

                tokio::spawn(async move {
                    tokio::select! {
                        _ = &mut up => { down.abort(); }
                        _ = &mut down => { up.abort(); }
                    }
                });
            } else {
                // stream-down over HTTP/1.1
                let session = hub.upsert_session(&session_id);
                session.connected.store(true, Ordering::Release);
                let rx_opt = session
                    .rx
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .take();
                let Some(rx) = rx_opt else {
                    return Ok(());
                };
                let hub_cleanup = Arc::clone(&hub);
                let sid_cleanup = session_id.clone();
                let max_buf = hub.max_buffered_posts;

                tokio::spawn(async move {
                    let mut up = tokio::spawn(pump_upload_queue_to_writer(rx, app_w, max_buf));
                    let mut down = tokio::spawn(async move {
                        let mut out = vec![0u8; 8192];
                        loop {
                            match app_r.read(&mut out).await {
                                Ok(0) | Err(_) => break,
                                Ok(n) => {
                                    if write_h1_chunk(&mut wire_w, &out[..n]).await.is_err() {
                                        break;
                                    }
                                }
                            }
                        }
                        let _ = wire_w.write_all(b"0\r\n\r\n").await;
                        let _ = wire_w.flush().await;
                    });
                    tokio::select! {
                        _ = &mut up => { down.abort(); }
                        _ = &mut down => { up.abort(); }
                    }
                    hub_cleanup.remove_session(&sid_cleanup);
                });
            }

            on_stream(Box::new(pump_side), forwarded_ip).await;
            return Ok(());
        } else {
            let _ = write_h1_status(&mut stream, 405, "Method Not Allowed", &hub, true).await;
            return Ok(());
        }
    }
}

async fn write_h1_status<W: AsyncWrite + Unpin>(
    w: &mut W,
    code: u16,
    reason: &str,
    hub: &XhttpHub,
    close: bool,
) -> io::Result<()> {
    let conn = if close { "close" } else { "keep-alive" };
    let resp = format!(
        "HTTP/1.1 {code} {reason}\r\n\
         X-Padding: {}\r\n\
         Cache-Control: no-store\r\n\
         Content-Length: 0\r\n\
         Connection: {conn}\r\n\r\n",
        hub.random_padding()
    );
    w.write_all(resp.as_bytes()).await?;
    w.flush().await
}

async fn write_h1_chunk<W: AsyncWrite + Unpin>(w: &mut W, data: &[u8]) -> io::Result<()> {
    let hdr = format!("{:x}\r\n", data.len());
    w.write_all(hdr.as_bytes()).await?;
    w.write_all(data).await?;
    w.write_all(b"\r\n").await?;
    w.flush().await
}

async fn read_h1_body<R: AsyncRead + Unpin>(
    r: &mut R,
    buf: &mut BytesMut,
    is_chunked: bool,
    content_length: Option<usize>,
    max_bytes: usize,
) -> io::Result<Vec<u8>> {
    if is_chunked {
        let mut out = Vec::new();
        loop {
            let line_end = read_crlf_line(r, buf).await?;
            let line = std::str::from_utf8(&buf[..line_end])
                .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "bad chunk size"))?;
            let hex_part = line.split(';').next().unwrap_or("").trim();
            let chunk_len = usize::from_str_radix(hex_part, 16)
                .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "bad hex chunk len"))?;
            buf.advance(line_end + 2);
            if chunk_len == 0 {
                // Consume trailing CRLF after 0-length chunk
                let _ = read_crlf_line(r, buf).await;
                if buf.len() >= 2 && &buf[..2] == b"\r\n" {
                    buf.advance(2);
                }
                break;
            }
            if out.len() + chunk_len > max_bytes {
                return Err(io::Error::new(io::ErrorKind::InvalidData, "chunked body too large"));
            }
            ensure_buf_len(r, buf, chunk_len + 2).await?;
            out.extend_from_slice(&buf[..chunk_len]);
            buf.advance(chunk_len + 2);
        }
        Ok(out)
    } else if let Some(cl) = content_length {
        if cl > max_bytes {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "body exceeds scMaxEachPostBytes"));
        }
        ensure_buf_len(r, buf, cl).await?;
        let data = buf.split_to(cl).to_vec();
        Ok(data)
    } else {
        Ok(Vec::new())
    }
}

async fn stream_h1_body_to_session<R: AsyncRead + Unpin>(
    r: &mut R,
    buf: &mut BytesMut,
    is_chunked: bool,
    content_length: Option<usize>,
    session: &XhttpSession,
) {
    if is_chunked {
        loop {
            let Ok(line_end) = read_crlf_line(r, buf).await else { break };
            let Ok(line) = std::str::from_utf8(&buf[..line_end]) else { break };
            let hex_part = line.split(';').next().unwrap_or("").trim();
            let Ok(chunk_len) = usize::from_str_radix(hex_part, 16) else { break };
            buf.advance(line_end + 2);
            if chunk_len == 0 {
                break;
            }
            if ensure_buf_len(r, buf, chunk_len + 2).await.is_err() {
                break;
            }
            let chunk = buf.split_to(chunk_len).to_vec();
            buf.advance(2);
            if session.tx.send(UploadItem::StreamChunk(chunk)).await.is_err() {
                break;
            }
        }
    } else if let Some(mut rem) = content_length {
        if !buf.is_empty() {
            let take = rem.min(buf.len());
            let chunk = buf.split_to(take).to_vec();
            rem -= take;
            if session.tx.send(UploadItem::StreamChunk(chunk)).await.is_err() {
                return;
            }
        }
        let mut t = vec![0u8; 8192];
        while rem > 0 {
            let to_read = rem.min(t.len());
            match r.read(&mut t[..to_read]).await {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    rem -= n;
                    if session
                        .tx
                        .send(UploadItem::StreamChunk(t[..n].to_vec()))
                        .await
                        .is_err()
                    {
                        break;
                    }
                }
            }
        }
    } else {
        if !buf.is_empty() {
            let chunk = buf.split().to_vec();
            if session.tx.send(UploadItem::StreamChunk(chunk)).await.is_err() {
                return;
            }
        }
        let mut t = vec![0u8; 8192];
        loop {
            match r.read(&mut t).await {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    if session
                        .tx
                        .send(UploadItem::StreamChunk(t[..n].to_vec()))
                        .await
                        .is_err()
                    {
                        break;
                    }
                }
            }
        }
    }
}

async fn stream_h1_chunked_to_writer<R: AsyncRead + Unpin, W: AsyncWrite + Unpin>(
    r: &mut R,
    buf: &mut BytesMut,
    w: &mut W,
) -> io::Result<()> {
    loop {
        let line_end = read_crlf_line(r, buf).await?;
        let line = std::str::from_utf8(&buf[..line_end])
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "bad chunk size"))?;
        let hex_part = line.split(';').next().unwrap_or("").trim();
        let chunk_len = usize::from_str_radix(hex_part, 16)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "bad hex chunk len"))?;
        buf.advance(line_end + 2);
        if chunk_len == 0 {
            break;
        }
        ensure_buf_len(r, buf, chunk_len + 2).await?;
        w.write_all(&buf[..chunk_len]).await?;
        buf.advance(chunk_len + 2);
    }
    Ok(())
}

async fn read_crlf_line<R: AsyncRead + Unpin>(r: &mut R, buf: &mut BytesMut) -> io::Result<usize> {
    let mut tmp = [0u8; 1024];
    loop {
        if let Some(pos) = buf.windows(2).position(|w| w == b"\r\n") {
            return Ok(pos);
        }
        if buf.len() > 4096 {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "chunk line too long"));
        }
        let n = timeout(HTTP1_READ_TIMEOUT, r.read(&mut tmp))
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "chunk line timeout"))??;
        if n == 0 {
            return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "EOF reading chunk line"));
        }
        buf.extend_from_slice(&tmp[..n]);
    }
}

async fn ensure_buf_len<R: AsyncRead + Unpin>(
    r: &mut R,
    buf: &mut BytesMut,
    needed: usize,
) -> io::Result<()> {
    let mut tmp = vec![0u8; 8192];
    while buf.len() < needed {
        let want = (needed - buf.len()).min(tmp.len());
        let n = timeout(HTTP1_READ_TIMEOUT, r.read(&mut tmp[..want]))
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "body read timeout"))??;
        if n == 0 {
            return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "EOF reading body"));
        }
        buf.extend_from_slice(&tmp[..n]);
    }
    Ok(())
}

fn send_h2_status(respond: &mut server::SendResponse<Bytes>, status: StatusCode, hub: &XhttpHub) {
    let resp = Response::builder()
        .status(status)
        .header("x-padding", hub.random_padding())
        .header("cache-control", "no-store")
        .body(())
        .unwrap();
    let _ = respond.send_response(resp, true);
}

async fn send_h2_all(send: &mut h2::SendStream<Bytes>, mut data: Bytes) -> io::Result<()> {
    while !data.is_empty() {
        send.reserve_capacity(data.len());
        let cap = std::future::poll_fn(|cx| send.poll_capacity(cx))
            .await
            .ok_or_else(|| io::Error::new(io::ErrorKind::BrokenPipe, "h2 stream closed"))?
            .map_err(|e| io::Error::new(io::ErrorKind::BrokenPipe, format!("h2 capacity: {e}")))?;
        let chunk = data.split_to(cap.min(data.len()));
        send.send_data(chunk, false)
            .map_err(|e| io::Error::new(io::ErrorKind::BrokenPipe, format!("h2 send: {e}")))?;
    }
    Ok(())
}

fn extract_forwarded_ip_h2(headers: &http::HeaderMap) -> Option<String> {
    headers
        .get("x-forwarded-for")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.split(',').next())
        .map(str::trim)
        .filter(|v| !v.is_empty())
        .map(str::to_string)
        .or_else(|| {
            headers
                .get("x-real-ip")
                .and_then(|v| v.to_str().ok())
                .map(str::trim)
                .filter(|v| !v.is_empty())
                .map(str::to_string)
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extract_meta_handles_all_xhttp_modes() {
        let hub = XhttpHub::new(XhttpSettings {
            path: "/xhttp".to_string(),
            ..Default::default()
        });
        assert_eq!(hub.extract_meta("/xhttp"), Some(("".to_string(), "".to_string())));
        assert_eq!(hub.extract_meta("/xhttp/"), Some(("".to_string(), "".to_string())));
        assert_eq!(
            hub.extract_meta("/xhttp/sess-123?x_padding=XXXX"),
            Some(("sess-123".to_string(), "".to_string()))
        );
        assert_eq!(
            hub.extract_meta("/xhttp/sess-123/42"),
            Some(("sess-123".to_string(), "42".to_string()))
        );
        assert_eq!(hub.extract_meta("/other/sess-123"), None);
    }

    #[tokio::test]
    async fn packet_up_reorders_out_of_order_sequences() {
        let (tx, rx) = mpsc::channel(8);
        tx.send(UploadItem::Packet { seq: 2, data: b"world".to_vec() }).await.unwrap();
        tx.send(UploadItem::Packet { seq: 0, data: b"hello".to_vec() }).await.unwrap();
        tx.send(UploadItem::Packet { seq: 1, data: b" ".to_vec() }).await.unwrap();
        drop(tx);

        let mut out = Vec::new();
        pump_upload_queue_to_writer(rx, &mut out, 30).await;
        assert_eq!(out, b"hello world");
    }
}
