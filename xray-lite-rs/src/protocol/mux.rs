use std::collections::HashMap;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tokio::time::timeout;

use crate::address::{TargetAddr, TargetHost};
use crate::log_debug;
use crate::outbound::{bind_udp_for, dial_tcp, is_bittorrent_handshake, resolve_udp_target};
use crate::protocol::InboundRuntime;
use crate::stats::UserTraffic;

const STATUS_NEW: u8 = 0x01;
const STATUS_KEEP: u8 = 0x02;
const STATUS_END: u8 = 0x03;
const STATUS_KEEP_ALIVE: u8 = 0x04;

const OPT_DATA: u8 = 0x01;
const OPT_ERROR: u8 = 0x02;

const NET_TCP: u8 = 0x01;
const NET_UDP: u8 = 0x02;

const MAX_META_LEN: usize = 512;
const MAX_MUX_SESSIONS: usize = 128;
const MUX_TCP_CHUNK_SIZE: usize = 8 * 1024;
const MUX_IDLE_TIMEOUT: Duration = Duration::from_secs(120);
const UDP_IDLE_TIMEOUT: Duration = Duration::from_secs(90);

#[derive(Debug, Clone)]
pub struct MuxFrame {
    pub session_id: u16,
    pub status: u8,
    pub option: u8,
    pub network: u8, // 0 = unspecified, 1 = TCP, 2 = UDP
    pub target: Option<TargetAddr>,
    pub payload: Vec<u8>,
}

enum SessionHandle {
    Tcp {
        tx: mpsc::Sender<Vec<u8>>,
        task: JoinHandle<()>,
    },
    Udp {
        tx: mpsc::Sender<(Option<TargetAddr>, Vec<u8>)>,
        task: JoinHandle<()>,
    },
}

impl SessionHandle {
    fn abort(self) {
        match self {
            Self::Tcp { task, .. } | Self::Udp { task, .. } => task.abort(),
        }
    }
}

/// Handles Xray Mux.Cool and XUDP (`CMD_MUX = 0x03`, `v1.mux.cool`) over an already-authenticated
/// VLESS or VMess stream, including Full Cone NAT UDP required by Xray-core clients for online games.
pub async fn handle_mux<S: AsyncRead + AsyncWrite + Unpin + Send + 'static>(
    stream: S,
    runtime: &InboundRuntime,
    peer_desc: &str,
    email: &str,
) -> io::Result<()> {
    let (client_r_raw, mut client_w) = tokio::io::split(stream);
    let mut client_r = BufReader::with_capacity(16 * 1024, client_r_raw);
    let (out_tx, mut out_rx) = mpsc::channel::<Vec<u8>>(128);

    // Single serialized writer task so concurrent UDP/TCP sub-sessions never interleave frames.
    let writer_task = tokio::spawn(async move {
        while let Some(frame) = out_rx.recv().await {
            if client_w.write_all(&frame).await.is_err() {
                break;
            }
        }
        let _ = client_w.shutdown().await;
    });

    let counters = runtime.stats.counters_for(email);
    let mut sessions: HashMap<u16, SessionHandle> = HashMap::new();
    let mut meta_buf = Vec::with_capacity(64);

    loop {
        let frame = match timeout(
            MUX_IDLE_TIMEOUT,
            read_mux_frame_with_buf(&mut client_r, &mut meta_buf),
        )
        .await
        {
            Ok(Ok(f)) => f,
            Ok(Err(_)) | Err(_) => break,
        };

        match frame.status {
            STATUS_NEW => {
                // Replace any stale session with the same ID.
                if let Some(old) = sessions.remove(&frame.session_id) {
                    old.abort();
                }
                if sessions.len() >= MAX_MUX_SESSIONS {
                    send_end_frame(&out_tx, frame.session_id, true).await;
                    continue;
                }
                let Some(target) = frame.target else {
                    send_end_frame(&out_tx, frame.session_id, true).await;
                    continue;
                };

                let net_label = if frame.network == NET_UDP { "udp" } else { "tcp" };
                runtime.access_log.log_accepted(
                    peer_desc,
                    net_label,
                    &target.to_string(),
                    &runtime.tag,
                    email,
                );
                log_debug!(
                    "[{}] Mux/XUDP NEW sid={} {} -> {}",
                    runtime.tag,
                    frame.session_id,
                    net_label,
                    target
                );

                match frame.network {
                    NET_UDP => {
                        let (tx, rx) = mpsc::channel::<(Option<TargetAddr>, Vec<u8>)>(64);
                        if !frame.payload.is_empty() {
                            let _ = tx.try_send((Some(target.clone()), frame.payload));
                        }
                        let task = tokio::spawn(run_mux_udp_session(
                            frame.session_id,
                            target,
                            rx,
                            out_tx.clone(),
                            runtime.block_private,
                            counters.clone(),
                        ));
                        sessions.insert(frame.session_id, SessionHandle::Udp { tx, task });
                    }
                    NET_TCP => {
                        let (tx, rx) = mpsc::channel::<Vec<u8>>(64);
                        if !frame.payload.is_empty() {
                            let _ = tx.try_send(frame.payload);
                        }
                        let task = tokio::spawn(run_mux_tcp_session(
                            frame.session_id,
                            target,
                            rx,
                            out_tx.clone(),
                            runtime.block_private,
                            runtime.block_bittorrent,
                            counters.clone(),
                        ));
                        sessions.insert(frame.session_id, SessionHandle::Tcp { tx, task });
                    }
                    _ => {
                        send_end_frame(&out_tx, frame.session_id, true).await;
                    }
                }
            }
            STATUS_KEEP => {
                if frame.payload.is_empty() {
                    continue;
                }
                let mut dead = false;
                if let Some(sess) = sessions.get(&frame.session_id) {
                    match sess {
                        SessionHandle::Udp { tx, .. } => {
                            if tx.send((frame.target, frame.payload)).await.is_err() {
                                dead = true;
                            }
                        }
                        SessionHandle::Tcp { tx, .. } => {
                            if tx.send(frame.payload).await.is_err() {
                                dead = true;
                            }
                        }
                    }
                }
                if dead {
                    if let Some(old) = sessions.remove(&frame.session_id) {
                        old.abort();
                    }
                }
            }
            STATUS_END => {
                if let Some(old) = sessions.remove(&frame.session_id) {
                    old.abort();
                }
            }
            STATUS_KEEP_ALIVE => {
                // Heartbeat frame — ignore payload (already consumed by read_mux_frame).
            }
            _ => break,
        }
    }

    for (_, sess) in sessions {
        sess.abort();
    }
    drop(out_tx);
    let _ = writer_task.await;
    Ok(())
}

async fn run_mux_udp_session(
    session_id: u16,
    initial_target: TargetAddr,
    mut up_rx: mpsc::Receiver<(Option<TargetAddr>, Vec<u8>)>,
    out_tx: mpsc::Sender<Vec<u8>>,
    block_private: bool,
    counters: Option<Arc<UserTraffic>>,
) {
    let Ok(first_remote) = resolve_udp_target(&initial_target, block_private).await else {
        send_end_frame(&out_tx, session_id, true).await;
        return;
    };
    let Ok(udp) = bind_udp_for(first_remote).await else {
        send_end_frame(&out_tx, session_id, true).await;
        return;
    };
    let udp = Arc::new(udp);
    let udp_recv = Arc::clone(&udp);

    let up_counters = counters.clone();
    let mut up_task = tokio::spawn(async move {
        let mut last_remote = first_remote;
        while let Ok(Some((pkt_target, payload))) = timeout(UDP_IDLE_TIMEOUT, up_rx.recv()).await {
            if payload.is_empty() {
                continue;
            }
            let dest = if let Some(t) = pkt_target {
                match resolve_udp_target(&t, block_private).await {
                    Ok(addr) => {
                        last_remote = addr;
                        addr
                    }
                    Err(_) => continue,
                }
            } else {
                last_remote
            };
            if udp.send_to(&payload, dest).await.is_ok() {
                if let Some(c) = &up_counters {
                    c.add_uplink(payload.len() as u64);
                }
            }
        }
    });

    let out_tx_down = out_tx.clone();
    let down_counters = counters;
    let mut down_task = tokio::spawn(async move {
        let mut recv_buf = vec![0u8; 8192];
        loop {
            let (n, src) = match timeout(UDP_IDLE_TIMEOUT, udp_recv.recv_from(&mut recv_buf)).await
            {
                Ok(Ok(pair)) => pair,
                _ => break,
            };
            if n == 0 || n > u16::MAX as usize {
                continue;
            }
            if let Some(c) = &down_counters {
                c.add_downlink(n as u64);
            }
            let frame = encode_udp_keep_frame(session_id, src, &recv_buf[..n]);
            if out_tx_down.send(frame).await.is_err() {
                break;
            }
        }
    });

    tokio::select! {
        _ = &mut up_task => { down_task.abort(); }
        _ = &mut down_task => { up_task.abort(); }
    }
    send_end_frame(&out_tx, session_id, false).await;
}

async fn run_mux_tcp_session(
    session_id: u16,
    target: TargetAddr,
    mut up_rx: mpsc::Receiver<Vec<u8>>,
    out_tx: mpsc::Sender<Vec<u8>>,
    block_private: bool,
    block_bittorrent: bool,
    counters: Option<Arc<UserTraffic>>,
) {
    let Ok(outbound) = dial_tcp(&target, block_private).await else {
        send_end_frame(&out_tx, session_id, true).await;
        return;
    };
    let (mut out_r, mut out_w) = outbound.into_split();

    let up_counters = counters.clone();
    let mut check_bt = block_bittorrent;
    let mut up_task = tokio::spawn(async move {
        while let Some(data) = up_rx.recv().await {
            if data.is_empty() {
                continue;
            }
            if check_bt {
                check_bt = false;
                if is_bittorrent_handshake(&data) {
                    break;
                }
            }
            if out_w.write_all(&data).await.is_err() {
                break;
            }
            if let Some(c) = &up_counters {
                c.add_uplink(data.len() as u64);
            }
        }
        let _ = out_w.shutdown().await;
    });

    let out_tx_down = out_tx.clone();
    let down_counters = counters;
    let mut down_task = tokio::spawn(async move {
        let mut buf = vec![0u8; MUX_TCP_CHUNK_SIZE];
        loop {
            match out_r.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    if let Some(c) = &down_counters {
                        c.add_downlink(n as u64);
                    }
                    let frame = encode_tcp_keep_frame(session_id, &buf[..n]);
                    if out_tx_down.send(frame).await.is_err() {
                        break;
                    }
                }
            }
        }
    });

    tokio::select! {
        _ = &mut up_task => { down_task.abort(); }
        _ = &mut down_task => { up_task.abort(); }
    }
    send_end_frame(&out_tx, session_id, false).await;
}

/// Reads a single Mux.Cool / XUDP frame from `reader`.
pub async fn read_mux_frame<R: AsyncRead + Unpin>(reader: &mut R) -> io::Result<MuxFrame> {
    let mut meta = Vec::with_capacity(64);
    read_mux_frame_with_buf(reader, &mut meta).await
}

async fn read_mux_frame_with_buf<R: AsyncRead + Unpin>(
    reader: &mut R,
    meta: &mut Vec<u8>,
) -> io::Result<MuxFrame> {
    let meta_len = reader.read_u16().await? as usize;
    if !(4..=MAX_META_LEN).contains(&meta_len) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("invalid Mux metadata length {meta_len}"),
        ));
    }
    meta.resize(meta_len, 0);
    reader.read_exact(meta).await?;

    let session_id = u16::from_be_bytes([meta[0], meta[1]]);
    let status = meta[2];
    let option = meta[3];

    let mut network = 0u8;
    let mut target = None;

    if status == STATUS_NEW
        || (status == STATUS_KEEP && meta.len() > 4 && meta[4] == NET_UDP)
    {
        if meta.len() < 8 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Mux metadata too short for target address",
            ));
        }
        network = meta[4];
        let (addr, _consumed) = parse_port_then_addr(&meta[5..])?;
        target = Some(addr);
    }

    let payload = if (option & OPT_DATA) != 0 {
        let data_len = reader.read_u16().await? as usize;
        let mut buf = vec![0u8; data_len];
        if data_len > 0 {
            reader.read_exact(&mut buf).await?;
        }
        buf
    } else {
        Vec::new()
    };

    Ok(MuxFrame {
        session_id,
        status,
        option,
        network,
        target,
        payload,
    })
}

/// Encodes a Mux/XUDP UDP response frame (`SessionStatusKeep` + `OptionData` + `NET_UDP` + `src`).
pub fn encode_udp_keep_frame(session_id: u16, src: SocketAddr, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(28 + payload.len());
    out.extend_from_slice(&[0u8, 0u8]);
    out.extend_from_slice(&session_id.to_be_bytes());
    out.push(STATUS_KEEP);
    out.push(OPT_DATA);
    out.push(NET_UDP);
    encode_port_then_socket_addr(src, &mut out);
    let meta_len = (out.len() - 2) as u16;
    out[0..2].copy_from_slice(&meta_len.to_be_bytes());
    out.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    out.extend_from_slice(payload);
    out
}

/// Encodes a Mux TCP response frame (`SessionStatusKeep` + `OptionData`).
pub fn encode_tcp_keep_frame(session_id: u16, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(8 + payload.len());
    out.extend_from_slice(&4u16.to_be_bytes()); // meta_len = 4
    out.extend_from_slice(&session_id.to_be_bytes());
    out.push(STATUS_KEEP);
    out.push(OPT_DATA);
    out.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    out.extend_from_slice(payload);
    out
}

async fn send_end_frame(tx: &mpsc::Sender<Vec<u8>>, session_id: u16, is_error: bool) {
    let mut out = Vec::with_capacity(6);
    out.extend_from_slice(&4u16.to_be_bytes());
    out.extend_from_slice(&session_id.to_be_bytes());
    out.push(STATUS_END);
    out.push(if is_error { OPT_ERROR } else { 0x00 });
    let _ = tx.send(out).await;
}

fn parse_port_then_addr(slice: &[u8]) -> io::Result<(TargetAddr, usize)> {
    if slice.len() < 3 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Mux address too short",
        ));
    }
    let port = u16::from_be_bytes([slice[0], slice[1]]);
    let atype = slice[2];
    match atype {
        0x01 => {
            if slice.len() < 7 {
                return Err(io::Error::new(io::ErrorKind::InvalidData, "Mux IPv4 truncated"));
            }
            let ip = Ipv4Addr::new(slice[3], slice[4], slice[5], slice[6]);
            Ok((TargetAddr { host: TargetHost::Ipv4(ip), port }, 7))
        }
        0x02 => {
            if slice.len() < 4 {
                return Err(io::Error::new(io::ErrorKind::InvalidData, "Mux domain len truncated"));
            }
            let len = slice[3] as usize;
            if slice.len() < 4 + len {
                return Err(io::Error::new(io::ErrorKind::InvalidData, "Mux domain truncated"));
            }
            let domain = std::str::from_utf8(&slice[4..4 + len])
                .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "Mux invalid UTF-8 domain"))?
                .to_string();
            Ok((TargetAddr { host: TargetHost::Domain(domain), port }, 4 + len))
        }
        0x03 => {
            if slice.len() < 19 {
                return Err(io::Error::new(io::ErrorKind::InvalidData, "Mux IPv6 truncated"));
            }
            let mut raw = [0u8; 16];
            raw.copy_from_slice(&slice[3..19]);
            let ip = Ipv6Addr::from(raw);
            Ok((TargetAddr { host: TargetHost::Ipv6(ip), port }, 19))
        }
        other => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("Mux unknown address type 0x{other:02x}"),
        )),
    }
}

fn encode_port_then_socket_addr(addr: SocketAddr, out: &mut Vec<u8>) {
    out.extend_from_slice(&addr.port().to_be_bytes());
    match addr.ip() {
        IpAddr::V4(v4) => {
            out.push(0x01);
            out.extend_from_slice(&v4.octets());
        }
        IpAddr::V6(v6) => {
            if let Some(v4) = v6.to_ipv4_mapped() {
                out.push(0x01);
                out.extend_from_slice(&v4.octets());
            } else {
                out.push(0x03);
                out.extend_from_slice(&v6.octets());
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn xudp_frame_encode_and_decode_roundtrip() {
        let src: SocketAddr = "1.2.3.4:27015".parse().unwrap();
        let raw = encode_udp_keep_frame(0, src, b"game-ping");

        let mut cursor = std::io::Cursor::new(raw);
        let frame = read_mux_frame(&mut cursor).await.unwrap();
        assert_eq!(frame.session_id, 0);
        assert_eq!(frame.status, STATUS_KEEP);
        assert_eq!(frame.option, OPT_DATA);
        assert_eq!(frame.network, NET_UDP);
        assert_eq!(frame.target, Some(TargetAddr::from_socket_addr(src)));
        assert_eq!(frame.payload, b"game-ping");
    }

    #[tokio::test]
    async fn xudp_new_frame_with_global_id_parses_cleanly() {
        // Exact wire format emitted by Xray-core common/xudp/xudp.go PacketWriter
        let mut meta = Vec::new();
        meta.extend_from_slice(&0u16.to_be_bytes()); // sid = 0
        meta.push(STATUS_NEW);
        meta.push(OPT_DATA);
        meta.push(NET_UDP);
        meta.extend_from_slice(&30001u16.to_be_bytes()); // game port
        meta.push(0x01); // IPv4
        meta.extend_from_slice(&[8, 8, 4, 4]);
        meta.extend_from_slice(&[0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88]); // 8B GlobalID

        let mut wire = Vec::new();
        wire.extend_from_slice(&(meta.len() as u16).to_be_bytes());
        wire.extend_from_slice(&meta);
        wire.extend_from_slice(&4u16.to_be_bytes());
        wire.extend_from_slice(b"PING");

        let mut cursor = std::io::Cursor::new(wire);
        let frame = read_mux_frame(&mut cursor).await.unwrap();
        assert_eq!(frame.session_id, 0);
        assert_eq!(frame.status, STATUS_NEW);
        assert_eq!(frame.network, NET_UDP);
        assert_eq!(
            frame.target,
            Some(TargetAddr {
                host: TargetHost::Ipv4(Ipv4Addr::new(8, 8, 4, 4)),
                port: 30001,
            })
        );
        assert_eq!(frame.payload, b"PING");
    }
}
