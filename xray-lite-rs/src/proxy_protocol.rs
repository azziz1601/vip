use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::pin::Pin;
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, ReadBuf};

const V2_SIG: [u8; 12] = [
    0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A,
];

/// Wraps a stream with any already-read prefix bytes that must be delivered before reading `inner`.
pub struct PrefixedStream<S> {
    prefix: Vec<u8>,
    pos: usize,
    inner: S,
}

impl<S> PrefixedStream<S> {
    pub fn new(prefix: Vec<u8>, inner: S) -> Self {
        Self {
            prefix,
            pos: 0,
            inner,
        }
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for PrefixedStream<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if self.pos < self.prefix.len() {
            let rem = &self.prefix[self.pos..];
            let to_copy = rem.len().min(buf.remaining());
            buf.put_slice(&rem[..to_copy]);
            self.pos += to_copy;
            if self.pos == self.prefix.len() {
                self.prefix = Vec::new();
                self.pos = 0;
            }
            return Poll::Ready(Ok(()));
        }
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for PrefixedStream<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

/// Parses an incoming HAProxy / Nginx PROXY Protocol v1 or v2 header.
/// Returns `(Option<real_client_addr>, wrapped_stream)`.
pub async fn consume_proxy_protocol<S: AsyncRead + AsyncWrite + Unpin>(
    mut stream: S,
) -> io::Result<(Option<SocketAddr>, PrefixedStream<S>)> {
    let mut head = [0u8; 16];
    // Read first 12 bytes to detect v1 ("PROXY ") vs v2 signature.
    stream.read_exact(&mut head[..12]).await?;

    if head[..12] == V2_SIG {
        // PROXY protocol v2: read remaining 4 header bytes (ver_cmd, fam_proto, len_be).
        stream.read_exact(&mut head[12..16]).await?;
        let ver_cmd = head[12];
        if (ver_cmd >> 4) != 0x02 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid PROXY protocol v2 version",
            ));
        }
        let fam_proto = head[13];
        let payload_len = u16::from_be_bytes([head[14], head[15]]) as usize;
        if payload_len > 4096 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "PROXY protocol v2 payload too large",
            ));
        }
        let mut payload = vec![0u8; payload_len];
        if payload_len > 0 {
            stream.read_exact(&mut payload).await?;
        }

        let cmd = ver_cmd & 0x0F;
        let client_addr = if cmd == 0x01 {
            // PROXY command
            match fam_proto >> 4 {
                0x01 if payload.len() >= 12 => {
                    let ip = Ipv4Addr::new(payload[0], payload[1], payload[2], payload[3]);
                    let port = u16::from_be_bytes([payload[8], payload[9]]);
                    Some(SocketAddr::new(IpAddr::V4(ip), port))
                }
                0x02 if payload.len() >= 36 => {
                    let mut ip_bytes = [0u8; 16];
                    ip_bytes.copy_from_slice(&payload[0..16]);
                    let port = u16::from_be_bytes([payload[32], payload[33]]);
                    Some(SocketAddr::new(IpAddr::V6(Ipv6Addr::from(ip_bytes)), port))
                }
                _ => None,
            }
        } else {
            None
        };

        return Ok((client_addr, PrefixedStream::new(Vec::new(), stream)));
    }

    if &head[..6] == b"PROXY " {
        // PROXY protocol v1: ASCII line terminated by `\r\n` (max 107 bytes).
        let mut line = head[..12].to_vec();
        let mut byte = [0u8; 1];
        while !line.ends_with(b"\r\n") {
            if line.len() >= 108 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "PROXY protocol v1 line too long",
                ));
            }
            stream.read_exact(&mut byte).await?;
            line.push(byte[0]);
        }

        let line_str = std::str::from_utf8(&line[..line.len() - 2]).map_err(|_| {
            io::Error::new(io::ErrorKind::InvalidData, "invalid UTF-8 in PROXY v1")
        })?;
        let parts: Vec<&str> = line_str.split(' ').collect();
        let client_addr = if parts.len() >= 6 && (parts[1] == "TCP4" || parts[1] == "TCP6") {
            let ip: IpAddr = parts[2].parse().ok().ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidData, "invalid PROXY v1 IP")
            })?;
            let port: u16 = parts[4].parse().ok().ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidData, "invalid PROXY v1 port")
            })?;
            Some(SocketAddr::new(ip, port))
        } else {
            None
        };

        return Ok((client_addr, PrefixedStream::new(Vec::new(), stream)));
    }

    Err(io::Error::new(
        io::ErrorKind::InvalidData,
        "missing PROXY protocol v1/v2 header",
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncWriteExt;

    #[tokio::test]
    async fn parses_proxy_v1_and_passes_payload() {
        let (mut c, s) = tokio::io::duplex(256);
        let write_task = tokio::spawn(async move {
            c.write_all(b"PROXY TCP4 203.0.113.5 127.0.0.1 54321 443\r\nHELLO")
                .await
                .unwrap();
        });
        let (addr, mut stream) = consume_proxy_protocol(s).await.unwrap();
        assert_eq!(addr.unwrap().to_string(), "203.0.113.5:54321");
        let mut buf = [0u8; 5];
        stream.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"HELLO");
        write_task.await.unwrap();
    }

    #[tokio::test]
    async fn parses_proxy_v2_ipv4() {
        let (mut c, s) = tokio::io::duplex(256);
        let write_task = tokio::spawn(async move {
            let mut hdr = Vec::new();
            hdr.extend_from_slice(&V2_SIG);
            hdr.push(0x21); // v2 + PROXY
            hdr.push(0x11); // AF_INET + STREAM
            hdr.extend_from_slice(&12u16.to_be_bytes());
            hdr.extend_from_slice(&[198, 51, 100, 9]); // src ip
            hdr.extend_from_slice(&[127, 0, 0, 1]); // dst ip
            hdr.extend_from_slice(&12345u16.to_be_bytes()); // src port
            hdr.extend_from_slice(&443u16.to_be_bytes()); // dst port
            hdr.extend_from_slice(b"OK");
            c.write_all(&hdr).await.unwrap();
        });
        let (addr, mut stream) = consume_proxy_protocol(s).await.unwrap();
        assert_eq!(addr.unwrap().to_string(), "198.51.100.9:12345");
        let mut buf = [0u8; 2];
        stream.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"OK");
        write_task.await.unwrap();
    }
}
