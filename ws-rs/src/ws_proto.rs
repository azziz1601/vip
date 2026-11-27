const WS_GUID: &str = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

/// Returns `true` if the leading bytes look like an HTTP/1.x or custom tunneling payload
/// request line (e.g. `GET `, `CONNECT `, `BMOVE `, `ACL `, `PATCH `, etc.), while returning
/// `false` for raw SSH banners (`SSH-2.0-...`) or binary TLS/OpenVPN frames.
pub fn looks_like_http(buf: &[u8]) -> bool {
    if buf.len() < 4 {
        return false;
    }
    // Raw SSH client banner or TLS ClientHello must pass through untouched.
    if buf.starts_with(b"SSH-") || buf.starts_with(&[0x16, 0x03]) {
        return false;
    }
    // Check first token (2..=16 ASCII letters/digits/'-') followed by a space.
    let limit = buf.len().min(17);
    let mut token_len = 0usize;
    for &b in &buf[..limit] {
        if b == b' ' {
            return token_len >= 2;
        }
        if b.is_ascii_alphabetic() || b == b'-' {
            token_len += 1;
        } else {
            return false;
        }
    }
    // Still reading a plausible method token if buffer is shorter than 17 bytes.
    token_len >= 2 && buf.len() < 17
}

/// Finds the byte index of `\r\n\r\n` marking the end of an HTTP header block.
pub fn find_header_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n")
}

#[derive(Debug, Default)]
pub struct ParsedHttpRequest {
    pub ws_key: Option<String>,
    pub real_ip: Option<String>,
    pub has_upgrade: bool,
}

/// Extracts `Sec-WebSocket-Key`, `Upgrade` presence, and `X-Forwarded-For`/`X-Real-IP`.
pub fn parse_http_headers(header_bytes: &[u8]) -> ParsedHttpRequest {
    let mut parsed = ParsedHttpRequest::default();
    let text = String::from_utf8_lossy(header_bytes);
    for line in text.split("\r\n").skip(1) {
        if let Some((k, v)) = line.split_once(':') {
            let v = v.trim();
            if v.is_empty() {
                continue;
            }
            if k.eq_ignore_ascii_case("upgrade") {
                parsed.has_upgrade = true;
            } else if k.eq_ignore_ascii_case("sec-websocket-key") {
                parsed.ws_key = Some(v.to_string());
            } else if k.eq_ignore_ascii_case("x-forwarded-for") && parsed.real_ip.is_none() {
                if let Some(first) = v.split(',').next().map(str::trim).filter(|s| !s.is_empty()) {
                    parsed.real_ip = Some(first.to_string());
                }
            } else if k.eq_ignore_ascii_case("x-real-ip") && parsed.real_ip.is_none() {
                parsed.real_ip = Some(v.to_string());
            }
        }
    }
    parsed
}

/// Builds the `HTTP/1.1 101 Switching Protocols` response expected by Nginx, HAProxy,
/// HTTP Injector, HTTP Custom, NetMod, and standard WebSocket/HTTPUpgrade SSH clients.
pub fn build_101_response(ws_key: Option<&str>) -> Vec<u8> {
    if let Some(key) = ws_key {
        let accept = compute_ws_accept(key);
        format!(
            "HTTP/1.1 101 Switching Protocols\r\n\
             Upgrade: websocket\r\n\
             Connection: Upgrade\r\n\
             Sec-WebSocket-Accept: {accept}\r\n\r\n"
        )
        .into_bytes()
    } else {
        b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n"
            .to_vec()
    }
}

/// Computes RFC 6455 `Sec-WebSocket-Accept = Base64(SHA-1(key || WS_GUID))`.
pub fn compute_ws_accept(key: &str) -> String {
    let mut input = Vec::with_capacity(key.len() + WS_GUID.len());
    input.extend_from_slice(key.trim().as_bytes());
    input.extend_from_slice(WS_GUID.as_bytes());
    let digest = sha1_digest(&input);
    base64_encode(&digest)
}

/// Pure-Rust RFC 3174 SHA-1 (zero external crypto crates).
fn sha1_digest(data: &[u8]) -> [u8; 20] {
    let mut h0: u32 = 0x6745_2301;
    let mut h1: u32 = 0xEFCD_AB89;
    let mut h2: u32 = 0x98BA_DCFE;
    let mut h3: u32 = 0x1032_5476;
    let mut h4: u32 = 0xC3D2_E1F0;

    let bit_len = (data.len() as u64).wrapping_mul(8);
    let mut msg = Vec::with_capacity(data.len() + 72);
    msg.extend_from_slice(data);
    msg.push(0x80);
    while (msg.len() % 64) != 56 {
        msg.push(0);
    }
    msg.extend_from_slice(&bit_len.to_be_bytes());

    let mut w = [0u32; 80];
    for chunk in msg.chunks_exact(64) {
        for i in 0..16 {
            w[i] = u32::from_be_bytes([
                chunk[i * 4],
                chunk[i * 4 + 1],
                chunk[i * 4 + 2],
                chunk[i * 4 + 3],
            ]);
        }
        for i in 16..80 {
            w[i] = (w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]).rotate_left(1);
        }

        let (mut a, mut b, mut c, mut d, mut e) = (h0, h1, h2, h3, h4);
        for (i, &wi) in w.iter().enumerate() {
            let (f, k) = match i {
                0..=19 => ((b & c) | ((!b) & d), 0x5A82_7999u32),
                20..=39 => (b ^ c ^ d, 0x6ED9_EBA1u32),
                40..=59 => ((b & c) | (b & d) | (c & d), 0x8F1B_BCDC),
                _ => (b ^ c ^ d, 0xCA62_C1D6u32),
            };
            let temp = a
                .rotate_left(5)
                .wrapping_add(f)
                .wrapping_add(e)
                .wrapping_add(k)
                .wrapping_add(wi);
            e = d;
            d = c;
            c = b.rotate_left(30);
            b = a;
            a = temp;
        }

        h0 = h0.wrapping_add(a);
        h1 = h1.wrapping_add(b);
        h2 = h2.wrapping_add(c);
        h3 = h3.wrapping_add(d);
        h4 = h4.wrapping_add(e);
    }

    let mut out = [0u8; 20];
    out[0..4].copy_from_slice(&h0.to_be_bytes());
    out[4..8].copy_from_slice(&h1.to_be_bytes());
    out[8..12].copy_from_slice(&h2.to_be_bytes());
    out[12..16].copy_from_slice(&h3.to_be_bytes());
    out[16..20].copy_from_slice(&h4.to_be_bytes());
    out
}

/// Pure-Rust RFC 4648 standard Base64 encoder.
fn base64_encode(input: &[u8]) -> String {
    const TABLE: &[u8; 64] =
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(input.len().div_ceil(3) * 4);
    for chunk in input.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = if chunk.len() > 1 { chunk[1] as u32 } else { 0 };
        let b2 = if chunk.len() > 2 { chunk[2] as u32 } else { 0 };
        let triple = (b0 << 16) | (b1 << 8) | b2;

        out.push(TABLE[((triple >> 18) & 0x3F) as usize] as char);
        out.push(TABLE[((triple >> 12) & 0x3F) as usize] as char);
        if chunk.len() > 1 {
            out.push(TABLE[((triple >> 6) & 0x3F) as usize] as char);
        } else {
            out.push('=');
        }
        if chunk.len() > 2 {
            out.push(TABLE[(triple & 0x3F) as usize] as char);
        } else {
            out.push('=');
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc6455_websocket_accept_vector() {
        assert_eq!(
            compute_ws_accept("dGhlIHNhbXBsZSBub25jZQ=="),
            "s3pPLMBiTxaQ9kYGzzhZRbK+xOo="
        );
    }

    #[test]
    fn detects_http_and_custom_payload_methods() {
        assert!(looks_like_http(b"GET / HTTP/1.1\r\n"));
        assert!(looks_like_http(b"BMOVE / HTTP/1.1\r\n"));
        assert!(looks_like_http(b"CONNECT 127.0.0.1:443 HTTP/1.1\r\n"));
        assert!(looks_like_http(b"ACL / HTTP/1.1\r\n"));
        assert!(!looks_like_http(b"SSH-2.0-OpenSSH_9.2\r\n"));
        assert!(!looks_like_http(&[0x16, 0x03, 0x01, 0x02, 0x00]));
    }
}
