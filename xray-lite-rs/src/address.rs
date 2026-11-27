use std::collections::HashMap;
use std::fmt;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::{OnceLock, RwLock};
use std::time::{Duration, Instant};

use tokio::io::{AsyncRead, AsyncReadExt};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TargetHost {
    Ipv4(Ipv4Addr),
    Ipv6(Ipv6Addr),
    Domain(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TargetAddr {
    pub host: TargetHost,
    pub port: u16,
}

impl fmt::Display for TargetAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.host {
            TargetHost::Ipv4(ip) => write!(f, "{ip}:{}", self.port),
            TargetHost::Ipv6(ip) => write!(f, "[{ip}]:{}", self.port),
            TargetHost::Domain(d) => write!(f, "{d}:{}", self.port),
        }
    }
}

impl TargetAddr {
    pub async fn resolve(&self) -> io::Result<SocketAddr> {
        match &self.host {
            TargetHost::Ipv4(ip) => Ok(SocketAddr::new(IpAddr::V4(*ip), self.port)),
            TargetHost::Ipv6(ip) => Ok(SocketAddr::new(IpAddr::V6(*ip), self.port)),
            TargetHost::Domain(domain) => {
                let ip = resolve_domain_cached(domain, self.port).await?;
                Ok(SocketAddr::new(ip, self.port))
            }
        }
    }

    pub fn from_socket_addr(addr: SocketAddr) -> Self {
        match addr {
            SocketAddr::V4(v4) => Self {
                host: TargetHost::Ipv4(*v4.ip()),
                port: v4.port(),
            },
            SocketAddr::V6(v6) => Self {
                host: TargetHost::Ipv6(*v6.ip()),
                port: v6.port(),
            },
        }
    }
}


const DNS_CACHE_TTL: Duration = Duration::from_secs(60);
const DNS_CACHE_MAX_ENTRIES: usize = 1024;

static DNS_CACHE: OnceLock<RwLock<HashMap<String, (IpAddr, Instant)>>> = OnceLock::new();

fn dns_cache() -> &'static RwLock<HashMap<String, (IpAddr, Instant)>> {
    DNS_CACHE.get_or_init(|| RwLock::new(HashMap::with_capacity(128)))
}

async fn resolve_domain_cached(domain: &str, port: u16) -> io::Result<IpAddr> {
    let key = domain.to_ascii_lowercase();
    let now = Instant::now();
    {
        let map = dns_cache().read().unwrap_or_else(|e| e.into_inner());
        if let Some(&(ip, ts)) = map.get(&key) {
            if now.duration_since(ts) < DNS_CACHE_TTL {
                return Ok(ip);
            }
        }
    }

    let mut addrs = tokio::net::lookup_host((domain, port)).await?;
    let addr = addrs.next().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::NotFound,
            format!("DNS resolution returned no addresses for {domain}"),
        )
    })?;
    let ip = addr.ip();

    {
        let mut map = dns_cache().write().unwrap_or_else(|e| e.into_inner());
        if map.len() >= DNS_CACHE_MAX_ENTRIES {
            map.retain(|_, &mut (_, ts)| now.duration_since(ts) < DNS_CACHE_TTL);
            if map.len() >= DNS_CACHE_MAX_ENTRIES {
                map.clear();
            }
        }
        map.insert(key, (ip, now));
    }

    Ok(ip)
}

/// Checks if an IP is loopback, private, link-local, or unspecified (SSRF protection).
pub fn is_private_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            v4.is_loopback()
                || v4.is_private()
                || v4.is_link_local()
                || v4.is_unspecified()
                || v4.is_broadcast()
                || v4.is_multicast()
        }
        IpAddr::V6(v6) => {
            if let Some(v4) = v6.to_ipv4_mapped() {
                return is_private_ip(IpAddr::V4(v4));
            }
            v6.is_loopback()
                || v6.is_unspecified()
                || v6.is_multicast()
                || (v6.segments()[0] & 0xfe00) == 0xfc00 // ULA fc00::/7
                || (v6.segments()[0] & 0xffc0) == 0xfe80 // link-local fe80::/10
        }
    }
}

/// Reads VLESS/VMess `PortThenAddress`: `[u16 BE port][atype: 1=IPv4, 2=Domain, 3=IPv6][addr]`.
pub async fn read_vless_vmess_addr<R: AsyncRead + Unpin>(reader: &mut R) -> io::Result<TargetAddr> {
    let mut head = [0u8; 3];
    reader.read_exact(&mut head).await?;
    let port = u16::from_be_bytes([head[0], head[1]]);
    let atype = head[2];
    let host = match atype {
        0x01 => {
            let mut ip = [0u8; 4];
            reader.read_exact(&mut ip).await?;
            TargetHost::Ipv4(Ipv4Addr::from(ip))
        }
        0x02 => {
            let len = reader.read_u8().await? as usize;
            let mut buf = vec![0u8; len];
            reader.read_exact(&mut buf).await?;
            let domain = String::from_utf8(buf).map_err(|_| {
                io::Error::new(io::ErrorKind::InvalidData, "invalid UTF-8 domain")
            })?;
            TargetHost::Domain(domain)
        }
        0x03 => {
            let mut ip = [0u8; 16];
            reader.read_exact(&mut ip).await?;
            TargetHost::Ipv6(Ipv6Addr::from(ip))
        }
        other => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("unknown VLESS/VMess address type 0x{other:02x}"),
            ));
        }
    };
    Ok(TargetAddr { host, port })
}

/// Parses VLESS/VMess `PortThenAddress` from an in-memory slice, returning `(TargetAddr, bytes_consumed)`.
pub fn parse_vless_vmess_addr_slice(buf: &[u8]) -> io::Result<(TargetAddr, usize)> {
    if buf.len() < 3 {
        return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "truncated addr"));
    }
    let port = u16::from_be_bytes([buf[0], buf[1]]);
    let atype = buf[2];
    match atype {
        0x01 => {
            if buf.len() < 7 {
                return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "truncated ipv4"));
            }
            let ip = Ipv4Addr::new(buf[3], buf[4], buf[5], buf[6]);
            Ok((TargetAddr { host: TargetHost::Ipv4(ip), port }, 7))
        }
        0x02 => {
            if buf.len() < 4 {
                return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "truncated domain len"));
            }
            let len = buf[3] as usize;
            if buf.len() < 4 + len {
                return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "truncated domain"));
            }
            let domain = String::from_utf8(buf[4..4 + len].to_vec()).map_err(|_| {
                io::Error::new(io::ErrorKind::InvalidData, "invalid UTF-8 domain")
            })?;
            Ok((TargetAddr { host: TargetHost::Domain(domain), port }, 4 + len))
        }
        0x03 => {
            if buf.len() < 19 {
                return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "truncated ipv6"));
            }
            let mut ip = [0u8; 16];
            ip.copy_from_slice(&buf[3..19]);
            Ok((TargetAddr { host: TargetHost::Ipv6(Ipv6Addr::from(ip)), port }, 19))
        }
        other => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("unknown VLESS/VMess address type 0x{other:02x}"),
        )),
    }
}

/// Reads Trojan / SOCKS5 `AddressThenPort`: `[atype: 1=IPv4, 3=Domain, 4=IPv6][addr][u16 BE port]`.
pub async fn read_socks5_addr<R: AsyncRead + Unpin>(reader: &mut R) -> io::Result<TargetAddr> {
    let atype = reader.read_u8().await?;
    let host = match atype {
        0x01 => {
            let mut ip = [0u8; 4];
            reader.read_exact(&mut ip).await?;
            TargetHost::Ipv4(Ipv4Addr::from(ip))
        }
        0x03 => {
            let len = reader.read_u8().await? as usize;
            let mut buf = vec![0u8; len];
            reader.read_exact(&mut buf).await?;
            let domain = String::from_utf8(buf).map_err(|_| {
                io::Error::new(io::ErrorKind::InvalidData, "invalid UTF-8 domain")
            })?;
            TargetHost::Domain(domain)
        }
        0x04 => {
            let mut ip = [0u8; 16];
            reader.read_exact(&mut ip).await?;
            TargetHost::Ipv6(Ipv6Addr::from(ip))
        }
        other => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("unknown SOCKS5/Trojan address type 0x{other:02x}"),
            ));
        }
    };
    let port = reader.read_u16().await?;
    Ok(TargetAddr { host, port })
}

/// Encodes Trojan / SOCKS5 `AddressThenPort` into `out`.
pub fn encode_socks5_addr(addr: &TargetAddr, out: &mut Vec<u8>) {
    match &addr.host {
        TargetHost::Ipv4(ip) => {
            out.push(0x01);
            out.extend_from_slice(&ip.octets());
        }
        TargetHost::Domain(domain) => {
            let b = domain.as_bytes();
            let len = b.len().min(255);
            out.push(0x03);
            out.push(len as u8);
            out.extend_from_slice(&b[..len]);
        }
        TargetHost::Ipv6(ip) => {
            out.push(0x04);
            out.extend_from_slice(&ip.octets());
        }
    }
    out.extend_from_slice(&addr.port.to_be_bytes());
}
