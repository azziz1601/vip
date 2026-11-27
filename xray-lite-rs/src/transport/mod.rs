pub mod grpc;
pub mod httpupgrade;
pub mod websocket;
pub mod xhttp;

use std::fs::File;
use std::io::BufReader;
use std::sync::Arc;

use tokio::io::{AsyncRead, AsyncWrite};
use tokio_rustls::rustls::ServerConfig;
use tokio_rustls::TlsAcceptor;

use crate::config::TlsSettings;

/// Unified async stream trait for all transports (TCP, Unix, TLS, WS, HTTPUpgrade, gRPC).
pub trait AsyncStream: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> AsyncStream for T {}

pub type BoxedStream = Box<dyn AsyncStream>;

pub fn build_tls_acceptor(tls: &TlsSettings, is_grpc: bool) -> Result<TlsAcceptor, String> {
    let cert_cfg = tls
        .certificates
        .first()
        .ok_or_else(|| "tlsSettings.certificates is empty".to_string())?;

    let cert_file = File::open(&cert_cfg.certificate_file).map_err(|e| {
        format!(
            "failed to open TLS certificate '{}': {e}",
            cert_cfg.certificate_file
        )
    })?;
    let mut cert_reader = BufReader::new(cert_file);
    let certs: Vec<_> = rustls_pemfile::certs(&mut cert_reader)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| format!("failed to parse TLS certificate PEM: {e}"))?;
    if certs.is_empty() {
        return Err(format!(
            "no certificates found in '{}'",
            cert_cfg.certificate_file
        ));
    }

    let key_file = File::open(&cert_cfg.key_file)
        .map_err(|e| format!("failed to open TLS key '{}': {e}", cert_cfg.key_file))?;
    let mut key_reader = BufReader::new(key_file);
    let key = rustls_pemfile::private_key(&mut key_reader)
        .map_err(|e| format!("failed to parse TLS private key PEM: {e}"))?
        .ok_or_else(|| format!("no private key found in '{}'", cert_cfg.key_file))?;

    let mut config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|e| format!("invalid TLS certificate/key pair: {e}"))?;

    if !tls.alpn.is_empty() {
        config.alpn_protocols = tls.alpn.iter().map(|s| s.as_bytes().to_vec()).collect();
    } else if is_grpc {
        config.alpn_protocols = vec![b"h2".to_vec()];
    } else {
        config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    }

    Ok(TlsAcceptor::from(Arc::new(config)))
}

/// Normalizes a configured path (ensures leading `/` and strips `?query` suffix like `?ed=2048`).
pub fn normalize_path(path: &str) -> String {
    let stripped = path.split('?').next().unwrap_or(path);
    if stripped.is_empty() {
        "/".to_string()
    } else if stripped.starts_with('/') {
        stripped.to_string()
    } else {
        format!("/{stripped}")
    }
}
