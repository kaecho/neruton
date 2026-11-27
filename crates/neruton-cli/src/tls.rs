//! TLS configuration, true TLS 1.3 ECH (with RFC 9849 `retry_configs` retry),
//! ClientHello TCP fragmentation, and custom/omitted SNI with strict real-host verification.

use std::collections::VecDeque;
use std::fmt;
use std::future::Future;
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::str::FromStr;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use anyhow::{anyhow, bail, Result};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::client::{EchConfig, EchMode, EchStatus, WebPkiServerVerifier};
use rustls::internal::msgs::handshake::EchConfigPayload;
use rustls::pki_types::{CertificateDer, EchConfigListBytes, ServerName, UnixTime};
use rustls::{
    ClientConfig, DigitallySignedStruct, DistinguishedName, Error, PeerIncompatible, RootCertStore,
    SignatureScheme,
};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;

use crate::doh::should_skip_doh;
use crate::hpke::{encode_ech_config_list, select_ech_public_name, ALL_SUPPORTED_SUITES};
use crate::ui;

const TCP_CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const TLS_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
const DEFAULT_FIRST_FRAGMENT_LEN: usize = 5;
const DEFAULT_FRAGMENT_CHUNK_LEN: usize = 32;
/// Brief async pause between initial ClientHello TCP fragments so Linux `tcp_autocorking`
/// flushes each segment onto the wire separately (only applied during ClientHello, never afterwards).
const DEFAULT_INTER_FRAGMENT_DELAY: Duration = Duration::from_millis(5);

/// Initialize the ring crypto provider for rustls (idempotent).
pub fn install_crypto_provider() {
    let _ = rustls::crypto::ring::default_provider().install_default();
}

/// Build the default WebPKI `RootCertStore` (Mozilla root certificates).
pub fn webpki_root_store() -> Arc<RootCertStore> {
    let mut roots = RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    Arc::new(roots)
}

/// Build a pure-rustls `ClientConfig` (no OpenSSL dependency) using Mozilla WebPKI root certs,
/// or skipping certificate verification when `--no-tls-verify` is requested.
///
/// Used by the local HTTPS target forwarder.
pub fn build_rustls_config(no_tls_verify: bool) -> Arc<ClientConfig> {
    install_crypto_provider();

    if no_tls_verify {
        let cfg = ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(NoCertificateVerification))
            .with_no_client_auth();
        return Arc::new(cfg);
    }

    let cfg = ClientConfig::builder()
        .with_root_certificates(webpki_root_store())
        .with_no_client_auth();
    Arc::new(cfg)
}

/// Build a `ClientConfig` for RFC 8484 DoH connections (WebPKI roots + h2/http1.1 ALPN).
pub fn build_doh_rustls_config() -> Arc<ClientConfig> {
    install_crypto_provider();
    let mut cfg = ClientConfig::builder()
        .with_root_certificates(webpki_root_store())
        .with_no_client_auth();
    cfg.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    Arc::new(cfg)
}

/// SNI hiding mode for `wss://` tunnel connections.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SniMode {
    /// Default: use real TLS 1.3 ECH when ECHConfigList is available, else ClientHello TCP fragmentation.
    #[default]
    Auto,
    /// Strict TLS 1.3 ECH: fail fast if no ECHConfigList is available or ECH is rejected after retry.
    Ech,
    /// Split initial TLS ClientHello record across TCP segments (`TCP_NODELAY`).
    Fragment,
    /// Omit TLS SNI extension completely (`enable_sni = false`) with strict real-host cert verification.
    None,
    /// Standard TLS SNI with no hiding.
    Plain,
}

impl SniMode {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Auto => "auto",
            Self::Ech => "ech",
            Self::Fragment => "fragment",
            Self::None => "none",
            Self::Plain => "plain",
        }
    }
}

impl FromStr for SniMode {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "" | "auto" => Ok(Self::Auto),
            "ech" => Ok(Self::Ech),
            "fragment" => Ok(Self::Fragment),
            "none" => Ok(Self::None),
            "plain" => Ok(Self::Plain),
            other => bail!(
                "invalid --sni-mode '{other}': expected one of auto, ech, fragment, none, plain"
            ),
        }
    }
}

impl fmt::Display for SniMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Options controlling TLS stealth behavior for the tunnel WebSocket connection.
#[derive(Debug, Clone, Default)]
pub struct StealthTlsOptions {
    pub sni_mode: SniMode,
    pub custom_sni: Option<String>,
    pub ech_config: Option<Vec<u8>>,
    pub no_tls_verify: bool,
}

/// Error returned when establishing a stealth TLS connection.
#[derive(Debug)]
pub enum TlsConnectError {
    /// Non-retryable configuration or strict ECH failure (fail fast).
    Fatal(String),
    /// Network / transient / handshake failure (eligible for IP failover or reconnect backoff).
    Retryable(String),
}

impl fmt::Display for TlsConnectError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Fatal(m) | Self::Retryable(m) => f.write_str(m),
        }
    }
}

impl std::error::Error for TlsConnectError {}

/// Unified transport stream passed into `tokio_tungstenite::client_async_with_config`.
pub enum TunnelStream {
    Plain(TcpStream),
    Tls(Box<tokio_rustls::client::TlsStream<TcpStream>>),
    FragmentedTls(Box<tokio_rustls::client::TlsStream<FragmentingStream<TcpStream>>>),
}

impl AsyncRead for TunnelStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        match &mut *self {
            Self::Plain(s) => Pin::new(s).poll_read(cx, buf),
            Self::Tls(s) => Pin::new(s).poll_read(cx, buf),
            Self::FragmentedTls(s) => Pin::new(s).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for TunnelStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        match &mut *self {
            Self::Plain(s) => Pin::new(s).poll_write(cx, buf),
            Self::Tls(s) => Pin::new(s).poll_write(cx, buf),
            Self::FragmentedTls(s) => Pin::new(s).poll_write(cx, buf),
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match &mut *self {
            Self::Plain(s) => Pin::new(s).poll_flush(cx),
            Self::Tls(s) => Pin::new(s).poll_flush(cx),
            Self::FragmentedTls(s) => Pin::new(s).poll_flush(cx),
        }
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match &mut *self {
            Self::Plain(s) => Pin::new(s).poll_shutdown(cx),
            Self::Tls(s) => Pin::new(s).poll_shutdown(cx),
            Self::FragmentedTls(s) => Pin::new(s).poll_shutdown(cx),
        }
    }
}

/// Successfully established TLS stream plus diagnostic metadata for connect logging.
pub struct ConnectedTls {
    pub stream: TunnelStream,
    pub mode_label: String,
    pub ech_status: EchStatus,
}

#[derive(Debug, Clone)]
enum EffectiveTlsPlan {
    Ech {
        ech_config_list: Vec<u8>,
        allow_fragment_fallback: bool,
    },
    Fragment {
        sni_override: Option<String>,
    },
    OmitSni,
    Plain {
        sni_override: Option<String>,
    },
}

fn plan_tls_mode(
    real_host: &str,
    opts: &StealthTlsOptions,
    doh_ech_config: Option<&[u8]>,
) -> std::result::Result<EffectiveTlsPlan, TlsConnectError> {
    let is_local = should_skip_doh(real_host);
    let custom_sni = opts
        .custom_sni
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(ToOwned::to_owned);
    let available_ech = opts.ech_config.as_deref().or(doh_ech_config);

    match opts.sni_mode {
        SniMode::Auto => {
            if is_local && custom_sni.is_none() && opts.ech_config.is_none() {
                return Ok(EffectiveTlsPlan::Plain { sni_override: None });
            }
            if let Some(sni) = custom_sni {
                return Ok(EffectiveTlsPlan::Fragment {
                    sni_override: Some(sni),
                });
            }
            if let Some(ech) = available_ech {
                return Ok(EffectiveTlsPlan::Ech {
                    ech_config_list: ech.to_vec(),
                    allow_fragment_fallback: opts.ech_config.is_none(),
                });
            }
            Ok(EffectiveTlsPlan::Fragment { sni_override: None })
        }
        SniMode::Ech => {
            let Some(ech) = available_ech else {
                return Err(TlsConnectError::Fatal(format!(
                    "ECH mode (--sni-mode ech) requires an ECHConfigList, but none was provided via --ech-config or DoH HTTPS record for '{real_host}'"
                )));
            };
            Ok(EffectiveTlsPlan::Ech {
                ech_config_list: ech.to_vec(),
                allow_fragment_fallback: false,
            })
        }
        SniMode::Fragment => Ok(EffectiveTlsPlan::Fragment {
            sni_override: custom_sni,
        }),
        SniMode::None => Ok(EffectiveTlsPlan::OmitSni),
        SniMode::Plain => Ok(EffectiveTlsPlan::Plain {
            sni_override: custom_sni,
        }),
    }
}

/// Connect TCP + stealth TLS to a pre-resolved `SocketAddr` for `real_host`.
pub async fn connect_stealth_tls(
    addr: SocketAddr,
    real_host: &str,
    opts: &StealthTlsOptions,
    doh_ech_config: Option<&[u8]>,
) -> std::result::Result<ConnectedTls, TlsConnectError> {
    connect_stealth_tls_with_roots(addr, real_host, opts, doh_ech_config, webpki_root_store()).await
}

/// Same as [`connect_stealth_tls`] with an injectable `RootCertStore` (used by unit tests).
pub async fn connect_stealth_tls_with_roots(
    addr: SocketAddr,
    real_host: &str,
    opts: &StealthTlsOptions,
    doh_ech_config: Option<&[u8]>,
    roots: Arc<RootCertStore>,
) -> std::result::Result<ConnectedTls, TlsConnectError> {
    install_crypto_provider();
    let plan = plan_tls_mode(real_host, opts, doh_ech_config)?;

    match plan {
        EffectiveTlsPlan::Ech {
            ech_config_list,
            allow_fragment_fallback,
        } => {
            match connect_ech_with_retry(
                addr,
                real_host,
                &ech_config_list,
                opts.no_tls_verify,
                roots.clone(),
                allow_fragment_fallback,
            )
            .await
            {
                Ok(connected) => Ok(connected),
                Err(EchAttemptError::FallbackToFragment(reason)) => {
                    ui::log_warn(&format!(
                        "ECH unavailable ({reason}); falling back to ClientHello TCP fragmentation."
                    ));
                    connect_non_ech(
                        addr,
                        real_host,
                        EffectiveTlsPlan::Fragment { sni_override: None },
                        opts.no_tls_verify,
                        roots,
                    )
                    .await
                }
                Err(EchAttemptError::Fatal(msg)) => Err(TlsConnectError::Fatal(msg)),
                Err(EchAttemptError::Retryable(msg)) => Err(TlsConnectError::Retryable(msg)),
            }
        }
        other => connect_non_ech(addr, real_host, other, opts.no_tls_verify, roots).await,
    }
}

enum EchAttemptError {
    FallbackToFragment(String),
    Fatal(String),
    Retryable(String),
}

async fn connect_tcp(addr: SocketAddr) -> std::result::Result<TcpStream, String> {
    let tcp = tokio::time::timeout(TCP_CONNECT_TIMEOUT, TcpStream::connect(addr))
        .await
        .map_err(|_| format!("TCP connect to {addr} timed out"))?
        .map_err(|e| format!("TCP connect to {addr} failed: {e}"))?;
    let _ = tcp.set_nodelay(true);
    Ok(tcp)
}

async fn connect_ech_with_retry(
    addr: SocketAddr,
    real_host: &str,
    initial_ech_config_list: &[u8],
    no_tls_verify: bool,
    roots: Arc<RootCertStore>,
    allow_fragment_fallback: bool,
) -> std::result::Result<ConnectedTls, EchAttemptError> {
    let real_server_name = ServerName::try_from(real_host.to_string())
        .map_err(|_| EchAttemptError::Fatal(format!("invalid TLS server name '{real_host}'")))?;

    let mut current_ech_bytes = initial_ech_config_list.to_vec();
    let mut retried = false;

    loop {
        let ech_cfg = match EchConfig::new(
            EchConfigListBytes::from(current_ech_bytes.as_slice()),
            ALL_SUPPORTED_SUITES,
        ) {
            Ok(cfg) => cfg,
            Err(e) => {
                let msg = format!("incompatible or invalid ECHConfigList: {e}");
                return if allow_fragment_fallback {
                    Err(EchAttemptError::FallbackToFragment(msg))
                } else {
                    Err(EchAttemptError::Fatal(msg))
                };
            }
        };

        let outer_name = select_ech_public_name(&current_ech_bytes);
        let tls_cfg = build_ech_client_config(ech_cfg, no_tls_verify, roots.clone())
            .map_err(|e| EchAttemptError::Fatal(format!("failed building ECH TLS config: {e}")))?;

        let tcp = connect_tcp(addr)
            .await
            .map_err(EchAttemptError::Retryable)?;

        let connector = TlsConnector::from(tls_cfg);
        let hs = tokio::time::timeout(
            TLS_HANDSHAKE_TIMEOUT,
            connector.connect(real_server_name.clone(), tcp),
        )
        .await
        .map_err(|_| {
            EchAttemptError::Retryable(format!("TLS ECH handshake to {addr} timed out"))
        })?;

        match hs {
            Ok(tls_stream) => {
                let ech_status = tls_stream.get_ref().1.ech_status();
                if ech_status != EchStatus::Accepted {
                    let msg = format!(
                        "TLS handshake completed with unexpected ECH status {ech_status:?}"
                    );
                    return if allow_fragment_fallback {
                        Err(EchAttemptError::FallbackToFragment(msg))
                    } else {
                        Err(EchAttemptError::Fatal(msg))
                    };
                }
                let outer_label = outer_name.as_deref().unwrap_or("unknown");
                let mode_label = if retried {
                    format!("ECH (outer: {outer_label}, retried)")
                } else {
                    format!("ECH (outer: {outer_label})")
                };
                return Ok(ConnectedTls {
                    stream: TunnelStream::Tls(Box::new(tls_stream)),
                    mode_label,
                    ech_status,
                });
            }
            Err(io_err) => {
                if let Some(maybe_retry_configs) = extract_ech_rejection(&io_err) {
                    if !retried {
                        if let Some(retry_configs) = maybe_retry_configs {
                            if !retry_configs.is_empty() {
                                ui::log_warn(
                                    "Server rejected initial ECH config and supplied retry_configs; retrying ECH once.",
                                );
                                current_ech_bytes = encode_ech_config_list(&retry_configs);
                                retried = true;
                                continue;
                            }
                        }
                    }
                    let msg = if retried {
                        "server rejected ECH even after RFC 9849 retry_configs retry".to_string()
                    } else {
                        "server rejected ECH without usable retry_configs".to_string()
                    };
                    return if allow_fragment_fallback {
                        Err(EchAttemptError::FallbackToFragment(msg))
                    } else {
                        Err(EchAttemptError::Fatal(msg))
                    };
                }
                return Err(EchAttemptError::Retryable(format!(
                    "TLS ECH handshake to {addr} failed: {io_err}"
                )));
            }
        }
    }
}

async fn connect_non_ech(
    addr: SocketAddr,
    real_host: &str,
    plan: EffectiveTlsPlan,
    no_tls_verify: bool,
    roots: Arc<RootCertStore>,
) -> std::result::Result<ConnectedTls, TlsConnectError> {
    let real_server_name = ServerName::try_from(real_host.to_string())
        .map_err(|_| TlsConnectError::Fatal(format!("invalid TLS server name '{real_host}'")))?;

    let (enable_sni, fragment, sni_override, mode_label) = match plan {
        EffectiveTlsPlan::Fragment { sni_override } => {
            let label = match &sni_override {
                Some(sni) => format!("ClientHello fragment + custom SNI ({sni})"),
                None => "ClientHello fragment".to_string(),
            };
            (true, true, sni_override, label)
        }
        EffectiveTlsPlan::OmitSni => (false, false, None, "omitted SNI".to_string()),
        EffectiveTlsPlan::Plain { sni_override } => {
            let label = match &sni_override {
                Some(sni) => format!("custom SNI ({sni})"),
                None => "plain TLS".to_string(),
            };
            (true, false, sni_override, label)
        }
        EffectiveTlsPlan::Ech { .. } => unreachable!("ECH handled separately"),
    };

    let wire_server_name = match &sni_override {
        Some(custom) => ServerName::try_from(custom.clone())
            .map_err(|_| TlsConnectError::Fatal(format!("invalid custom --sni host '{custom}'")))?,
        None => real_server_name.clone(),
    };

    let verify_override = if sni_override.is_some() || !enable_sni {
        Some(real_server_name)
    } else {
        None
    };

    let tls_cfg = build_custom_client_config(roots, no_tls_verify, enable_sni, verify_override)
        .map_err(|e| TlsConnectError::Fatal(format!("failed building TLS config: {e}")))?;

    let tcp = connect_tcp(addr)
        .await
        .map_err(TlsConnectError::Retryable)?;

    let connector = TlsConnector::from(tls_cfg);

    if fragment {
        let frag_stream = FragmentingStream::new(tcp);
        let tls_stream = tokio::time::timeout(
            TLS_HANDSHAKE_TIMEOUT,
            connector.connect(wire_server_name, frag_stream),
        )
        .await
        .map_err(|_| TlsConnectError::Retryable(format!("TLS handshake to {addr} timed out")))?
        .map_err(|e| TlsConnectError::Retryable(format!("TLS handshake to {addr} failed: {e}")))?;
        let ech_status = tls_stream.get_ref().1.ech_status();
        Ok(ConnectedTls {
            stream: TunnelStream::FragmentedTls(Box::new(tls_stream)),
            mode_label,
            ech_status,
        })
    } else {
        let tls_stream = tokio::time::timeout(
            TLS_HANDSHAKE_TIMEOUT,
            connector.connect(wire_server_name, tcp),
        )
        .await
        .map_err(|_| TlsConnectError::Retryable(format!("TLS handshake to {addr} timed out")))?
        .map_err(|e| TlsConnectError::Retryable(format!("TLS handshake to {addr} failed: {e}")))?;
        let ech_status = tls_stream.get_ref().1.ech_status();
        Ok(ConnectedTls {
            stream: TunnelStream::Tls(Box::new(tls_stream)),
            mode_label,
            ech_status,
        })
    }
}

fn build_ech_client_config(
    ech_cfg: EchConfig,
    no_tls_verify: bool,
    roots: Arc<RootCertStore>,
) -> Result<Arc<ClientConfig>> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let builder = ClientConfig::builder_with_provider(provider)
        .with_ech(EchMode::Enable(ech_cfg))
        .map_err(|e| anyhow!("rustls rejected ECH mode: {e}"))?;

    let cfg = if no_tls_verify {
        builder
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(NoCertificateVerification))
            .with_no_client_auth()
    } else {
        builder.with_root_certificates(roots).with_no_client_auth()
    };
    Ok(Arc::new(cfg))
}

fn build_custom_client_config(
    roots: Arc<RootCertStore>,
    no_tls_verify: bool,
    enable_sni: bool,
    verify_real_host: Option<ServerName<'static>>,
) -> Result<Arc<ClientConfig>> {
    let mut cfg = if no_tls_verify {
        ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(NoCertificateVerification))
            .with_no_client_auth()
    } else if let Some(real_host) = verify_real_host {
        let webpki = WebPkiServerVerifier::builder(roots)
            .build()
            .map_err(|e| anyhow!("failed to build WebPkiServerVerifier: {e}"))?;
        ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(RealHostCertVerifier {
                inner: webpki,
                real_host,
            }))
            .with_no_client_auth()
    } else {
        ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth()
    };

    cfg.enable_sni = enable_sni;
    Ok(Arc::new(cfg))
}

/// Inspect a `tokio-rustls` `io::Error` to see if it represents RFC 9849 ECH rejection.
fn extract_ech_rejection(err: &io::Error) -> Option<Option<Vec<EchConfigPayload>>> {
    let rustls_err = err.get_ref()?.downcast_ref::<Error>()?;
    match rustls_err {
        Error::PeerIncompatible(PeerIncompatible::ServerRejectedEncryptedClientHello(configs)) => {
            Some(configs.clone())
        }
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// ClientHello-fragmenting AsyncWrite wrapper (SNI-aware + autocork-safe pacing)
// ---------------------------------------------------------------------------

enum FragState {
    Initial,
    Fragmenting {
        remaining_chunks: VecDeque<usize>,
        delay: Option<Pin<Box<tokio::time::Sleep>>>,
    },
    Passthrough,
}

/// Locate the byte span `(start, end)` of the SNI `host_name` inside a TLS ClientHello record.
///
/// Pure bounds-checked read; returns `None` if the record is not a complete ClientHello with
/// an SNI hostname extension.
fn find_client_hello_sni_span(record: &[u8]) -> Option<(usize, usize)> {
    // 5-byte TLS record header + 4-byte Handshake header + 2-byte version + 32-byte random
    if record.len() < 44 || record[0] != 0x16 || record[5] != 0x01 {
        return None;
    }
    let record_len = u16::from_be_bytes([record[3], record[4]]) as usize;
    let record_end = (5usize.checked_add(record_len)?).min(record.len());

    let mut pos = 43usize; // session_id_len
    let sid_len = *record.get(pos)? as usize;
    pos = pos.checked_add(1)?.checked_add(sid_len)?;

    let cs_len = u16::from_be_bytes([*record.get(pos)?, *record.get(pos + 1)?]) as usize;
    pos = pos.checked_add(2)?.checked_add(cs_len)?;

    let comp_len = *record.get(pos)? as usize;
    pos = pos.checked_add(1)?.checked_add(comp_len)?;

    let exts_len = u16::from_be_bytes([*record.get(pos)?, *record.get(pos + 1)?]) as usize;
    pos = pos.checked_add(2)?;
    let exts_end = pos.checked_add(exts_len)?.min(record_end);

    while pos.checked_add(4)? <= exts_end {
        let ext_type = u16::from_be_bytes([record[pos], record[pos + 1]]);
        let ext_len = u16::from_be_bytes([record[pos + 2], record[pos + 3]]) as usize;
        let data_start = pos + 4;
        let data_end = data_start.checked_add(ext_len)?;
        if data_end > exts_end {
            return None;
        }
        if ext_type == 0x0000 && ext_len >= 5 {
            // ServerNameList: list_len (2) + entries [name_type (1), name_len (2), name]
            let list_len =
                u16::from_be_bytes([record[data_start], record[data_start + 1]]) as usize;
            let list_end = data_start
                .checked_add(2)?
                .checked_add(list_len)?
                .min(data_end);
            let mut npos = data_start + 2;
            while npos.checked_add(3)? <= list_end {
                let name_type = record[npos];
                let name_len = u16::from_be_bytes([record[npos + 1], record[npos + 2]]) as usize;
                let name_start = npos + 3;
                let name_end = name_start.checked_add(name_len)?;
                if name_end > list_end {
                    return None;
                }
                if name_type == 0x00 && name_len >= 2 {
                    return Some((name_start, name_end));
                }
                npos = name_end;
            }
        }
        pos = data_end;
    }
    None
}

/// Plan chunk sizes covering `total` bytes of the initial TLS ClientHello record.
///
/// When an SNI hostname is present, splits into 3 strategic TCP segments:
/// `[0..first_chunk]` (TLS record header), `[first_chunk..sni_mid]` (first half of SNI),
/// and `[sni_mid..total]` (second half of SNI + remainder) — keeping added latency to ~10ms
/// while guaranteeing the SNI hostname itself is split across wire TCP segments.
fn plan_client_hello_chunks(
    buf: &[u8],
    total: usize,
    first_chunk: usize,
    fallback_chunk_size: usize,
) -> VecDeque<usize> {
    let mut chunks = VecDeque::new();
    if let Some((sni_start, sni_end)) = find_client_hello_sni_span(buf) {
        let sni_mid = sni_start + (sni_end - sni_start) / 2;
        if sni_mid > first_chunk && sni_mid < total {
            chunks.push_back(first_chunk);
            chunks.push_back(sni_mid - first_chunk);
            chunks.push_back(total - sni_mid);
            return chunks;
        }
    }

    // Fallback when SNI is absent or not in initial slice: header chunk + fixed-size chunks.
    let first = total.min(first_chunk.max(1));
    chunks.push_back(first);
    let mut rem = total - first;
    let step = fallback_chunk_size.max(1);
    while rem > 0 {
        let take = rem.min(step);
        chunks.push_back(take);
        rem -= take;
    }
    chunks
}

/// `AsyncRead` + `AsyncWrite` wrapper that splits the initial TLS ClientHello record (`0x16`)
/// across paced TCP write segments (defeating Linux `tcp_autocorking` with `TCP_NODELAY`),
/// then switches to zero-overhead passthrough for all subsequent records.
pub struct FragmentingStream<S> {
    inner: S,
    first_chunk: usize,
    chunk_size: usize,
    inter_chunk_delay: Duration,
    state: FragState,
}

impl<S> FragmentingStream<S> {
    pub fn new(inner: S) -> Self {
        Self::with_params(
            inner,
            DEFAULT_FIRST_FRAGMENT_LEN,
            DEFAULT_FRAGMENT_CHUNK_LEN,
            DEFAULT_INTER_FRAGMENT_DELAY,
        )
    }

    pub fn with_params(
        inner: S,
        first_chunk: usize,
        chunk_size: usize,
        inter_chunk_delay: Duration,
    ) -> Self {
        Self {
            inner,
            first_chunk: first_chunk.max(1),
            chunk_size: chunk_size.max(1),
            inter_chunk_delay,
            state: FragState::Initial,
        }
    }

    #[cfg(test)]
    pub fn into_inner(self) -> S {
        self.inner
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for FragmentingStream<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for FragmentingStream<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        if buf.is_empty() {
            return Pin::new(&mut self.inner).poll_write(cx, buf);
        }

        let this = self.get_mut();

        match &mut this.state {
            FragState::Passthrough => Pin::new(&mut this.inner).poll_write(cx, buf),
            FragState::Initial => {
                // TLS Handshake record header: content_type=0x16, legacy_version=0x0301/0x0303, length=u16
                if buf.len() >= 5 && buf[0] == 0x16 {
                    let record_len = u16::from_be_bytes([buf[3], buf[4]]) as usize;
                    let total = 5 + record_len;
                    let mut chunks =
                        plan_client_hello_chunks(buf, total, this.first_chunk, this.chunk_size);
                    let first_target = chunks.pop_front().unwrap_or(buf.len());
                    let slice_len = buf.len().min(first_target);
                    match Pin::new(&mut this.inner).poll_write(cx, &buf[..slice_len]) {
                        Poll::Ready(Ok(n)) => {
                            let finished_chunk = n >= first_target;
                            if !finished_chunk {
                                chunks.push_front(first_target - n);
                            }
                            if chunks.is_empty() {
                                this.state = FragState::Passthrough;
                            } else {
                                let delay = if finished_chunk && !this.inter_chunk_delay.is_zero() {
                                    Some(Box::pin(tokio::time::sleep(this.inter_chunk_delay)))
                                } else {
                                    None
                                };
                                this.state = FragState::Fragmenting {
                                    remaining_chunks: chunks,
                                    delay,
                                };
                            }
                            Poll::Ready(Ok(n))
                        }
                        other => other,
                    }
                } else {
                    this.state = FragState::Passthrough;
                    Pin::new(&mut this.inner).poll_write(cx, buf)
                }
            }
            FragState::Fragmenting {
                remaining_chunks,
                delay,
            } => {
                if let Some(sleep) = delay.as_mut() {
                    if sleep.as_mut().poll(cx).is_pending() {
                        return Poll::Pending;
                    }
                    *delay = None;
                }

                let Some(chunk_target) = remaining_chunks.pop_front() else {
                    this.state = FragState::Passthrough;
                    return Pin::new(&mut this.inner).poll_write(cx, buf);
                };

                let slice_len = buf.len().min(chunk_target);
                match Pin::new(&mut this.inner).poll_write(cx, &buf[..slice_len]) {
                    Poll::Ready(Ok(n)) => {
                        let finished_chunk = n >= chunk_target;
                        if !finished_chunk {
                            remaining_chunks.push_front(chunk_target - n);
                        }
                        if remaining_chunks.is_empty() {
                            this.state = FragState::Passthrough;
                        } else if finished_chunk && !this.inter_chunk_delay.is_zero() {
                            *delay = Some(Box::pin(tokio::time::sleep(this.inter_chunk_delay)));
                        }
                        Poll::Ready(Ok(n))
                    }
                    other => {
                        remaining_chunks.push_front(chunk_target);
                        other
                    }
                }
            }
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

// ---------------------------------------------------------------------------
// Certificate verifiers
// ---------------------------------------------------------------------------

/// Delegating WebPKI certificate verifier that always validates the server certificate chain
/// against `real_host` rather than whatever SNI (custom or omitted) was sent on the wire.
#[derive(Debug)]
struct RealHostCertVerifier {
    inner: Arc<WebPkiServerVerifier>,
    real_host: ServerName<'static>,
}

impl ServerCertVerifier for RealHostCertVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        ocsp_response: &[u8],
        now: UnixTime,
    ) -> std::result::Result<ServerCertVerified, Error> {
        self.inner.verify_server_cert(
            end_entity,
            intermediates,
            &self.real_host,
            ocsp_response,
            now,
        )
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, Error> {
        self.inner.verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, Error> {
        self.inner.verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.inner.supported_verify_schemes()
    }

    fn root_hint_subjects(&self) -> Option<&[DistinguishedName]> {
        self.inner.root_hint_subjects()
    }

    fn requires_raw_public_keys(&self) -> bool {
        self.inner.requires_raw_public_keys()
    }
}

#[derive(Debug)]
struct NoCertificateVerification;

impl ServerCertVerifier for NoCertificateVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> std::result::Result<ServerCertVerified, Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![
            SignatureScheme::RSA_PKCS1_SHA256,
            SignatureScheme::RSA_PKCS1_SHA384,
            SignatureScheme::RSA_PKCS1_SHA512,
            SignatureScheme::ECDSA_NISTP256_SHA256,
            SignatureScheme::ECDSA_NISTP384_SHA384,
            SignatureScheme::ECDSA_NISTP521_SHA512,
            SignatureScheme::RSA_PSS_SHA256,
            SignatureScheme::RSA_PSS_SHA384,
            SignatureScheme::RSA_PSS_SHA512,
            SignatureScheme::ED25519,
        ]
    }
}

/// Build a test TLS server+client pair negotiating HTTP/2 ALPN for `127.0.0.1` (used by `doh::tests`).
#[cfg(test)]
pub(crate) fn test_h2_server_and_client_configs() -> (Arc<rustls::ServerConfig>, Arc<ClientConfig>)
{
    use base64::engine::general_purpose::STANDARD;
    use base64::Engine;
    use rustls::pki_types::PrivateKeyDer;

    install_crypto_provider();
    let cert = CertificateDer::from(STANDARD.decode(tests::REAL_CERT_DER_B64).unwrap());
    let key =
        PrivateKeyDer::try_from(STANDARD.decode(tests::REAL_KEY_PK8_DER_B64).unwrap()).unwrap();
    let mut server_cfg = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert], key)
        .unwrap();
    server_cfg.alpn_protocols = vec![b"h2".to_vec()];

    let mut client_cfg = ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(NoCertificateVerification))
        .with_no_client_auth();
    client_cfg.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    (Arc::new(server_cfg), Arc::new(client_cfg))
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::engine::general_purpose::STANDARD;
    use base64::Engine;
    use rustls::pki_types::PrivateKeyDer;
    use rustls::ServerConfig;
    use tokio::io::AsyncWriteExt;
    use tokio::net::TcpListener;
    use tokio_rustls::TlsAcceptor;

    // Self-signed ECDSA P-256 Test CA & Leaf certs valid 2020-01-01 to 2099-12-31.
    const CA_CERT_DER_B64: &str = "MIIBejCCASCgAwIBAgIUQ6l7zGLXorItGIXQoykqFxbghzAwCgYIKoZIzj0EAwIwGjEYMBYGA1UEAwwPTmVydXRvbiBUZXN0IENBMCAXDTIwMDEwMTAwMDAwMFoYDzIwOTkxMjMxMjM1OTU5WjAaMRgwFgYDVQQDDA9OZXJ1dG9uIFRlc3QgQ0EwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAASgArUW5LPbqDOctGpDilkWTL5yL6VtKdRkp2431u0cyWU7uEu/gJh92w41bph/zmIlDti3jgXhIQYTjUO+Ca42o0IwQDAdBgNVHQ4EFgQUmtmi+VCq1ZxnrwwLw67HdNbjbDIwDwYDVR0TAQH/BAUwAwEB/zAOBgNVHQ8BAf8EBAMCAQYwCgYIKoZIzj0EAwIDSAAwRQIgCZhn2NQwjMRQ6nYfHtVKfYkXQZPbiQYMF1wELtIpB5MCIQCwnmjVn//xYu83zEjPxpZtffuehbePPsRWOlm7EHdI+g==";
    pub(super) const REAL_CERT_DER_B64: &str = "MIIBhzCCAS2gAwIBAgIUTyMjUJgXGib7TxfhDtaU2834S1QwCgYIKoZIzj0EAwIwGjEYMBYGA1UEAwwPTmVydXRvbiBUZXN0IENBMCAXDTIwMDEwMTAwMDAwMFoYDzIwOTkxMjMxMjM1OTU5WjAcMRowGAYDVQQDDBFyZWFsLmV4YW1wbGUudGVzdDBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABEtjOG7xSOuSI0KOZoX1G/LwVh7ojur8XKX1MfurVXLBKas8QLvb/1Kl/9aCA/z+yS0q1CX4WaXH/cwqE7uvSa2jTTBLMAkGA1UdEwQCMAAwCwYDVR0PBAQDAgeAMBMGA1UdJQQMMAoGCCsGAQUFBwMBMBwGA1UdEQQVMBOCEXJlYWwuZXhhbXBsZS50ZXN0MAoGCCqGSM49BAMCA0gAMEUCIQCE502ArYd0FU7f3vjqs/04m5iSeXZS5wuHFpczxvDWsQIgDG7+IvCKeQlc3dRtR9ZjPlv43UtsnlKo+F5lpXdvN8o=";
    pub(super) const REAL_KEY_PK8_DER_B64: &str = "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgkJ2+UrnSh5TiKDh5ofQF6ZX4QgnrJ/YvYXO+quk00MWhRANCAARLYzhu8UjrkiNCjmaF9Rvy8FYe6I7q/Fyl9TH7q1VywSmrPEC72/9Spf/WggP8/sktKtQl+Fmlx/3MKhO7r0mt";
    const WRONG_CERT_DER_B64: &str = "MIIBijCCAS+gAwIBAgIUTyMjUJgXGib7TxfhDtaU2834S1QwCgYIKoZIzj0EAwIwGjEYMBYGA1UEAwwPTmVydXRvbiBUZXN0IENBMCAXDTIwMDEwMTAwMDAwMFoYDzIwOTkxMjMxMjM1OTU5WjAdMRswGQYDVQQDDBJmcm9udC5leGFtcGxlLnRlc3QwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAQUXMbJCTtayfiH5GE/lgF0kMH6eNYXBmjvXQJAXi6Mv4aWLN2sabcavnoFfZ7xo4zfY89FIRNK+H213HLnpDbeo04wTDAJBgNVHRMEAjAAMAsGA1UdDwQEAwIHgDATBgNVHSUEDDAKBggrBgEFBQcDATAdBgNVHREEFjAUghJmcm9udC5leGFtcGxlLnRlc3QwCgYIKoZIzj0EAwIDSQAwRgIhANCU4l6B7ZenC47rGPhJKNjfS37OHv7SL0WCWSZVT8aiAiEA03KRUFfA2Mv2k8DtkfEOW1PCoirCN5YfYrmoUXyVHdc=";
    const WRONG_KEY_PK8_DER_B64: &str = "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgoc++QPRj8V3vHcDZoL0458y2ju2OYv09/Llrh/xEEG2hRANCAAQUXMbJCTtayfiH5GE/lgF0kMH6eNYXBmjvXQJAXi6Mv4aWLN2sabcavnoFfZ7xo4zfY89FIRNK+H213HLnpDbe";

    fn test_roots() -> Arc<RootCertStore> {
        let mut roots = RootCertStore::empty();
        let ca_der = STANDARD.decode(CA_CERT_DER_B64).unwrap();
        roots.add(CertificateDer::from(ca_der)).unwrap();
        Arc::new(roots)
    }

    async fn spawn_tls_server(
        cert_b64: &str,
        key_b64: &str,
    ) -> (SocketAddr, tokio::sync::oneshot::Receiver<Option<String>>) {
        install_crypto_provider();
        let cert = CertificateDer::from(STANDARD.decode(cert_b64).unwrap());
        let key = PrivateKeyDer::try_from(STANDARD.decode(key_b64).unwrap()).unwrap();
        let server_cfg = ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![cert], key)
            .unwrap();
        let acceptor = TlsAcceptor::from(Arc::new(server_cfg));
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (tx, rx) = tokio::sync::oneshot::channel();
        tokio::spawn(async move {
            if let Ok((tcp, _)) = listener.accept().await {
                if let Ok(tls) = acceptor.accept(tcp).await {
                    let sni = tls.get_ref().1.server_name().map(ToOwned::to_owned);
                    let _ = tx.send(sni);
                    tokio::time::sleep(Duration::from_millis(50)).await;
                }
            }
        });
        (addr, rx)
    }

    #[derive(Default)]
    struct RecordingWriter {
        chunks: Vec<Vec<u8>>,
    }

    impl AsyncWrite for RecordingWriter {
        fn poll_write(
            mut self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            self.chunks.push(buf.to_vec());
            Poll::Ready(Ok(buf.len()))
        }

        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    #[tokio::test]
    async fn fragmenting_stream_splits_client_hello_then_passes_through() {
        // 1. Non-SNI handshake payload -> fallback fixed chunking (5 + 32*3 + 24) then passthrough
        let mut fake_client_hello = vec![0x16, 0x03, 0x01, 0x00, 120];
        fake_client_hello.extend(vec![0xAA; 120]);
        let app_data = vec![0x17, 0x03, 0x03, 0x00, 64];

        let mut frag =
            FragmentingStream::with_params(RecordingWriter::default(), 5, 32, Duration::ZERO);
        frag.write_all(&fake_client_hello).await.unwrap();
        frag.write_all(&app_data).await.unwrap();

        let rec = frag.into_inner();
        assert_eq!(rec.chunks.len(), 6);
        assert_eq!(rec.chunks[0].len(), 5);
        assert_eq!(rec.chunks[1].len(), 32);
        assert_eq!(rec.chunks[2].len(), 32);
        assert_eq!(rec.chunks[3].len(), 32);
        assert_eq!(rec.chunks[4].len(), 24);
        assert_eq!(rec.chunks[5], app_data);
        assert_eq!(rec.chunks[..5].concat(), fake_client_hello);

        // 2. Real ClientHello with SNI extension -> hostname itself is split across two chunks!
        let sni = b"neruton.moer.eu.org";
        let mut sni_ext = Vec::new();
        let list_len = (1 + 2 + sni.len()) as u16;
        sni_ext.extend_from_slice(&0x0000u16.to_be_bytes()); // ext_type = server_name
        sni_ext.extend_from_slice(&(2 + list_len).to_be_bytes());
        sni_ext.extend_from_slice(&list_len.to_be_bytes());
        sni_ext.push(0x00); // host_name
        sni_ext.extend_from_slice(&(sni.len() as u16).to_be_bytes());
        sni_ext.extend_from_slice(sni);

        let mut ch_body = Vec::new();
        ch_body.extend_from_slice(&[0x03, 0x03]); // legacy_version
        ch_body.extend_from_slice(&[0x11; 32]); // random
        ch_body.push(0); // session_id_len
        ch_body.extend_from_slice(&2u16.to_be_bytes());
        ch_body.extend_from_slice(&[0x13, 0x01]); // TLS_AES_128_GCM_SHA256
        ch_body.extend_from_slice(&[1, 0]); // compression
        ch_body.extend_from_slice(&(sni_ext.len() as u16).to_be_bytes());
        ch_body.extend_from_slice(&sni_ext);

        let mut hs = vec![0x01]; // ClientHello
        let hs_len = ch_body.len();
        hs.extend_from_slice(&[
            ((hs_len >> 16) & 0xFF) as u8,
            ((hs_len >> 8) & 0xFF) as u8,
            (hs_len & 0xFF) as u8,
        ]);
        hs.extend_from_slice(&ch_body);

        let mut record = vec![0x16, 0x03, 0x01];
        record.extend_from_slice(&(hs.len() as u16).to_be_bytes());
        record.extend_from_slice(&hs);

        let mut sni_frag = FragmentingStream::with_params(
            RecordingWriter::default(),
            5,
            32,
            Duration::from_millis(2),
        );
        sni_frag.write_all(&record).await.unwrap();
        sni_frag.write_all(&app_data).await.unwrap();
        let rec2 = sni_frag.into_inner();
        assert_eq!(rec2.chunks.len(), 4); // 3 ClientHello chunks + 1 passthrough app_data
        assert_eq!(rec2.chunks[..3].concat(), record);
        assert_eq!(rec2.chunks[3], app_data);
        for chunk in &rec2.chunks[..3] {
            assert!(
                !chunk.windows(sni.len()).any(|w| w == sni),
                "no single ClientHello TCP segment may contain the complete SNI hostname"
            );
        }
    }

    #[tokio::test]
    async fn custom_sni_sends_fake_sni_and_verifies_real_host_cert() {
        // Server presents cert for real.example.test
        let (addr, sni_rx) = spawn_tls_server(REAL_CERT_DER_B64, REAL_KEY_PK8_DER_B64).await;
        let opts = StealthTlsOptions {
            sni_mode: SniMode::Fragment,
            custom_sni: Some("front.example.test".to_string()),
            ech_config: None,
            no_tls_verify: false,
        };
        let connected =
            connect_stealth_tls_with_roots(addr, "real.example.test", &opts, None, test_roots())
                .await
                .expect("cert for real.example.test should verify even with custom SNI");
        assert!(connected.mode_label.contains("front.example.test"));
        assert_eq!(sni_rx.await.unwrap().as_deref(), Some("front.example.test"));

        // Server presents cert matching the CUSTOM SNI (front.example.test) instead of real host -> MUST FAIL!
        let (wrong_addr, _) = spawn_tls_server(WRONG_CERT_DER_B64, WRONG_KEY_PK8_DER_B64).await;
        let err = connect_stealth_tls_with_roots(
            wrong_addr,
            "real.example.test",
            &opts,
            None,
            test_roots(),
        )
        .await;
        assert!(
            err.is_err(),
            "verifier MUST reject cert matching fake SNI instead of real target host"
        );
    }

    #[tokio::test]
    async fn omitted_sni_omits_extension_and_verifies_real_host_cert() {
        let (addr, sni_rx) = spawn_tls_server(REAL_CERT_DER_B64, REAL_KEY_PK8_DER_B64).await;
        let opts = StealthTlsOptions {
            sni_mode: SniMode::None,
            custom_sni: None,
            ech_config: None,
            no_tls_verify: false,
        };
        let connected =
            connect_stealth_tls_with_roots(addr, "real.example.test", &opts, None, test_roots())
                .await
                .expect("cert for real.example.test should verify with omitted SNI");
        assert_eq!(connected.mode_label, "omitted SNI");
        assert_eq!(sni_rx.await.unwrap(), None);

        // Wrong host cert MUST still be rejected when SNI is omitted!
        let (wrong_addr, _) = spawn_tls_server(WRONG_CERT_DER_B64, WRONG_KEY_PK8_DER_B64).await;
        let err = connect_stealth_tls_with_roots(
            wrong_addr,
            "real.example.test",
            &opts,
            None,
            test_roots(),
        )
        .await;
        assert!(
            err.is_err(),
            "omitted SNI must still strictly verify real host certificate"
        );
    }

    #[test]
    fn sni_mode_planning_and_strict_ech_fail_fast() {
        assert_eq!("auto".parse::<SniMode>().unwrap(), SniMode::Auto);
        assert_eq!("ECH".parse::<SniMode>().unwrap(), SniMode::Ech);
        assert_eq!("fragment".parse::<SniMode>().unwrap(), SniMode::Fragment);
        assert_eq!("none".parse::<SniMode>().unwrap(), SniMode::None);
        assert_eq!("plain".parse::<SniMode>().unwrap(), SniMode::Plain);
        assert!("bogus".parse::<SniMode>().is_err());

        // Local target skips SNI hiding under auto
        let auto_opts = StealthTlsOptions::default();
        assert!(matches!(
            plan_tls_mode("localhost", &auto_opts, None).unwrap(),
            EffectiveTlsPlan::Plain { sni_override: None }
        ));
        assert!(matches!(
            plan_tls_mode("127.0.0.1", &auto_opts, None).unwrap(),
            EffectiveTlsPlan::Plain { sni_override: None }
        ));

        // Remote target under auto: ECH if available, else Fragment
        assert!(matches!(
            plan_tls_mode("neruton.moer.eu.org", &auto_opts, Some(&[1, 2, 3])).unwrap(),
            EffectiveTlsPlan::Ech {
                allow_fragment_fallback: true,
                ..
            }
        ));
        assert!(matches!(
            plan_tls_mode("neruton.moer.eu.org", &auto_opts, None).unwrap(),
            EffectiveTlsPlan::Fragment { sni_override: None }
        ));

        // Auto + explicit --sni -> custom SNI + Fragment
        let sni_opts = StealthTlsOptions {
            sni_mode: SniMode::Auto,
            custom_sni: Some("decoy.example.com".into()),
            ..Default::default()
        };
        assert!(matches!(
            plan_tls_mode("neruton.moer.eu.org", &sni_opts, Some(&[1, 2, 3])).unwrap(),
            EffectiveTlsPlan::Fragment { sni_override: Some(ref s) } if s == "decoy.example.com"
        ));

        // Strict ECH with no config fails fast with Fatal!
        let strict_ech = StealthTlsOptions {
            sni_mode: SniMode::Ech,
            ..Default::default()
        };
        assert!(matches!(
            plan_tls_mode("neruton.moer.eu.org", &strict_ech, None),
            Err(TlsConnectError::Fatal(_))
        ));
    }

    #[tokio::test]
    async fn fragmented_tls_handshake_succeeds_end_to_end() {
        let (addr, sni_rx) = spawn_tls_server(REAL_CERT_DER_B64, REAL_KEY_PK8_DER_B64).await;
        let opts = StealthTlsOptions {
            sni_mode: SniMode::Fragment,
            custom_sni: None,
            ech_config: None,
            no_tls_verify: false,
        };
        let connected =
            connect_stealth_tls_with_roots(addr, "real.example.test", &opts, None, test_roots())
                .await
                .expect("fragmented TLS 1.3 handshake should succeed");
        assert!(matches!(connected.stream, TunnelStream::FragmentedTls(_)));
        assert_eq!(connected.mode_label, "ClientHello fragment");
        assert_eq!(connected.ech_status, EchStatus::NotOffered);
        assert_eq!(sni_rx.await.unwrap().as_deref(), Some("real.example.test"));
    }

    #[test]
    fn ech_rejection_retry_config_extraction_roundtrips() {
        use rustls::internal::msgs::base::PayloadU16;
        use rustls::internal::msgs::enums::{HpkeAead, HpkeKdf, HpkeKem};
        use rustls::internal::msgs::handshake::{
            EchConfigContents, HpkeKeyConfig, HpkeSymmetricCipherSuite,
        };
        use rustls::pki_types::DnsName;

        let retry_payload = EchConfigPayload::V18(EchConfigContents {
            key_config: HpkeKeyConfig {
                config_id: 7,
                kem_id: HpkeKem::DHKEM_X25519_HKDF_SHA256,
                public_key: PayloadU16::new(vec![0x42; 32]),
                symmetric_cipher_suites: vec![HpkeSymmetricCipherSuite {
                    kdf_id: HpkeKdf::HKDF_SHA256,
                    aead_id: HpkeAead::AES_128_GCM,
                }],
            },
            maximum_name_length: 64,
            public_name: DnsName::try_from("cloudflare-ech.com").unwrap(),
            extensions: vec![],
        });

        let rustls_err = Error::PeerIncompatible(
            PeerIncompatible::ServerRejectedEncryptedClientHello(Some(vec![retry_payload])),
        );
        let io_err = io::Error::new(io::ErrorKind::InvalidData, rustls_err);
        let extracted = extract_ech_rejection(&io_err)
            .expect("should detect ECH rejection")
            .expect("should carry retry_configs");
        let encoded = encode_ech_config_list(&extracted);
        assert_eq!(
            select_ech_public_name(&encoded).as_deref(),
            Some("cloudflare-ech.com")
        );
        assert!(EchConfig::new(
            EchConfigListBytes::from(encoded.as_slice()),
            ALL_SUPPORTED_SUITES
        )
        .is_ok());
    }
}
