//! DNS-over-HTTPS (RFC 8484) resolver with RFC 1035 wire codec & RFC 9460 HTTPS/ECH parsing.
//!
//! Uses IP-based DoH endpoints by default to avoid bootstrap plaintext DNS leaks, racing the
//! first two endpoints with a short timeout and falling back across remaining endpoints.

use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, bail, Context, Result};
use bytes::Bytes;
use http::{header, Method, Request, StatusCode};
use http_body_util::{BodyExt, Full};
use hyper_util::rt::{TokioExecutor, TokioIo};
use rustls::pki_types::ServerName;
use rustls::ClientConfig;
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use tracing::debug;
use url::Url;

use crate::tls::build_doh_rustls_config;
use crate::ui;

/// Default IP-based RFC 8484 DoH endpoints (zero bootstrap DNS leak).
///
/// The first two (`1.0.0.1` global Cloudflare & `223.5.5.5` AliDNS) are raced in parallel so
/// resolution is fast both inside China and globally; remaining endpoints serve as fallbacks.
pub const DEFAULT_DOH_ENDPOINTS: &[&str] = &[
    "https://1.0.0.1/dns-query",
    "https://223.5.5.5/dns-query",
    "https://1.1.1.1/dns-query",
    "https://8.8.4.4/dns-query",
];

const DOH_REQUEST_TIMEOUT: Duration = Duration::from_secs(3);
const MAX_DOH_RESPONSE_BYTES: usize = 64 * 1024;

pub const QTYPE_A: u16 = 1;
pub const QTYPE_AAAA: u16 = 28;
pub const QTYPE_HTTPS: u16 = 65;

const QCLASS_IN: u16 = 1;
const SVCPARAM_IPV4HINT: u16 = 4;
const SVCPARAM_ECH: u16 = 5;
const SVCPARAM_IPV6HINT: u16 = 6;

/// Configured DoH behavior.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum DohConfig {
    /// Default: use IP-based DoH endpoints; warn and fall back to system DNS if all fail.
    #[default]
    Auto,
    /// Strict DoH only: fail if all DoH endpoints are unreachable or yield no addresses.
    Strict,
    /// Disabled (`--no-doh`): use system DNS directly.
    Off,
    /// Custom comma-separated DoH endpoint URL(s).
    Custom(Vec<String>),
}

impl DohConfig {
    pub fn parse(raw: &str) -> Result<Self> {
        let trimmed = raw.trim();
        if trimmed.is_empty() || trimmed.eq_ignore_ascii_case("auto") {
            return Ok(Self::Auto);
        }
        if trimmed.eq_ignore_ascii_case("strict") {
            return Ok(Self::Strict);
        }
        if trimmed.eq_ignore_ascii_case("off")
            || trimmed.eq_ignore_ascii_case("false")
            || trimmed.eq_ignore_ascii_case("none")
            || trimmed.eq_ignore_ascii_case("disabled")
        {
            return Ok(Self::Off);
        }

        let urls: Vec<String> = trimmed
            .split(',')
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(ToOwned::to_owned)
            .collect();

        if urls.is_empty() {
            bail!("invalid --doh value '{raw}': expected 'auto', 'strict', 'off', or comma-separated https:// URL(s)");
        }

        for u in &urls {
            let parsed =
                Url::parse(u).with_context(|| format!("invalid DoH endpoint URL '{u}'"))?;
            match parsed.scheme() {
                "https" => {}
                "http" if is_loopback_host(parsed.host_str().unwrap_or("")) => {}
                other => {
                    bail!("unsupported DoH URL scheme '{other}' in '{u}' (expected https://)");
                }
            }
            if parsed.host_str().is_none() {
                bail!("DoH endpoint URL '{u}' is missing a host");
            }
        }

        Ok(Self::Custom(urls))
    }

    pub fn display_value(&self) -> String {
        match self {
            Self::Auto => "auto".to_string(),
            Self::Strict => "strict".to_string(),
            Self::Off => "off".to_string(),
            Self::Custom(urls) => urls.join(","),
        }
    }
}

impl FromStr for DohConfig {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self> {
        Self::parse(s)
    }
}

impl fmt::Display for DohConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.display_value())
    }
}

/// Where a resolved address list came from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResolutionSource {
    IpLiteral,
    LocalSystemDns,
    SystemDns,
    SystemDnsFallback,
    Doh(String),
}

impl ResolutionSource {
    pub fn short_label(&self) -> &'static str {
        match self {
            Self::IpLiteral => "direct IP",
            Self::LocalSystemDns | Self::SystemDns => "system DNS",
            Self::SystemDnsFallback => "system DNS (DoH fallback)",
            Self::Doh(_) => "DoH",
        }
    }
}

/// Resolution result for a remote host:port.
#[derive(Debug, Clone)]
pub struct ResolvedHost {
    pub addrs: Vec<SocketAddr>,
    pub ech_config_list: Option<Vec<u8>>,
    pub source: ResolutionSource,
}

/// Returns true if `host` is an IPv4/IPv6 literal, `localhost`, `*.localhost`, or `*.local`.
pub fn should_skip_doh(host: &str) -> bool {
    let clean = strip_ipv6_brackets(host.trim()).trim_end_matches('.');
    if clean.is_empty() {
        return true;
    }
    if clean.parse::<IpAddr>().is_ok() {
        return true;
    }
    let lower = clean.to_ascii_lowercase();
    lower == "localhost" || lower.ends_with(".localhost") || lower.ends_with(".local")
}

fn is_loopback_host(host: &str) -> bool {
    let clean = strip_ipv6_brackets(host.trim()).trim_end_matches('.');
    if let Ok(ip) = clean.parse::<IpAddr>() {
        return ip.is_loopback();
    }
    clean.eq_ignore_ascii_case("localhost")
}

pub fn strip_ipv6_brackets(host: &str) -> &str {
    host.strip_prefix('[')
        .and_then(|s| s.strip_suffix(']'))
        .unwrap_or(host)
}

/// Resolve `host:port` using the configured DoH policy (with default WebPKI roots).
pub async fn resolve_host(config: &DohConfig, host: &str, port: u16) -> Result<ResolvedHost> {
    let tls_cfg = build_doh_rustls_config();
    resolve_host_with_tls(config, host, port, tls_cfg, DOH_REQUEST_TIMEOUT).await
}

/// Resolve `host:port` using an explicit `ClientConfig` and per-endpoint timeout (used in tests too).
pub async fn resolve_host_with_tls(
    config: &DohConfig,
    host: &str,
    port: u16,
    tls_cfg: Arc<ClientConfig>,
    timeout: Duration,
) -> Result<ResolvedHost> {
    let default_endpoints: Vec<String> = DEFAULT_DOH_ENDPOINTS
        .iter()
        .map(|s| (*s).to_string())
        .collect();
    resolve_host_with_endpoints(config, &default_endpoints, host, port, tls_cfg, timeout).await
}

async fn resolve_host_with_endpoints(
    config: &DohConfig,
    default_endpoints: &[String],
    host: &str,
    port: u16,
    tls_cfg: Arc<ClientConfig>,
    timeout: Duration,
) -> Result<ResolvedHost> {
    let clean_host = strip_ipv6_brackets(host.trim());
    if let Ok(ip) = clean_host.parse::<IpAddr>() {
        return Ok(ResolvedHost {
            addrs: vec![SocketAddr::new(ip, port)],
            ech_config_list: None,
            source: ResolutionSource::IpLiteral,
        });
    }

    if should_skip_doh(clean_host) {
        let addrs = resolve_system_dns(clean_host, port).await?;
        return Ok(ResolvedHost {
            addrs,
            ech_config_list: None,
            source: ResolutionSource::LocalSystemDns,
        });
    }

    match config {
        DohConfig::Off => {
            let addrs = resolve_system_dns(clean_host, port).await?;
            Ok(ResolvedHost {
                addrs,
                ech_config_list: None,
                source: ResolutionSource::SystemDns,
            })
        }
        DohConfig::Auto => {
            match query_endpoints_raced(default_endpoints, clean_host, port, tls_cfg, timeout).await
            {
                Ok(resolved) => Ok(resolved),
                Err(err) => {
                    ui::log_warn(&format!(
                        "DoH lookup failed for '{clean_host}' ({err}); falling back to system DNS."
                    ));
                    let addrs = resolve_system_dns(clean_host, port).await?;
                    Ok(ResolvedHost {
                        addrs,
                        ech_config_list: None,
                        source: ResolutionSource::SystemDnsFallback,
                    })
                }
            }
        }
        DohConfig::Strict => {
            query_endpoints_raced(default_endpoints, clean_host, port, tls_cfg, timeout)
                .await
                .with_context(|| format!("strict DoH lookup failed for '{clean_host}'"))
        }
        DohConfig::Custom(endpoints) => {
            query_endpoints_raced(endpoints, clean_host, port, tls_cfg, timeout)
                .await
                .with_context(|| format!("custom DoH lookup failed for '{clean_host}'"))
        }
    }
}

async fn resolve_system_dns(host: &str, port: u16) -> Result<Vec<SocketAddr>> {
    let mut v4 = Vec::new();
    let mut v6 = Vec::new();
    for addr in tokio::net::lookup_host((host, port))
        .await
        .with_context(|| format!("system DNS lookup failed for '{host}:{port}'"))?
    {
        if addr.is_ipv4() {
            if !v4.contains(&addr) {
                v4.push(addr);
            }
        } else if !v6.contains(&addr) {
            v6.push(addr);
        }
    }
    v4.extend(v6);
    if v4.is_empty() {
        bail!("system DNS returned no addresses for '{host}'");
    }
    Ok(v4)
}

/// Race the first two DoH endpoints concurrently; if both fail, sequentially fall back across the rest.
async fn query_endpoints_raced(
    endpoints: &[String],
    host: &str,
    port: u16,
    tls_cfg: Arc<ClientConfig>,
    timeout: Duration,
) -> Result<ResolvedHost> {
    if endpoints.is_empty() {
        bail!("no DoH endpoints configured");
    }

    let mut errors: Vec<String> = Vec::new();

    if endpoints.len() == 1 {
        return query_host_on_endpoint(&endpoints[0], host, port, tls_cfg, timeout).await;
    }

    // Race endpoints[0] and endpoints[1] concurrently.
    let ep0 = endpoints[0].clone();
    let ep1 = endpoints[1].clone();
    let mut f0 = Box::pin(query_host_on_endpoint(
        &ep0,
        host,
        port,
        tls_cfg.clone(),
        timeout,
    ));
    let mut f1 = Box::pin(query_host_on_endpoint(
        &ep1,
        host,
        port,
        tls_cfg.clone(),
        timeout,
    ));

    let first_winner = tokio::select! {
        r0 = &mut f0 => match r0 {
            Ok(res) => Some(res),
            Err(e0) => {
                debug!("DoH endpoint {ep0} failed: {e0}");
                errors.push(format!("{ep0}: {e0}"));
                match f1.await {
                    Ok(res) => Some(res),
                    Err(e1) => {
                        debug!("DoH endpoint {ep1} failed: {e1}");
                        errors.push(format!("{ep1}: {e1}"));
                        None
                    }
                }
            }
        },
        r1 = &mut f1 => match r1 {
            Ok(res) => Some(res),
            Err(e1) => {
                debug!("DoH endpoint {ep1} failed: {e1}");
                errors.push(format!("{ep1}: {e1}"));
                match f0.await {
                    Ok(res) => Some(res),
                    Err(e0) => {
                        debug!("DoH endpoint {ep0} failed: {e0}");
                        errors.push(format!("{ep0}: {e0}"));
                        None
                    }
                }
            }
        },
    };

    if let Some(resolved) = first_winner {
        return Ok(resolved);
    }

    // Fall back across remaining endpoints in order.
    for ep in &endpoints[2..] {
        match query_host_on_endpoint(ep, host, port, tls_cfg.clone(), timeout).await {
            Ok(res) => return Ok(res),
            Err(e) => {
                debug!("DoH fallback endpoint {ep} failed: {e}");
                errors.push(format!("{ep}: {e}"));
            }
        }
    }

    bail!("all DoH endpoints failed: {}", errors.join("; "))
}

/// Query A (1), AAAA (28), and HTTPS (65) records in parallel against one RFC 8484 endpoint.
async fn query_host_on_endpoint(
    endpoint: &str,
    host: &str,
    port: u16,
    tls_cfg: Arc<ClientConfig>,
    timeout: Duration,
) -> Result<ResolvedHost> {
    let q_a = build_dns_query(host, QTYPE_A)?;
    let q_aaaa = build_dns_query(host, QTYPE_AAAA)?;
    let q_https = build_dns_query(host, QTYPE_HTTPS)?;

    let (res_a, res_aaaa, res_https) = tokio::join!(
        doh_post_wire(endpoint, q_a, tls_cfg.clone(), timeout),
        doh_post_wire(endpoint, q_aaaa, tls_cfg.clone(), timeout),
        doh_post_wire(endpoint, q_https, tls_cfg, timeout),
    );

    let mut ipv4s: Vec<Ipv4Addr> = Vec::new();
    let mut ipv6s: Vec<Ipv6Addr> = Vec::new();
    let mut hint_v4s: Vec<Ipv4Addr> = Vec::new();
    let mut hint_v6s: Vec<Ipv6Addr> = Vec::new();
    let mut ech_config_list: Option<Vec<u8>> = None;
    let mut any_ok = false;
    let mut first_err: Option<anyhow::Error> = None;

    match res_a {
        Ok(bytes) => match parse_dns_response(&bytes) {
            Ok(parsed) => {
                any_ok = true;
                ipv4s.extend(parsed.a_records);
            }
            Err(e) => {
                debug!("DoH A parse error from {endpoint}: {e}");
                if first_err.is_none() {
                    first_err = Some(e);
                }
            }
        },
        Err(e) => {
            if first_err.is_none() {
                first_err = Some(e);
            }
        }
    }

    match res_aaaa {
        Ok(bytes) => match parse_dns_response(&bytes) {
            Ok(parsed) => {
                any_ok = true;
                ipv6s.extend(parsed.aaaa_records);
            }
            Err(e) => {
                debug!("DoH AAAA parse error from {endpoint}: {e}");
                if first_err.is_none() {
                    first_err = Some(e);
                }
            }
        },
        Err(e) => {
            if first_err.is_none() {
                first_err = Some(e);
            }
        }
    }

    match res_https {
        Ok(bytes) => match parse_dns_response(&bytes) {
            Ok(mut parsed) => {
                any_ok = true;
                parsed.https_records.sort_by_key(|r| r.priority);
                for rec in parsed.https_records {
                    if rec.priority == 0 {
                        continue; // AliasMode
                    }
                    if ech_config_list.is_none() {
                        if let Some(ech) = rec.ech_config_list {
                            if !ech.is_empty() {
                                ech_config_list = Some(ech);
                            }
                        }
                    }
                    hint_v4s.extend(rec.ipv4_hints);
                    hint_v6s.extend(rec.ipv6_hints);
                }
            }
            Err(e) => {
                debug!("DoH HTTPS(65) parse error from {endpoint}: {e}");
            }
        },
        Err(e) => {
            debug!("DoH HTTPS(65) request error from {endpoint}: {e}");
        }
    }

    // Order IPv4 first (A records, then ipv4hints), then IPv6 (AAAA records, then ipv6hints), deduplicated.
    let mut addrs: Vec<SocketAddr> = Vec::new();
    for ip in ipv4s.into_iter().chain(hint_v4s) {
        let sa = SocketAddr::new(IpAddr::V4(ip), port);
        if !addrs.contains(&sa) {
            addrs.push(sa);
        }
    }
    for ip in ipv6s.into_iter().chain(hint_v6s) {
        let sa = SocketAddr::new(IpAddr::V6(ip), port);
        if !addrs.contains(&sa) {
            addrs.push(sa);
        }
    }

    if addrs.is_empty() {
        if let Some(err) = first_err {
            return Err(err);
        }
        if !any_ok {
            bail!("DoH queries failed on {endpoint}");
        }
        bail!("no A/AAAA addresses returned by {endpoint} for '{host}'");
    }

    Ok(ResolvedHost {
        addrs,
        ech_config_list,
        source: ResolutionSource::Doh(endpoint.to_string()),
    })
}

/// Perform a single RFC 8484 binary POST (`application/dns-message`) request with timeout.
async fn doh_post_wire(
    endpoint: &str,
    query_wire: Vec<u8>,
    tls_cfg: Arc<ClientConfig>,
    timeout: Duration,
) -> Result<Vec<u8>> {
    tokio::time::timeout(timeout, doh_post_wire_inner(endpoint, query_wire, tls_cfg))
        .await
        .map_err(|_| anyhow!("timed out after {}ms", timeout.as_millis()))?
}

async fn doh_post_wire_inner(
    endpoint: &str,
    query_wire: Vec<u8>,
    tls_cfg: Arc<ClientConfig>,
) -> Result<Vec<u8>> {
    let url = Url::parse(endpoint).with_context(|| format!("invalid DoH URL '{endpoint}'"))?;
    let is_https = match url.scheme() {
        "https" => true,
        "http" => false,
        s => bail!("unsupported DoH scheme '{s}'"),
    };
    let host_raw = url
        .host_str()
        .ok_or_else(|| anyhow!("DoH URL missing host"))?;
    let host = strip_ipv6_brackets(host_raw);
    let port = url
        .port_or_known_default()
        .unwrap_or(if is_https { 443 } else { 80 });

    // Connect directly to IP literal if host is an IP (zero bootstrap DNS leak!).
    let tcp = if let Ok(ip) = host.parse::<IpAddr>() {
        TcpStream::connect(SocketAddr::new(ip, port)).await?
    } else {
        TcpStream::connect((host, port)).await?
    };
    let _ = tcp.set_nodelay(true);

    let path_and_query = match url.query() {
        Some(q) => format!("{}?{q}", url.path()),
        None => url.path().to_string(),
    };
    let host_header = match url.port() {
        Some(p) => format!("{host_raw}:{p}"),
        None => host_raw.to_string(),
    };

    let build_req = |is_h2: bool| -> Result<Request<Full<Bytes>>> {
        let mut builder = Request::builder().method(Method::POST);
        if is_h2 {
            // RFC 9113 §8.3.1: HTTP/2 requests MUST include :scheme and :authority (derived from
            // absolute URI by hyper/h2) and MUST NOT send a redundant Host header.
            builder = builder.uri(url.as_str());
        } else {
            builder = builder
                .uri(path_and_query.as_str())
                .header(header::HOST, host_header.as_str());
        }
        builder
            .header(header::CONTENT_TYPE, "application/dns-message")
            .header(header::ACCEPT, "application/dns-message")
            .header(header::CONTENT_LENGTH, query_wire.len())
            .body(Full::new(Bytes::from(query_wire)))
            .context("failed to build DoH HTTP request")
    };

    let resp = if is_https {
        let connector = TlsConnector::from(tls_cfg);
        let server_name = ServerName::try_from(host.to_string())
            .map_err(|_| anyhow!("invalid TLS server name '{host}' for DoH endpoint"))?;
        let tls_stream = connector.connect(server_name, tcp).await?;
        let is_h2 = tls_stream
            .get_ref()
            .1
            .alpn_protocol()
            .is_some_and(|p| p == b"h2");

        let req = build_req(is_h2)?;

        if is_h2 {
            let (mut sender, conn) = hyper::client::conn::http2::handshake(
                TokioExecutor::new(),
                TokioIo::new(tls_stream),
            )
            .await?;
            tokio::spawn(async move {
                let _ = conn.await;
            });
            sender.send_request(req).await?
        } else {
            let (mut sender, conn) =
                hyper::client::conn::http1::handshake(TokioIo::new(tls_stream)).await?;
            tokio::spawn(async move {
                let _ = conn.await;
            });
            sender.send_request(req).await?
        }
    } else {
        let req = build_req(false)?;
        let (mut sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(tcp)).await?;
        tokio::spawn(async move {
            let _ = conn.await;
        });
        sender.send_request(req).await?
    };

    if resp.status() != StatusCode::OK {
        bail!("HTTP {}", resp.status().as_u16());
    }

    let mut body = resp.into_body();
    let mut out = Vec::new();
    while let Some(frame_res) = body.frame().await {
        let frame = frame_res?;
        if let Some(chunk) = frame.data_ref() {
            if out.len() + chunk.len() > MAX_DOH_RESPONSE_BYTES {
                bail!("DoH response exceeds {} bytes", MAX_DOH_RESPONSE_BYTES);
            }
            out.extend_from_slice(chunk);
        }
    }
    Ok(out)
}

// ---------------------------------------------------------------------------
// RFC 1035 DNS Wire Codec + RFC 9460 HTTPS (Type 65) SvcParam Parser
// ---------------------------------------------------------------------------

/// Parsed RFC 9460 HTTPS (Type 65) resource record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpsRecord {
    pub priority: u16,
    pub target_name: String,
    pub ech_config_list: Option<Vec<u8>>,
    pub ipv4_hints: Vec<Ipv4Addr>,
    pub ipv6_hints: Vec<Ipv6Addr>,
}

/// Parsed subset of an RFC 1035 DNS response packet.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DnsResponse {
    pub rcode: u8,
    pub a_records: Vec<Ipv4Addr>,
    pub aaaa_records: Vec<Ipv6Addr>,
    pub https_records: Vec<HttpsRecord>,
}

/// Encode an RFC 1035 standard recursive DNS query (`ID = 0` per RFC 8484 §4.1).
pub fn build_dns_query(domain: &str, qtype: u16) -> Result<Vec<u8>> {
    let trimmed = domain.trim().trim_end_matches('.');
    if trimmed.is_empty() {
        bail!("cannot build DNS query for empty domain");
    }

    let mut buf = Vec::with_capacity(12 + trimmed.len() + 6);
    // Header: ID=0, Flags=0x0100 (RD=1), QDCOUNT=1, ANCOUNT=0, NSCOUNT=0, ARCOUNT=0
    buf.extend_from_slice(&[
        0x00, 0x00, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ]);

    let qname_start = buf.len();
    for label in trimmed.split('.') {
        if label.is_empty() || label.len() > 63 {
            bail!("invalid DNS label '{label}' in '{domain}'");
        }
        buf.push(label.len() as u8);
        buf.extend_from_slice(label.as_bytes());
    }
    buf.push(0x00); // root label
    if buf.len() - qname_start > 255 {
        bail!("DNS QNAME exceeds 255 bytes for '{domain}'");
    }

    buf.extend_from_slice(&qtype.to_be_bytes());
    buf.extend_from_slice(&QCLASS_IN.to_be_bytes());
    Ok(buf)
}

/// Decode an RFC 1035 DNS wire response, extracting `A`, `AAAA`, and `HTTPS` (RFC 9460) records.
pub fn parse_dns_response(packet: &[u8]) -> Result<DnsResponse> {
    if packet.len() < 12 {
        bail!("DNS response truncated ({} bytes)", packet.len());
    }

    let flags = u16::from_be_bytes([packet[2], packet[3]]);
    if (flags & 0x8000) == 0 {
        bail!("DNS packet does not have QR response bit set");
    }
    let rcode = (flags & 0x000F) as u8;
    let qdcount = u16::from_be_bytes([packet[4], packet[5]]) as usize;
    let ancount = u16::from_be_bytes([packet[6], packet[7]]) as usize;

    let mut pos = 12usize;

    // Skip question section.
    for _ in 0..qdcount {
        pos = skip_dns_name(packet, pos)?;
        if pos + 4 > packet.len() {
            bail!("truncated DNS question");
        }
        pos += 4; // QTYPE + QCLASS
    }

    let mut resp = DnsResponse {
        rcode,
        ..Default::default()
    };

    if rcode != 0 {
        return Ok(resp);
    }

    // Parse answer records.
    for _ in 0..ancount {
        pos = skip_dns_name(packet, pos)?;
        if pos + 10 > packet.len() {
            bail!("truncated DNS answer header");
        }
        let rtype = u16::from_be_bytes([packet[pos], packet[pos + 1]]);
        let rclass = u16::from_be_bytes([packet[pos + 2], packet[pos + 3]]);
        let rdlength = u16::from_be_bytes([packet[pos + 8], packet[pos + 9]]) as usize;
        pos += 10;

        if pos + rdlength > packet.len() {
            bail!("truncated DNS answer RDATA");
        }
        let rdata = &packet[pos..pos + rdlength];
        pos += rdlength;

        if rclass != QCLASS_IN {
            continue;
        }

        match rtype {
            QTYPE_A if rdata.len() == 4 => {
                resp.a_records
                    .push(Ipv4Addr::new(rdata[0], rdata[1], rdata[2], rdata[3]));
            }
            QTYPE_AAAA if rdata.len() == 16 => {
                let octets: [u8; 16] = rdata.try_into().expect("checked 16 bytes");
                resp.aaaa_records.push(Ipv6Addr::from(octets));
            }
            QTYPE_HTTPS => {
                if let Ok(rec) = parse_https_rdata(rdata) {
                    resp.https_records.push(rec);
                }
            }
            _ => {}
        }
    }

    Ok(resp)
}

fn skip_dns_name(packet: &[u8], start: usize) -> Result<usize> {
    let mut pos = start;
    let mut jumps = 0u8;
    let mut end_pos: Option<usize> = None;

    loop {
        if pos >= packet.len() {
            bail!("DNS name exceeds packet bounds");
        }
        let len = packet[pos];
        if len == 0 {
            return Ok(end_pos.unwrap_or(pos + 1));
        }
        if (len & 0xC0) == 0xC0 {
            if pos + 1 >= packet.len() {
                bail!("truncated DNS compression pointer");
            }
            let ptr = (((len & 0x3F) as usize) << 8) | (packet[pos + 1] as usize);
            if ptr >= packet.len() {
                bail!("out-of-bounds DNS compression pointer");
            }
            if end_pos.is_none() {
                end_pos = Some(pos + 2);
            }
            jumps += 1;
            if jumps > 16 {
                bail!("DNS compression pointer loop detected");
            }
            pos = ptr;
        } else if (len & 0xC0) != 0 {
            bail!("invalid DNS label tag 0x{len:02x}");
        } else {
            let next = pos + 1 + (len as usize);
            if next > packet.len() {
                bail!("DNS label extends past packet");
            }
            pos = next;
        }
    }
}

/// Parse RFC 9460 `HTTPS` (Type 65) RDATA: SvcPriority(2) + TargetName(uncompressed wire) + SvcParams*.
fn parse_https_rdata(rdata: &[u8]) -> Result<HttpsRecord> {
    if rdata.len() < 3 {
        bail!("HTTPS RDATA too short");
    }
    let priority = u16::from_be_bytes([rdata[0], rdata[1]]);
    let mut pos = 2usize;

    // RFC 9460 §2.2: TargetName MUST be uncompressed wire format.
    let mut labels = Vec::new();
    loop {
        if pos >= rdata.len() {
            bail!("truncated HTTPS TargetName");
        }
        let len = rdata[pos];
        pos += 1;
        if len == 0 {
            break;
        }
        if (len & 0xC0) != 0 {
            bail!("unexpected compression pointer in HTTPS TargetName");
        }
        let end = pos + (len as usize);
        if end > rdata.len() {
            bail!("HTTPS TargetName label exceeds RDATA");
        }
        labels.push(String::from_utf8_lossy(&rdata[pos..end]).into_owned());
        pos = end;
    }
    let target_name = if labels.is_empty() {
        ".".to_string()
    } else {
        labels.join(".")
    };

    let mut ech_config_list = None;
    let mut ipv4_hints = Vec::new();
    let mut ipv6_hints = Vec::new();

    if priority > 0 {
        while pos < rdata.len() {
            if pos + 4 > rdata.len() {
                bail!("truncated HTTPS SvcParam header");
            }
            let key = u16::from_be_bytes([rdata[pos], rdata[pos + 1]]);
            let val_len = u16::from_be_bytes([rdata[pos + 2], rdata[pos + 3]]) as usize;
            pos += 4;
            if pos + val_len > rdata.len() {
                bail!("truncated HTTPS SvcParam value");
            }
            let val = &rdata[pos..pos + val_len];
            pos += val_len;

            match key {
                SVCPARAM_ECH if !val.is_empty() => {
                    ech_config_list = Some(val.to_vec());
                }
                SVCPARAM_IPV4HINT if val.chunks_exact(4).remainder().is_empty() => {
                    for chunk in val.chunks_exact(4) {
                        ipv4_hints.push(Ipv4Addr::new(chunk[0], chunk[1], chunk[2], chunk[3]));
                    }
                }
                SVCPARAM_IPV6HINT if val.chunks_exact(16).remainder().is_empty() => {
                    for chunk in val.chunks_exact(16) {
                        let octets: [u8; 16] = chunk.try_into().expect("16 bytes");
                        ipv6_hints.push(Ipv6Addr::from(octets));
                    }
                }
                _ => {}
            }
        }
    }

    Ok(HttpsRecord {
        priority,
        target_name,
        ech_config_list,
        ipv4_hints,
        ipv6_hints,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Bytes as AxumBytes;
    use axum::http::StatusCode as AxumStatus;
    use axum::routing::post;
    use axum::Router;
    use tokio::net::TcpListener;

    fn build_mock_dns_response(query: &[u8], answers: &[(&[u8], u16, &[u8])]) -> Vec<u8> {
        let mut resp = Vec::new();
        // Copy ID, set QR=1 RD=1 RA=1 (0x8180)
        resp.extend_from_slice(&query[0..2]);
        resp.extend_from_slice(&[0x81, 0x80]);
        resp.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT=1
        resp.extend_from_slice(&(answers.len() as u16).to_be_bytes()); // ANCOUNT
        resp.extend_from_slice(&0u16.to_be_bytes()); // NSCOUNT
        resp.extend_from_slice(&0u16.to_be_bytes()); // ARCOUNT
                                                     // Copy original question verbatim
        resp.extend_from_slice(&query[12..]);

        for &(name_wire, rtype, rdata) in answers {
            resp.extend_from_slice(name_wire);
            resp.extend_from_slice(&rtype.to_be_bytes());
            resp.extend_from_slice(&QCLASS_IN.to_be_bytes());
            resp.extend_from_slice(&300u32.to_be_bytes()); // TTL
            resp.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
            resp.extend_from_slice(rdata);
        }
        resp
    }

    fn extract_query_qtype(query: &[u8]) -> u16 {
        let qend = skip_dns_name(query, 12).unwrap();
        u16::from_be_bytes([query[qend], query[qend + 1]])
    }

    #[test]
    fn skip_doh_rules() {
        assert!(should_skip_doh("localhost"));
        assert!(should_skip_doh("LOCALHOST."));
        assert!(should_skip_doh("api.localhost"));
        assert!(should_skip_doh("mybox.local"));
        assert!(should_skip_doh("127.0.0.1"));
        assert!(should_skip_doh("104.21.2.247"));
        assert!(should_skip_doh("::1"));
        assert!(should_skip_doh("[2606:4700::1]"));

        assert!(!should_skip_doh("neruton.moer.eu.org"));
        assert!(!should_skip_doh("local.example.com"));
        assert!(!should_skip_doh("localhost.example.com"));
    }

    #[test]
    fn doh_config_parsing() {
        assert_eq!(DohConfig::parse("auto").unwrap(), DohConfig::Auto);
        assert_eq!(DohConfig::parse("").unwrap(), DohConfig::Auto);
        assert_eq!(DohConfig::parse("strict").unwrap(), DohConfig::Strict);
        assert_eq!(DohConfig::parse("off").unwrap(), DohConfig::Off);
        assert_eq!(DohConfig::parse("false").unwrap(), DohConfig::Off);
        assert_eq!(
            DohConfig::parse("https://1.0.0.1/dns-query, https://8.8.4.4/dns-query").unwrap(),
            DohConfig::Custom(vec![
                "https://1.0.0.1/dns-query".to_string(),
                "https://8.8.4.4/dns-query".to_string(),
            ])
        );
        assert!(DohConfig::parse("ftp://1.0.0.1/dns-query").is_err());
        assert!(DohConfig::parse("http://1.0.0.1/dns-query").is_err());
        assert!(DohConfig::parse("not-a-url").is_err());
    }

    #[test]
    fn dns_wire_codec_and_https_ech_svcparams() {
        let q = build_dns_query("neruton.moer.eu.org", QTYPE_HTTPS).unwrap();
        assert_eq!(&q[0..2], &[0x00, 0x00]); // ID=0 per RFC 8484
        assert_eq!(extract_query_qtype(&q), QTYPE_HTTPS);

        // Build HTTPS RDATA: priority=1, target=".", alpn="h2", ipv4hint=[104.21.2.247], ech=[0xfe,0x0d,...], ipv6hint=[2606:4700::1]
        let fake_ech = vec![0x00, 0x05, 0xfe, 0x0d, 0x00, 0x01, 0x42];
        let mut rdata = Vec::new();
        rdata.extend_from_slice(&1u16.to_be_bytes()); // priority
        rdata.push(0x00); // target = "."
                          // SvcParam key 1 (alpn): "h2"
        rdata.extend_from_slice(&1u16.to_be_bytes());
        rdata.extend_from_slice(&3u16.to_be_bytes());
        rdata.extend_from_slice(&[2, b'h', b'2']);
        // SvcParam key 4 (ipv4hint)
        rdata.extend_from_slice(&4u16.to_be_bytes());
        rdata.extend_from_slice(&4u16.to_be_bytes());
        rdata.extend_from_slice(&[104, 21, 2, 247]);
        // SvcParam key 5 (ech)
        rdata.extend_from_slice(&5u16.to_be_bytes());
        rdata.extend_from_slice(&(fake_ech.len() as u16).to_be_bytes());
        rdata.extend_from_slice(&fake_ech);
        // SvcParam key 6 (ipv6hint)
        let v6: Ipv6Addr = "2606:4700:3032::6815:2f7".parse().unwrap();
        rdata.extend_from_slice(&6u16.to_be_bytes());
        rdata.extend_from_slice(&16u16.to_be_bytes());
        rdata.extend_from_slice(&v6.octets());

        // Name compression pointer to offset 12 (0xC0 0x0C)
        let resp_wire = build_mock_dns_response(
            &q,
            &[
                (&[0xC0, 0x0C], QTYPE_A, &[104, 21, 2, 247]),
                (&[0xC0, 0x0C], QTYPE_AAAA, &v6.octets()),
                (&[0xC0, 0x0C], QTYPE_HTTPS, &rdata),
            ],
        );

        let parsed = parse_dns_response(&resp_wire).unwrap();
        assert_eq!(parsed.rcode, 0);
        assert_eq!(parsed.a_records, vec![Ipv4Addr::new(104, 21, 2, 247)]);
        assert_eq!(parsed.aaaa_records, vec![v6]);
        assert_eq!(parsed.https_records.len(), 1);
        assert_eq!(parsed.https_records[0].priority, 1);
        assert_eq!(parsed.https_records[0].target_name, ".");
        assert_eq!(
            parsed.https_records[0].ech_config_list.as_deref(),
            Some(fake_ech.as_slice())
        );
        assert_eq!(
            parsed.https_records[0].ipv4_hints,
            vec![Ipv4Addr::new(104, 21, 2, 247)]
        );
        assert_eq!(parsed.https_records[0].ipv6_hints, vec![v6]);
    }

    #[test]
    fn compression_pointer_loop_rejected() {
        // Malformed response whose question name points to itself at offset 12.
        let bad = [
            0x00, 0x00, 0x81, 0x80, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xC0, 0x0C,
            0x00, 0x01, 0x00, 0x01,
        ];
        assert!(parse_dns_response(&bad).is_err());
    }

    #[tokio::test]
    async fn mock_doh_server_resolves_a_aaaa_and_ech_and_races_fallback() {
        let fake_ech = vec![0x00, 0x04, 0xfe, 0x0d, 0xaa, 0xbb];
        let ech_for_handler = fake_ech.clone();

        // Working mock RFC 8484 server on 127.0.0.1
        let app = Router::new().route(
            "/dns-query",
            post(move |body: AxumBytes| {
                let ech = ech_for_handler.clone();
                async move {
                    let qtype = extract_query_qtype(&body);
                    let wire = match qtype {
                        QTYPE_A => build_mock_dns_response(
                            &body,
                            &[(&[0xC0, 0x0C], QTYPE_A, &[198, 51, 100, 7])],
                        ),
                        QTYPE_AAAA => build_mock_dns_response(&body, &[]),
                        QTYPE_HTTPS => {
                            let mut rdata = vec![0x00, 0x01, 0x00]; // prio=1, target="."
                            rdata.extend_from_slice(&SVCPARAM_ECH.to_be_bytes());
                            rdata.extend_from_slice(&(ech.len() as u16).to_be_bytes());
                            rdata.extend_from_slice(&ech);
                            build_mock_dns_response(&body, &[(&[0xC0, 0x0C], QTYPE_HTTPS, &rdata)])
                        }
                        _ => build_mock_dns_response(&body, &[]),
                    };
                    (
                        AxumStatus::OK,
                        [(header::CONTENT_TYPE, "application/dns-message")],
                        wire,
                    )
                }
            }),
        );
        let good_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let good_addr = good_listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(good_listener, app).await.unwrap();
        });

        // Failing mock server returning HTTP 500
        let bad_app = Router::new().route(
            "/dns-query",
            post(|| async { AxumStatus::INTERNAL_SERVER_ERROR }),
        );
        let bad_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let bad_addr = bad_listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(bad_listener, bad_app).await.unwrap();
        });

        // 1. Race failing endpoint + good endpoint -> succeeds via good endpoint!
        let cfg = DohConfig::Custom(vec![
            format!("http://{bad_addr}/dns-query"),
            format!("http://{good_addr}/dns-query"),
        ]);
        let res = resolve_host_with_tls(
            &cfg,
            "tunnel.example.test",
            443,
            build_doh_rustls_config(),
            Duration::from_secs(2),
        )
        .await
        .unwrap();
        assert_eq!(
            res.addrs,
            vec![SocketAddr::new(
                IpAddr::V4(Ipv4Addr::new(198, 51, 100, 7)),
                443
            )]
        );
        assert_eq!(res.ech_config_list.as_deref(), Some(fake_ech.as_slice()));
        assert_eq!(
            res.source,
            ResolutionSource::Doh(format!("http://{good_addr}/dns-query"))
        );

        // 2. Fallback to 3rd endpoint when first two fail
        let cfg_fallback = DohConfig::Custom(vec![
            format!("http://{bad_addr}/dns-query"),
            format!("http://{bad_addr}/dns-query"),
            format!("http://{good_addr}/dns-query"),
        ]);
        let res2 = resolve_host_with_tls(
            &cfg_fallback,
            "tunnel.example.test",
            443,
            build_doh_rustls_config(),
            Duration::from_secs(2),
        )
        .await
        .unwrap();
        assert_eq!(
            res2.addrs[0].ip(),
            IpAddr::V4(Ipv4Addr::new(198, 51, 100, 7))
        );

        // 3. All endpoints failing -> error (no silent system DNS fallback for Custom/Strict)
        let cfg_fail = DohConfig::Custom(vec![format!("http://{bad_addr}/dns-query")]);
        assert!(resolve_host_with_tls(
            &cfg_fail,
            "tunnel.example.test",
            443,
            build_doh_rustls_config(),
            Duration::from_secs(2),
        )
        .await
        .is_err());

        // 4. Localhost & IP literal skip DoH even when custom endpoint is failing!
        let ip_res = resolve_host_with_tls(
            &cfg_fail,
            "127.0.0.1",
            8080,
            build_doh_rustls_config(),
            Duration::from_secs(2),
        )
        .await
        .unwrap();
        assert_eq!(ip_res.source, ResolutionSource::IpLiteral);
        assert_eq!(ip_res.addrs, vec!["127.0.0.1:8080".parse().unwrap()]);

        let local_res = resolve_host_with_tls(
            &cfg_fail,
            "localhost",
            8080,
            build_doh_rustls_config(),
            Duration::from_secs(2),
        )
        .await
        .unwrap();
        assert_eq!(local_res.source, ResolutionSource::LocalSystemDns);
        assert!(!local_res.addrs.is_empty());
    }

    #[tokio::test]
    async fn strict_mode_fails_without_fallback_and_auto_falls_back_when_unreachable() {
        let tmp_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let closed_addr = tmp_listener.local_addr().unwrap();
        drop(tmp_listener);

        let dead_endpoints = vec![format!("http://{closed_addr}/dns-query")];

        // Strict mode fails cleanly without touching system DNS.
        let err = resolve_host_with_endpoints(
            &DohConfig::Strict,
            &dead_endpoints,
            "neruton.moer.eu.org",
            443,
            build_doh_rustls_config(),
            Duration::from_secs(1),
        )
        .await
        .unwrap_err();
        assert!(
            err.to_string().contains("strict DoH lookup failed"),
            "unexpected strict error: {err:#}"
        );

        // Auto mode warns and falls back to system DNS (tested using a valid /etc/hosts or live host;
        // verify fallback path triggers by checking that it reaches system DNS lookup rather than
        // returning "strict DoH lookup failed").
        let auto_err_or_ok = resolve_host_with_endpoints(
            &DohConfig::Auto,
            &dead_endpoints,
            "nonexistent-neruton-test.invalid",
            443,
            build_doh_rustls_config(),
            Duration::from_secs(1),
        )
        .await;
        let auto_err = auto_err_or_ok.unwrap_err();
        assert!(
            auto_err.to_string().contains("system DNS lookup failed"),
            "auto mode should have fallen back to system DNS, got: {auto_err:#}"
        );
    }

    #[tokio::test]
    async fn doh_over_http2_sends_scheme_and_authority_pseudo_headers() {
        use http::{Response, Version};
        use hyper::body::Incoming;
        use hyper::service::service_fn;
        use std::convert::Infallible;
        use tokio_rustls::TlsAcceptor;

        let (server_cfg, client_cfg) = crate::tls::test_h2_server_and_client_configs();
        let acceptor = TlsAcceptor::from(server_cfg);
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        tokio::spawn(async move {
            loop {
                let Ok((tcp, _)) = listener.accept().await else {
                    break;
                };
                let acceptor = acceptor.clone();
                tokio::spawn(async move {
                    let Ok(tls) = acceptor.accept(tcp).await else {
                        return;
                    };
                    let svc = service_fn(|req: Request<Incoming>| async move {
                        assert_eq!(req.version(), Version::HTTP_2);
                        assert_eq!(req.uri().scheme_str(), Some("https"));
                        assert!(
                            req.uri().authority().is_some(),
                            "HTTP/2 DoH request must carry :authority"
                        );
                        assert!(
                            !req.headers().contains_key(header::HOST),
                            "HTTP/2 DoH request must not send redundant Host header"
                        );
                        let body = req.into_body().collect().await.unwrap().to_bytes();
                        let qtype = extract_query_qtype(&body);
                        let wire = match qtype {
                            QTYPE_A => build_mock_dns_response(
                                &body,
                                &[(&[0xC0, 0x0C], QTYPE_A, &[203, 0, 113, 42])],
                            ),
                            _ => build_mock_dns_response(&body, &[]),
                        };
                        Ok::<_, Infallible>(
                            Response::builder()
                                .status(StatusCode::OK)
                                .header(header::CONTENT_TYPE, "application/dns-message")
                                .body(Full::new(Bytes::from(wire)))
                                .unwrap(),
                        )
                    });
                    let _ = hyper::server::conn::http2::Builder::new(TokioExecutor::new())
                        .serve_connection(TokioIo::new(tls), svc)
                        .await;
                });
            }
        });

        let cfg = DohConfig::Custom(vec![format!("https://127.0.0.1:{}/dns-query", addr.port())]);
        let resolved = resolve_host_with_tls(
            &cfg,
            "h2-test.example.test",
            443,
            client_cfg,
            Duration::from_secs(2),
        )
        .await
        .expect("HTTP/2 DoH query should succeed");
        assert_eq!(
            resolved.addrs,
            vec![SocketAddr::new(
                IpAddr::V4(Ipv4Addr::new(203, 0, 113, 42)),
                443
            )]
        );
    }
}
