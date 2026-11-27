use aws_lc_rs::digest::{SHA256, digest};
use clap::Parser;
use log::{debug, error, info, warn};
use quinn::{Endpoint, ServerConfig, TransportConfig, VarInt, crypto};
use rustls::RootCertStore;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject};
use rustls::server::WebPkiClientVerifier;
use rustls::server::danger::ClientCertVerifier;
use serde::Deserialize;
use std::collections::HashMap;
use std::error::Error;
use std::future::Future;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::fs::read_to_string;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

const DEFAULT_MAX_CONNECTIONS: usize = 256;
const DEFAULT_MAX_CONNECTIONS_PER_IP: usize = 32;
const DEFAULT_MAX_IN_FLIGHT_HANDSHAKES: usize = 64;
const MAX_IN_FLIGHT_HANDSHAKES_PER_IP: usize = 8;
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(5);
const STREAM_ACCEPT_TIMEOUT: Duration = Duration::from_secs(10);
const BACKEND_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const BACKEND_EOF_GRACE_TIMEOUT: Duration = Duration::from_secs(2);
const LOG_RATE_LIMIT_INTERVAL: Duration = Duration::from_secs(1);

#[derive(Parser, Debug)]
#[clap(name = "server")]
pub struct Opt {
    /// Address to listen on
    #[clap(long = "listen", short = 'l', default_value = "0.0.0.0:4433")]
    listen: SocketAddr,
    /// Address of the ssh server
    #[clap(long = "proxy-to", short = 'p')]
    proxy_to: Option<SocketAddr>,
    /// Path to TOML config file for SNI-based proxy routing
    #[clap(long = "conf", short = 'F')]
    conf_path: Option<PathBuf>,
    /// Path to PEM-encoded TLS certificate chain
    #[clap(long = "cert")]
    cert: Option<PathBuf>,
    /// Path to PEM-encoded TLS private key
    #[clap(long = "key")]
    key: Option<PathBuf>,
    /// Path to PEM-encoded CA certificate(s) to enforce mTLS client authentication
    #[clap(long = "client-ca")]
    client_ca: Option<PathBuf>,
    /// Maximum number of concurrent connections
    #[clap(long = "max-connections", default_value_t = DEFAULT_MAX_CONNECTIONS)]
    max_connections: usize,
    /// Maximum number of concurrent connections per client IP (IPv6 grouped by /64)
    #[clap(long = "max-connections-per-ip", default_value_t = DEFAULT_MAX_CONNECTIONS_PER_IP)]
    max_connections_per_ip: usize,
    /// Disable QUIC address validation Retry
    #[clap(long = "no-retry", default_value_t = false)]
    no_retry: bool,
}

#[derive(Deserialize, Debug)]
#[serde(deny_unknown_fields)]
struct ServerConf {
    proxy: HashMap<String, SocketAddr>,
}

struct ServeConfig {
    proxy_map: HashMap<String, SocketAddr>,
    default_proxy: SocketAddr,
    max_connections: usize,
    max_connections_per_ip: usize,
    max_in_flight_handshakes: usize,
    max_handshakes_per_ip: usize,
    no_retry: bool,
    handshake_timeout: Duration,
    backend_eof_grace_timeout: Duration,
}

struct ServeState {
    config: ServeConfig,
    conn_semaphore: Arc<Semaphore>,
    established_by_ip: Arc<Mutex<HashMap<IpAddr, usize>>>,
    log_limiters: LogLimiters,
}

fn normalize_client_ip(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V4(v4) => IpAddr::V4(v4),
        IpAddr::V6(v6) => {
            // Unmap IPv4-mapped IPv6 addresses so dual-stack listeners do not collapse all IPv4
            // clients into the ::/64 bucket.
            if let [0, 0, 0, 0, 0, 0xffff, hi, lo] = v6.segments() {
                return IpAddr::V4(Ipv4Addr::from(((hi as u32) << 16) | (lo as u32)));
            }
            IpAddr::V6(Ipv6Addr::from(
                u128::from(v6) & 0xffff_ffff_ffff_ffff_0000_0000_0000_0000,
            ))
        }
    }
}

struct IpCounterGuard {
    ip: IpAddr,
    counts: Arc<Mutex<HashMap<IpAddr, usize>>>,
}

impl IpCounterGuard {
    fn try_acquire(
        counts: Arc<Mutex<HashMap<IpAddr, usize>>>,
        ip: IpAddr,
        limit: usize,
    ) -> Option<Self> {
        let mut map = counts.lock().unwrap_or_else(|e| e.into_inner());
        let current = map.get(&ip).copied().unwrap_or(0);
        if current >= limit {
            return None;
        }
        map.insert(ip, current + 1);
        drop(map);
        Some(Self { ip, counts })
    }
}

impl Drop for IpCounterGuard {
    fn drop(&mut self) {
        let mut map = self.counts.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(count) = map.get_mut(&self.ip) {
            *count -= 1;
            if *count == 0 {
                map.remove(&self.ip);
            }
        }
    }
}

fn is_ip_at_limit(counts: &Mutex<HashMap<IpAddr, usize>>, ip_key: IpAddr, limit: usize) -> bool {
    let map = counts.lock().unwrap_or_else(|e| e.into_inner());
    map.get(&ip_key).copied().unwrap_or(0) >= limit
}

struct LogRateState {
    last_logged: Option<Instant>,
    suppressed: u64,
}

struct LogRateLimiter {
    interval: Duration,
    state: Mutex<LogRateState>,
}

impl LogRateLimiter {
    fn new(interval: Duration) -> Self {
        Self {
            interval,
            state: Mutex::new(LogRateState {
                last_logged: None,
                suppressed: 0,
            }),
        }
    }

    fn check(&self) -> Option<u64> {
        let now = Instant::now();
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        match state.last_logged {
            Some(last) if now.saturating_duration_since(last) < self.interval => {
                state.suppressed = state.suppressed.saturating_add(1);
                None
            }
            _ => {
                let suppressed = state.suppressed;
                state.last_logged = Some(now);
                state.suppressed = 0;
                Some(suppressed)
            }
        }
    }
}

struct LogLimiters {
    global_limit: LogRateLimiter,
    per_ip_limit: LogRateLimiter,
    handshake_error: LogRateLimiter,
    relay_error: Arc<LogRateLimiter>,
}

impl LogLimiters {
    fn new(interval: Duration) -> Self {
        Self {
            global_limit: LogRateLimiter::new(interval),
            per_ip_limit: LogRateLimiter::new(interval),
            handshake_error: LogRateLimiter::new(interval),
            relay_error: Arc::new(LogRateLimiter::new(interval)),
        }
    }
}

const MAX_SANITIZED_LOG_LEN: usize = 256;

/// Escapes control characters (newlines, ANSI escapes, NUL, etc.) and truncates
/// peer-influenced strings before logging to prevent log/terminal injection.
fn sanitize_log_value(input: &str) -> String {
    let mut out = String::with_capacity(input.len().min(MAX_SANITIZED_LOG_LEN));
    for c in input.chars() {
        if c.is_control() {
            for esc in c.escape_default() {
                if out.len() + esc.len_utf8() > MAX_SANITIZED_LOG_LEN {
                    out.push_str("...");
                    return out;
                }
                out.push(esc);
            }
        } else {
            if out.len() + c.len_utf8() > MAX_SANITIZED_LOG_LEN {
                out.push_str("...");
                return out;
            }
            out.push(c);
        }
    }
    out
}

struct ParsedServerConf {
    proxy_map: HashMap<String, SocketAddr>,
    default_proxy: Option<SocketAddr>,
}

fn parse_server_conf(toml_str: &str) -> Result<ParsedServerConf, Box<dyn Error>> {
    let conf: ServerConf = toml::from_str(toml_str)?;
    let mut normalized = HashMap::with_capacity(conf.proxy.len());
    for (key, addr) in conf.proxy {
        let lower = key.to_ascii_lowercase();
        if normalized.insert(lower.clone(), addr).is_some() {
            return Err(format!("duplicate proxy key '{}' after case normalization", lower).into());
        }
    }
    let default_proxy = normalized.remove("default");
    Ok(ParsedServerConf {
        proxy_map: normalized,
        default_proxy,
    })
}

fn resolve_default_proxy(
    cli_proxy_to: Option<SocketAddr>,
    config_default: Option<SocketAddr>,
) -> SocketAddr {
    cli_proxy_to
        .or(config_default)
        .unwrap_or_else(|| SocketAddr::new(Ipv4Addr::LOCALHOST.into(), 22))
}

fn resolve_proxy(
    sni: Option<&str>,
    proxy_map: &HashMap<String, SocketAddr>,
    default_proxy: SocketAddr,
) -> SocketAddr {
    sni.and_then(|name| proxy_map.get(&name.to_ascii_lowercase()))
        .copied()
        .unwrap_or(default_proxy)
}

fn validate_options(options: &Opt) -> Result<(), Box<dyn Error>> {
    if options.max_connections == 0 || options.max_connections > Semaphore::MAX_PERMITS {
        return Err(format!(
            "--max-connections must be between 1 and {}",
            Semaphore::MAX_PERMITS
        )
        .into());
    }
    if options.max_connections_per_ip == 0 {
        return Err("--max-connections-per-ip must be greater than 0".into());
    }
    if options.cert.is_some() != options.key.is_some() {
        return Err("--cert and --key must both be specified together".into());
    }
    Ok(())
}

fn format_sha256_fingerprint(der: &[u8]) -> String {
    let hash = digest(&SHA256, der);
    hash.as_ref()
        .iter()
        .map(|b| format!("{:02X}", b))
        .collect::<Vec<_>>()
        .join(":")
}

fn load_cert_chain(path: &Path) -> Result<Vec<CertificateDer<'static>>, Box<dyn Error>> {
    let certs = CertificateDer::pem_file_iter(path)
        .map_err(|e| format!("failed to read certificates from {}: {}", path.display(), e))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| format!("failed to parse certificate in {}: {}", path.display(), e))?;
    if certs.is_empty() {
        return Err(format!("no certificates found in {}", path.display()).into());
    }
    Ok(certs)
}

fn load_private_key(path: &Path) -> Result<PrivateKeyDer<'static>, Box<dyn Error>> {
    PrivateKeyDer::from_pem_file(path)
        .map_err(|e| format!("failed to load private key from {}: {}", path.display(), e).into())
}

fn build_client_verifier(ca_path: &Path) -> Result<Arc<dyn ClientCertVerifier>, Box<dyn Error>> {
    let certs = load_cert_chain(ca_path)?;
    let mut root_store = RootCertStore::empty();
    for cert in certs {
        root_store
            .add(cert)
            .map_err(|e| format!("invalid CA certificate in {}: {}", ca_path.display(), e))?;
    }
    if root_store.is_empty() {
        return Err(format!("no valid CA certificates found in {}", ca_path.display()).into());
    }
    let verifier = WebPkiClientVerifier::builder_with_provider(
        Arc::new(root_store),
        Arc::new(rustls::crypto::aws_lc_rs::default_provider()),
    )
    .build()
    .map_err(|e| format!("failed to build client certificate verifier: {}", e))?;
    Ok(verifier)
}

fn configure_server(
    cert_path: Option<&Path>,
    key_path: Option<&Path>,
    client_ca_path: Option<&Path>,
) -> Result<(ServerConfig, Vec<u8>), Box<dyn Error>> {
    let (cert_chain, priv_key) = match (cert_path, key_path) {
        (Some(cert), Some(key)) => (load_cert_chain(cert)?, load_private_key(key)?),
        (Some(_), None) | (None, Some(_)) => {
            return Err("--cert and --key must both be specified together".into());
        }
        (None, None) => {
            let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()])?;
            let cert_der = cert.cert.der().clone();
            let fingerprint = format_sha256_fingerprint(cert_der.as_ref());
            warn!(
                "[server] using ephemeral self-signed certificate (pin with --server-cert-sha256): SHA256:{}",
                fingerprint
            );
            let priv_key = PrivateKeyDer::from(cert.signing_key);
            (vec![cert_der], priv_key)
        }
    };

    let leaf_cert_der = cert_chain[0].as_ref().to_vec();

    let tls_builder = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::aws_lc_rs::default_provider(),
    ))
    .with_protocol_versions(&[&rustls::version::TLS13])?;
    let tls_config = match client_ca_path {
        Some(ca_path) => {
            let verifier = build_client_verifier(ca_path)?;
            info!("[server] mTLS client certificate authentication enabled");
            tls_builder
                .with_client_cert_verifier(verifier)
                .with_single_cert(cert_chain, priv_key)?
        }
        None => tls_builder
            .with_no_client_auth()
            .with_single_cert(cert_chain, priv_key)?,
    };

    let quic_config = crypto::rustls::QuicServerConfig::try_from(tls_config)?;
    let mut server_config = ServerConfig::with_crypto(Arc::new(quic_config));
    server_config.max_incoming(256);
    server_config.incoming_buffer_size(64 * 1024);
    server_config.incoming_buffer_size_total(4 * 1024 * 1024);

    let mut transport_config = TransportConfig::default();
    transport_config.datagram_receive_buffer_size(None);
    transport_config.stream_receive_window(VarInt::from_u32(256 * 1024));
    transport_config.receive_window(VarInt::from_u32(512 * 1024));
    transport_config.send_window(512 * 1024);
    transport_config.max_concurrent_uni_streams(0_u8.into());
    transport_config.max_concurrent_bidi_streams(1_u8.into());
    transport_config.max_idle_timeout(Some(VarInt::from_u32(60_000).into()));
    #[cfg(any(windows, target_os = "linux"))]
    transport_config.mtu_discovery_config(Some(quinn::MtuDiscoveryConfig::default()));
    #[cfg(not(any(windows, target_os = "linux")))]
    transport_config.mtu_discovery_config(None);
    server_config.transport_config(Arc::new(transport_config));

    Ok((server_config, leaf_cert_der))
}

fn extract_sni(conn: &quinn::Connection) -> Option<String> {
    conn.handshake_data()
        .and_then(|data| data.downcast::<crypto::rustls::HandshakeData>().ok())
        .and_then(|hs| hs.server_name)
}

#[cfg(unix)]
async fn wait_for_unix_signal(kind: tokio::signal::unix::SignalKind, name: &'static str) {
    match tokio::signal::unix::signal(kind) {
        Ok(mut stream) => {
            if stream.recv().await.is_some() {
                info!("[server] received {}, shutting down", name);
                return;
            }
            error!("[server] {} signal stream closed unexpectedly", name);
        }
        Err(e) => {
            error!("[server] failed to install {} handler: {}", name, e);
        }
    }
    std::future::pending::<()>().await;
}

#[cfg(unix)]
async fn shutdown_signal() {
    use tokio::signal::unix::SignalKind;

    tokio::select! {
        () = wait_for_unix_signal(SignalKind::interrupt(), "SIGINT") => {}
        () = wait_for_unix_signal(SignalKind::terminate(), "SIGTERM") => {}
    }
}

#[cfg(not(unix))]
async fn shutdown_signal() {
    match tokio::signal::ctrl_c().await {
        Ok(()) => info!("[server] received Ctrl+C, shutting down"),
        Err(e) => {
            error!("[server] failed to listen for Ctrl+C: {}", e);
            std::future::pending::<()>().await;
        }
    }
}

#[tokio::main]
pub async fn run(options: Opt) -> Result<(), Box<dyn Error>> {
    validate_options(&options)?;

    let parsed_conf = match options.conf_path {
        Some(ref path) => {
            info!("[server] importing conf file: {}", path.display());
            let content = read_to_string(path).await?;
            parse_server_conf(&content)?
        }
        None => ParsedServerConf {
            proxy_map: HashMap::new(),
            default_proxy: None,
        },
    };

    let default_proxy = resolve_default_proxy(options.proxy_to, parsed_conf.default_proxy);
    info!("[server] default proxy aim: {}", default_proxy);

    let (server_config, _) = configure_server(
        options.cert.as_deref(),
        options.key.as_deref(),
        options.client_ca.as_deref(),
    )?;
    let endpoint = Endpoint::server(server_config, options.listen)?;
    info!("[server] listening on: {}", options.listen);

    serve_endpoint_until(
        endpoint,
        ServeConfig {
            proxy_map: parsed_conf.proxy_map,
            default_proxy,
            max_connections: options.max_connections,
            max_connections_per_ip: options.max_connections_per_ip,
            max_in_flight_handshakes: DEFAULT_MAX_IN_FLIGHT_HANDSHAKES,
            max_handshakes_per_ip: MAX_IN_FLIGHT_HANDSHAKES_PER_IP,
            no_retry: options.no_retry,
            handshake_timeout: HANDSHAKE_TIMEOUT,
            backend_eof_grace_timeout: BACKEND_EOF_GRACE_TIMEOUT,
        },
        shutdown_signal(),
    )
    .await;

    Ok(())
}

#[cfg(test)]
async fn serve_endpoint(endpoint: Endpoint, config: ServeConfig) {
    serve_endpoint_until(endpoint, config, std::future::pending()).await;
}

async fn serve_endpoint_until<F: Future<Output = ()>>(
    endpoint: Endpoint,
    config: ServeConfig,
    shutdown: F,
) {
    let handshake_semaphore = Arc::new(Semaphore::new(config.max_in_flight_handshakes));
    let in_flight_by_ip = Arc::new(Mutex::new(HashMap::new()));
    let state = Arc::new(ServeState {
        conn_semaphore: Arc::new(Semaphore::new(config.max_connections)),
        established_by_ip: Arc::new(Mutex::new(HashMap::new())),
        log_limiters: LogLimiters::new(LOG_RATE_LIMIT_INTERVAL),
        config,
    });

    tokio::pin!(shutdown);

    loop {
        let incoming_conn = tokio::select! {
            biased;
            _ = &mut shutdown => {
                info!("[server] closing endpoint for graceful shutdown");
                endpoint.close(0u32.into(), b"server shutdown");
                let _ = tokio::time::timeout(Duration::from_secs(2), endpoint.wait_idle()).await;
                break;
            }
            accepted = endpoint.accept() => match accepted {
                Some(conn) => conn,
                None => break,
            },
        };

        if !state.config.no_retry && !incoming_conn.remote_address_validated() {
            if let Err(e) = incoming_conn.retry() {
                debug!("[server] failed to send retry packet: {}", e);
            }
            continue;
        }

        let remote_addr = incoming_conn.remote_address();
        let ip_key = normalize_client_ip(remote_addr.ip());

        if state.conn_semaphore.available_permits() == 0 {
            debug!(
                "[server] max connections ({}) saturated, refusing pre-handshake from {}",
                state.config.max_connections, remote_addr
            );
            if let Some(suppressed) = state.log_limiters.global_limit.check() {
                warn!(
                    "[server] max connections ({}) reached, refusing connection from {} (suppressed {} prior events)",
                    state.config.max_connections, remote_addr, suppressed
                );
            }
            incoming_conn.refuse();
            continue;
        }

        if is_ip_at_limit(
            &state.established_by_ip,
            ip_key,
            state.config.max_connections_per_ip,
        ) {
            debug!(
                "[server] max connections per IP ({}) reached for {} (bucket {}), refusing pre-handshake",
                state.config.max_connections_per_ip, remote_addr, ip_key
            );
            if let Some(suppressed) = state.log_limiters.per_ip_limit.check() {
                warn!(
                    "[server] max connections per IP ({}) reached for {}, refusing connection (suppressed {} prior events)",
                    state.config.max_connections_per_ip, ip_key, suppressed
                );
            }
            incoming_conn.refuse();
            continue;
        }

        let handshake_permit = match handshake_semaphore.clone().try_acquire_owned() {
            Ok(permit) => permit,
            Err(_) => {
                debug!(
                    "[server] max in-flight handshakes ({}) reached, refusing connection from {}",
                    state.config.max_in_flight_handshakes, remote_addr
                );
                if let Some(suppressed) = state.log_limiters.global_limit.check() {
                    warn!(
                        "[server] max in-flight handshakes ({}) reached, refusing connection from {} (suppressed {} prior events)",
                        state.config.max_in_flight_handshakes, remote_addr, suppressed
                    );
                }
                incoming_conn.refuse();
                continue;
            }
        };

        let handshake_ip_guard = match IpCounterGuard::try_acquire(
            Arc::clone(&in_flight_by_ip),
            ip_key,
            state.config.max_handshakes_per_ip,
        ) {
            Some(guard) => guard,
            None => {
                debug!(
                    "[server] max in-flight handshakes per IP ({}) reached for {} (bucket {}), refusing connection",
                    state.config.max_handshakes_per_ip, remote_addr, ip_key
                );
                if let Some(suppressed) = state.log_limiters.per_ip_limit.check() {
                    warn!(
                        "[server] max in-flight handshakes per IP ({}) reached for {}, refusing connection (suppressed {} prior events)",
                        state.config.max_handshakes_per_ip, ip_key, suppressed
                    );
                }
                incoming_conn.refuse();
                continue;
            }
        };

        let state = Arc::clone(&state);
        tokio::spawn(async move {
            handle_incoming(incoming_conn, handshake_permit, handshake_ip_guard, state).await;
        });
    }
}

async fn handle_incoming(
    incoming_conn: quinn::Incoming,
    handshake_permit: OwnedSemaphorePermit,
    handshake_ip_guard: IpCounterGuard,
    state: Arc<ServeState>,
) {
    let remote_addr = incoming_conn.remote_address();
    let handshake_res =
        tokio::time::timeout(state.config.handshake_timeout, incoming_conn.into_future()).await;
    drop(handshake_permit);
    drop(handshake_ip_guard);

    let conn = match handshake_res {
        Ok(Ok(conn)) => conn,
        Ok(Err(e)) => {
            let safe_err = sanitize_log_value(&e.to_string());
            debug!(
                "[server] accept connection error from {}: {}",
                remote_addr, safe_err
            );
            if let Some(suppressed) = state.log_limiters.handshake_error.check() {
                warn!(
                    "[server] accept connection error from {}: {} (suppressed {} prior events)",
                    remote_addr, safe_err, suppressed
                );
            }
            return;
        }
        Err(_) => {
            debug!("[server] handshake timed out from {}", remote_addr);
            if let Some(suppressed) = state.log_limiters.handshake_error.check() {
                warn!(
                    "[server] handshake timed out from {} (suppressed {} prior events)",
                    remote_addr, suppressed
                );
            }
            return;
        }
    };

    let _conn_permit = match state.conn_semaphore.clone().try_acquire_owned() {
        Ok(permit) => permit,
        Err(_) => {
            debug!(
                "[server] max connections ({}) reached post-handshake, closing connection from {}",
                state.config.max_connections,
                conn.remote_address()
            );
            if let Some(suppressed) = state.log_limiters.global_limit.check() {
                warn!(
                    "[server] max connections ({}) reached, closing connection from {} (suppressed {} prior events)",
                    state.config.max_connections,
                    conn.remote_address(),
                    suppressed
                );
            }
            conn.close(VarInt::from_u32(1), b"max connections reached");
            return;
        }
    };

    let ip_key = normalize_client_ip(conn.remote_address().ip());
    let _conn_ip_guard = match IpCounterGuard::try_acquire(
        Arc::clone(&state.established_by_ip),
        ip_key,
        state.config.max_connections_per_ip,
    ) {
        Some(guard) => guard,
        None => {
            debug!(
                "[server] max connections per IP ({}) reached post-handshake for {} (bucket {}), closing connection",
                state.config.max_connections_per_ip,
                conn.remote_address(),
                ip_key
            );
            if let Some(suppressed) = state.log_limiters.per_ip_limit.check() {
                warn!(
                    "[server] max connections per IP ({}) reached for {}, closing connection (suppressed {} prior events)",
                    state.config.max_connections_per_ip, ip_key, suppressed
                );
            }
            conn.close(VarInt::from_u32(1), b"max connections reached");
            return;
        }
    };

    let sni = extract_sni(&conn);
    let proxy_to = resolve_proxy(
        sni.as_deref(),
        &state.config.proxy_map,
        state.config.default_proxy,
    );
    info!(
        "[server] connection accepted: ({}, {}) -> {}",
        conn.remote_address(),
        sni.as_deref().unwrap_or("-"),
        proxy_to
    );

    handle_connection(
        proxy_to,
        conn,
        state.config.backend_eof_grace_timeout,
        Arc::clone(&state.log_limiters.relay_error),
    )
    .await;
}

async fn handle_connection(
    proxy_for: SocketAddr,
    connection: quinn::Connection,
    backend_eof_grace_timeout: Duration,
    relay_log_limiter: Arc<LogRateLimiter>,
) {
    handle_connection_with_timeouts(
        proxy_for,
        connection,
        STREAM_ACCEPT_TIMEOUT,
        BACKEND_CONNECT_TIMEOUT,
        backend_eof_grace_timeout,
        relay_log_limiter,
    )
    .await;
}

async fn handle_connection_with_timeouts(
    proxy_for: SocketAddr,
    connection: quinn::Connection,
    stream_accept_timeout: Duration,
    backend_connect_timeout: Duration,
    backend_eof_grace_timeout: Duration,
    relay_log_limiter: Arc<LogRateLimiter>,
) {
    let (mut quinn_send, mut quinn_recv) = match tokio::time::timeout(
        stream_accept_timeout,
        connection.accept_bi(),
    )
    .await
    {
        Ok(Ok(stream)) => stream,
        Ok(Err(e)) => {
            let safe_err = sanitize_log_value(&e.to_string());
            debug!("[server] open quic stream error: {}", safe_err);
            if let Some(suppressed) = relay_log_limiter.check() {
                warn!(
                    "[server] open quic stream error: {} (suppressed {} prior events)",
                    safe_err, suppressed
                );
            }
            return;
        }
        Err(_) => {
            debug!(
                "[server] timed out waiting for quic stream from {}",
                connection.remote_address()
            );
            if let Some(suppressed) = relay_log_limiter.check() {
                warn!(
                    "[server] timed out waiting for quic stream from {} (suppressed {} prior events)",
                    connection.remote_address(),
                    suppressed
                );
            }
            connection.close(VarInt::from_u32(1), b"stream accept timeout");
            return;
        }
    };

    let ssh_conn = match tokio::time::timeout(
        backend_connect_timeout,
        TcpStream::connect(proxy_for),
    )
    .await
    {
        Ok(Ok(conn)) => conn,
        Ok(Err(e)) => {
            debug!("[server] connect to ssh error: {}", e);
            if let Some(suppressed) = relay_log_limiter.check() {
                error!(
                    "[server] connect to ssh error: {} (suppressed {} prior events)",
                    e, suppressed
                );
            }
            // Close connection before dropping `quinn_send` so SendStream::drop does not
            // race a clean STREAM(FIN) ahead of connection teardown.
            connection.close(VarInt::from_u32(1), b"backend connect error");
            return;
        }
        Err(_) => {
            debug!("[server] timed out connecting to ssh backend {}", proxy_for);
            if let Some(suppressed) = relay_log_limiter.check() {
                error!(
                    "[server] timed out connecting to ssh backend {} (suppressed {} prior events)",
                    proxy_for, suppressed
                );
            }
            connection.close(VarInt::from_u32(1), b"backend connect timeout");
            return;
        }
    };

    info!("[server] ssh connection established");

    let (mut ssh_recv, mut ssh_write) = ssh_conn.into_split();
    let ssh_to_quic_limiter = Arc::clone(&relay_log_limiter);
    let quic_to_ssh_limiter = Arc::clone(&relay_log_limiter);

    let ssh_to_quic = async move {
        let mut buf = [0; 2048];
        loop {
            match ssh_recv.read(&mut buf).await {
                Ok(0) => {
                    info!("[server] ssh EOF received, finishing quic send stream");
                    let _ = quinn_send.finish();
                    return Ok(quinn_send);
                }
                Ok(n) => {
                    debug!("[server] recv data from ssh server {} bytes", n);
                    if let Err(e) = quinn_send.write_all(&buf[..n]).await {
                        let safe_err = sanitize_log_value(&e.to_string());
                        debug!("[server] writing to quic stream error: {}", safe_err);
                        if let Some(suppressed) = ssh_to_quic_limiter.check() {
                            warn!(
                                "[server] writing to quic stream error: {} (suppressed {} prior events)",
                                safe_err, suppressed
                            );
                        }
                        return Err(());
                    }
                }
                Err(e) => {
                    debug!("[server] reading from ssh server error: {}", e);
                    if let Some(suppressed) = ssh_to_quic_limiter.check() {
                        error!(
                            "[server] reading from ssh server error: {} (suppressed {} prior events)",
                            e, suppressed
                        );
                    }
                    // Reset send stream before drop so client cannot misinterpret a backend read
                    // failure as clean EOF.
                    let _ = quinn_send.reset(VarInt::from_u32(1));
                    return Err(());
                }
            }
        }
    };

    let quic_to_ssh = async move {
        let mut buf = [0; 2048];
        loop {
            match quinn_recv.read(&mut buf).await {
                Ok(None) | Ok(Some(0)) => {
                    info!("[server] quic stream EOF received, shutting down ssh write half");
                    let _ = ssh_write.shutdown().await;
                    return Ok(());
                }
                Ok(Some(n)) => {
                    debug!("[server] recv data from quic stream {} bytes", n);
                    if let Err(e) = ssh_write.write_all(&buf[..n]).await {
                        debug!("[server] writing to ssh server error: {}", e);
                        if let Some(suppressed) = quic_to_ssh_limiter.check() {
                            warn!(
                                "[server] writing to ssh server error: {} (suppressed {} prior events)",
                                e, suppressed
                            );
                        }
                        return Err(());
                    }
                }
                Err(quinn::ReadError::ConnectionLost(
                    quinn::ConnectionError::ApplicationClosed(ref close),
                )) if close.error_code == VarInt::from_u32(0) => {
                    info!("[server] quic client closed connection cleanly");
                    let _ = ssh_write.shutdown().await;
                    return Ok(());
                }
                Err(e) => {
                    let safe_err = sanitize_log_value(&e.to_string());
                    debug!("[server] reading from quic client error: {}", safe_err);
                    if let Some(suppressed) = quic_to_ssh_limiter.check() {
                        warn!(
                            "[server] reading from quic client error: {} (suppressed {} prior events)",
                            safe_err, suppressed
                        );
                    }
                    return Err(());
                }
            }
        }
    };

    tokio::pin!(ssh_to_quic, quic_to_ssh);

    tokio::select! {
        quic_res = &mut quic_to_ssh => {
            match quic_res {
                Ok(()) => {
                    // Client half-closed: wait for backend to finish sending its reply.
                    match ssh_to_quic.await {
                        Ok(quinn_send) => {
                            let _ = tokio::time::timeout(
                                Duration::from_millis(500),
                                quinn_send.stopped(),
                            )
                            .await;
                        }
                        Err(()) => {
                            connection.close(VarInt::from_u32(1), b"relay error");
                            return;
                        }
                    }
                }
                Err(()) => {
                    connection.close(VarInt::from_u32(1), b"relay error");
                    return;
                }
            }
        }
        ssh_res = &mut ssh_to_quic => {
            match ssh_res {
                Ok(quinn_send) => {
                    // Backend closed TCP and quinn_send.finish() was called. Give the client a
                    // bounded grace period to close its send half so slots and FDs cannot leak.
                    match tokio::time::timeout(backend_eof_grace_timeout, &mut quic_to_ssh).await {
                        Ok(Ok(())) => {
                            let _ = tokio::time::timeout(
                                Duration::from_millis(500),
                                quinn_send.stopped(),
                            )
                            .await;
                        }
                        Ok(Err(())) => {
                            let _ = tokio::time::timeout(
                                Duration::from_millis(200),
                                quinn_send.stopped(),
                            )
                            .await;
                            connection.close(VarInt::from_u32(1), b"relay error");
                            return;
                        }
                        Err(_) => {
                            debug!(
                                "[server] client {} kept stream open after backend EOF, closing connection",
                                connection.remote_address()
                            );
                            if let Some(suppressed) = relay_log_limiter.check() {
                                warn!(
                                    "[server] client {} kept stream open after backend EOF, closing connection (suppressed {} prior events)",
                                    connection.remote_address(),
                                    suppressed
                                );
                            }
                            let _ = tokio::time::timeout(
                                Duration::from_millis(200),
                                quinn_send.stopped(),
                            )
                            .await;
                            connection.close(VarInt::from_u32(0), b"backend closed");
                            return;
                        }
                    }
                }
                Err(()) => {
                    connection.close(VarInt::from_u32(1), b"relay error");
                    return;
                }
            }
        }
    }

    info!("[server] exit client");
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::sync::atomic::{AtomicU64, Ordering};
    use tokio::net::{TcpListener, UdpSocket};

    struct TestTempDir {
        path: PathBuf,
    }

    impl TestTempDir {
        fn new(prefix: &str) -> Self {
            static COUNTER: AtomicU64 = AtomicU64::new(0);
            let id = COUNTER.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "quicssh-rs-{}-{}-{}",
                prefix,
                std::process::id(),
                id
            ));
            fs::create_dir_all(&path).expect("create temp test dir");
            Self { path }
        }

        fn path(&self) -> &Path {
            &self.path
        }
    }

    impl Drop for TestTempDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.path);
        }
    }

    struct MtlsFixtures {
        cert_path: PathBuf,
        key_path: PathBuf,
        ca_path: PathBuf,
        ca_der: Vec<u8>,
        client_cert_der: CertificateDer<'static>,
        client_key_pem: String,
        expired_client_cert_der: CertificateDer<'static>,
        expired_client_key_pem: String,
        server_auth_client_cert_der: CertificateDer<'static>,
        server_auth_client_key_pem: String,
    }

    impl MtlsFixtures {
        fn create(dir: &TestTempDir) -> Self {
            let mut ca_params =
                rcgen::CertificateParams::new(Vec::<String>::new()).expect("ca params");
            ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
            let ca_key = rcgen::KeyPair::generate().expect("ca key");
            let ca_issuer =
                rcgen::CertifiedIssuer::self_signed(ca_params, ca_key).expect("ca issuer");

            let server_key = rcgen::KeyPair::generate().expect("server key");
            let server_params =
                rcgen::CertificateParams::new(vec!["localhost".into()]).expect("server params");
            let server_cert = server_params
                .signed_by(&server_key, &ca_issuer)
                .expect("sign server cert");

            let client_key = rcgen::KeyPair::generate().expect("client key");
            let mut client_params =
                rcgen::CertificateParams::new(vec!["client.local".into()]).expect("client params");
            client_params.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ClientAuth];
            let client_cert = client_params
                .signed_by(&client_key, &ca_issuer)
                .expect("sign client cert");

            let expired_client_key = rcgen::KeyPair::generate().expect("expired client key");
            let mut expired_params = rcgen::CertificateParams::new(vec!["expired.local".into()])
                .expect("expired params");
            expired_params.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ClientAuth];
            expired_params.not_before = rcgen::date_time_ymd(2020, 1, 1);
            expired_params.not_after = rcgen::date_time_ymd(2020, 1, 2);
            let expired_client_cert = expired_params
                .signed_by(&expired_client_key, &ca_issuer)
                .expect("sign expired client cert");

            let server_auth_client_key =
                rcgen::KeyPair::generate().expect("server-auth client key");
            let mut server_auth_params =
                rcgen::CertificateParams::new(vec!["server-auth.local".into()])
                    .expect("server-auth params");
            server_auth_params.extended_key_usages =
                vec![rcgen::ExtendedKeyUsagePurpose::ServerAuth];
            let server_auth_client_cert = server_auth_params
                .signed_by(&server_auth_client_key, &ca_issuer)
                .expect("sign server-auth client cert");

            let cert_path = dir.path().join("server.crt");
            let key_path = dir.path().join("server.key");
            let ca_path = dir.path().join("ca.crt");
            fs::write(&cert_path, server_cert.pem()).expect("write server cert");
            fs::write(&key_path, server_key.serialize_pem()).expect("write server key");
            fs::write(&ca_path, ca_issuer.pem()).expect("write ca cert");

            Self {
                cert_path,
                key_path,
                ca_path,
                ca_der: ca_issuer.der().as_ref().to_vec(),
                client_cert_der: client_cert.der().clone(),
                client_key_pem: client_key.serialize_pem(),
                expired_client_cert_der: expired_client_cert.der().clone(),
                expired_client_key_pem: expired_client_key.serialize_pem(),
                server_auth_client_cert_der: server_auth_client_cert.der().clone(),
                server_auth_client_key_pem: server_auth_client_key.serialize_pem(),
            }
        }

        fn client_identity(&self) -> (Vec<CertificateDer<'static>>, PrivateKeyDer<'static>) {
            let key = PrivateKeyDer::from_pem_slice(self.client_key_pem.as_bytes())
                .expect("parse client key");
            (vec![self.client_cert_der.clone()], key)
        }

        fn expired_client_identity(
            &self,
        ) -> (Vec<CertificateDer<'static>>, PrivateKeyDer<'static>) {
            let key = PrivateKeyDer::from_pem_slice(self.expired_client_key_pem.as_bytes())
                .expect("parse expired client key");
            (vec![self.expired_client_cert_der.clone()], key)
        }

        fn server_auth_client_identity(
            &self,
        ) -> (Vec<CertificateDer<'static>>, PrivateKeyDer<'static>) {
            let key = PrivateKeyDer::from_pem_slice(self.server_auth_client_key_pem.as_bytes())
                .expect("parse server-auth client key");
            (vec![self.server_auth_client_cert_der.clone()], key)
        }
    }

    fn test_serve_config(default_proxy: SocketAddr) -> ServeConfig {
        ServeConfig {
            proxy_map: HashMap::new(),
            default_proxy,
            max_connections: 4,
            max_connections_per_ip: DEFAULT_MAX_CONNECTIONS_PER_IP,
            max_in_flight_handshakes: DEFAULT_MAX_IN_FLIGHT_HANDSHAKES,
            max_handshakes_per_ip: MAX_IN_FLIGHT_HANDSHAKES_PER_IP,
            no_retry: true,
            handshake_timeout: Duration::from_secs(2),
            backend_eof_grace_timeout: BACKEND_EOF_GRACE_TIMEOUT,
        }
    }

    fn make_client_endpoint_with_opts(
        server_cert_der: &[u8],
        client_identity: Option<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>)>,
        enable_sni: bool,
        keep_alive_interval: Option<Duration>,
    ) -> Endpoint {
        let mut roots = RootCertStore::empty();
        roots
            .add(CertificateDer::from(server_cert_der.to_vec()))
            .expect("add server root cert");

        let builder = rustls::ClientConfig::builder_with_provider(Arc::new(
            rustls::crypto::aws_lc_rs::default_provider(),
        ))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .expect("tls 1.3 client builder")
        .with_root_certificates(roots);
        let mut tls_config = match client_identity {
            Some((certs, key)) => builder
                .with_client_auth_cert(certs, key)
                .expect("configure client auth"),
            None => builder.with_no_client_auth(),
        };
        tls_config.enable_sni = enable_sni;

        let quic_config =
            crypto::rustls::QuicClientConfig::try_from(tls_config).expect("quic client config");
        let mut client_config = quinn::ClientConfig::new(Arc::new(quic_config));
        if let Some(interval) = keep_alive_interval {
            let mut transport = TransportConfig::default();
            transport.keep_alive_interval(Some(interval));
            client_config.transport_config(Arc::new(transport));
        }

        let mut endpoint = Endpoint::client(SocketAddr::new(Ipv4Addr::LOCALHOST.into(), 0))
            .expect("client endpoint");
        endpoint.set_default_client_config(client_config);
        endpoint
    }

    fn make_client_endpoint_with_sni(
        server_cert_der: &[u8],
        client_identity: Option<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>)>,
        enable_sni: bool,
    ) -> Endpoint {
        make_client_endpoint_with_opts(server_cert_der, client_identity, enable_sni, None)
    }

    fn make_client_endpoint(
        server_cert_der: &[u8],
        client_identity: Option<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>)>,
    ) -> Endpoint {
        make_client_endpoint_with_opts(server_cert_der, client_identity, true, None)
    }

    /// Forward only the first QUIC Initial packet from a fresh client so the server accepts an
    /// `Incoming` whose TLS handshake never finishes.
    async fn inject_stalled_handshake(
        server_addr: SocketAddr,
        server_cert_der: &[u8],
    ) -> (Endpoint, UdpSocket, quinn::Connecting) {
        let proxy_udp = UdpSocket::bind(SocketAddr::new(Ipv4Addr::LOCALHOST.into(), 0))
            .await
            .expect("bind proxy udp");
        let proxy_addr = proxy_udp.local_addr().expect("proxy addr");
        let stalled_client = make_client_endpoint(server_cert_der, None);
        let stalled_connecting = stalled_client
            .connect(proxy_addr, "localhost")
            .expect("start stalled connect");
        let mut initial_pkt = [0u8; 2048];
        let (n, _) = proxy_udp
            .recv_from(&mut initial_pkt)
            .await
            .expect("recv initial packet");
        proxy_udp
            .send_to(&initial_pkt[..n], server_addr)
            .await
            .expect("forward initial packet");
        (stalled_client, proxy_udp, stalled_connecting)
    }

    async fn assert_application_closed(
        connect_res: Result<quinn::Connection, quinn::ConnectionError>,
        expected_code: u32,
        expected_reason: &[u8],
    ) {
        let err = match connect_res {
            Ok(conn) => tokio::time::timeout(Duration::from_secs(2), conn.closed())
                .await
                .expect("client should observe connection close promptly"),
            Err(err) => err,
        };
        match err {
            quinn::ConnectionError::ApplicationClosed(close) => {
                assert_eq!(close.error_code, VarInt::from_u32(expected_code));
                assert_eq!(close.reason.as_ref(), expected_reason);
            }
            other => panic!(
                "expected ApplicationClosed({}, {:?}), got: {:?}",
                expected_code, expected_reason, other
            ),
        }
    }

    fn assert_connection_refused(connect_res: Result<quinn::Connection, quinn::ConnectionError>) {
        match connect_res {
            Err(quinn::ConnectionError::ConnectionClosed(close)) => {
                assert_eq!(
                    close.error_code,
                    quinn::TransportErrorCode::CONNECTION_REFUSED,
                    "expected CONNECTION_REFUSED, got: {:?}",
                    close
                );
            }
            other => panic!(
                "expected pre-handshake ConnectionClosed(CONNECTION_REFUSED), got: {:?}",
                other
            ),
        }
    }

    #[test]
    fn validate_options_rejects_unpaired_cert_or_key_and_zero_limits() {
        let defaults = Opt::try_parse_from(["server"]).expect("parse defaults");
        assert_eq!(defaults.max_connections, DEFAULT_MAX_CONNECTIONS);
        assert_eq!(
            defaults.max_connections_per_ip,
            DEFAULT_MAX_CONNECTIONS_PER_IP
        );
        assert!(!defaults.no_retry);
        assert!(validate_options(&defaults).is_ok());

        let only_cert =
            Opt::try_parse_from(["server", "--cert", "/tmp/cert.pem"]).expect("parse only cert");
        assert!(validate_options(&only_cert).is_err());
        assert!(
            configure_server(only_cert.cert.as_deref(), only_cert.key.as_deref(), None).is_err()
        );

        let only_key =
            Opt::try_parse_from(["server", "--key", "/tmp/key.pem"]).expect("parse only key");
        assert!(validate_options(&only_key).is_err());
        assert!(configure_server(only_key.cert.as_deref(), only_key.key.as_deref(), None).is_err());

        let zero_max =
            Opt::try_parse_from(["server", "--max-connections", "0"]).expect("parse zero max");
        assert!(validate_options(&zero_max).is_err());

        let zero_per_ip = Opt::try_parse_from(["server", "--max-connections-per-ip", "0"])
            .expect("parse zero per ip");
        assert!(validate_options(&zero_per_ip).is_err());
    }

    #[test]
    fn normalize_client_ip_masks_ipv6_to_slash_64_and_preserves_ipv4() {
        let v4_a: IpAddr = "192.0.2.1".parse().unwrap();
        let v4_b: IpAddr = "192.0.2.2".parse().unwrap();
        assert_eq!(normalize_client_ip(v4_a), v4_a);
        assert_eq!(normalize_client_ip(v4_b), v4_b);
        assert_ne!(normalize_client_ip(v4_a), normalize_client_ip(v4_b));

        let v6_same_1: IpAddr = "2001:db8:abcd:1234::1".parse().unwrap();
        let v6_same_2: IpAddr = "2001:db8:abcd:1234:ffff:eeee:dddd:cccc".parse().unwrap();
        let v6_prefix: IpAddr = "2001:db8:abcd:1234::".parse().unwrap();
        assert_eq!(normalize_client_ip(v6_same_1), v6_prefix);
        assert_eq!(normalize_client_ip(v6_same_2), v6_prefix);

        let v6_other: IpAddr = "2001:db8:abcd:1235::1".parse().unwrap();
        let v6_other_prefix: IpAddr = "2001:db8:abcd:1235::".parse().unwrap();
        assert_eq!(normalize_client_ip(v6_other), v6_other_prefix);
        assert_ne!(
            normalize_client_ip(v6_same_1),
            normalize_client_ip(v6_other)
        );

        // IPv4-mapped IPv6 addresses should unmap to their distinct IPv4 addresses.
        let v4_mapped_1: IpAddr = "::ffff:192.0.2.1".parse().unwrap();
        let v4_mapped_2: IpAddr = "::ffff:192.0.2.2".parse().unwrap();
        assert_eq!(normalize_client_ip(v4_mapped_1), v4_a);
        assert_eq!(normalize_client_ip(v4_mapped_2), v4_b);
    }

    #[test]
    fn format_sha256_fingerprint_matches_known_vectors() {
        assert_eq!(
            format_sha256_fingerprint(b""),
            "E3:B0:C4:42:98:FC:1C:14:9A:FB:F4:C8:99:6F:B9:24:27:AE:41:E4:64:9B:93:4C:A4:95:99:1B:78:52:B8:55"
        );
        assert_eq!(
            format_sha256_fingerprint(b"abc"),
            "BA:78:16:BF:8F:01:CF:EA:41:41:40:DE:5D:AE:22:23:B0:03:61:A3:96:17:7A:9C:B4:10:FF:61:F2:00:15:AD"
        );
    }

    #[test]
    fn ip_counter_guard_enforces_per_ip_limit_and_cleans_up_on_drop() {
        let counts = Arc::new(Mutex::new(HashMap::new()));
        let ip1: IpAddr = Ipv4Addr::LOCALHOST.into();
        let ip2: IpAddr = Ipv4Addr::new(127, 0, 0, 2).into();

        assert!(!is_ip_at_limit(&counts, ip1, 2));
        let g1 = IpCounterGuard::try_acquire(Arc::clone(&counts), ip1, 2).expect("slot 1");
        assert!(!is_ip_at_limit(&counts, ip1, 2));
        let g2 = IpCounterGuard::try_acquire(Arc::clone(&counts), ip1, 2).expect("slot 2");
        assert!(is_ip_at_limit(&counts, ip1, 2));
        assert!(IpCounterGuard::try_acquire(Arc::clone(&counts), ip1, 2).is_none());

        // Independent IP still has its own budget.
        assert!(!is_ip_at_limit(&counts, ip2, 2));
        let g_other =
            IpCounterGuard::try_acquire(Arc::clone(&counts), ip2, 2).expect("other ip slot");

        drop(g1);
        assert!(!is_ip_at_limit(&counts, ip1, 2));
        assert_eq!(counts.lock().unwrap().get(&ip1).copied(), Some(1));
        let g3 = IpCounterGuard::try_acquire(Arc::clone(&counts), ip1, 2).expect("re-acquired");
        drop(g2);
        drop(g3);
        assert!(!counts.lock().unwrap().contains_key(&ip1));

        drop(g_other);
        assert!(counts.lock().unwrap().is_empty());
    }

    #[test]
    fn log_rate_limiter_emits_first_suppresses_burst_and_reports_suppressed_count() {
        let limiter = LogRateLimiter::new(Duration::from_millis(30));

        assert_eq!(limiter.check(), Some(0));
        assert_eq!(limiter.check(), None);
        assert_eq!(limiter.check(), None);
        assert_eq!(limiter.check(), None);

        std::thread::sleep(Duration::from_millis(45));
        assert_eq!(limiter.check(), Some(3));
        assert_eq!(limiter.check(), None);

        std::thread::sleep(Duration::from_millis(45));
        assert_eq!(limiter.check(), Some(1));
    }

    #[test]
    fn server_conf_rejects_unknown_top_level_fields() {
        let unknown_field = r#"
unexpected_option = true
[proxy]
"example.com" = "127.0.0.1:2201"
"#;
        assert!(
            parse_server_conf(unknown_field).is_err(),
            "ServerConf must reject unknown top-level TOML fields"
        );
    }

    #[test]
    fn sni_config_normalization_duplicate_rejection_and_precedence() {
        let toml_cfg = r#"
[proxy]
"HostA.Example.COM" = "127.0.0.1:2201"
"127.0.0.1" = "127.0.0.1:2299"
"Default" = "127.0.0.1:2200"
"#;
        let ParsedServerConf {
            proxy_map,
            default_proxy: config_default,
        } = parse_server_conf(toml_cfg).expect("parse valid server conf");
        let cfg_default_addr: SocketAddr = "127.0.0.1:2200".parse().unwrap();
        let cli_opt = Opt::try_parse_from(["server", "--proxy-to", "127.0.0.1:2222"])
            .expect("parse cli proxy-to");
        let cli_default_addr = cli_opt.proxy_to.expect("cli proxy-to set");
        let host_a_addr: SocketAddr = "127.0.0.1:2201".parse().unwrap();
        let fallback_addr: SocketAddr = "127.0.0.1:22".parse().unwrap();

        assert_eq!(config_default, Some(cfg_default_addr));
        assert!(!proxy_map.contains_key("default"));
        assert_eq!(
            proxy_map.get("hosta.example.com").copied(),
            Some(host_a_addr)
        );

        // Case-insensitive lookup works for both lowercase and mixed-case SNI.
        assert_eq!(
            resolve_proxy(Some("hosta.example.com"), &proxy_map, cfg_default_addr),
            host_a_addr
        );
        assert_eq!(
            resolve_proxy(Some("HOSTA.EXAMPLE.COM"), &proxy_map, cfg_default_addr),
            host_a_addr
        );

        // Missing SNI must route to default_proxy, never to an IP entry in proxy_map.
        assert_eq!(
            resolve_proxy(None, &proxy_map, cfg_default_addr),
            cfg_default_addr
        );

        // Precedence: CLI --proxy-to > [proxy].default > 127.0.0.1:22.
        assert_eq!(
            resolve_default_proxy(Some(cli_default_addr), config_default),
            cli_default_addr
        );
        assert_eq!(
            resolve_default_proxy(None, config_default),
            cfg_default_addr
        );
        assert_eq!(resolve_default_proxy(None, None), fallback_addr);

        // Duplicate keys after ASCII lowercasing must fail fast.
        let dup_host = r#"
[proxy]
"Example.com" = "127.0.0.1:2201"
"example.com" = "127.0.0.1:2202"
"#;
        assert!(parse_server_conf(dup_host).is_err());

        let dup_default = r#"
[proxy]
"Default" = "127.0.0.1:2201"
"default" = "127.0.0.1:2202"
"#;
        assert!(parse_server_conf(dup_default).is_err());
    }

    #[test]
    fn load_pem_cert_key_and_client_ca_validation() {
        let dir = TestTempDir::new("pem-load");
        let fixtures = MtlsFixtures::create(&dir);

        let empty_path = dir.path().join("empty.pem");
        let bad_der_ca_path = dir.path().join("bad-ca.pem");
        fs::write(&empty_path, "").expect("write empty pem");
        fs::write(
            &bad_der_ca_path,
            "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n",
        )
        .expect("write bad ca pem");

        let expected_cert = load_cert_chain(&fixtures.cert_path).expect("reload server cert");
        let (_, cert_der) = configure_server(
            Some(&fixtures.cert_path),
            Some(&fixtures.key_path),
            Some(&fixtures.ca_path),
        )
        .expect("configure mTLS server");
        assert_eq!(cert_der, expected_cert[0].as_ref());

        // Empty cert file and empty/invalid CA file must fail fast.
        assert!(configure_server(Some(&empty_path), Some(&fixtures.key_path), None).is_err());
        assert!(build_client_verifier(&empty_path).is_err());
        assert!(build_client_verifier(&bad_der_ca_path).is_err());
    }

    #[tokio::test]
    async fn mtls_enforces_client_certificate_verification() {
        let dir = TestTempDir::new("mtls-handshake");
        let fixtures = MtlsFixtures::create(&dir);

        let (server_config, _) = configure_server(
            Some(&fixtures.cert_path),
            Some(&fixtures.key_path),
            Some(&fixtures.ca_path),
        )
        .expect("configure mTLS server");
        let server_endpoint = Endpoint::server(
            server_config,
            SocketAddr::new(Ipv4Addr::LOCALHOST.into(), 0),
        )
        .expect("server endpoint");
        let server_addr = server_endpoint.local_addr().expect("server addr");

        // Unauthenticated client must be rejected by the mTLS server.
        let unauth_client = make_client_endpoint(&fixtures.ca_der, None);
        let server_accept = tokio::spawn({
            let ep = server_endpoint.clone();
            async move { ep.accept().await.expect("incoming").await }
        });
        let unauth_result = unauth_client
            .connect(server_addr, "localhost")
            .expect("start connect")
            .await;
        assert!(
            server_accept.await.expect("join").is_err(),
            "server must reject client without certificate"
        );
        if let Ok(conn) = unauth_result {
            let close_err = tokio::time::timeout(Duration::from_secs(2), conn.closed())
                .await
                .expect("client should observe TLS rejection promptly");
            assert!(
                matches!(
                    close_err,
                    quinn::ConnectionError::ConnectionClosed(_)
                        | quinn::ConnectionError::TransportError(_)
                ),
                "expected TLS close/transport error on rejected client, got: {:?}",
                close_err
            );
        }

        // Client with CA-signed certificate must succeed.
        let auth_client = make_client_endpoint(&fixtures.ca_der, Some(fixtures.client_identity()));
        let server_accept = tokio::spawn({
            let ep = server_endpoint.clone();
            async move { ep.accept().await.expect("incoming").await }
        });
        let auth_conn = auth_client
            .connect(server_addr, "localhost")
            .expect("start connect")
            .await
            .expect("mTLS client handshake should succeed");
        let server_conn = server_accept
            .await
            .expect("join")
            .expect("mTLS server handshake should succeed");
        assert_eq!(extract_sni(&server_conn).as_deref(), Some("localhost"));

        auth_conn.close(0u32.into(), b"done");
        server_endpoint.close(0u32.into(), b"shutdown");
    }

    #[tokio::test]
    async fn mtls_rejects_expired_and_server_auth_only_client_certs() {
        let dir = TestTempDir::new("mtls-expired-eku");
        let fixtures = MtlsFixtures::create(&dir);

        let (server_config, _) = configure_server(
            Some(&fixtures.cert_path),
            Some(&fixtures.key_path),
            Some(&fixtures.ca_path),
        )
        .expect("configure mTLS server");
        let server_endpoint = Endpoint::server(
            server_config,
            SocketAddr::new(Ipv4Addr::LOCALHOST.into(), 0),
        )
        .expect("server endpoint");
        let server_addr = server_endpoint.local_addr().expect("server addr");

        // 1. Expired client certificate must be rejected.
        let expired_client =
            make_client_endpoint(&fixtures.ca_der, Some(fixtures.expired_client_identity()));
        let server_accept = tokio::spawn({
            let ep = server_endpoint.clone();
            async move { ep.accept().await.expect("incoming").await }
        });
        let expired_res = expired_client
            .connect(server_addr, "localhost")
            .expect("connect expired")
            .await;
        assert!(
            server_accept.await.expect("join").is_err(),
            "server must reject expired client certificate"
        );
        if let Ok(conn) = expired_res {
            let close_err = tokio::time::timeout(Duration::from_secs(2), conn.closed())
                .await
                .expect("expired client should observe TLS rejection promptly");
            assert!(
                matches!(
                    close_err,
                    quinn::ConnectionError::ConnectionClosed(_)
                        | quinn::ConnectionError::TransportError(_)
                ),
                "expected TLS close/transport error for expired client cert, got: {:?}",
                close_err
            );
        }

        // 2. Client certificate with ServerAuth-only EKU must be rejected.
        let wrong_eku_client = make_client_endpoint(
            &fixtures.ca_der,
            Some(fixtures.server_auth_client_identity()),
        );
        let server_accept = tokio::spawn({
            let ep = server_endpoint.clone();
            async move { ep.accept().await.expect("incoming").await }
        });
        let wrong_eku_res = wrong_eku_client
            .connect(server_addr, "localhost")
            .expect("connect server-auth eku")
            .await;
        assert!(
            server_accept.await.expect("join").is_err(),
            "server must reject client certificate with ServerAuth-only EKU"
        );
        if let Ok(conn) = wrong_eku_res {
            let close_err = tokio::time::timeout(Duration::from_secs(2), conn.closed())
                .await
                .expect("ServerAuth-only client should observe TLS rejection promptly");
            assert!(
                matches!(
                    close_err,
                    quinn::ConnectionError::ConnectionClosed(_)
                        | quinn::ConnectionError::TransportError(_)
                ),
                "expected TLS close/transport error for ServerAuth-only EKU cert, got: {:?}",
                close_err
            );
        }

        // 3. Valid ClientAuth certificate signed by the same CA still succeeds.
        let valid_client = make_client_endpoint(&fixtures.ca_der, Some(fixtures.client_identity()));
        let server_accept = tokio::spawn({
            let ep = server_endpoint.clone();
            async move { ep.accept().await.expect("incoming").await }
        });
        let valid_conn = valid_client
            .connect(server_addr, "localhost")
            .expect("connect valid")
            .await
            .expect("valid mTLS client should succeed");
        server_accept
            .await
            .expect("join")
            .expect("server should accept valid mTLS client");

        valid_conn.close(0u32.into(), b"done");
        server_endpoint.close(0u32.into(), b"shutdown");
    }

    #[tokio::test]
    async fn accept_bi_times_out_before_connecting_to_backend() {
        let backend_listener = TcpListener::bind(SocketAddr::new(Ipv4Addr::LOCALHOST.into(), 0))
            .await
            .expect("bind backend tcp");
        let backend_addr = backend_listener.local_addr().expect("backend addr");

        let (server_config, server_cert_der) =
            configure_server(None, None, None).expect("configure ephemeral server");
        let server_endpoint = Endpoint::server(
            server_config,
            SocketAddr::new(Ipv4Addr::LOCALHOST.into(), 0),
        )
        .expect("server endpoint");
        let server_addr = server_endpoint.local_addr().expect("server addr");

        let client_endpoint = make_client_endpoint(&server_cert_der, None);

        let (client_res, server_res) = tokio::join!(
            async {
                client_endpoint
                    .connect(server_addr, "localhost")
                    .expect("connect")
                    .await
            },
            async { server_endpoint.accept().await.expect("incoming").await }
        );
        let _client_conn = client_res.expect("client connected");
        let server_conn = server_res.expect("server accepted");

        // Client never opens a bidi stream; handle_connection_with_timeouts must time out quickly
        // without opening a TCP connection to the backend.
        let start = tokio::time::Instant::now();
        handle_connection_with_timeouts(
            backend_addr,
            server_conn,
            Duration::from_millis(120),
            Duration::from_secs(1),
            Duration::from_millis(150),
            Arc::new(LogRateLimiter::new(Duration::from_secs(1))),
        )
        .await;
        assert!(start.elapsed() < Duration::from_secs(2));

        let tcp_accept =
            tokio::time::timeout(Duration::from_millis(50), backend_listener.accept()).await;
        assert!(
            tcp_accept.is_err(),
            "backend TCP connection must not be opened before accept_bi succeeds"
        );

        server_endpoint.close(0u32.into(), b"shutdown");
    }

    #[tokio::test]
    async fn transport_limits_disable_datagrams_uni_streams_and_extra_bidi_streams() {
        let (server_config, server_cert_der) =
            configure_server(None, None, None).expect("configure ephemeral server");
        let server_endpoint = Endpoint::server(
            server_config,
            SocketAddr::new(Ipv4Addr::LOCALHOST.into(), 0),
        )
        .expect("server endpoint");
        let server_addr = server_endpoint.local_addr().expect("server addr");

        let client_endpoint = make_client_endpoint(&server_cert_der, None);
        let (client_res, server_res) = tokio::join!(
            async {
                client_endpoint
                    .connect(server_addr, "localhost")
                    .expect("connect")
                    .await
            },
            async { server_endpoint.accept().await.expect("incoming").await }
        );
        let client_conn = client_res.expect("client connected");
        let server_conn = server_res.expect("server accepted");

        // Server explicitly disables QUIC datagrams (datagram_receive_buffer_size(None)).
        assert_eq!(client_conn.max_datagram_size(), None);

        // Server sets max_concurrent_uni_streams = 0, so client open_uni must block.
        assert!(
            tokio::time::timeout(Duration::from_millis(150), client_conn.open_uni())
                .await
                .is_err(),
            "unidirectional stream must be blocked by server transport limit 0"
        );

        // Server sets max_concurrent_bidi_streams = 1: first open_bi succeeds, second blocks
        // while the first stream remains open.
        let (mut send1, _recv1) = client_conn.open_bi().await.expect("first bidi stream");
        send1.write_all(b"hi").await.expect("write on first stream");
        let (_srv_send, mut srv_recv) = server_conn.accept_bi().await.expect("server accept_bi");
        let mut buf = [0u8; 2];
        srv_recv
            .read_exact(&mut buf)
            .await
            .expect("server read first stream");
        assert_eq!(&buf, b"hi");

        assert!(
            tokio::time::timeout(Duration::from_millis(150), client_conn.open_bi())
                .await
                .is_err(),
            "second concurrent bidi stream must be blocked while first is open"
        );

        client_conn.close(0u32.into(), b"done");
        server_endpoint.close(0u32.into(), b"shutdown");
    }

    #[tokio::test]
    async fn half_close_drains_backend_reply_after_client_fin() {
        let backend_listener = TcpListener::bind(SocketAddr::new(Ipv4Addr::LOCALHOST.into(), 0))
            .await
            .expect("bind backend tcp");
        let backend_addr = backend_listener.local_addr().expect("backend addr");

        let payload = b"client-half-close-payload";
        let reply = b"backend-reply-after-tcp-eof";

        let backend_task = tokio::spawn(async move {
            let (mut stream, _) = backend_listener.accept().await.expect("accept backend");
            // Backend waits for full TCP EOF before writing its reply and closing.
            let mut received = Vec::new();
            stream
                .read_to_end(&mut received)
                .await
                .expect("read until tcp eof");
            assert_eq!(received, payload);
            stream.write_all(reply).await.expect("write backend reply");
            stream.shutdown().await.expect("shutdown backend write");
        });

        let (server_config, server_cert_der) =
            configure_server(None, None, None).expect("configure ephemeral server");
        let server_endpoint = Endpoint::server(
            server_config,
            SocketAddr::new(Ipv4Addr::LOCALHOST.into(), 0),
        )
        .expect("server endpoint");
        let server_addr = server_endpoint.local_addr().expect("server addr");

        let server_task = tokio::spawn(serve_endpoint(
            server_endpoint.clone(),
            test_serve_config(backend_addr),
        ));

        let client_endpoint = make_client_endpoint(&server_cert_der, None);
        let client_conn = client_endpoint
            .connect(server_addr, "localhost")
            .expect("connect")
            .await
            .expect("handshake");

        let (mut send, mut recv) = client_conn.open_bi().await.expect("open_bi");
        send.write_all(payload).await.expect("write payload");
        send.finish().expect("finish client send stream");

        let mut received_reply = Vec::new();
        let mut buf = [0u8; 64];
        let saw_fin = tokio::time::timeout(Duration::from_secs(3), async {
            loop {
                match recv.read(&mut buf).await.expect("read reply chunk") {
                    Some(n) => received_reply.extend_from_slice(&buf[..n]),
                    None => break true,
                }
            }
        })
        .await
        .expect("timed out waiting for backend reply and QUIC FIN");

        assert!(saw_fin);
        assert_eq!(received_reply, reply);

        backend_task.await.expect("backend task");
        client_conn.close(0u32.into(), b"done");
        server_endpoint.close(0u32.into(), b"shutdown");
        tokio::time::timeout(Duration::from_secs(2), server_task)
            .await
            .expect("serve_endpoint exit")
            .expect("serve_endpoint join");
    }

    #[tokio::test]
    async fn backend_eof_closes_connection_after_grace_timeout_when_client_stays_open() {
        let backend_listener = TcpListener::bind(SocketAddr::new(Ipv4Addr::LOCALHOST.into(), 0))
            .await
            .expect("bind backend tcp");
        let backend_addr = backend_listener.local_addr().expect("backend addr");

        let backend_task = tokio::spawn(async move {
            let (mut stream, _) = backend_listener.accept().await.expect("accept backend");
            let mut req = [0u8; 5];
            stream.read_exact(&mut req).await.expect("read hello");
            assert_eq!(&req, b"hello");
            stream.write_all(b"banner").await.expect("write banner");
            // Gracefully close TCP without waiting for client EOF.
            stream.shutdown().await.expect("shutdown backend");
            drop(stream);
        });

        let (server_config, server_cert_der) =
            configure_server(None, None, None).expect("configure ephemeral server");
        let server_endpoint = Endpoint::server(
            server_config,
            SocketAddr::new(Ipv4Addr::LOCALHOST.into(), 0),
        )
        .expect("server endpoint");
        let server_addr = server_endpoint.local_addr().expect("server addr");

        // Keep-alive PINGs keep the QUIC connection alive indefinitely unless server closes it.
        let client_endpoint = make_client_endpoint_with_opts(
            &server_cert_der,
            None,
            true,
            Some(Duration::from_millis(40)),
        );

        let (client_res, server_res) = tokio::join!(
            async {
                client_endpoint
                    .connect(server_addr, "localhost")
                    .expect("connect")
                    .await
            },
            async { server_endpoint.accept().await.expect("incoming").await }
        );
        let client_conn = client_res.expect("client connected");
        let server_conn = server_res.expect("server accepted");

        let (mut client_send, mut client_recv) = client_conn.open_bi().await.expect("open_bi");
        client_send.write_all(b"hello").await.expect("write hello");
        // Intentionally never call client_send.finish() so the client keeps its send stream open.

        let start = tokio::time::Instant::now();
        let handler_task = tokio::spawn(handle_connection_with_timeouts(
            backend_addr,
            server_conn,
            Duration::from_secs(1),
            Duration::from_secs(1),
            Duration::from_millis(150),
            Arc::new(LogRateLimiter::new(Duration::from_secs(1))),
        ));

        let received = tokio::time::timeout(Duration::from_secs(2), client_recv.read_to_end(64))
            .await
            .expect("read banner timeout")
            .expect("read banner");
        assert_eq!(received, b"banner");

        // Keep client_send alive while verifying handle_connection_with_timeouts returns promptly.
        tokio::time::timeout(Duration::from_secs(1), handler_task)
            .await
            .expect("handle_connection_with_timeouts must exit after backend_eof_grace_timeout")
            .expect("handler join");
        assert!(
            start.elapsed() < Duration::from_secs(1),
            "handler took too long to close after backend EOF: {:?}",
            start.elapsed()
        );

        assert_application_closed(Ok(client_conn), 0, b"backend closed").await;
        drop(client_send);
        backend_task.await.expect("backend task");
        server_endpoint.close(0u32.into(), b"shutdown");
    }

    #[tokio::test]
    async fn backend_eof_releases_slot_for_next_client_under_max_connections_one() {
        let backend_listener = TcpListener::bind(SocketAddr::new(Ipv4Addr::LOCALHOST.into(), 0))
            .await
            .expect("bind backend tcp");
        let backend_addr = backend_listener.local_addr().expect("backend addr");

        let backend_task = tokio::spawn(async move {
            // Connection 1: drain client's opening byte, send one chunk, and close TCP cleanly.
            let (mut s1, _) = backend_listener.accept().await.expect("accept backend 1");
            let mut req1 = [0u8; 1];
            s1.read_exact(&mut req1).await.expect("read first req");
            assert_eq!(&req1, b"a");
            s1.write_all(b"first").await.expect("write first");
            s1.shutdown().await.expect("shutdown backend 1");
            drop(s1);

            // Connection 2: echo 6 bytes to prove the single slot was released cleanly.
            let (mut s2, _) = backend_listener.accept().await.expect("accept backend 2");
            let mut buf = [0u8; 6];
            s2.read_exact(&mut buf).await.expect("read second");
            s2.write_all(&buf).await.expect("write second");
        });

        let (server_config, server_cert_der) =
            configure_server(None, None, None).expect("configure ephemeral server");
        let server_endpoint = Endpoint::server(
            server_config,
            SocketAddr::new(Ipv4Addr::LOCALHOST.into(), 0),
        )
        .expect("server endpoint");
        let server_addr = server_endpoint.local_addr().expect("server addr");

        let server_task = tokio::spawn(serve_endpoint(
            server_endpoint.clone(),
            ServeConfig {
                max_connections: 1,
                backend_eof_grace_timeout: Duration::from_millis(150),
                ..test_serve_config(backend_addr)
            },
        ));

        // Client 1 stays alive with keep-alive PINGs and never sends FIN after backend EOF.
        let client1 = make_client_endpoint_with_opts(
            &server_cert_der,
            None,
            true,
            Some(Duration::from_millis(40)),
        );
        let conn1 = client1
            .connect(server_addr, "localhost")
            .expect("connect 1")
            .await
            .expect("handshake 1");
        let (mut send1, mut recv1) = conn1.open_bi().await.expect("open_bi 1");
        send1.write_all(b"a").await.expect("write 1");
        let first_reply = tokio::time::timeout(Duration::from_secs(2), recv1.read_to_end(64))
            .await
            .expect("read first timeout")
            .expect("read first");
        assert_eq!(first_reply, b"first");

        // Server must close client 1 after the grace timeout even though send1 is still held.
        assert_application_closed(Ok(conn1), 0, b"backend closed").await;
        drop(send1);
        tokio::time::sleep(Duration::from_millis(30)).await;

        // Client 2 must immediately succeed on the freed single connection slot.
        let client2 = make_client_endpoint(&server_cert_der, None);
        let conn2 = tokio::time::timeout(
            Duration::from_secs(2),
            client2
                .connect(server_addr, "localhost")
                .expect("connect 2"),
        )
        .await
        .expect("client2 connect timeout")
        .expect("client2 must succeed after client1 slot is freed");
        let (mut send2, mut recv2) = conn2.open_bi().await.expect("open_bi 2");
        send2.write_all(b"second").await.expect("write 2");
        let mut resp2 = [0u8; 6];
        recv2.read_exact(&mut resp2).await.expect("read 2");
        assert_eq!(&resp2, b"second");

        drop(send2);
        drop(recv2);
        conn2.close(0u32.into(), b"done");
        backend_task.await.expect("backend task");

        server_endpoint.close(0u32.into(), b"shutdown");
        tokio::time::timeout(Duration::from_secs(2), server_task)
            .await
            .expect("serve_endpoint exit")
            .expect("serve_endpoint join");
    }

    #[tokio::test]
    async fn retry_validates_remote_address_before_handshake() {
        let (server_config, server_cert_der) =
            configure_server(None, None, None).expect("configure ephemeral server");
        let server_endpoint = Endpoint::server(
            server_config,
            SocketAddr::new(Ipv4Addr::LOCALHOST.into(), 0),
        )
        .expect("server endpoint");
        let server_addr = server_endpoint.local_addr().expect("server addr");

        let client_endpoint = make_client_endpoint(&server_cert_der, None);
        let client_connect = tokio::spawn({
            let ep = client_endpoint.clone();
            async move { ep.connect(server_addr, "localhost").expect("connect").await }
        });

        // Post-quantum ClientHello can span multiple Initial packets before the client processes
        // Retry; reply with Retry to every unvalidated Initial until the retried Initial arrives.
        let mut retries_sent = 0usize;
        let validated_incoming = tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                let incoming = server_endpoint.accept().await.expect("incoming");
                if !incoming.remote_address_validated() {
                    retries_sent += 1;
                    incoming.retry().expect("send retry packet");
                    continue;
                }
                break incoming;
            }
        })
        .await
        .expect("timed out waiting for address-validated incoming after retry");
        assert!(
            retries_sent >= 1,
            "initial attempt must trigger at least one Retry packet"
        );
        assert!(
            validated_incoming.remote_address_validated(),
            "retried incoming must have remote_address_validated() == true"
        );

        let server_conn = validated_incoming
            .await
            .expect("server handshake after retry");
        let client_conn = client_connect
            .await
            .expect("client join")
            .expect("client handshake after retry");
        assert_eq!(extract_sni(&server_conn).as_deref(), Some("localhost"));

        client_conn.close(0u32.into(), b"done");
        server_endpoint.close(0u32.into(), b"shutdown");
    }

    #[tokio::test]
    async fn stalled_handshake_does_not_block_other_connections() {
        let backend_listener = TcpListener::bind(SocketAddr::new(Ipv4Addr::LOCALHOST.into(), 0))
            .await
            .expect("bind backend tcp");
        let backend_addr = backend_listener.local_addr().expect("backend addr");

        let backend_task = tokio::spawn(async move {
            let (mut stream, _) = backend_listener.accept().await.expect("accept backend");
            let mut buf = [0u8; 32];
            let n = stream.read(&mut buf).await.expect("read backend");
            stream.write_all(&buf[..n]).await.expect("write backend");
            let _ = stream.read(&mut buf).await;
        });

        let (server_config, server_cert_der) =
            configure_server(None, None, None).expect("configure ephemeral server");
        let server_endpoint = Endpoint::server(
            server_config,
            SocketAddr::new(Ipv4Addr::LOCALHOST.into(), 0),
        )
        .expect("server endpoint");
        let server_addr = server_endpoint.local_addr().expect("server addr");

        // Long handshake timeout (5s): if the accept loop awaited handshakes inline, the second
        // client below would stall past its 2s timeout.
        let server_task = tokio::spawn(serve_endpoint(
            server_endpoint.clone(),
            ServeConfig {
                handshake_timeout: Duration::from_secs(5),
                ..test_serve_config(backend_addr)
            },
        ));

        let _stalled = inject_stalled_handshake(server_addr, &server_cert_der).await;
        tokio::time::sleep(Duration::from_millis(50)).await;

        // A legitimate client must still complete handshake + stream relay immediately.
        let client_endpoint = make_client_endpoint(&server_cert_der, None);
        let client_conn = tokio::time::timeout(
            Duration::from_secs(2),
            client_endpoint
                .connect(server_addr, "localhost")
                .expect("connect"),
        )
        .await
        .expect("client connect must not be head-of-line blocked")
        .expect("client handshake");

        let (mut send, mut recv) = client_conn.open_bi().await.expect("open_bi");
        send.write_all(b"ping").await.expect("write ping");
        let mut resp = [0u8; 4];
        recv.read_exact(&mut resp).await.expect("read echo");
        assert_eq!(&resp, b"ping");

        drop(send);
        drop(recv);
        client_conn.close(0u32.into(), b"done");
        backend_task.await.expect("backend task");

        // Closing the endpoint must exit serve_endpoint cleanly (no infinite spin on None).
        server_endpoint.close(0u32.into(), b"shutdown");
        tokio::time::timeout(Duration::from_secs(2), server_task)
            .await
            .expect("serve_endpoint should exit on endpoint close")
            .expect("serve_endpoint join");
    }

    #[tokio::test]
    async fn stalled_handshakes_do_not_exhaust_conn_slots_and_cap_per_ip() {
        let dir = TestTempDir::new("m1-mtls");
        let fixtures = MtlsFixtures::create(&dir);

        let backend_listener = TcpListener::bind(SocketAddr::new(Ipv4Addr::LOCALHOST.into(), 0))
            .await
            .expect("bind backend tcp");
        let backend_addr = backend_listener.local_addr().expect("backend addr");

        let backend_task = tokio::spawn(async move {
            let (mut stream, _) = backend_listener.accept().await.expect("accept backend");
            let mut buf = [0u8; 4];
            let n = stream.read(&mut buf).await.expect("read backend");
            stream.write_all(&buf[..n]).await.expect("write backend");
            let _ = stream.read(&mut buf).await;
        });

        let (server_config, _) = configure_server(
            Some(&fixtures.cert_path),
            Some(&fixtures.key_path),
            Some(&fixtures.ca_path),
        )
        .expect("configure mTLS server");
        let server_endpoint = Endpoint::server(
            server_config,
            SocketAddr::new(Ipv4Addr::LOCALHOST.into(), 0),
        )
        .expect("server endpoint");
        let server_addr = server_endpoint.local_addr().expect("server addr");

        // Only 1 authenticated connection slot, but handshake slots are separate (per-IP cap = 2).
        let server_task = tokio::spawn(serve_endpoint(
            server_endpoint.clone(),
            ServeConfig {
                max_connections: 1,
                max_in_flight_handshakes: 4,
                max_handshakes_per_ip: 2,
                handshake_timeout: Duration::from_secs(5),
                ..test_serve_config(backend_addr)
            },
        ));

        // 1 stalled unauthenticated handshake must NOT consume the single conn_semaphore slot.
        let _stalled1 = inject_stalled_handshake(server_addr, &fixtures.ca_der).await;
        tokio::time::sleep(Duration::from_millis(50)).await;

        let auth_client = make_client_endpoint(&fixtures.ca_der, Some(fixtures.client_identity()));
        let auth_conn = tokio::time::timeout(
            Duration::from_secs(2),
            auth_client
                .connect(server_addr, "localhost")
                .expect("connect auth client"),
        )
        .await
        .expect("auth client must not be blocked by stalled handshake")
        .expect("mTLS handshake must succeed despite 1 stalled handshake and max_connections = 1");

        let (mut send, mut recv) = auth_conn.open_bi().await.expect("open_bi");
        send.write_all(b"auth").await.expect("write auth");
        let mut resp = [0u8; 4];
        recv.read_exact(&mut resp).await.expect("read auth echo");
        assert_eq!(&resp, b"auth");

        drop(send);
        drop(recv);
        auth_conn.close(0u32.into(), b"done");
        backend_task.await.expect("backend task");
        tokio::time::sleep(Duration::from_millis(30)).await;

        // Adding a second stalled handshake from the same IP saturates max_handshakes_per_ip = 2.
        let _stalled2 = inject_stalled_handshake(server_addr, &fixtures.ca_der).await;
        tokio::time::sleep(Duration::from_millis(50)).await;

        let capped_client =
            make_client_endpoint(&fixtures.ca_der, Some(fixtures.client_identity()));
        let capped_res = tokio::time::timeout(
            Duration::from_secs(2),
            capped_client
                .connect(server_addr, "localhost")
                .expect("connect capped client"),
        )
        .await
        .expect("per-IP refusal should return promptly");
        assert_connection_refused(capped_res);

        server_endpoint.close(0u32.into(), b"shutdown");
        tokio::time::timeout(Duration::from_secs(2), server_task)
            .await
            .expect("serve_endpoint exit")
            .expect("serve_endpoint join");
    }

    #[tokio::test]
    async fn handshake_timeout_releases_handshake_permit_and_ip_guard() {
        let backend_listener = TcpListener::bind(SocketAddr::new(Ipv4Addr::LOCALHOST.into(), 0))
            .await
            .expect("bind backend tcp");
        let backend_addr = backend_listener.local_addr().expect("backend addr");

        let backend_task = tokio::spawn(async move {
            let (mut stream, _) = backend_listener.accept().await.expect("accept backend");
            let mut buf = [0u8; 2];
            let n = stream.read(&mut buf).await.expect("read backend");
            stream.write_all(&buf[..n]).await.expect("write backend");
            let _ = stream.read(&mut buf).await;
        });

        let (server_config, server_cert_der) =
            configure_server(None, None, None).expect("configure ephemeral server");
        let server_endpoint = Endpoint::server(
            server_config,
            SocketAddr::new(Ipv4Addr::LOCALHOST.into(), 0),
        )
        .expect("server endpoint");
        let server_addr = server_endpoint.local_addr().expect("server addr");

        let server_task = tokio::spawn(serve_endpoint(
            server_endpoint.clone(),
            ServeConfig {
                max_connections: 1,
                max_in_flight_handshakes: 1,
                max_handshakes_per_ip: 1,
                handshake_timeout: Duration::from_millis(150),
                ..test_serve_config(backend_addr)
            },
        ));

        // Saturate both the single global handshake slot and single per-IP slot.
        let _stalled = inject_stalled_handshake(server_addr, &server_cert_der).await;
        tokio::time::sleep(Duration::from_millis(30)).await;

        let blocked_client = make_client_endpoint(&server_cert_der, None);
        let blocked_res = tokio::time::timeout(
            Duration::from_secs(1),
            blocked_client
                .connect(server_addr, "localhost")
                .expect("connect while saturated"),
        )
        .await
        .expect("refusal should be immediate");
        assert_connection_refused(blocked_res);

        // Wait for the stalled handshake to time out and release both guards.
        tokio::time::sleep(Duration::from_millis(220)).await;

        let client = make_client_endpoint(&server_cert_der, None);
        let conn = tokio::time::timeout(
            Duration::from_secs(2),
            client
                .connect(server_addr, "localhost")
                .expect("connect after timeout release"),
        )
        .await
        .expect("connect timeout after release")
        .expect("handshake must succeed once timed-out handshake releases guards");

        let (mut send, mut recv) = conn.open_bi().await.expect("open_bi");
        send.write_all(b"ok").await.expect("write ok");
        let mut resp = [0u8; 2];
        recv.read_exact(&mut resp).await.expect("read ok");
        assert_eq!(&resp, b"ok");

        drop(send);
        drop(recv);
        conn.close(0u32.into(), b"done");
        backend_task.await.expect("backend task");

        server_endpoint.close(0u32.into(), b"shutdown");
        tokio::time::timeout(Duration::from_secs(2), server_task)
            .await
            .expect("serve_endpoint exit")
            .expect("serve_endpoint join");
    }

    #[tokio::test]
    async fn retry_and_max_connections_limit_are_enforced() {
        let backend_listener = TcpListener::bind(SocketAddr::new(Ipv4Addr::LOCALHOST.into(), 0))
            .await
            .expect("bind backend tcp");
        let backend_addr = backend_listener.local_addr().expect("backend addr");

        let (server_config, server_cert_der) =
            configure_server(None, None, None).expect("configure ephemeral server");
        let server_endpoint = Endpoint::server(
            server_config,
            SocketAddr::new(Ipv4Addr::LOCALHOST.into(), 0),
        )
        .expect("server endpoint");
        let server_addr = server_endpoint.local_addr().expect("server addr");

        // Retry enabled (no_retry = false), global max_connections = 1 (per-IP cap is higher so
        // this exercises global conn_semaphore pre-handshake refusal).
        let server_task = tokio::spawn(serve_endpoint(
            server_endpoint.clone(),
            ServeConfig {
                max_connections: 1,
                max_connections_per_ip: 4,
                no_retry: false,
                ..test_serve_config(backend_addr)
            },
        ));

        let client1 = make_client_endpoint(&server_cert_der, None);
        let conn1 = tokio::time::timeout(
            Duration::from_secs(3),
            client1
                .connect(server_addr, "localhost")
                .expect("connect 1"),
        )
        .await
        .expect("client1 connect timeout")
        .expect("client1 handshake with Retry should succeed");

        let (mut send1, mut recv1) = conn1.open_bi().await.expect("open_bi 1");
        send1.write_all(b"hold").await.expect("write 1");

        let (mut backend_stream1, _) =
            tokio::time::timeout(Duration::from_secs(2), backend_listener.accept())
                .await
                .expect("accept backend 1 timeout")
                .expect("accept backend 1");
        let mut buf1 = [0u8; 4];
        backend_stream1
            .read_exact(&mut buf1)
            .await
            .expect("read backend 1");
        backend_stream1
            .write_all(&buf1)
            .await
            .expect("write backend 1");

        let mut resp1 = [0u8; 4];
        recv1.read_exact(&mut resp1).await.expect("read 1");
        assert_eq!(&resp1, b"hold");

        // While client1 holds the single permit, client2 is refused BEFORE the TLS handshake
        // (QUIC CONNECTION_REFUSED) and never triggers a backend TCP connection.
        let client2 = make_client_endpoint(&server_cert_der, None);
        let conn2_res = tokio::time::timeout(
            Duration::from_secs(3),
            client2
                .connect(server_addr, "localhost")
                .expect("connect 2"),
        )
        .await
        .expect("client2 connect should resolve promptly");
        assert_connection_refused(conn2_res);
        assert!(
            tokio::time::timeout(Duration::from_millis(50), backend_listener.accept())
                .await
                .is_err(),
            "rejected connection must not open a backend TCP connection"
        );

        // Close client1 and ensure the server releases its conn_semaphore permit.
        drop(send1);
        drop(recv1);
        conn1.close(0u32.into(), b"done");
        let mut drain = [0u8; 8];
        let _ =
            tokio::time::timeout(Duration::from_secs(2), backend_stream1.read(&mut drain)).await;
        drop(backend_stream1);

        // Give the server task a moment to exit handle_connection and release _conn_permit.
        tokio::time::sleep(Duration::from_millis(50)).await;

        // Client3 must now succeed using the released permit.
        let client3 = make_client_endpoint(&server_cert_der, None);
        let conn3 = tokio::time::timeout(
            Duration::from_secs(3),
            client3
                .connect(server_addr, "localhost")
                .expect("connect 3"),
        )
        .await
        .expect("client3 connect timeout")
        .expect("client3 handshake should succeed after client1 released permit");

        let (mut send3, mut recv3) = conn3.open_bi().await.expect("open_bi 3");
        send3.write_all(b"next").await.expect("write 3");

        let (mut backend_stream3, _) =
            tokio::time::timeout(Duration::from_secs(2), backend_listener.accept())
                .await
                .expect("accept backend 3 timeout")
                .expect("accept backend 3");
        let mut buf3 = [0u8; 4];
        backend_stream3
            .read_exact(&mut buf3)
            .await
            .expect("read backend 3");
        backend_stream3
            .write_all(&buf3)
            .await
            .expect("write backend 3");

        let mut resp3 = [0u8; 4];
        recv3.read_exact(&mut resp3).await.expect("read 3");
        assert_eq!(&resp3, b"next");

        drop(send3);
        drop(recv3);
        conn3.close(0u32.into(), b"done");
        drop(backend_stream3);

        server_endpoint.close(0u32.into(), b"shutdown");
        tokio::time::timeout(Duration::from_secs(2), server_task)
            .await
            .expect("serve_endpoint should exit on endpoint close")
            .expect("serve_endpoint join");
    }

    #[tokio::test]
    async fn per_ip_established_connection_limit_refuses_and_releases_after_disconnect() {
        let backend_listener = TcpListener::bind(SocketAddr::new(Ipv4Addr::LOCALHOST.into(), 0))
            .await
            .expect("bind backend tcp");
        let backend_addr = backend_listener.local_addr().expect("backend addr");

        let (server_config, server_cert_der) =
            configure_server(None, None, None).expect("configure ephemeral server");
        let server_endpoint = Endpoint::server(
            server_config,
            SocketAddr::new(Ipv4Addr::LOCALHOST.into(), 0),
        )
        .expect("server endpoint");
        let server_addr = server_endpoint.local_addr().expect("server addr");

        // Global cap is 4, but per-IP established cap is 1.
        let server_task = tokio::spawn(serve_endpoint(
            server_endpoint.clone(),
            ServeConfig {
                max_connections: 4,
                max_connections_per_ip: 1,
                ..test_serve_config(backend_addr)
            },
        ));

        let client1 = make_client_endpoint(&server_cert_der, None);
        let conn1 = client1
            .connect(server_addr, "localhost")
            .expect("connect 1")
            .await
            .expect("handshake 1");
        let (mut send1, mut recv1) = conn1.open_bi().await.expect("open_bi 1");
        send1.write_all(b"hold").await.expect("write 1");

        let (mut backend1, _) = backend_listener.accept().await.expect("accept backend 1");
        let mut buf = [0u8; 4];
        backend1.read_exact(&mut buf).await.expect("read backend 1");
        backend1.write_all(&buf).await.expect("write backend 1");
        let mut resp1 = [0u8; 4];
        recv1.read_exact(&mut resp1).await.expect("read 1");
        assert_eq!(&resp1, b"hold");

        // Second connection from the same loopback IP must be refused pre-handshake.
        let client2 = make_client_endpoint(&server_cert_der, None);
        let conn2_res = tokio::time::timeout(
            Duration::from_secs(2),
            client2
                .connect(server_addr, "localhost")
                .expect("connect 2"),
        )
        .await
        .expect("client2 refusal should return promptly");
        assert_connection_refused(conn2_res);
        assert!(
            tokio::time::timeout(Duration::from_millis(50), backend_listener.accept())
                .await
                .is_err(),
            "per-IP refused connection must not open a backend TCP connection"
        );

        // Disconnect client1 and ensure per-IP count is released.
        drop(send1);
        drop(recv1);
        conn1.close(0u32.into(), b"done");
        let _ = tokio::time::timeout(Duration::from_secs(2), backend1.read(&mut buf)).await;
        drop(backend1);
        tokio::time::sleep(Duration::from_millis(50)).await;

        // Client3 from the same IP must now succeed.
        let client3 = make_client_endpoint(&server_cert_der, None);
        let conn3 = tokio::time::timeout(
            Duration::from_secs(2),
            client3
                .connect(server_addr, "localhost")
                .expect("connect 3"),
        )
        .await
        .expect("client3 connect timeout")
        .expect("client3 should succeed after per-IP slot release");
        let (mut send3, mut recv3) = conn3.open_bi().await.expect("open_bi 3");
        send3.write_all(b"pass").await.expect("write 3");
        let (mut backend3, _) = backend_listener.accept().await.expect("accept backend 3");
        backend3.read_exact(&mut buf).await.expect("read backend 3");
        backend3.write_all(&buf).await.expect("write backend 3");
        let mut resp3 = [0u8; 4];
        recv3.read_exact(&mut resp3).await.expect("read 3");
        assert_eq!(&resp3, b"pass");

        drop(send3);
        drop(recv3);
        conn3.close(0u32.into(), b"done");
        drop(backend3);

        server_endpoint.close(0u32.into(), b"shutdown");
        tokio::time::timeout(Duration::from_secs(2), server_task)
            .await
            .expect("serve_endpoint exit")
            .expect("serve_endpoint join");
    }

    #[tokio::test]
    async fn multi_sni_routing_matches_mixed_case_toml_keys_and_falls_back_to_default() {
        let dir = TestTempDir::new("multi-sni");

        let alpha_listener = TcpListener::bind(SocketAddr::new(Ipv4Addr::LOCALHOST.into(), 0))
            .await
            .expect("bind alpha");
        let alpha_addr = alpha_listener.local_addr().expect("alpha addr");

        let beta_listener = TcpListener::bind(SocketAddr::new(Ipv4Addr::LOCALHOST.into(), 0))
            .await
            .expect("bind beta");
        let beta_addr = beta_listener.local_addr().expect("beta addr");

        let default_listener = TcpListener::bind(SocketAddr::new(Ipv4Addr::LOCALHOST.into(), 0))
            .await
            .expect("bind default");
        let default_addr = default_listener.local_addr().expect("default addr");

        let spawn_tagged_backend = |listener: TcpListener, tag: &'static [u8; 4]| {
            tokio::spawn(async move {
                let (mut stream, _) = listener.accept().await.expect("accept backend");
                let mut buf = [0u8; 4];
                stream.read_exact(&mut buf).await.expect("read ping");
                stream.write_all(tag).await.expect("write tag");
                stream.shutdown().await.expect("shutdown backend");
            })
        };
        let alpha_task = spawn_tagged_backend(alpha_listener, b"alfa");
        let beta_task = spawn_tagged_backend(beta_listener, b"beta");
        let default_task = spawn_tagged_backend(default_listener, b"dflt");

        // Create a server certificate valid for all three SNI hostnames.
        let cert = rcgen::generate_simple_self_signed(vec![
            "alpha.example.com".into(),
            "beta.example.org".into(),
            "unknown.example.net".into(),
        ])
        .expect("generate multi-SAN cert");
        let cert_path = dir.path().join("multi.crt");
        let key_path = dir.path().join("multi.key");
        fs::write(&cert_path, cert.cert.pem()).expect("write multi cert");
        fs::write(&key_path, cert.signing_key.serialize_pem()).expect("write multi key");

        let toml_cfg = format!(
            "[proxy]\n\"Alpha.Example.COM\" = \"{}\"\n\"BeTa.Example.ORG\" = \"{}\"\n\"Default\" = \"{}\"\n",
            alpha_addr, beta_addr, default_addr
        );
        let parsed = parse_server_conf(&toml_cfg).expect("parse multi-SNI conf");
        let resolved_default = resolve_default_proxy(None, parsed.default_proxy);
        assert_eq!(resolved_default, default_addr);

        let (server_config, server_cert_der) =
            configure_server(Some(&cert_path), Some(&key_path), None)
                .expect("configure multi-SAN server");
        let server_endpoint = Endpoint::server(
            server_config,
            SocketAddr::new(Ipv4Addr::LOCALHOST.into(), 0),
        )
        .expect("server endpoint");
        let server_addr = server_endpoint.local_addr().expect("server addr");

        let server_task = tokio::spawn(serve_endpoint(
            server_endpoint.clone(),
            ServeConfig {
                proxy_map: parsed.proxy_map,
                default_proxy: resolved_default,
                ..test_serve_config(resolved_default)
            },
        ));

        for (sni, expected_tag) in [
            ("alpha.example.com", b"alfa"),
            ("BETA.EXAMPLE.ORG", b"beta"),
            ("unknown.example.net", b"dflt"),
        ] {
            let client = make_client_endpoint(&server_cert_der, None);
            let conn = tokio::time::timeout(
                Duration::from_secs(2),
                client.connect(server_addr, sni).expect("connect"),
            )
            .await
            .expect("connect timeout")
            .expect("handshake");
            let (mut send, mut recv) = conn.open_bi().await.expect("open_bi");
            send.write_all(b"ping").await.expect("write ping");
            send.finish().expect("finish send");
            let mut reply = [0u8; 4];
            recv.read_exact(&mut reply).await.expect("read tag");
            assert_eq!(&reply, expected_tag, "SNI {} routed to wrong backend", sni);
            conn.close(0u32.into(), b"done");
        }

        alpha_task.await.expect("alpha task");
        beta_task.await.expect("beta task");
        default_task.await.expect("default task");

        server_endpoint.close(0u32.into(), b"shutdown");
        tokio::time::timeout(Duration::from_secs(2), server_task)
            .await
            .expect("serve_endpoint exit")
            .expect("serve_endpoint join");
    }

    #[tokio::test]
    async fn serve_endpoint_until_closes_gracefully_on_shutdown_signal() {
        let backend_listener = TcpListener::bind(SocketAddr::new(Ipv4Addr::LOCALHOST.into(), 0))
            .await
            .expect("bind backend tcp");
        let backend_addr = backend_listener.local_addr().expect("backend addr");

        let (server_config, server_cert_der) =
            configure_server(None, None, None).expect("configure ephemeral server");
        let server_endpoint = Endpoint::server(
            server_config,
            SocketAddr::new(Ipv4Addr::LOCALHOST.into(), 0),
        )
        .expect("server endpoint");
        let server_addr = server_endpoint.local_addr().expect("server addr");

        let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
        let server_task = tokio::spawn(serve_endpoint_until(
            server_endpoint.clone(),
            test_serve_config(backend_addr),
            async move {
                let _ = shutdown_rx.await;
            },
        ));

        let client = make_client_endpoint(&server_cert_der, None);
        let conn = client
            .connect(server_addr, "localhost")
            .expect("connect")
            .await
            .expect("handshake");

        shutdown_tx.send(()).expect("trigger shutdown");

        assert_application_closed(Ok(conn), 0, b"server shutdown").await;
        tokio::time::timeout(Duration::from_secs(3), server_task)
            .await
            .expect("serve_endpoint_until must exit promptly on shutdown")
            .expect("serve_endpoint_until join");
    }

    #[tokio::test]
    async fn missing_sni_routes_to_default_proxy_not_client_ip() {
        let default_listener = TcpListener::bind(SocketAddr::new(Ipv4Addr::LOCALHOST.into(), 0))
            .await
            .expect("bind default backend");
        let default_addr = default_listener.local_addr().expect("default addr");

        let ip_listener = TcpListener::bind(SocketAddr::new(Ipv4Addr::LOCALHOST.into(), 0))
            .await
            .expect("bind ip backend");
        let ip_addr = ip_listener.local_addr().expect("ip addr");

        let default_backend = tokio::spawn(async move {
            let (mut stream, _) = default_listener.accept().await.expect("accept default");
            let mut buf = [0u8; 4];
            stream.read_exact(&mut buf).await.expect("read default");
            stream.write_all(b"dflt").await.expect("write default");
            let _ = stream.read(&mut buf).await;
        });

        let (server_config, server_cert_der) =
            configure_server(None, None, None).expect("configure ephemeral server");
        let server_endpoint = Endpoint::server(
            server_config,
            SocketAddr::new(Ipv4Addr::LOCALHOST.into(), 0),
        )
        .expect("server endpoint");
        let server_addr = server_endpoint.local_addr().expect("server addr");

        let mut proxy_map = HashMap::new();
        proxy_map.insert("127.0.0.1".to_string(), ip_addr);

        let server_task = tokio::spawn(serve_endpoint(
            server_endpoint.clone(),
            ServeConfig {
                proxy_map,
                ..test_serve_config(default_addr)
            },
        ));

        // Client sends no SNI extension; server must route to default_proxy, never proxy_map["127.0.0.1"].
        let no_sni_client = make_client_endpoint_with_sni(&server_cert_der, None, false);
        let conn = tokio::time::timeout(
            Duration::from_secs(2),
            no_sni_client
                .connect(server_addr, "localhost")
                .expect("connect without sni"),
        )
        .await
        .expect("connect timeout")
        .expect("handshake without sni");

        let (mut send, mut recv) = conn.open_bi().await.expect("open_bi");
        send.write_all(b"test").await.expect("write");
        let mut resp = [0u8; 4];
        recv.read_exact(&mut resp).await.expect("read reply");
        assert_eq!(&resp, b"dflt");

        assert!(
            tokio::time::timeout(Duration::from_millis(50), ip_listener.accept())
                .await
                .is_err(),
            "missing SNI must never fall back to client IP lookup"
        );

        drop(send);
        drop(recv);
        conn.close(0u32.into(), b"done");
        default_backend.await.expect("default backend join");

        server_endpoint.close(0u32.into(), b"shutdown");
        tokio::time::timeout(Duration::from_secs(2), server_task)
            .await
            .expect("serve_endpoint exit")
            .expect("serve_endpoint join");
    }

    #[test]
    fn sanitize_log_value_escapes_control_chars_and_truncates() {
        let injected = "bad\r\nFAKE LOG\x1b[31mred\0tail";
        let sanitized = sanitize_log_value(injected);
        assert!(!sanitized.contains('\n'));
        assert!(!sanitized.contains('\r'));
        assert!(!sanitized.contains('\x1b'));
        assert!(!sanitized.contains('\0'));
        assert!(sanitized.contains("\\r\\nFAKE LOG\\u{1b}[31mred\\u{0}tail"));

        let oversized = "a".repeat(MAX_SANITIZED_LOG_LEN + 50);
        let truncated = sanitize_log_value(&oversized);
        assert!(truncated.ends_with("..."));
        assert!(truncated.len() <= MAX_SANITIZED_LOG_LEN + 3);
    }

    #[test]
    fn log_limiters_isolate_categories() {
        let limiters = LogLimiters::new(Duration::from_secs(60));
        assert_eq!(limiters.per_ip_limit.check(), Some(0));
        assert_eq!(limiters.per_ip_limit.check(), None);
        // Saturating per_ip_limit must not suppress other categories.
        assert_eq!(limiters.global_limit.check(), Some(0));
        assert_eq!(limiters.handshake_error.check(), Some(0));
        assert_eq!(limiters.relay_error.check(), Some(0));
    }

    #[test]
    fn validate_options_rejects_excessive_max_connections() {
        let opt = Opt::try_parse_from([
            "server",
            "--max-connections",
            &(Semaphore::MAX_PERMITS + 1).to_string(),
        ])
        .expect("parse excessive max connections");
        assert!(validate_options(&opt).is_err());
    }

    #[tokio::test]
    async fn backend_connect_failure_closes_connection_without_spurious_fin() {
        // Bind and immediately drop a TCP listener so connecting to its port fails with ECONNREFUSED.
        let closed_listener = TcpListener::bind(SocketAddr::new(Ipv4Addr::LOCALHOST.into(), 0))
            .await
            .expect("bind temp tcp");
        let unreachable_backend = closed_listener.local_addr().expect("temp tcp addr");
        drop(closed_listener);

        let (server_config, server_cert_der) =
            configure_server(None, None, None).expect("configure ephemeral server");
        let server_endpoint = Endpoint::server(
            server_config,
            SocketAddr::new(Ipv4Addr::LOCALHOST.into(), 0),
        )
        .expect("server endpoint");
        let server_addr = server_endpoint.local_addr().expect("server addr");

        let client_endpoint = make_client_endpoint(&server_cert_der, None);
        let (client_res, server_res) = tokio::join!(
            async {
                client_endpoint
                    .connect(server_addr, "localhost")
                    .expect("connect")
                    .await
            },
            async { server_endpoint.accept().await.expect("incoming").await }
        );
        let client_conn = client_res.expect("client connected");
        let server_conn = server_res.expect("server accepted");

        let (mut client_send, mut client_recv) = client_conn.open_bi().await.expect("open_bi");
        client_send.write_all(b"x").await.expect("write");

        let handler = tokio::spawn(handle_connection_with_timeouts(
            unreachable_backend,
            server_conn,
            Duration::from_secs(1),
            Duration::from_secs(1),
            Duration::from_millis(150),
            Arc::new(LogRateLimiter::new(Duration::from_secs(1))),
        ));

        // Client must observe a connection error (not Ok(None) clean EOF).
        let mut buf = [0u8; 16];
        let read_res = tokio::time::timeout(Duration::from_secs(2), client_recv.read(&mut buf))
            .await
            .expect("read timeout");
        assert!(
            matches!(
                read_res,
                Err(quinn::ReadError::ConnectionLost(
                    quinn::ConnectionError::ApplicationClosed(ref close)
                )) if close.error_code == VarInt::from_u32(1)
            ),
            "expected application close error code 1 instead of clean EOF, got: {read_res:?}"
        );

        handler.await.expect("handler join");
        server_endpoint.close(0u32.into(), b"shutdown");
    }
}
