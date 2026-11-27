use ::aws_lc_rs::digest::{SHA256, digest};
use clap::Parser;
use log::{debug, error, info, warn};
use quinn::crypto::rustls::QuicClientConfig;
use quinn::{ClientConfig, Endpoint, VarInt};
use rustls::{
    client,
    crypto::{CryptoProvider, aws_lc_rs},
    pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime, pem::PemObject},
};
use std::{
    error::Error,
    fmt,
    net::SocketAddr,
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};
use subtle::ConstantTimeEq;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
#[cfg(not(windows))]
use tokio::signal::unix::{SignalKind, signal};
#[cfg(windows)]
use tokio::signal::windows::ctrl_c;
use url::Url;

#[derive(Parser, Debug)]
#[clap(name = "client")]
pub struct Opt {
    /// Server address
    url: Url,
    /// Client address
    #[clap(long = "bind", short = 'b')]
    bind_addr: Option<SocketAddr>,
    /// Custom PEM CA certificate(s) to verify the server certificate against
    #[clap(long, conflicts_with_all = ["server_cert_sha256", "insecure"])]
    ca_cert: Option<PathBuf>,
    /// Pin the server's leaf certificate by SHA-256 hex digest
    #[clap(long, conflicts_with_all = ["ca_cert", "insecure"])]
    server_cert_sha256: Option<String>,
    /// Disable server certificate chain and hostname verification (insecure)
    #[clap(long, conflicts_with_all = ["ca_cert", "server_cert_sha256"])]
    insecure: bool,
    /// PEM client certificate chain for mTLS
    #[clap(long, requires = "client_key")]
    client_cert: Option<PathBuf>,
    /// PEM client private key for mTLS
    #[clap(long, requires = "client_cert")]
    client_key: Option<PathBuf>,
}

/// Enables MTUD if supported by the operating system
#[cfg(not(any(windows, target_os = "linux")))]
pub fn enable_mtud_if_supported() -> quinn::TransportConfig {
    let mut transport_config = quinn::TransportConfig::default();
    transport_config.mtu_discovery_config(None);
    transport_config
}

/// Enables MTUD if supported by the operating system
#[cfg(any(windows, target_os = "linux"))]
pub fn enable_mtud_if_supported() -> quinn::TransportConfig {
    let mut transport_config = quinn::TransportConfig::default();
    transport_config.mtu_discovery_config(Some(quinn::MtuDiscoveryConfig::default()));
    transport_config
}

#[derive(Debug)]
struct CertPinMismatchError;

impl fmt::Display for CertPinMismatchError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("server certificate SHA-256 fingerprint does not match expected pin")
    }
}

impl Error for CertPinMismatchError {}

/// Verifies the server's leaf certificate against a pinned SHA-256 digest while
/// still verifying TLS handshake signatures using the crypto provider.
#[derive(Debug)]
struct PinnedCertVerifier {
    expected_sha256: [u8; 32],
    provider: Arc<CryptoProvider>,
}

impl PinnedCertVerifier {
    fn new(expected_sha256: [u8; 32], provider: Arc<CryptoProvider>) -> Arc<Self> {
        Arc::new(Self {
            expected_sha256,
            provider,
        })
    }
}

impl client::danger::ServerCertVerifier for PinnedCertVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<client::danger::ServerCertVerified, rustls::Error> {
        let actual = digest(&SHA256, end_entity.as_ref());
        if bool::from(actual.as_ref().ct_eq(&self.expected_sha256)) {
            Ok(client::danger::ServerCertVerified::assertion())
        } else {
            Err(rustls::Error::InvalidCertificate(
                rustls::CertificateError::Other(rustls::OtherError(Arc::new(CertPinMismatchError))),
            ))
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

/// Skips server certificate chain and hostname verification (`--insecure`),
/// while still verifying TLS handshake signatures to prove possession of the
/// certificate's private key.
#[derive(Debug)]
struct InsecureServerVerifier {
    provider: Arc<CryptoProvider>,
}

impl InsecureServerVerifier {
    fn new(provider: Arc<CryptoProvider>) -> Arc<Self> {
        Arc::new(Self { provider })
    }
}

impl client::danger::ServerCertVerifier for InsecureServerVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<client::danger::ServerCertVerified, rustls::Error> {
        Ok(client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

fn decode_hex_nibble(c: char) -> Result<u8, Box<dyn Error>> {
    match c {
        '0'..='9' => Ok((c as u8) - b'0'),
        'a'..='f' => Ok((c as u8) - b'a' + 10),
        'A'..='F' => Ok((c as u8) - b'A' + 10),
        _ => Err(format!("invalid SHA-256 hex digest: unexpected character '{c}'").into()),
    }
}

fn parse_sha256_hex(input: &str) -> Result<[u8; 32], Box<dyn Error>> {
    let rest = input
        .strip_prefix("SHA256:")
        .or_else(|| input.strip_prefix("sha256:"))
        .unwrap_or(input);

    let mut out = [0u8; 32];
    if rest.contains(':') {
        let mut parts = rest.split(':');
        for byte in &mut out {
            let Some(group) = parts.next() else {
                return Err(
                    "invalid SHA-256 hex digest: expected 32 colon-separated hex bytes".into(),
                );
            };
            let mut chars = group.chars();
            let (Some(hi), Some(lo), None) = (chars.next(), chars.next(), chars.next()) else {
                return Err(format!(
                    "invalid SHA-256 hex digest: colon-separated byte '{group}' must be 2 hex characters"
                )
                .into());
            };
            *byte = (decode_hex_nibble(hi)? << 4) | decode_hex_nibble(lo)?;
        }
        if parts.next().is_some() {
            return Err("invalid SHA-256 hex digest: expected 32 colon-separated hex bytes".into());
        }
    } else {
        let mut chars = rest.chars();
        for byte in &mut out {
            let (Some(hi), Some(lo)) = (chars.next(), chars.next()) else {
                return Err(format!(
                    "invalid SHA-256 hex digest: expected 64 hex characters, got {}",
                    rest.chars().count()
                )
                .into());
            };
            *byte = (decode_hex_nibble(hi)? << 4) | decode_hex_nibble(lo)?;
        }
        if chars.next().is_some() {
            return Err(format!(
                "invalid SHA-256 hex digest: expected 64 hex characters, got {}",
                rest.chars().count()
            )
            .into());
        }
    }

    Ok(out)
}

fn load_pem_certs(path: &Path) -> Result<Vec<CertificateDer<'static>>, Box<dyn Error>> {
    let certs: Vec<CertificateDer<'static>> = CertificateDer::pem_file_iter(path)
        .map_err(|e| format!("failed to open certificate file {}: {}", path.display(), e))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| format!("failed to parse PEM certificate {}: {}", path.display(), e))?;
    if certs.is_empty() {
        return Err(format!("no PEM certificates found in {}", path.display()).into());
    }
    Ok(certs)
}

fn load_pem_private_key(path: &Path) -> Result<PrivateKeyDer<'static>, Box<dyn Error>> {
    PrivateKeyDer::from_pem_file(path)
        .map_err(|e| format!("failed to load PEM private key {}: {}", path.display(), e).into())
}

fn build_custom_ca_verifier(
    ca_path: &Path,
    provider: Arc<CryptoProvider>,
) -> Result<Arc<dyn client::danger::ServerCertVerifier>, Box<dyn Error>> {
    let certs = load_pem_certs(ca_path)?;
    let mut roots = rustls::RootCertStore::empty();
    for cert in certs {
        roots
            .add(cert)
            .map_err(|e| format!("invalid CA certificate in {}: {}", ca_path.display(), e))?;
    }
    let verifier =
        rustls::client::WebPkiServerVerifier::builder_with_provider(Arc::new(roots), provider)
            .build()?;
    Ok(verifier)
}

fn build_transport_config() -> quinn::TransportConfig {
    let mut transport_config = enable_mtud_if_supported();
    transport_config.max_idle_timeout(Some(VarInt::from_u32(60_000).into()));
    transport_config.keep_alive_interval(Some(Duration::from_secs(15)));
    transport_config.datagram_receive_buffer_size(None);
    transport_config.max_concurrent_uni_streams(0_u8.into());
    transport_config.max_concurrent_bidi_streams(0_u8.into());
    transport_config.stream_receive_window(VarInt::from_u32(256 * 1024));
    transport_config.receive_window(VarInt::from_u32(512 * 1024));
    transport_config.send_window(512 * 1024);
    transport_config
}

fn configure_client(options: &Opt) -> Result<ClientConfig, Box<dyn Error>> {
    let provider = Arc::new(aws_lc_rs::default_provider());

    let verifier: Arc<dyn client::danger::ServerCertVerifier> = match (
        options.ca_cert.as_deref(),
        options.server_cert_sha256.as_deref(),
        options.insecure,
    ) {
        (None, None, false) => Arc::new(rustls_platform_verifier::Verifier::new(Arc::clone(
            &provider,
        ))?),
        (Some(ca_path), None, false) => build_custom_ca_verifier(ca_path, Arc::clone(&provider))?,
        (None, Some(hex), false) => {
            let expected = parse_sha256_hex(hex)?;
            PinnedCertVerifier::new(expected, Arc::clone(&provider))
        }
        (None, None, true) => {
            warn!("[client] TLS certificate and hostname verification disabled (--insecure)");
            InsecureServerVerifier::new(Arc::clone(&provider))
        }
        _ => {
            return Err(
                "--ca-cert, --server-cert-sha256, and --insecure are mutually exclusive".into(),
            );
        }
    };

    let builder = rustls::ClientConfig::builder_with_provider(Arc::clone(&provider))
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .dangerous()
        .with_custom_certificate_verifier(verifier);

    let crypto = match (&options.client_cert, &options.client_key) {
        (Some(cert_path), Some(key_path)) => {
            let cert_chain = load_pem_certs(cert_path)?;
            let priv_key = load_pem_private_key(key_path)?;
            builder.with_client_auth_cert(cert_chain, priv_key)?
        }
        (None, None) => builder.with_no_client_auth(),
        _ => return Err("--client-cert and --client-key must be specified together".into()),
    };

    let quic_config = QuicClientConfig::try_from(crypto)?;
    let mut client_config = ClientConfig::new(Arc::new(quic_config));
    client_config.transport_config(Arc::new(build_transport_config()));

    Ok(client_config)
}

/// Constructs a QUIC endpoint configured for client use only.
fn make_client_endpoint(
    bind_addr: SocketAddr,
    client_cfg: ClientConfig,
) -> Result<Endpoint, Box<dyn Error>> {
    let mut endpoint = Endpoint::client(bind_addr)?;
    endpoint.set_default_client_config(client_cfg);
    Ok(endpoint)
}

pub fn run(options: Opt) -> Result<(), Box<dyn Error>> {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    let result = rt.block_on(run_async(options));
    // `tokio::io::stdin()` parks a blocking thread on `read(0)` when the remote QUIC
    // stream closes or fails first; avoid deadlocking runtime drop on process exit.
    rt.shutdown_background();
    result
}

fn parse_target_url(url: &Url) -> Result<&str, Box<dyn Error>> {
    if url.scheme() != "quic" {
        return Err("URL scheme must be quic".into());
    }
    if !url.username().is_empty() || url.password().is_some() {
        return Err("URL must not contain userinfo".into());
    }
    if !url.path().is_empty() && url.path() != "/" {
        return Err("URL must not contain a path".into());
    }
    if url.query().is_some() || url.fragment().is_some() {
        return Err("URL must not contain query or fragment".into());
    }

    url.host_str()
        .map(|h| h.trim_start_matches('[').trim_end_matches(']'))
        .filter(|h| !h.is_empty())
        .ok_or_else(|| "URL must include a host".into())
}

async fn run_async(options: Opt) -> Result<(), Box<dyn Error>> {
    let _ = aws_lc_rs::default_provider().install_default();
    let sni = parse_target_url(&options.url)?;

    let client_cfg = configure_client(&options)?;

    // Currently `url` crate doesn't recognize quic as scheme (see socket_addrs()), so we can set default port using argument. In future if quic default port is added (as 80 or 443, likely), we will fail to connect to proper port. Ideally we should define own scheme. (ex. "qsrs://" abbr of quicssh-rs)
    let sock_list = options
        .url
        .socket_addrs(|| Some(4433))
        .map_err(|_| "Couldn't resolve to any address")?;

    // Currently we only use the first addr. The other addrs should be fallbacks of the connection, but not implemented now.
    let remote = *sock_list.first().ok_or("Couldn't resolve to any address")?;

    info!("[client] Connecting to: {} <- {}", remote, sni);

    let bind_addr = match options.bind_addr {
        Some(local) => local,
        None => {
            use std::net::{IpAddr::*, Ipv4Addr, Ipv6Addr};
            if remote.is_ipv6() {
                SocketAddr::new(V6(Ipv6Addr::UNSPECIFIED), 0)
            } else {
                SocketAddr::new(V4(Ipv4Addr::UNSPECIFIED), 0)
            }
        }
    };
    let endpoint = make_client_endpoint(bind_addr, client_cfg)?;
    let connection = endpoint
        .connect(remote, sni)
        .map_err(|e| format!("failed to initiate QUIC connection: {}", e))?
        .await
        .map_err(|e| format!("failed to establish QUIC connection: {}", e))?;
    info!(
        "[client] Connected to: {} <- {}",
        connection.remote_address(),
        sni
    );

    let (send, recv) = connection
        .open_bi()
        .await
        .map_err(|e| format!("failed to open stream: {}", e))?;

    let relay_result = relay_streams(
        &connection,
        send,
        recv,
        tokio::io::stdin(),
        tokio::io::stdout(),
        create_signal_thread(),
    )
    .await;

    // No-op if already closed (e.g., on signal); flush CONNECTION_CLOSE before runtime shutdown.
    connection.close(0u32.into(), b"done");
    let _ = tokio::time::timeout(Duration::from_millis(200), endpoint.wait_idle()).await;

    info!("[client] exit client");

    relay_result
}

async fn relay_streams<R, W, F>(
    connection: &quinn::Connection,
    mut send: quinn::SendStream,
    mut recv: quinn::RecvStream,
    mut stdin: R,
    mut stdout: W,
    signal_thread: F,
) -> Result<(), Box<dyn Error>>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
    F: Future<Output = ()>,
{
    let recv_thread = async move {
        let mut buf = [0u8; 2048];

        loop {
            match recv.read(&mut buf).await {
                Ok(None) => {
                    info!("[client] recv EOF from quic server");
                    return Ok::<(), Box<dyn Error>>(());
                }
                Ok(Some(n)) => {
                    debug!("[client] recv data from quic server {} bytes", n);
                    stdout
                        .write_all(&buf[..n])
                        .await
                        .map_err(|e| format!("[client] write to stdout error: {}", e))?;
                    stdout
                        .flush()
                        .await
                        .map_err(|e| format!("[client] flush stdout error: {}", e))?;
                }
                Err(quinn::ReadError::ConnectionLost(conn_err)) => {
                    return Err(format!(
                        "[client] recv data from quic server error: connection lost: {}",
                        conn_err
                    )
                    .into());
                }
                Err(err) => {
                    return Err(
                        format!("[client] recv data from quic server error: {}", err).into(),
                    );
                }
            }
        }
    };

    let write_thread = async move {
        let mut buf = [0u8; 2048];

        loop {
            match stdin.read(&mut buf).await {
                Ok(0) => {
                    info!("[client] recv EOF from stdin");
                    let _ = send.finish();
                    return Ok::<(), Box<dyn Error>>(());
                }
                Ok(n) => {
                    debug!("[client] recv data from stdin {} bytes", n);
                    send.write_all(&buf[..n]).await.map_err(|e| match e {
                        quinn::WriteError::ConnectionLost(conn_err) => format!(
                            "[client] send data to quic server error: connection lost: {}",
                            conn_err
                        ),
                        other => format!("[client] send data to quic server error: {}", other),
                    })?;
                }
                Err(err) => {
                    let _ = send.reset(VarInt::from_u32(1));
                    return Err(format!("[client] recv data from stdin error: {}", err).into());
                }
            }
        }
    };

    tokio::pin!(recv_thread, write_thread, signal_thread);

    tokio::select! {
        res = &mut recv_thread => res,
        res = &mut write_thread => match res {
            Ok(()) => {
                // Local input hit EOF and sent QUIC FIN; keep reading remote output
                // (or any QUIC/TLS error such as mTLS rejection) until remote EOF or signal.
                tokio::select! {
                    recv_res = &mut recv_thread => recv_res,
                    _ = &mut signal_thread => {
                        connection.close(0u32.into(), b"signal");
                        Ok(())
                    }
                }
            }
            Err(e) => Err(e),
        },
        _ = &mut signal_thread => {
            connection.close(0u32.into(), b"signal");
            Ok(())
        }
    }
}

#[cfg(windows)]
async fn create_signal_thread() {
    match ctrl_c() {
        Ok(mut stream) => {
            if stream.recv().await.is_some() {
                info!("[client] got signal Ctrl-C");
                return;
            }
            error!("[client] signal stream closed unexpectedly");
        }
        Err(e) => {
            error!("[client] create signal stream error: {}", e);
        }
    }
    std::future::pending::<()>().await;
}

#[cfg(not(windows))]
async fn wait_for_unix_signal(kind: SignalKind, name: &'static str) {
    match signal(kind) {
        Ok(mut stream) => {
            if stream.recv().await.is_some() {
                info!("[client] got signal {}", name);
                return;
            }
            error!("[client] {} signal stream closed unexpectedly", name);
        }
        Err(e) => {
            error!("[client] create {} signal stream error: {}", name, e);
        }
    }
    std::future::pending::<()>().await;
}

#[cfg(not(windows))]
async fn create_signal_thread() {
    tokio::select! {
        () = wait_for_unix_signal(SignalKind::hangup(), "SIGHUP") => {}
        () = wait_for_unix_signal(SignalKind::terminate(), "SIGTERM") => {}
        () = wait_for_unix_signal(SignalKind::interrupt(), "SIGINT") => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rcgen::{
        BasicConstraints, CertificateParams, CertifiedIssuer, ExtendedKeyUsagePurpose, IsCa,
        KeyPair, KeyUsagePurpose, generate_simple_self_signed,
    };
    use rustls::client::danger::ServerCertVerifier;
    use std::sync::atomic::{AtomicU64, Ordering};

    struct TempFile {
        path: PathBuf,
    }

    impl TempFile {
        fn new(name: &str, contents: &[u8]) -> Self {
            static COUNTER: AtomicU64 = AtomicU64::new(0);
            let id = COUNTER.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "quicssh-rs-client-test-{}-{}-{}",
                std::process::id(),
                id,
                name
            ));
            std::fs::write(&path, contents).expect("write temp file");
            Self { path }
        }
    }

    impl Drop for TempFile {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.path);
        }
    }

    fn base_opt() -> Opt {
        Opt {
            url: Url::parse("quic://example.test:4433").unwrap(),
            bind_addr: None,
            ca_cert: None,
            server_cert_sha256: None,
            insecure: false,
            client_cert: None,
            client_key: None,
        }
    }

    #[test]
    fn parse_sha256_hex_accepts_valid_formats() {
        let expected: [u8; 32] = [
            0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54,
            0x32, 0x10, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb,
            0xcc, 0xdd, 0xee, 0xff,
        ];
        let lower = "0123456789abcdeffedcba987654321000112233445566778899aabbccddeeff";
        let upper = "0123456789ABCDEFFEDCBA987654321000112233445566778899AABBCCDDEEFF";
        let colons = "01:23:45:67:89:ab:cd:ef:fe:dc:ba:98:76:54:32:10:00:11:22:33:44:55:66:77:88:99:aa:bb:cc:dd:ee:ff";
        let prefixed_upper = format!("SHA256:{colons}");
        let prefixed_lower = format!("sha256:{lower}");

        assert_eq!(parse_sha256_hex(lower).unwrap(), expected);
        assert_eq!(parse_sha256_hex(upper).unwrap(), expected);
        assert_eq!(parse_sha256_hex(colons).unwrap(), expected);
        assert_eq!(parse_sha256_hex(&prefixed_upper).unwrap(), expected);
        assert_eq!(parse_sha256_hex(&prefixed_lower).unwrap(), expected);
    }

    #[test]
    fn parse_sha256_hex_rejects_invalid_inputs() {
        // Too short and too long
        assert!(parse_sha256_hex("").is_err());
        assert!(parse_sha256_hex("SHA256:").is_err());
        assert!(parse_sha256_hex("0123456789abcdef").is_err());
        assert!(
            parse_sha256_hex("0123456789abcdeffedcba987654321000112233445566778899aabbccddeeff00")
                .is_err()
        );

        // Non-hex characters
        assert!(
            parse_sha256_hex("g123456789abcdeffedcba987654321000112233445566778899aabbccddeeff")
                .is_err()
        );
        assert!(
            parse_sha256_hex("0123456789abcdeffedcba987654321000112233445566778899aabbccddee-f")
                .is_err()
        );

        // Malformed colon placement
        assert!(
            parse_sha256_hex(":0123456789abcdeffedcba987654321000112233445566778899aabbccddeeff")
                .is_err()
        );
        assert!(
            parse_sha256_hex("0123456789abcdeffedcba987654321000112233445566778899aabbccddeeff:")
                .is_err()
        );
        assert!(
            parse_sha256_hex("01::23456789abcdeffedcba987654321000112233445566778899aabbccddeeff")
                .is_err()
        );
    }

    #[test]
    fn pinned_cert_verifier_accepts_matching_and_rejects_mismatched_cert() {
        let provider = Arc::new(aws_lc_rs::default_provider());
        let cert_a = generate_simple_self_signed(vec!["a.example".to_string()]).unwrap();
        let cert_b = generate_simple_self_signed(vec!["b.example".to_string()]).unwrap();

        let digest_a = digest(&SHA256, cert_a.cert.der().as_ref());
        let expected: [u8; 32] = digest_a.as_ref().try_into().unwrap();
        let verifier = PinnedCertVerifier::new(expected, provider);
        let server_name = ServerName::try_from("a.example").unwrap();

        assert!(
            verifier
                .verify_server_cert(cert_a.cert.der(), &[], &server_name, &[], UnixTime::now())
                .is_ok()
        );

        let err = verifier
            .verify_server_cert(cert_b.cert.der(), &[], &server_name, &[], UnixTime::now())
            .unwrap_err();
        assert!(matches!(
            err,
            rustls::Error::InvalidCertificate(rustls::CertificateError::Other(_))
        ));

        // Even when the leaf cert matches the pin, a forged handshake signature must fail.
        let provider = Arc::new(aws_lc_rs::default_provider());
        let wrong_key = provider
            .key_provider
            .load_private_key(PrivateKeyDer::Pkcs8(
                cert_b.signing_key.serialize_der().into(),
            ))
            .unwrap();
        let forged_cert_key =
            rustls::sign::CertifiedKey::new(vec![cert_a.cert.der().clone()], wrong_key);
        let forged_server = Arc::new(
            rustls::ServerConfig::builder_with_provider(Arc::clone(&provider))
                .with_protocol_versions(&[&rustls::version::TLS13])
                .unwrap()
                .with_no_client_auth()
                .with_cert_resolver(Arc::new(rustls::sign::SingleCertAndKey::from(
                    forged_cert_key,
                ))),
        );
        let pinned_client = Arc::new(
            rustls::ClientConfig::builder_with_provider(Arc::clone(&provider))
                .with_protocol_versions(&[&rustls::version::TLS13])
                .unwrap()
                .dangerous()
                .with_custom_certificate_verifier(PinnedCertVerifier::new(
                    expected,
                    Arc::clone(&provider),
                ))
                .with_no_client_auth(),
        );
        let sig_err = run_tls13_handshake(pinned_client, forged_server, "a.example").unwrap_err();
        assert!(matches!(
            sig_err,
            rustls::Error::InvalidCertificate(rustls::CertificateError::BadSignature)
        ));
    }

    fn run_tls13_handshake(
        client_config: Arc<rustls::ClientConfig>,
        server_config: Arc<rustls::ServerConfig>,
        server_name: &str,
    ) -> Result<(), rustls::Error> {
        let mut client = rustls::ClientConnection::new(
            client_config,
            ServerName::try_from(server_name.to_owned()).unwrap(),
        )?;
        let mut server = rustls::ServerConnection::new(server_config)?;
        let mut buf = Vec::new();

        while client.is_handshaking() || server.is_handshaking() {
            buf.clear();
            client.write_tls(&mut buf).unwrap();
            if !buf.is_empty() {
                server.read_tls(&mut buf.as_slice()).unwrap();
                server.process_new_packets()?;
            }

            buf.clear();
            server.write_tls(&mut buf).unwrap();
            if !buf.is_empty() {
                client.read_tls(&mut buf.as_slice()).unwrap();
                client.process_new_packets()?;
            }
        }
        Ok(())
    }

    #[test]
    fn insecure_verifier_still_rejects_forged_tls13_handshake_signature() {
        let provider = Arc::new(aws_lc_rs::default_provider());
        let cert_a = generate_simple_self_signed(vec!["example.test".to_string()]).unwrap();
        let cert_b = generate_simple_self_signed(vec!["attacker.test".to_string()]).unwrap();

        let real_key = provider
            .key_provider
            .load_private_key(PrivateKeyDer::Pkcs8(
                cert_a.signing_key.serialize_der().into(),
            ))
            .unwrap();
        let wrong_key = provider
            .key_provider
            .load_private_key(PrivateKeyDer::Pkcs8(
                cert_b.signing_key.serialize_der().into(),
            ))
            .unwrap();

        let client_config = Arc::new(
            rustls::ClientConfig::builder_with_provider(Arc::clone(&provider))
                .with_protocol_versions(&[&rustls::version::TLS13])
                .unwrap()
                .dangerous()
                .with_custom_certificate_verifier(InsecureServerVerifier::new(Arc::clone(
                    &provider,
                )))
                .with_no_client_auth(),
        );

        // Server presents cert_a but signs CertificateVerify with cert_b's key (forged signature).
        let forged_cert_key =
            rustls::sign::CertifiedKey::new(vec![cert_a.cert.der().clone()], wrong_key);
        let forged_server = Arc::new(
            rustls::ServerConfig::builder_with_provider(Arc::clone(&provider))
                .with_protocol_versions(&[&rustls::version::TLS13])
                .unwrap()
                .with_no_client_auth()
                .with_cert_resolver(Arc::new(rustls::sign::SingleCertAndKey::from(
                    forged_cert_key,
                ))),
        );
        let err = run_tls13_handshake(Arc::clone(&client_config), forged_server, "example.test")
            .unwrap_err();
        assert!(matches!(
            err,
            rustls::Error::InvalidCertificate(rustls::CertificateError::BadSignature)
        ));

        // Server presenting cert_a with its real signing key succeeds under --insecure.
        let valid_cert_key =
            rustls::sign::CertifiedKey::new(vec![cert_a.cert.der().clone()], real_key);
        let valid_server = Arc::new(
            rustls::ServerConfig::builder_with_provider(Arc::clone(&provider))
                .with_protocol_versions(&[&rustls::version::TLS13])
                .unwrap()
                .with_no_client_auth()
                .with_cert_resolver(Arc::new(rustls::sign::SingleCertAndKey::from(
                    valid_cert_key,
                ))),
        );
        assert!(run_tls13_handshake(client_config, valid_server, "example.test").is_ok());
    }

    #[test]
    fn conflicting_tls_flags_and_partial_mtls_fail_fast() {
        let valid_hex = "0123456789abcdeffedcba987654321000112233445566778899aabbccddeeff";

        // CLI parser rejects mutually exclusive TLS options.
        assert!(
            Opt::try_parse_from([
                "client",
                "quic://example.test",
                "--ca-cert",
                "ca.pem",
                "--insecure"
            ])
            .is_err()
        );
        assert!(
            Opt::try_parse_from([
                "client",
                "quic://example.test",
                "--ca-cert",
                "ca.pem",
                "--server-cert-sha256",
                valid_hex,
            ])
            .is_err()
        );
        assert!(
            Opt::try_parse_from([
                "client",
                "quic://example.test",
                "--server-cert-sha256",
                valid_hex,
                "--insecure",
            ])
            .is_err()
        );

        // CLI parser rejects partial mTLS options.
        assert!(
            Opt::try_parse_from(["client", "quic://example.test", "--client-cert", "cert.pem"])
                .is_err()
        );
        assert!(
            Opt::try_parse_from(["client", "quic://example.test", "--client-key", "key.pem"])
                .is_err()
        );

        // Valid flag combinations parse cleanly.
        let default_opt = Opt::try_parse_from(["client", "quic://example.test"]).unwrap();
        assert!(!default_opt.insecure);
        assert!(
            Opt::try_parse_from(["client", "quic://example.test", "--ca-cert", "ca.pem"]).is_ok()
        );
        assert!(
            Opt::try_parse_from([
                "client",
                "quic://example.test",
                "--server-cert-sha256",
                valid_hex,
            ])
            .is_ok()
        );
        assert!(Opt::try_parse_from(["client", "quic://example.test", "--insecure"]).is_ok());
        assert!(
            Opt::try_parse_from([
                "client",
                "quic://example.test",
                "--client-cert",
                "cert.pem",
                "--client-key",
                "key.pem",
            ])
            .is_ok()
        );

        // Default platform-verifier mode configures cleanly.
        assert!(configure_client(&base_opt()).is_ok());

        // Programmatic Opt construction also fails fast in configure_client.
        let mut conflicting = base_opt();
        conflicting.ca_cert = Some(PathBuf::from("ca.pem"));
        conflicting.insecure = true;
        assert!(configure_client(&conflicting).is_err());

        let mut cert_only = base_opt();
        cert_only.insecure = true;
        cert_only.client_cert = Some(PathBuf::from("client.pem"));
        assert!(configure_client(&cert_only).is_err());

        let mut key_only = base_opt();
        key_only.insecure = true;
        key_only.client_key = Some(PathBuf::from("client.key"));
        assert!(configure_client(&key_only).is_err());
    }

    #[test]
    fn custom_ca_cert_loading_and_verification() {
        let provider = Arc::new(aws_lc_rs::default_provider());

        // Generate a custom CA and a server leaf signed by that CA.
        let mut ca_params = CertificateParams::new(Vec::<String>::new()).unwrap();
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        ca_params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
        let ca_key = KeyPair::generate().unwrap();
        let ca = CertifiedIssuer::self_signed(ca_params, ca_key).unwrap();

        let mut leaf_params = CertificateParams::new(vec!["example.test".to_string()]).unwrap();
        leaf_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        let leaf_key = KeyPair::generate().unwrap();
        let leaf_cert = leaf_params.signed_by(&leaf_key, &ca).unwrap();

        let ca_file = TempFile::new("ca.pem", ca.pem().as_bytes());
        let verifier = build_custom_ca_verifier(&ca_file.path, Arc::clone(&provider)).unwrap();

        // Trusted leaf with matching hostname succeeds.
        let valid_name = ServerName::try_from("example.test").unwrap();
        assert!(
            verifier
                .verify_server_cert(leaf_cert.der(), &[], &valid_name, &[], UnixTime::now())
                .is_ok()
        );

        // Wrong hostname fails.
        let wrong_name = ServerName::try_from("other.test").unwrap();
        assert!(
            verifier
                .verify_server_cert(leaf_cert.der(), &[], &wrong_name, &[], UnixTime::now())
                .is_err()
        );

        // Unrelated self-signed cert fails.
        let untrusted = generate_simple_self_signed(vec!["example.test".to_string()]).unwrap();
        assert!(
            verifier
                .verify_server_cert(untrusted.cert.der(), &[], &valid_name, &[], UnixTime::now())
                .is_err()
        );

        // configure_client succeeds with custom CA and optional mTLS client cert + key.
        let client_id = generate_simple_self_signed(vec!["client.test".to_string()]).unwrap();
        let client_cert_file = TempFile::new("client-cert.pem", client_id.cert.pem().as_bytes());
        let client_key_file = TempFile::new(
            "client-key.pem",
            client_id.signing_key.serialize_pem().as_bytes(),
        );

        let mut opt = base_opt();
        opt.ca_cert = Some(ca_file.path.clone());
        opt.client_cert = Some(client_cert_file.path.clone());
        opt.client_key = Some(client_key_file.path.clone());
        assert!(configure_client(&opt).is_ok());

        // Empty CA PEM file fails fast.
        let empty_ca = TempFile::new("empty-ca.pem", b"");
        assert!(build_custom_ca_verifier(&empty_ca.path, provider).is_err());
    }

    #[test]
    fn parse_sha256_hex_rejects_non_byte_aligned_colons() {
        // 64 single-nibble groups separated by colons
        let single_nibbles = "0123456789abcdeffedcba987654321000112233445566778899aabbccddeeff"
            .chars()
            .map(|c| c.to_string())
            .collect::<Vec<_>>()
            .join(":");
        assert!(parse_sha256_hex(&single_nibbles).is_err());

        // 3-char first group with 64 total hex characters
        let odd_grouped = "012:3:45:67:89:ab:cd:ef:fe:dc:ba:98:76:54:32:10:00:11:22:33:44:55:66:77:88:99:aa:bb:cc:dd:ee:ff";
        assert!(parse_sha256_hex(odd_grouped).is_err());

        // 16 groups of 4 hex characters (64 hex chars total, but not 32 byte groups)
        let four_char_groups =
            "0123:4567:89ab:cdef:fedc:ba98:7654:3210:0011:2233:4455:6677:8899:aabb:ccdd:eeff";
        assert!(parse_sha256_hex(four_char_groups).is_err());

        // Single colon inside 64 hex characters
        assert!(
            parse_sha256_hex("01:23456789abcdeffedcba987654321000112233445566778899aabbccddeeff")
                .is_err()
        );

        // 31 and 33 valid 2-hex-char colon-separated groups
        let thirty_one = "01:23:45:67:89:ab:cd:ef:fe:dc:ba:98:76:54:32:10:00:11:22:33:44:55:66:77:88:99:aa:bb:cc:dd:ee";
        let thirty_three = "01:23:45:67:89:ab:cd:ef:fe:dc:ba:98:76:54:32:10:00:11:22:33:44:55:66:77:88:99:aa:bb:cc:dd:ee:ff:00";
        assert!(parse_sha256_hex(thirty_one).is_err());
        assert!(parse_sha256_hex(thirty_three).is_err());
    }

    #[test]
    fn parse_target_url_validates_scheme_and_host() {
        assert_eq!(
            parse_target_url(&Url::parse("quic://example.test:4433").unwrap()).unwrap(),
            "example.test"
        );
        assert_eq!(
            parse_target_url(&Url::parse("quic://example.test").unwrap()).unwrap(),
            "example.test"
        );
        assert_eq!(
            parse_target_url(&Url::parse("quic://127.0.0.1:4433").unwrap()).unwrap(),
            "127.0.0.1"
        );
        assert_eq!(
            parse_target_url(&Url::parse("quic://[::1]:4433").unwrap()).unwrap(),
            "::1"
        );
        assert_eq!(
            parse_target_url(&Url::parse("quic://[2001:db8::1]:4433").unwrap()).unwrap(),
            "2001:db8::1"
        );

        // Non-quic schemes must be rejected.
        assert!(parse_target_url(&Url::parse("https://example.test:4433").unwrap()).is_err());
        assert!(parse_target_url(&Url::parse("ssh://example.test:22").unwrap()).is_err());
        assert!(parse_target_url(&Url::parse("http://127.0.0.1:4433").unwrap()).is_err());

        // Missing or empty host must be rejected.
        assert!(parse_target_url(&Url::parse("quic:///path").unwrap()).is_err());
        assert!(parse_target_url(&Url::parse("quic:path").unwrap()).is_err());

        // Unexpected userinfo, path, query, or fragment must be rejected fail-fast.
        assert!(parse_target_url(&Url::parse("quic://user@example.test:4433").unwrap()).is_err());
        assert!(
            parse_target_url(&Url::parse("quic://user:pass@example.test:4433").unwrap()).is_err()
        );
        assert!(parse_target_url(&Url::parse("quic://example.test:4433/ssh").unwrap()).is_err());
        assert!(
            parse_target_url(&Url::parse("quic://example.test:4433?foo=bar").unwrap()).is_err()
        );
        assert!(parse_target_url(&Url::parse("quic://example.test:4433#frag").unwrap()).is_err());
    }

    #[tokio::test]
    async fn custom_ca_rejects_expired_and_client_auth_only_server_certs() {
        let provider = Arc::new(aws_lc_rs::default_provider());

        let mut ca_params = CertificateParams::new(Vec::<String>::new()).unwrap();
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        ca_params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
        let ca_key = KeyPair::generate().unwrap();
        let ca = CertifiedIssuer::self_signed(ca_params, ca_key).unwrap();

        let ca_file = TempFile::new("ca-reject.pem", ca.pem().as_bytes());
        let verifier = build_custom_ca_verifier(&ca_file.path, Arc::clone(&provider)).unwrap();
        let server_name = ServerName::try_from("localhost").unwrap();

        // Control: valid ServerAuth leaf signed by the custom CA succeeds.
        let mut valid_params = CertificateParams::new(vec!["localhost".to_string()]).unwrap();
        valid_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        let valid_key = KeyPair::generate().unwrap();
        let valid_cert = valid_params.signed_by(&valid_key, &ca).unwrap();
        assert!(
            verifier
                .verify_server_cert(valid_cert.der(), &[], &server_name, &[], UnixTime::now())
                .is_ok()
        );

        // Expired ServerAuth leaf must be rejected with Expired/ExpiredContext.
        let mut expired_params = CertificateParams::new(vec!["localhost".to_string()]).unwrap();
        expired_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        expired_params.not_before = rcgen::date_time_ymd(2020, 1, 1);
        expired_params.not_after = rcgen::date_time_ymd(2021, 1, 1);
        let expired_key = KeyPair::generate().unwrap();
        let expired_cert = expired_params.signed_by(&expired_key, &ca).unwrap();
        let expired_err = verifier
            .verify_server_cert(expired_cert.der(), &[], &server_name, &[], UnixTime::now())
            .unwrap_err();
        assert!(
            matches!(
                expired_err,
                rustls::Error::InvalidCertificate(
                    rustls::CertificateError::Expired
                        | rustls::CertificateError::ExpiredContext { .. }
                )
            ),
            "expected expired certificate error, got: {expired_err:?}"
        );

        // ClientAuth-only leaf (missing ServerAuth EKU) must be rejected with InvalidPurpose*.
        let mut client_only_params = CertificateParams::new(vec!["localhost".to_string()]).unwrap();
        client_only_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
        let client_only_key = KeyPair::generate().unwrap();
        let client_only_cert = client_only_params.signed_by(&client_only_key, &ca).unwrap();
        let purpose_err = verifier
            .verify_server_cert(
                client_only_cert.der(),
                &[],
                &server_name,
                &[],
                UnixTime::now(),
            )
            .unwrap_err();
        assert!(
            matches!(
                purpose_err,
                rustls::Error::InvalidCertificate(
                    rustls::CertificateError::InvalidPurpose
                        | rustls::CertificateError::InvalidPurposeContext { .. }
                )
            ),
            "expected invalid purpose error for ClientAuth-only cert, got: {purpose_err:?}"
        );

        // End-to-end check through configure_client(--ca-cert) over QUIC loopback.
        let mut opt = base_opt();
        opt.ca_cert = Some(ca_file.path.clone());
        let client_cfg = configure_client(&opt).unwrap();
        let client_ep = make_client_endpoint("127.0.0.1:0".parse().unwrap(), client_cfg).unwrap();

        let make_server = |cert: &rcgen::Certificate, key: &KeyPair| -> (Endpoint, SocketAddr) {
            let server_tls = rustls::ServerConfig::builder_with_provider(Arc::clone(&provider))
                .with_protocol_versions(&[&rustls::version::TLS13])
                .unwrap()
                .with_no_client_auth()
                .with_single_cert(
                    vec![cert.der().clone()],
                    PrivateKeyDer::Pkcs8(key.serialize_der().into()),
                )
                .unwrap();
            let quic_cfg = quinn::crypto::rustls::QuicServerConfig::try_from(server_tls).unwrap();
            let ep = Endpoint::server(
                quinn::ServerConfig::with_crypto(Arc::new(quic_cfg)),
                "127.0.0.1:0".parse().unwrap(),
            )
            .unwrap();
            let addr = ep.local_addr().unwrap();
            (ep, addr)
        };

        for (label, cert, key, should_succeed) in [
            ("valid ServerAuth", &valid_cert, &valid_key, true),
            ("expired ServerAuth", &expired_cert, &expired_key, false),
            (
                "ClientAuth-only",
                &client_only_cert,
                &client_only_key,
                false,
            ),
        ] {
            let (server_ep, addr) = make_server(cert, key);
            let server_task = tokio::spawn(async move {
                let incoming = server_ep.accept().await.unwrap();
                let _ = incoming.await;
                server_ep
            });

            let connect_res = tokio::time::timeout(
                Duration::from_secs(5),
                client_ep.connect(addr, "localhost").unwrap(),
            )
            .await
            .expect("connect timed out");
            assert_eq!(
                connect_res.is_ok(),
                should_succeed,
                "unexpected handshake outcome for {label}: {connect_res:?}"
            );
            if let Ok(conn) = connect_res {
                conn.close(0u32.into(), b"done");
            }
            let _server_ep = server_task.await.unwrap();
        }
    }

    #[test]
    fn transport_config_hardening() {
        let mtud_debug = format!("{:?}", enable_mtud_if_supported());
        #[cfg(any(windows, target_os = "linux"))]
        assert!(
            mtud_debug.contains("mtu_discovery_config: Some("),
            "expected MTUD enabled on Windows/Linux, got: {mtud_debug}"
        );
        #[cfg(not(any(windows, target_os = "linux")))]
        assert!(
            mtud_debug.contains("mtu_discovery_config: None"),
            "expected MTUD disabled on non-(Windows|Linux), got: {mtud_debug}"
        );

        let transport_debug = format!("{:?}", build_transport_config());
        assert!(
            transport_debug.contains("datagram_receive_buffer_size: None"),
            "expected incoming datagrams disabled, got: {transport_debug}"
        );
        assert!(
            transport_debug.contains("keep_alive_interval: Some(15s)"),
            "expected 15s keep-alive interval, got: {transport_debug}"
        );
        assert!(
            transport_debug.contains("max_idle_timeout: Some(60000)"),
            "expected 60s idle timeout, got: {transport_debug}"
        );
        assert!(
            transport_debug.contains("max_concurrent_uni_streams: 0"),
            "expected server-initiated uni streams disabled, got: {transport_debug}"
        );
        assert!(
            transport_debug.contains("max_concurrent_bidi_streams: 0"),
            "expected server-initiated bidi streams disabled, got: {transport_debug}"
        );
        assert!(
            transport_debug.contains("stream_receive_window: 262144"),
            "expected 256 KiB stream receive window, got: {transport_debug}"
        );
        assert!(
            transport_debug.contains("receive_window: 524288"),
            "expected 512 KiB connection receive window, got: {transport_debug}"
        );
        assert!(
            transport_debug.contains("send_window: 524288"),
            "expected 512 KiB send window, got: {transport_debug}"
        );
    }

    #[tokio::test]
    async fn client_blocks_server_initiated_streams_while_allowing_client_open_bi() {
        let (server_ep, addr, sha256_hex) = make_loopback_quic_server(false);
        let client_ep = make_pinned_client_endpoint(sha256_hex);
        let (checks_done_tx, checks_done_rx) = tokio::sync::oneshot::channel::<()>();

        let server_task = tokio::spawn(async move {
            let conn = server_ep.accept().await.unwrap().await.unwrap();

            // Client-initiated bidirectional stream must succeed.
            let (mut send, mut recv) = conn.accept_bi().await.unwrap();
            let received = recv.read_to_end(1024).await.unwrap();
            assert_eq!(received, b"client-open-bi-ok");
            send.write_all(b"server-ack").await.unwrap();
            send.finish().unwrap();

            // Server-initiated uni and bidi streams must be blocked (client advertises 0).
            assert!(
                tokio::time::timeout(Duration::from_millis(150), conn.open_uni())
                    .await
                    .is_err(),
                "server-initiated open_uni() must be blocked by client transport limit 0"
            );
            assert!(
                tokio::time::timeout(Duration::from_millis(150), conn.open_bi())
                    .await
                    .is_err(),
                "server-initiated open_bi() must be blocked by client transport limit 0"
            );

            let _ = checks_done_tx.send(());
            let close_err = tokio::time::timeout(Duration::from_secs(2), conn.closed())
                .await
                .expect("server did not promptly receive CONNECTION_CLOSE");
            (server_ep, close_err)
        });

        let client_conn = client_ep.connect(addr, "localhost").unwrap().await.unwrap();
        let (mut send, mut recv) = client_conn.open_bi().await.unwrap();
        send.write_all(b"client-open-bi-ok").await.unwrap();
        send.finish().unwrap();
        let reply = recv.read_to_end(1024).await.unwrap();
        assert_eq!(reply, b"server-ack");

        // Wait until the server finishes verifying blocked open_uni/open_bi, then flush
        // CONNECTION_CLOSE as run_async does on exit.
        checks_done_rx.await.unwrap();
        client_conn.close(0u32.into(), b"done");
        let _ = tokio::time::timeout(Duration::from_millis(200), client_ep.wait_idle()).await;

        let (_server_ep, close_err) = server_task.await.unwrap();
        assert!(
            matches!(
                close_err,
                quinn::ConnectionError::ApplicationClosed(ref close) if close.reason.as_ref() == b"done"
            ),
            "expected server to observe done close, got: {close_err:?}"
        );
    }

    struct FailingWriter {
        fail_on_flush: bool,
    }

    impl AsyncWrite for FailingWriter {
        fn poll_write(
            self: std::pin::Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
            buf: &[u8],
        ) -> std::task::Poll<std::io::Result<usize>> {
            if self.fail_on_flush {
                std::task::Poll::Ready(Ok(buf.len()))
            } else {
                std::task::Poll::Ready(Err(std::io::Error::new(
                    std::io::ErrorKind::BrokenPipe,
                    "broken pipe on write",
                )))
            }
        }

        fn poll_flush(
            self: std::pin::Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            if self.fail_on_flush {
                std::task::Poll::Ready(Err(std::io::Error::new(
                    std::io::ErrorKind::BrokenPipe,
                    "broken pipe on flush",
                )))
            } else {
                std::task::Poll::Ready(Ok(()))
            }
        }

        fn poll_shutdown(
            self: std::pin::Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            std::task::Poll::Ready(Ok(()))
        }
    }

    fn make_loopback_quic_server(require_client_auth: bool) -> (Endpoint, SocketAddr, String) {
        let provider = Arc::new(aws_lc_rs::default_provider());
        let server_cert = generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
        let cert_der = server_cert.cert.der().clone();
        let key_der = PrivateKeyDer::Pkcs8(server_cert.signing_key.serialize_der().into());
        let sha256_hex: String = digest(&SHA256, cert_der.as_ref())
            .as_ref()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();

        let server_tls_builder = rustls::ServerConfig::builder_with_provider(Arc::clone(&provider))
            .with_protocol_versions(&[&rustls::version::TLS13])
            .unwrap();
        let server_tls = if require_client_auth {
            let mut ca_params = CertificateParams::new(Vec::<String>::new()).unwrap();
            ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
            ca_params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
            let ca = CertifiedIssuer::self_signed(ca_params, KeyPair::generate().unwrap()).unwrap();
            let mut roots = rustls::RootCertStore::empty();
            roots.add(ca.der().clone()).unwrap();
            let client_verifier = rustls::server::WebPkiClientVerifier::builder_with_provider(
                Arc::new(roots),
                Arc::clone(&provider),
            )
            .build()
            .unwrap();
            server_tls_builder
                .with_client_cert_verifier(client_verifier)
                .with_single_cert(vec![cert_der], key_der)
                .unwrap()
        } else {
            server_tls_builder
                .with_no_client_auth()
                .with_single_cert(vec![cert_der], key_der)
                .unwrap()
        };

        let quic_server_cfg =
            quinn::crypto::rustls::QuicServerConfig::try_from(server_tls).unwrap();
        let server_cfg = quinn::ServerConfig::with_crypto(Arc::new(quic_server_cfg));
        let bind: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let server_ep = Endpoint::server(server_cfg, bind).unwrap();
        let addr = server_ep.local_addr().unwrap();
        (server_ep, addr, sha256_hex)
    }

    fn make_pinned_client_endpoint(sha256_hex: String) -> Endpoint {
        let mut opt = base_opt();
        opt.server_cert_sha256 = Some(sha256_hex);
        let cfg = configure_client(&opt).unwrap();
        make_client_endpoint("127.0.0.1:0".parse().unwrap(), cfg).unwrap()
    }

    #[tokio::test]
    async fn relay_streams_half_close_continues_reading_until_remote_eof() {
        let (server_ep, addr, sha256_hex) = make_loopback_quic_server(false);
        let client_ep = make_pinned_client_endpoint(sha256_hex);

        let server_task = tokio::spawn(async move {
            let conn = server_ep.accept().await.unwrap().await.unwrap();
            let (mut send, mut recv) = conn.accept_bi().await.unwrap();
            let received = recv.read_to_end(1024).await.unwrap();
            assert_eq!(received, b"request-before-fin");

            // Delay briefly so the client's write side has already finished on stdin EOF.
            tokio::time::sleep(Duration::from_millis(20)).await;
            send.write_all(b"response-after-fin").await.unwrap();
            send.finish().unwrap();
            let _ = send.stopped().await;
            server_ep
        });

        let client_conn = client_ep.connect(addr, "localhost").unwrap().await.unwrap();
        let (send, recv) = client_conn.open_bi().await.unwrap();
        let mut out = Vec::new();

        let res = tokio::time::timeout(
            Duration::from_secs(5),
            relay_streams(
                &client_conn,
                send,
                recv,
                &b"request-before-fin"[..],
                &mut out,
                std::future::pending(),
            ),
        )
        .await
        .expect("relay timed out");

        assert!(res.is_ok(), "expected clean half-close completion: {res:?}");
        assert_eq!(out, b"response-after-fin");

        drop(client_conn);
        let _server_ep = server_task.await.unwrap();
    }

    #[tokio::test]
    async fn relay_streams_propagates_remote_error_after_stdin_eof() {
        let (server_ep, addr, sha256_hex) = make_loopback_quic_server(false);
        let client_ep = make_pinned_client_endpoint(sha256_hex);

        let server_task = tokio::spawn(async move {
            let conn = server_ep.accept().await.unwrap().await.unwrap();
            let (_send, mut recv) = conn.accept_bi().await.unwrap();
            let received = recv.read_to_end(1024).await.unwrap();
            assert_eq!(received, b"hello");

            // Reject the connection after client stdin has already reached EOF and sent FIN.
            conn.close(VarInt::from_u32(42), b"rejected");
            tokio::time::sleep(Duration::from_millis(50)).await;
            server_ep
        });

        let client_conn = client_ep.connect(addr, "localhost").unwrap().await.unwrap();
        let (send, recv) = client_conn.open_bi().await.unwrap();
        let mut out = Vec::new();

        let res = tokio::time::timeout(
            Duration::from_secs(5),
            relay_streams(
                &client_conn,
                send,
                recv,
                &b"hello"[..],
                &mut out,
                std::future::pending(),
            ),
        )
        .await
        .expect("relay timed out");

        assert!(
            res.is_err(),
            "expected remote connection error after stdin EOF to propagate"
        );
        let _server_ep = server_task.await.unwrap();
    }

    #[tokio::test]
    async fn relay_streams_propagates_mtls_rejection_even_with_empty_stdin() {
        let (server_ep, addr, sha256_hex) = make_loopback_quic_server(true);
        let client_ep = make_pinned_client_endpoint(sha256_hex);

        let server_task = tokio::spawn(async move {
            let incoming = server_ep.accept().await.unwrap();
            assert!(incoming.await.is_err());
            server_ep
        });

        let client_res: Result<(), Box<dyn Error>> =
            tokio::time::timeout(Duration::from_secs(5), async {
                let conn = client_ep.connect(addr, "localhost")?.await?;
                let (send, recv) = conn.open_bi().await?;
                let mut out = Vec::new();
                relay_streams(
                    &conn,
                    send,
                    recv,
                    tokio::io::empty(),
                    &mut out,
                    std::future::pending(),
                )
                .await
            })
            .await
            .expect("mtls test timed out");

        assert!(
            client_res.is_err(),
            "expected mTLS rejection error even with immediately-EOF stdin"
        );
        let _server_ep = server_task.await.unwrap();
    }

    #[tokio::test]
    async fn relay_streams_propagates_stdout_write_and_flush_errors() {
        for fail_on_flush in [false, true] {
            let (server_ep, addr, sha256_hex) = make_loopback_quic_server(false);
            let client_ep = make_pinned_client_endpoint(sha256_hex);

            let server_task = tokio::spawn(async move {
                let conn = server_ep.accept().await.unwrap().await.unwrap();
                let (mut send, _recv) = conn.accept_bi().await.unwrap();
                send.write_all(b"server-banner").await.unwrap();
                let _ = send.finish();
                tokio::time::sleep(Duration::from_millis(50)).await;
                server_ep
            });

            let client_conn = client_ep.connect(addr, "localhost").unwrap().await.unwrap();
            let (send, recv) = client_conn.open_bi().await.unwrap();
            // Send a byte so QUIC opens the stream on the wire while keeping stdin open
            // (no EOF) so only the broken stdout writer can terminate the relay.
            let (mut stdin_tx, stdin_rx) = tokio::io::duplex(64);
            stdin_tx.write_all(b"x").await.unwrap();
            let stdout = FailingWriter { fail_on_flush };

            let res = tokio::time::timeout(
                Duration::from_secs(5),
                relay_streams(
                    &client_conn,
                    send,
                    recv,
                    stdin_rx,
                    stdout,
                    std::future::pending(),
                ),
            )
            .await
            .expect("relay timed out");

            let err = res.expect_err("expected broken stdout to return Err");
            let msg = err.to_string();
            assert!(
                msg.contains("stdout"),
                "expected stdout error message (fail_on_flush={fail_on_flush}), got: {msg}"
            );
            drop(client_conn);
            let _server_ep = server_task.await.unwrap();
        }
    }

    #[tokio::test]
    async fn relay_streams_signal_closes_connection_after_stdin_eof() {
        let (server_ep, addr, sha256_hex) = make_loopback_quic_server(false);
        let client_ep = make_pinned_client_endpoint(sha256_hex);
        let (sig_tx, sig_rx) = tokio::sync::oneshot::channel::<()>();

        let server_task = tokio::spawn(async move {
            let conn = server_ep.accept().await.unwrap().await.unwrap();
            let (_send, mut recv) = conn.accept_bi().await.unwrap();
            let received = recv.read_to_end(1024).await.unwrap();
            assert_eq!(received, b"eof-then-signal");

            // Client is now waiting in the inner select! after stdin EOF; fire the signal.
            let _ = sig_tx.send(());
            let close_err = conn.closed().await;
            (server_ep, close_err)
        });

        let client_conn = client_ep.connect(addr, "localhost").unwrap().await.unwrap();
        let (send, recv) = client_conn.open_bi().await.unwrap();
        let mut out = Vec::new();

        let res = tokio::time::timeout(
            Duration::from_secs(5),
            relay_streams(
                &client_conn,
                send,
                recv,
                &b"eof-then-signal"[..],
                &mut out,
                async move {
                    let _ = sig_rx.await;
                },
            ),
        )
        .await
        .expect("relay timed out");

        assert!(res.is_ok(), "signal shutdown should exit cleanly: {res:?}");
        // Mirror run_async's unconditional flush; must not overwrite the "signal" reason.
        client_conn.close(0u32.into(), b"done");
        let _ = tokio::time::timeout(Duration::from_millis(200), client_ep.wait_idle()).await;

        let (_server_ep, close_err) = server_task.await.unwrap();
        assert!(
            matches!(
                close_err,
                quinn::ConnectionError::ApplicationClosed(ref close) if close.reason.as_ref() == b"signal"
            ),
            "expected server to observe signal close, got: {close_err:?}"
        );
    }
}
