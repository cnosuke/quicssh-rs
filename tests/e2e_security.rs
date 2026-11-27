use rcgen::{
    BasicConstraints, CertificateParams, CertifiedIssuer, ExtendedKeyUsagePurpose, IsCa, KeyPair,
    KeyUsagePurpose,
};
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, UdpSocket};
use std::path::PathBuf;
use std::process::{Child, ChildStderr, Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc;
use std::time::{Duration, Instant};

struct ChildGuard {
    child: Child,
    stderr_drainer: Option<std::thread::JoinHandle<()>>,
}

impl Drop for ChildGuard {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        if let Some(handle) = self.stderr_drainer.take() {
            let _ = handle.join();
        }
    }
}

struct TempDir {
    path: PathBuf,
}

impl TempDir {
    fn new(prefix: &str) -> Self {
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let id = COUNTER.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "quicssh-rs-e2e-{}-{}-{}",
            prefix,
            std::process::id(),
            id
        ));
        std::fs::create_dir_all(&path).expect("create temp dir");
        Self { path }
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

/// Continuously drains server stderr until EOF so the server process never hits EPIPE,
/// while signaling the first line matching `marker`.
fn spawn_stderr_drainer(
    stderr: ChildStderr,
    marker: &'static str,
) -> (mpsc::Receiver<String>, std::thread::JoinHandle<()>) {
    let (tx, rx) = mpsc::channel();
    let handle = std::thread::spawn(move || {
        let mut reader = BufReader::new(stderr);
        let mut line = String::new();
        let mut signaled = false;
        loop {
            line.clear();
            match reader.read_line(&mut line) {
                Ok(0) | Err(_) => break,
                Ok(_) => {
                    if !signaled && line.contains(marker) {
                        let _ = tx.send(line.clone());
                        signaled = true;
                    }
                }
            }
        }
    });
    (rx, handle)
}

fn free_udp_port() -> u16 {
    let sock = UdpSocket::bind("127.0.0.1:0").expect("bind ephemeral udp");
    sock.local_addr().expect("udp local addr").port()
}

fn spawn_one_shot_echo_tcp() -> (std::net::SocketAddr, std::thread::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind tcp");
    let addr = listener.local_addr().expect("tcp local addr");
    let handle = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("accept tcp");
        let mut buf = [0u8; 64];
        let n = stream.read(&mut buf).expect("read tcp");
        stream.write_all(&buf[..n]).expect("write tcp");
        stream.flush().expect("flush tcp");
    });
    (addr, handle)
}

/// Waits for TCP client half-close (EOF) before replying and closing.
fn spawn_half_close_tcp(
    reply: &'static [u8],
) -> (std::net::SocketAddr, std::thread::JoinHandle<Vec<u8>>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind tcp");
    let addr = listener.local_addr().expect("tcp local addr");
    let handle = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("accept tcp");
        let mut received = Vec::new();
        stream.read_to_end(&mut received).expect("read tcp to EOF");
        stream.write_all(reply).expect("write tcp reply");
        stream.flush().expect("flush tcp reply");
        received
    });
    (addr, handle)
}

#[test]
fn e2e_ephemeral_server_verifies_pin_rejects_default_and_mismatch_and_supports_insecure() {
    let bin = env!("CARGO_BIN_EXE_quicssh-rs");
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind backend");
    let backend_addr = listener.local_addr().expect("backend addr");
    // Serve two echo connections (pinned + insecure).
    let backend_handle = std::thread::spawn(move || {
        for _ in 0..2 {
            let (mut stream, _) = listener.accept().expect("accept tcp");
            let mut buf = [0u8; 64];
            let n = stream.read(&mut buf).expect("read tcp");
            stream.write_all(&buf[..n]).expect("write tcp");
            stream.flush().expect("flush tcp");
        }
    });

    let server_port = free_udp_port();
    let listen_addr = format!("127.0.0.1:{server_port}");

    let mut server = Command::new(bin)
        .args([
            "server",
            "--listen",
            &listen_addr,
            "--proxy-to",
            &backend_addr.to_string(),
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn server");

    let stderr = server.stderr.take().expect("server stderr");
    let (rx, drainer) = spawn_stderr_drainer(stderr, "SHA256:");
    let _server_guard = ChildGuard {
        child: server,
        stderr_drainer: Some(drainer),
    };

    let line = rx
        .recv_timeout(Duration::from_secs(5))
        .expect("server must log ephemeral SHA256 fingerprint by default");
    let pos = line.find("SHA256:").expect("SHA256 prefix");
    let fingerprint = line[pos..].trim().to_string();

    let url = format!("quic://127.0.0.1:{server_port}");

    // 1. Default client (OS trust store) must reject the untrusted self-signed cert.
    let default_out = Command::new(bin)
        .args(["client", &url])
        .stdin(Stdio::null())
        .output()
        .expect("run default client");
    assert!(
        !default_out.status.success(),
        "default client must reject untrusted self-signed server certificate"
    );
    let default_err = String::from_utf8_lossy(&default_out.stderr);
    assert!(
        default_err.contains("failed to establish QUIC connection")
            && (default_err.contains("certificate") || default_err.contains("crypto error")),
        "expected TLS certificate error on stderr, got: {default_err}"
    );

    // 2. Wrong SHA-256 pin must be rejected with pin mismatch error.
    let wrong_pin = "0000000000000000000000000000000000000000000000000000000000000000";
    let mismatch_out = Command::new(bin)
        .args(["client", "--server-cert-sha256", wrong_pin, &url])
        .stdin(Stdio::null())
        .output()
        .expect("run mismatch pin client");
    assert!(
        !mismatch_out.status.success(),
        "mismatched --server-cert-sha256 pin must be rejected"
    );
    let mismatch_err = String::from_utf8_lossy(&mismatch_out.stderr);
    assert!(
        mismatch_err.contains("fingerprint does not match")
            || mismatch_err.contains("invalid peer certificate"),
        "expected pin mismatch error on stderr, got: {mismatch_err}"
    );

    // 3. Matching SHA-256 pin must succeed, relay data, and exit promptly on server EOF
    //    even while client stdin remains open (no CPU busy-loop or runtime drop deadlock).
    let mut client = Command::new(bin)
        .args(["client", "--server-cert-sha256", &fingerprint, &url])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn pinned client");
    {
        let mut stdin = client.stdin.take().expect("client stdin");
        stdin.write_all(b"hello-quicssh").expect("write stdin");
        stdin.flush().expect("flush stdin");
        let _keep_stdin_open = stdin;

        let mut stdout = client.stdout.take().expect("client stdout");
        let mut received = Vec::new();
        stdout
            .read_to_end(&mut received)
            .expect("read stdout to EOF");
        assert_eq!(received, b"hello-quicssh");

        let start = Instant::now();
        let status = loop {
            if let Some(status) = client.try_wait().expect("try_wait client") {
                break status;
            }
            assert!(
                start.elapsed() < Duration::from_secs(3),
                "client must exit promptly on remote stream EOF"
            );
            std::thread::sleep(Duration::from_millis(20));
        };
        assert!(status.success(), "pinned client failed: {status}");
    }

    // 4. Explicit --insecure opt-in works and logs a warning to stderr.
    let mut insecure_client = Command::new(bin)
        .args(["client", "--insecure", &url])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn insecure client");
    {
        let mut stdin = insecure_client.stdin.take().expect("insecure stdin");
        stdin.write_all(b"insecure-ok").expect("write stdin");
        stdin.flush().expect("flush stdin");
    }
    let out = insecure_client
        .wait_with_output()
        .expect("wait insecure client");
    assert!(out.status.success(), "insecure client failed");
    assert_eq!(out.stdout, b"insecure-ok");
    let stderr_text = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr_text.contains("--insecure"),
        "expected warning on stderr when --insecure is used, got: {stderr_text}"
    );

    backend_handle.join().expect("backend thread");
}

#[test]
fn e2e_consecutive_sessions_release_single_connection_slot_immediately() {
    // H-1 regression test: with max_connections=1 and max_connections_per_ip=1, two consecutive
    // normal client sessions (where the backend closes first while client stdin stays open) must
    // both succeed back-to-back without waiting 60s for idle timeout.
    let bin = env!("CARGO_BIN_EXE_quicssh-rs");
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind backend");
    let backend_addr = listener.local_addr().expect("backend addr");
    let backend_handle = std::thread::spawn(move || {
        for _ in 0..2 {
            let (mut stream, _) = listener.accept().expect("accept tcp");
            let mut buf = [0u8; 64];
            let n = stream.read(&mut buf).expect("read tcp");
            stream.write_all(&buf[..n]).expect("write tcp");
            stream.flush().expect("flush tcp");
        }
    });

    let server_port = free_udp_port();
    let listen_addr = format!("127.0.0.1:{server_port}");

    let mut server = Command::new(bin)
        .args([
            "server",
            "--listen",
            &listen_addr,
            "--proxy-to",
            &backend_addr.to_string(),
            "--max-connections",
            "1",
            "--max-connections-per-ip",
            "1",
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn single-slot server");

    let stderr = server.stderr.take().expect("server stderr");
    let (rx, drainer) = spawn_stderr_drainer(stderr, "SHA256:");
    let _server_guard = ChildGuard {
        child: server,
        stderr_drainer: Some(drainer),
    };

    let line = rx
        .recv_timeout(Duration::from_secs(5))
        .expect("fingerprint");
    let fingerprint = line[line.find("SHA256:").unwrap()..].trim().to_string();
    let url = format!("quic://127.0.0.1:{server_port}");

    let start = Instant::now();
    for payload in [b"session-1".as_slice(), b"session-2".as_slice()] {
        let mut client = Command::new(bin)
            .args(["client", "--server-cert-sha256", &fingerprint, &url])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn client");
        let mut stdin = client.stdin.take().expect("stdin");
        stdin.write_all(payload).expect("write");
        stdin.flush().expect("flush");
        let _keep_open = stdin;

        let mut stdout = client.stdout.take().expect("stdout");
        let mut received = Vec::new();
        stdout.read_to_end(&mut received).expect("read stdout");
        assert_eq!(received, payload);

        let status = client.wait().expect("wait client");
        assert!(status.success(), "client failed: {status}");
    }
    assert!(
        start.elapsed() < Duration::from_secs(5),
        "consecutive sessions on max_connections=1 server took too long: {:?}",
        start.elapsed()
    );

    backend_handle.join().expect("backend thread");
}

#[test]
fn e2e_half_close_delivers_full_response_after_stdin_eof() {
    let bin = env!("CARGO_BIN_EXE_quicssh-rs");
    let (backend_addr, backend_handle) = spawn_half_close_tcp(b"reply-after-half-close");
    let server_port = free_udp_port();
    let listen_addr = format!("127.0.0.1:{server_port}");

    let mut server = Command::new(bin)
        .args([
            "server",
            "--listen",
            &listen_addr,
            "--proxy-to",
            &backend_addr.to_string(),
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn server");

    let stderr = server.stderr.take().expect("server stderr");
    let (rx, drainer) = spawn_stderr_drainer(stderr, "SHA256:");
    let _server_guard = ChildGuard {
        child: server,
        stderr_drainer: Some(drainer),
    };

    let line = rx
        .recv_timeout(Duration::from_secs(5))
        .expect("fingerprint");
    let fingerprint = line[line.find("SHA256:").unwrap()..].trim().to_string();
    let url = format!("quic://127.0.0.1:{server_port}");

    let mut client = Command::new(bin)
        .args(["client", "--server-cert-sha256", &fingerprint, &url])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn client");

    // Write request and immediately close stdin (triggering client half-close FIN).
    {
        let mut stdin = client.stdin.take().expect("client stdin");
        stdin
            .write_all(b"request-before-eof")
            .expect("write request");
        stdin.flush().expect("flush request");
    }

    let output = client.wait_with_output().expect("wait client");
    assert!(
        output.status.success(),
        "half-close client failed: {} ({})",
        output.status,
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(output.stdout, b"reply-after-half-close");

    let backend_received = backend_handle.join().expect("backend thread");
    assert_eq!(backend_received, b"request-before-eof");
}

#[test]
fn e2e_mtls_rejects_unauth_even_with_null_stdin_and_wrong_ca_and_relays_valid_client() {
    let bin = env!("CARGO_BIN_EXE_quicssh-rs");
    let dir = TempDir::new("mtls");

    let mut ca_params = CertificateParams::new(Vec::<String>::new()).expect("ca params");
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca_params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    let ca_key = KeyPair::generate().expect("ca key");
    let ca = CertifiedIssuer::self_signed(ca_params, ca_key).expect("ca issuer");

    let mut other_ca_params = CertificateParams::new(Vec::<String>::new()).expect("other ca");
    other_ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    other_ca_params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    let other_ca_key = KeyPair::generate().expect("other ca key");
    let other_ca = CertifiedIssuer::self_signed(other_ca_params, other_ca_key).expect("other ca");

    let mut server_params =
        CertificateParams::new(vec!["127.0.0.1".into()]).expect("server params");
    server_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    let server_key = KeyPair::generate().expect("server key");
    let server_cert = server_params
        .signed_by(&server_key, &ca)
        .expect("sign server");

    let mut client_params =
        CertificateParams::new(vec!["client.local".into()]).expect("client params");
    client_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
    let client_key = KeyPair::generate().expect("client key");
    let client_cert = client_params
        .signed_by(&client_key, &ca)
        .expect("sign client");

    let mut rogue_params =
        CertificateParams::new(vec!["rogue.local".into()]).expect("rogue params");
    rogue_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
    let rogue_key = KeyPair::generate().expect("rogue key");
    let rogue_cert = rogue_params
        .signed_by(&rogue_key, &other_ca)
        .expect("sign rogue client");

    let ca_path = dir.path.join("ca.pem");
    let server_cert_path = dir.path.join("server.pem");
    let server_key_path = dir.path.join("server.key");
    let client_cert_path = dir.path.join("client.pem");
    let client_key_path = dir.path.join("client.key");
    let rogue_cert_path = dir.path.join("rogue.pem");
    let rogue_key_path = dir.path.join("rogue.key");

    std::fs::write(&ca_path, ca.pem()).expect("write ca");
    std::fs::write(&server_cert_path, server_cert.pem()).expect("write server cert");
    std::fs::write(&server_key_path, server_key.serialize_pem()).expect("write server key");
    std::fs::write(&client_cert_path, client_cert.pem()).expect("write client cert");
    std::fs::write(&client_key_path, client_key.serialize_pem()).expect("write client key");
    std::fs::write(&rogue_cert_path, rogue_cert.pem()).expect("write rogue cert");
    std::fs::write(&rogue_key_path, rogue_key.serialize_pem()).expect("write rogue key");

    let (backend_addr, backend_handle) = spawn_one_shot_echo_tcp();
    let server_port = free_udp_port();
    let listen_addr = format!("127.0.0.1:{server_port}");

    let mut server = Command::new(bin)
        .args([
            "--log-level",
            "info",
            "server",
            "--listen",
            &listen_addr,
            "--proxy-to",
            &backend_addr.to_string(),
            "--cert",
            server_cert_path.to_str().unwrap(),
            "--key",
            server_key_path.to_str().unwrap(),
            "--client-ca",
            ca_path.to_str().unwrap(),
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn mtls server");

    let stderr = server.stderr.take().expect("server stderr");
    let (rx, drainer) = spawn_stderr_drainer(stderr, "listening on:");
    let _server_guard = ChildGuard {
        child: server,
        stderr_drainer: Some(drainer),
    };
    rx.recv_timeout(Duration::from_secs(5))
        .expect("mTLS server did not start listening");

    let url = format!("quic://127.0.0.1:{server_port}");

    // 1. Client without client certificate must fail EVEN with Stdio::null() (M2 regression test).
    let unauth_out = Command::new(bin)
        .args(["client", "--ca-cert", ca_path.to_str().unwrap(), &url])
        .stdin(Stdio::null())
        .output()
        .expect("run unauth client");
    assert!(
        !unauth_out.status.success(),
        "unauthenticated client must fail against mTLS server even when stdin is closed"
    );
    let unauth_err = String::from_utf8_lossy(&unauth_out.stderr);
    assert!(
        unauth_err.contains("certificate") || unauth_err.contains("crypto error"),
        "expected mTLS certificate alert on stderr, got: {unauth_err}"
    );

    // 2. Client with a certificate signed by an untrusted CA must also fail with Stdio::null().
    let rogue_out = Command::new(bin)
        .args([
            "client",
            "--ca-cert",
            ca_path.to_str().unwrap(),
            "--client-cert",
            rogue_cert_path.to_str().unwrap(),
            "--client-key",
            rogue_key_path.to_str().unwrap(),
            &url,
        ])
        .stdin(Stdio::null())
        .output()
        .expect("run rogue client");
    assert!(
        !rogue_out.status.success(),
        "client signed by wrong CA must fail against mTLS server"
    );
    let rogue_err = String::from_utf8_lossy(&rogue_out.stderr);
    assert!(
        rogue_err.contains("certificate") || rogue_err.contains("crypto error"),
        "expected mTLS certificate rejection on stderr, got: {rogue_err}"
    );

    // 3. Client with valid CA-signed certificate must succeed and relay data.
    let mut auth_client = Command::new(bin)
        .args([
            "client",
            "--ca-cert",
            ca_path.to_str().unwrap(),
            "--client-cert",
            client_cert_path.to_str().unwrap(),
            "--client-key",
            client_key_path.to_str().unwrap(),
            &url,
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn mtls client");
    {
        let mut stdin = auth_client.stdin.take().expect("client stdin");
        stdin.write_all(b"mtls-ok").expect("write");
        stdin.flush().expect("flush");
    }
    let output = auth_client.wait_with_output().expect("wait auth client");
    assert!(
        output.status.success(),
        "mTLS client failed: {} ({})",
        output.status,
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(output.stdout, b"mtls-ok");

    backend_handle.join().expect("backend thread");
}

#[test]
fn e2e_ipv6_loopback_literal_connection() {
    // Gracefully skip only if the host does not support IPv6 loopback.
    let Ok(sock) = UdpSocket::bind("[::1]:0") else {
        return;
    };
    let server_port = sock.local_addr().expect("ipv6 udp addr").port();
    drop(sock);

    let bin = env!("CARGO_BIN_EXE_quicssh-rs");
    let (backend_addr, backend_handle) = spawn_one_shot_echo_tcp();
    let listen_addr = format!("[::1]:{server_port}");

    let mut server = Command::new(bin)
        .args([
            "server",
            "--listen",
            &listen_addr,
            "--proxy-to",
            &backend_addr.to_string(),
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn ipv6 server");

    let stderr = server.stderr.take().expect("server stderr");
    let (rx, drainer) = spawn_stderr_drainer(stderr, "SHA256:");
    let _server_guard = ChildGuard {
        child: server,
        stderr_drainer: Some(drainer),
    };

    let line = rx
        .recv_timeout(Duration::from_secs(5))
        .expect("fingerprint");
    let fingerprint = line[line.find("SHA256:").unwrap()..].trim().to_string();
    let url = format!("quic://[::1]:{server_port}");

    let mut client = Command::new(bin)
        .args(["client", "--server-cert-sha256", &fingerprint, &url])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn ipv6 client");
    {
        let mut stdin = client.stdin.take().expect("stdin");
        stdin.write_all(b"ipv6-ok").expect("write");
        stdin.flush().expect("flush");
    }
    let output = client.wait_with_output().expect("wait ipv6 client");
    assert!(
        output.status.success(),
        "IPv6 client failed: {} ({})",
        output.status,
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(output.stdout, b"ipv6-ok");

    backend_handle.join().expect("backend thread");
}
