# quicssh-rs

> :smile: **quicssh-rs** is a QUIC proxy that allows to use QUIC to connect to an SSH server without needing to patch the client or the server.

`quicssh-rs` is [quicssh](https://github.com/moul/quicssh) rust implementation. It is based on [quinn](https://github.com/quinn-rs/quinn) and [tokio](https://github.com/tokio-rs/tokio)

Why use QUIC? Because SSH is vulnerable in TCP connection environments, and most SSH packets are actually small, so it is only necessary to maintain the SSH connection to use it in any network environment. QUIC is a good choice because it has good weak network optimization and an important feature called connection migration. This means that I can switch Wi-Fi networks freely when remote, ensuring a stable SSH connection.

## Demo

https://user-images.githubusercontent.com/39181969/235409750-234de94a-1189-4288-93c2-45f62a9dfc48.mp4

## Why not mosh?

Because the architecture of mosh requires the opening of many ports to support control and data connections, which is not very user-friendly in many environments. In addition, vscode remote development does not support mosh.

## Architecture

Standard SSH connection

```
┌───────────────────────────────────────┐             ┌───────────────────────┐
│                  bob                  │             │         wopr          │
│ ┌───────────────────────────────────┐ │             │ ┌───────────────────┐ │
│ │           ssh user@wopr           │─┼────tcp──────┼▶│       sshd        │ │
│ └───────────────────────────────────┘ │             │ └───────────────────┘ │
└───────────────────────────────────────┘             └───────────────────────┘
```

---

SSH Connection proxified with QUIC

```
┌───────────────────────────────────────┐             ┌───────────────────────┐
│                  bob                  │             │         wopr          │
│ ┌───────────────────────────────────┐ │             │ ┌───────────────────┐ │
│ │ssh -o ProxyCommand="quicssh-rs    │ │             │ │       sshd        │ │
│ │ client quic://%h:4433"            │ │             │ └───────────────────┘ │
│ │       user@wopr                   │ │             │           ▲           │
│ └───────────────────────────────────┘ │             │           │           │
│                   │                   │             │           │           │
│                process                │             │  tcp to localhost:22  │
│                   │                   │             │           │           │
│                   ▼                   │             │           │           │
│ ┌───────────────────────────────────┐ │             │┌─────────────────────┐│
│ │quicssh-rs client quic://wopr:4433 │─┼─quic (udp)─▶│   quicssh-rs server ││
│ └───────────────────────────────────┘ │             │└─────────────────────┘│
└───────────────────────────────────────┘             └───────────────────────┘
```

## Usage

```console
$ quicssh-rs -h
A simple ssh server based on quic protocol

Usage: quicssh-rs [OPTIONS] <COMMAND>

Commands:
  server  Server
  client  Client
  help    Print this message or the help of the given subcommand(s)

Options:
      --log <LOG_FILE>         Location of log file (defaults to stderr)
      --log-level <LOG_LEVEL>  Log level, Default Warn
  -h, --help                   Print help
  -V, --version                Print version
```

### Client

```console
$ quicssh-rs client -h
Client

Usage: quicssh-rs client [OPTIONS] <URL>

Arguments:
  <URL>  Server address

Options:
  -b, --bind <BIND_ADDR>
          Client address
      --ca-cert <CA_CERT>
          Custom PEM CA certificate(s) to verify the server certificate against
      --server-cert-sha256 <SERVER_CERT_SHA256>
          Pin the server's leaf certificate by SHA-256 hex digest
      --insecure
          Disable server certificate chain and hostname verification (insecure)
      --client-cert <CLIENT_CERT>
          PEM client certificate chain for mTLS
      --client-key <CLIENT_KEY>
          PEM client private key for mTLS
  -h, --help
          Print help
  -V, --version
          Print version
```

#### Client SSH Config

Using a certificate trusted by the OS trust store:

```sshconfig
Host test
    HostName ssh.example.com
    User alice
    Port 4433
    ProxyCommand quicssh-rs client quic://%h:%p
```

Using a private CA and mutual TLS (mTLS):

```sshconfig
Host test
    HostName ssh.example.com
    User alice
    Port 4433
    ProxyCommand quicssh-rs client --ca-cert ~/.ssh/quicssh-ca.pem --client-cert ~/.ssh/quicssh-client.pem --client-key ~/.ssh/quicssh-client-key.pem quic://%h:%p
```

Or pinning a self-signed server certificate by its SHA-256 fingerprint:

```sshconfig
Host test
    HostName ssh.example.com
    User alice
    Port 4433
    ProxyCommand quicssh-rs client --server-cert-sha256 <SHA256_HEX> quic://%h:%p
```

### Server

```console
$ quicssh-rs server -h
Server

Usage: quicssh-rs server [OPTIONS]

Options:
  -l, --listen <LISTEN>
          Address to listen on [default: 0.0.0.0:4433]
  -p, --proxy-to <PROXY_TO>
          Address of the ssh server
  -F, --conf <CONF_PATH>
          Path to TOML config file for SNI-based proxy routing
      --cert <CERT>
          Path to PEM-encoded TLS certificate chain
      --key <KEY>
          Path to PEM-encoded TLS private key
      --client-ca <CLIENT_CA>
          Path to PEM-encoded CA certificate(s) to enforce mTLS client authentication
      --max-connections <MAX_CONNECTIONS>
          Maximum number of concurrent connections [default: 256]
      --max-connections-per-ip <MAX_CONNECTIONS_PER_IP>
          Maximum number of concurrent connections per client IP (IPv6 grouped by /64) [default: 32]
      --no-retry
          Disable QUIC address validation Retry
  -h, --help
          Print help
  -V, --version
          Print version
```

Example with explicit TLS credentials and mTLS:

```console
$ quicssh-rs server \
    --listen 0.0.0.0:4433 \
    --proxy-to 127.0.0.1:22 \
    --cert /etc/quicssh/server.pem \
    --key /etc/quicssh/server-key.pem \
    --client-ca /etc/quicssh/client-ca.pem \
    --max-connections 256 \
    --max-connections-per-ip 32
```

#### SNI-based Proxy Configuration (`-F` / `--conf`)

To route incoming QUIC connections to different backend SSH servers based on TLS SNI, pass a TOML file with `-F` / `--conf`:

```toml
[proxy]
default = "127.0.0.1:22"
"git.example.com" = "127.0.0.1:2222"
"bastion.example.com" = "10.0.0.10:22"
```

- Quote hostnames containing dots so TOML parses them as flat keys in `[proxy]` rather than nested tables.
- SNI hostnames are matched **case-insensitively** against the keys in `[proxy]`.
- When an incoming connection's SNI does not match any entry in `[proxy]`, the default backend is chosen in the following precedence order: `--proxy-to` > `[proxy].default` > `127.0.0.1:22`.

## Security

- **TLS server verification is enabled by default**: `quicssh-rs client` validates the server certificate against the OS trust store by default. For private CAs or self-signed certificates, pass `--ca-cert <CA_CERT>` or pin the certificate fingerprint with `--server-cert-sha256 <SERVER_CERT_SHA256>`. Note that `--server-cert-sha256` pins the exact leaf certificate DER SHA-256 and verifies the TLS handshake signature, without checking CA chains, hostnames, or certificate expiry. The `--insecure` flag disables server verification and is an explicit opt-in only—avoid using it outside local testing.
- **Use mTLS on untrusted networks**: When exposing `quicssh-rs server` to the internet or any untrusted network, enabling mutual TLS (`--client-ca` on the server; `--client-cert` and `--client-key` on the client) is strongly recommended so only authorized clients can complete the QUIC handshake and reach backend TCP targets. Note that `--client-ca` currently validates certificate chains against the CA without CRL/OCSP revocation checks, and when combined with `-F/--conf`, any client holding a valid certificate from that CA can reach any configured SNI route. Keep QUIC Retry enabled (avoid `--no-retry`) and tune `--max-connections` and `--max-connections-per-ip` as needed.
- **Keep TLS private keys `0600 root:root` under systemd (`DynamicUser=yes`)**: When using the bundled `quicssh-rs.service` unit with `DynamicUser=yes`, do not weaken private key permissions to `0644` so the dynamic user can read them. Instead, pass credentials through systemd's `LoadCredential=` (for example `LoadCredential=server-key:/etc/quicssh/server-key.pem`) and reference `%d/server-key` in `ExecStart=`.
- **Source-IP masking (`127.0.0.1`) and backend exposure**: Because `quicssh-rs server` connects to `sshd` locally, `sshd` sees every proxied connection as coming from `127.0.0.1`:
  - Do **not** relax `sshd` authentication policies for loopback addresses (e.g., avoid `Match Address 127.0.0.1` rules that allow password or root login).
  - Be aware of `fail2ban` behavior: default configurations typically list `127.0.0.1/8` in `ignoreip` (so failed logins over QUIC will not be banned), while banning `127.0.0.1` would block all QUIC-proxied clients at once. Rely on SSH key authentication and mTLS instead of IP-based bans on `sshd`.
  - Avoid exposing internal non-SSH TCP services through `-F/--conf` SNI routing unless mTLS (`--client-ca`) is enabled, as an unauthenticated client that supplies a matching SNI hostname could otherwise reach those internal backends.
- **Log rotation for `--log`**: If `--log <LOG_FILE>` is enabled on a long-running server, configure external log rotation (e.g., `logrotate`) or prefer systemd journald (the default stderr output) to prevent unbounded log growth.

[![Powered by DartNode](https://dartnode.com/branding/DN-Open-Source-sm.png)](https://dartnode.com "Powered by DartNode - Free VPS for Open Source")
