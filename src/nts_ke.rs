use std::fmt;
use std::io::{self, Read, Write};
use std::net::{SocketAddr, TcpStream, ToSocketAddrs};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Arc};
use std::thread;
use std::time::{Duration, Instant};

use rustls::pki_types::ServerName;
use rustls::{ClientConfig, ClientConnection, RootCertStore, StreamOwned};

pub const DEFAULT_KE_PORT: u16 = 4460;
pub const ALPN: &[u8] = b"ntske/1";
const EXPORTER_LABEL: &[u8] = b"EXPORTER-network-time-security";

/// Next Protocol ID for NTPv4
pub const PROTOCOL_NTPV4: u16 = 0;
/// IANA AEAD ID for AEAD_AES_SIV_CMAC_256
pub const AEAD_AES_SIV_CMAC_256: u16 = 15;
const AES_SIV_CMAC_256_KEY_LEN: usize = 32;
const MAX_RESPONSE_LEN: usize = 64 * 1024;

pub mod record_type {
    pub const END_OF_MESSAGE: u16 = 0;
    pub const NEXT_PROTOCOL: u16 = 1;
    pub const ERROR: u16 = 2;
    pub const WARNING: u16 = 3;
    pub const AEAD_ALGORITHM: u16 = 4;
    pub const NEW_COOKIE: u16 = 5;
    pub const NTPV4_SERVER: u16 = 6;
    pub const NTPV4_PORT: u16 = 7;
}
use record_type::*;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Record {
    pub critical: bool,
    pub kind: u16,
    pub body: Vec<u8>,
}

impl Record {
    pub fn new(critical: bool, kind: u16, body: Vec<u8>) -> Self {
        Self {
            critical,
            kind,
            body,
        }
    }

    fn u16_list(critical: bool, kind: u16, values: &[u16]) -> Self {
        Self::new(
            critical,
            kind,
            values.iter().flat_map(|v| v.to_be_bytes()).collect(),
        )
    }

    pub fn encode(&self, out: &mut Vec<u8>) {
        let header = (self.kind & 0x7FFF) | if self.critical { 0x8000 } else { 0 };
        out.extend_from_slice(&header.to_be_bytes());
        out.extend_from_slice(&(self.body.len() as u16).to_be_bytes());
        out.extend_from_slice(&self.body);
    }

    fn body_u16s(&self) -> Result<Vec<u16>, KeError> {
        if !self.body.len().is_multiple_of(2) {
            return Err(KeError::BadResponse("odd-length u16 list"));
        }
        Ok(self
            .body
            .as_chunks::<2>()
            .0
            .iter()
            .map(|&c| u16::from_be_bytes(c))
            .collect())
    }
}

/// NTPv4, AES-SIV-CMAC-256, end of message
pub fn build_request() -> Vec<u8> {
    let mut out = Vec::new();
    Record::u16_list(true, NEXT_PROTOCOL, &[PROTOCOL_NTPV4]).encode(&mut out);
    Record::u16_list(true, AEAD_ALGORITHM, &[AEAD_AES_SIV_CMAC_256]).encode(&mut out);
    Record::new(true, END_OF_MESSAGE, vec![]).encode(&mut out);
    out
}

/// Reads records up to and including EOM
pub fn read_records(r: &mut impl Read) -> Result<Vec<Record>, KeError> {
    let mut records = Vec::new();
    let mut total = 0;
    loop {
        let mut header = [0u8; 4];
        r.read_exact(&mut header)?;
        let raw = u16::from_be_bytes([header[0], header[1]]);
        let len = u16::from_be_bytes([header[2], header[3]]) as usize;
        total += 4 + len;
        if total > MAX_RESPONSE_LEN {
            return Err(KeError::BadResponse("response too large"));
        }
        let mut body = vec![0u8; len];
        r.read_exact(&mut body)?;
        let record = Record::new(raw & 0x8000 != 0, raw & 0x7FFF, body);
        let done = record.kind == END_OF_MESSAGE;
        records.push(record);
        if done {
            return Ok(records);
        }
    }
}

/// What the server agreed to
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeResponse {
    pub aead: u16,
    pub cookies: Vec<Vec<u8>>,
    /// Absent means same host as the KE server
    pub ntp_server: Option<String>,
    /// Absent means 123
    pub ntp_port: Option<u16>,
}

/// Validates the server's records
pub fn parse_response(records: &[Record]) -> Result<KeResponse, KeError> {
    let mut protocol = None;
    let mut aead = None;
    let mut cookies = Vec::new();
    let mut ntp_server = None;
    let mut ntp_port = None;

    for rec in records {
        match rec.kind {
            END_OF_MESSAGE => break,
            ERROR => {
                let code = rec.body_u16s()?.first().copied().unwrap_or(u16::MAX);
                return Err(KeError::ServerError(code));
            }

            WARNING => {
                let code = rec.body_u16s()?.first().copied().unwrap_or(u16::MAX);
                return Err(KeError::ServerWarning(code));
            }

            NEXT_PROTOCOL => {
                if protocol.is_some() {
                    return Err(KeError::BadResponse("duplicate Next Protocol record"));
                }
                protocol = Some(rec.body_u16s()?);
            }
            AEAD_ALGORITHM => {
                if aead.is_some() {
                    return Err(KeError::BadResponse("duplicate AEAD record"));
                }
                aead = Some(rec.body_u16s()?);
            }
            NEW_COOKIE => cookies.push(rec.body.clone()),
            NTPV4_SERVER => {
                let s = std::str::from_utf8(&rec.body)
                    .ok()
                    .filter(|s| !s.is_empty() && s.is_ascii())
                    .ok_or(KeError::BadResponse("invalid NTPv4 server name"))?;
                ntp_server = Some(s.to_owned());
            }
            NTPV4_PORT => {
                let ports = rec.body_u16s()?;
                if ports.len() != 1 {
                    return Err(KeError::BadResponse("invalid NTPv4 port record"));
                }
                ntp_port = Some(ports[0]);
            }
            kind if rec.critical => return Err(KeError::UnrecognizedCritical(kind)),
            _ => {}
        }
    }

    if records.last().map(|r| r.kind) != Some(END_OF_MESSAGE) {
        return Err(KeError::BadResponse("missing End of Message"));
    }
    match protocol.as_deref() {
        Some([PROTOCOL_NTPV4]) => {}
        Some([]) => return Err(KeError::BadResponse("server accepted no protocol")),
        _ => return Err(KeError::BadResponse("server did not negotiate NTPv4")),
    }
    let aead = match aead.as_deref() {
        Some([AEAD_AES_SIV_CMAC_256]) => AEAD_AES_SIV_CMAC_256,
        _ => {
            return Err(KeError::BadResponse(
                "server did not pick an AEAD we offered",
            ));
        }
    };
    if cookies.is_empty() {
        return Err(KeError::BadResponse("server sent no cookies"));
    }
    Ok(KeResponse {
        aead,
        cookies,
        ntp_server,
        ntp_port,
    })
}

#[derive(Clone)]
pub struct NtsKeys {
    pub aead: u16,
    /// Client-to-server key
    pub c2s: Vec<u8>,
    /// Server-to-client key
    pub s2c: Vec<u8>,
    /// Single-use - each NTP request uses one and each reply gives new ones
    pub cookies: Vec<Vec<u8>>,
    pub ntp_server: String,
    pub ntp_port: u16,
    pub tls_version: String,
    pub cipher_suite: String,
    pub peer: SocketAddr,
    pub timings: KeTimings,
}

#[derive(Debug, Clone, Copy, Default)]
pub struct KeTimings {
    pub connect: Duration,
    pub handshake: Duration,
    pub exchange: Duration,
}

impl fmt::Debug for NtsKeys {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NtsKeys")
            .field("aead", &self.aead)
            .field("c2s", &"<redacted>")
            .field("s2c", &"<redacted>")
            .field("cookies", &self.cookies.len())
            .field("ntp_server", &self.ntp_server)
            .field("ntp_port", &self.ntp_port)
            .finish()
    }
}

#[derive(Debug)]
pub enum KeError {
    Resolve(String),
    InvalidName(String),
    Io(io::Error),
    Tls(rustls::Error),
    Timeout(&'static str),
    AlpnMismatch,
    ServerError(u16),
    ServerWarning(u16),
    UnrecognizedCritical(u16),
    BadResponse(&'static str),
}

impl fmt::Display for KeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Resolve(h) => write!(f, "could not resolve {h}"),
            Self::InvalidName(h) => write!(f, "{h:?} is not a valid TLS server name"),
            Self::Io(e) => write!(f, "network/TLS error: {e}"),
            Self::Tls(e) => write!(f, "TLS error: {e}"),
            Self::Timeout(phase) => write!(f, "timed out during {phase}"),
            Self::AlpnMismatch => write!(f, "server did not agree to ALPN \"ntske/1\""),
            Self::ServerError(c) => {
                let what = match c {
                    0 => "unrecognized critical record",
                    1 => "bad request",
                    2 => "internal server error",
                    _ => "unknown",
                };
                write!(f, "server returned error {c} ({what})")
            }
            Self::ServerWarning(c) => write!(f, "server returned unknown warning {c}"),
            Self::UnrecognizedCritical(t) => write!(f, "unrecognized critical record type {t}"),
            Self::BadResponse(why) => write!(f, "invalid NTS-KE response: {why}"),
        }
    }
}

impl std::error::Error for KeError {}

impl From<io::Error> for KeError {
    fn from(e: io::Error) -> Self {
        match e.kind() {
            io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut => Self::Timeout("network I/O"),
            _ => Self::Io(e),
        }
    }
}

/// Labels a timeout with the phase it happened in.
fn in_phase<T, E: Into<KeError>>(r: Result<T, E>, phase: &'static str) -> Result<T, KeError> {
    r.map_err(|e| match e.into() {
        KeError::Timeout(_) => KeError::Timeout(phase),
        other => other,
    })
}

impl From<rustls::Error> for KeError {
    fn from(e: rustls::Error) -> Self {
        Self::Tls(e)
    }
}

fn tls_config() -> Result<Arc<ClientConfig>, KeError> {
    let roots = RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let mut config =
        ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_protocol_versions(&[&rustls::version::TLS13])?
            .with_root_certificates(roots)
            .with_no_client_auth();
    config.alpn_protocols = vec![ALPN.to_vec()];
    Ok(Arc::new(config))
}

/// Exports one AEAD key - Context = protocol ID || AEAD ID || direction (0 = c2s, 1 = s2c).
fn export_key(conn: &ClientConnection, aead: u16, direction: u8) -> Result<Vec<u8>, KeError> {
    let mut context = Vec::with_capacity(5);
    context.extend_from_slice(&PROTOCOL_NTPV4.to_be_bytes());
    context.extend_from_slice(&aead.to_be_bytes());
    context.push(direction);
    let key = conn.export_keying_material(
        vec![0u8; AES_SIV_CMAC_256_KEY_LEN],
        EXPORTER_LABEL,
        Some(&context),
    )?;
    Ok(key)
}

/// Runs NTS-KE against `host:port` and returns keys + cookies
pub fn key_exchange(host: &str, port: u16, timeout: Duration) -> Result<NtsKeys, KeError> {
    let server_name =
        ServerName::try_from(host.to_owned()).map_err(|_| KeError::InvalidName(host.into()))?;

    let addrs: Vec<_> = (host, port)
        .to_socket_addrs()
        .map_err(|_| KeError::Resolve(host.into()))?
        .collect();
    let mut timings = KeTimings::default();
    let start = Instant::now();
    let (tcp, peer) = in_phase(connect_any(&addrs, timeout), "TCP connect")?;
    timings.connect = start.elapsed();
    tcp.set_read_timeout(Some(timeout))?;
    tcp.set_write_timeout(Some(timeout))?;

    let conn = ClientConnection::new(tls_config()?, server_name)?;
    let mut tls = StreamOwned::new(conn, tcp);

    // Finish the handshake first so ALPN is checked
    let start = Instant::now();
    while tls.conn.is_handshaking() {
        in_phase(tls.conn.complete_io(&mut tls.sock), "TLS handshake")?;
    }
    timings.handshake = start.elapsed();
    if tls.conn.alpn_protocol() != Some(ALPN) {
        return Err(KeError::AlpnMismatch);
    }

    let start = Instant::now();
    in_phase(tls.write_all(&build_request()), "sending request")?;
    in_phase(tls.flush(), "sending request")?;
    let records = in_phase(read_records(&mut tls), "waiting for response")?;
    let response = parse_response(&records)?;
    timings.exchange = start.elapsed();

    let c2s = export_key(&tls.conn, response.aead, 0)?;
    let s2c = export_key(&tls.conn, response.aead, 1)?;
    let tls_version = tls
        .conn
        .protocol_version()
        .map(|v| format!("{v:?}"))
        .unwrap_or_default();
    let cipher_suite = tls
        .conn
        .negotiated_cipher_suite()
        .map(|s| format!("{:?}", s.suite()))
        .unwrap_or_default();

    tls.conn.send_close_notify();
    let _ = tls.flush();

    Ok(NtsKeys {
        aead: response.aead,
        c2s,
        s2c,
        cookies: response.cookies,
        ntp_server: response.ntp_server.unwrap_or_else(|| host.to_owned()),
        ntp_port: response.ntp_port.unwrap_or(crate::client::DEFAULT_PORT),
        tls_version,
        cipher_suite,
        peer,
        timings,
    })
}

/// Happy Eyeballs (RFC 8305), simplified: start a connection attempt to the
/// next address every 250 ms instead of waiting out the full timeout on an
/// unreachable one, and use whichever connects first.
fn connect_any(addrs: &[SocketAddr], timeout: Duration) -> io::Result<(TcpStream, SocketAddr)> {
    const STAGGER: Duration = Duration::from_millis(250);
    let done = Arc::new(AtomicBool::new(false));
    let (tx, rx) = mpsc::channel();
    for (i, addr) in interleave_families(addrs).into_iter().enumerate() {
        let (tx, done) = (tx.clone(), done.clone());
        thread::spawn(move || {
            thread::sleep(STAGGER * i as u32);
            if done.load(Ordering::Relaxed) {
                return;
            }
            let _ = tx.send(TcpStream::connect_timeout(&addr, timeout).map(|s| (s, addr)));
        });
    }
    drop(tx);

    let mut last_err = io::Error::new(io::ErrorKind::NotFound, "no addresses to connect to");
    for result in rx {
        match result {
            Ok(winner) => {
                done.store(true, Ordering::Relaxed);
                return Ok(winner);
            }
            Err(e) => last_err = e,
        }
    }
    Err(last_err)
}

/// Alternates address families, starting with the resolver's first choice.
fn interleave_families(addrs: &[SocketAddr]) -> Vec<SocketAddr> {
    let Some(first) = addrs.first() else {
        return vec![];
    };
    let (mut preferred, mut other): (Vec<SocketAddr>, Vec<SocketAddr>) = addrs
        .iter()
        .partition(|a| a.is_ipv6() == first.is_ipv6());
    preferred.reverse();
    other.reverse();
    let mut out = Vec::with_capacity(addrs.len());
    while !preferred.is_empty() || !other.is_empty() {
        out.extend(preferred.pop());
        out.extend(other.pop());
    }
    out
}

/// [`key_exchange`], retrying a few times since a lost packet can stall the TLS handshake.
/// `on_retry` is told about each failed attempt that will be retried.
pub fn key_exchange_with_retries(
    host: &str,
    port: u16,
    timeout: Duration,
    mut on_retry: impl FnMut(u32, &KeError),
) -> Result<NtsKeys, KeError> {
    const ATTEMPTS: u32 = 3;
    let mut attempt = 1;
    loop {
        match key_exchange(host, port, timeout) {
            Ok(k) => return Ok(k),
            Err(e) if attempt < ATTEMPTS => {
                on_retry(attempt, &e);
                thread::sleep(Duration::from_secs(1));
                attempt += 1;
            }
            Err(e) => return Err(e),
        }
    }
}

/// Splits `host`, `host:port`, `[v6]:port` or a bare IPv6 address
pub fn split_host_port(s: &str, default_port: u16) -> Result<(String, u16), String> {
    let bad_port = || format!("invalid port in {s:?}");
    if let Some(rest) = s.strip_prefix('[') {
        let (host, after) = rest
            .split_once(']')
            .ok_or_else(|| format!("missing ] in {s:?}"))?;
        let port = match after.strip_prefix(':') {
            Some(p) => p.parse().map_err(|_| bad_port())?,
            None if after.is_empty() => default_port,
            None => return Err(bad_port()),
        };
        return Ok((host.to_owned(), port));
    }
    match s.rsplit_once(':') {
        Some((host, port)) if !host.contains(':') => {
            Ok((host.to_owned(), port.parse().map_err(|_| bad_port())?))
        }
        _ => Ok((s.to_owned(), default_port)), // no port or bare IPv6
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn encode_all(records: &[Record]) -> Vec<u8> {
        let mut out = Vec::new();
        records.iter().for_each(|r| r.encode(&mut out));
        out
    }

    fn eom() -> Record {
        Record::new(true, END_OF_MESSAGE, vec![])
    }

    fn good_response() -> Vec<Record> {
        vec![
            Record::u16_list(true, NEXT_PROTOCOL, &[PROTOCOL_NTPV4]),
            Record::u16_list(false, AEAD_ALGORITHM, &[AEAD_AES_SIV_CMAC_256]),
            Record::new(false, NEW_COOKIE, vec![1; 100]),
            Record::new(false, NEW_COOKIE, vec![2; 100]),
            eom(),
        ]
    }

    #[test]
    fn request_bytes() {
        assert_eq!(
            build_request(),
            [
                0x80, 0x01, 0x00, 0x02, 0x00, 0x00, // critical Next Protocol: [NTPv4]
                0x80, 0x04, 0x00, 0x02, 0x00, 0x0F, // critical AEAD: [15]
                0x80, 0x00, 0x00, 0x00, // critical End of Message
            ]
        );
    }

    #[test]
    fn read_records_roundtrip_and_stops_at_eom() {
        let mut bytes = encode_all(&good_response());
        bytes.extend_from_slice(&[0xFF; 8]); // trailing junk must not be read
        let mut cursor = io::Cursor::new(bytes);
        assert_eq!(read_records(&mut cursor).unwrap(), good_response());
        assert_eq!(
            cursor.position() as usize,
            encode_all(&good_response()).len()
        );
    }

    #[test]
    fn read_records_truncated() {
        let bytes = encode_all(&good_response());
        let mut cursor = io::Cursor::new(&bytes[..bytes.len() - 2]);
        assert!(matches!(read_records(&mut cursor), Err(KeError::Io(_))));
    }

    #[test]
    fn parse_good_response_with_defaults() {
        let r = parse_response(&good_response()).unwrap();
        assert_eq!(r.aead, AEAD_AES_SIV_CMAC_256);
        assert_eq!(r.cookies.len(), 2);
        assert_eq!((r.ntp_server, r.ntp_port), (None, None));
    }

    #[test]
    fn parse_server_and_port_override() {
        let mut recs = good_response();
        recs.insert(
            0,
            Record::new(false, NTPV4_SERVER, b"ntp.example.com".to_vec()),
        );
        recs.insert(0, Record::u16_list(false, NTPV4_PORT, &[1234]));
        let r = parse_response(&recs).unwrap();
        assert_eq!(r.ntp_server.as_deref(), Some("ntp.example.com"));
        assert_eq!(r.ntp_port, Some(1234));
    }

    #[test]
    fn parse_rejections() {
        let err = |recs: Vec<Record>| parse_response(&recs).unwrap_err().to_string();

        assert!(err(vec![Record::u16_list(true, ERROR, &[1]), eom()]).contains("bad request"));

        let mut recs = good_response();
        recs.insert(0, Record::new(true, 0x1234, vec![]));
        assert!(err(recs).contains("critical record type 4660"));

        let mut recs = good_response();
        recs.retain(|r| r.kind != NEW_COOKIE);
        assert!(err(recs).contains("no cookies"));

        let mut recs = good_response();
        recs[1] = Record::u16_list(false, AEAD_ALGORITHM, &[30]);
        assert!(err(recs).contains("AEAD"));

        let mut recs = good_response();
        recs[0] = Record::u16_list(true, NEXT_PROTOCOL, &[]);
        assert!(err(recs).contains("no protocol"));

        let mut recs = good_response();
        recs.pop();
        assert!(err(recs).contains("End of Message"));
    }

    #[test]
    fn unknown_noncritical_is_ignored() {
        let mut recs = good_response();
        recs.insert(0, Record::new(false, 0x1234, vec![9, 9]));
        assert!(parse_response(&recs).is_ok());
    }

    #[test]
    fn families_interleave() {
        let a: Vec<SocketAddr> = ["[::1]:1", "[::2]:1", "1.1.1.1:1", "2.2.2.2:1", "3.3.3.3:1"]
            .iter()
            .map(|s| s.parse().unwrap())
            .collect();
        let order: Vec<String> = interleave_families(&a)
            .iter()
            .map(|a| a.to_string())
            .collect();
        assert_eq!(
            order,
            ["[::1]:1", "1.1.1.1:1", "[::2]:1", "2.2.2.2:1", "3.3.3.3:1"]
        );
        assert!(interleave_families(&[]).is_empty());
    }

    #[test]
    fn host_port_splitting() {
        let ok = |s| split_host_port(s, 4460).unwrap();
        assert_eq!(
            ok("time.cloudflare.com"),
            ("time.cloudflare.com".into(), 4460)
        );
        assert_eq!(ok("example.com:1234"), ("example.com".into(), 1234));
        assert_eq!(ok("[::1]:99"), ("::1".into(), 99));
        assert_eq!(ok("[::1]"), ("::1".into(), 4460));
        assert_eq!(ok("2606:4700::1"), ("2606:4700::1".into(), 4460));
        assert!(split_host_port("example.com:x", 4460).is_err());
    }
}
