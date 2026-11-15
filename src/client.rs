//! 4 timestamps:
//! ```text
//!   client                 server
//!   T1 ──── request ────▶  T2
//!   T4 ◀──── reply ─────── T3
//!
//!   offset = ((T2 - T1) + (T3 - T4)) / 2   // how far our clock is behind (+) or ahead (-)
//!   delay  = (T4 - T1) - (T3 - T2)         // round trip minus server processing time
//! ```

use std::fmt;
use std::io;
use std::net::{SocketAddr, ToSocketAddrs, UdpSocket};
use std::time::{Duration, Instant, SystemTime};

use crate::nts::{random_bytes, NtsError};
use crate::packet::{DecodeError, LeapIndicator, Mode, NtpPacket, HEADER_LEN};
use crate::time::{NtpDuration, NtpTimestamp};

pub const DEFAULT_PORT: u16 = 123;

/// 1 successful request/response
#[derive(Debug, Clone)]
pub struct Sample {
    pub response: NtpPacket,
    pub t1: NtpTimestamp,
    pub t2: NtpTimestamp,
    pub t3: NtpTimestamp,
    pub t4: NtpTimestamp,
    /// Positive means server is ahead
    pub offset: NtpDuration,
    pub delay: NtpDuration,
}

#[derive(Debug)]
pub enum ClientError {
    Resolve(String),
    Io(io::Error),
    Timeout,
    Decode(DecodeError),
    UnexpectedMode(Mode),
    /// Stratum 0: slow down/go away
    KissOfDeath(String),
    ServerUnsynchronized,
    InvalidStratum(u8),
    ZeroTransmitTimestamp,
    Nts(NtsError),
}

impl fmt::Display for ClientError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Resolve(host) => write!(f, "could not resolve {host}"),
            Self::Io(e) => write!(f, "network error: {e}"),
            Self::Timeout => write!(f, "timed out waiting for a reply"),
            Self::Decode(e) => write!(f, "malformed reply: {e}"),
            Self::UnexpectedMode(m) => write!(f, "reply has mode {m:?}, expected Server"),
            Self::KissOfDeath(code) => write!(f, "server sent Kiss-o'-Death code {code:?}"),
            Self::ServerUnsynchronized => write!(f, "server reports its clock is unsynchronized"),
            Self::InvalidStratum(s) => write!(f, "invalid stratum {s}"),
            Self::ZeroTransmitTimestamp => write!(f, "reply has a zero transmit timestamp"),
            Self::Nts(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for ClientError {}

impl From<NtsError> for ClientError {
    fn from(e: NtsError) -> Self {
        Self::Nts(e)
    }
}

impl From<io::Error> for ClientError {
    fn from(e: io::Error) -> Self {
        match e.kind() {
            io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut => Self::Timeout,
            _ => Self::Io(e),
        }
    }
}

/// Resolves `host`, `host:port`, `ip`, `ip:port` or IPv6 as `[addr]:port`
pub fn resolve(server: &str) -> Result<SocketAddr, ClientError> {
    let mut addrs = match server.to_socket_addrs() {
        Ok(a) => a,
        // No port given (or a bare IPv6 address): use NTP default
        Err(_) => (server, DEFAULT_PORT)
            .to_socket_addrs()
            .map_err(|_| ClientError::Resolve(server.into()))?,
    };
    addrs
        .next()
        .ok_or_else(|| ClientError::Resolve(server.into()))
}

pub fn compute_offset_delay(
    t1: NtpTimestamp,
    t2: NtpTimestamp,
    t3: NtpTimestamp,
    t4: NtpTimestamp,
) -> (NtpDuration, NtpDuration) {
    let offset = ((t2 - t1).0 as i128 + (t3 - t4).0 as i128) / 2;
    let delay = (t4 - t1) - (t3 - t2);
    (NtpDuration(offset as i64), delay)
}

/// Hook for adding security to requests on top of the plain exchange
pub trait Protection {
    /// Turns the 48-byte header into the bytes to send
    fn request(&mut self, header: &[u8; HEADER_LEN]) -> Result<Vec<u8>, ClientError>;
    /// Checks a reply whose origin timestamp already matched
    fn verify(&mut self, packet: &NtpPacket, raw: &[u8]) -> Result<(), ClientError>;
}

/// Regular NTP
pub struct Plain;

impl Protection for Plain {
    fn request(&mut self, header: &[u8; HEADER_LEN]) -> Result<Vec<u8>, ClientError> {
        Ok(header.to_vec())
    }

    fn verify(&mut self, _: &NtpPacket, _: &[u8]) -> Result<(), ClientError> {
        Ok(())
    }
}

/// Sends a client request to `server` and waits up to `timeout` for a valid reply.
/// `protection` builds the request and checks the reply ([`Plain`] for none).
pub fn query_with(
    server: SocketAddr,
    timeout: Duration,
    protection: &mut impl Protection,
) -> Result<Sample, ClientError> {
    let bind: SocketAddr = if server.is_ipv4() {
        "0.0.0.0:0".parse().unwrap()
    } else {
        "[::]:0".parse().unwrap()
    };
    let socket = UdpSocket::bind(bind)?;
    socket.connect(server)?;

    let nonce = NtpTimestamp(u64::from_be_bytes(random_bytes()?));
    let request = protection.request(&NtpPacket::client_request(nonce).encode())?;

    let t1_wall = SystemTime::now();
    let t1_mono = Instant::now();
    socket.send(&request)?;

    let deadline = t1_mono + timeout;
    // NTS replies carrying 8 cookies are ~1 KB
    let mut buf = [0u8; 4096];
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(ClientError::Timeout);
        }
        socket.set_read_timeout(Some(remaining))?;
        let len = socket.recv(&mut buf)?;
        let elapsed = t1_mono.elapsed();

        let response = NtpPacket::decode(&buf[..len]).map_err(ClientError::Decode)?;
        if response.origin_ts != nonce {
            continue; // stale or bogus reply; keep waiting for ours
        }
        protection.verify(&response, &buf[..len])?;
        validate(&response)?;

        let t1 = NtpTimestamp::from_system_time(t1_wall);
        let t4 = t1 + NtpDuration::from_duration(elapsed);
        let (t2, t3) = (response.receive_ts, response.transmit_ts);
        let (offset, delay) = compute_offset_delay(t1, t2, t3, t4);
        return Ok(Sample {
            response,
            t1,
            t2,
            t3,
            t4,
            offset,
            delay,
        });
    }
}

/// Packet checks
fn validate(r: &NtpPacket) -> Result<(), ClientError> {
    if r.mode != Mode::Server {
        return Err(ClientError::UnexpectedMode(r.mode));
    }
    if r.stratum == 0 {
        return Err(ClientError::KissOfDeath(r.reference_id.ascii()));
    }
    if r.stratum > 15 {
        return Err(ClientError::InvalidStratum(r.stratum));
    }
    if r.leap == LeapIndicator::Unsynchronized {
        return Err(ClientError::ServerUnsynchronized);
    }
    if r.transmit_ts == NtpTimestamp::ZERO {
        return Err(ClientError::ZeroTransmitTimestamp);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ts(secs: f64) -> NtpTimestamp {
        NtpTimestamp((secs * 4_294_967_296.0) as u64)
    }

    #[test]
    fn offset_and_delay_symmetric_path() {
        // Our clock is 5 s slow. 100 ms each way, server takes 10 ms.
        let t1 = ts(1000.000); // our clock
        let t2 = ts(1005.100); // server clock = ours + 5 s, plus 100 ms transit
        let t3 = ts(1005.110);
        let t4 = ts(1000.210);
        let (offset, delay) = compute_offset_delay(t1, t2, t3, t4);
        assert!((offset.as_secs_f64() - 5.0).abs() < 1e-6, "{offset}");
        assert!((delay.as_secs_f64() - 0.2).abs() < 1e-6, "{delay}");
    }

    #[test]
    fn offset_negative_when_we_are_ahead() {
        let (offset, _) = compute_offset_delay(ts(100.0), ts(98.05), ts(98.05), ts(100.1));
        assert!((offset.as_secs_f64() + 2.0).abs() < 1e-6, "{offset}");
    }

    #[test]
    fn rejects_kiss_of_death_and_unsynced() {
        let mut r = NtpPacket::client_request(ts(1.0));
        r.mode = Mode::Server;
        r.stratum = 0;
        r.reference_id.0 = *b"RATE";
        assert!(matches!(validate(&r), Err(ClientError::KissOfDeath(c)) if c == "RATE"));

        r.stratum = 2;
        r.leap = LeapIndicator::Unsynchronized;
        assert!(matches!(
            validate(&r),
            Err(ClientError::ServerUnsynchronized)
        ));

        r.leap = LeapIndicator::NoWarning;
        assert!(validate(&r).is_ok());
    }

    #[test]
    fn resolve_forms() {
        assert_eq!(
            resolve("127.0.0.1").unwrap(),
            "127.0.0.1:123".parse().unwrap()
        );
        assert_eq!(
            resolve("127.0.0.1:1234").unwrap(),
            "127.0.0.1:1234".parse().unwrap()
        );
        assert_eq!(resolve("::1").unwrap(), "[::1]:123".parse().unwrap());
        assert_eq!(resolve("[::1]:999").unwrap(), "[::1]:999".parse().unwrap());
    }
}
