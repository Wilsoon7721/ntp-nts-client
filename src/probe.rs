use std::time::Duration;

use crate::client::{fmt_host_port, query_with, resolve, Plain};
use crate::nts::NtsSession;
use crate::nts_ke;

#[derive(Debug, Clone, PartialEq)]
pub enum Probe {
    /// NTS-KE worked and an authenticated query got a valid reply
    Nts { offset_ms: f64 },
    /// No NTS, but plain NTP answered
    NtpOnly { nts_error: String, offset_ms: f64 },
    Neither { nts_error: String, ntp_error: String },
}

pub fn probe(host: &str, timeout: Duration) -> Probe {
    let nts_error = match probe_nts(host, timeout) {
        Ok(offset_ms) => return Probe::Nts { offset_ms },
        Err(e) => e,
    };
    match probe_ntp(host, timeout) {
        Ok(offset_ms) => Probe::NtpOnly {
            nts_error,
            offset_ms,
        },
        Err(ntp_error) => Probe::Neither {
            nts_error,
            ntp_error,
        },
    }
}

fn probe_nts(host: &str, timeout: Duration) -> Result<f64, String> {
    let (ke_host, port) = nts_ke::split_host_port(host, nts_ke::DEFAULT_KE_PORT)?;
    let keys = nts_ke::key_exchange(&ke_host, port, timeout).map_err(|e| e.to_string())?;
    let addr = resolve(&fmt_host_port(&keys.ntp_server, keys.ntp_port)).map_err(|e| e.to_string())?;
    let mut session = NtsSession::new(keys);
    let sample = query_with(addr, timeout, &mut session).map_err(|e| e.to_string())?;
    Ok(sample.offset.as_millis_f64())
}

fn probe_ntp(host: &str, timeout: Duration) -> Result<f64, String> {
    let addr = resolve(host).map_err(|e| e.to_string())?;
    let sample = query_with(addr, timeout, &mut Plain).map_err(|e| e.to_string())?;
    Ok(sample.offset.as_millis_f64())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nothing_listening_on_localhost() {
        // Nothing serves NTS-KE or NTP on loopback here (W32Time only binds when running)
        match probe("127.0.0.1", Duration::from_millis(500)) {
            Probe::Neither { .. } | Probe::NtpOnly { .. } => {}
            other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    #[ignore = "needs internet; run with --ignored"]
    fn live_servers() {
        let t = Duration::from_secs(5);
        let p = probe("time.cloudflare.com", t);
        assert!(matches!(p, Probe::Nts { .. }), "{p:?}");
        let p = probe("time.windows.com", t);
        assert!(matches!(p, Probe::NtpOnly { .. }), "{p:?}");
        let p = probe("example.com", Duration::from_secs(2));
        assert!(matches!(p, Probe::Neither { .. }), "{p:?}");
    }

    #[test]
    fn unresolvable_host() {
        let p = probe("no-such-host.invalid", Duration::from_millis(500));
        assert!(matches!(p, Probe::Neither { .. }), "{p:?}");
    }
}
