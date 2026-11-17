//! --sync: Keeps the system clock in sync until stopped

use std::cell::Cell;
use std::net::SocketAddr;
use std::sync::mpsc::{Receiver, RecvTimeoutError};
use std::thread::sleep;
use std::time::{Duration, Instant, SystemTime};

use crate::client::{query_with, resolve, ClientError, Sample};
use crate::discipline::{Action, Discipline};
use crate::nts::{NtsError, NtsSession};
use crate::{clock, fmt_host_port, ke_with_retries, nts_ke, time, Args};

/// Where log lines go
pub type Log<'a> = &'a mut dyn FnMut(&str);

/// Lets another thread ask the loop to stop
pub struct Stop {
    rx: Option<Receiver<()>>,
    stopped: Cell<bool>,
}

impl Stop {
    /// Runs until the process ends (console: Ctrl+C)
    pub fn never() -> Self {
        Self {
            rx: None,
            stopped: Cell::new(false),
        }
    }

    /// Stops when something is sent on (or the sender for) `rx` is dropped
    pub fn on(rx: Receiver<()>) -> Self {
        Self {
            rx: Some(rx),
            stopped: Cell::new(false),
        }
    }

    /// Sleeps for `d`, waking early if asked to stop. Returns true if stopping.
    fn wait(&self, d: Duration) -> bool {
        if self.stopped.get() {
            return true;
        }
        let Some(rx) = &self.rx else {
            sleep(d);
            return false;
        };
        match rx.recv_timeout(d) {
            Err(RecvTimeoutError::Timeout) => false,
            Ok(()) | Err(RecvTimeoutError::Disconnected) => {
                self.stopped.set(true);
                true
            }
        }
    }
}

/// Puts the clock rate back to Windows' default when dropped (stop, errors, panics)
struct RateGuard;

impl Drop for RateGuard {
    fn drop(&mut self) {
        let _ = clock::reset_rate();
    }
}

pub fn run(args: &Args, stop: &Stop, log: Log) -> Result<(), String> {
    let (host, port) = nts_ke::split_host_port(&args.server, nts_ke::DEFAULT_KE_PORT)
        .map_err(|e| e.to_string())?;
    clock::enable_privilege().map_err(|e| e.to_string())?;
    match clock::w32time_running() {
        Ok(false) => {}
        Ok(true) => {
            return Err(
                "the Windows Time service is running and would fight over the clock. \
                 Stop it first (elevated terminal): net stop w32time"
                    .into(),
            );
        }
        Err(e) => return Err(format!("could not check the Windows Time service: {e}")),
    }
    let _guard = RateGuard;

    line(
        log,
        format_args!(
            "Syncing the clock to {host} over NTS every {} s",
            args.poll.as_secs()
        ),
    );
    let start = Instant::now();
    let mut discipline = Discipline::new(args.poll.as_secs_f64());
    let mut nts: Option<(NtsSession, SocketAddr)> = None;

    loop {
        let poll_start = Instant::now();
        if nts.is_none() {
            nts = connect(&host, port, args, log);
        }

        let best = match &mut nts {
            Some((session, addr)) => {
                let (best, rekey) = burst(*addr, args, session, stop, log);
                if rekey {
                    nts = None;
                }
                best
            }
            None => None,
        };
        if stop.wait(Duration::ZERO) {
            break;
        }

        let result = match best {
            Some((at, sample)) => {
                let t = at.duration_since(start).as_secs_f64();
                apply(&mut discipline, t, &sample, log)
            }
            None => {
                line(log, format_args!("no valid replies, holding frequency"));
                clock::set_rate(discipline.holdover(start.elapsed().as_secs_f64()))
            }
        };
        result.map_err(|e| e.to_string())?;

        if stop.wait(args.poll.saturating_sub(poll_start.elapsed())) {
            break;
        }
    }
    line(
        log,
        format_args!("Stopping, clock rate handed back to Windows"),
    );
    Ok(())
}

fn line(log: Log, msg: std::fmt::Arguments) {
    log(&format!("{}  {msg}", time::format_utc(SystemTime::now())));
}

/// NTS-KE, then resolves the NTP server it names
fn connect(host: &str, port: u16, args: &Args, log: Log) -> Option<(NtsSession, SocketAddr)> {
    let keys = match ke_with_retries(host, port, args.timeout) {
        Ok(k) => k,
        Err(e) => {
            line(log, format_args!("NTS-KE with {host}:{port} failed: {e}"));
            return None;
        }
    };
    let ntp = fmt_host_port(&keys.ntp_server, keys.ntp_port);
    let addr = match resolve(&ntp) {
        Ok(a) => a,
        Err(e) => {
            line(log, format_args!("{e}"));
            return None;
        }
    };
    line(
        log,
        format_args!(
            "NTS-KE with {}: {} cookies, NTP server {ntp} ({addr})",
            keys.peer,
            keys.cookies.len()
        ),
    );
    Some((NtsSession::new(keys), addr))
}

/// Takes `args.samples` samples 2 s apart. Returns the lowest-delay one with when it was taken, and whether the session needs a new NTS-KE
fn burst(
    addr: SocketAddr,
    args: &Args,
    session: &mut NtsSession,
    stop: &Stop,
    log: Log,
) -> (Option<(Instant, Sample)>, bool) {
    let mut best: Option<(Instant, Sample)> = None;
    for i in 0..args.samples {
        if i > 0 && stop.wait(Duration::from_secs(2)) {
            break;
        }
        match query_with(addr, args.timeout, session) {
            Ok(s) => {
                let at = Instant::now();
                if best.as_ref().is_none_or(|(_, b)| s.delay < b.delay) {
                    best = Some((at, s));
                }
            }
            Err(ClientError::Nts(e @ (NtsError::Nak | NtsError::NoCookies))) => {
                line(log, format_args!("{e}"));
                return (best, true);
            }
            Err(e) => line(log, format_args!("sample failed: {e}")),
        }
    }
    (best, session.cookies_left() == 0)
}

fn apply(
    discipline: &mut Discipline,
    t: f64,
    s: &Sample,
    log: Log,
) -> Result<(), clock::ClockError> {
    let action = discipline.update(t, s.offset.as_secs_f64());
    if let Action::Step(_) = action {
        clock::step(s.offset)?;
    }
    clock::set_rate(discipline.rate())?;

    let freq = match discipline.freq() {
        Some(f) => format!("{:+8.3} ppm", f * 1e6),
        None => "measuring".into(),
    };
    let what = match action {
        Action::Step(_) => "stepped".to_string(),
        Action::Slew => format!("rate {:+8.3} ppm", discipline.rate() * 1e6),
    };
    line(
        log,
        format_args!(
            "offset {:>12}  delay {:>7.3} ms  freq {freq:>12}  {what}",
            s.offset.to_string(),
            s.delay.as_millis_f64()
        ),
    );
    Ok(())
}
