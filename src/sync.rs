//! --sync: Keeps the system clock in sync until stopped

use std::cell::{Cell, RefCell};
use std::net::SocketAddr;
use std::sync::mpsc::{Receiver, RecvTimeoutError};
use std::sync::Mutex;
use std::thread::sleep;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use crate::client::{fmt_host_port, query_with, resolve, ClientError, Plain, Protection, Sample};
use crate::discipline::{Action, Discipline};
use crate::nts::{NtsError, NtsSession};
use crate::servers::Protocol;
use crate::{clock, nts_ke, time};

/// Where log lines go
pub type Log<'a> = &'a mut dyn FnMut(&str);

/// What to sync to: `host`, `host:port` or `[v6]:port`
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Source {
    pub host: String,
    pub protocol: Protocol,
}

pub struct SyncConfig {
    pub source: Source,
    /// Samples per poll, 2 s apart
    pub samples: u32,
    pub timeout: Duration,
    pub poll: Duration,
}

/// What the loop is doing, for the tray app
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Status {
    pub host: String,
    pub protocol: Option<Protocol>,
    pub state: String,
    pub last_sync: Option<f64>,
    pub offset_ms: Option<f64>,
    pub delay_ms: Option<f64>,
    pub freq_ppm: Option<f64>,
    pub rate_ppm: Option<f64>,
}

pub enum Command {
    Stop,
    /// Switch to another server without restarting
    SetSource(Source),
}

/// Lets another thread stop the loop or switch its server
pub struct Control {
    rx: Option<Receiver<Command>>,
    stopped: Cell<bool>,
    switch: RefCell<Option<Source>>,
}

impl Control {
    /// Runs until the process ends (console: Ctrl+C)
    pub fn never() -> Self {
        Self::new(None)
    }

    pub fn on(rx: Receiver<Command>) -> Self {
        Self::new(Some(rx))
    }

    fn new(rx: Option<Receiver<Command>>) -> Self {
        Self {
            rx,
            stopped: Cell::new(false),
            switch: RefCell::new(None),
        }
    }

    /// Sleeps for `d`, waking early on a command. Returns true if interrupted (stop or switch).
    fn wait(&self, d: Duration) -> bool {
        if self.interrupted() {
            return true;
        }
        let Some(rx) = &self.rx else {
            sleep(d);
            return false;
        };
        match rx.recv_timeout(d) {
            Err(RecvTimeoutError::Timeout) => false,
            Ok(Command::SetSource(s)) => {
                *self.switch.borrow_mut() = Some(s);
                true
            }
            Ok(Command::Stop) | Err(RecvTimeoutError::Disconnected) => {
                self.stopped.set(true);
                true
            }
        }
    }

    fn interrupted(&self) -> bool {
        self.stopped.get() || self.switch.borrow().is_some()
    }
}

/// Puts the clock rate back to Windows' default when dropped (stop, errors, panics)
struct RateGuard;

impl Drop for RateGuard {
    fn drop(&mut self) {
        let _ = clock::reset_rate();
    }
}

/// An NTP server ready to query
enum Session {
    Nts(Box<NtsSession>, SocketAddr),
    Plain(SocketAddr),
}

pub fn run(
    config: SyncConfig,
    control: &Control,
    status: &Mutex<Status>,
    log: Log,
) -> Result<(), String> {
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

    let mut source = config.source.clone();
    let start = Instant::now();
    let mut discipline = Discipline::new(config.poll.as_secs_f64());
    let mut session: Option<Session> = None;
    announce(&source, &config, status, log);

    loop {
        if let Some(new) = control.switch.borrow_mut().take() {
            // The clock's drift doesn't depend on the server, so keep the discipline
            source = new;
            session = None;
            announce(&source, &config, status, log);
        }
        let poll_start = Instant::now();
        if session.is_none() {
            session = connect(&source, &config, status, log);
        }

        let best = match &mut session {
            Some(s) => {
                let (best, reconnect) = burst(s, &config, control, log);
                if reconnect {
                    session = None;
                }
                best
            }
            None => None,
        };

        if control.switch.borrow().is_some() {
            continue; // drop samples from the old server
        }
        if control.stopped.get() {
            break;
        }

        let result = match best {
            Some((at, sample)) => {
                let t = at.duration_since(start).as_secs_f64();
                apply(&mut discipline, t, &sample, status, log)
            }
            None => {
                line(log, format_args!("no valid replies, holding frequency"));
                set_state(status, "No replies, holding frequency");
                clock::set_rate(discipline.holdover(start.elapsed().as_secs_f64()))
            }
        };
        result.map_err(|e| e.to_string())?;

        if control.wait(config.poll.saturating_sub(poll_start.elapsed())) && control.stopped.get()
        {
            break;
        }
    }
    line(log, format_args!("Stopping, clock rate handed back to Windows"));
    set_state(status, "Stopped");
    Ok(())
}

fn line(log: Log, msg: std::fmt::Arguments) {
    log(&format!("{}  {msg}", time::format_utc(SystemTime::now())));
}

fn set_state(status: &Mutex<Status>, state: impl Into<String>) {
    if let Ok(mut s) = status.lock() {
        s.state = state.into();
    }
}

fn announce(source: &Source, config: &SyncConfig, status: &Mutex<Status>, log: Log) {
    line(
        log,
        format_args!(
            "Syncing the clock to {} over {} every {} s",
            source.host,
            source.protocol.label(),
            config.poll.as_secs()
        ),
    );
    if let Ok(mut s) = status.lock() {
        *s = Status {
            host: source.host.clone(),
            protocol: Some(source.protocol),
            state: "Connecting".into(),
            freq_ppm: s.freq_ppm,
            rate_ppm: s.rate_ppm,
            ..Status::default()
        };
    }
}

/// Plain: resolves the server. NTS: NTS-KE, then resolves the NTP server it names.
fn connect(
    source: &Source,
    config: &SyncConfig,
    status: &Mutex<Status>,
    log: Log,
) -> Option<Session> {
    let fail = |log: Log, msg: String| {
        line(log, format_args!("{msg}"));
        set_state(status, msg);
        None
    };

    if source.protocol == Protocol::Ntp {
        return match resolve(&source.host) {
            Ok(addr) => {
                line(log, format_args!("NTP server {} ({addr}), unauthenticated", source.host));
                Some(Session::Plain(addr))
            }
            Err(e) => fail(log, e.to_string()),
        };
    }

    let (host, port) = match nts_ke::split_host_port(&source.host, nts_ke::DEFAULT_KE_PORT) {
        Ok(hp) => hp,
        Err(e) => return fail(log, e),
    };
    let keys = match nts_ke::key_exchange_with_retries(&host, port, config.timeout, |n, e| {
        line(log, format_args!("NTS-KE attempt {n} failed: {e}, retrying"));
    }) {
        Ok(k) => k,
        Err(e) => return fail(log, format!("NTS-KE with {host}:{port} failed: {e}")),
    };
    let ntp = fmt_host_port(&keys.ntp_server, keys.ntp_port);
    let addr = match resolve(&ntp) {
        Ok(a) => a,
        Err(e) => return fail(log, e.to_string()),
    };
    line(
        log,
        format_args!(
            "NTS-KE with {}: {} cookies, NTP server {ntp} ({addr})",
            keys.peer,
            keys.cookies.len()
        ),
    );
    Some(Session::Nts(Box::new(NtsSession::new(keys)), addr))
}

fn burst(
    session: &mut Session,
    config: &SyncConfig,
    control: &Control,
    log: Log,
) -> (Option<(Instant, Sample)>, bool) {
    let mut plain = Plain;
    let (addr, protection): (SocketAddr, &mut dyn ProtectionDyn) = match session {
        Session::Nts(s, addr) => (*addr, &mut **s),
        Session::Plain(addr) => (*addr, &mut plain),
    };
    let mut best: Option<(Instant, Sample)> = None;
    for i in 0..config.samples {
        if i > 0 && control.wait(Duration::from_secs(2)) {
            break;
        }
        match protection.query(addr, config.timeout) {
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
    let out_of_cookies = matches!(session, Session::Nts(s, _) if s.cookies_left() == 0);
    (best, out_of_cookies)
}

trait ProtectionDyn {
    fn query(&mut self, addr: SocketAddr, timeout: Duration) -> Result<Sample, ClientError>;
}

impl<P: Protection> ProtectionDyn for P {
    fn query(&mut self, addr: SocketAddr, timeout: Duration) -> Result<Sample, ClientError> {
        query_with(addr, timeout, self)
    }
}

fn apply(
    discipline: &mut Discipline,
    t: f64,
    s: &Sample,
    status: &Mutex<Status>,
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

    if let Ok(mut st) = status.lock() {
        st.state = match action {
            Action::Step(_) => "Stepped the clock".into(),
            Action::Slew if discipline.freq().is_none() => "Measuring drift".into(),
            Action::Slew => "Synced".into(),
        };
        st.last_sync = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .ok()
            .map(|d| d.as_secs_f64());
        st.offset_ms = Some(s.offset.as_millis_f64());
        st.delay_ms = Some(s.delay.as_millis_f64());
        st.freq_ppm = discipline.freq().map(|f| f * 1e6);
        st.rate_ppm = Some(discipline.rate() * 1e6);
    }
    Ok(())
}
