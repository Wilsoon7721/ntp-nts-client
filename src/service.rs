//! Running the `--sync` loop as a Windows service
//!
//! `--install` registers this exe with the Service Control Manager (SCM) to be launched as `nts-client.exe --service <your options>`
//! Log goes to `%ProgramData%\nts-client\sync.log`

use std::error::Error as _;
use std::ffi::OsString;
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::mpsc;
use std::sync::OnceLock;
use std::thread::sleep;
use std::time::{Duration, Instant};

use windows_service::service::{
    ServiceAccess, ServiceControl, ServiceControlAccept, ServiceErrorControl, ServiceExitCode,
    ServiceInfo, ServiceStartType, ServiceState, ServiceStatus, ServiceType,
};
use windows_service::service_control_handler::{self, ServiceControlHandlerResult};
use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};
use windows_service::{define_windows_service, service_dispatcher};

use crate::sync::{self, Stop};
use crate::Args;

pub const SERVICE_NAME: &str = "nts-client";
const DISPLAY_NAME: &str = "NTS Client";
const DESCRIPTION: &str = "Keeps the system clock in sync using NTS-authenticated NTP.";
const ACCOUNT: &str = r"NT AUTHORITY\LocalService";
/// Log is moved to `sync.log.old` past this size
const MAX_LOG_BYTES: u64 = 1024 * 1024;
static ARGS: OnceLock<Args> = OnceLock::new();

define_windows_service!(ffi_service_main, service_main);

/// Registers the service
pub fn install(options: Vec<OsString>) -> Result<(), String> {
    let exe = std::env::current_exe().map_err(|e| e.to_string())?;
    // Files under a user profile are only readable by that user, SYSTEM and
    // Administrators, so LOCAL SERVICE couldn't even launch the exe
    if let Some(profile) = std::env::var_os("USERPROFILE") {
        let exe_lower = exe.to_string_lossy().to_lowercase();
        let profile_lower = profile.to_string_lossy().to_lowercase();
        if exe_lower.starts_with(&format!("{profile_lower}\\")) {
            return Err(format!(
                "{} is inside your user folder, which the service account (LOCAL SERVICE) \
                 can't read. Copy nts-client.exe to e.g. C:\\Program Files\\nts-client\\ \
                 and run --install from there",
                exe.display()
            ));
        }
    }
    let manager = ServiceManager::local_computer(
        None::<&str>,
        ServiceManagerAccess::CONNECT | ServiceManagerAccess::CREATE_SERVICE,
    )
    .map_err(|e| {
        format!(
            "could not open the service manager (run elevated): {}",
            describe(e)
        )
    })?;

    let mut launch_arguments = vec![OsString::from("--service")];
    launch_arguments.extend(options);
    let info = ServiceInfo {
        name: SERVICE_NAME.into(),
        display_name: DISPLAY_NAME.into(),
        service_type: ServiceType::OWN_PROCESS,
        start_type: ServiceStartType::AutoStart,
        error_control: ServiceErrorControl::Normal,
        executable_path: exe,
        launch_arguments,
        dependencies: vec![],
        account_name: Some(ACCOUNT.into()),
        account_password: None,
    };
    let service = manager
        .create_service(&info, ServiceAccess::CHANGE_CONFIG)
        .map_err(|e| format!("could not create the service: {}", describe(e)))?;
    service.set_description(DESCRIPTION).map_err(describe)?;
    Ok(())
}

/// Stops the service if it's running then removes it
pub fn uninstall() -> Result<(), String> {
    let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)
        .map_err(|e| format!("could not open the service manager: {}", describe(e)))?;
    let service = manager
        .open_service(
            SERVICE_NAME,
            ServiceAccess::QUERY_STATUS | ServiceAccess::STOP | ServiceAccess::DELETE,
        )
        .map_err(|e| format!("could not open the service (run elevated): {}", describe(e)))?;

    let state = || {
        service
            .query_status()
            .map(|s| s.current_state)
            .map_err(describe)
    };
    if state()? != ServiceState::Stopped {
        service.stop().map_err(describe)?;
        // A burst in progress can take ~20 s to notice the stop
        let deadline = Instant::now() + Duration::from_secs(40);
        while state()? != ServiceState::Stopped {
            if Instant::now() > deadline {
                return Err("service didn't stop within 40 s".into());
            }
            sleep(Duration::from_millis(500));
        }
    }
    service.delete().map_err(describe)
}

/// Entry point when the SCM launches us (`--service`) - blocks until the service stops
pub fn dispatch(args: Args) -> ExitCode {
    let _ = ARGS.set(args);
    match service_dispatcher::start(SERVICE_NAME, ffi_service_main) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!(
                "error: {}\n--service is used by the Windows service manager; install with --install",
                describe(e)
            );
            ExitCode::FAILURE
        }
    }
}

/// The crate's errors say "IO error in winapi call", the Windows error is in `source()`
fn describe(e: windows_service::Error) -> String {
    match e.source() {
        Some(cause) => format!("{e}: {cause}"),
        None => e.to_string(),
    }
}

/// Runs on a thread the SCM creates
fn service_main(_start_arguments: Vec<OsString>) {
    let mut log = FileLog::open();
    let Some(args) = ARGS.get() else { return };

    let (stop_tx, stop_rx) = mpsc::channel();
    let handler = move |control| match control {
        ServiceControl::Stop | ServiceControl::Shutdown => {
            let _ = stop_tx.send(());
            ServiceControlHandlerResult::NoError
        }
        ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
        _ => ServiceControlHandlerResult::NotImplemented,
    };
    let status = match service_control_handler::register(SERVICE_NAME, handler) {
        Ok(s) => s,
        Err(e) => {
            log.write(&format!(
                "could not register with the service manager: {}",
                describe(e)
            ));
            return;
        }
    };
    let report = |state, accept, exit_code| {
        let _ = status.set_service_status(ServiceStatus {
            service_type: ServiceType::OWN_PROCESS,
            current_state: state,
            controls_accepted: accept,
            exit_code,
            checkpoint: 0,
            wait_hint: Duration::ZERO,
            process_id: None,
        });
    };

    report(
        ServiceState::Running,
        ServiceControlAccept::STOP | ServiceControlAccept::SHUTDOWN,
        ServiceExitCode::Win32(0),
    );
    let result = sync::run(args, &Stop::on(stop_rx), &mut |line| log.write(line));
    let exit_code = match result {
        Ok(()) => ServiceExitCode::Win32(0),
        Err(e) => {
            log.write(&format!("error: {e}"));
            ServiceExitCode::ServiceSpecific(1)
        }
    };
    report(
        ServiceState::Stopped,
        ServiceControlAccept::empty(),
        exit_code,
    );
}

/// Appends lines to `%ProgramData%\nts-client\sync.log`, keeping one old file
struct FileLog {
    path: PathBuf,
    file: Option<File>,
}

impl FileLog {
    fn open() -> Self {
        let dir = std::env::var_os("ProgramData")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from(r"C:\ProgramData"))
            .join("nts-client");
        let path = dir.join("sync.log");
        let _ = fs::create_dir_all(&dir);
        let mut log = Self { path, file: None };
        log.reopen();
        log
    }

    fn reopen(&mut self) {
        self.file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)
            .ok();
    }

    /// Logging must never take the service down, so failures are ignored
    fn write(&mut self, line: &str) {
        let too_big = fs::metadata(&self.path).is_ok_and(|m| m.len() > MAX_LOG_BYTES);
        if too_big {
            self.file = None;
            let _ = fs::rename(&self.path, self.path.with_extension("log.old"));
            self.reopen();
        }
        if let Some(f) = &mut self.file {
            let _ = writeln!(f, "{line}");
        }
    }
}
