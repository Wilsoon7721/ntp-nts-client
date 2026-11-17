use std::error::Error as _;
use std::ffi::OsString;
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::PathBuf;
use std::process::ExitCode;
use std::ptr;
use std::sync::{mpsc, Arc, Mutex};
use std::thread::{self, sleep};
use std::time::{Duration, Instant};

use windows_service::service::{
    ServiceAccess, ServiceControl, ServiceControlAccept, ServiceErrorControl, ServiceExitCode,
    Service, ServiceInfo, ServiceStartType, ServiceState, ServiceStatus, ServiceType,
};
use windows_service::service_control_handler::{self, ServiceControlHandlerResult};
use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};
use windows_service::{define_windows_service, service_dispatcher};
use windows_sys::Win32::Foundation::ERROR_SERVICE_DOES_NOT_EXIST;
use windows_sys::Win32::System::Services::{
    ChangeServiceConfigW, SERVICE_DEMAND_START, SERVICE_DISABLED, SERVICE_NO_CHANGE,
    SERVICE_START_TYPE,
};

use crate::config::{self, Config, CustomServer};
use crate::ipc::{self, Client, Reply, Request};
use crate::servers::{self, Protocol};
use crate::sync::{self, Command, Control, Status, SyncConfig};

pub const SERVICE_NAME: &str = "nts-client";
const DISPLAY_NAME: &str = "NTS Client";
const DESCRIPTION: &str = "Keeps the system clock in sync using NTS-authenticated NTP.";
const ACCOUNT: &str = r"NT AUTHORITY\LocalService";
const W32TIME: &str = "W32Time";
/// Log is moved to `sync.log.old` past this size
const MAX_LOG_BYTES: u64 = 1024 * 1024;

define_windows_service!(ffi_service_main, service_main);

/// Registers the service
pub fn install() -> Result<(), String> {
    let exe = std::env::current_exe().map_err(|e| e.to_string())?;
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

    let info = ServiceInfo {
        name: SERVICE_NAME.into(),
        display_name: DISPLAY_NAME.into(),
        service_type: ServiceType::OWN_PROCESS,
        start_type: ServiceStartType::AutoStart,
        error_control: ServiceErrorControl::Normal,
        executable_path: exe,
        launch_arguments: vec![OsString::from("--service")],
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

    if state_of(&service)? != ServiceState::Stopped {
        service.stop().map_err(describe)?;
        // A burst in progress can take ~20 s to notice the stop
        wait_for(&service, ServiceState::Stopped, Duration::from_secs(40))?;
    }
    service.delete().map_err(describe)?;
    restore_w32time(&manager)
        .map_err(|e| format!("removed the service, but could not re-enable Windows Time: {e}"))
}

/// Stops and disables Windows Time, then starts the service
pub fn start() -> Result<(), String> {
    let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)
        .map_err(|e| format!("could not open the service manager: {}", describe(e)))?;

    disable_w32time(&manager)?;

    let service = manager
        .open_service(SERVICE_NAME, ServiceAccess::QUERY_STATUS | ServiceAccess::START)
        .map_err(|e| format!("could not open the service (run elevated): {}", describe(e)))?;
    if state_of(&service)? != ServiceState::Running {
        service
            .start::<&str>(&[])
            .map_err(|e| format!("could not start the service: {}", describe(e)))?;
        wait_for(&service, ServiceState::Running, Duration::from_secs(30))?;
    }
    Ok(())
}

pub fn query() -> Result<Option<ServiceState>, String> {
    let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)
        .map_err(describe)?;
    match manager.open_service(SERVICE_NAME, ServiceAccess::QUERY_STATUS) {
        Ok(service) => state_of(&service).map(Some),
        Err(windows_service::Error::Winapi(e))
            if e.raw_os_error() == Some(ERROR_SERVICE_DOES_NOT_EXIST as i32) =>
        {
            Ok(None)
        }
        Err(e) => Err(describe(e)),
    }
}

/// Opens Windows Time; `Ok(None)` if this Windows doesn't have it
fn open_w32time(manager: &ServiceManager, access: ServiceAccess) -> Result<Option<Service>, String> {
    match manager.open_service(W32TIME, access) {
        Ok(s) => Ok(Some(s)),
        Err(windows_service::Error::Winapi(e))
            if e.raw_os_error() == Some(ERROR_SERVICE_DOES_NOT_EXIST as i32) =>
        {
            Ok(None)
        }
        Err(e) => Err(format!("could not open Windows Time (run elevated): {}", describe(e))),
    }
}

/// Disabling, not just stopping, keeps it down: otherwise its domain-join
/// trigger, the weekly "SynchronizeTime" scheduled task, or "Sync now" in
/// Settings start it again and it fights the service over the clock
fn disable_w32time(manager: &ServiceManager) -> Result<(), String> {
    let access = ServiceAccess::QUERY_STATUS
        | ServiceAccess::STOP
        | ServiceAccess::QUERY_CONFIG
        | ServiceAccess::CHANGE_CONFIG;
    let Some(w32time) = open_w32time(manager, access)? else {
        return Ok(());
    };
    if w32time.query_config().map_err(describe)?.start_type != ServiceStartType::Disabled {
        set_start_type(&w32time, SERVICE_DISABLED)
            .map_err(|e| format!("could not disable Windows Time: {e}"))?;
    }
    if state_of(&w32time)? != ServiceState::Stopped {
        w32time
            .stop()
            .map_err(|e| format!("could not stop Windows Time: {}", describe(e)))?;
        wait_for(&w32time, ServiceState::Stopped, Duration::from_secs(30))?;
    }
    Ok(())
}

/// Back to Windows' default (manual, started by its triggers), if we disabled it
fn restore_w32time(manager: &ServiceManager) -> Result<(), String> {
    let access = ServiceAccess::QUERY_CONFIG | ServiceAccess::CHANGE_CONFIG;
    let Some(w32time) = open_w32time(manager, access)? else {
        return Ok(());
    };
    if w32time.query_config().map_err(describe)?.start_type == ServiceStartType::Disabled {
        set_start_type(&w32time, SERVICE_DEMAND_START)?;
    }
    Ok(())
}

/// Whether Windows Time is disabled (or absent). Read-only, works without admin rights.
pub fn w32time_disabled() -> Result<bool, String> {
    let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)
        .map_err(describe)?;
    match open_w32time(&manager, ServiceAccess::QUERY_CONFIG)? {
        None => Ok(true),
        Some(s) => Ok(s.query_config().map_err(describe)?.start_type == ServiceStartType::Disabled),
    }
}

/// Changes only the start type; `windows_service`'s `change_config` wants every field
fn set_start_type(service: &Service, start_type: SERVICE_START_TYPE) -> Result<(), String> {
    let ok = unsafe {
        ChangeServiceConfigW(
            service.raw_handle(),
            SERVICE_NO_CHANGE,
            start_type,
            SERVICE_NO_CHANGE,
            ptr::null(),
            ptr::null(),
            ptr::null_mut(),
            ptr::null(),
            ptr::null(),
            ptr::null(),
            ptr::null(),
        )
    };
    if ok == 0 {
        return Err(std::io::Error::last_os_error().to_string());
    }
    Ok(())
}

fn state_of(service: &Service) -> Result<ServiceState, String> {
    service
        .query_status()
        .map(|s| s.current_state)
        .map_err(describe)
}

fn wait_for(service: &Service, target: ServiceState, timeout: Duration) -> Result<(), String> {
    let deadline = Instant::now() + timeout;
    loop {
        let state = state_of(service)?;
        if state == target {
            return Ok(());
        }
        if target == ServiceState::Running && state == ServiceState::Stopped {
            return Err(format!(
                "the service stopped right after starting; see {}",
                config::data_dir().join("sync.log").display()
            ));
        }
        if Instant::now() > deadline {
            return Err(format!(
                "still {state:?} after {} s, expected {target:?}",
                timeout.as_secs()
            ));
        }
        sleep(Duration::from_millis(300));
    }
}

/// Entry point when the SCM launches us (`--service`) - blocks until the service stops
pub fn dispatch() -> ExitCode {
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
    let log = Arc::new(Mutex::new(FileLog::open()));
    let write_log = |line: &str| {
        if let Ok(mut l) = log.lock() {
            l.write(line);
        }
    };

    let (commands, command_rx) = mpsc::channel();
    let stop = commands.clone();
    let handler = move |control| match control {
        ServiceControl::Stop | ServiceControl::Shutdown => {
            let _ = stop.send(Command::Stop);
            ServiceControlHandlerResult::NoError
        }
        ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
        _ => ServiceControlHandlerResult::NotImplemented,
    };
    let status_handle = match service_control_handler::register(SERVICE_NAME, handler) {
        Ok(s) => s,
        Err(e) => {
            write_log(&format!(
                "could not register with the service manager: {}",
                describe(e)
            ));
            return;
        }
    };
    let report = |state, accept, exit_code| {
        let _ = status_handle.set_service_status(ServiceStatus {
            service_type: ServiceType::OWN_PROCESS,
            current_state: state,
            controls_accepted: accept,
            exit_code,
            checkpoint: 0,
            wait_hint: Duration::ZERO,
            process_id: None,
        });
    };

    let config = Arc::new(Mutex::new(Config::load()));
    let status = Arc::new(Mutex::new(Status::default()));
    let source = config
        .lock()
        .map(|c| c.source())
        .unwrap_or_else(|_| Config::default().source());

    {
        let (config, status, log) = (config.clone(), status.clone(), log.clone());
        let commands = Mutex::new(commands);
        thread::spawn(move || {
            let handler =
                move |req, client| handle_request(req, client, &config, &status, &commands);
            if let Err(e) = ipc::serve(ipc::PIPE_NAME, handler)
                && let Ok(mut l) = log.lock()
            {
                l.write(&format!("pipe for the tray app failed: {e}"));
            }
        });
    }

    report(
        ServiceState::Running,
        ServiceControlAccept::STOP | ServiceControlAccept::SHUTDOWN,
        ServiceExitCode::Win32(0),
    );
    let sync_config = SyncConfig {
        source,
        samples: 4,
        timeout: Duration::from_secs(5),
        poll: Duration::from_secs(64),
    };
    let result = sync::run(
        sync_config,
        &Control::on(command_rx),
        &status,
        &mut |line| write_log(line),
    );
    let exit_code = match result {
        Ok(()) => ServiceExitCode::Win32(0),
        Err(e) => {
            write_log(&format!("error: {e}"));
            ServiceExitCode::ServiceSpecific(1)
        }
    };
    report(
        ServiceState::Stopped,
        ServiceControlAccept::empty(),
        exit_code,
    );
}

/// Answers the tray app
fn handle_request(
    request: Request,
    client: Client,
    config: &Mutex<Config>,
    status: &Mutex<Status>,
    commands: &Mutex<mpsc::Sender<Command>>,
) -> Reply {
    let error = match request {
        Request::Status => None,
        Request::SetServer {
            id,
            accept_unauthenticated,
        } => set_server(&id, accept_unauthenticated, config, commands).err(),
        Request::SetCustom {
            host,
            protocol,
            accept_unauthenticated,
        } => set_custom(
            host,
            protocol,
            accept_unauthenticated,
            client,
            config,
            commands,
        )
        .err(),
    };
    let (server_id, custom) = config
        .lock()
        .map(|c| (c.server.clone(), c.custom.clone()))
        .unwrap_or_default();
    Reply {
        error,
        server_id,
        custom,
        status: status.lock().map(|s| s.clone()).unwrap_or_default(),
    }
}

fn set_server(
    id: &str,
    accept_unauthenticated: bool,
    config: &Mutex<Config>,
    commands: &Mutex<mpsc::Sender<Command>>,
) -> Result<(), String> {
    let server = servers::find(id).ok_or_else(|| format!("unknown server {id:?}"))?;
    if server.protocol == Protocol::Ntp && !accept_unauthenticated {
        return Err(format!(
            "{} is unauthenticated NTP; the risk must be accepted first",
            server.host
        ));
    }
    switch(config, commands, |c| Config {
        server: server.id.into(),
        // Remembered so it can be picked again
        custom: c.custom.clone(),
    })
}

fn set_custom(
    host: String,
    protocol: Protocol,
    accept_unauthenticated: bool,
    client: Client,
    config: &Mutex<Config>,
    commands: &Mutex<mpsc::Sender<Command>>,
) -> Result<(), String> {
    if !client.is_admin {
        return Err("custom servers can only be set from an administrator account".into());
    }
    let host = host.trim().to_string();
    if !config::valid_host(&host) {
        return Err(format!("{host:?} isn't a valid hostname or IP address"));
    }
    if protocol == Protocol::Ntp && !accept_unauthenticated {
        return Err(format!(
            "{host} is unauthenticated NTP; the risk must be accepted first"
        ));
    }
    switch(config, commands, |_| Config {
        server: config::CUSTOM_ID.into(),
        custom: Some(CustomServer { host, protocol }),
    })
}

/// Saves the new config and points the sync loop at it, unless nothing changed
fn switch(
    config: &Mutex<Config>,
    commands: &Mutex<mpsc::Sender<Command>>,
    make: impl FnOnce(&Config) -> Config,
) -> Result<(), String> {
    let mut config = config.lock().map_err(|_| "config lock poisoned")?;
    let new = make(&config);
    if new.source() == config.source() {
        return Ok(());
    }
    new.save()?;
    let source = new.source();
    *config = new;
    commands
        .lock()
        .map_err(|_| "command lock poisoned")?
        .send(Command::SetSource(source))
        .map_err(|_| "the sync loop has stopped".to_string())
}

/// Appends lines to `%ProgramData%\nts-client\sync.log`, keeping one old file
struct FileLog {
    path: PathBuf,
    file: Option<File>,
}

impl FileLog {
    fn open() -> Self {
        let dir = config::data_dir();
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
