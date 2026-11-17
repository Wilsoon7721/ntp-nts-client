#![windows_subsystem = "windows"]

use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, Sender};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use eframe::egui::{
    self, Color32, CornerRadius, FontData, FontDefinitions, FontFamily, Margin, RichText, Stroke,
    Theme, ViewportCommand, Visuals,
};
use lucide_icons::Icon;
use serde::{Deserialize, Serialize};
use tray_icon::menu::{Menu, MenuEvent, MenuItem};
use tray_icon::{MouseButton, MouseButtonState, TrayIcon, TrayIconBuilder, TrayIconEvent};
use windows_service::service::ServiceState;
use windows_sys::Win32::Foundation::{CloseHandle, ERROR_CANCELLED, SYSTEMTIME};
use windows_sys::Win32::System::SystemInformation::{GetLocalTime, GetSystemTime};
use windows_sys::Win32::System::Threading::{GetExitCodeProcess, WaitForSingleObject, INFINITE};
use windows_sys::Win32::UI::Shell::{
    ShellExecuteExW, SEE_MASK_NOASYNC, SEE_MASK_NOCLOSEPROCESS, SHELLEXECUTEINFOW,
};
use windows_sys::Win32::UI::WindowsAndMessaging::SW_HIDE;

use nts_client::autostart;
use nts_client::config::CUSTOM_ID;
use nts_client::ipc::{self, Reply, Request};
use nts_client::probe::{self, Probe};
use nts_client::servers::{self, Protocol, Server};
use nts_client::service;
use nts_client::timezone::{self, Zone};
use nts_client::update::{self, Release, Version};

/// How often the service is asked for its status
const POLL: Duration = Duration::from_secs(2);
/// First update check after start-up, then this often
const UPDATE_FIRST_CHECK: Duration = Duration::from_secs(15);
const UPDATE_INTERVAL: Duration = Duration::from_secs(24 * 60 * 60);
/// Per-attempt timeout when checking a custom server
const PROBE_TIMEOUT: Duration = Duration::from_secs(4);

const ACCENT: Color32 = Color32::from_rgb(0x3b, 0x82, 0xf6);
const GOOD: Color32 = Color32::from_rgb(0x22, 0xa0, 0x5b);
const WARN: Color32 = Color32::from_rgb(0xe0, 0x8e, 0x0b);
const BAD: Color32 = Color32::from_rgb(0xe5, 0x48, 0x4d);

fn main() -> eframe::Result {
    let start_hidden = std::env::args().any(|a| a == "--hidden");
    let (rgba, size) = icon_rgba();
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_title("NTS Client")
            .with_inner_size([420.0, 660.0])
            .with_min_inner_size([360.0, 520.0])
            .with_visible(!start_hidden)
            .with_icon(egui::IconData {
                rgba: rgba.clone(),
                width: size,
                height: size,
            }),
        ..Default::default()
    };
    eframe::run_native(
        "NTS Client",
        options,
        Box::new(move |cc| {
            style(&cc.egui_ctx);
            Ok(Box::new(TrayApp::new(&cc.egui_ctx, rgba, size)?))
        }),
    )
}

/// Per-user settings for the tray app, in `%APPDATA%\nts-client\tray.json`
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
struct Prefs {
    #[serde(default)]
    skip_ntp_warning: bool,
    /// "Start with Windows" is switched on once, the first time the app runs
    #[serde(default)]
    autostart_set_up: bool,
}

impl Prefs {
    fn path() -> Option<PathBuf> {
        std::env::var_os("APPDATA").map(|d| PathBuf::from(d).join("nts-client").join("tray.json"))
    }

    fn load() -> Self {
        Self::path()
            .and_then(|p| fs::read_to_string(p).ok())
            .and_then(|s| serde_json::from_str(&s).ok())
            .unwrap_or_default()
    }

    fn save(&self) {
        if let Some(path) = Self::path() {
            if let Some(dir) = path.parent() {
                let _ = fs::create_dir_all(dir);
            }
            if let Ok(json) = serde_json::to_string_pretty(self) {
                let _ = fs::write(path, json);
            }
        }
    }
}

/// What the background thread last heard from the service
#[derive(Default)]
struct Shared {
    reply: Option<Reply>,
    /// Couldn't reach the service at all
    unreachable: Option<String>,
    /// The service refused the last server change
    refused: Option<String>,
    /// Server id we've asked to switch to and are waiting on
    pending: Option<String>,
    /// From the Service Control Manager while the pipe isn't answering: `Ok(None)` = not installed
    service: Option<Result<Option<ServiceState>, String>>,
    /// The elevated `nts-client --start` helper
    helper: Helper,
    /// Whether Windows Time is disabled, so it can't fight the service over the clock
    w32time_disabled: Option<bool>,
}

#[derive(Default, Clone, PartialEq)]
enum Helper {
    #[default]
    Idle,
    Running,
    Failed(String),
}

/// What the status card's button asks for
#[derive(Clone, Copy)]
enum ServiceAction {
    Start,
    InstallAndStart,
    /// `--start` also disables Windows Time
    DisableW32Time,
}

/// A plain NTP server waiting for the user to accept the risk
#[derive(Clone)]
enum NtpChoice {
    Listed(&'static Server),
    /// A custom server that only answered NTP
    Custom(String),
}

enum Dialog {
    None,
    /// Typing a custom server, or checking it
    Custom {
        input: String,
        checking: Option<Arc<Mutex<Option<Probe>>>>,
        /// Why the last check failed: summary and details
        failed: Option<(String, String)>,
    },
    Ntp {
        choice: NtpChoice,
        dont_show_again: bool,
    },
}

#[derive(Clone)]
enum UpdateState {
    /// A local build, which doesn't update itself
    Off,
    Idle,
    Checking,
    UpToDate,
    Available(Release),
    /// Downloading or waiting on the admin prompt; the text says which
    Installing(Release, &'static str),
    Failed {
        /// Still offered, so it can be retried
        release: Option<Release>,
        error: String,
    },
}

struct TrayApp {
    shared: Arc<Mutex<Shared>>,
    requests: Sender<Request>,
    dialog: Dialog,
    prefs: Prefs,
    show: Arc<AtomicBool>,
    quit: Arc<AtomicBool>,
    was_minimized: bool,
    zones: Vec<Zone>,
    zone_search: String,
    autostart: bool,
    /// Why the last time zone or startup change failed
    settings_error: Option<String>,
    update: Arc<Mutex<UpdateState>>,
    /// Asks the update thread to check now
    check_now: Sender<()>,
    tooltip_says_update: bool,
    /// Removed from the tray when dropped
    _tray: TrayIcon,
}

impl TrayApp {
    fn new(
        ctx: &egui::Context,
        rgba: Vec<u8>,
        size: u32,
    ) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let show = Arc::new(AtomicBool::new(false));
        let quit = Arc::new(AtomicBool::new(false));

        let open_item = MenuItem::new("Open", true, None);
        let quit_item = MenuItem::new("Quit", true, None);
        let menu = Menu::new();
        menu.append(&open_item)?;
        menu.append(&quit_item)?;

        let tray = TrayIconBuilder::new()
            .with_tooltip("NTS Client")
            .with_icon(tray_icon::Icon::from_rgba(rgba, size, size)?)
            .with_menu(Box::new(menu))
            .with_menu_on_left_click(false)
            .build()?;

        {
            let (show, ctx) = (show.clone(), ctx.clone());
            TrayIconEvent::set_event_handler(Some(move |event| {
                if let TrayIconEvent::Click {
                    button: MouseButton::Left,
                    button_state: MouseButtonState::Up,
                    ..
                } = event
                {
                    show.store(true, Ordering::Relaxed);
                    ctx.request_repaint();
                }
            }));
        }
        {
            let (show, quit, ctx) = (show.clone(), quit.clone(), ctx.clone());
            let (open_id, quit_id) = (open_item.id().clone(), quit_item.id().clone());
            MenuEvent::set_event_handler(Some(move |event: MenuEvent| {
                if event.id == open_id {
                    show.store(true, Ordering::Relaxed);
                } else if event.id == quit_id {
                    quit.store(true, Ordering::Relaxed);
                }
                ctx.request_repaint();
            }));
        }

        let shared = Arc::new(Mutex::new(Shared::default()));
        let (requests, request_rx) = mpsc::channel();
        {
            let (shared, ctx) = (shared.clone(), ctx.clone());
            thread::spawn(move || talk_to_service(request_rx, shared, ctx));
        }

        let update = Arc::new(Mutex::new(if update::enabled() {
            UpdateState::Idle
        } else {
            UpdateState::Off
        }));
        let (check_now, check_rx) = mpsc::channel();
        if update::enabled() {
            let (update, ctx) = (update.clone(), ctx.clone());
            thread::spawn(move || check_for_updates(check_rx, update, ctx));
        }

        let mut prefs = Prefs::load();
        if !prefs.autostart_set_up {
            if let Ok(exe) = std::env::current_exe() {
                let _ = autostart::enable(&exe);
            }
            prefs.autostart_set_up = true;
            prefs.save();
        }

        Ok(Self {
            shared,
            requests,
            dialog: Dialog::None,
            prefs,
            show,
            quit,
            was_minimized: false,
            zones: timezone::list(),
            zone_search: String::new(),
            autostart: autostart::is_enabled(),
            settings_error: None,
            update,
            check_now,
            tooltip_says_update: false,
            _tray: tray,
        })
    }

    fn send(&self, pending_id: &str, request: Request) {
        if let Ok(mut s) = self.shared.lock() {
            s.pending = Some(pending_id.into());
            s.refused = None;
        }
        let _ = self.requests.send(request);
    }

    fn use_listed(&self, server: &Server, accept_unauthenticated: bool) {
        self.send(
            server.id,
            Request::SetServer {
                id: server.id.into(),
                accept_unauthenticated,
            },
        );
    }

    fn use_custom(&self, host: String, protocol: Protocol) {
        self.send(
            CUSTOM_ID,
            Request::SetCustom {
                host,
                protocol,
                accept_unauthenticated: protocol == Protocol::Ntp,
            },
        );
    }

    /// Plain NTP: straight away if the user turned the warning off, else ask
    fn use_ntp(&mut self, choice: NtpChoice) {
        if self.prefs.skip_ntp_warning {
            self.accept_ntp(choice);
        } else {
            self.dialog = Dialog::Ntp {
                choice,
                dont_show_again: false,
            };
        }
    }

    fn accept_ntp(&self, choice: NtpChoice) {
        match choice {
            NtpChoice::Listed(server) => self.use_listed(server, true),
            NtpChoice::Custom(host) => self.use_custom(host, Protocol::Ntp),
        }
    }
}

/// Background thread: checks GitHub soon after start-up, then daily, or when asked
fn check_for_updates(check_now: Receiver<()>, state: Arc<Mutex<UpdateState>>, ctx: egui::Context) {
    let mut wait = UPDATE_FIRST_CHECK;
    loop {
        match check_now.recv_timeout(wait) {
            Ok(()) | Err(RecvTimeoutError::Timeout) => {}
            Err(RecvTimeoutError::Disconnected) => return,
        }
        wait = UPDATE_INTERVAL;
        let set = |new: UpdateState| {
            if let Ok(mut s) = state.lock() {
                *s = new;
            }
            ctx.request_repaint();
        };
        // Don't disturb an install in progress
        if matches!(state.lock().as_deref(), Ok(UpdateState::Installing(..))) {
            continue;
        }
        set(UpdateState::Checking);
        set(match update::check() {
            Ok(Some(release)) => UpdateState::Available(release),
            Ok(None) => UpdateState::UpToDate,
            Err(error) => UpdateState::Failed {
                release: None,
                error,
            },
        });
    }
}

/// Background thread: polls the service and forwards server changes, so a slow or missing service never blocks the UI
fn talk_to_service(requests: Receiver<Request>, shared: Arc<Mutex<Shared>>, ctx: egui::Context) {
    loop {
        let request = match requests.recv_timeout(POLL) {
            Ok(r) => r,
            Err(RecvTimeoutError::Timeout) => Request::Status,
            Err(RecvTimeoutError::Disconnected) => return,
        };
        let is_change = !matches!(request, Request::Status);
        let result = ipc::request(ipc::PIPE_NAME, &request);
        let w32time_disabled = service::w32time_disabled().ok();
        if let Ok(mut s) = shared.lock() {
            s.w32time_disabled = w32time_disabled;
            match result {
                Ok(reply) => {
                    if is_change {
                        s.refused = reply.error.clone();
                        s.pending = None;
                    }
                    s.unreachable = None;
                    s.reply = Some(reply);
                    s.service = None;
                }
                Err(e) => {
                    if is_change {
                        s.pending = None;
                    }
                    s.unreachable = Some(match e.kind() {
                        std::io::ErrorKind::NotFound => {
                            "The service isn't running, or is an older version without \
                             the tray connection."
                                .into()
                        }
                        _ => e.to_string(),
                    });
                    // Read-only query, fine without admin rights
                    s.service = Some(service::query());
                }
            }
        }
        ctx.request_repaint();
    }
}

impl eframe::App for TrayApp {
    /// Also runs while the window is hidden, so the tray can bring it back
    fn logic(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        if self.quit.load(Ordering::Relaxed) {
            ctx.send_viewport_cmd(ViewportCommand::Close);
            return;
        }
        let update_ready = matches!(
            self.update.lock().as_deref(),
            Ok(UpdateState::Available(_) | UpdateState::Failed { release: Some(_), .. })
        );
        if update_ready != self.tooltip_says_update {
            let tooltip = if update_ready {
                "NTS Client · update available"
            } else {
                "NTS Client"
            };
            let _ = self._tray.set_tooltip(Some(tooltip));
            self.tooltip_says_update = update_ready;
        }
        if self.show.swap(false, Ordering::Relaxed) {
            // May have been changed from Task Manager while hidden
            self.autostart = autostart::is_enabled();
            ctx.send_viewport_cmd(ViewportCommand::Visible(true));
            ctx.send_viewport_cmd(ViewportCommand::Minimized(false));
            ctx.send_viewport_cmd(ViewportCommand::Focus);
            return;
        }

        let (minimized, close_requested) = ctx.input(|i| {
            let v = i.viewport();
            (v.minimized == Some(true), v.close_requested())
        });
        if minimized && !self.was_minimized {
            ctx.send_viewport_cmd(ViewportCommand::Visible(false));
        }
        self.was_minimized = minimized;
        if close_requested {
            ctx.send_viewport_cmd(ViewportCommand::CancelClose);
            ctx.send_viewport_cmd(ViewportCommand::Visible(false));
        }
    }

    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        let (reply, unreachable, refused, pending, svc, helper, w32time_disabled) =
            match self.shared.lock() {
                Ok(s) => (
                    s.reply.clone(),
                    s.unreachable.clone(),
                    s.refused.clone(),
                    s.pending.clone(),
                    s.service.clone(),
                    s.helper.clone(),
                    s.w32time_disabled,
                ),
                Err(_) => {
                    let e = Some("internal error".into());
                    (None, e, None, None, None, Helper::Idle, None)
                }
            };
        let connected = unreachable.is_none() && reply.is_some();
        let update_state = self
            .update
            .lock()
            .map(|u| u.clone())
            .unwrap_or(UpdateState::Off);

        let mut picked = None;
        let mut action = None;
        let mut update_action = None;
        let panel = egui::Frame::new()
            .fill(ui.visuals().panel_fill)
            .inner_margin(Margin::same(16));
        egui::CentralPanel::default().frame(panel).show(ui, |ui| {
            egui::ScrollArea::vertical().show(ui, |ui| {
                ui.spacing_mut().item_spacing.y = 12.0;
                if let Some(release) = offered_release(&update_state) {
                    card(ui, |ui| update_action = update_banner(ui, release, &update_state));
                }
                card(ui, clock);
                card(ui, |ui| {
                    action = status(
                        ui,
                        reply.as_ref(),
                        unreachable.as_deref(),
                        svc.as_ref(),
                        &helper,
                        w32time_disabled,
                    );
                });
                card(ui, |ui| {
                    picked = server_picker(ui, reply.as_ref(), connected, pending.as_deref());
                    if let Some(e) = &refused {
                        ui.colored_label(BAD, format!("Not changed: {e}"));
                    }
                    ui.add_space(6.0);
                    self.timezone_picker(ui);
                    ui.add_space(6.0);
                    self.startup_toggle(ui);
                    if let Some(e) = &self.settings_error {
                        ui.colored_label(BAD, e);
                    }
                });
                if let Some(a) = version_line(ui, &update_state) {
                    update_action = Some(a);
                }
            });
        });

        match update_action {
            Some(UpdateAction::CheckNow) => {
                let _ = self.check_now.send(());
            }
            Some(UpdateAction::Install(release)) => self.install_update(ui.ctx(), release),
            None => {}
        }

        if let Some(action) = action {
            self.run_helper(ui.ctx(), action);
        }
        match picked {
            Some(Pick::Listed(server)) if server.protocol == Protocol::Nts => {
                self.use_listed(server, false)
            }
            Some(Pick::Listed(server)) => self.use_ntp(NtpChoice::Listed(server)),
            Some(Pick::SavedCustom(host, Protocol::Nts)) => self.use_custom(host, Protocol::Nts),
            Some(Pick::SavedCustom(host, Protocol::Ntp)) => self.use_ntp(NtpChoice::Custom(host)),
            Some(Pick::NewCustom) => {
                self.dialog = Dialog::Custom {
                    input: String::new(),
                    checking: None,
                    failed: None,
                }
            }
            None => {}
        }

        self.dialogs(ui.ctx());

        // Tick the clock on the next second
        let ms_into_second = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.subsec_millis())
            .unwrap_or(0);
        ui.ctx()
            .request_repaint_after(Duration::from_millis(1000 - ms_into_second as u64 + 5));
    }
}

impl TrayApp {
    /// Downloads and verifies the installer, starts it, then quits so it can replace this exe
    fn install_update(&self, ctx: &egui::Context, release: Release) {
        let (state, quit, ctx) = (self.update.clone(), self.quit.clone(), ctx.clone());
        thread::spawn(move || {
            let set = |new: UpdateState| {
                if let Ok(mut s) = state.lock() {
                    *s = new;
                }
                ctx.request_repaint();
            };
            set(UpdateState::Installing(release.clone(), "Downloading..."));
            let result = update::download(&release).and_then(|path| {
                set(UpdateState::Installing(
                    release.clone(),
                    "Approve the Windows prompt to continue...",
                ));
                update::run_installer(&path)
            });
            match result {
                Ok(()) => {
                    quit.store(true, Ordering::Relaxed);
                    ctx.request_repaint();
                }
                Err(error) => set(UpdateState::Failed {
                    release: Some(release),
                    error,
                }),
            }
        });
    }

    fn run_helper(&self, ctx: &egui::Context, action: ServiceAction) {
        let args = match action {
            ServiceAction::Start | ServiceAction::DisableW32Time => "--start",
            ServiceAction::InstallAndStart => "--install --start",
        };
        if let Ok(mut s) = self.shared.lock() {
            s.helper = Helper::Running;
        }
        let (shared, ctx) = (self.shared.clone(), ctx.clone());
        thread::spawn(move || {
            let result = run_elevated(args);
            if let Ok(mut s) = shared.lock() {
                s.helper = match result {
                    Ok(()) => Helper::Idle,
                    Err(e) => Helper::Failed(e),
                };
                // Look again straight away rather than waiting for the next poll
                s.service = Some(service::query());
            }
            ctx.request_repaint();
        });
    }

    fn timezone_picker(&mut self, ui: &mut egui::Ui) {
        caption(ui, "Time zone");
        let current = timezone::current();
        let selected = self
            .zones
            .iter()
            .position(|z| Some(&z.key) == current.as_ref());
        let text = match selected {
            Some(i) => self.zones[i].display.clone(),
            None => current.unwrap_or_else(|| "—".into()),
        };

        let mut pick = None;
        egui::ComboBox::from_id_salt("timezone")
            .width(ui.available_width())
            .height(360.0)
            .selected_text(RichText::new(text).size(15.0))
            .show_ui(ui, |ui| {
                let search = ui.add(
                    egui::TextEdit::singleline(&mut self.zone_search)
                        .hint_text("Search, e.g. Singapore or UTC+08")
                        .desired_width(f32::INFINITY),
                );
                if ui.memory(|m| m.focused().is_none()) {
                    search.request_focus();
                }
                let query = self.zone_search.to_lowercase();
                for (i, zone) in self.zones.iter().enumerate() {
                    let matches = query.is_empty()
                        || zone.display.to_lowercase().contains(&query)
                        || zone.key.to_lowercase().contains(&query);
                    if matches
                        && ui
                            .selectable_label(selected == Some(i), &zone.display)
                            .clicked()
                        && selected != Some(i)
                    {
                        pick = Some(i);
                    }
                }
            });

        if let Some(i) = pick {
            self.zone_search.clear();
            self.settings_error = timezone::set(&self.zones[i]).err();
        }
        if timezone::auto_update_on() {
            ui.label(
                RichText::new(
                    "\"Set time zone automatically\" is on in Windows Settings, so Windows may \
                     change this back.",
                )
                .small()
                .color(WARN),
            );
        }
    }

    fn startup_toggle(&mut self, ui: &mut egui::Ui) {
        let mut on = self.autostart;
        if ui.checkbox(&mut on, "Start with Windows").changed() {
            let result = if on {
                std::env::current_exe().and_then(|exe| autostart::enable(&exe))
            } else {
                autostart::disable()
            };
            self.settings_error = result
                .err()
                .map(|e| format!("Could not change the startup setting: {e}"));
            self.autostart = autostart::is_enabled();
        }
        ui.label(
            RichText::new("Opens in the tray when you sign in.")
                .small()
                .weak(),
        );
    }

    fn dialogs(&mut self, ctx: &egui::Context) {
        match std::mem::replace(&mut self.dialog, Dialog::None) {
            Dialog::None => {}
            Dialog::Custom {
                input,
                checking,
                failed,
            } => self.custom_dialog(ctx, input, checking, failed),
            Dialog::Ntp {
                choice,
                mut dont_show_again,
            } => match ntp_dialog(ctx, &choice, &mut dont_show_again) {
                Some(true) => {
                    if dont_show_again {
                        self.prefs.skip_ntp_warning = true;
                        self.prefs.save();
                    }
                    self.accept_ntp(choice);
                }
                Some(false) => {}
                None => {
                    self.dialog = Dialog::Ntp {
                        choice,
                        dont_show_again,
                    }
                }
            },
        }
    }

    fn custom_dialog(
        &mut self,
        ctx: &egui::Context,
        mut input: String,
        mut checking: Option<Arc<Mutex<Option<Probe>>>>,
        mut failed: Option<(String, String)>,
    ) {
        // A finished check decides what happens next
        let result = checking
            .as_ref()
            .and_then(|c| c.lock().ok().and_then(|mut r| r.take()));
        if let Some(result) = result {
            checking = None;
            let host = input.trim().to_string();
            match result {
                Probe::Nts { .. } => return self.use_custom(host, Protocol::Nts),
                Probe::NtpOnly { .. } => return self.use_ntp(NtpChoice::Custom(host)),
                Probe::Neither {
                    nts_error,
                    ntp_error,
                } => {
                    failed = Some((
                        format!("No NTS or NTP server is running on {host}."),
                        format!("NTS: {nts_error}\nNTP: {ntp_error}"),
                    ));
                }
            }
        }

        let mut close = false;
        let mut start = false;
        let modal = egui::Modal::new(egui::Id::unique("custom-server")).show(ctx, |ui| {
            ui.set_width(340.0);
            ui.spacing_mut().item_spacing.y = 8.0;
            ui.label(RichText::new("Custom server").size(18.0).strong());
            ui.label(
                RichText::new(
                    "Enter a hostname or IP address. NTS is tried first, then plain NTP.",
                )
                .weak(),
            );

            let busy = checking.is_some();
            let edit = ui.add_enabled(
                !busy,
                egui::TextEdit::singleline(&mut input)
                    .hint_text("time.example.com or 192.168.1.10")
                    .desired_width(f32::INFINITY)
                    .margin(Margin::symmetric(8, 6)),
            );
            if !busy && failed.is_none() && input.is_empty() {
                edit.request_focus();
            }
            let entered = edit.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter));

            if busy {
                ui.horizontal(|ui| {
                    ui.spinner();
                    ui.label(format!("Checking {}...", input.trim()));
                });
            } else if let Some((summary, details)) = &failed {
                ui.colored_label(BAD, summary);
                ui.label(RichText::new(details).weak().small());
            }

            ui.add_space(4.0);
            ui.horizontal(|ui| {
                let valid = nts_client::config::valid_host(input.trim());
                let check = ui.add_enabled(!busy && valid, accent_button("Check and use"));
                if check.clicked() || (entered && valid && !busy) {
                    start = true;
                }
                if ui.button("Cancel").clicked() {
                    close = true;
                }
            });
        });
        if modal.should_close() && checking.is_none() {
            close = true;
        }
        if close {
            return;
        }

        if start {
            failed = None;
            let slot = Arc::new(Mutex::new(None));
            let (host, out, ctx) = (input.trim().to_string(), slot.clone(), ctx.clone());
            thread::spawn(move || {
                let result = probe::probe(&host, PROBE_TIMEOUT);
                if let Ok(mut r) = out.lock() {
                    *r = Some(result);
                }
                ctx.request_repaint();
            });
            checking = Some(slot);
        }
        self.dialog = Dialog::Custom {
            input,
            checking,
            failed,
        };
    }
}

enum UpdateAction {
    CheckNow,
    Install(Release),
}

/// The release the banner offers, if any
fn offered_release(state: &UpdateState) -> Option<&Release> {
    match state {
        UpdateState::Available(r)
        | UpdateState::Installing(r, _)
        | UpdateState::Failed {
            release: Some(r), ..
        } => Some(r),
        _ => None,
    }
}

fn update_banner(ui: &mut egui::Ui, release: &Release, state: &UpdateState) -> Option<UpdateAction> {
    let mut action = None;
    ui.horizontal(|ui| {
        ui.label(icon(Icon::CircleArrowUp).size(18.0).color(ACCENT));
        ui.label(
            RichText::new(format!("Version {} is available", release.version))
                .size(15.0)
                .strong(),
        );
        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
            if let UpdateState::Installing(..) = state {
                ui.spinner();
            } else if ui.add(accent_button("Install")).clicked() {
                action = Some(UpdateAction::Install(release.clone()));
            }
        });
    });
    match state {
        UpdateState::Installing(_, step) => {
            ui.label(RichText::new(*step).weak());
        }
        UpdateState::Failed { error, .. } => {
            ui.colored_label(BAD, error);
        }
        _ => {
            ui.horizontal(|ui| {
                ui.label(
                    RichText::new("Needs administrator permission. The service restarts after.")
                        .small()
                        .weak(),
                );
                ui.hyperlink_to(RichText::new("What's new").small(), &release.page_url);
            });
        }
    }
    action
}

/// "NTS Client 1.0.0 (abc1234) · Up to date · Check now" under the cards
fn version_line(ui: &mut egui::Ui, state: &UpdateState) -> Option<UpdateAction> {
    let mut action = None;
    ui.horizontal(|ui| {
        ui.label(
            RichText::new(format!("NTS Client {} ({})", Version::current(), update::COMMIT))
                .small()
                .weak(),
        );
        let (text, can_check) = match state {
            UpdateState::Off => ("Local build, doesn't update itself".to_string(), false),
            UpdateState::Idle => (String::new(), true),
            UpdateState::Checking => ("Checking for updates...".into(), false),
            UpdateState::UpToDate => ("Up to date".into(), true),
            UpdateState::Available(_) | UpdateState::Installing(..) => (String::new(), false),
            UpdateState::Failed { release: Some(_), .. } => (String::new(), false),
            UpdateState::Failed { error, .. } => (format!("Update check failed: {error}"), true),
        };
        if !text.is_empty() {
            ui.label(RichText::new("·").small().weak());
            ui.label(RichText::new(text).small().weak());
        }
        if can_check && ui.link(RichText::new("Check now").small()).clicked() {
            action = Some(UpdateAction::CheckNow);
        }
    });
    action
}

/// Asks before using plain NTP. `Some(true)` = accepted, `Some(false)` = cancelled.
fn ntp_dialog(ctx: &egui::Context, choice: &NtpChoice, dont_show_again: &mut bool) -> Option<bool> {
    let (title, intro) = match choice {
        NtpChoice::Listed(s) => (
            "Unauthenticated time source".to_string(),
            format!("{} ({}) uses plain NTP.", s.name, s.host),
        ),
        NtpChoice::Custom(host) => (
            "This server only supports NTP".to_string(),
            format!("{host} answered plain NTP, but not NTS."),
        ),
    };
    let mut answer = None;
    let modal = egui::Modal::new(egui::Id::unique("confirm-ntp")).show(ctx, |ui| {
        ui.set_width(340.0);
        ui.spacing_mut().item_spacing.y = 8.0;
        ui.horizontal(|ui| {
            ui.label(icon(Icon::TriangleAlert).size(20.0).color(WARN));
            ui.label(RichText::new(title).size(18.0).strong());
        });
        ui.label(format!(
            "{intro} Its replies aren't signed, so anyone between you and the server \
             (your Wi-Fi, your ISP, or a hijacked route) could send a fake time, and \
             the service would set your clock to it."
        ));
        ui.label(
            RichText::new(
                "A wrong clock can break HTTPS certificate checks, two-factor codes and \
                 file timestamps. NTS servers sign every reply to prevent this.",
            )
            .weak(),
        );
        ui.checkbox(dont_show_again, "Don't show this again");
        ui.add_space(4.0);
        ui.horizontal(|ui| {
            let use_it = egui::Button::new(RichText::new("Use it anyway").color(Color32::WHITE))
                .fill(WARN)
                .corner_radius(CornerRadius::same(6));
            if ui.add(use_it).clicked() {
                answer = Some(true);
            }
            if ui.button("Cancel").clicked() {
                answer = Some(false);
            }
        });
    });
    if answer.is_none() && modal.should_close() {
        answer = Some(false); // Escape or a click outside
    }
    answer
}

/// A rounded panel
fn card<R>(ui: &mut egui::Ui, add: impl FnOnce(&mut egui::Ui) -> R) -> R {
    let v = ui.visuals();
    egui::Frame::new()
        .fill(v.faint_bg_color)
        .stroke(Stroke::new(1.0, v.widgets.noninteractive.bg_stroke.color))
        .corner_radius(CornerRadius::same(12))
        .inner_margin(Margin::same(16))
        .show(ui, |ui| {
            ui.set_width(ui.available_width());
            add(ui)
        })
        .inner
}

fn accent_button(text: &str) -> egui::Button<'_> {
    egui::Button::new(RichText::new(text).color(Color32::WHITE))
        .fill(ACCENT)
        .corner_radius(CornerRadius::same(6))
}

fn caption(ui: &mut egui::Ui, text: &str) {
    ui.label(RichText::new(text.to_uppercase()).small().weak());
}

fn clock(ui: &mut egui::Ui) {
    let local = system_time(GetLocalTime);
    let utc = system_time(GetSystemTime);
    let to_min = |t: &SYSTEMTIME| t.wHour as i32 * 60 + t.wMinute as i32;
    let mut diff = to_min(&local) - to_min(&utc);
    if diff > 14 * 60 {
        diff -= 24 * 60;
    } else if diff < -12 * 60 {
        diff += 24 * 60;
    }
    ui.vertical_centered(|ui| {
        ui.label(
            RichText::new(format!(
                "{:02}:{:02}:{:02}",
                local.wHour, local.wMinute, local.wSecond
            ))
            .family(light_family(ui))
            .size(54.0),
        );
        ui.label(
            RichText::new(format!(
                "{}, {} {} {}",
                WEEKDAYS[local.wDayOfWeek as usize % 7],
                local.wDay,
                MONTHS[(local.wMonth as usize).saturating_sub(1) % 12],
                local.wYear
            ))
            .size(15.0),
        );
        ui.label(
            RichText::new(format!(
                "UTC {:02}:{:02}:{:02}  ·  UTC{}{:02}:{:02}",
                utc.wHour,
                utc.wMinute,
                utc.wSecond,
                if diff < 0 { '−' } else { '+' },
                diff.abs() / 60,
                diff.abs() % 60
            ))
            .weak(),
        );
    });
}

const WEEKDAYS: [&str; 7] = [
    "Sunday",
    "Monday",
    "Tuesday",
    "Wednesday",
    "Thursday",
    "Friday",
    "Saturday",
];
const MONTHS: [&str; 12] = [
    "January",
    "February",
    "March",
    "April",
    "May",
    "June",
    "July",
    "August",
    "September",
    "October",
    "November",
    "December",
];

fn system_time(get: unsafe extern "system" fn(*mut SYSTEMTIME)) -> SYSTEMTIME {
    let mut st: SYSTEMTIME = unsafe { std::mem::zeroed() };
    unsafe { get(&mut st) };
    st
}

/// The service's state
fn status(
    ui: &mut egui::Ui,
    reply: Option<&Reply>,
    unreachable: Option<&str>,
    svc: Option<&Result<Option<ServiceState>, String>>,
    helper: &Helper,
    w32time_disabled: Option<bool>,
) -> Option<ServiceAction> {
    let Some(reply) = reply.filter(|_| unreachable.is_none()) else {
        return service_down(ui, unreachable, svc, helper);
    };

    let s = &reply.status;
    let healthy = matches!(
        s.state.as_str(),
        "Synced" | "Measuring drift" | "Stepped the clock"
    );
    ui.horizontal(|ui| {
        dot(ui, if healthy { GOOD } else { WARN });
        ui.label(RichText::new(&s.state).size(16.0).strong());
        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
            if let Some(p) = s.protocol {
                badge(ui, p);
            }
        });
    });
    if !s.host.is_empty() {
        ui.label(RichText::new(&s.host).weak());
    }

    ui.add_space(4.0);
    ui.columns(3, |cols| {
        stat(
            &mut cols[0],
            "Offset",
            s.offset_ms.map(|o| format!("{o:+.2} ms")),
        );
        stat(
            &mut cols[1],
            "Delay",
            s.delay_ms.map(|d| format!("{d:.1} ms")),
        );
        stat(
            &mut cols[2],
            "Drift",
            s.freq_ppm.map(|f| format!("{f:+.2} ppm")),
        );
    });
    if let Some(t) = s.last_sync {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs_f64())
            .unwrap_or(t);
        ui.label(
            RichText::new(format!("Last checked {:.0} s ago", (now - t).max(0.0)))
                .small()
                .weak(),
        );
    }
    if w32time_disabled == Some(false) {
        return w32time_warning(ui, helper);
    }
    None
}

/// Windows Time can be started again by Windows and would clash
fn w32time_warning(ui: &mut egui::Ui, helper: &Helper) -> Option<ServiceAction> {
    let why = "Windows can start the default Windows Time Service again (via \"Sync now\" in Settings or a weekly task), and it would clash with this service regarding the clock. Disabling the service needs administrator permissions.";
    let mut pressed = None;
    ui.horizontal(|ui| {
        ui.label(icon(Icon::TriangleAlert).color(WARN))
            .on_hover_text(why);
        ui.label(RichText::new("Windows Time Service isn't disabled").color(WARN))
            .on_hover_text(why);
        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
            if *helper == Helper::Running {
                ui.spinner()
                    .on_hover_text("Approve the Windows prompt to continue");
            } else if ui
                .add(accent_button("Disable"))
                .on_hover_text(why)
                .clicked()
            {
                pressed = Some(ServiceAction::DisableW32Time);
            }
        });
    });
    if let Helper::Failed(e) = helper {
        ui.colored_label(BAD, e);
    }
    pressed
}

/// Why the service can't be reached
fn service_down(
    ui: &mut egui::Ui,
    unreachable: Option<&str>,
    svc: Option<&Result<Option<ServiceState>, String>>,
    helper: &Helper,
) -> Option<ServiceAction> {
    let Some(unreachable) = unreachable else {
        ui.horizontal(|ui| {
            dot(ui, Color32::GRAY);
            ui.label(RichText::new("Connecting...").size(16.0).strong());
        });
        return None;
    };

    let (title, detail, action) = match svc {
        Some(Ok(None)) => (
            "Service not installed",
            "The NTS Client service keeps your clock in sync in the background.".to_string(),
            Some((ServiceAction::InstallAndStart, "Install and start")),
        ),
        Some(Ok(Some(ServiceState::Stopped))) => (
            "Service stopped",
            "Your clock isn't being kept in sync.".to_string(),
            Some((ServiceAction::Start, "Start service")),
        ),
        Some(Ok(Some(ServiceState::StartPending))) => (
            "Service starting",
            "Waiting for it to answer...".to_string(),
            None,
        ),
        Some(Ok(Some(ServiceState::StopPending))) => (
            "Service stopping",
            "Waiting for it to stop...".to_string(),
            None,
        ),
        Some(Ok(Some(_))) => (
            "Service not answering",
            format!("It's running, but the connection failed: {unreachable}"),
            None,
        ),
        Some(Err(e)) => ("Service unavailable", e.clone(), None),
        None => ("Service unavailable", unreachable.to_string(), None),
    };

    ui.horizontal(|ui| {
        dot(ui, BAD);
        ui.label(RichText::new(title).size(16.0).strong());
    });
    ui.label(RichText::new(detail).weak());

    let mut pressed = None;
    match helper {
        Helper::Running => {
            ui.horizontal(|ui| {
                ui.spinner();
                ui.label(RichText::new("Approve the Windows prompt to continue...").weak());
            });
        }
        _ => {
            if let Some((action, label)) = action {
                ui.add_space(2.0);
                if ui.add(accent_button(label)).clicked() {
                    pressed = Some(action);
                }
                ui.label(
                    RichText::new("Needs administrator permission")
                        .small()
                        .weak(),
                );
            }
            if let Helper::Failed(e) = helper {
                ui.colored_label(BAD, e);
            }
        }
    }
    pressed
}

/// Runs nts-client.exe from next to this exe, elevated, and waits for it
fn run_elevated(args: &str) -> Result<(), String> {
    let exe = std::env::current_exe()
        .map_err(|e| e.to_string())?
        .with_file_name("nts-client.exe");
    if !exe.exists() {
        return Err(format!("{} not found", exe.display()));
    }
    let error_file = std::env::temp_dir().join(format!("nts-tray-{}.txt", std::process::id()));
    let _ = fs::remove_file(&error_file);
    let params = format!("{args} --error-file \"{}\"", error_file.display());

    let wide = |s: &str| s.encode_utf16().chain([0]).collect::<Vec<u16>>();
    let (verb, file, params) = (wide("runas"), wide(&exe.to_string_lossy()), wide(&params));
    let code = unsafe {
        let mut info: SHELLEXECUTEINFOW = std::mem::zeroed();
        info.cbSize = size_of::<SHELLEXECUTEINFOW>() as u32;
        info.fMask = SEE_MASK_NOCLOSEPROCESS | SEE_MASK_NOASYNC;
        info.lpVerb = verb.as_ptr();
        info.lpFile = file.as_ptr();
        info.lpParameters = params.as_ptr();
        info.nShow = SW_HIDE;
        if ShellExecuteExW(&mut info) == 0 {
            let e = std::io::Error::last_os_error();
            return Err(if e.raw_os_error() == Some(ERROR_CANCELLED as i32) {
                "Cancelled at the Windows prompt.".into()
            } else {
                e.to_string()
            });
        }
        WaitForSingleObject(info.hProcess, INFINITE);
        let mut code = 1u32;
        GetExitCodeProcess(info.hProcess, &mut code);
        CloseHandle(info.hProcess);
        code
    };
    if code == 0 {
        return Ok(());
    }
    let message = fs::read_to_string(&error_file).unwrap_or_default();
    let _ = fs::remove_file(&error_file);
    match message.trim() {
        "" => Err(format!("nts-client exited with code {code}")),
        m => Err(m.to_string()),
    }
}

fn stat(ui: &mut egui::Ui, name: &str, value: Option<String>) {
    caption(ui, name);
    ui.label(
        RichText::new(value.unwrap_or_else(|| "—".into()))
            .size(17.0)
            .strong(),
    );
}

fn dot(ui: &mut egui::Ui, colour: Color32) {
    let (rect, _) = ui.allocate_exact_size(egui::vec2(10.0, 10.0), egui::Sense::hover());
    ui.painter().circle_filled(rect.center(), 5.0, colour);
}

fn badge(ui: &mut egui::Ui, protocol: Protocol) {
    let (glyph, text, colour) = match protocol {
        Protocol::Nts => (Icon::ShieldCheck, "NTS · authenticated", GOOD),
        Protocol::Ntp => (Icon::ShieldAlert, "NTP · unauthenticated", WARN),
    };
    egui::Frame::new()
        .fill(colour.gamma_multiply(0.18))
        .corner_radius(CornerRadius::same(10))
        .inner_margin(Margin::symmetric(8, 2))
        .show(ui, |ui| {
            let mut job = egui::text::LayoutJob::default();
            let format = |family: FontFamily, size: f32| egui::TextFormat {
                font_id: egui::FontId::new(size, family),
                color: colour,
                valign: egui::Align::Center,
                ..Default::default()
            };
            job.append(
                &glyph.unicode().to_string(),
                0.0,
                format(FontFamily::Name("icons".into()), 13.0),
            );
            job.append(text, 5.0, format(FontFamily::Proportional, 12.0));
            ui.label(job);
        });
}

enum Pick {
    Listed(&'static Server),
    /// The saved custom server, picked again
    SavedCustom(String, Protocol),
    /// "Custom server..."
    NewCustom,
}

fn server_picker(
    ui: &mut egui::Ui,
    reply: Option<&Reply>,
    connected: bool,
    pending: Option<&str>,
) -> Option<Pick> {
    caption(ui, "Time server");
    let current_id = reply.map(|r| r.server_id.as_str());
    let custom = reply.and_then(|r| r.custom.clone());
    let selected_text = match (current_id, &custom) {
        (Some(CUSTOM_ID), Some(c)) => format!("Custom: {}", c.host),
        (Some(id), _) => servers::find(id).map_or(id.to_string(), |s| s.name.to_string()),
        (None, _) => "—".into(),
    };

    let mut pick = None;
    ui.add_enabled_ui(connected && pending.is_none(), |ui| {
        egui::ComboBox::from_id_salt("server")
            .width(ui.available_width())
            .height(400.0)
            .selected_text(RichText::new(selected_text).size(15.0))
            .show_ui(ui, |ui| {
                for (protocol, heading) in [
                    (Protocol::Nts, "Authenticated (NTS)"),
                    (Protocol::Ntp, "Unauthenticated (NTP)"),
                ] {
                    ui.add_space(4.0);
                    caption(ui, heading);
                    for s in servers::SERVERS.iter().filter(|s| s.protocol == protocol) {
                        let selected = current_id == Some(s.id);
                        let text = format!("{}  ·  {}", s.name, s.host);
                        if ui.selectable_label(selected, text).clicked() && !selected {
                            pick = Some(Pick::Listed(s));
                        }
                    }
                }
                ui.add_space(4.0);
                caption(ui, "Custom");
                if let Some(c) = &custom {
                    let selected = current_id == Some(CUSTOM_ID);
                    let text = format!("{}  ·  {}", c.host, c.protocol.label());
                    if ui.selectable_label(selected, text).clicked() && !selected {
                        pick = Some(Pick::SavedCustom(c.host.clone(), c.protocol));
                    }
                }
                if ui.selectable_label(false, "Custom server...").clicked() {
                    pick = Some(Pick::NewCustom);
                }
            });
    });

    if pending.is_some() {
        ui.horizontal(|ui| {
            ui.spinner();
            ui.label(RichText::new("Switching...").weak());
        });
    } else {
        let note = match reply.map(|r| r.status.protocol) {
            Some(Some(Protocol::Ntp)) => RichText::new(
                "Plain NTP: replies aren't signed, so the time could be faked on the way.",
            )
            .color(WARN),
            _ => {
                RichText::new("NTS signs every reply, so nobody on the network can fake the time.")
                    .weak()
            }
        };
        ui.label(note.small());
    }
    pick
}

fn style(ctx: &egui::Context) {
    let mut fonts = FontDefinitions::default();
    let windows_fonts =
        PathBuf::from(std::env::var_os("WINDIR").unwrap_or_else(|| "C:\\Windows".into()))
            .join("Fonts");
    let load = |file: &str| fs::read(windows_fonts.join(file)).ok();
    if let Some(regular) = load("segoeui.ttf") {
        fonts
            .font_data
            .insert("segoe".into(), Arc::new(FontData::from_owned(regular)));
        fonts
            .families
            .entry(FontFamily::Proportional)
            .or_default()
            .insert(0, "segoe".into());
    }
    if let Some(light) = load("segoeuil.ttf") {
        fonts
            .font_data
            .insert("segoe-light".into(), Arc::new(FontData::from_owned(light)));
        let fallback = fonts.families[&FontFamily::Proportional].clone();
        fonts.families.insert(
            FontFamily::Name("light".into()),
            std::iter::once("segoe-light".to_string())
                .chain(fallback)
                .collect(),
        );
    }
    fonts.font_data.insert(
        "lucide".into(),
        Arc::new(FontData::from_static(lucide_icons::LUCIDE_FONT_BYTES)),
    );
    fonts
        .families
        .insert(FontFamily::Name("icons".into()), vec!["lucide".into()]);
    ctx.set_fonts(fonts);

    for theme in [Theme::Dark, Theme::Light] {
        let mut v = match theme {
            Theme::Dark => Visuals::dark(),
            Theme::Light => Visuals::light(),
        };
        if theme == Theme::Dark {
            v.panel_fill = Color32::from_rgb(0x16, 0x18, 0x1d);
            v.faint_bg_color = Color32::from_rgb(0x1f, 0x22, 0x29);
            v.extreme_bg_color = Color32::from_rgb(0x12, 0x14, 0x18);
            v.window_fill = Color32::from_rgb(0x23, 0x26, 0x2e);
        } else {
            v.panel_fill = Color32::from_rgb(0xf3, 0xf4, 0xf6);
            v.faint_bg_color = Color32::WHITE;
            v.window_fill = Color32::WHITE;
        }
        v.selection.bg_fill = ACCENT.gamma_multiply(0.45);
        v.selection.stroke = Stroke::new(1.0, ACCENT);
        v.hyperlink_color = ACCENT;
        v.window_corner_radius = CornerRadius::same(12);
        v.menu_corner_radius = CornerRadius::same(10);
        for w in [
            &mut v.widgets.noninteractive,
            &mut v.widgets.inactive,
            &mut v.widgets.hovered,
            &mut v.widgets.active,
            &mut v.widgets.open,
        ] {
            w.corner_radius = CornerRadius::same(6);
        }
        ctx.set_visuals_of(theme, v);
    }
    ctx.all_styles_mut(|s| {
        s.spacing.item_spacing = egui::vec2(8.0, 6.0);
        s.spacing.button_padding = egui::vec2(12.0, 6.0);
        s.spacing.interact_size.y = 28.0;
    });
}

fn icon(icon: Icon) -> RichText {
    RichText::new(icon.unicode().to_string()).family(FontFamily::Name("icons".into()))
}

fn light_family(ui: &egui::Ui) -> FontFamily {
    let light = FontFamily::Name("light".into());
    if ui.fonts(|f| f.families().contains(&light)) {
        light
    } else {
        FontFamily::Proportional
    }
}

/// A 32×32 clock face for the tray and window icon
fn icon_rgba() -> (Vec<u8>, u32) {
    const N: u32 = 32;
    let c = (N as f32 - 1.0) / 2.0;
    let mut rgba = vec![0u8; (N * N * 4) as usize];
    // Hands at 10:10, as distances from the centre along each direction
    let hands = [(-0.81f32, -0.59f32, 8.0f32), (0.81, -0.59, 11.0)];
    for y in 0..N {
        for x in 0..N {
            let (dx, dy) = (x as f32 - c, y as f32 - c);
            let r = (dx * dx + dy * dy).sqrt();
            let on_hand = hands.iter().any(|&(hx, hy, len)| {
                let along = dx * hx + dy * hy;
                let across = (dx * hy - dy * hx).abs();
                (0.0..=len).contains(&along) && across < 1.3
            });
            let colour = if r > 15.5 {
                None
            } else if r > 13.0 {
                Some([0x2b, 0x6c, 0xb0]) // rim
            } else if on_hand || r < 2.0 {
                Some([0x1a, 0x1a, 0x1a])
            } else {
                Some([0xfa, 0xfa, 0xfa]) // face
            };
            if let Some([red, green, blue]) = colour {
                let i = ((y * N + x) * 4) as usize;
                rgba[i..i + 4].copy_from_slice(&[red, green, blue, 0xff]);
            }
        }
    }
    (rgba, N)
}
