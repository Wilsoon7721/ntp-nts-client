//! Start the tray app at sign-in

use std::io;
use std::path::Path;

use crate::registry::{self, Root};

const RUN_KEY: &str = r"Software\Microsoft\Windows\CurrentVersion\Run";
const APPROVED_KEY: &str =
    r"Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run";
const VALUE: &str = "NTS Client";

pub fn is_enabled() -> bool {
    let present = matches!(
        registry::read_string(Root::CurrentUser, RUN_KEY, VALUE),
        Ok(Some(_))
    );

    // 1st byte is 2 when enabled, 3 when disabled
    let switched_off = matches!(
        registry::read_binary(Root::CurrentUser, APPROVED_KEY, VALUE),
        Ok(Some(b)) if b.first().is_some_and(|f| f & 1 == 1)
    );
    present && !switched_off
}

/// Starts hidden in the tray at sign-in
pub fn enable(exe: &Path) -> io::Result<()> {
    registry::set_string(
        Root::CurrentUser,
        RUN_KEY,
        VALUE,
        &format!("\"{}\" --hidden", exe.display()),
    )?;

    // Undo a disable from Task Manager or the run entry may be ignored
    registry::delete_value(Root::CurrentUser, APPROVED_KEY, VALUE)
}

pub fn disable() -> io::Result<()> {
    registry::delete_value(Root::CurrentUser, RUN_KEY, VALUE)?;
    registry::delete_value(Root::CurrentUser, APPROVED_KEY, VALUE)
}
