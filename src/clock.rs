//! Changing the Windows system clock.
//!
//! Setting the time needs `SeSystemtimePrivilege`. Administrators hold it, but
//! only in an elevated ("Run as administrator") process, and even then it is
//! disabled until the process switches it on with `AdjustTokenPrivileges`.

use std::fmt;
use std::io;
use std::mem;
use std::ptr;
use std::time::{SystemTime, UNIX_EPOCH};

use windows_sys::core::{w, BOOL};
use windows_sys::Win32::Foundation::{
    CloseHandle, GetLastError, ERROR_NOT_ALL_ASSIGNED, ERROR_SERVICE_DOES_NOT_EXIST, FILETIME,
    HANDLE, LUID, SYSTEMTIME,
};
use windows_sys::Win32::Security::{
    AdjustTokenPrivileges, LookupPrivilegeValueW, LUID_AND_ATTRIBUTES, SE_PRIVILEGE_ENABLED,
    SE_SYSTEMTIME_NAME, TOKEN_ADJUST_PRIVILEGES, TOKEN_PRIVILEGES, TOKEN_QUERY,
};
use windows_sys::Win32::System::Console::SetConsoleCtrlHandler;
use windows_sys::Win32::System::Services::{
    CloseServiceHandle, OpenSCManagerW, OpenServiceW, QueryServiceStatus, SC_MANAGER_CONNECT,
    SERVICE_QUERY_STATUS, SERVICE_STATUS, SERVICE_STOPPED,
};
use windows_sys::Win32::System::SystemInformation::{
    GetSystemTimeAdjustmentPrecise, SetSystemTime, SetSystemTimeAdjustmentPrecise,
};
use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};
use windows_sys::Win32::System::Time::FileTimeToSystemTime;

use crate::time::{add_signed, NtpDuration};

/// 100 ns intervals from 1601-01-01 (FILETIME epoch) to 1970-01-01
const FILETIME_UNIX_OFFSET: u64 = 116_444_736_000_000_000;

#[derive(Debug)]
pub enum ClockError {
    /// The process token doesn't hold the privilege (not elevated)
    NoPrivilege,
    Os(&'static str, io::Error),
    BeforeUnixEpoch,
}

impl fmt::Display for ClockError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoPrivilege => write!(
                f,
                "no permission to set the clock (run from an elevated/administrator terminal)"
            ),
            Self::Os(call, e) => write!(f, "{call} failed: {e}"),
            Self::BeforeUnixEpoch => write!(f, "target time is before 1970"),
        }
    }
}

impl std::error::Error for ClockError {}

fn last_error(call: &'static str) -> ClockError {
    ClockError::Os(call, io::Error::last_os_error())
}

/// Switches on `SeSystemtimePrivilege` for this process
pub fn enable_privilege() -> Result<(), ClockError> {
    unsafe {
        let mut token: HANDLE = ptr::null_mut();
        if OpenProcessToken(
            GetCurrentProcess(),
            TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
            &mut token,
        ) == 0
        {
            return Err(last_error("OpenProcessToken"));
        }

        let result = (|| {
            let mut luid: LUID = mem::zeroed();
            if LookupPrivilegeValueW(ptr::null(), SE_SYSTEMTIME_NAME, &mut luid) == 0 {
                return Err(last_error("LookupPrivilegeValueW"));
            }
            let privileges = TOKEN_PRIVILEGES {
                PrivilegeCount: 1,
                Privileges: [LUID_AND_ATTRIBUTES {
                    Luid: luid,
                    Attributes: SE_PRIVILEGE_ENABLED,
                }],
            };
            let ok = AdjustTokenPrivileges(
                token,
                0,
                &privileges,
                0,
                ptr::null_mut(),
                ptr::null_mut(),
            );
            if ok == 0 {
                return Err(last_error("AdjustTokenPrivileges"));
            }
            // Succeeds even when the token lacks the privilege; this is how it says so
            if GetLastError() == ERROR_NOT_ALL_ASSIGNED {
                return Err(ClockError::NoPrivilege);
            }
            Ok(())
        })();

        CloseHandle(token);
        result
    }
}

/// Jumps the clock by `offset`. Returns the time it was set to.
pub fn step(offset: NtpDuration) -> Result<SystemTime, ClockError> {
    let target = add_signed(SystemTime::now(), offset);
    let st = to_systemtime(target)?;
    if unsafe { SetSystemTime(&st) } == 0 {
        return Err(last_error("SetSystemTime"));
    }
    Ok(target)
}

/// Makes the clock run faster (+) or slower (-) by `rate`, e.g. `54e-6` = 54 ppm.
///
/// `increment` is the performance counter frequency (10,000,000 ticks/s here)
/// and `adjustment` is how many ticks Windows counts as one second of clock
/// time, so a *bigger* adjustment makes the clock run *slower*. Resolution is
/// 0.1 ppm. The setting stays in effect after this process exits.
pub fn set_rate(rate: f64) -> Result<(), ClockError> {
    let (mut adjustment, mut increment, mut disabled) = (0u64, 0u64, 0);
    if unsafe { GetSystemTimeAdjustmentPrecise(&mut adjustment, &mut increment, &mut disabled) }
        == 0
    {
        return Err(last_error("GetSystemTimeAdjustmentPrecise"));
    }
    let adjustment = (increment as f64 / (1.0 + rate)).round() as u64;
    if unsafe { SetSystemTimeAdjustmentPrecise(adjustment, 0) } == 0 {
        return Err(last_error("SetSystemTimeAdjustmentPrecise"));
    }
    Ok(())
}

/// Hands the clock rate back to Windows' default
pub fn reset_rate() -> Result<(), ClockError> {
    if unsafe { SetSystemTimeAdjustmentPrecise(0, 1) } == 0 {
        return Err(last_error("SetSystemTimeAdjustmentPrecise"));
    }
    Ok(())
}

/// Calls [`reset_rate`] on Ctrl+C or when the console window is closed.
/// Those end the process without unwinding, so `Drop` guards don't run.
pub fn reset_rate_on_console_exit() -> Result<(), ClockError> {
    unsafe extern "system" fn handler(_ctrl_type: u32) -> BOOL {
        let _ = reset_rate();
        0 // not handled: let Windows go on to end the process
    }
    if unsafe { SetConsoleCtrlHandler(Some(handler), 1) } == 0 {
        return Err(last_error("SetConsoleCtrlHandler"));
    }
    Ok(())
}

/// Whether the Windows Time service (W32Time) is running (false if it isn't installed)
pub fn w32time_running() -> Result<bool, ClockError> {
    unsafe {
        let scm = OpenSCManagerW(ptr::null(), ptr::null(), SC_MANAGER_CONNECT);
        if scm.is_null() {
            return Err(last_error("OpenSCManagerW"));
        }
        let service = OpenServiceW(scm, w!("W32Time"), SERVICE_QUERY_STATUS);
        if service.is_null() {
            let err = GetLastError();
            CloseServiceHandle(scm);
            if err == ERROR_SERVICE_DOES_NOT_EXIST {
                return Ok(false);
            }
            return Err(ClockError::Os(
                "OpenServiceW",
                io::Error::from_raw_os_error(err as i32),
            ));
        }
        let mut status: SERVICE_STATUS = mem::zeroed();
        let ok = QueryServiceStatus(service, &mut status);
        let err = io::Error::last_os_error();
        CloseServiceHandle(service);
        CloseServiceHandle(scm);
        if ok == 0 {
            return Err(ClockError::Os("QueryServiceStatus", err));
        }
        Ok(status.dwCurrentState != SERVICE_STOPPED)
    }
}

/// UTC `SystemTime` -> Win32 `SYSTEMTIME`, rounded to its millisecond resolution
fn to_systemtime(t: SystemTime) -> Result<SYSTEMTIME, ClockError> {
    let since_unix = t
        .duration_since(UNIX_EPOCH)
        .map_err(|_| ClockError::BeforeUnixEpoch)?;
    let ticks = FILETIME_UNIX_OFFSET + (since_unix.as_nanos() / 100) as u64 + 5_000;
    let ft = FILETIME {
        dwLowDateTime: ticks as u32,
        dwHighDateTime: (ticks >> 32) as u32,
    };
    let mut st: SYSTEMTIME = unsafe { mem::zeroed() };
    if unsafe { FileTimeToSystemTime(&ft, &mut st) } == 0 {
        return Err(last_error("FileTimeToSystemTime"));
    }
    Ok(st)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn detects_w32time() {
        // Read-only query; just checks the calls work
        w32time_running().unwrap();
    }

    #[test]
    fn systemtime_fields_and_rounding() {
        // 2000-02-29 13:45:30.2496 UTC rounds to .250
        let t = UNIX_EPOCH + Duration::from_nanos(951_831_930_249_600_000);
        let st = to_systemtime(t).unwrap();
        assert_eq!(
            (st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond),
            (2000, 2, 29, 13, 45, 30)
        );
        assert_eq!(st.wMilliseconds, 250);
        assert_eq!(st.wDayOfWeek, 2); // Tuesday
    }
}
