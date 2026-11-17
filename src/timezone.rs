use std::mem;

use windows_sys::Win32::Foundation::ERROR_SUCCESS;
use windows_sys::Win32::System::Time::{
    EnumDynamicTimeZoneInformation, GetDynamicTimeZoneInformation, SetDynamicTimeZoneInformation,
    DYNAMIC_TIME_ZONE_INFORMATION, TIME_ZONE_ID_INVALID,
};

use crate::clock;
use crate::registry::{self, Root};

const ZONES_KEY: &str = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Time Zones";
/// Set time zone automatically - Start = 3 when it's on, 4 when off
const TZ_AUTO_UPDATE_KEY: &str = r"SYSTEM\CurrentControlSet\Services\tzautoupdate";

#[derive(Clone)]
pub struct Zone {
    /// Reg key: Singapore Standard Time
    pub key: String,
    /// (UTC+08:00) Kuala Lumpur, Singapore
    pub display: String,
    info: DYNAMIC_TIME_ZONE_INFORMATION,
}

fn from_wide(units: &[u16]) -> String {
    let end = units.iter().position(|&u| u == 0).unwrap_or(units.len());
    String::from_utf16_lossy(&units[..end])
}

/// Every time zone Windows knows
pub fn list() -> Vec<Zone> {
    let mut zones = Vec::new();
    for index in 0.. {
        let mut info: DYNAMIC_TIME_ZONE_INFORMATION = unsafe { mem::zeroed() };
        if unsafe { EnumDynamicTimeZoneInformation(index, &mut info) } != ERROR_SUCCESS {
            break;
        }
        let key = from_wide(&info.TimeZoneKeyName);
        let display = registry::read_string(
            Root::LocalMachine,
            &format!(r"{ZONES_KEY}\{key}"),
            "Display",
        )
        .ok()
        .flatten()
        .unwrap_or_else(|| key.clone());
        zones.push(Zone { key, display, info });
    }

    zones.sort_by(|a, b| {
        b.info
            .Bias
            .cmp(&a.info.Bias)
            .then_with(|| a.display.cmp(&b.display))
    });
    zones
}

/// Key name of the current time zone
pub fn current() -> Option<String> {
    let mut info: DYNAMIC_TIME_ZONE_INFORMATION = unsafe { mem::zeroed() };
    if unsafe { GetDynamicTimeZoneInformation(&mut info) } == TIME_ZONE_ID_INVALID {
        return None;
    }
    Some(from_wide(&info.TimeZoneKeyName)).filter(|k| !k.is_empty())
}

/// Changes the system time zone
pub fn set(zone: &Zone) -> Result<(), String> {
    clock::enable_time_zone_privilege().map_err(|e| match e {
        clock::ClockError::NoPrivilege => {
            "this account isn't allowed to change the time zone".into()
        }
        e => format!("could not change the time zone: {e}"),
    })?;
    let mut info = zone.info;
    info.DynamicDaylightTimeDisabled = false; // follow daylight saving
    if unsafe { SetDynamicTimeZoneInformation(&info) } == 0 {
        return Err(format!(
            "could not change the time zone: {}",
            std::io::Error::last_os_error()
        ));
    }
    Ok(())
}

/// Whether Windows' "Set time zone automatically" is on
pub fn auto_update_on() -> bool {
    registry::read_dword(Root::LocalMachine, TZ_AUTO_UPDATE_KEY, "Start")
        .ok()
        .flatten()
        == Some(3)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn current_zone_is_listed() {
        let zones = list();
        assert!(zones.len() > 50, "{}", zones.len());
        assert!(zones.iter().any(|z| z.key == "UTC"));
        assert!(
            zones.iter().all(|z| z.display.starts_with("(UTC")),
            "{}",
            zones[0].display
        );
        // West to east
        assert!(zones.first().unwrap().info.Bias > zones.last().unwrap().info.Bias);
        let current = current().expect("a time zone is set");
        assert!(zones.iter().any(|z| z.key == current), "{current}");
    }
}
