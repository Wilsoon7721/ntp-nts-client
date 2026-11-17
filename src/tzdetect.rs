use std::sync::OnceLock;

use windows::Devices::Geolocation::{GeolocationAccessStatus, Geolocator};
use windows::Foundation::TimeSpan;
use windows_sys::core::{s, w};
use windows_sys::Win32::System::LibraryLoader::{
    GetProcAddress, LoadLibraryExW, LOAD_LIBRARY_SEARCH_SYSTEM32,
};

const MAX_AGE_SECS: i64 = 10 * 60;
const TIMEOUT_SECS: i64 = 30;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Detected {
    /// Asia/Singapore
    pub iana: String,
    /// Windows TZ key: "Singapore Standard Time"
    pub windows_key: String,
}

pub fn detect() -> Result<Detected, String> {
    let (latitude, longitude) = locate()?;
    let iana = iana_zone_at(latitude, longitude)
        .ok_or("no time zone is known for your location")?;
    let windows_key =
        windows_zone(&iana).ok_or_else(|| format!("Windows has no time zone matching {iana}"))?;
    Ok(Detected { iana, windows_key })
}

fn locate() -> Result<(f64, f64), String> {
    if let Ok(status) = Geolocator::RequestAccessAsync().and_then(|op| op.join())
        && status != GeolocationAccessStatus::Allowed
    {
        return Err("location access is off in Windows Settings (Privacy → Location, \
                    including \"Let desktop apps access your location\")"
            .into());
    }
    let seconds = |s: i64| TimeSpan {
        Duration: s * 10_000_000,
    };
    let position = Geolocator::new()
        .and_then(|locator| {
            locator.GetGeopositionAsyncWithAgeAndTimeout(seconds(MAX_AGE_SECS), seconds(TIMEOUT_SECS))
        })
        .and_then(|op| op.join())
        .and_then(|p| p.Coordinate())
        .and_then(|c| c.Point())
        .and_then(|p| p.Position())
        .map_err(|e| format!("Windows couldn't find your location: {}", e.message()))?;
    Ok((position.Latitude, position.Longitude))
}

/// IANA time zone at a point
pub fn iana_zone_at(latitude: f64, longitude: f64) -> Option<String> {
    static FINDER: OnceLock<tzf_rs::DefaultFinder> = OnceLock::new();
    let name = FINDER
        .get_or_init(tzf_rs::DefaultFinder::new)
        .get_tz_name(longitude, latitude);
    (!name.is_empty()).then(|| name.to_string())
}

/// IANA name -> Windows time zone key using icu
pub fn windows_zone(iana: &str) -> Option<String> {
    type GetWindowsId = unsafe extern "C" fn(*const u16, i32, *mut u16, i32, *mut i32) -> i32;

    let id: Vec<u16> = iana.encode_utf16().collect();
    for dll in [w!("icu.dll"), w!("icuin.dll")] {
        let function = unsafe {
            let module = LoadLibraryExW(dll, std::ptr::null_mut(), LOAD_LIBRARY_SEARCH_SYSTEM32);
            if module.is_null() {
                continue;
            }
            GetProcAddress(module, s!("ucal_getWindowsTimeZoneID"))
        };
        let Some(function) = function else { continue };
        let get: GetWindowsId = unsafe { std::mem::transmute(function) };
        let mut out = [0u16; 128];
        let mut status = 0i32;
        let len = unsafe {
            get(id.as_ptr(), id.len() as i32, out.as_mut_ptr(), out.len() as i32, &mut status)
        };
        if status > 0 || len <= 0 {
            return None;
        }
        return Some(String::from_utf16_lossy(&out[..len as usize]));
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finds_zones_offline() {
        assert_eq!(iana_zone_at(1.2903, 103.8520).as_deref(), Some("Asia/Singapore"));
        assert_eq!(iana_zone_at(52.13, -106.67).as_deref(), Some("America/Regina")); // Saskatoon
        assert_eq!(iana_zone_at(51.5072, -0.1276).as_deref(), Some("Europe/London"));
    }

    #[test]
    fn maps_to_windows_zones() {
        assert_eq!(windows_zone("Asia/Singapore").as_deref(), Some("Singapore Standard Time"));
        assert_eq!(windows_zone("America/Regina").as_deref(), Some("Canada Central Standard Time"));
        assert_eq!(windows_zone("Europe/London").as_deref(), Some("GMT Standard Time"));
        assert_eq!(windows_zone("Not/AZone"), None);
    }

    #[test]
    fn mapped_zones_exist_on_this_pc() {
        let zones = crate::timezone::list();
        for iana in ["Asia/Singapore", "America/Regina", "Europe/London", "Asia/Kolkata"] {
            let key = windows_zone(iana).unwrap();
            assert!(zones.iter().any(|z| z.key == key), "{iana} -> {key}");
        }
    }

    #[test]
    #[ignore = "uses this PC's location; run with --ignored"]
    fn live_detect() {
        let detected = detect().unwrap();
        // Prints the zone only, never the coordinates
        println!("{} ({})", detected.windows_key, detected.iana);
    }
}
