use std::fmt;
use std::ops::{Add, Div, Sub};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// Seconds from 1900-01-01 (NTP epoch) to 1970-01-01 (Unix epoch)
pub const NTP_UNIX_OFFSET_SECS: u64 = 2_208_988_800;

const FRAC_PER_SEC: f64 = 4_294_967_296.0; // 2^32

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct NtpTimestamp(pub u64);

impl NtpTimestamp {
    pub const ZERO: Self = Self(0);

    pub fn from_system_time(t: SystemTime) -> Self {
        let (secs, nanos) = match t.duration_since(UNIX_EPOCH) {
            Ok(d) => (d.as_secs() as i64, d.subsec_nanos()),
            Err(e) => {
                let d = e.duration();
                if d.subsec_nanos() == 0 {
                    (-(d.as_secs() as i64), 0)
                } else {
                    (-(d.as_secs() as i64) - 1, 1_000_000_000 - d.subsec_nanos())
                }
            }
        };
        let ntp_secs = (secs + NTP_UNIX_OFFSET_SECS as i64) as u64 & 0xFFFF_FFFF;
        let frac = ((nanos as u64) << 32) / 1_000_000_000;
        Self((ntp_secs << 32) | frac)
    }

    /// Converts to wall-clock time
    pub fn to_system_time(self, reference: SystemTime) -> SystemTime {
        let delta = self - Self::from_system_time(reference);
        add_signed(reference, delta)
    }

    #[cfg(test)]
    pub fn seconds(self) -> u32 {
        (self.0 >> 32) as u32
    }

    #[cfg(test)]
    pub fn fraction(self) -> u32 {
        self.0 as u32
    }
}

impl Sub for NtpTimestamp {
    type Output = NtpDuration;

    fn sub(self, rhs: Self) -> NtpDuration {
        NtpDuration(self.0.wrapping_sub(rhs.0) as i64)
    }
}

impl Add<NtpDuration> for NtpTimestamp {
    type Output = NtpTimestamp;

    fn add(self, rhs: NtpDuration) -> NtpTimestamp {
        NtpTimestamp(self.0.wrapping_add(rhs.0 as u64))
    }
}

/// Signed fixed point duration representing the difference of 2 timestamps
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct NtpDuration(pub i64);

impl NtpDuration {
    pub fn from_duration(d: Duration) -> Self {
        let frac = ((d.subsec_nanos() as u64) << 32) / 1_000_000_000;
        Self(((d.as_secs() << 32) | frac) as i64)
    }

    pub fn as_secs_f64(self) -> f64 {
        self.0 as f64 / FRAC_PER_SEC
    }

    pub fn as_millis_f64(self) -> f64 {
        self.as_secs_f64() * 1000.0
    }

    pub fn as_nanos(self) -> i128 {
        (self.0 as i128 * 1_000_000_000) >> 32
    }
}

impl Add for NtpDuration {
    type Output = Self;
    fn add(self, rhs: Self) -> Self {
        Self(self.0.wrapping_add(rhs.0))
    }
}

impl Sub for NtpDuration {
    type Output = Self;
    fn sub(self, rhs: Self) -> Self {
        Self(self.0.wrapping_sub(rhs.0))
    }
}

impl Div<i64> for NtpDuration {
    type Output = Self;
    fn div(self, rhs: i64) -> Self {
        Self(self.0 / rhs)
    }
}

impl fmt::Display for NtpDuration {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:+.3} ms", self.as_millis_f64())
    }
}

pub fn add_signed(t: SystemTime, d: NtpDuration) -> SystemTime {
    let nanos = d.as_nanos();
    let mag = Duration::from_nanos(nanos.unsigned_abs() as u64);
    if nanos >= 0 {
        t + mag
    } else {
        t - mag
    }
}

/// Formats a `SystemTime` as `YYYY-MM-DD HH:MM:SS.mmm UTC`
pub fn format_utc(t: SystemTime) -> String {
    let (secs, millis) = match t.duration_since(UNIX_EPOCH) {
        Ok(d) => (d.as_secs() as i64, d.subsec_millis()),
        Err(_) => return "<before 1970>".into(),
    };
    let days = secs.div_euclid(86_400);
    let sod = secs.rem_euclid(86_400);
    let (y, m, d) = civil_from_days(days);
    format!(
        "{y:04}-{m:02}-{d:02} {:02}:{:02}:{:02}.{millis:03} UTC",
        sod / 3600,
        (sod % 3600) / 60,
        sod % 60
    )
}

/// Days since 1970-01-01 -> (year, month, day) in the Gregorian calendar
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    let y = yoe + era * 400 + if m <= 2 { 1 } else { 0 };
    (y, m, d)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unix_epoch_is_ntp_offset() {
        let ts = NtpTimestamp::from_system_time(UNIX_EPOCH);
        assert_eq!(ts.seconds() as u64, NTP_UNIX_OFFSET_SECS);
        assert_eq!(ts.fraction(), 0);
    }

    #[test]
    fn half_second_fraction() {
        let ts = NtpTimestamp::from_system_time(UNIX_EPOCH + Duration::from_millis(500));
        assert_eq!(ts.fraction(), 0x8000_0000);
    }

    #[test]
    fn roundtrip_system_time_within_a_microsecond() {
        let t = UNIX_EPOCH + Duration::new(1_763_164_800, 123_456_789); // 2025-11-15
        let back = NtpTimestamp::from_system_time(t).to_system_time(t);
        let err = back.duration_since(t).unwrap_or_else(|e| e.duration());
        assert!(err < Duration::from_nanos(2), "{err:?}");
    }

    #[test]
    fn era_rollover_2036() {
        // 2036-02-07 06:28:16 UTC is NTP second 2^32, i.e. raw seconds = 0 in era 1.
        let rollover = UNIX_EPOCH + Duration::from_secs((1u64 << 32) - NTP_UNIX_OFFSET_SECS);
        let before = rollover - Duration::from_secs(10);
        let after = rollover + Duration::from_secs(10);

        let ts_before = NtpTimestamp::from_system_time(before);
        let ts_after = NtpTimestamp::from_system_time(after);
        assert_eq!(ts_after.seconds(), 10); // wrapped

        // Differences still come out right across the wrap.
        assert_eq!((ts_after - ts_before).as_secs_f64(), 20.0);
        // And era selection resolves the wrapped value to 2036, not 1900.
        assert_eq!(ts_after.to_system_time(before), after);
        assert_eq!(format_utc(rollover), "2036-02-07 06:28:16.000 UTC");
    }

    #[test]
    fn negative_differences() {
        let a = NtpTimestamp(10 << 32);
        let b = NtpTimestamp(12 << 32);
        assert_eq!((a - b).as_secs_f64(), -2.0);
        assert_eq!(b + (a - b), a);
    }

    #[test]
    fn utc_formatting() {
        assert_eq!(format_utc(UNIX_EPOCH), "1970-01-01 00:00:00.000 UTC");
        let t = UNIX_EPOCH + Duration::from_millis(951_782_400_250); // leap day 2000
        assert_eq!(format_utc(t), "2000-02-29 00:00:00.250 UTC");
    }
}
