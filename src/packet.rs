//! NTP packet format:
//! ```text
//!  0                   1                   2                   3
//!  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |LI | VN  |Mode |    Stratum    |     Poll      |   Precision   |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |                         Root Delay (16.16)                    |
//! |                      Root Dispersion (16.16)                  |
//! |                          Reference ID                         |
//! |                   Reference Timestamp (64)                    |
//! |                      Origin Timestamp (64)                    |
//! |                      Receive Timestamp (64)                   |
//! |                      Transmit Timestamp (64)                  |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! ```
//!
//! Everything is big-endian. Header is 48 bytes, NTS adds extension fields after it

use std::fmt;

use crate::time::NtpTimestamp;

pub const HEADER_LEN: usize = 48;
pub const NTP_VERSION: u8 = 4;

/// Warns of an upcoming leap second or that the server itself is not synchronized
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LeapIndicator {
    NoWarning,
    LastMinute61,
    LastMinute59,
    Unsynchronized,
}

impl LeapIndicator {
    fn from_bits(bits: u8) -> Self {
        match bits & 0b11 {
            0 => Self::NoWarning,
            1 => Self::LastMinute61,
            2 => Self::LastMinute59,
            _ => Self::Unsynchronized,
        }
    }

    fn to_bits(self) -> u8 {
        match self {
            Self::NoWarning => 0,
            Self::LastMinute61 => 1,
            Self::LastMinute59 => 2,
            Self::Unsynchronized => 3,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    Reserved,
    SymmetricActive,
    SymmetricPassive,
    Client,
    Server,
    Broadcast,
    Control,
    Private,
}

impl Mode {
    fn from_bits(bits: u8) -> Self {
        match bits & 0b111 {
            0 => Self::Reserved,
            1 => Self::SymmetricActive,
            2 => Self::SymmetricPassive,
            3 => Self::Client,
            4 => Self::Server,
            5 => Self::Broadcast,
            6 => Self::Control,
            _ => Self::Private,
        }
    }

    fn to_bits(self) -> u8 {
        match self {
            Self::Reserved => 0,
            Self::SymmetricActive => 1,
            Self::SymmetricPassive => 2,
            Self::Client => 3,
            Self::Server => 4,
            Self::Broadcast => 5,
            Self::Control => 6,
            Self::Private => 7,
        }
    }
}

/// Used for root delay and root dispersion
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct NtpShort(pub u32);

impl NtpShort {
    pub fn as_secs_f64(self) -> f64 {
        self.0 as f64 / 65536.0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ReferenceId(pub [u8; 4]);

impl ReferenceId {
    pub fn ascii(&self) -> String {
        self.0
            .iter()
            .take_while(|&&b| b != 0)
            .map(|&b| if b.is_ascii_graphic() { b as char } else { '?' })
            .collect()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NtpPacket {
    pub leap: LeapIndicator,
    pub version: u8,
    pub mode: Mode,
    pub stratum: u8,
    /// Max poll interval in seconds
    pub poll: i8,
    /// Server clock's precision in seconds
    pub precision: i8,
    pub root_delay: NtpShort,
    pub root_dispersion: NtpShort,
    pub reference_id: ReferenceId,
    pub reference_ts: NtpTimestamp,
    pub origin_ts: NtpTimestamp,
    pub receive_ts: NtpTimestamp,
    pub transmit_ts: NtpTimestamp,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DecodeError {
    TooShort(usize),
}

impl fmt::Display for DecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooShort(n) => write!(f, "packet too short: {n} bytes, need {HEADER_LEN}"),
        }
    }
}

impl std::error::Error for DecodeError {}

impl NtpPacket {
    pub fn client_request(transmit_ts: NtpTimestamp) -> Self {
        Self {
            leap: LeapIndicator::NoWarning,
            version: NTP_VERSION,
            mode: Mode::Client,
            stratum: 0,
            poll: 0,
            precision: 0,
            root_delay: NtpShort(0),
            root_dispersion: NtpShort(0),
            reference_id: ReferenceId([0; 4]),
            reference_ts: NtpTimestamp::ZERO,
            origin_ts: NtpTimestamp::ZERO,
            receive_ts: NtpTimestamp::ZERO,
            transmit_ts,
        }
    }

    pub fn encode(&self) -> [u8; HEADER_LEN] {
        let mut buf = [0u8; HEADER_LEN];
        buf[0] = (self.leap.to_bits() << 6) | ((self.version & 0b111) << 3) | self.mode.to_bits();
        buf[1] = self.stratum;
        buf[2] = self.poll as u8;
        buf[3] = self.precision as u8;
        buf[4..8].copy_from_slice(&self.root_delay.0.to_be_bytes());
        buf[8..12].copy_from_slice(&self.root_dispersion.0.to_be_bytes());
        buf[12..16].copy_from_slice(&self.reference_id.0);
        buf[16..24].copy_from_slice(&self.reference_ts.0.to_be_bytes());
        buf[24..32].copy_from_slice(&self.origin_ts.0.to_be_bytes());
        buf[32..40].copy_from_slice(&self.receive_ts.0.to_be_bytes());
        buf[40..48].copy_from_slice(&self.transmit_ts.0.to_be_bytes());
        buf
    }

    /// Parses the 48-byte header
    pub fn decode(buf: &[u8]) -> Result<Self, DecodeError> {
        if buf.len() < HEADER_LEN {
            return Err(DecodeError::TooShort(buf.len()));
        }
        let u32_at = |i: usize| u32::from_be_bytes(buf[i..i + 4].try_into().unwrap());
        let u64_at = |i: usize| u64::from_be_bytes(buf[i..i + 8].try_into().unwrap());
        Ok(Self {
            leap: LeapIndicator::from_bits(buf[0] >> 6),
            version: (buf[0] >> 3) & 0b111,
            mode: Mode::from_bits(buf[0]),
            stratum: buf[1],
            poll: buf[2] as i8,
            precision: buf[3] as i8,
            root_delay: NtpShort(u32_at(4)),
            root_dispersion: NtpShort(u32_at(8)),
            reference_id: ReferenceId(buf[12..16].try_into().unwrap()),
            reference_ts: NtpTimestamp(u64_at(16)),
            origin_ts: NtpTimestamp(u64_at(24)),
            receive_ts: NtpTimestamp(u64_at(32)),
            transmit_ts: NtpTimestamp(u64_at(40)),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn client_request_first_byte() {
        // LI=0, VN=4, Mode=3 -> 0b00_100_011 = 0x23
        let pkt = NtpPacket::client_request(NtpTimestamp(0x1122334455667788));
        let buf = pkt.encode();
        assert_eq!(buf[0], 0x23);
        assert_eq!(
            &buf[40..48],
            &[0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88]
        );
        assert!(buf[1..40].iter().all(|&b| b == 0));
    }

    #[test]
    fn roundtrip() {
        let pkt = NtpPacket {
            leap: LeapIndicator::LastMinute61,
            version: 4,
            mode: Mode::Server,
            stratum: 3,
            poll: 6,
            precision: -24,
            root_delay: NtpShort(0x0001_8000),
            root_dispersion: NtpShort(42),
            reference_id: ReferenceId(*b"GPS\0"),
            reference_ts: NtpTimestamp(1),
            origin_ts: NtpTimestamp(2),
            receive_ts: NtpTimestamp(3),
            transmit_ts: NtpTimestamp(u64::MAX),
        };
        assert_eq!(NtpPacket::decode(&pkt.encode()).unwrap(), pkt);
        assert_eq!(pkt.root_delay.as_secs_f64(), 1.5);
        assert_eq!(pkt.reference_id.ascii(), "GPS");
    }

    #[test]
    fn decode_ignores_extension_fields_but_rejects_short() {
        let mut buf = NtpPacket::client_request(NtpTimestamp(7)).encode().to_vec();
        buf.extend_from_slice(&[0xAA; 16]);
        assert_eq!(
            NtpPacket::decode(&buf).unwrap().transmit_ts,
            NtpTimestamp(7)
        );
        assert_eq!(
            NtpPacket::decode(&buf[..47]),
            Err(DecodeError::TooShort(47))
        );
    }
}
