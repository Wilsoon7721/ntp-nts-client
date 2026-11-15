//! NTS-protected NTP
//! A normal 48-byte NTP header followed by extension fields:
//! ```text
//! request:  header | Unique ID | Cookie | Placeholder* | Authenticator
//! reply:    header | Unique ID | Authenticator{ encrypted: New Cookie* }
//! ```
//! The Authenticator holds an AES-SIV tag over everything before it (the associated data), so the header and timestamps can't be tampered with.
//! Extension field: `| Type (16) | Length (16) | Value + padding to 4 bytes |`

use std::fmt;

use aes_siv::aead::{Aead, KeyInit, Payload};
use aes_siv::Aes128SivAead;

use crate::client::{ClientError, Protection};
use crate::nts_ke::NtsKeys;
use crate::packet::{NtpPacket, HEADER_LEN};

pub mod ef_type {
    pub const UNIQUE_IDENTIFIER: u16 = 0x0104;
    pub const NTS_COOKIE: u16 = 0x0204;
    pub const NTS_COOKIE_PLACEHOLDER: u16 = 0x0304;
    pub const NTS_AUTHENTICATOR: u16 = 0x0404;
}
use ef_type::*;

pub const UID_LEN: usize = 32;
/// AES-SIV is nonce-misuse resistant, but RFC 5297 recommends >= 16 random bytes
const NONCE_LEN: usize = 16;
/// Keep this many cookies, like the 8 NTS-KE hands out
const WANT_COOKIES: usize = 8;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NtsError {
    Malformed(&'static str),
    UniqueIdMismatch,
    MissingAuthenticator,
    AuthenticationFailed,
    /// Server couldn't decrypt our cookie, redo NTS-KE
    Nak,
    NoCookies,
    BadKey,
    Rng,
}

impl fmt::Display for NtsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Malformed(why) => write!(f, "malformed NTS reply: {why}"),
            Self::UniqueIdMismatch => write!(f, "reply's Unique Identifier doesn't match ours"),
            Self::MissingAuthenticator => write!(f, "reply has no NTS Authenticator"),
            Self::AuthenticationFailed => write!(f, "reply failed AEAD authentication"),
            Self::Nak => write!(f, "server sent NTS NAK (cookie rejected), redo NTS-KE"),
            Self::NoCookies => write!(f, "out of cookies, redo NTS-KE"),
            Self::BadKey => write!(f, "invalid AEAD key length"),
            Self::Rng => write!(f, "system random number generator failed"),
        }
    }
}

impl std::error::Error for NtsError {}

/// Cryptographically secure random bytes from the OS (via the rustls ring provider)
pub fn random_bytes<const N: usize>() -> Result<[u8; N], NtsError> {
    let mut buf = [0u8; N];
    rustls::crypto::ring::default_provider()
        .secure_random
        .fill(&mut buf)
        .map_err(|_| NtsError::Rng)?;
    Ok(buf)
}

fn push_ef(out: &mut Vec<u8>, kind: u16, value: &[u8]) {
    let padded = value.len().next_multiple_of(4);
    out.extend_from_slice(&kind.to_be_bytes());
    out.extend_from_slice(&((4 + padded) as u16).to_be_bytes());
    out.extend_from_slice(value);
    out.resize(out.len() + padded - value.len(), 0);
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Ef<'a> {
    kind: u16,
    /// Includes any padding
    value: &'a [u8],
    /// Where this field starts in the buffer
    offset: usize,
}

fn parse_efs(buf: &[u8], start: usize) -> Result<Vec<Ef<'_>>, NtsError> {
    let mut efs = Vec::new();
    let mut pos = start;
    while pos < buf.len() {
        let header = buf
            .get(pos..pos + 4)
            .ok_or(NtsError::Malformed("truncated extension field header"))?;
        let kind = u16::from_be_bytes([header[0], header[1]]);
        let len = u16::from_be_bytes([header[2], header[3]]) as usize;
        if len < 4 || !len.is_multiple_of(4) {
            return Err(NtsError::Malformed("bad extension field length"));
        }
        let value = buf
            .get(pos + 4..pos + len)
            .ok_or(NtsError::Malformed("extension field overruns packet"))?;
        efs.push(Ef {
            kind,
            value,
            offset: pos,
        });
        pos += len;
    }
    Ok(efs)
}

fn cipher(key: &[u8]) -> Result<Aes128SivAead, NtsError> {
    Aes128SivAead::new_from_slice(key).map_err(|_| NtsError::BadKey)
}

/// Authenticator body: `| Nonce Len | Ciphertext Len | Nonce (padded) | Ciphertext (padded) |`
fn seal(key: &[u8], aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, NtsError> {
    let nonce: [u8; NONCE_LEN] = random_bytes()?;
    let ct = cipher(key)?
        .encrypt(
            (&nonce).into(),
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|_| NtsError::AuthenticationFailed)?;
    let mut body = Vec::new();
    body.extend_from_slice(&(NONCE_LEN as u16).to_be_bytes());
    body.extend_from_slice(&(ct.len() as u16).to_be_bytes());
    body.extend_from_slice(&nonce);
    body.extend_from_slice(&ct);
    body.resize(body.len().next_multiple_of(4), 0);
    Ok(body)
}

fn open(key: &[u8], aad: &[u8], body: &[u8]) -> Result<Vec<u8>, NtsError> {
    let short = NtsError::Malformed("truncated authenticator");
    let nonce_len = u16::from_be_bytes(body.get(0..2).ok_or(short.clone())?.try_into().unwrap());
    let ct_len = u16::from_be_bytes(body.get(2..4).ok_or(short.clone())?.try_into().unwrap());
    let nonce = body.get(4..4 + nonce_len as usize).ok_or(short.clone())?;
    let ct_start = 4 + (nonce_len as usize).next_multiple_of(4);
    let ct = body
        .get(ct_start..ct_start + ct_len as usize)
        .ok_or(short)?;
    if nonce.len() != NONCE_LEN {
        return Err(NtsError::Malformed("unsupported nonce length"));
    }
    cipher(key)?
        .decrypt(nonce.try_into().unwrap(), Payload { msg: ct, aad })
        .map_err(|_| NtsError::AuthenticationFailed)
}

/// Appends NTS fields to a 48-byte header and return the packet and our Unique ID.
pub fn build_request(
    header: &[u8; HEADER_LEN],
    cookie: &[u8],
    placeholders: usize,
    c2s: &[u8],
) -> Result<(Vec<u8>, [u8; UID_LEN]), NtsError> {
    let uid: [u8; UID_LEN] = random_bytes()?;
    let mut pkt = header.to_vec();
    push_ef(&mut pkt, UNIQUE_IDENTIFIER, &uid);
    push_ef(&mut pkt, NTS_COOKIE, cookie);
    // Placeholders ask for extra cookies and keep the request as big as the
    // reply, so NTS can't be used for traffic amplification
    let zeros = vec![0u8; cookie.len()];
    for _ in 0..placeholders {
        push_ef(&mut pkt, NTS_COOKIE_PLACEHOLDER, &zeros);
    }
    let auth = seal(c2s, &pkt, &[])?;
    push_ef(&mut pkt, NTS_AUTHENTICATOR, &auth);
    Ok((pkt, uid))
}

fn has_uid(efs: &[Ef], uid: &[u8; UID_LEN]) -> Option<usize> {
    efs.iter()
        .find(|ef| ef.kind == UNIQUE_IDENTIFIER && ef.value == uid)
        .map(|ef| ef.offset)
}

/// Checks the reply is ours and authentic - returns the fresh cookies inside it.
pub fn verify_reply(raw: &[u8], uid: &[u8; UID_LEN], s2c: &[u8]) -> Result<Vec<Vec<u8>>, NtsError> {
    let efs = parse_efs(raw, HEADER_LEN)?;
    let uid_at = has_uid(&efs, uid).ok_or(NtsError::UniqueIdMismatch)?;
    let auth = efs
        .iter()
        .find(|ef| ef.kind == NTS_AUTHENTICATOR)
        .ok_or(NtsError::MissingAuthenticator)?;
    if uid_at > auth.offset {
        // The UID must be covered by the authenticator
        return Err(NtsError::UniqueIdMismatch);
    }
    let plaintext = open(s2c, &raw[..auth.offset], auth.value)?;
    Ok(parse_efs(&plaintext, 0)?
        .into_iter()
        .filter(|ef| ef.kind == NTS_COOKIE)
        .map(|ef| ef.value.to_vec())
        .collect())
}

/// NTS state across requests
pub struct NtsSession {
    keys: NtsKeys,
    pending_uid: Option<[u8; UID_LEN]>,
}

impl NtsSession {
    pub fn new(keys: NtsKeys) -> Self {
        Self {
            keys,
            pending_uid: None,
        }
    }

    pub fn cookies_left(&self) -> usize {
        self.keys.cookies.len()
    }
}

impl Protection for NtsSession {
    fn request(&mut self, header: &[u8; HEADER_LEN]) -> Result<Vec<u8>, ClientError> {
        // Each cookie is single-use so requests can't be linked together
        let cookie = self.keys.cookies.pop().ok_or(NtsError::NoCookies)?;
        let placeholders = WANT_COOKIES.saturating_sub(self.keys.cookies.len() + 1);
        let (pkt, uid) = build_request(header, &cookie, placeholders, &self.keys.c2s)?;
        self.pending_uid = Some(uid);
        Ok(pkt)
    }

    fn verify(&mut self, packet: &NtpPacket, raw: &[u8]) -> Result<(), ClientError> {
        let uid = self.pending_uid.ok_or(NtsError::UniqueIdMismatch)?;
        // NAK is an unauthenticated stratum-0 "NTSN" reply echoing our UID
        if packet.stratum == 0 && packet.reference_id.0 == *b"NTSN" {
            let efs = parse_efs(raw, HEADER_LEN)?;
            return Err(match has_uid(&efs, &uid) {
                Some(_) => NtsError::Nak,
                None => NtsError::UniqueIdMismatch,
            }
            .into());
        }
        let cookies = verify_reply(raw, &uid, &self.keys.s2c)?;
        self.pending_uid = None;
        self.keys.cookies.extend(cookies);
        self.keys.cookies.truncate(WANT_COOKIES);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::time::NtpTimestamp;

    const C2S: [u8; 32] = [1; 32];
    const S2C: [u8; 32] = [2; 32];

    fn header() -> [u8; HEADER_LEN] {
        NtpPacket::client_request(NtpTimestamp(42)).encode()
    }

    /// Plays the server: echo the UID, seal new cookies with the s2c key
    fn fake_reply(uid: &[u8], cookies: &[&[u8]]) -> Vec<u8> {
        let mut pkt = header().to_vec();
        push_ef(&mut pkt, UNIQUE_IDENTIFIER, uid);
        let mut plaintext = Vec::new();
        for c in cookies {
            push_ef(&mut plaintext, NTS_COOKIE, c);
        }
        let auth = seal(&S2C, &pkt, &plaintext).unwrap();
        push_ef(&mut pkt, NTS_AUTHENTICATOR, &auth);
        pkt
    }

    #[test]
    fn ef_padding() {
        let mut out = Vec::new();
        push_ef(&mut out, 0xABCD, &[1, 2, 3, 4, 5]);
        assert_eq!(out, [0xAB, 0xCD, 0x00, 0x0C, 1, 2, 3, 4, 5, 0, 0, 0]);
    }

    #[test]
    fn request_layout_and_server_can_verify() {
        let cookie = [7u8; 96];
        let (pkt, uid) = build_request(&header(), &cookie, 2, &C2S).unwrap();
        let efs = parse_efs(&pkt, HEADER_LEN).unwrap();
        let kinds: Vec<u16> = efs.iter().map(|e| e.kind).collect();
        assert_eq!(
            kinds,
            [
                UNIQUE_IDENTIFIER,
                NTS_COOKIE,
                NTS_COOKIE_PLACEHOLDER,
                NTS_COOKIE_PLACEHOLDER,
                NTS_AUTHENTICATOR
            ]
        );
        assert_eq!(efs[0].value, uid);
        assert_eq!(efs[1].value, cookie);
        assert!(efs[2].value.iter().all(|&b| b == 0) && efs[2].value.len() == 96);

        // The server opens it with the same (c2s) key, empty plaintext
        let auth = efs[4];
        assert_eq!(open(&C2S, &pkt[..auth.offset], auth.value).unwrap(), b"");
        assert!(open(&S2C, &pkt[..auth.offset], auth.value).is_err());
    }

    #[test]
    fn verify_good_reply_returns_cookies() {
        let uid = [9u8; UID_LEN];
        let reply = fake_reply(&uid, &[&[0xAA; 96], &[0xBB; 96]]);
        let cookies = verify_reply(&reply, &uid, &S2C).unwrap();
        assert_eq!(cookies, vec![vec![0xAA; 96], vec![0xBB; 96]]);
    }

    #[test]
    fn verify_rejects_tampering_wrong_uid_and_wrong_key() {
        let uid = [9u8; UID_LEN];
        let reply = fake_reply(&uid, &[&[0xAA; 96]]);

        // Flip a bit in the transmit timestamp, which is associated data
        let mut tampered = reply.clone();
        tampered[47] ^= 1;
        assert_eq!(
            verify_reply(&tampered, &uid, &S2C),
            Err(NtsError::AuthenticationFailed)
        );

        assert_eq!(
            verify_reply(&reply, &[8u8; UID_LEN], &S2C),
            Err(NtsError::UniqueIdMismatch)
        );
        assert_eq!(
            verify_reply(&reply, &uid, &C2S),
            Err(NtsError::AuthenticationFailed)
        );
        assert_eq!(
            verify_reply(&reply[..HEADER_LEN + 36], &uid, &S2C),
            Err(NtsError::MissingAuthenticator)
        );
    }

    #[test]
    fn session_cookie_accounting_and_nak() {
        let keys = NtsKeys {
            aead: crate::nts_ke::AEAD_AES_SIV_CMAC_256,
            c2s: C2S.to_vec(),
            s2c: S2C.to_vec(),
            cookies: vec![vec![1; 96]; 3],
            ntp_server: "x".into(),
            ntp_port: 123,
            tls_version: String::new(),
            cipher_suite: String::new(),
            peer: "127.0.0.1:4460".parse().unwrap(),
            timings: Default::default(),
        };
        let mut s = NtsSession::new(keys);

        // 3 cookies -> spend 1, ask for 8 - 2 - 1 = 5 placeholders
        let req = s.request(&header()).unwrap();
        let efs = parse_efs(&req, HEADER_LEN).unwrap();
        assert_eq!(
            efs.iter()
                .filter(|e| e.kind == NTS_COOKIE_PLACEHOLDER)
                .count(),
            5
        );
        assert_eq!(s.cookies_left(), 2);

        let uid: [u8; UID_LEN] = efs[0].value.try_into().unwrap();
        let reply = fake_reply(&uid, &[&[5u8; 96][..]; 6]);
        let pkt = NtpPacket::decode(&reply).unwrap();
        s.verify(&pkt, &reply).unwrap();
        assert_eq!(s.cookies_left(), 8);

        // NAK: stratum 0, "NTSN", echoes UID, no authenticator
        let req = s.request(&header()).unwrap();
        let efs = parse_efs(&req, HEADER_LEN).unwrap();
        let mut nak = header().to_vec();
        nak[1] = 0;
        nak[12..16].copy_from_slice(b"NTSN");
        push_ef(&mut nak, UNIQUE_IDENTIFIER, efs[0].value);
        let pkt = NtpPacket::decode(&nak).unwrap();
        assert!(matches!(
            s.verify(&pkt, &nak),
            Err(ClientError::Nts(NtsError::Nak))
        ));
    }
}
