use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Protocol {
    /// NTS-KE on port 4460, then authenticated NTP
    Nts,
    /// Plain NTP on port 123: anyone on the network path can forge replies
    Ntp,
}

impl Protocol {
    pub fn label(self) -> &'static str {
        match self {
            Self::Nts => "NTS",
            Self::Ntp => "NTP",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Server {
    /// Stable id stored in the config and sent over the pipe
    pub id: &'static str,
    pub name: &'static str,
    pub host: &'static str,
    pub protocol: Protocol,
}

pub const DEFAULT_ID: &str = "cloudflare";

pub const SERVERS: &[Server] = &[
    Server {
        id: "cloudflare",
        name: "Cloudflare (anycast, worldwide)",
        host: "time.cloudflare.com",
        protocol: Protocol::Nts,
    },
    Server {
        id: "netnod",
        name: "Netnod (Sweden)",
        host: "nts.netnod.se",
        protocol: Protocol::Nts,
    },
    Server {
        id: "ptb",
        name: "PTB (Germany)",
        host: "ptbtime1.ptb.de",
        protocol: Protocol::Nts,
    },
    Server {
        id: "sidn",
        name: "SIDN Labs (Netherlands)",
        host: "ntppool1.time.nl",
        protocol: Protocol::Nts,
    },
    Server {
        id: "nicbr",
        name: "NIC.br (Brazil)",
        host: "a.st1.ntp.br",
        protocol: Protocol::Nts,
    },
    Server {
        id: "system76",
        name: "System76 (US East)",
        host: "virginia.time.system76.com",
        protocol: Protocol::Nts,
    },
    Server {
        id: "pool",
        name: "NTP Pool (volunteers, worldwide)",
        host: "pool.ntp.org",
        protocol: Protocol::Ntp,
    },
    Server {
        id: "windows",
        name: "Microsoft",
        host: "time.windows.com",
        protocol: Protocol::Ntp,
    },
    Server {
        id: "google",
        name: "Google (smears leap seconds)",
        host: "time.google.com",
        protocol: Protocol::Ntp,
    },
    Server {
        id: "nist",
        name: "NIST (US)",
        host: "time.nist.gov",
        protocol: Protocol::Ntp,
    },
];

pub fn find(id: &str) -> Option<&'static Server> {
    SERVERS.iter().find(|s| s.id == id)
}

pub fn default_server() -> &'static Server {
    find(DEFAULT_ID).expect("default server is in the list")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ids_are_unique_and_default_exists() {
        for (i, a) in SERVERS.iter().enumerate() {
            assert!(SERVERS[i + 1..].iter().all(|b| b.id != a.id), "{}", a.id);
        }
        assert_eq!(default_server().protocol, Protocol::Nts);
    }
}
