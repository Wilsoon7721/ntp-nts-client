use std::fs;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::servers::{self, Protocol};
use crate::sync::Source;

/// `Config::server` when a custom server is selected
pub const CUSTOM_ID: &str = "custom";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Config {
    /// An id from [`servers::SERVERS`], or [`CUSTOM_ID`]
    pub server: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub custom: Option<CustomServer>,
}

/// A server the user typed in, and the protocol it was found to speak
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CustomServer {
    pub host: String,
    pub protocol: Protocol,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            server: servers::DEFAULT_ID.into(),
            custom: None,
        }
    }
}

impl Config {
    /// The saved settings, or the defaults if the file is missing or unreadable
    pub fn load() -> Self {
        fs::read_to_string(path())
            .ok()
            .and_then(|s| serde_json::from_str::<Config>(&s).ok())
            .filter(Config::is_valid)
            .unwrap_or_default()
    }

    pub fn save(&self) -> Result<(), String> {
        fs::create_dir_all(data_dir()).map_err(|e| e.to_string())?;
        let json = serde_json::to_string_pretty(self).map_err(|e| e.to_string())?;
        fs::write(path(), json).map_err(|e| format!("could not save {}: {e}", path().display()))
    }

    fn is_valid(&self) -> bool {
        match self.server.as_str() {
            CUSTOM_ID => self.custom.as_ref().is_some_and(|c| valid_host(&c.host)),
            id => servers::find(id).is_some(),
        }
    }

    /// What the sync loop should use
    pub fn source(&self) -> Source {
        if self.server == CUSTOM_ID
            && let Some(c) = &self.custom
        {
            return Source {
                host: c.host.clone(),
                protocol: c.protocol,
            };
        }
        let server = servers::find(&self.server).unwrap_or_else(servers::default_server);
        Source {
            host: server.host.into(),
            protocol: server.protocol,
        }
    }
}

/// Looks like a hostname, IPv4 or IPv6 address, optionally with a port
pub fn valid_host(host: &str) -> bool {
    !host.is_empty()
        && host.len() <= 260
        && host
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || ".-_:[]".contains(c))
}

/// `%ProgramData%\nts-client`, also where the service log goes
pub fn data_dir() -> PathBuf {
    std::env::var_os("ProgramData")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(r"C:\ProgramData"))
        .join("nts-client")
}

fn path() -> PathBuf {
    data_dir().join("config.json")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn custom_source_and_validation() {
        let c = Config {
            server: CUSTOM_ID.into(),
            custom: Some(CustomServer {
                host: "192.168.1.10".into(),
                protocol: Protocol::Ntp,
            }),
        };
        assert!(c.is_valid());
        assert_eq!(c.source().host, "192.168.1.10");
        assert_eq!(c.source().protocol, Protocol::Ntp);

        let missing = Config {
            server: CUSTOM_ID.into(),
            custom: None,
        };
        assert!(!missing.is_valid());
        assert!(valid_host("[2606:4700:f1::1]:123"));
        assert!(!valid_host("evil host; rm"));
        assert!(!valid_host(""));
    }

    #[test]
    fn old_config_files_still_load() {
        // Saved by the previous version, before custom servers
        let c: Config = serde_json::from_str(r#"{"server":"ptb"}"#).unwrap();
        assert!(c.is_valid());
        assert_eq!(c.source().host, "ptbtime1.ptb.de");
    }
}
