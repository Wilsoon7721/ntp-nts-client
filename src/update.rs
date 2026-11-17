//! Updates from GitHub Releases.
//!
//! GitHub lists a SHA-256 `digest` for every release file, and the download
//! must match it before it's run. That catches corrupt or swapped downloads;
//! it relies on the GitHub account itself being kept secure.

use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::Duration;

use ring::digest::{digest, SHA256};
use serde::Deserialize;
use ureq::tls::{RootCerts, TlsConfig};
use windows_sys::Win32::Foundation::ERROR_CANCELLED;
use windows_sys::Win32::UI::Shell::{SHELLEXECUTEINFOW, ShellExecuteExW};
use windows_sys::Win32::UI::WindowsAndMessaging::SW_SHOWNORMAL;

/// `owner/name` of the GitHub repository releases come from. Stamped by
/// build.rs in release builds only, so local builds never update themselves.
pub const REPO: &str = env!("NTS_REPO");
/// Short commit this was built from, or "dev"
pub const COMMIT: &str = env!("NTS_COMMIT");

/// False in local builds, which have no repository to update from
pub fn enabled() -> bool {
    !REPO.is_empty()
}

const MAX_INSTALLER_BYTES: u64 = 100 * 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Version(pub u64, pub u64, pub u64);

impl Version {
    /// `1.2.3` or `v1.2.3`; anything else (e.g. `1.2.3-beta`) is rejected
    pub fn parse(s: &str) -> Option<Self> {
        let mut parts = s.strip_prefix('v').unwrap_or(s).split('.');
        let mut next = || parts.next()?.parse().ok();
        let v = Version(next()?, next()?, next()?);
        parts.next().is_none().then_some(v)
    }

    pub fn current() -> Self {
        Self::parse(env!("NTS_VERSION")).expect("build.rs stamps a plain x.y.z version")
    }
}

impl fmt::Display for Version {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{}.{}", self.0, self.1, self.2)
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct Release {
    pub version: Version,
    /// The release page, for "What's new"
    pub page_url: String,
    installer_name: String,
    installer_url: String,
    /// Lowercase hex, from GitHub
    sha256: String,
}

/// What GitHub's API returns, the parts we use
#[derive(Deserialize)]
struct GhRelease {
    tag_name: String,
    html_url: String,
    #[serde(default)]
    assets: Vec<GhAsset>,
}

#[derive(Deserialize)]
struct GhAsset {
    name: String,
    browser_download_url: String,
    /// `sha256:<hex>`; GitHub adds it to every file uploaded since mid-2025
    #[serde(default)]
    digest: Option<String>,
}

fn sha256_hex(bytes: &[u8]) -> String {
    digest(&SHA256, bytes)
        .as_ref()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

pub fn installer_name(version: Version) -> String {
    format!("nts-client-setup-{version}.exe")
}

fn agent(timeout: Duration) -> ureq::Agent {
    ureq::Agent::config_builder()
        // Windows' certificate store, which Windows Update keeps current
        .tls_config(TlsConfig::builder().root_certs(RootCerts::PlatformVerifier).build())
        .timeout_global(Some(timeout))
        .user_agent(format!("nts-client-updater/{}", env!("NTS_VERSION")))
        .build()
        .new_agent()
}

/// The latest release, if it's newer than this build
pub fn check() -> Result<Option<Release>, String> {
    if !enabled() {
        return Ok(None);
    }
    let url = format!("https://api.github.com/repos/{REPO}/releases/latest");
    let release: GhRelease = match agent(Duration::from_secs(30))
        .get(&url)
        .header("Accept", "application/vnd.github+json")
        .call()
    {
        Ok(mut response) => response.body_mut().read_json().map_err(|e| e.to_string())?,
        // No releases published yet
        Err(ureq::Error::StatusCode(404)) => return Ok(None),
        Err(e) => return Err(format!("could not reach GitHub: {e}")),
    };
    newer_release(release, Version::current())
}

fn newer_release(release: GhRelease, current: Version) -> Result<Option<Release>, String> {
    let version = Version::parse(&release.tag_name)
        .ok_or_else(|| format!("the latest release's tag {:?} isn't a version", release.tag_name))?;
    if version <= current {
        return Ok(None);
    }
    let name = installer_name(version);
    let asset = release
        .assets
        .iter()
        .find(|a| a.name == name)
        .ok_or_else(|| format!("release {version} is missing {name}"))?;
    let sha256 = asset
        .digest
        .as_deref()
        .and_then(|d| d.strip_prefix("sha256:"))
        .filter(|h| h.len() == 64 && h.bytes().all(|b| b.is_ascii_hexdigit()))
        .ok_or_else(|| format!("GitHub lists no SHA-256 for {name}"))?
        .to_ascii_lowercase();
    Ok(Some(Release {
        version,
        page_url: release.html_url,
        installer_url: asset.browser_download_url.clone(),
        sha256,
        installer_name: name,
    }))
}

/// Downloads the installer and checks it against GitHub's digest. Returns where it was saved.
pub fn download(release: &Release) -> Result<PathBuf, String> {
    let installer = agent(Duration::from_secs(600))
        .get(&release.installer_url)
        .call()
        .map_err(|e| format!("download failed: {e}"))?
        .body_mut()
        .with_config()
        .limit(MAX_INSTALLER_BYTES)
        .read_to_vec()
        .map_err(|e| format!("download failed: {e}"))?;
    verify(&release.sha256, &installer)?;

    let dir = std::env::temp_dir().join("nts-client-update");
    fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    let path = dir.join(&release.installer_name);
    fs::write(&path, &installer).map_err(|e| format!("could not save the installer: {e}"))?;
    Ok(path)
}

fn verify(expected_sha256: &str, installer: &[u8]) -> Result<(), String> {
    let actual = sha256_hex(installer);
    if actual != expected_sha256 {
        return Err(format!(
            "the download doesn't match the release (SHA-256 {actual}, expected \
             {expected_sha256}), so it wasn't run"
        ));
    }
    Ok(())
}

/// Starts the installer silently (it shows progress only) behind a Windows
/// admin prompt, without waiting. It stops the tray and service, replaces
/// them, then starts both again.
pub fn run_installer(path: &Path) -> Result<(), String> {
    let wide = |s: &str| s.encode_utf16().chain([0]).collect::<Vec<u16>>();
    let (verb, file) = (wide("runas"), wide(&path.to_string_lossy()));
    let params = wide("/SILENT /SUPPRESSMSGBOXES /NORESTART");
    unsafe {
        let mut info: SHELLEXECUTEINFOW = std::mem::zeroed();
        info.cbSize = size_of::<SHELLEXECUTEINFOW>() as u32;
        info.lpVerb = verb.as_ptr();
        info.lpFile = file.as_ptr();
        info.lpParameters = params.as_ptr();
        info.nShow = SW_SHOWNORMAL;
        if ShellExecuteExW(&mut info) == 0 {
            let e = std::io::Error::last_os_error();
            return Err(if e.raw_os_error() == Some(ERROR_CANCELLED as i32) {
                "Cancelled at the Windows prompt.".into()
            } else {
                format!("could not start the installer: {e}")
            });
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const DIGEST: &str = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";

    #[test]
    fn versions() {
        assert_eq!(Version::parse("v1.2.3"), Some(Version(1, 2, 3)));
        assert_eq!(Version::parse("1.10.0"), Some(Version(1, 10, 0)));
        assert!(Version(1, 10, 0) > Version(1, 9, 9));
        for bad in ["1.2", "1.2.3.4", "v1.2.3-beta", "", "x.y.z"] {
            assert_eq!(Version::parse(bad), None, "{bad}");
        }
        Version::current();
    }

    #[test]
    #[ignore = "needs internet; run with --ignored"]
    fn live_check_reaches_github() {
        // Run with NTSCLIENT_REPO=Wilsoon7721/ntp-nts-client set, or this checks nothing.
        // Until the repository has a release it's Ok(None) (GitHub answers 404).
        check().unwrap();
    }

    fn release(tag: &str, assets: &[(&str, Option<String>)]) -> GhRelease {
        GhRelease {
            tag_name: tag.into(),
            html_url: "https://example.invalid/release".into(),
            assets: assets
                .iter()
                .map(|(n, digest)| GhAsset {
                    name: n.to_string(),
                    browser_download_url: format!("https://example.invalid/{n}"),
                    digest: digest.clone(),
                })
                .collect(),
        }
    }

    #[test]
    fn picks_only_newer_releases_with_a_digest() {
        let current = Version(1, 0, 0);
        let setup = "nts-client-setup-1.1.0.exe";
        let with_digest = [(setup, Some(format!("sha256:{}", DIGEST.to_uppercase())))];
        let r = newer_release(release("v1.1.0", &with_digest), current).unwrap().unwrap();
        assert_eq!(r.version, Version(1, 1, 0));
        assert!(r.installer_url.ends_with(setup));
        assert_eq!(r.sha256, DIGEST);

        assert_eq!(newer_release(release("v1.0.0", &[]), current).unwrap(), None);
        assert!(newer_release(release("v1.1.0", &[]), current).is_err());
        assert!(newer_release(release("v1.1.0", &[(setup, None)]), current).is_err());
        assert!(newer_release(release("latest", &with_digest), current).is_err());
    }

    #[test]
    fn download_must_match_digest() {
        assert_eq!(sha256_hex(b"abc"), DIGEST); // as sha256sum prints it
        assert!(verify(DIGEST, b"abc").is_ok());
        assert!(verify(DIGEST, b"abd").is_err());
    }
}
