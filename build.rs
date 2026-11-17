//! Embeds the icon and version info, and stamps each build with its version
//! and commit, and release builds with the repository they update from.

use std::path::Path;
use std::process::Command;

fn stamp(name: &str) -> Option<String> {
    println!("cargo:rerun-if-env-changed={name}");
    std::env::var(name).ok().filter(|value| !value.trim().is_empty())
}

fn local_commit() -> Option<String> {
    let output = Command::new("git").args(["rev-parse", "--short=7", "HEAD"]).output().ok()?;
    output.status.success().then(|| String::from_utf8_lossy(&output.stdout).trim().to_owned())
}

fn main() {
    println!("cargo:rerun-if-changed=assets/icon.ico");
    // A commit or checkout should show up without a clean build
    for file in [".git/HEAD", ".git/logs/HEAD"] {
        if Path::new(file).exists() {
            println!("cargo:rerun-if-changed={file}");
        }
    }

    let version = stamp("NTSCLIENT_VERSION").unwrap_or_else(|| env!("CARGO_PKG_VERSION").to_owned());
    let commit = stamp("NTSCLIENT_COMMIT").or_else(local_commit).unwrap_or_else(|| "dev".to_owned());
    // Only release builds name a repository, which is what lets them update themselves
    let repo = stamp("NTSCLIENT_REPO").unwrap_or_default();
    println!("cargo:rustc-env=NTS_VERSION={}", version.trim_start_matches('v'));
    println!("cargo:rustc-env=NTS_COMMIT={commit}");
    println!("cargo:rustc-env=NTS_REPO={repo}");

    // Icon (resource 1, which nts-tray also loads for the tray) and the
    // details Explorer and Task Manager show
    #[cfg(windows)]
    {
        let version = version.trim_start_matches('v');
        let mut parts = version.split('.').map(|p| p.parse::<u64>().unwrap_or(0));
        let mut next = || parts.next().unwrap_or(0);
        let packed = (next() << 48) | (next() << 32) | (next() << 16);
        winresource::WindowsResource::new()
            .set_icon("assets/icon.ico")
            .set("ProductName", "NTS Client")
            .set("FileDescription", "NTS Client")
            .set("ProductVersion", version)
            .set("FileVersion", version)
            .set_version_info(winresource::VersionInfo::PRODUCTVERSION, packed)
            .set_version_info(winresource::VersionInfo::FILEVERSION, packed)
            .compile()
            .expect("embed the icon and version info");
    }
}
