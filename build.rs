//! Stamps each build with its version and commit, and release builds with the
//! repository they update from.

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
}
