# Builds the release exes and the installer into dist\.
#   .\scripts\release.ps1
# .github/workflows/release.yml runs this for tagged releases, with the
# NTSCLIENT_* variables build.rs stamps in. Run locally, the version comes
# from Cargo.toml and the build won't update itself (no NTSCLIENT_REPO).
$ErrorActionPreference = 'Stop'
$root = Split-Path $PSScriptRoot
$manifest = Join-Path $root 'Cargo.toml'

$version = $env:NTSCLIENT_VERSION
if (-not $version) {
    $version = (Select-String -Path $manifest -Pattern '^version\s*=\s*"(\d+\.\d+\.\d+)"').Matches[0].Groups[1].Value
}
if ($version -notmatch '^\d+\.\d+\.\d+$') { throw "Not a plain x.y.z version: $version" }

cargo build --release --locked --manifest-path $manifest
if ($LASTEXITCODE) { throw 'cargo build failed' }

# Licenses of everything compiled in, shipped next to the exes
if (-not (Get-Command cargo-about -ErrorAction SilentlyContinue)) {
    throw 'cargo-about not found; install it with: cargo install --locked --features cli cargo-about'
}
Push-Location $root
try {
    cargo about generate --fail installer\notices.hbs -o target\THIRD-PARTY-NOTICES.txt
    if ($LASTEXITCODE) { throw 'cargo about failed (a dependency may use a license not accepted in about.toml)' }
} finally {
    Pop-Location
}

$iscc = @(
    "${env:ProgramFiles(x86)}\Inno Setup 6\ISCC.exe",
    "$env:ProgramFiles\Inno Setup 6\ISCC.exe",
    "$env:LOCALAPPDATA\Programs\Inno Setup 6\ISCC.exe"
) | Where-Object { Test-Path $_ } | Select-Object -First 1
if (-not $iscc) { throw 'Inno Setup 6 not found; install it from https://jrsoftware.org/isdl.php' }

& $iscc /Q "/DVersion=$version" (Join-Path $root 'installer\nts-client.iss')
if ($LASTEXITCODE) { throw 'ISCC failed' }

Write-Host "Built $(Join-Path $root "dist\nts-client-setup-$version.exe")"
