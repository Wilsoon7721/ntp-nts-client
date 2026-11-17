<p align="center">
  <img src="assets/logo.png" alt="NTS Client logo" width="128">
</p>

<h1 align="center">NTS Client</h1>

<p align="center">
  Keeps the Windows clock in sync using <b>NTS</b> (Network Time Security), so nobody on the network can fake the time.
</p>

> [!NOTE]
> **This is a low-priority project.** NTP and NTS are stable, well-established protocols, so the app isn't expected to change much. Ideas and bug reports are welcome and will be read, but may not be implemented. Feel free to fork it and implement your own features.

> [!IMPORTANT]
> The installer is not code-signed (costs about $10/mo for me), so Windows SmartScreen may warn you. Choose **More info → Run anyway** to proceed. Each release comes with a `.sha256` file if you'd like to check the download.

## Why

By default, Windows syncs its clock with plain NTP, whose replies aren't signed. Anyone between you and the time server (your Wi-Fi, your ISP, or a hijacked route) can send a fake time, and a wrong clock breaks HTTPS certificate checks, two-factor codes and file timestamps.

[NTS (RFC 8915)](https://www.rfc-editor.org/rfc/rfc8915) fixes this by allowing the client and server to agree on keys over TLS, which allows every reply from the server to be authenticated. NTS Client replaces the Windows Time service with one that speaks NTS.

## Features

- A **background service** that keeps the clock in sync
- A **tray app** showing the time, sync status (offset, delay, drift) and settings
- **Built-in NTS servers** such as Cloudflare, Netnod, PTB, SIDN Labs, NIC.br and System76 are added by default, with plain NTP and custom servers available after a warning is displayed. Custom servers will try NTS first before falling back to NTP.
- **Time zone picker** with Windows' automatic time zone capability
- **Start with Windows** and **updates** from GitHub Releases

## Install

Download `nts-client-setup-X.Y.Z.exe` from the [latest release](https://github.com/Wilsoon7721/ntp-nts-client/releases/latest) and run it. This requires 64-bit Windows 10 or 11.

A Windows SmartScreen warning will likely show up as the installer is not code-signed. To proceed, click on **More info** and then **Run anyway**.

### What Changes After Installing

- The programs (`nts-tray.exe` and `nts-client.exe`) are installed to `C:\Program Files\nts-client` by default. Do avoid placing it in your Windows user folder as the service may not have enough permissions to run.
- Adds the **NTS Client** service which starts with Windows and runs as `LOCAL SERVICE`.
- Disables the default **Windows Time Service** (w32time) to prevent the service from clashing with the clock time. Uninstalling the application sets the service back.
- Opens the tray app when you sign in (can be disabled in-app)
- Keeps its settings and program log in `C:\ProgramData\nts-client` (see `sync.log`)

Uninstall from **Settings → Apps**.

## Command Line Usage

`nts-client.exe` can also check servers directly:

```powershell
nts-client time.cloudflare.com --nts      # measure the offset over NTS
nts-client nts.netnod.se --nts-ke         # show what NTS key exchange negotiates
nts-client pool.ntp.org                   # plain NTP, for comparison
```

From an administrator terminal, `--nts --set` steps the clock once and
`--sync` keeps it in sync in the foreground. Run `nts-client --help` for every option.

## Security

- Plain NTP needs explicit consent in the tray. Custom servers can only be set from an **administrator account**.
- The tray talks to the service over a local named pipe that remote machines can't access.
- NTS certificates are checked against Windows' own certificate store.
- Updates are only installed if the download matches the SHA-256 that GitHub records for the release file

## Building

Requires Windows and stable Rust.

```powershell
cargo build --release
cargo test
```

`scripts\release.ps1` builds the installer, and needs [Inno Setup 6](https://jrsoftware.org/isdl.php) and `cargo install --locked --features cli cargo-about`. Local builds don't update themselves.

## License

[MIT](LICENSE)
