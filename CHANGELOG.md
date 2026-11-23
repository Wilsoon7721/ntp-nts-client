# Changelog

Each version's section here is also its GitHub release notes, and what the
tray's "What's new" link opens.

## 1.0.3

- Starting with Windows now opens NTS Client quietly in the tray, as intended,
  instead of showing its window and taking focus.

## 1.0.2

- **Automatic time zone now works on desktop PCs.** The tray works out your
  time zone from your location itself, instead of relying on Windows'
  automatic time zone, which often never changes anything on PCs without
  Wi-Fi. It checks again every hour, and needs no administrator prompt.
- Shows an error under the time zone when it can't be set automatically,
  for example when location access is off.
- "What's new" opens this changelog. Before, it did nothing.
- The "Selected" time zone line is easier to read and sits closer to the dropdown.

## 1.0.1

- Added an **Automatic** option to the time zone picker.
- Shows the time zone in use under the picker.
- Added a README.

## 1.0.0

First release.

- Keeps the Windows clock in sync over NTS, as a background service.
- Tray app with the time, sync status, server picker (NTS, NTP and custom
  servers), time zone picker and Start with Windows.
- Disables the Windows Time service so the two don't fight over the clock.
- Updates from GitHub Releases, checked against GitHub's SHA-256 for each installer.
