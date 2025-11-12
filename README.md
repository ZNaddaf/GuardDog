# GuardDog
Read-only baseline security checks for Windows 10/11. Runs from a mounted ISO on a generic USB. No admin. No network. Saves one HTML report to the USB.

## Quick start
1) Full-format a USB as exFAT.
2) Copy `guarddog.iso`, `README_START_HERE.html`, `SHA256SUMS`, `SHA256SUMS.sig` to the USB, plus an empty `reports/` folder.
3) Double-click `guarddog.iso` to mount. Run `GuardDog.exe`.
4) Click **Verify**. If PASS, click **Run Baseline Checks**.
5) Report opens and is saved to `\reports\YYYY-MM-DD_HH-MM-SSZ_HOST\report.html`.

## Scope
- Windows-only, non-admin MVP.
- Read-only system inspection. No registry or system changes.
- Offline. No network access.

## Integrity
- Verify outer `SHA256SUMS` with `SHA256SUMS.sig`.
- App verifies an inner `manifest.json` signed with `manifest.sig`.

## Privacy
- Report contains host name and local Administrators list.
- No user files, tokens, or browsing data collected.

## Build (high-level)
- Build `GuardDog.exe` and `verifier.exe`.
- Generate `manifest.json` and `manifest.sig`.
- Package ISO.
- Produce `SHA256SUMS` and `SHA256SUMS.sig`.

See `/docs` for detailed guides.
