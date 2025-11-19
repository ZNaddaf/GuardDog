# GuardDog ISO Build (maintainers)

## Prereqs
- Windows ADK (Deployment Tools) installed → provides `oscdimg.exe`.
- `minisign.exe` on PATH.
- Your signing private key file path (minisign).

## Inputs (from repo)
- `build\GuardDog.exe` (or a placeholder for first run)
- `build\verifier.exe` (or a placeholder for first run)
- `packaging\signing\public.key`
- `report\report_template.html`
- `checks\checks_catalog.json`
- `docs\README_START_HERE.html`
- `LICENSE`

## Outputs
- `dist\guarddog.iso` (ISO with all runtime files)
- `dist\release\SHA256SUMS` and `dist\release\SHA256SUMS.sig`
- `dist\release\README_START_HERE.html` (outer copy)

## One command
powershell -ExecutionPolicy Bypass -File packaging\iso\make_iso.ps1 -Version 0.1.0 -PrivateKey C:\Keys\private.key

## Notes
- The script will stage files into `dist\iso_root\`, generate `manifest.json`, sign it to `manifest.sig`, build `dist\guarddog.iso`, then write and sign outer `SHA256SUMS`.
- For first run, if you don’t have real EXEs yet, create tiny placeholder files named `GuardDog.exe` and `verifier.exe` in `build\`.
