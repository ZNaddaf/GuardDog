# GuardDog ISO Build (maintainers)

This document is for **maintainers** who build the GuardDog ISO.

The goal: run **one PowerShell command**, and get a ready-to-ship ISO plus checksum files.

---

## 1. Prerequisites

You need:

- Windows 10 or 11
- [Windows ADK](https://learn.microsoft.com/windows-hardware/get-started/adk-install) – install **Deployment Tools** (this gives you `oscdimg.exe`)
- `minisign.exe` on your `PATH`
- Your **minisign private key** file (this stays on your machine, never in Git)

---

## 2. Inputs (files from this repo)

The ISO build expects these to exist:

- `build\GuardDog.exe`          – main tool (or a small placeholder exe for first runs)
- `build\verifier.exe`          – integrity verifier (or placeholder)
- `packaging\signing\public.key` – minisign **public** key (committed)
- `report\report_template.html`  – HTML report template
- `checks\checks_catalog.json`   – checks configuration
- `docs\README_START_HERE.html`  – user-facing intro shown **inside** the ISO
- `LICENSE`                      – project license

> For the very first test build, you can create tiny text files named
> `GuardDog.exe` and `verifier.exe` in `build\` just so the script has
> something to package.

---

## 3. Outputs

After a successful build, you should see:

- `dist\guarddog.iso`
  - The ISO file users will mount and run GuardDog from.
- `dist\release\SHA256SUMS`
  - Contains the SHA-256 hash of `guarddog.iso`.
- `dist\release\SHA256SUMS.sig`
  - `minisign` signature for `SHA256SUMS`.
- `dist\release\README_START_HERE.html`
  - Copy of the inner README for outer distribution.

All of these paths are **ignored by Git** (via `.gitignore`).

---

## 4. One command to build

Example:

```powershell
powershell -ExecutionPolicy Bypass -File packaging\iso\make_iso.ps1 `
    -Version 0.1.0 `
    -PrivateKey C:\Keys\guarddog.key `
    -DryRun