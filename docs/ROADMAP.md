# GuardDog Roadmap

GuardDog is a **portable Windows security helper** that runs from a USB stick and gives non-technical users a simple security health report.

This roadmap explicitly separates:

- **Phase 1 – GuardDog Basic (MVP)**
- **Phase 2 – GuardDog Hardened (advanced integrity & packaging)**

---

## Phase 1 – GuardDog Basic (MVP)

### Goal

Make it possible for a non-technical person to:

1. Download GuardDog (as a ZIP).
2. Copy it to a cheap, retail USB stick.
3. Plug the USB into a Windows 10/11 machine.
4. Run `GuardDog.exe`.
5. Get an easy-to-understand HTML report about basic security settings.

No ISO, no minisign, no extra tools required for the user.

### Technical Shape

- **Delivery**: `GuardDog-<version>.zip` (GitHub Releases).
- **Contents of the ZIP**:
  - `GuardDog.exe` – main executable (single-file if possible).
  - `README_START_HERE.html` – friendly instructions and privacy notes.
- **Runtime behavior**:
  - Read-only checks, non-admin.
  - No network calls.
  - Writes a single HTML report to the **same USB** (`.\reports\...`).
- **Target OS**:
  - Windows 10/11 (64-bit).

### MVP Check List (non-admin, read-only)

Initial checks (subject to iteration):

1. **OS and Patch Info**
   - Windows edition, version, build, and last update install date (where available).

2. **Firewall Status**
   - Is Windows Defender Firewall enabled for the active profile(s)?

3. **Remote Desktop (RDP)**
   - Is Remote Desktop enabled?
   - If enabled, is Network Level Authentication (NLA) required?

4. **Local Administrators**
   - List local users that are members of the local Administrators group.

5. **Microsoft Defender State**
   - Is real-time protection enabled?
   - Is periodic scanning enabled?

6. **Screen Lock / Idle Timeout**
   - Is there a screen lock / timeout configured (non-zero)?

7. **Time Sync / Clock Skew (basic)**
   - Is the system clock roughly correct relative to UTC (within a loose tolerance) or at least synced via Windows Time service.

Each check produces:

- A **status**: `OK`, `Warn`, or `High`.
- A short **explanation in plain language**.
- Simple **remediation steps**.

### Reporting

- **Output**:
  - `.\reports\GuardDog_Report_YYYYMMDD_HHMMSS.html` (relative to where `GuardDog.exe` lives).
- **Format**:
  - Self-contained HTML (inline CSS, minimal or no JavaScript).
  - Sections:
    - Summary (big “All good / Some things to fix” message).
    - Each check with:
      - Status color (green/yellow/red).
      - Explanation.
      - “What you can do” steps.

### Phase 1 Non-Goals

- No ISO build.
- No minisign signatures.
- No `manifest.json` or `verifier.exe`.
- No CI/CD packaging pipelines (basic GitHub Actions for build/test is fine, but not required for MVP).

---

## Phase 2 – GuardDog Hardened (post-MVP)

Phase 2 focuses on making GuardDog **tamper-resistant** and more “production-grade” for distribution.

### Planned Features

1. **Integrity Manifest**
   - `manifest.json` listing every file on the ISO with SHA-256 hashes.
   - `manifest.sig` (minisign detached signature using an offline private key).

2. **verifier.exe**
   - Small helper binary.
   - Verifies `manifest.json` against `manifest.sig` using an **embedded public key**.
   - Re-hashes all files and returns JSON + exit codes.
   - GuardDog refuses to run if verification fails.

3. **ISO Packaging**
   - Deterministic ISO build (Windows ADK `oscdimg.exe`).
   - Staging path under `dist\iso_root\`.
   - Signing of outer `SHA256SUMS` + `SHA256SUMS.sig`.

4. **CI/QA for Packaging**
   - GitHub Actions to:
     - Build binaries.
     - Run tests.
     - Build ISO (in a controlled way).
     - Enforce “no writes outside `dist\`” for packaging scripts.

### Rationale

- Phase 2 is about:
  - **Portfolio strength**: demonstrates secure distribution, supply-chain hygiene, and integrity verification.
  - **User safety in the wild**: makes it harder for attackers to tamper with GuardDog between build and execution.

### Dependency on Phase 1

- Phase 1 (Basic) must be functional first:
  - GuardDog.exe should already:
    - Run checks.
    - Produce useful reports.
- Phase 2 **adds protection** around that existing behavior, it does not change the core user experience.

---

## Summary

- **Phase 1 (Basic)**: shipping a simple, helpful, USB-friendly check tool with HTML reports.
- **Phase 2 (Hardened)**: layering on integrity mechanisms (manifests, signatures, ISO packaging, CI) to make GuardDog safer and more “production-grade”.

Development should focus on **Phase 1 first** until:
- Non-admin checks are implemented.
- Reports are generated.
- A basic release ZIP can be produced and used by a non-technical person.