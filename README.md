# GuardDog

GuardDog is a **portable Windows security helper** that runs from a USB stick and generates a simple HTML report with a few high-impact baseline checks.

- **Windows 10/11 only**
- **Non-admin** (no UAC prompt required)
- **Read-only** checks (no registry or system changes)
- **Offline** (no network access)
- Writes a single HTML report back to the USB

---

## What GuardDog does (current status)

This repository currently contains **GuardDog Basic (MVP runtime)** implemented in Python.

When you run GuardDog on a Windows 10/11 machine, it:

- Collects some **basic security signals**, including:
  - Windows Defender Firewall status
  - Remote Desktop (RDP) and Network Level Authentication (NLA) settings
  - Microsoft Defender (real-time protection) status
  - Local Administrators group membership
  - Screen lock / idle timeout configuration
- Generates a **self-contained HTML report** summarizing:
  - What looks OK ✅
  - What could be improved ⚠️
  - What may be high risk 🔴
  - Simple, plain-language remediation steps for each item
- Writes the report into a `reports` folder **next to the executable**.

> GuardDog does **not** install anything, change registry values, or make network connections.  
> It only reads system state and writes HTML reports.

---

## Intended user workflow (GuardDog Basic)

> This describes how GuardDog is meant to be used once a release ZIP is produced (see Development section for building from source).

For a non-technical user:

1. **Get GuardDog**  
   - Download a ZIP (for example, `GuardDog-0.1.0.zip`) from the official release page.
   - Extract it. You should see:
     - `GuardDog.exe`
     - `README_START_HERE.html`

2. **Prepare a USB drive**  
   - Use any standard USB stick (formatted as exFAT or NTFS is fine).
   - Copy:
     - `GuardDog.exe`
     - `README_START_HERE.html`
   - Optionally create an empty `reports` folder (GuardDog will create it if missing).

3. **Run GuardDog on a Windows 10/11 machine**  
   - Plug the USB into the computer you want to check.
   - Open the USB in File Explorer.
   - Double-click `GuardDog.exe`.

4. **View the report**  
   - GuardDog runs a series of read-only checks.
   - It writes a report to:
     - `.\reports\GuardDog_Report_YYYYMMDD_HHMMSS.html`
   - It will try to open the report in your default browser.
   - You can also open the report manually from the `reports` folder.

---

## Checks implemented (MVP runtime)

The current codebase implements these checks as non-admin, read-only probes:

- **Windows Defender Firewall**
  - Uses `netsh advfirewall show allprofiles`.
  - Detects ON/OFF state per profile (Domain/Private/Public).
  - Classifies:
    - `OK` if all profiles appear ON.
    - `HIGH` if any profile is OFF.
    - `WARN`/`UNKNOWN` if output cannot be fully interpreted.

- **Remote Desktop (RDP) + NLA**
  - Reads registry keys under:
    - `HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server`
  - Detects:
    - Whether Remote Desktop is enabled (`fDenyTSConnections`).
    - Whether Network Level Authentication (NLA) is required (`UserAuthentication`).
  - Classifies:
    - `OK` if RDP is OFF, or RDP ON + NLA required.
    - `HIGH` if RDP ON and NLA explicitly NOT required.
    - `WARN`/`UNKNOWN` when state is ambiguous.

- **Microsoft Defender (real-time protection)**
  - First tries PowerShell:

    ```powershell
    Get-MpComputerStatus | Select-Object AMServiceEnabled, RealTimeProtectionEnabled
    ```

  - Parses `RealTimeProtectionEnabled` as the primary signal.
  - Falls back to registry policy flags if PowerShell is unavailable.
  - Classifies:
    - `OK` if real-time protection appears enabled.
    - `HIGH` if Defender appears explicitly disabled.
    - `UNKNOWN` if status cannot be reliably determined (e.g., another AV product is primary).

- **Local Administrators**
  - Uses PowerShell:

    ```powershell
    Get-LocalGroupMember -Group 'Administrators'
    ```

  - Lists all members of the local Administrators group.
  - Identifies **local user accounts** (`COMPUTERNAME\user`) vs built-in/domain accounts.
  - Classifies:
    - `OK` if only built-in/domain admins.
    - `WARN` if extra local user accounts are admins.

- **Screen Lock / Idle Timeout**
  - Reads current user registry values:

    - `HKCU\Control Panel\Desktop\ScreenSaveActive`
    - `HKCU\Control Panel\Desktop\ScreenSaverIsSecure`
    - `HKCU\Control Panel\Desktop\ScreenSaveTimeOut`

  - Estimates:
    - Whether automatic screen lock is active.
    - Whether a password is required on resume.
    - Approximate idle timeout.
  - Classifies:
    - `OK` if automatic lock is enabled, password required, timeout ≤ ~15 minutes.
    - `WARN` if lock is enabled but timeout is long or password requirement cannot be confirmed.
    - `HIGH` if automatic lock appears disabled.

Each check returns a structured result with:

- `id`
- `title`
- `status` (`OK`, `WARN`, `HIGH`, `UNKNOWN`)
- `summary`
- `details`
- `remediation`

The HTML report renders one section per check with this data.

---

## What GuardDog does **not** do (MVP)

- Does **not**:
  - Modify registry or system settings.
  - Install drivers, services, or scheduled tasks.
  - Open any network connections or contact remote servers.
  - Require administrative privileges for the basic checks.

- Current repo does **not yet**:
  - Bundle a production `GuardDog.exe` (no build script here yet).
  - Ship ISO images, manifests, or signed checksums.

---

## Development (from source)

GuardDog is currently implemented in Python with a small test suite using `pytest`.

### Layout (relevant to runtime)

```text
src/
  guarddog/
    __init__.py
    __main__.py          # `python -m guarddog`
    main.py              # entry logic (runs checks + writes report)
    checks/
      firewall.py
      rdp.py
      defender.py
      local_admins.py
      screen_lock.py
    reporting/
      html_report.py
report/
  template.html          # HTML style/template (logic is embedded in code)
tests/
  test_*.py              # pytest-based unit tests
  ```

 ### Running from source (dev)

From the repo root on Windows:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install pytest
$env:PYTHONPATH = "$PWD\src"
python -m pytest           # run tests
cd src
python -m guarddog         # run GuardDog from source
