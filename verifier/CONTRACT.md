# verifier.exe – Contract

This document describes exactly what `verifier.exe` must do, how it is called, and what it returns.

The goal: **GuardDog.exe can ask “Is this ISO intact?” and get a clear yes/no answer.**

---

## 1. What verifier.exe does (in one sentence)

- `verifier.exe` checks that:
  - `manifest.json` is **signed by our minisign private key**, and  
  - every file listed in `manifest.json` is present under the ISO root and matches its **SHA-256 hash**.

If anything is wrong, `verifier.exe` **fails** and GuardDog must not run checks.

---

## 2. How GuardDog calls verifier.exe

GuardDog will run `verifier.exe` like this:

```powershell
verifier.exe --root "D:\" --manifest "D:\manifest.json" --signature "D:\manifest.sig"