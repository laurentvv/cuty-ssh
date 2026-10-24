# Cuty-SSH v0.9.0 — Passphrase-Protected OpenSSH Key Generator & Taskbar Dismissal Gestures

## ✨ New in v0.9.0

### Key generator: passphrase-protected OpenSSH keys (PuTTYgen-style .ppk generation removed)
* The built-in generator now emits an **Ed25519 OpenSSH private key encrypted with bcrypt + AES256-CTR** (16-byte salt / 16 rounds, matching `ssh-keygen` defaults), plus its `.pub` `authorized_keys` line in the same save. Verified interoperable with the real Windows `ssh-keygen`: identical public line (comment included), wrong passphrases refused.
* The passphrase is **mandatory** (button stays disabled until one is entered), wiped from the input field once the key is safely on disk, and the PEM document is zeroized on drop — no plaintext secret ever touches persistent storage.
* The algorithm combo was removed: its ECDSA-P256 / RSA-2048 entries were never honored (generation was silently always Ed25519). Generation is now honestly Ed25519-only. The **Inspector & Converter** still reads and converts `.ppk` v2/v3 ↔ OpenSSH in both directions.

### Dismissal gestures: shrink-to-sliver joins drag-past-left
* Shrinking the window below ~160 pt of width (the OS minimum drops from 600 pt to 120 pt so the sliver is reachable mid-resize) now **minimizes it to the taskbar**, exactly like the existing drag-past-the-left-edge gesture. SSH sessions, tunnels and Cuty Agent keep running — it is a dismissal, not an exit.
* Before minimizing, the window is **restored to its last usable size and parked inside the monitor work area**, so a taskbar click never resurrects a 100-pixel column stuck off-screen. A one-shot latch prevents a minimize loop if the restore command is lost while minimized.
* Verified end-to-end on the interactive desktop: a window shrunk to 150 px auto-minimized (`IsIconic = True`) and came back from the taskbar at its full 1336×859 size, on-screen.

### Key manager modal: uniform section widths
* The four framed sections of the 🔑 Keys manager (« Clé SSH Principale », « Cuty Agent », « Inspecteur & Convertisseur », « Générateur ») now all fill the window width — previously the bottom sections sized themselves to their content (~600 px) and looked misaligned next to the wider ones above.

---

## 📦 Downloads & Verification

| Asset | Format | Description |
| :--- | :--- | :--- |
| **`cuty-ssh-v0.9.0-windows-x64.msi`** | MSI Installer | WiX Windows 64-bit installer with Start Menu shortcut |
| **`cuty-ssh-v0.9.0-windows-x64.zip`** | Portable ZIP | Zero-install archive with `cuty-ssh.exe`, license and documentation |
| **`cuty-ssh.exe`** | Standalone EXE | Single standalone binary, ready to run anywhere |

**Full Changelog**: https://github.com/laurentvv/cuty-ssh/compare/v0.8.0...v0.9.0
