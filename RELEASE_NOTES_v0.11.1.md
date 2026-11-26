# Cuty-SSH v0.11.1 — Versioned Guide Title & Cleaner About Modal

## 🛠 Fixed in v0.11.1

### UI
* **Guide title follows the app version**: the illustrated guide window and its HTML export read a hardcoded **"Cuty-SSH v0.6"** since v0.6.0 — ten releases left it behind. The titles are now baked at compile time from the Cargo manifest, and a unit test pins them to it.
* **Cleaner About modal**: removed the **`Ouvrir le dossier des assets` / `Open Assets Folder`** and **`Ouvrir README du projet` / `Open Project README`** buttons. They opened paths relative to the current directory, so from the installed folder they opened nothing useful. The modal keeps the version, tagline and design-system sheet.

No functional change: the SFTP follow-terminal, the dependency updates and the Cuty Agent key retention of v0.11.0 are unchanged.

---

## 📦 Downloads & Verification

| Asset | Format | Description |
| :--- | :--- | :--- |
| **`cuty-ssh-v0.11.1-windows-x64.msi`** | MSI Installer | WiX Windows 64-bit installer with Start Menu shortcut |
| **`cuty-ssh-v0.11.1-windows-x64.zip`** | Portable ZIP | Zero-install archive with `cuty-ssh.exe`, license and documentation |
| **`cuty-ssh.exe`** | Standalone EXE | Single standalone binary, ready to run anywhere |

**Full Changelog**: https://github.com/laurentvv/cuty-ssh/compare/v0.11.0...v0.11.1
