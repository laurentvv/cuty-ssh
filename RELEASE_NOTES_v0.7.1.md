# Cuty-SSH v0.7.1 — Terminal Drag-Selection Start Fix

## 🐛 Fixed in v0.7.1

### Terminal drag-selection no longer skips the first character
* Selecting text with the mouse in the terminal now reliably includes the very first character you press on: starting a drag on the `h` of `history` selects the `h`. Previously the selection could start one or more characters further, unless you began the drag slightly before the intended first character.
* Root cause: egui only reports `drag_started` once the pointer has moved past its 6 pt click threshold, so the selection start was recorded at the already-moved pointer position instead of the actual press position. The selection start is now anchored at the exact press origin (`pointer.press_origin()`).
* Applies to all terminal tabs (SSH2, Telnet, Raw TCP, Serial and local ConPTY shell). Double-click word selection and triple-click line selection are unchanged.

---

## 📦 Downloads & Verification

| Asset | Format | Description |
| :--- | :--- | :--- |
| **`cuty-ssh-v0.7.1-windows-x64.msi`** | MSI Installer | WiX Windows 64-bit installer with Start Menu shortcut |
| **`cuty-ssh-v0.7.1-windows-x64.zip`** | Portable ZIP | Zero-install archive with `cuty-ssh.exe`, license and documentation |
| **`cuty-ssh.exe`** | Standalone EXE | Single standalone binary, ready to run anywhere |

**Full Changelog**: https://github.com/laurentvv/cuty-ssh/compare/v0.7.0...v0.7.1
