# Cuty-SSH v0.10.1 — Split View Fixes & Working Clear Button

## 🐛 Fixed in v0.10.1

### Split View (H and V)
* **Split H**: clicking the lower pane to type no longer swaps the two sessions. Each session now keeps its slot (tab order); a click only moves the keyboard focus.
* **Split V**: the vertical split was badly broken (collapsed panes, telemetry strip rendered one character per line). Both split modes now lay panes out in explicit equal rectangles with a separator.

### Clear button
* **Vider / Clear** now also wipes the visible screen (not only the scrollback) and sends Ctrl+L so the shell redraws its prompt.

---

## 📦 Downloads & Verification

| Asset | Format | Description |
| :--- | :--- | :--- |
| **`cuty-ssh-v0.10.1-windows-x64.msi`** | MSI Installer | WiX Windows 64-bit installer with Start Menu shortcut |
| **`cuty-ssh-v0.10.1-windows-x64.zip`** | Portable ZIP | Zero-install archive with `cuty-ssh.exe`, license and documentation |
| **`cuty-ssh.exe`** | Standalone EXE | Single standalone binary, ready to run anywhere |

**Full Changelog**: https://github.com/laurentvv/cuty-ssh/compare/v0.10.0...v0.10.1
