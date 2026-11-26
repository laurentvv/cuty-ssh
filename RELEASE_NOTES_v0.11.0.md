# Cuty-SSH v0.11.0 — SFTP Follows the Terminal & Typed Passphrases Stay in Cuty Agent

## ✨ New in v0.11.0

### SFTP Client — Follow the Terminal Working Directory
* **The remote pane follows the terminal**: it opens on the working directory of the interactive shell and follows every `cd` (toggle **`📍 Follow terminal`**, on by default). The directory is read from the prompt on screen (`host:/path#`, `[user@host ~/dir]$`); when the prompt does not show it (RHEL's `[user@host dir]$`, a full-screen program), the server reports it over a short-lived `exec` channel reading `/proc` — nothing is ever typed into the terminal. A manual navigation in the pane stays put until the shell moves.

### Cuty Agent — Passphrase Typed Once
* **A key unlocked by a session stays in Cuty Agent**: when a session asks for the passphrase of an encrypted key (or the profile stores it), the decrypted key is kept in the agent's memory exactly like the **1-Click Session Key Loader**. The next session using the same key authenticates through the agent and connects **without a passphrase**. A toast names the key the first time it is loaded; a stopped agent is never restarted for it, and nothing ever reaches the disk.

## 📦 Dependencies

* **russh 0.64.1 → 0.65.4**: 15 security advisories published with the 0.65 line (unbounded allocations in the client, agent server and pageant client, host-key algorithm not enforced after key exchange, channel open confirmations accepted for channels that are not pending…).
* **russh-sftp 3.0.1 → 4.0.0**, **rfd 0.17.2 → 0.18.0**, **tokio 1.53.3 → 1.54.1**, **uuid 1.28.0 → 1.29.3**, **ssh-key → 0.7.0-rc.12**, plus **aes 0.9.4**, **anyhow 1.0.105**, **open 5.4.5**, **sha2 0.11.2**.
* egui, eframe and windows-sys were already at their latest versions; the GUI stack is unchanged.

---

## 📦 Downloads & Verification

| Asset | Format | Description |
| :--- | :--- | :--- |
| **`cuty-ssh-v0.11.0-windows-x64.msi`** | MSI Installer | WiX Windows 64-bit installer with Start Menu shortcut |
| **`cuty-ssh-v0.11.0-windows-x64.zip`** | Portable ZIP | Zero-install archive with `cuty-ssh.exe`, license and documentation |
| **`cuty-ssh.exe`** | Standalone EXE | Single standalone binary, ready to run anywhere |

**Full Changelog**: https://github.com/laurentvv/cuty-ssh/compare/v0.10.2...v0.11.0
