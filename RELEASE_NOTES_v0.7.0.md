# Cuty-SSH v0.7.0 — Headless CLI Automation & Smart Pageant Discovery

## 🚀 What's New in v0.7.0

### 1. Headless CLI Automation & Remote Execution (plink / OpenSSH alternative)
Transform Cuty-SSH into a powerful, scriptable command-line automation tool without sacrificing the rich GUI experience:
* **Remote command execution**:
  * `cuty-ssh -ssh root@host -i key.ppk --exec "uptime && free -m"`
  * `cuty-ssh -load "PROD_SERVER" -- hostname -I` (everything after `--` is executed remotely)
  * Real-time streaming of stdout and stderr separately (unbuffered binary/UTF-8)
  * Exit code propagation (exit code matches remote process; exit code 255 on SSH connection or auth errors)
* **Local script execution**:
  * `cuty-ssh -load "PROD_SERVER" -m ./deploy.sh`
  * Reads the local script file and sends it safely to the remote host.
* **Non-interactive batch mode (`--batch`)**:
  * Ideal for automated pipelines, cron tasks, and CI/CD services.
  * Zero prompts: unknown hosts in `known_hosts` fail with exit 255 instead of hanging. Missing credentials fail immediately.
  * Redirection-safe with no terminal escape noise.
* **Configurable timeouts**:
  * `--timeout <seconds>`: automatically cancels and exits with 255 if connection or command execution exceeds the threshold.
* **PTY force allocation (`-t`)**:
  * Force PTY allocation for interactive curses/terminal utilities when needed.

---

### 2. SFTP Command-Line Transfers (`--sftp-put` & `--sftp-get`)
Scriptable file and directory transfers directly from the command line:
* `cuty-ssh --sftp-put ./build.tar.gz /var/www/ -load "PROD_SERVER"`
* `cuty-ssh --sftp-get /var/log/syslog ./syslog.log -ssh root@host -pw secret`
* `-r` / `--recursive` flag for complete folder transfers.
* Adaptive interactive progress bar when attached to a TTY, completely silent when redirected for script safety.

---

### 3. Command-Line Port Forwarding Tunnel (`--tunnel`)
* `cuty-ssh --tunnel 8080:localhost:80 -ssh root@host -i key.ppk`
* `cuty-ssh --tunnel 0.0.0.0:5432:db.internal:5432 -load "DB_BASTION"`
* Stays in the foreground and closes cleanly on Ctrl+C. Reuses all session settings (bastion `-J`, proxy, stored secrets).

---

### 4. Smart Pageant & SSH Agent Guidance
* **Automatic detection**: Scans common installation directories and SSH key folders for Pageant (`pageant.exe`) or KiTTY (`kageant.exe`).
* **Path display & folder explorer**: When detected, the path is clearly displayed with 1-click **"Open Folder"** and **"Re-detect"** buttons.
* **Installation helper**: When not detected, an informative helper box appears in the "🔑 Keys" modal with:
  * Direct link to the official PuTTY download page.
  * Direct link to KiTTY download page.
  * 1-click button to copy the WinGet command: `winget install SimonTatham.PuTTY`.

---

## 📦 Downloads & Verification

| Asset | Format | Description |
| :--- | :--- | :--- |
| **`cuty-ssh-v0.7.0-windows-x64.msi`** | MSI Installer | WiX Windows 64-bit installer with Start Menu shortcut & PATH integration |
| **`cuty-ssh-v0.7.0-windows-x64.zip`** | Portable ZIP | Zero-install archive with `cuty-ssh.exe`, license and documentation |
| **`cuty-ssh.exe`** | Standalone EXE | Single standalone binary, ready to run anywhere |

**Full Changelog**: https://github.com/laurentvv/cuty-ssh/compare/v0.6.2...v0.7.0
