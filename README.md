<div align="center">

# Cuty-SSH

### Fast, Native Windows SSH2, SFTP, Telnet, Raw TCP & ConPTY Connection Manager in Pure Rust

![Cuty-SSH Hero Banner](assets/cuty_ssh_hero.png)

[![Release](https://img.shields.io/github/v/release/laurentvv/cuty-ssh?style=flat-square&logo=github&color=00b4d8)](https://github.com/laurentvv/cuty-ssh/releases)
[![CI Status](https://img.shields.io/github/actions/workflow/status/laurentvv/cuty-ssh/ci.yml?branch=main&style=flat-square&logo=githubactions&label=CI)](https://github.com/laurentvv/cuty-ssh/actions)
[![Rust 2024](https://img.shields.io/badge/Rust-2024_Edition-f74c00?style=flat-square&logo=rust)](https://www.rust-lang.org/)
[![Platform](https://img.shields.io/badge/Platform-Windows_10_%2F_11_(x64)-0078d4?style=flat-square&logo=windows)](https://github.com/laurentvv/cuty-ssh/releases)
[![GUI](https://img.shields.io/badge/GUI-egui_0.37_(DirectX_12)-8a2be2?style=flat-square)](https://github.com/emilk/egui)
[![SSH Engine](https://img.shields.io/badge/SSH2-russh_0.64-2ea043?style=flat-square)](https://crates.io/crates/russh)
[![Bilingual](https://img.shields.io/badge/UI-English_%2F_Fran%C3%A7ais-ffb703?style=flat-square)](#5-bilingual-ui-en--fr--in-app-illustrated-user-guide--help)
[![License: MIT](https://img.shields.io/badge/License-MIT-success?style=flat-square)](LICENSE)

<p align="center">
  <img src="assets/cuty_ssh_icon.png" width="88" alt="Cuty-SSH App Icon" style="border-radius: 18px;" />
</p>

[**Download Latest Release (`v0.6.2`)**](https://github.com/laurentvv/cuty-ssh/releases/latest) · [**🇫🇷 Version Française**](README.fr.md) · [**Animated Tour**](#interactive-animated-tour--cockpit-preview) · [**Key Features**](#key-features) · [**1-Click `ssh-copy-id`**](#1-click-ssh-copy-id--automatic-password-to-key-migration) · [**Bastion (`-J`)**](#ssh-bastion--jump-host--j--proxyjump) · [**Architecture**](#architecture) · [**Build from Source**](#build-from-source)

</div>

---

## Overview

**Cuty-SSH** (`v0.6.2`) is a single-binary, portable, GPU-accelerated (**DirectX 12 / wgpu**) terminal emulator and sysadmin connection cockpit for Windows written in **100% safe, async Rust (`russh` + `egui` + `tokio`)** with **zero external binary dependencies** (no `putty.exe` or `kitty.exe` wrapper).

It bridges the gap between the classic **PuTTY / KiTTY** ecosystem and modern **OpenSSH** workflows:
- Load **PuTTY `.ppk` v2 & v3** private keys natively (including **Argon2id** passphrase encryption) alongside OpenSSH/PEM keys.
- Authenticate transparently via **Pageant** (Windows shared memory) **and** the native **Windows OpenSSH Agent** (`\\.\pipe\openssh-ssh-agent`).
- Provision new servers in **1 click (`ssh-copy-id`)**: connect once with a password, deploy your Primary SSH Key to `~/.ssh/authorized_keys`, and let Cuty-SSH automatically switch the saved session profile to passwordless key authentication while wiping the stored password.
- Route sessions through **SSH Bastions / Jump Hosts (`-J` / `ProxyJump`)**, manage **TOFU `known_hosts` SHA-256 fingerprints**, encrypt credentials at rest with **Windows DPAPI**, transfer files via **Drag-and-Drop streaming SFTP**, and monitor live remote server telemetry (`CPU load`, `RAM`, `Disk`, `Uptime`).

---

## Interactive Animated Tour & Cockpit Preview

### Animated Feature Tour (`assets/cuty_ssh_demo.gif`)
> Live walkthrough of the **SysAdmin Cockpit**, **Bastion / Jump Host (`-J`) Session Editor**, **Built-in Illustrated User Guide (`📖 Help`)**, **Network & IPv4 CIDR Toolkit**, **TOFU Known Hosts (`🛡 Hosts`)**, and **PuTTY `.ppk` Key Inspector & Pageant Manager**:

![Cuty-SSH Animated Feature Tour](assets/cuty_ssh_demo.gif)

### English SysAdmin Cockpit (`assets/screenshot_cockpit.png`)

![Cuty-SSH English Cockpit Screenshot](assets/screenshot_cockpit.png)

---

## Feature Matrix: Why Cuty-SSH?

| Capability | Classic PuTTY / KiTTY | Windows Terminal + `ssh.exe` | **Cuty-SSH (`v0.6.2`)** |
| :--- | :---: | :---: | :---: |
| **Pure Rust Async SSH2 Engine (`russh`)** | ❌ C legacy | ❌ External process | ✅ **Built-in (`russh 0.64`)** |
| **Native PuTTY `.ppk` v2 & v3 (Argon2id) Keys** | ✅ | ❌ Requires conversion | ✅ **Direct load & inspection** |
| **Dual Agent: Pageant + Windows OpenSSH Agent** | Pageant only | OpenSSH Agent only | ✅ **Both queried automatically** |
| **1-Click `ssh-copy-id` + Auto Password ➡ Key Switch** | ❌ | ❌ Manual CLI | ✅ **1-Click button + auto profile migration** |
| **SSH Bastion / Jump Host (`-J` / `ProxyJump`)** | Complex proxy cmd | ✅ `-J` flag | ✅ **Visual selector + inline `ProxyJump`** |
| **Integrated Streaming SFTP + Explorer Drag & Drop** | ❌ Separate `psftp` | ❌ | ✅ **Built-in side panel + 64 KB streaming** |
| **Live Remote Telemetry Bar (`Load` / `RAM` / `Disk`)** | ❌ | ❌ | ✅ **Non-intrusive header bar** |
| **Windows DPAPI Hardware-Bound Secret Encryption** | ❌ Plaintext registry | ❌ | ✅ **`CryptProtectData` + `zeroize`** |
| **TOFU `known_hosts` SHA-256 Fingerprint Manager** | Registry popup | Text file only | ✅ **Visual `Tools ▾ → Known Hosts` modal + MITM alert** |
| **Split-Screen Terminal (`◫ Split V` / `⊟ Split H`)** | ❌ | ✅ | ✅ **Side-by-side & top-bottom panes** |
| **Multi-Terminal Keystroke Broadcast (`📡 Broadcast`)** | ❌ | ❌ | ✅ **Simultaneous input with visual badge** |
| **Session Recording (`🔴 REC`) & Player (`Tools ▾ → Replay`)** | Text logging only | ❌ | ✅ **Asciinema v2 (`.cast`) + GUI player** |
| **Zero-Trust Edge Presets (ShellHub / Tailscale)** | ❌ | ❌ | ✅ **Native integration & auto-formatting** |
| **Fleet Health Probing & Bulk `ssh-copy-id`** | ❌ | ❌ | ✅ **Periodic 45s TCP ping + 1-click batch key** |
| **Audit Log Trail (`Tools ▾ → Audit`) with CSV/JSON Export** | ❌ | ❌ | ✅ **Local session events + zero-secret audit** |
| **SysAdmin Toolkit (Port Scanner, CIDR, Health Check)** | ❌ | ❌ | ✅ **Built-in `🛠 Network & CIDR`** |
| **Bilingual UI (`🌐 EN / FR`) + Illustrated User Guide** | ❌ | ❌ | ✅ **Instant switch + HTML export** |

---

## Key Features

### 1. Native PuTTY Key (`.ppk`), Pageant & Windows OpenSSH Agent
- **Direct `.ppk` v2 & v3 Support**: Load PuTTY private keys (`PuTTY-User-Key-File-2` and `PuTTY-User-Key-File-3`) directly without conversion.
  - Supports **Ed25519**, **RSA**, **ECDSA (`nistp256` / `nistp384` / `nistp521`)**, and **DSA**.
  - Supports unencrypted (`Encryption: none`) and passphrase-encrypted keys (`aes256-cbc`, **Argon2id / Argon2d / Argon2i** KDF in `.ppk` v3, and SHA-1 KDF in `.ppk` v2).
  - Automatic memory wiping (`zeroize`) of decrypted key material and seeds.
- **Dual SSH Agent Support (Pageant + Windows OpenSSH Agent)**:
  - Zero-prompt SSH authentication via the running **Pageant** process using Windows shared-memory IPC.
  - Automatic fallback to the native **Windows OpenSSH Authentication Agent** service (`\\.\pipe\openssh-ssh-agent`).
  - Built-in **Pageant Launcher & 1-Click `.ppk` Batch Loader**: launch `pageant.exe` or push all configured `.ppk` keys from saved sessions into Pageant in one click.
- **Built-in Key Inspector, Converter & Generator (PuTTYgen in Rust)**:
  - Inspect any `.ppk`, OpenSSH, PEM, PKCS#8, or `.pub` key (format, algorithm, encryption KDF, SHA-256 fingerprint, comment, and `authorized_keys` public key line).
  - Convert `.ppk` ↔ OpenSSH private keys (`id_ed25519` / `id_rsa`).
  - Generate new Ed25519, ECDSA-P256, or RSA-2048 keys directly in PuTTY `.ppk` v3 format.

#### 1-Click `ssh-copy-id` & Automatic Password-to-Key Migration
Provisioning a brand-new Linux server typically requires logging in with a password, manually creating `~/.ssh/authorized_keys`, fixing `chmod 700`/`600` permissions, and reconfiguring your SSH client. **Cuty-SSH automates the entire workflow in 1 click**:
1. **From the Session Editor (first connection with Login + Password)**:
   - Enter your server's `Host`, `Username`, and `Password`, then click the green **`🔑➡🖥 Connect (Pwd) & Copy Primary Key (ssh-copy-id)`** button (or check **`🔑➡🖥 Copy my Primary Key on 1st login`**).
2. **Or from any active SSH terminal tab**:
   - Click **`🔑➡🖥 Copy My Key (ssh-copy-id)`** in the top-right terminal toolbar at any time.
3. **What happens under the hood**:
   - Cuty-SSH resolves your configured **Primary SSH Key** (`🔑 Keys` modal), or automatically generates a dedicated `ssh-ed25519` key pair (`cuty-ssh-portable/keys/id_cuty_primary.ppk` + `.pub` + OpenSSH format) if you don't have one yet.
   - Over a dedicated background SSH `exec` channel, it creates `~/.ssh` (`chmod 700`), appends your public key to `~/.ssh/authorized_keys` (`chmod 600`) with idempotent `grep -qxF` deduplication, and verifies installation.
   - As soon as the server confirms installation, Cuty-SSH **automatically switches the saved `SessionProfile` from `Password` to `PrivateKeyFile`**, **zeroizes and erases the stored password**, and saves `config.json`. Every future connection to that server is 100% passwordless.

---

### 2. Multi-Protocol Engine, Bastion (`ProxyJump`) & Security Vault
- **SSH2** (`russh 0.64`): PTY + interactive shell, public-key (`.ppk` / OpenSSH / OpenSSH `-cert.pub` certificates), Pageant & Windows OpenSSH Agent, Password, Keyboard-Interactive (PAM / 2FA / TOTP), SSH Agent Forwarding, Keepalive, and **Local (`-L`) / Remote (`-R`) Port Forwarding** tunnels.

#### SSH Bastion / Jump Host (`-J` / `ProxyJump`)
Connect to isolated private or DMZ servers transparently through an intermediate SSH Bastion host using encrypted `direct-tcpip` stream tunneling (`russh::client::connect_stream`):
1. Open the Session Editor (`➕ New` or click `⚙` on any session card).
2. In the **🔌 Connection & .PPK / Pageant Key** tab (with `SSH2` selected), scroll to **🏰 SSH Bastion / Jump Host (-J / ProxyJump)**.
3. Either select an existing saved SSH session in the **Bastion Session** dropdown, or type an inline jump specification (`user@bastion.corp:22`) in **Inline ProxyJump**, then click **💾 Save**.
4. Sessions routed through a Bastion display a purple **`🏰 Bastion` / `🏰 -J`** badge in the Sidebar and Cockpit.

- **TOFU Host Key Verification & `known_hosts` Manager (`Tools ▾ → 🛡 Known Hosts`)**:
  - Automatic Trust-On-First-Use (TOFU) verification of server SHA-256 public key fingerprints stored in `cuty-ssh-portable/known_hosts.json`.
  - Strict anti-MITM protection: immediately blocks the connection with a security alert if a server's public key changes, with a dedicated modal (`Tools ▾ → Known Hosts`) to inspect, copy, or revoke fingerprints.
- **Windows DPAPI Encrypted Credentials Vault**:
  - Saved passwords and key passphrases are automatically encrypted at rest using Windows **DPAPI** (`CryptProtectData` / `CryptUnprotectData`, bound to the current Windows user account) with `"dpapi:<base64>"` encoding and `zeroize` in-memory protection.
- **Live Remote Server Telemetry Bar**:
  - Lightweight background SSH telemetry reporting live `hostname`, `kernel`, `uptime`, `load average`, RAM usage (`free -m`), and root filesystem usage (`df -P -h /`) above active SSH terminals.
- **Telnet (RFC 854), Raw TCP & Local Windows ConPTY Shell**:
  - Full Telnet IAC negotiation (`NAWS` resize, `TTYPE` `xterm-256color`, `SGA`, `ECHO`) + auto-login.
  - Raw TCP socket stream for network appliance debugging.
  - Local **Windows ConPTY** (`portable-pty 0.9`) to run `powershell.exe`, `cmd.exe`, or `wsl.exe` inside tabs right next to remote SSH servers.

---

### 3. Split View, SFTP Drag & Drop & High-Performance Terminal
- **Split-Screen Terminal Panes (`◫ Split V` / `⊟ Split H`)**:
  - View and interact with two active terminal tabs simultaneously in **Side-by-Side Vertical** or **Top-Bottom Horizontal** split mode, with independent PTY resizing and click-to-focus.
- **Streaming SFTP Explorer with Drag & Drop & Progress Bar**:
  - Drag and drop files directly from **Windows Explorer** onto the Cuty-SSH window to upload them to the active SFTP directory.
  - Asynchronous chunked streaming (`64 KB` buffers) for large uploads and downloads with a live transfer progress bar.
  - **Integrated Bitvise dual-pane SFTP client** (local & remote files side-by-side, upload/download queues, full right-click context menu: Open, Edit, Move to, Erase, Rename, SHA-256 hashes, symlinks) replacing any need for external WinSCP.
- **High-Throughput Batched Terminal Renderer**:
  - Run-length text batching of adjacent cells sharing foreground color (`painter.text` per contiguous run instead of per cell).
  - Compact 1-byte bitflag `TerminalCell` attributes (`CELL_FLAG_*`), alternate screen buffer (`?1049h` for `vim`, `htop`, `tmux`), 256-color & 24-bit TrueColor SGR, and Ctrl+Click URL opening.

---

### 4. Session Organization, Tags (`#tag`) & SysAdmin Network Toolkit
- **Real-Time Multi-Criteria Search & Session Tags (`#tag`)**:
  - Filter sessions instantaneously as you type by **Name**, **Host / IP**, **Port**, **Username**, **Protocol**, **Folder**, or **`#tag`**.
  - Assign custom tags (`prod`, `docker`, `db`, `dmz`, `linux`, etc.) in the Session Editor or tag/untag multiple sessions in bulk inside the **Session Manager (`📁 Manager`)**.
- **Automatic `~/.ssh/config` Importer (`Import ▾ → Sync`) & PuTTY Registry Sync**:
  - Parses standard `~/.ssh/config` files (`Host`, `HostName`, `User`, `Port`, `IdentityFile`, `ProxyJump`, `LocalForward`, `RemoteForward`) and imports them with tags and tunnels.
  - Automatic & manual import from `HKCU\Software\SimonTatham\PuTTY\Sessions`.
  - **`Import ▾ → KiTTY…`**: pick a portable KiTTY folder (the one containing `Sessions/`) to import all its sessions; `Import ▾ → Sync` re-imports it afterwards.
- **SysAdmin Diagnostic Toolkit (`🛠 Network & CIDR`) & Command Palette (`Ctrl+K`)**:
  - Fuzzy session & command launcher (`Ctrl+K`).
  - Multi-threaded async **TCP Port Scanner & SSH Banner Grabber**.
  - **Saved Sessions Fleet Health Check** (parallel TCP latency & reachability probe across all saved servers).
  - **IPv4 CIDR Subnet Calculator** (netmask, wildcard, network/broadcast addresses, usable host range, host count).
  - **PuTTY / OpenSSH / WinSCP CLI Command Generator**.

---

### 5. Bilingual UI (`EN / FR`) & In-App Illustrated User Guide (`📖 Help`)
- **Full English & French Localization (`🌐 EN` / `🌐 FR`)**:
  - Switch the entire application interface on the fly between **English** and **French** via:
    1. The **`🌐 EN` / `🌐 FR`** button in the top-right toolbar.
    2. The **🎨 Appearance & Options** tab inside the Session Editor (`🌐 Application Language`).
    3. The **`🇬🇧 English` / `🇫🇷 Français`** selector inside the `📖 Help` modal.
  - Persisted automatically in `cuty-ssh-portable/config.json` (`"language": "English"` or `"French"`).
- **In-App Illustrated User Guide (`📖 Help`) & Standalone HTML Export**:
  - Click **`📖 Help`** in the top toolbar to browse **9 illustrated documentation chapters** with embedded high-DPI screenshots, step-by-step callouts, and a 1-click **`🌐 Open in Browser (HTML)`** exporter (`cuty-ssh-portable/user-guide.html`).

---

### 6. Fleet Management, Zero-Trust Edge, Session Recording & Audit Trail
- **Multi-Terminal Keystroke Broadcast (`📡 Broadcast`)**:
  - In Split View mode (Vertical or Horizontal), toggle `📡 Broadcast` to mirror every typed character simultaneously across all connected sessions.
  - Distinct safety indicators (orange `📡 BROADCAST ON` badge) in each terminal header clearly alert you when broadcast mode is armed.
- **Session Recording (`🔴 REC`) & Built-in Player (`Tools ▾ → Replay`)**:
  - Record any active SSH or local terminal session on-the-fly into standard **Asciinema v2 (`.cast`)** JSON Lines format stored in `cuty-ssh-portable/recordings/`.
  - Replay recordings anytime with the built-in **`Tools ▾ → ▶ Replay`** modal featuring interactive timeline scrubbing, play/pause controls, and speed multipliers (`0.5x`, `1x`, `2x`, `4x`).
  - 100% compatible with external tools like `asciinema play` or `agg`.
- **Zero-Trust & Edge Gateway Presets (ShellHub & Tailscale)**:
  - First-class support for **ShellHub** IoT & edge device access (UUID-based routing through ShellHub Cloud or self-hosted instances) and **Tailscale** MagicDNS mesh IPs.
  - Automatically formats the SSH target connection string according to each gateway's connection protocol.
- **Background Fleet Health Probing & Bulk `ssh-copy-id`**:
  - Automatic non-blocking TCP ping probes run every 45 seconds across all saved sessions.
  - Live color-coded reachability dots (`🟢 Online`, `🔴 Offline`, `⏳ Timeout`) appear in both the Cockpit cards and the Sidebar session list.
  - `● Online` / `● Offline` filter toggles on the Cockpit show only reachable or only unreachable servers; the same toggles in the Session Manager let you select and bulk-delete dead VMs.
  - Manual `📡 Ping` button in the Cockpit toolbar triggers an immediate fleet-wide check.
  - In **`📁 Manager`**, select multiple hosts and click **`🔑 Deploy Primary Key`** to bulk-install your public key across your fleet in parallel.
- **Local Session & Audit Log (`Tools ▾ → 📜 Audit`)**:
  - Centralized local audit trail recording connect, disconnect, session duration, error, and key deployment events.
  - Full-text search and event filter chips (`CONNECT`, `DISCONNECT`, `ERROR`, `DEPLOY_KEY`).
  - 1-click **CSV** and **JSON** exports for security audits and reporting.
  - Strictly compliant with our **Zero Plaintext Secrets** policy (no credentials, passwords, or private keys are ever written to the audit log).

### 7. Resilience, Scripting & Tunnels

- **Auto-reconnect**: tick *Reconnect automatically* in the session editor, or use the `↻ Auto-reconnect` toggle on a tab. A dropped connection retries with back-off (2 s → 30 s, 10 attempts); the status bar shows the countdown, and `↻ Reconnect` forces an immediate retry.
- **Command line**: `cuty-ssh --session "Prod Web"` opens a saved session at startup (name, unique name fragment or UUID); `cuty-ssh --list` prints the saved sessions.
- **One-click SOCKS5 / HTTP proxy**: the `SOCKS5/HTTP` button of an SSH tab starts a local proxy (port editable, default `1080`) that accepts both SOCKS5 and HTTP `CONNECT` clients through the session; a `SOCKS5 (-D)` rule can also be saved in the *Port Forwarding* tab.
- **Keyboard-interactive fallback**: when a server refuses `password` but offers keyboard-interactive (PAM / 2FA), Cuty-SSH continues with it automatically.
- **SFTP properties & mirror**: `…` on a remote entry opens chmod (rwx grid + octal), symlink creation and SHA-256; `Mirror` previews and runs a one-way local/remote sync.
- **Bitvise import**: `Import > Bitvise…` reads `.tlp` / `.bscp` profiles (host, port, user).
- **Resumable SFTP transfers**: uploads and downloads go to `<name>.cutypart` and are renamed when complete; re-running an interrupted transfer continues from the bytes already transferred.

| SFTP properties (chmod, symlink, SHA-256) | SFTP mirror (preview, then sync) | Auto-reconnect |
|---|---|---|
| ![SFTP properties](assets/screenshot_sftp_properties.png) | ![SFTP mirror](assets/screenshot_sftp_mirror.png) | ![Auto-reconnect](assets/screenshot_auto_reconnect.png) |

---

## Mouse & Keyboard Shortcuts

| Shortcut / Interaction | Action |
| :--- | :--- |
| **`Double-Click`** | Select word, IP address, path, or URL under pointer (auto-copies if `Copy on Select` is on) |
| **`Triple-Click`** | Select entire line across the terminal row |
| **`Right-Click`** | Paste clipboard text (PuTTY style, or copies text if selection is active) |
| **`Ctrl + K`** | Open the **Command Palette** (fuzzy search sessions, filter by `#tag`, or launch `ssh user@host:port`) |
| **`Ctrl + Shift + C`** | Copy selected terminal text to clipboard (or right-click selection) |
| **`Ctrl + Shift + V`** | Paste clipboard text into the active terminal (or right-click when nothing is selected) |
| **`Ctrl + F`** | Toggle the in-terminal search bar (highlight matches across scrollback & screen) |
| **`Ctrl + Click`** | Open any detected `http://` or `https://` URL inside the terminal in your default browser |

---

## Download & Quick Start

### Option 1 — Windows Installer (.msi) & WinGet (Recommended)
- **Direct Download**: Download and run [**`cuty-ssh-v0.6.2-windows-x64.msi`**](https://github.com/laurentvv/cuty-ssh/releases/download/v0.6.2/cuty-ssh-v0.6.2-windows-x64.msi).
  - Installs cleanly to `%LOCALAPPDATA%\Programs\Cuty-SSH` without administrator/UAC prompts.
  - Automatically adds a **Cuty-SSH** Start Menu shortcut with application icon.
  - Clean 1-click uninstall from Windows Settings / Installed apps.
- **Via Windows Package Manager (`winget`)**:
  ```powershell
  winget install LaurentVolff.Cuty-SSH
  ```

### Option 2 — Portable Standalone Binary
1. Download **`cuty-ssh.exe`** (or **`cuty-ssh-v0.6.2-windows-x64.zip`**) from the [**GitHub Releases**](https://github.com/laurentvv/cuty-ssh/releases/latest) page.
2. Place `cuty-ssh.exe` in any folder and run it — zero installation required.
3. Cuty-SSH automatically creates a local **`cuty-ssh-portable/`** directory next to the executable containing:
   - `config.json` (DPAPI-protected session profiles, folders, tags, snippets, UI language & theme)
   - `known_hosts.json` (TOFU SHA-256 server host key fingerprints)
   - `keys/` (auto-generated or imported `.ppk` / OpenSSH keys, including your Primary SSH Key)
   - `Sessions/` (individual portable session files)

### Option 3 — Build from Source
Requires the **Rust 2024 toolchain** (`rustup` stable on Windows 10/11 x64):

```powershell
git clone https://github.com/laurentvv/cuty-ssh.git
cd cuty-ssh

# Format check, Clippy linter, and unit tests (21 tests)
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test

# Build optimized release binary (Thin LTO + stripped symbols)
cargo build --release
```

The compiled executable is generated at `target/release/cuty-ssh.exe`.
- **Release builds** run as native Windows GUI binaries (`lto = "thin"`, `codegen-units = 1`, `strip = true`) with no background console window.
- **Renderer**: defaults to **DirectX 12** via `wgpu` on Windows (override with `WGPU_BACKEND=vulkan` or `WGPU_BACKEND=gl` if needed).

---

## Architecture

| Module | File | Responsibility |
| :--- | :--- | :--- |
| **Entrypoint & Native Viewport** | [`src/main.rs`](src/main.rs) | Native `eframe 0.37` viewport bootstrap (`1320×820`), DirectX 12 `wgpu` backend, embedded cyber-cat icon, Tokio runtime setup, and integration test suite. |
| **Config, DPAPI Vault & Audit Storage** | [`src/config/mod.rs`](src/config/mod.rs) | `SessionProfile`, `AppConfig`, `UiLanguage` (`English` / `French`), Windows DPAPI encryption (`CryptProtectData`), TOFU `known_hosts.json` store, `AuditLogEntry` append-only engine, Edge Gateway presets, `~/.ssh/config` parser, and Registry PuTTY importer. |
| **PuTTY `.ppk`, Agents & `ssh-copy-id`** | [`src/ssh/ppk.rs`](src/ssh/ppk.rs) | `.ppk` v2/v3 & OpenSSH/PEM/`.pub` inspection, `zeroize`-hardened decoding, `.ppk` v3 encoder, Primary Key resolver/generator, `ssh-copy-id` POSIX script builder, and Pageant/OpenSSH Agent client helpers. |
| **VT100 Terminal Engine & Fast Selection** | [`src/terminal/mod.rs`](src/terminal/mod.rs) | `vte 0.15`-backed terminal grid, compact 1-byte bitflag `TerminalCell`, alternate screen (`?1049h`), 256-color/TrueColor SGR, scrollback, double-click word/token and triple-click line selection, search, and URL detection. |
| **Asciinema v2 Session Recorder & Player** | [`src/terminal/recording.rs`](src/terminal/recording.rs) | Standard `.cast` JSON Lines session recorder, event parser, and interactive playback engine. |
| **Async Protocols, Bastion & SFTP** | [`src/protocols/mod.rs`](src/protocols/mod.rs) | Async SSH2 (`russh`), `ProxyJump` (`direct-tcpip`), TOFU host key check, `DeployPublicKey` (`ssh-copy-id` exec channel), streaming SFTP (`russh-sftp`), Telnet RFC 854, Raw TCP, Windows ConPTY (`portable-pty`), live SSH telemetry, and IPv4 CIDR calculator. |
| **Desktop UI & SysAdmin Cockpit** | [`src/ui/mod.rs`](src/ui/mod.rs) | `egui 0.37` / `eframe 0.37` desktop interface: Dark-Tech theme, bilingual EN/FR localization, interactive Cockpit dashboard, Command Palette (`Ctrl+K`), 1-click Password-to-Key migration, Fleet Health check, Network Toolkit, and SFTP side panel. |
| **Batched Terminal & Split View** | [`src/ui/terminal_view.rs`](src/ui/terminal_view.rs) | Run-length batched terminal renderer, Horizontal/Vertical Split View panes, Broadcast Input mode, and VT key encoder. |
| **Local Audit Trail Modal** | [`src/ui/audit_modal.rs`](src/ui/audit_modal.rs) | Full-text audit log explorer, event filters, duration tracking, and 1-click CSV/JSON export. |
| **Asciinema Replay Player Modal** | [`src/ui/replay_modal.rs`](src/ui/replay_modal.rs) | In-app session replay player with interactive timeline scrubber and speed multiplier (`0.5x`–`4x`). |
| **Known Hosts TOFU Modal** | [`src/ui/known_hosts_modal.rs`](src/ui/known_hosts_modal.rs) | TOFU `known_hosts` SHA-256 fingerprint manager and `~/.ssh/config` import dialog. |
| **Built-in Illustrated User Guide** | [`src/ui/help_modal.rs`](src/ui/help_modal.rs) | In-app bilingual User Guide modal (`📖 Help`), 9 illustrated chapters, embedded Cockpit screenshot texture, and standalone HTML User Guide exporter. |

---

## License

Distributed under the [**MIT License**](LICENSE).
