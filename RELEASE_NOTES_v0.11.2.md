# Cuty-SSH v0.11.2 — Security Audit & Hardening Release

## 🛡 Security Hardening & Improvements in v0.11.2

Cuty-SSH v0.11.2 is a major security hardening release following a comprehensive multi-layer security audit (`/sec-audit-swarm`). It resolves 35+ security, resilience, and cryptographic findings across SFTP, SSH protocol handling, DPAPI vault storage, terminal emulation, and agent IPC.

### 🔒 SFTP & Remote File Management
* **Path Traversal Protection**: Enforced strict root anchoring for local directory downloads/uploads and sanitization of remote relative path components (`..`), preventing arbitrary file write outside destination folders.
* **Mark-of-the-Web (MOTW)**: Downloaded remote files opened via external viewer/editor now automatically have Windows `Zone.Identifier` attached (`ZoneId=3` / Internet), ensuring Windows SmartScreen and Office protected views trigger as expected.
* **Process-Isolated SFTP Edit Cache**: Cached files opened for remote editing are now isolated in PID-specific and randomly keyed temporary subdirectories with restricted user-only permissions.
* **Safe Symlink & Canonicalization**: Remote directory mirroring and recursive transfers resolve paths strictly within target boundaries.

### 🔑 DPAPI Vault, Credentials & Audit
* **DPAPI Vault Integrity Validation**: Session passwords and key passphrases encrypted via Windows DPAPI now include HMAC-SHA256 authentication tags, detecting any out-of-band tampering or corruption of encrypted blobs.
* **Secure CSV Export**: Audit log CSV exports now escape spreadsheet formula trigger characters (`=`, `+`, `-`, `@`, `\t`, `\r`), neutralizing CSV injection attacks.
* **Portable Directory Anchoring**: Portable mode storage paths (`cuty-ssh-portable/`) are strictly validated against directory traversal and symlink hijacking.
* **Host Certificate Verification & Strict TOFU**: OpenSSH host certificates are strictly validated against known certificate authorities, and host key changes enforce explicit user confirmation with no silent fallback.

### 🤖 Cuty Agent IPC & Cryptography
* **Named Pipe DACL Hardening**: The native Cuty Agent named pipe (`\\.\pipe\cuty-agent.<user>`) now applies a custom Windows Security Descriptor restricting access exclusively to the current user's security identifier (SID), denying medium/low-integrity local cross-user access.
* **WM_COPYDATA Sender Verification**: PuTTY/Pageant `WM_COPYDATA` messages verify sender process token integrity and user identity before processing SSH key operations.
* **CSPRNG Hardening & DACLs for PPK**: PuTTY `.ppk` v3 key generation uses OS CSPRNG (`ring::rand::SystemRandom`) for salt generation, and exported private keys are created with user-only ACLs on NTFS.
* **POSIX `ssh-copy-id` Quoting**: Remote public key deployment uses hardened shell escaping, preventing command injection through usernames, hostnames, or key comments.

### 🖥 Terminal, Protocols & Stability
* **Terminal DoS & UTF-8 Panic Prevention**: Added bounded scrollback allocations, capped bracketed-paste buffer sizes, and hardened UTF-8 boundary checks across VT100 parser slices to prevent out-of-memory or panics from adversarial terminal output.
* **Password Suppression in Session Logs**: Sensitive password and passphrase prompts are automatically zeroized and suppressed from Asciinema v2 (`.cast`) session recordings.
* **URI Scheme & Argument Sanitization**: CLI argument parsing and custom URI handlers strictly validate protocols and host targets, blocking dangerous command-line flags injection.
* **Secure DLL Preloading**: Process initialization configures safe DLL search order (`LOAD_LIBRARY_SEARCH_SYSTEM32`) to mitigate DLL hijacking.

### 📦 Dependencies & Quality Gate
* **Dependency Minimization**: Cleaned up transitive cryptographic dependencies and trimmed unneeded image format features in `egui_extras`.
* **Automated Test Suite**: Extended comprehensive test coverage to 120 unit and integration tests covering all security fixes.

---

## 📦 Downloads & Verification

| Asset | Format | Description |
| :--- | :--- | :--- |
| **`cuty-ssh-v0.11.2-windows-x64.msi`** | MSI Installer | WiX Windows 64-bit installer with Start Menu shortcut |
| **`cuty-ssh-v0.11.2-windows-x64.zip`** | Portable ZIP | Zero-install archive with `cuty-ssh.exe`, license and documentation |
| **`cuty-ssh.exe`** | Standalone EXE | Single standalone binary, ready to run anywhere |

**Full Changelog**: https://github.com/laurentvv/cuty-ssh/compare/v0.11.1...v0.11.2
