# Cuty-SSH v0.10.2 — Fleet Ping Fix: No More Errors in SSH Server Logs

## 🐛 Fixed in v0.10.2

### Fleet Ping
* **No more errors in SSH server logs**: the background health probe (every 45 s) now sends its SSH client identification (RFC 4253) before closing the connection. OpenSSH servers used to log `kex_exchange_identification: Connection closed by remote host` (error level, about 1,900 times a day per server); each probe now leaves a single information-level line only. Telnet and raw TCP targets receive nothing, and reachability, latency and banner results are unchanged.

---

## 📦 Downloads & Verification

| Asset | Format | Description |
| :--- | :--- | :--- |
| **`cuty-ssh-v0.10.2-windows-x64.msi`** | MSI Installer | WiX Windows 64-bit installer with Start Menu shortcut |
| **`cuty-ssh-v0.10.2-windows-x64.zip`** | Portable ZIP | Zero-install archive with `cuty-ssh.exe`, license and documentation |
| **`cuty-ssh.exe`** | Standalone EXE | Single standalone binary, ready to run anywhere |

**Full Changelog**: https://github.com/laurentvv/cuty-ssh/compare/v0.10.1...v0.10.2
