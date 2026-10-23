# Cuty-SSH v0.8.0 — SFTP Folder Transfers & Drag & Drop

## ✨ New in v0.8.0

### Recursive folder transfers (upload & download)
* SFTP folder uploads/downloads now walk the whole tree: previously only regular files were transferable (`sftp.open` on a directory fails silently). The new `download_sftp_tree` / `upload_sftp_tree` walkers handle nested folders iteratively, skip symlinks, and report+skip failed children instead of aborting the whole folder.
* Folder queue entries complete via a final progress event carrying the folder name, so the transfer queue and progress bar reflect folder jobs correctly.

### Drag & drop between the SFTP panes
* Drag rows from the local pane to the remote pane to upload, and from remote to local to download. Dragging a selected row carries the whole selection; the target pane highlights on hover.
* Drops reuse the existing transfer batches (collision rules included); folders merge silently instead of opening the file collision dialog.

### Auto-reconnect: persisted toggle & no respawn on deliberate close
* The toolbar « ↻ Auto-reconnexion » toggle now writes through to the saved profile (`sessions.json`), survives restarts, and stays in sync with the session editor checkbox (editor saves update open tabs too).
* Typing `exit`/`logout` in a remote shell is now treated as a deliberate close (exit status received): no auto-reconnect loop anymore. Real network drops (« Connexion SSH fermée par l'hôte distant ») still reconnect automatically with back-off (2 s → 30 s, 10 attempts).

### Pageant integration hardening
* « Charger toutes les clés .ppk des sessions » filters strictly to `.ppk` files: OpenSSH/PEM private keys and `.pub` public keys are skipped (counted in the toast) instead of being handed to `pageant.exe`, which popped one « Couldn't load this key » error dialog per foreign format.
* Agent key queries no longer swallow failures: the status bar and the key manager now tell exactly what happened — « Pageant non détecté (fenêtre introuvable) », « Pageant détecté mais requête échouée (…elevation?) », « Pageant actif, 0 clé chargée », or « N clé(s) prête(s) ». Previously a failed query was indistinguishable from an empty agent and pinned a permanent « 0 clé » verdict.
* Key-loading actions keep probing the agent every 2 s for up to 90 s, because entering per-key passphrases in Pageant's dialogs takes as long as the user needs; plain refresh keeps a short two-round probe.

### External editor dialog
* Native title-bar close button (✕) on the « Configuration de l'éditeur externe » window, matching the other modals. Brand mentions removed from remaining tooltips.

---

## 📦 Downloads & Verification

| Asset | Format | Description |
| :--- | :--- | :--- |
| **`cuty-ssh-v0.8.0-windows-x64.msi`** | MSI Installer | WiX Windows 64-bit installer with Start Menu shortcut |
| **`cuty-ssh-v0.8.0-windows-x64.zip`** | Portable ZIP | Zero-install archive with `cuty-ssh.exe`, license and documentation |
| **`cuty-ssh.exe`** | Standalone EXE | Single standalone binary, ready to run anywhere |

**Full Changelog**: https://github.com/laurentvv/cuty-ssh/compare/v0.7.1...v0.8.0
