//! Session profile definitions, portable JSON storage, and Windows Registry importer.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use uuid::Uuid;

/// Supported connection protocols in Cuty-SSH.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ProtocolType {
    Ssh,
    Telnet,
    RawTcp,
    LocalShell,
}

impl ProtocolType {
    pub fn label(self) -> &'static str {
        match self {
            Self::Ssh => "SSH2",
            Self::Telnet => "Telnet",
            Self::RawTcp => "Raw TCP",
            Self::LocalShell => "Shell Local (ConPTY)",
        }
    }

    pub fn badge(self) -> &'static str {
        match self {
            Self::Ssh => "🔐 SSH",
            Self::Telnet => "🖧 Telnet",
            Self::RawTcp => "🔌 Raw",
            Self::LocalShell => "💻 Local",
        }
    }

    pub fn default_port(self) -> u16 {
        match self {
            Self::Ssh => 22,
            Self::Telnet => 23,
            Self::RawTcp => 80,
            Self::LocalShell => 0,
        }
    }
}

/// SSH authentication method configured for a session profile.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum SshAuthMethod {
    /// Interactive or automatic password authentication.
    #[default]
    Password,
    /// Private key file authentication supporting PuTTY `.ppk` (v2/v3), OpenSSH, PEM, and PKCS#8.
    PrivateKeyFile {
        key_path: String,
        passphrase: String,
        cert_path: String,
    },
    /// SSH agent authentication via Pageant (`pageant.exe`) or Windows OpenSSH Agent.
    Agent {
        use_pageant: bool,
        use_openssh_agent: bool,
    },
    /// Keyboard-Interactive authentication (PAM / 2FA).
    KeyboardInteractive,
}

/// Expect/send automation rule executed during session logon.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExpectRule {
    pub enabled: bool,
    pub trigger_prompt: String,
    pub send_response: String,
    pub delay_ms: u64,
}

/// Direction of an SSH port-forwarding rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PortForwardType {
    Local,
    Remote,
    /// Dynamic SOCKS5 proxy (`-D`): target host/port are ignored.
    Dynamic,
}

/// SSH tunnel / port-forwarding rule (`-L` or `-R`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PortForwardRule {
    pub enabled: bool,
    pub forward_type: PortForwardType,
    pub bind_address: String,
    pub bind_port: u16,
    pub target_host: String,
    pub target_port: u16,
}

/// Complete configuration for a saved connection profile.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionProfile {
    pub id: Uuid,
    pub name: String,
    pub folder: String,
    pub icon_badge: String,
    pub protocol: ProtocolType,
    pub host: String,
    pub port: u16,
    pub username: String,
    pub password: String,
    pub ssh_auth: SshAuthMethod,
    pub try_pageant: bool,
    pub agent_forwarding: bool,
    pub local_shell_cmd: String,

    // Automation settings
    pub auto_login: bool,
    pub auto_password: bool,
    pub startup_command: String,
    pub local_script_path: String,
    pub logon_expect_rules: Vec<ExpectRule>,
    pub keepalive_secs: u32,
    pub anti_idle_string: String,
    pub compression: bool,
    pub port_forwards: Vec<PortForwardRule>,

    // Terminal appearance and ergonomics
    pub theme_name: String,
    pub font_size: f32,
    pub scrollback_lines: usize,
    pub transparency: u8,
    pub always_on_top: bool,
    pub read_only: bool,
    pub log_to_file: bool,
    pub notes: String,
    #[serde(default)]
    pub tags: Vec<String>,
    /// Optional UUID of another saved SSH session profile used as a Bastion / Jump Host (`-J`).
    #[serde(default)]
    pub jump_host_id: Option<Uuid>,
    /// Optional inline `user@bastion:port` ProxyJump specification (e.g. imported from `~/.ssh/config`).
    #[serde(default)]
    pub proxy_jump: String,
    /// When true, automatically installs the user's Primary SSH Public Key (`ssh-copy-id`) right after connecting with a password and switches the profile to key authentication.
    #[serde(default)]
    pub deploy_primary_key_on_connect: bool,
    /// Edge or Zero-Trust Gateway architecture preset (ShellHub, Tailscale SSH).
    #[serde(default)]
    pub edge_preset: EdgeGatewayPreset,
    /// ShellHub target device name or unique ID.
    #[serde(default)]
    pub shellhub_device_id: String,
    /// ShellHub gateway host address (defaults to `ssh.shellhub.io`).
    #[serde(default)]
    pub shellhub_server: String,
    /// Reconnect automatically (with back-off) when an established connection drops.
    #[serde(default)]
    pub auto_reconnect: bool,
}

/// Supported Edge or Zero-Trust Gateway architecture presets.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum EdgeGatewayPreset {
    #[default]
    None,
    /// ShellHub Edge Gateway (`user@device-id@ssh.shellhub.io`).
    ShellHub,
    /// Tailscale SSH Zero-Trust mesh connection (`.ts.net`).
    Tailscale,
}

impl EdgeGatewayPreset {
    pub fn label(self) -> &'static str {
        match self {
            Self::None => "Standard SSH",
            Self::ShellHub => "🐚 ShellHub Edge",
            Self::Tailscale => "🟣 Tailscale SSH",
        }
    }
}

/// Trusted SSH server host key entry for TOFU (Trust On First Use) verification.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct KnownHostEntry {
    pub host_port: String,
    pub algorithm: String,
    pub fingerprint_sha256: String,
    pub public_key_base64: String,
    pub first_seen: String,
    pub last_seen: String,
}

/// Outcome of verifying a server's SSH host key against the local `known_hosts.json` store.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HostKeyCheckResult {
    /// Host key was already known and matches the stored fingerprint.
    TrustedMatch {
        fingerprint: String,
        algorithm: String,
    },
    /// First time connecting to this host: key was automatically recorded (TOFU).
    NewlyTrusted {
        fingerprint: String,
        algorithm: String,
    },
    /// Host key changed! Potential MITM attack or server reinstallation.
    Mismatch {
        expected_fingerprint: String,
        actual_fingerprint: String,
        algorithm: String,
    },
}

impl Default for SessionProfile {
    fn default() -> Self {
        Self {
            id: Uuid::new_v4(),
            name: "Nouvelle Session".to_string(),
            folder: "Général".to_string(),
            icon_badge: "🖥".to_string(),
            protocol: ProtocolType::Ssh,
            host: "127.0.0.1".to_string(),
            port: 22,
            username: "root".to_string(),
            password: String::new(),
            ssh_auth: SshAuthMethod::Password,
            try_pageant: true,
            agent_forwarding: false,
            local_shell_cmd: "powershell.exe".to_string(),
            auto_login: true,
            auto_password: false,
            startup_command: String::new(),
            local_script_path: String::new(),
            logon_expect_rules: Vec::new(),
            keepalive_secs: 30,
            anti_idle_string: String::new(),
            compression: true,
            port_forwards: Vec::new(),
            theme_name: "Cuty Dark".to_string(),
            font_size: 14.5,
            scrollback_lines: 10_000,
            transparency: 255,
            always_on_top: false,
            read_only: false,
            log_to_file: false,
            notes: String::new(),
            tags: Vec::new(),
            jump_host_id: None,
            proxy_jump: String::new(),
            deploy_primary_key_on_connect: false,
            edge_preset: EdgeGatewayPreset::None,
            shellhub_device_id: String::new(),
            shellhub_server: "ssh.shellhub.io".to_string(),
            auto_reconnect: false,
        }
    }
}

/// Pre-defined command shortcut displayed in the quick command bar.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PredefinedCommand {
    pub id: Uuid,
    pub label: String,
    pub category: String,
    pub command: String,
    pub append_enter: bool,
    pub description: String,
}

/// User interface display language (French or English).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum UiLanguage {
    #[default]
    French,
    English,
}

impl UiLanguage {
    pub fn is_en(self) -> bool {
        matches!(self, UiLanguage::English)
    }

    pub fn code(self) -> &'static str {
        match self {
            UiLanguage::French => "FR",
            UiLanguage::English => "EN",
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            UiLanguage::French => "Français (FR)",
            UiLanguage::English => "English (EN)",
        }
    }

    pub fn toggle(self) -> Self {
        match self {
            UiLanguage::French => UiLanguage::English,
            UiLanguage::English => UiLanguage::French,
        }
    }
}

/// Top-level portable application configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppConfig {
    pub portable_mode: bool,
    pub pageant_path: String,
    pub winscp_path: String,
    pub default_key_dir: String,
    /// Path to the user's Primary SSH Private Key (`.ppk` or OpenSSH) used for 1-click `ssh-copy-id` key deployment.
    #[serde(default)]
    pub primary_key_path: String,
    /// Folder of a portable KiTTY/PuTTY install (containing `Sessions/`) imported by 📥 Sync.
    #[serde(default)]
    pub kitty_dir: String,
    pub copy_on_select: bool,
    pub right_click_paste: bool,
    pub detect_hyperlinks: bool,
    pub global_transparency: u8,
    pub global_always_on_top: bool,
    pub show_command_bar: bool,
    #[serde(default)]
    pub language: UiLanguage,
    pub sessions: Vec<SessionProfile>,
    pub predefined_commands: Vec<PredefinedCommand>,
}

impl Default for AppConfig {
    fn default() -> Self {
        Self {
            portable_mode: true,
            pageant_path: r"C:\Program Files\PuTTY\pageant.exe".to_string(),
            winscp_path: r"C:\Program Files (x86)\WinSCP\WinSCP.exe".to_string(),
            default_key_dir: default_ssh_dir(),
            primary_key_path: String::new(),
            kitty_dir: String::new(),
            copy_on_select: true,
            right_click_paste: true,
            detect_hyperlinks: true,
            global_transparency: 255,
            global_always_on_top: false,
            show_command_bar: true,
            language: UiLanguage::French,
            sessions: default_starter_sessions(),
            predefined_commands: default_predefined_commands(),
        }
    }
}

pub fn default_ssh_dir() -> String {
    if let Ok(profile) = std::env::var("USERPROFILE") {
        let p = PathBuf::from(profile).join(".ssh");
        if p.exists() {
            return p.to_string_lossy().to_string();
        }
    }
    ".".to_string()
}

fn default_starter_sessions() -> Vec<SessionProfile> {
    vec![
        SessionProfile {
            name: "PowerShell Local".to_string(),
            folder: "Shells Locaux".to_string(),
            icon_badge: "⚡".to_string(),
            protocol: ProtocolType::LocalShell,
            host: "localhost".to_string(),
            port: 0,
            username: std::env::var("USERNAME").unwrap_or_else(|_| "user".to_string()),
            local_shell_cmd: "powershell.exe".to_string(),
            theme_name: "Cuty Dark".to_string(),
            tags: vec!["local".to_string(), "shell".to_string()],
            ..Default::default()
        },
        SessionProfile {
            name: "CMD Windows".to_string(),
            folder: "Shells Locaux".to_string(),
            icon_badge: "🪟".to_string(),
            protocol: ProtocolType::LocalShell,
            host: "localhost".to_string(),
            port: 0,
            username: std::env::var("USERNAME").unwrap_or_else(|_| "user".to_string()),
            local_shell_cmd: "cmd.exe".to_string(),
            theme_name: "Classic PuTTY".to_string(),
            tags: vec!["local".to_string(), "cmd".to_string()],
            ..Default::default()
        },
        SessionProfile {
            name: "WSL / Linux Local".to_string(),
            folder: "Shells Locaux".to_string(),
            icon_badge: "🐧".to_string(),
            protocol: ProtocolType::LocalShell,
            host: "localhost".to_string(),
            port: 0,
            username: "root".to_string(),
            local_shell_cmd: "wsl.exe".to_string(),
            theme_name: "Dracula".to_string(),
            tags: vec!["local".to_string(), "wsl".to_string(), "linux".to_string()],
            ..Default::default()
        },
        SessionProfile {
            name: "Serveur Linux (Clé .ppk)".to_string(),
            folder: "Production".to_string(),
            icon_badge: "🔐".to_string(),
            protocol: ProtocolType::Ssh,
            host: "192.168.1.10".to_string(),
            port: 22,
            username: "admin".to_string(),
            ssh_auth: SshAuthMethod::PrivateKeyFile {
                key_path: String::new(),
                passphrase: String::new(),
                cert_path: String::new(),
            },
            startup_command: "uname -a && uptime".to_string(),
            theme_name: "Cuty Dark".to_string(),
            tags: vec!["prod".to_string(), "linux".to_string()],
            ..Default::default()
        },
        SessionProfile {
            name: "Switch / Routeur Telnet".to_string(),
            folder: "Réseau".to_string(),
            icon_badge: "🖧".to_string(),
            protocol: ProtocolType::Telnet,
            host: "192.168.1.1".to_string(),
            port: 23,
            username: "admin".to_string(),
            theme_name: "Matrix Green".to_string(),
            ..Default::default()
        },
    ]
}

fn default_predefined_commands() -> Vec<PredefinedCommand> {
    vec![
        PredefinedCommand {
            id: Uuid::new_v4(),
            label: "📊 Système & Uptime".to_string(),
            category: "Linux".to_string(),
            command: "uname -a && uptime && df -h".to_string(),
            append_enter: true,
            description: "Affiche le noyau, l'uptime et l'espace disque".to_string(),
        },
        PredefinedCommand {
            id: Uuid::new_v4(),
            label: "🐳 Docker PS".to_string(),
            category: "Conteneurs".to_string(),
            command: "docker ps --format 'table {{.Names}}\\t{{.Status}}\\t{{.Ports}}'".to_string(),
            append_enter: true,
            description: "Liste les conteneurs Docker actifs".to_string(),
        },
        PredefinedCommand {
            id: Uuid::new_v4(),
            label: "🔥 Ports en écoute".to_string(),
            category: "Réseau".to_string(),
            command: "ss -tulpn".to_string(),
            append_enter: true,
            description: "Affiche les sockets TCP/UDP en écoute".to_string(),
        },
        PredefinedCommand {
            id: Uuid::new_v4(),
            label: "📜 Journald Erreurs".to_string(),
            category: "Logs".to_string(),
            command: "journalctl -p 3 -xb -n 50".to_string(),
            append_enter: true,
            description: "Dernières erreurs système systemd".to_string(),
        },
        PredefinedCommand {
            id: Uuid::new_v4(),
            label: "👑 Sudo Root".to_string(),
            category: "Admin".to_string(),
            command: "sudo -i".to_string(),
            append_enter: true,
            description: "Passer en shell root interactif".to_string(),
        },
        PredefinedCommand {
            id: Uuid::new_v4(),
            label: "🧹 Clear".to_string(),
            category: "Terminal".to_string(),
            command: "clear".to_string(),
            append_enter: true,
            description: "Effacer l'écran du terminal".to_string(),
        },
    ]
}

impl AppConfig {
    /// Resolves the portable configuration file path next to the executable or working directory.
    pub fn portable_config_path() -> PathBuf {
        let local_path = PathBuf::from("cuty-ssh-portable").join("config.json");
        if local_path.exists() {
            return local_path;
        }
        if let Ok(exe) = std::env::current_exe()
            && let Some(dir) = exe.parent()
        {
            let candidate = dir.join("cuty-ssh-portable").join("config.json");
            if candidate.exists() {
                return candidate;
            }
            if let Some(parent) = dir.parent().and_then(|p| p.parent()) {
                let candidate2 = parent.join("cuty-ssh-portable").join("config.json");
                if candidate2.exists() {
                    return candidate2;
                }
            }
        }
        local_path
    }

    /// Finds a saved session from a CLI key: UUID, exact name, then a unique
    /// case-insensitive substring of the name (all case-insensitive).
    pub fn find_session(&self, key: &str) -> Result<&SessionProfile, String> {
        let key = key.trim();
        if let Some(s) = self
            .sessions
            .iter()
            .find(|s| s.id.to_string().eq_ignore_ascii_case(key))
        {
            return Ok(s);
        }
        let lower = key.to_lowercase();
        if let Some(s) = self
            .sessions
            .iter()
            .find(|s| s.name.to_lowercase() == lower)
        {
            return Ok(s);
        }
        let matches: Vec<&SessionProfile> = self
            .sessions
            .iter()
            .filter(|s| s.name.to_lowercase().contains(&lower))
            .collect();
        match matches.as_slice() {
            [one] => Ok(one),
            [] => Err(format!("no saved session matches '{key}'")),
            many => Err(format!(
                "'{key}' is ambiguous: {}",
                many.iter()
                    .map(|s| s.name.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            )),
        }
    }

    pub fn load_or_default() -> Self {
        let path = Self::portable_config_path();
        let mut cfg = if path.exists()
            && let Ok(data) = fs::read_to_string(&path)
            && let Ok(loaded) = serde_json::from_str::<Self>(&data)
        {
            loaded
        } else {
            Self::default()
        };
        cfg.sanitize_and_sync();
        let _ = cfg.save();
        cfg
    }

    /// Normalizes `user@host` fields, decrypts DPAPI-protected credentials into memory,
    /// cleans up legacy folder names, and syncs Saved Sessions from the Windows Registry.
    pub fn sanitize_and_sync(&mut self) {
        for s in &mut self.sessions {
            if s.host.contains('@') {
                let (user, clean_host) = split_user_and_host(&s.host, &s.username);
                s.username = user;
                s.host = clean_host;
            }
            if !s.password.is_empty() {
                s.password = dpapi_decrypt(&s.password);
            }
            if let SshAuthMethod::PrivateKeyFile { passphrase, .. } = &mut s.ssh_auth
                && !passphrase.is_empty()
            {
                *passphrase = dpapi_decrypt(passphrase);
            }
            if s.folder == "Import PuTTY/Import PuTTY"
                || s.folder == "Import PuTTY"
                || s.folder.contains("KiTTY")
            {
                s.folder = "Saved Sessions (Pageant / PuTTY)".to_string();
            }
            if s.theme_name == "KiTTY Dark" {
                s.theme_name = "Cuty Dark".to_string();
            }
        }
        #[cfg(windows)]
        {
            let _ = self.import_from_windows_registry();
        }
    }

    pub fn save(&self) -> anyhow::Result<()> {
        let path = Self::portable_config_path();
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }

        // Encrypt saved passwords and private key passphrases with Windows DPAPI before writing to disk.
        let mut disk_copy = self.clone();
        for s in &mut disk_copy.sessions {
            if !s.password.is_empty() {
                s.password = dpapi_encrypt(&s.password);
            }
            if let SshAuthMethod::PrivateKeyFile { passphrase, .. } = &mut s.ssh_auth
                && !passphrase.is_empty()
            {
                *passphrase = dpapi_encrypt(passphrase);
            }
        }

        let json = serde_json::to_string_pretty(&disk_copy)?;
        fs::write(&path, json)?;

        // Also export individual INI session files in `Sessions/` when portable mode is enabled.
        if self.portable_mode
            && let Some(parent) = path.parent()
        {
            let sessions_dir = parent.join("Sessions");
            let _ = fs::create_dir_all(&sessions_dir);
            for s in &self.sessions {
                let safe_name = url_encode_session_name(&s.name);
                let session_file = sessions_dir.join(safe_name);
                let _ = fs::write(session_file, export_session_to_ini(s));
            }
        }
        Ok(())
    }

    /// Imports saved sessions from Windows Registry keys created by PuTTY.
    #[cfg(windows)]
    pub fn import_from_windows_registry(&mut self) -> anyhow::Result<usize> {
        use winreg::RegKey;
        use winreg::enums::HKEY_CURRENT_USER;

        let hkcu = RegKey::predef(HKEY_CURRENT_USER);
        let mut imported_count = 0;
        let mut modified = false;

        let reg_paths = [(
            r"Software\SimonTatham\PuTTY\Sessions",
            "Saved Sessions (Pageant / PuTTY)",
        )];

        for (base_path, default_folder) in reg_paths {
            if let Ok(sessions_key) = hkcu.open_subkey(base_path) {
                for subkey_name in sessions_key.enum_keys().flatten() {
                    if subkey_name == "Default%20Settings" {
                        continue;
                    }
                    if let Ok(subkey) = sessions_key.open_subkey(&subkey_name) {
                        let decoded_name = url_decode_session_name(&subkey_name);
                        let raw_host: String = subkey.get_value("HostName").unwrap_or_default();
                        if raw_host.trim().is_empty() {
                            continue;
                        }
                        let raw_username: String = subkey.get_value("UserName").unwrap_or_default();
                        let (username, host) = split_user_and_host(&raw_host, &raw_username);
                        if host.is_empty() {
                            continue;
                        }

                        let protocol_str: String = subkey
                            .get_value("Protocol")
                            .unwrap_or_else(|_| "ssh".to_string());
                        let protocol = match protocol_str.to_lowercase().as_str() {
                            "telnet" => ProtocolType::Telnet,
                            "raw" => ProtocolType::RawTcp,
                            _ => ProtocolType::Ssh,
                        };
                        let port: u32 = subkey
                            .get_value("PortNumber")
                            .unwrap_or_else(|_| u32::from(protocol.default_port()));
                        let ppk_file: String =
                            subkey.get_value("PublicKeyFile").unwrap_or_default();
                        let remote_cmd: String =
                            subkey.get_value("RemoteCommand").unwrap_or_default();
                        let subfolder: String = subkey
                            .get_value("Folder")
                            .or_else(|_| subkey.get_value("SubFolder"))
                            .unwrap_or_default();
                        let clean_sub = subfolder.trim().replace('\\', "/");
                        let folder = if clean_sub.is_empty()
                            || clean_sub.eq_ignore_ascii_case("Default")
                            || clean_sub == default_folder
                        {
                            default_folder.to_string()
                        } else {
                            format!("{}/{}", default_folder, clean_sub)
                        };

                        let agent_fwd: u32 = subkey.get_value("AgentFwd").unwrap_or(0);
                        let try_agent: u32 = subkey.get_value("TryAgent").unwrap_or(1);

                        let ssh_auth = if !ppk_file.trim().is_empty() {
                            SshAuthMethod::PrivateKeyFile {
                                key_path: ppk_file.clone(),
                                passphrase: String::new(),
                                cert_path: String::new(),
                            }
                        } else if try_agent > 0 {
                            SshAuthMethod::Agent {
                                use_pageant: true,
                                use_openssh_agent: true,
                            }
                        } else {
                            SshAuthMethod::Password
                        };

                        if let Some(existing) =
                            self.sessions.iter_mut().find(|s| s.name == decoded_name)
                        {
                            if existing.host != host {
                                existing.host = host;
                                modified = true;
                            }
                            if existing.username.trim().is_empty() && !username.is_empty() {
                                existing.username = username;
                                modified = true;
                            }
                            if existing.folder == "Import PuTTY/Import PuTTY"
                                || existing.folder == "Import PuTTY"
                                || existing.folder.contains("KiTTY")
                            {
                                existing.folder = folder;
                                modified = true;
                            }
                            if !ppk_file.trim().is_empty() {
                                let needs_key_restore = match &existing.ssh_auth {
                                    SshAuthMethod::PrivateKeyFile { key_path, .. } => {
                                        key_path.trim().is_empty()
                                    }
                                    _ => true,
                                };
                                if needs_key_restore {
                                    existing.ssh_auth = SshAuthMethod::PrivateKeyFile {
                                        key_path: ppk_file,
                                        passphrase: String::new(),
                                        cert_path: String::new(),
                                    };
                                    modified = true;
                                }
                            }
                            if try_agent > 0 && !existing.try_pageant {
                                existing.try_pageant = true;
                                modified = true;
                            }
                        } else {
                            self.sessions.push(SessionProfile {
                                id: Uuid::new_v4(),
                                name: decoded_name,
                                folder,
                                icon_badge: match protocol {
                                    ProtocolType::Ssh => "🔐".to_string(),
                                    ProtocolType::Telnet => "🖧".to_string(),
                                    ProtocolType::RawTcp => "🔌".to_string(),
                                    ProtocolType::LocalShell => "💻".to_string(),
                                },
                                protocol,
                                host,
                                port: u16::try_from(port).unwrap_or(22),
                                username,
                                ssh_auth,
                                try_pageant: try_agent > 0,
                                agent_forwarding: agent_fwd > 0,
                                startup_command: remote_cmd,
                                ..Default::default()
                            });
                            imported_count += 1;
                            modified = true;
                        }
                    }
                }
            }
        }

        if modified {
            let _ = self.save();
        }
        Ok(imported_count)
    }

    /// Imports sessions from a portable KiTTY/PuTTY folder (`dir` or `dir/Sessions`),
    /// where each file is one session in `Key\Value\` format. Existing names are kept.
    pub fn import_from_kitty_dir(&mut self, dir: &Path) -> anyhow::Result<usize> {
        let sessions_dir = if dir.join("Sessions").is_dir() {
            dir.join("Sessions")
        } else {
            dir.to_path_buf()
        };
        let mut imported = 0;
        for entry in fs::read_dir(&sessions_dir)?.flatten() {
            let path = entry.path();
            let Some(file_name) = path.file_name().map(|n| n.to_string_lossy().to_string()) else {
                continue;
            };
            if !path.is_file() || file_name == "Default%20Settings" {
                continue;
            }
            let Ok(content) = fs::read_to_string(&path) else {
                continue;
            };
            let kv: BTreeMap<String, String> = content
                .lines()
                .filter_map(|l| l.trim().split_once('\\'))
                .map(|(k, v)| {
                    (
                        k.trim().to_string(),
                        url_decode_session_name(v.trim_end_matches('\\')),
                    )
                })
                .collect();
            let name = url_decode_session_name(&file_name);
            let get = |k: &str| kv.get(k).cloned().unwrap_or_default();
            let (username, host) = split_user_and_host(&get("HostName"), &get("UserName"));
            if host.is_empty() || self.sessions.iter().any(|s| s.name == name) {
                continue;
            }
            let protocol = match get("Protocol").to_lowercase().as_str() {
                "telnet" => ProtocolType::Telnet,
                "raw" => ProtocolType::RawTcp,
                _ => ProtocolType::Ssh,
            };
            let port = get("PortNumber")
                .parse::<u16>()
                .unwrap_or_else(|_| protocol.default_port());
            let ppk = get("PublicKeyFile");
            let try_agent = get("TryAgent") != "0";
            let ssh_auth = if !ppk.trim().is_empty() {
                SshAuthMethod::PrivateKeyFile {
                    key_path: ppk,
                    passphrase: String::new(),
                    cert_path: String::new(),
                }
            } else if try_agent {
                SshAuthMethod::Agent {
                    use_pageant: true,
                    use_openssh_agent: true,
                }
            } else {
                SshAuthMethod::Password
            };
            let sub = get("Folder").trim().replace('\\', "/");
            let folder = if sub.is_empty() || sub.eq_ignore_ascii_case("Default") {
                "KiTTY".to_string()
            } else {
                format!("KiTTY/{sub}")
            };
            self.sessions.push(SessionProfile {
                id: Uuid::new_v4(),
                name,
                folder,
                protocol,
                host,
                port,
                username,
                ssh_auth,
                try_pageant: try_agent,
                agent_forwarding: get("AgentFwd") == "1",
                startup_command: get("RemoteCommand"),
                ..Default::default()
            });
            imported += 1;
        }
        if imported > 0 {
            let _ = self.save();
        }
        Ok(imported)
    }

    /// Imports an INI session file (`Key\Value\` lines) or directory.
    /// Imports Bitvise SSH Client profiles (`.tlp` / `.bscp`). Returns how many sessions were
    /// added; a profile with the same name, host, port and user is skipped.
    pub fn import_bitvise_profiles(&mut self, paths: &[PathBuf]) -> anyhow::Result<usize> {
        let mut added = 0;
        for path in paths {
            let bytes = fs::read(path)?;
            let name = path
                .file_stem()
                .map(|n| n.to_string_lossy().to_string())
                .unwrap_or_else(|| "Bitvise".to_string());
            let profile = parse_bitvise_profile(&bytes, &name)
                .map_err(|e| anyhow::anyhow!("{}: {e}", path.display()))?;
            let duplicate = self.sessions.iter().any(|s| {
                s.name == profile.name
                    && s.host == profile.host
                    && s.port == profile.port
                    && s.username == profile.username
            });
            if !duplicate {
                self.sessions.push(profile);
                added += 1;
            }
        }
        if added > 0 {
            let _ = self.save();
        }
        Ok(added)
    }

    pub fn import_ini_portable_file(&mut self, path: &Path) -> anyhow::Result<usize> {
        if path.is_dir() {
            let mut count = 0;
            for entry in fs::read_dir(path)?.flatten() {
                let p = entry.path();
                if p.is_file()
                    && let Ok(c) = self.import_ini_portable_file(&p)
                {
                    count += c;
                }
            }
            return Ok(count);
        }

        let content = fs::read_to_string(path)?;
        if let Ok(profile) = serde_json::from_str::<SessionProfile>(&content) {
            self.sessions.push(profile);
            let _ = self.save();
            return Ok(1);
        }

        let mut kv = BTreeMap::new();
        for line in content.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') || line.starts_with('[') {
                continue;
            }
            if let Some((k, rest)) = line.split_once('\\') {
                let val = rest.trim_end_matches('\\');
                kv.insert(k.trim().to_string(), val.to_string());
            } else if let Some((k, val)) = line.split_once('=') {
                kv.insert(k.trim().to_string(), val.trim().to_string());
            }
        }

        let raw_host = kv.get("HostName").cloned().unwrap_or_default();
        if raw_host.is_empty() {
            anyhow::bail!("No HostName entry found in file {:?}", path);
        }

        let raw_name = path
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_else(|| "Session Importée".to_string());
        let name = url_decode_session_name(&raw_name);
        let protocol_str = kv
            .get("Protocol")
            .cloned()
            .unwrap_or_else(|| "ssh".to_string());
        let protocol = match protocol_str.to_lowercase().as_str() {
            "telnet" => ProtocolType::Telnet,
            "raw" => ProtocolType::RawTcp,
            _ => ProtocolType::Ssh,
        };
        let port = kv
            .get("PortNumber")
            .and_then(|p| p.parse::<u16>().ok())
            .unwrap_or_else(|| protocol.default_port());
        let raw_username = kv.get("UserName").cloned().unwrap_or_default();
        let (username, host) = split_user_and_host(&raw_host, &raw_username);
        let ppk_file = kv.get("PublicKeyFile").cloned().unwrap_or_default();
        let startup_command = kv.get("RemoteCommand").cloned().unwrap_or_default();
        let folder = kv
            .get("Folder")
            .or_else(|| kv.get("SubFolder"))
            .or_else(|| {
                kv.iter()
                    .find(|(k, _)| k.ends_with("SubFolder"))
                    .map(|(_, v)| v)
            })
            .cloned()
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| "Import Sessions".to_string());

        let ssh_auth = if !ppk_file.is_empty() {
            SshAuthMethod::PrivateKeyFile {
                key_path: ppk_file,
                passphrase: String::new(),
                cert_path: String::new(),
            }
        } else {
            SshAuthMethod::Password
        };

        self.sessions.push(SessionProfile {
            id: Uuid::new_v4(),
            name,
            folder,
            protocol,
            host,
            port,
            username,
            ssh_auth,
            startup_command,
            ..Default::default()
        });
        let _ = self.save();
        Ok(1)
    }

    /// Returns a sorted list of unique non-empty folder names from existing sessions.
    pub fn all_folders(&self) -> Vec<String> {
        let mut set = std::collections::BTreeSet::new();
        for s in &self.sessions {
            let f = s.folder.trim();
            if !f.is_empty() {
                set.insert(f.to_string());
            } else {
                set.insert("Général".to_string());
            }
        }
        set.into_iter().collect()
    }

    /// Duplicates a session by UUID, appending " (Copie)" to its name and assigning a new UUID.
    pub fn duplicate_session(&mut self, id: Uuid) -> Option<SessionProfile> {
        if let Some(pos) = self.sessions.iter().position(|s| s.id == id) {
            let mut clone = self.sessions[pos].clone();
            clone.id = Uuid::new_v4();
            clone.name = format!("{} (Copie)", clone.name);
            self.sessions.insert(pos + 1, clone.clone());
            let _ = self.save();
            Some(clone)
        } else {
            None
        }
    }

    /// Deletes a session by UUID and saves config.
    pub fn delete_session(&mut self, id: Uuid) -> bool {
        let before = self.sessions.len();
        self.sessions.retain(|s| s.id != id);
        let removed = self.sessions.len() < before;
        if removed {
            let _ = self.save();
        }
        removed
    }

    /// Bulk deletes sessions matching any of the given UUIDs.
    pub fn delete_sessions(&mut self, ids: &[Uuid]) -> usize {
        let before = self.sessions.len();
        self.sessions.retain(|s| !ids.contains(&s.id));
        let count = before - self.sessions.len();
        if count > 0 {
            let _ = self.save();
        }
        count
    }

    /// Moves selected sessions to a target folder.
    pub fn move_sessions_to_folder(&mut self, ids: &[Uuid], target_folder: &str) -> usize {
        let target = if target_folder.trim().is_empty() {
            "Général".to_string()
        } else {
            target_folder.trim().to_string()
        };
        let mut count = 0;
        for s in &mut self.sessions {
            if ids.contains(&s.id) {
                s.folder = target.clone();
                count += 1;
            }
        }
        if count > 0 {
            let _ = self.save();
        }
        count
    }

    /// Returns a sorted list of unique tags across all sessions.
    pub fn all_tags(&self) -> Vec<String> {
        let mut set = std::collections::BTreeSet::new();
        for s in &self.sessions {
            for tag in &s.tags {
                let trimmed = tag.trim();
                if !trimmed.is_empty() {
                    set.insert(trimmed.to_string());
                }
            }
        }
        set.into_iter().collect()
    }

    /// Adds a tag to multiple sessions.
    pub fn add_tag_to_sessions(&mut self, ids: &[Uuid], tag: &str) -> usize {
        let tag_clean = tag.trim();
        if tag_clean.is_empty() {
            return 0;
        }
        let mut count = 0;
        for s in &mut self.sessions {
            if ids.contains(&s.id) && !s.tags.iter().any(|t| t.eq_ignore_ascii_case(tag_clean)) {
                s.tags.push(tag_clean.to_string());
                count += 1;
            }
        }
        if count > 0 {
            let _ = self.save();
        }
        count
    }

    /// Removes a tag from multiple sessions.
    pub fn remove_tag_from_sessions(&mut self, ids: &[Uuid], tag: &str) -> usize {
        let tag_clean = tag.trim();
        if tag_clean.is_empty() {
            return 0;
        }
        let mut count = 0;
        for s in &mut self.sessions {
            if ids.contains(&s.id) {
                let before = s.tags.len();
                s.tags.retain(|t| !t.eq_ignore_ascii_case(tag_clean));
                if s.tags.len() < before {
                    count += 1;
                }
            }
        }
        if count > 0 {
            let _ = self.save();
        }
        count
    }

    /// Exports selected sessions (or all if filter_ids is None) to a formatted JSON string.
    pub fn export_sessions_json(
        &self,
        filter_ids: Option<&[Uuid]>,
    ) -> Result<String, serde_json::Error> {
        let export_list: Vec<&SessionProfile> = match filter_ids {
            Some(ids) => self
                .sessions
                .iter()
                .filter(|s| ids.contains(&s.id))
                .collect(),
            None => self.sessions.iter().collect(),
        };
        serde_json::to_string_pretty(&export_list)
    }

    /// Imports sessions from a JSON string (either `Vec<SessionProfile>` or full `AppConfig`).
    /// Generates new UUIDs for collisions and adds new sessions.
    pub fn import_sessions_json(&mut self, json_str: &str) -> Result<usize, String> {
        let imported_sessions: Vec<SessionProfile> =
            if let Ok(list) = serde_json::from_str::<Vec<SessionProfile>>(json_str) {
                list
            } else if let Ok(cfg) = serde_json::from_str::<AppConfig>(json_str) {
                cfg.sessions
            } else {
                return Err(
                "Format JSON non reconnu (attendu : liste de sessions ou configuration Cuty-SSH)"
                    .to_string(),
            );
            };

        if imported_sessions.is_empty() {
            return Ok(0);
        }

        let mut count = 0;
        let mut existing_ids: std::collections::HashSet<Uuid> =
            self.sessions.iter().map(|s| s.id).collect();

        for mut s in imported_sessions {
            if s.name.trim().is_empty() {
                continue;
            }
            if existing_ids.contains(&s.id) {
                s.id = Uuid::new_v4();
            }
            existing_ids.insert(s.id);
            self.sessions.push(s);
            count += 1;
        }

        if count > 0 {
            let _ = self.save();
        }
        Ok(count)
    }

    /// Imports SSH sessions from `~/.ssh/config` (or a custom OpenSSH config path).
    pub fn import_from_openssh_config(
        &mut self,
        custom_path: Option<&Path>,
    ) -> anyhow::Result<usize> {
        let path = custom_path
            .map(PathBuf::from)
            .unwrap_or_else(default_openssh_config_path);
        if !path.exists() {
            anyhow::bail!("OpenSSH config file not found at {:?}", path);
        }
        let content = fs::read_to_string(&path)?;
        let parsed = parse_openssh_config_content(&content);
        if parsed.is_empty() {
            return Ok(0);
        }

        let mut added = 0;
        for profile in parsed {
            let already_exists = self.sessions.iter().any(|s| {
                s.name == profile.name && s.host == profile.host && s.port == profile.port
            });
            if !already_exists {
                self.sessions.push(profile);
                added += 1;
            }
        }
        if added > 0 {
            let _ = self.save();
        }
        Ok(added)
    }

    /// Resolves the path to `known_hosts.json` next to `config.json`.
    pub fn known_hosts_path() -> PathBuf {
        let cfg_path = Self::portable_config_path();
        if let Some(parent) = cfg_path.parent() {
            parent.join("known_hosts.json")
        } else {
            PathBuf::from("known_hosts.json")
        }
    }
}

/// Splits PuTTY `user@host` syntax in `HostName` into `(username, host)`.
/// If `existing_user` is non-empty, it takes precedence over the prefix in `raw_host`.
pub fn split_user_and_host(raw_host: &str, existing_user: &str) -> (String, String) {
    let trimmed_host = raw_host.trim();
    let trimmed_user = existing_user.trim();
    if let Some((prefix_user, host_part)) = trimmed_host.rsplit_once('@') {
        let final_user = if trimmed_user.is_empty() {
            prefix_user.trim().to_string()
        } else {
            trimmed_user.to_string()
        };
        (final_user, host_part.trim().to_string())
    } else {
        (trimmed_user.to_string(), trimmed_host.to_string())
    }
}

pub fn url_encode_session_name(name: &str) -> String {
    let mut out = String::with_capacity(name.len());
    for b in name.bytes() {
        if b.is_ascii_alphanumeric() || b == b'-' || b == b'_' || b == b'.' {
            out.push(char::from(b));
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

pub fn url_decode_session_name(encoded: &str) -> String {
    let mut bytes = Vec::with_capacity(encoded.len());
    let raw = encoded.as_bytes();
    let mut i = 0;
    while i < raw.len() {
        if raw[i] == b'%'
            && i + 2 < raw.len()
            && let Ok(hex_str) = std::str::from_utf8(&raw[i + 1..i + 3])
            && let Ok(val) = u8::from_str_radix(hex_str, 16)
        {
            bytes.push(val);
            i += 3;
            continue;
        }
        bytes.push(raw[i]);
        i += 1;
    }
    String::from_utf8_lossy(&bytes).to_string()
}

pub fn export_session_to_ini(s: &SessionProfile) -> String {
    let proto = match s.protocol {
        ProtocolType::Ssh => "ssh",
        ProtocolType::Telnet => "telnet",
        ProtocolType::RawTcp => "raw",
        ProtocolType::LocalShell => "cygterm",
    };
    let ppk_path = match &s.ssh_auth {
        SshAuthMethod::PrivateKeyFile { key_path, .. } => key_path.as_str(),
        _ => "",
    };
    format!(
        "HostName\\{}\\\nPortNumber\\{}\\\nProtocol\\{}\\\nUserName\\{}\\\nPublicKeyFile\\{}\\\nRemoteCommand\\{}\\\nFolder\\{}\\\nPingIntervalSecs\\{}\\\nCompression\\{}\\\n",
        s.host,
        s.port,
        proto,
        s.username,
        ppk_path,
        s.startup_command,
        s.folder,
        s.keepalive_secs,
        u8::from(s.compression)
    )
}

/// Returns the default path to the user's `~/.ssh/config` file.
pub fn default_openssh_config_path() -> PathBuf {
    if let Ok(profile) = std::env::var("USERPROFILE") {
        PathBuf::from(profile).join(".ssh").join("config")
    } else {
        PathBuf::from(".ssh").join("config")
    }
}

fn expand_tilde_path(raw: &str) -> String {
    let trimmed = raw.trim().trim_matches('"');
    if let Some(rest) = trimmed
        .strip_prefix("~/")
        .or_else(|| trimmed.strip_prefix("~\\"))
        && let Ok(profile) = std::env::var("USERPROFILE")
    {
        return PathBuf::from(profile)
            .join(rest)
            .to_string_lossy()
            .to_string();
    }
    trimmed.to_string()
}

/// Parses standard OpenSSH `~/.ssh/config` text into `SessionProfile` items.
pub fn parse_openssh_config_content(content: &str) -> Vec<SessionProfile> {
    let mut profiles = Vec::new();
    let mut current_aliases: Vec<String> = Vec::new();
    let mut hostname = String::new();
    let mut user = String::new();
    let mut port: u16 = 22;
    let mut identity_file = String::new();
    let mut proxy_jump = String::new();
    let mut forward_agent = false;
    let mut compression = true;
    let mut keepalive: u32 = 30;
    let mut port_forwards: Vec<PortForwardRule> = Vec::new();

    let flush_current = |aliases: &[String],
                         hostname: &str,
                         user: &str,
                         port: u16,
                         identity_file: &str,
                         proxy_jump: &str,
                         forward_agent: bool,
                         compression: bool,
                         keepalive: u32,
                         port_forwards: &[PortForwardRule],
                         out: &mut Vec<SessionProfile>| {
        for alias in aliases {
            if alias.is_empty() || alias.contains('*') || alias.contains('?') {
                continue;
            }
            let effective_host = if hostname.is_empty() {
                alias.clone()
            } else {
                hostname.to_string()
            };
            let effective_user = if user.is_empty() {
                std::env::var("USERNAME").unwrap_or_else(|_| "root".to_string())
            } else {
                user.to_string()
            };
            let ssh_auth = if !identity_file.is_empty() {
                SshAuthMethod::PrivateKeyFile {
                    key_path: expand_tilde_path(identity_file),
                    passphrase: String::new(),
                    cert_path: String::new(),
                }
            } else {
                SshAuthMethod::Agent {
                    use_pageant: true,
                    use_openssh_agent: true,
                }
            };
            let mut tags = vec!["ssh-config".to_string()];
            if !proxy_jump.is_empty() {
                tags.push("bastion".to_string());
            }
            out.push(SessionProfile {
                id: Uuid::new_v4(),
                name: alias.clone(),
                folder: "OpenSSH Config".to_string(),
                icon_badge: "🔐".to_string(),
                protocol: ProtocolType::Ssh,
                host: effective_host,
                port,
                username: effective_user,
                ssh_auth,
                try_pageant: true,
                agent_forwarding: forward_agent,
                compression,
                keepalive_secs: keepalive,
                port_forwards: port_forwards.to_vec(),
                proxy_jump: proxy_jump.to_string(),
                tags,
                ..Default::default()
            });
        }
    };

    for raw_line in content.lines() {
        let line = raw_line.split('#').next().unwrap_or("").trim();
        if line.is_empty() {
            continue;
        }
        let Some((key, val)) = line.split_once([' ', '\t', '=']) else {
            continue;
        };
        let key_lower = key.trim().to_ascii_lowercase();
        let val = val.trim().trim_start_matches('=').trim();

        match key_lower.as_str() {
            "host" => {
                flush_current(
                    &current_aliases,
                    &hostname,
                    &user,
                    port,
                    &identity_file,
                    &proxy_jump,
                    forward_agent,
                    compression,
                    keepalive,
                    &port_forwards,
                    &mut profiles,
                );
                current_aliases = val
                    .split_whitespace()
                    .map(|s| s.trim().to_string())
                    .collect();
                hostname.clear();
                user.clear();
                port = 22;
                identity_file.clear();
                proxy_jump.clear();
                forward_agent = false;
                compression = true;
                keepalive = 30;
                port_forwards.clear();
            }
            "hostname" => hostname = val.to_string(),
            "user" => user = val.to_string(),
            "port" => {
                if let Ok(p) = val.parse::<u16>() {
                    port = p;
                }
            }
            "identityfile" => {
                if identity_file.is_empty() {
                    identity_file = val.to_string();
                }
            }
            "proxyjump" => proxy_jump = val.to_string(),
            "forwardagent" => forward_agent = val.eq_ignore_ascii_case("yes"),
            "compression" => compression = val.eq_ignore_ascii_case("yes"),
            "serveraliveinterval" => {
                if let Ok(s) = val.parse::<u32>() {
                    keepalive = s;
                }
            }
            "localforward" => {
                if let Some(rule) = parse_ssh_config_forward(val, PortForwardType::Local) {
                    port_forwards.push(rule);
                }
            }
            "remoteforward" => {
                if let Some(rule) = parse_ssh_config_forward(val, PortForwardType::Remote) {
                    port_forwards.push(rule);
                }
            }
            _ => {}
        }
    }

    flush_current(
        &current_aliases,
        &hostname,
        &user,
        port,
        &identity_file,
        &proxy_jump,
        forward_agent,
        compression,
        keepalive,
        &port_forwards,
        &mut profiles,
    );

    profiles
}

/// Reads a big-endian `u32` length-prefixed string at `*o`.
fn read_be_string(b: &[u8], o: &mut usize) -> Option<String> {
    let len = u32::from_be_bytes(b.get(*o..*o + 4)?.try_into().ok()?) as usize;
    let raw = b.get(*o + 4..(*o + 4).checked_add(len)?)?;
    *o += 4 + len;
    Some(String::from_utf8_lossy(raw).to_string())
}

/// Extracts the connection settings of a Bitvise SSH Client profile (`.tlp` / `.bscp`).
///
/// The format is not documented by Bitvise: the layout below was derived by comparing profiles
/// saved from the user's own installation (9.66) with known host/port/user values. After the
/// `Tunnelier x.y` banner come eight `u32` + one `u16`, then the host (length-prefixed string),
/// the SSH port (`u32`), 11 zero bytes and the user name (length-prefixed string; empty when
/// the profile has none). Everything else (algorithms, forwardings, secrets) is ignored.
pub fn parse_bitvise_profile(bytes: &[u8], name: &str) -> Result<SessionProfile, String> {
    let mut o = 0usize;
    let banner = read_be_string(bytes, &mut o).ok_or("not a Bitvise profile (too short)")?;
    if !banner.starts_with("Tunnelier ") && !banner.starts_with("Bitvise") {
        return Err("not a Bitvise profile (unknown header)".to_string());
    }
    o += 8 * 4 + 2;
    let host = read_be_string(bytes, &mut o)
        .filter(|h| !h.is_empty() && h.len() <= 253 && h.bytes().all(|c| c.is_ascii_graphic()))
        .ok_or("host not found in this profile layout")?;
    let port_raw = bytes
        .get(o..o + 4)
        .ok_or("port not found")?
        .try_into()
        .map(u32::from_be_bytes)
        .map_err(|_| "port not found".to_string())?;
    o += 4;
    let port = u16::try_from(port_raw)
        .ok()
        .filter(|p| *p != 0)
        .unwrap_or(22);

    // The user name is a length-prefixed string a few zero bytes after the port. Lengths are
    // small, so the first non-zero byte is the low byte of the length word.
    let mut username = String::new();
    if let Some(q) = bytes
        .iter()
        .enumerate()
        .skip(o)
        .take(32)
        .find_map(|(i, b)| (*b != 0).then_some(i))
        && q >= o + 3
    {
        let len = bytes[q] as usize;
        if len <= 64
            && let Some(raw) = bytes.get(q + 1..q + 1 + len)
            && raw.iter().all(|c| c.is_ascii_graphic())
        {
            username = String::from_utf8_lossy(raw).to_string();
        }
    }

    Ok(SessionProfile {
        name: name.to_string(),
        protocol: ProtocolType::Ssh,
        host,
        port,
        username,
        ..Default::default()
    })
}

fn parse_ssh_config_forward(val: &str, forward_type: PortForwardType) -> Option<PortForwardRule> {
    let parts: Vec<&str> = val.split_whitespace().collect();
    if parts.len() < 2 {
        return None;
    }
    let (bind_address, bind_port_str) = if let Some((addr, p)) = parts[0].rsplit_once(':') {
        (addr.to_string(), p)
    } else {
        ("127.0.0.1".to_string(), parts[0])
    };
    let bind_port = bind_port_str.parse::<u16>().ok()?;
    let (target_host, target_port_str) = parts[1].rsplit_once(':')?;
    let target_port = target_port_str.parse::<u16>().ok()?;
    Some(PortForwardRule {
        enabled: true,
        forward_type,
        bind_address,
        bind_port,
        target_host: target_host.to_string(),
        target_port,
    })
}

/// Loads all stored SSH host keys from `known_hosts.json`.
pub fn load_known_hosts() -> Vec<KnownHostEntry> {
    let path = AppConfig::known_hosts_path();
    if path.exists()
        && let Ok(data) = fs::read_to_string(&path)
        && let Ok(entries) = serde_json::from_str::<Vec<KnownHostEntry>>(&data)
    {
        return entries;
    }
    Vec::new()
}

/// Persists the SSH `known_hosts` list to `known_hosts.json`.
pub fn save_known_hosts(entries: &[KnownHostEntry]) -> anyhow::Result<()> {
    let path = AppConfig::known_hosts_path();
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let json = serde_json::to_string_pretty(entries)?;
    fs::write(path, json)?;
    Ok(())
}

/// Verifies a server's SSH host key against a slice of `KnownHostEntry` items (in-memory TOFU logic).
pub fn verify_or_record_known_host_in_list(
    entries: &mut Vec<KnownHostEntry>,
    host: &str,
    port: u16,
    algorithm: &str,
    fingerprint_sha256: &str,
    public_key_base64: &str,
) -> HostKeyCheckResult {
    let host_port = if port == 22 {
        host.trim().to_lowercase()
    } else {
        format!("[{}]:{}", host.trim().to_lowercase(), port)
    };
    let now = chrono::Local::now().format("%Y-%m-%d %H:%M:%S").to_string();

    if let Some(existing) = entries.iter_mut().find(|e| e.host_port == host_port) {
        if existing.fingerprint_sha256 == fingerprint_sha256 {
            existing.last_seen = now;
            HostKeyCheckResult::TrustedMatch {
                fingerprint: fingerprint_sha256.to_string(),
                algorithm: algorithm.to_string(),
            }
        } else {
            HostKeyCheckResult::Mismatch {
                expected_fingerprint: existing.fingerprint_sha256.clone(),
                actual_fingerprint: fingerprint_sha256.to_string(),
                algorithm: algorithm.to_string(),
            }
        }
    } else {
        entries.push(KnownHostEntry {
            host_port,
            algorithm: algorithm.to_string(),
            fingerprint_sha256: fingerprint_sha256.to_string(),
            public_key_base64: public_key_base64.to_string(),
            first_seen: now.clone(),
            last_seen: now,
        });
        HostKeyCheckResult::NewlyTrusted {
            fingerprint: fingerprint_sha256.to_string(),
            algorithm: algorithm.to_string(),
        }
    }
}

/// Verifies a server's SSH host key against `known_hosts.json` on disk (TOFU).
pub fn verify_or_record_known_host(
    host: &str,
    port: u16,
    algorithm: &str,
    fingerprint_sha256: &str,
    public_key_base64: &str,
) -> HostKeyCheckResult {
    let mut entries = load_known_hosts();
    let result = verify_or_record_known_host_in_list(
        &mut entries,
        host,
        port,
        algorithm,
        fingerprint_sha256,
        public_key_base64,
    );
    if !matches!(result, HostKeyCheckResult::Mismatch { .. }) {
        let _ = save_known_hosts(&entries);
    }
    result
}

/// Removes a host entry from `known_hosts.json` (e.g., to accept a newly reinstalled server's key).
pub fn remove_known_host(host_port: &str) -> bool {
    let mut entries = load_known_hosts();
    let before = entries.len();
    entries.retain(|e| e.host_port != host_port);
    let removed = entries.len() < before;
    if removed {
        let _ = save_known_hosts(&entries);
    }
    removed
}

/// An entry in the local Cuty-SSH session & connection audit trail.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditLogEntry {
    pub id: Uuid,
    pub timestamp_rfc3339: String,
    #[serde(default)]
    pub session_id: Option<Uuid>,
    pub session_name: String,
    pub protocol: ProtocolType,
    pub target: String,
    /// Event type: "CONNECT", "DISCONNECT", "ERROR", "DEPLOY_KEY"
    pub event_type: String,
    #[serde(default)]
    pub duration_secs: Option<u64>,
    #[serde(default)]
    pub details: String,
}

impl AppConfig {
    /// Resolves the path to `cuty-ssh-portable/audit_log.json`.
    pub fn audit_log_path() -> PathBuf {
        Self::portable_config_path()
            .parent()
            .map(|p| p.join("audit_log.json"))
            .unwrap_or_else(|| PathBuf::from("cuty-ssh-portable").join("audit_log.json"))
    }
}

/// Loads all audit trail entries from `audit_log.json`.
pub fn load_audit_log() -> Vec<AuditLogEntry> {
    let path = AppConfig::audit_log_path();
    if path.exists()
        && let Ok(data) = fs::read_to_string(&path)
        && let Ok(entries) = serde_json::from_str::<Vec<AuditLogEntry>>(&data)
    {
        return entries;
    }
    Vec::new()
}

/// Appends a new audit record to `audit_log.json`.
pub fn append_audit_entry(entry: AuditLogEntry) {
    let path = AppConfig::audit_log_path();
    if let Some(parent) = path.parent() {
        let _ = fs::create_dir_all(parent);
    }
    let mut entries = load_audit_log();
    entries.push(entry);
    // Keep the most recent 10,000 entries to prevent unbounded growth
    if entries.len() > 10_000 {
        entries.drain(0..entries.len() - 10_000);
    }
    if let Ok(json) = serde_json::to_string_pretty(&entries) {
        let tmp = path.with_extension("tmp");
        if fs::write(&tmp, json).is_ok() {
            let _ = fs::rename(tmp, path);
        }
    }
}

/// Clears the entire local audit trail.
pub fn clear_audit_log() -> bool {
    let path = AppConfig::audit_log_path();
    if path.exists() {
        fs::remove_file(path).is_ok()
    } else {
        true
    }
}

/// Formats audit entries as a standard CSV string.
pub fn export_audit_csv(entries: &[AuditLogEntry]) -> String {
    let mut csv = String::from("ID,Timestamp,Session,Protocol,Target,Event,DurationSecs,Details\n");
    for e in entries {
        let dur = e.duration_secs.map(|d| d.to_string()).unwrap_or_default();
        let safe_name = e.session_name.replace('"', "\"\"");
        let safe_target = e.target.replace('"', "\"\"");
        let safe_details = e.details.replace('"', "\"\"");
        csv.push_str(&format!(
            "\"{}\",\"{}\",\"{}\",\"{}\",\"{}\",\"{}\",\"{}\",\"{}\"\n",
            e.id,
            e.timestamp_rfc3339,
            safe_name,
            e.protocol.label(),
            safe_target,
            e.event_type,
            dur,
            safe_details
        ));
    }
    csv
}

/// Encrypts a sensitive credential string using Windows DPAPI (`CryptProtectData`), returning `"dpapi:<base64>"`.
pub fn dpapi_encrypt(plaintext: &str) -> String {
    if plaintext.is_empty() || plaintext.starts_with("dpapi:") {
        return plaintext.to_string();
    }
    #[cfg(windows)]
    {
        use base64::Engine as _;
        use std::ptr;
        use windows_sys::Win32::Foundation::LocalFree;
        use windows_sys::Win32::Security::Cryptography::{
            CRYPT_INTEGER_BLOB, CRYPTPROTECT_UI_FORBIDDEN, CryptProtectData,
        };

        let bytes = plaintext.as_bytes();
        let in_blob = CRYPT_INTEGER_BLOB {
            cbData: bytes.len() as u32,
            pbData: bytes.as_ptr() as *mut u8,
        };
        let mut out_blob = CRYPT_INTEGER_BLOB {
            cbData: 0,
            pbData: ptr::null_mut(),
        };

        // SAFETY: `in_blob` points to valid UTF-8 bytes for the duration of the call, and `out_blob.pbData`
        // allocated by Windows is copied and freed immediately with `LocalFree`.
        unsafe {
            let ok = CryptProtectData(
                &in_blob,
                ptr::null(),
                ptr::null(),
                ptr::null_mut(),
                ptr::null(),
                CRYPTPROTECT_UI_FORBIDDEN,
                &mut out_blob,
            );
            if ok != 0 && !out_blob.pbData.is_null() {
                let slice = std::slice::from_raw_parts(out_blob.pbData, out_blob.cbData as usize);
                let encoded = base64::engine::general_purpose::STANDARD.encode(slice);
                LocalFree(out_blob.pbData as *mut _);
                return format!("dpapi:{encoded}");
            }
        }
    }
    plaintext.to_string()
}

/// Decrypts a `"dpapi:<base64>"` credential string using Windows DPAPI (`CryptUnprotectData`).
/// Plaintext strings without the `"dpapi:"` prefix are returned unchanged for backward compatibility.
pub fn dpapi_decrypt(stored: &str) -> String {
    let Some(b64) = stored.strip_prefix("dpapi:") else {
        return stored.to_string();
    };
    #[cfg(windows)]
    {
        use base64::Engine as _;
        use std::ptr;
        use windows_sys::Win32::Foundation::LocalFree;
        use windows_sys::Win32::Security::Cryptography::{
            CRYPT_INTEGER_BLOB, CRYPTPROTECT_UI_FORBIDDEN, CryptUnprotectData,
        };
        use zeroize::Zeroize;

        if let Ok(mut cipher_bytes) = base64::engine::general_purpose::STANDARD.decode(b64) {
            let in_blob = CRYPT_INTEGER_BLOB {
                cbData: cipher_bytes.len() as u32,
                pbData: cipher_bytes.as_mut_ptr(),
            };
            let mut out_blob = CRYPT_INTEGER_BLOB {
                cbData: 0,
                pbData: ptr::null_mut(),
            };

            // SAFETY: `in_blob` points to valid decoded bytes, and `out_blob.pbData` is freed via `LocalFree`.
            unsafe {
                let ok = CryptUnprotectData(
                    &in_blob,
                    ptr::null_mut(),
                    ptr::null(),
                    ptr::null_mut(),
                    ptr::null(),
                    CRYPTPROTECT_UI_FORBIDDEN,
                    &mut out_blob,
                );
                cipher_bytes.zeroize();
                if ok != 0 && !out_blob.pbData.is_null() {
                    let slice =
                        std::slice::from_raw_parts(out_blob.pbData, out_blob.cbData as usize);
                    let plain = String::from_utf8_lossy(slice).to_string();
                    LocalFree(out_blob.pbData as *mut _);
                    return plain;
                }
            }
        }
    }
    String::new()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dpapi_encrypt_decrypt_roundtrip() {
        let secret = "S3cr3t_P@ssw0rd!2026";
        let encrypted = dpapi_encrypt(secret);
        assert!(encrypted.starts_with("dpapi:"));
        assert_ne!(encrypted, secret);

        let decrypted = dpapi_decrypt(&encrypted);
        assert_eq!(decrypted, secret);

        // Plaintext fallback for legacy unencrypted strings
        assert_eq!(dpapi_decrypt("legacy_plain"), "legacy_plain");
    }

    #[test]
    fn test_parse_openssh_config() {
        let sample = r#"
# Global wildcard should be ignored
Host *
    ServerAliveInterval 60

Host bastion-prod
    HostName 203.0.113.10
    User jumpuser
    Port 2222
    IdentityFile ~/.ssh/id_ed25519

Host app-internal db-internal
    HostName 10.10.0.50
    User ubuntu
    ProxyJump bastion-prod
    LocalForward 127.0.0.1:5432 10.10.0.60:5432
"#;
        let profiles = parse_openssh_config_content(sample);
        assert_eq!(profiles.len(), 3);
        assert_eq!(profiles[0].name, "bastion-prod");
        assert_eq!(profiles[0].host, "203.0.113.10");
        assert_eq!(profiles[0].username, "jumpuser");
        assert_eq!(profiles[0].port, 2222);

        assert_eq!(profiles[1].name, "app-internal");
        assert_eq!(profiles[1].proxy_jump, "bastion-prod");
        assert_eq!(profiles[1].port_forwards.len(), 1);
        assert_eq!(profiles[1].port_forwards[0].bind_port, 5432);
    }

    #[test]
    fn test_known_hosts_tofu_verification() {
        let mut store = Vec::new();
        let r1 = verify_or_record_known_host_in_list(
            &mut store,
            "192.168.1.50",
            22,
            "ssh-ed25519",
            "SHA256:abc123xyz",
            "AAAAC3NzaC1lZDI1NTE5AAAA",
        );
        assert!(matches!(r1, HostKeyCheckResult::NewlyTrusted { .. }));
        assert_eq!(store.len(), 1);

        let r2 = verify_or_record_known_host_in_list(
            &mut store,
            "192.168.1.50",
            22,
            "ssh-ed25519",
            "SHA256:abc123xyz",
            "AAAAC3NzaC1lZDI1NTE5AAAA",
        );
        assert!(matches!(r2, HostKeyCheckResult::TrustedMatch { .. }));

        let r3 = verify_or_record_known_host_in_list(
            &mut store,
            "192.168.1.50",
            22,
            "ssh-ed25519",
            "SHA256:DIFFERENT_MITM_KEY",
            "AAAAC3NzaC1lZDI1NTE5BBBB",
        );
        assert!(matches!(r3, HostKeyCheckResult::Mismatch { .. }));
    }

    #[test]
    fn test_audit_log_csv_export() {
        let entries = vec![AuditLogEntry {
            id: Uuid::new_v4(),
            timestamp_rfc3339: "2026-10-18T14:30:00Z".to_string(),
            session_id: None,
            session_name: "Prod Bastion".to_string(),
            protocol: ProtocolType::Ssh,
            target: "bastion.example.com:22".to_string(),
            event_type: "CONNECT".to_string(),
            duration_secs: Some(3600),
            details: "Logged in via Ed25519 key".to_string(),
        }];

        let csv = export_audit_csv(&entries);
        assert!(csv.contains("Prod Bastion"));
        assert!(csv.contains("CONNECT"));
        assert!(csv.contains("3600"));
        assert!(csv.contains("bastion.example.com:22"));
    }

    #[test]
    fn test_edge_gateway_preset_defaults() {
        let p = SessionProfile::default();
        assert_eq!(p.edge_preset, EdgeGatewayPreset::None);
        assert_eq!(p.shellhub_server, "ssh.shellhub.io");
        assert_eq!(p.shellhub_device_id, "");
    }

    #[test]
    fn bitvise_profile_host_port_user_are_extracted() {
        fn be_str(s: &str) -> Vec<u8> {
            let mut v = (s.len() as u32).to_be_bytes().to_vec();
            v.extend_from_slice(s.as_bytes());
            v
        }
        let build = |host: &str, port: u32, user: &str| {
            let mut b = be_str("Tunnelier 9.66");
            b.extend_from_slice(&[0u8; 8 * 4 + 2]);
            b.extend(be_str(host));
            b.extend_from_slice(&port.to_be_bytes());
            b.extend_from_slice(&[0u8; 11]);
            b.extend(be_str(user));
            b.extend_from_slice(&[0u8; 16]);
            b
        };
        let p = parse_bitvise_profile(&build("alpha.example.com", 2222, "alice"), "alpha").unwrap();
        assert_eq!(
            (
                p.name.as_str(),
                p.host.as_str(),
                p.port,
                p.username.as_str()
            ),
            ("alpha", "alpha.example.com", 2222, "alice")
        );
        let p = parse_bitvise_profile(&build("10.1.2.3", 22, "bob"), "beta").unwrap();
        assert_eq!(
            (p.host.as_str(), p.port, p.username.as_str()),
            ("10.1.2.3", 22, "bob")
        );
        let p = parse_bitvise_profile(&build("h", 0, ""), "empty").unwrap();
        assert_eq!((p.port, p.username.as_str()), (22, ""));
        assert!(parse_bitvise_profile(b"{\"json\": true}", "x").is_err());
        assert!(parse_bitvise_profile(&be_str("Tunnelier 9.66"), "x").is_err());
    }

    #[test]
    fn import_from_kitty_dir_reads_sessions_and_skips_duplicates() {
        let dir = std::env::temp_dir().join(format!("cuty_kitty_{}", Uuid::new_v4()));
        let sessions = dir.join("Sessions");
        fs::create_dir_all(&sessions).unwrap();
        fs::write(
            sessions.join("BI-BDD1%20-%20Maria"),
            "Folder|Default|\nPublicKeyFile|D%3A%5Ck.ppk|\nPortNumber|2222|\nProtocol|ssh|\nHostName|root@10.0.0.1|\n"
                .replace('|', &'\u{5c}'.to_string()),
        )
        .unwrap();
        fs::write(
            sessions.join("Default%20Settings"),
            "HostName|x|\n".replace('|', &'\u{5c}'.to_string()),
        )
        .unwrap();
        let mut cfg = AppConfig {
            sessions: vec![],
            ..Default::default()
        };
        assert_eq!(cfg.import_from_kitty_dir(&dir).unwrap_or(0), 1);
        let s = &cfg.sessions[0];
        assert_eq!(s.name, "BI-BDD1 - Maria");
        assert_eq!(
            (s.host.as_str(), s.username.as_str(), s.port),
            ("10.0.0.1", "root", 2222)
        );
        assert!(
            matches!(&s.ssh_auth, SshAuthMethod::PrivateKeyFile { key_path, .. } if key_path == r"D:\k.ppk")
        );
        assert_eq!(cfg.import_from_kitty_dir(&dir).unwrap_or(0), 0);
        let _ = fs::remove_dir_all(&dir);
    }
}
