use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use uuid::Uuid;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ProtocolType {
    Ssh,
    Telnet,
    RawTcp,
    LocalShell,
}

impl ProtocolType {
    pub fn label(&self) -> &'static str {
        match self {
            ProtocolType::Ssh => "SSH2",
            ProtocolType::Telnet => "Telnet",
            ProtocolType::RawTcp => "Raw TCP",
            ProtocolType::LocalShell => "Shell Local (ConPTY)",
        }
    }

    pub fn badge(&self) -> &'static str {
        match self {
            ProtocolType::Ssh => "🔐 SSH",
            ProtocolType::Telnet => "🖧 Telnet",
            ProtocolType::RawTcp => "🔌 Raw",
            ProtocolType::LocalShell => "💻 Local",
        }
    }

    pub fn default_port(&self) -> u16 {
        match self {
            ProtocolType::Ssh => 22,
            ProtocolType::Telnet => 23,
            ProtocolType::RawTcp => 80,
            ProtocolType::LocalShell => 0,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SshAuthMethod {
    /// Mot de passe (interactif ou automatique KiTTY)
    Password,
    /// Fichier clé privée PuTTY (.ppk v2/v3), OpenSSH, PEM ou PKCS#8
    PrivateKeyFile {
        key_path: String,
        passphrase: String,
        cert_path: String,
    },
    /// Agent SSH Windows : Pageant (PuTTY) ou OpenSSH Agent
    Agent {
        use_pageant: bool,
        use_openssh_agent: bool,
    },
    /// Authentification Keyboard-Interactive (PAM / 2FA)
    KeyboardInteractive,
}

impl Default for SshAuthMethod {
    fn default() -> Self {
        Self::Password
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExpectRule {
    pub enabled: bool,
    pub trigger_prompt: String,
    pub send_response: String,
    pub delay_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum PortForwardType {
    Local,
    Remote,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PortForwardRule {
    pub enabled: bool,
    pub forward_type: PortForwardType,
    pub bind_address: String,
    pub bind_port: u16,
    pub target_host: String,
    pub target_port: u16,
}

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

    // Fonctionnalités d'automatisation KiTTY
    pub auto_login: bool,
    pub auto_password: bool,
    pub startup_command: String,
    pub local_script_path: String,
    pub logon_expect_rules: Vec<ExpectRule>,
    pub keepalive_secs: u32,
    pub anti_idle_string: String,
    pub compression: bool,
    pub port_forwards: Vec<PortForwardRule>,

    // Apparence & ergonomie par session
    pub theme_name: String,
    pub font_size: f32,
    pub scrollback_lines: usize,
    pub transparency: u8,
    pub always_on_top: bool,
    pub read_only: bool,
    pub log_to_file: bool,
    pub notes: String,
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
            theme_name: "KiTTY Dark".to_string(),
            font_size: 14.5,
            scrollback_lines: 10_000,
            transparency: 255,
            always_on_top: false,
            read_only: false,
            log_to_file: false,
            notes: String::new(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PredefinedCommand {
    pub id: Uuid,
    pub label: String,
    pub category: String,
    pub command: String,
    pub append_enter: bool,
    pub description: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppConfig {
    pub portable_mode: bool,
    pub pageant_path: String,
    pub winscp_path: String,
    pub default_key_dir: String,
    pub copy_on_select: bool,
    pub right_click_paste: bool,
    pub detect_hyperlinks: bool,
    pub global_transparency: u8,
    pub global_always_on_top: bool,
    pub show_command_bar: bool,
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
            copy_on_select: true,
            right_click_paste: true,
            detect_hyperlinks: true,
            global_transparency: 255,
            global_always_on_top: false,
            show_command_bar: true,
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
            theme_name: "KiTTY Dark".to_string(),
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
            theme_name: "KiTTY Dark".to_string(),
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
    /// Emplacement portable du fichier de configuration (à côté de l'exécutable ou dans le dossier courant)
    pub fn portable_config_path() -> PathBuf {
        let local_path = PathBuf::from("cuty-ssh-portable").join("config.json");
        if local_path.parent().map(|p| p.exists()).unwrap_or(false) {
            return local_path;
        }
        if let Ok(exe) = std::env::current_exe() {
            if let Some(dir) = exe.parent() {
                let candidate = dir.join("cuty-ssh-portable").join("config.json");
                if candidate.exists() {
                    return candidate;
                }
            }
        }
        local_path
    }

    pub fn load_or_default() -> Self {
        let path = Self::portable_config_path();
        if path.exists() {
            if let Ok(data) = fs::read_to_string(&path) {
                if let Ok(cfg) = serde_json::from_str::<AppConfig>(&data) {
                    return cfg;
                }
            }
        }
        let cfg = Self::default();
        let _ = cfg.save();
        cfg
    }

    pub fn save(&self) -> anyhow::Result<()> {
        let path = Self::portable_config_path();
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        let json = serde_json::to_string_pretty(self)?;
        fs::write(&path, json)?;

        // Sauvegarde également au format compatible KiTTY portable (Sessions/) si mode portable actif
        if self.portable_mode {
            if let Some(parent) = path.parent() {
                let sessions_dir = parent.join("Sessions");
                let _ = fs::create_dir_all(&sessions_dir);
                for s in &self.sessions {
                    let safe_name = url_encode_session_name(&s.name);
                    let session_file = sessions_dir.join(safe_name);
                    let _ = fs::write(session_file, export_session_to_kitty_ini(s));
                }
            }
        }
        Ok(())
    }

    /// Importe automatiquement les sessions depuis le Registre Windows de PuTTY et KiTTY
    #[cfg(windows)]
    pub fn import_from_windows_registry(&mut self) -> anyhow::Result<usize> {
        use winreg::RegKey;
        use winreg::enums::*;

        let hkcu = RegKey::predef(HKEY_CURRENT_USER);
        let mut imported_count = 0;

        let reg_paths = [
            (r"Software\9bis.com\KiTTY\Sessions", "Import KiTTY"),
            (r"Software\SimonTatham\PuTTY\Sessions", "Import PuTTY"),
        ];

        for (base_path, default_folder) in reg_paths {
            if let Ok(sessions_key) = hkcu.open_subkey(base_path) {
                for subkey_name in sessions_key.enum_keys().flatten() {
                    if subkey_name == "Default%20Settings" {
                        continue;
                    }
                    if let Ok(subkey) = sessions_key.open_subkey(&subkey_name) {
                        let decoded_name = url_decode_session_name(&subkey_name);
                        let host: String = subkey.get_value("HostName").unwrap_or_default();
                        if host.trim().is_empty() {
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
                            .unwrap_or_else(|_| protocol.default_port() as u32);
                        let username: String = subkey.get_value("UserName").unwrap_or_default();
                        let ppk_file: String = subkey.get_value("PublicKeyFile").unwrap_or_default();
                        let remote_cmd: String =
                            subkey.get_value("RemoteCommand").unwrap_or_default();
                        let subfolder: String = subkey
                            .get_value("KiTTYSubFolder")
                            .or_else(|_| subkey.get_value("Folder"))
                            .unwrap_or_else(|_| default_folder.to_string());
                        let folder = if subfolder.trim().is_empty() || subfolder == "Default" {
                            default_folder.to_string()
                        } else {
                            format!("{}/{}", default_folder, subfolder.replace('\\', "/"))
                        };

                        let ssh_auth = if !ppk_file.trim().is_empty() {
                            SshAuthMethod::PrivateKeyFile {
                                key_path: ppk_file,
                                passphrase: String::new(),
                                cert_path: String::new(),
                            }
                        } else {
                            let agent_fwd: u32 = subkey.get_value("AgentFwd").unwrap_or(0);
                            let try_agent: u32 = subkey.get_value("TryAgent").unwrap_or(1);
                            if agent_fwd > 0 && username.is_empty() && try_agent > 0 {
                                SshAuthMethod::Agent {
                                    use_pageant: true,
                                    use_openssh_agent: true,
                                }
                            } else {
                                SshAuthMethod::Password
                            }
                        };

                        let already_exists = self
                            .sessions
                            .iter()
                            .any(|s| s.name == decoded_name && s.host == host);
                        if !already_exists {
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
                                port: port as u16,
                                username,
                                ssh_auth,
                                startup_command: remote_cmd,
                                ..Default::default()
                            });
                            imported_count += 1;
                        }
                    }
                }
            }
        }

        if imported_count > 0 {
            let _ = self.save();
        }
        Ok(imported_count)
    }

    /// Importe un fichier de session portable KiTTY (format `Key\Value\` dans `Sessions/`) ou un dossier
    pub fn import_kitty_portable_file(&mut self, path: &Path) -> anyhow::Result<usize> {
        if path.is_dir() {
            let mut count = 0;
            for entry in fs::read_dir(path)?.flatten() {
                let p = entry.path();
                if p.is_file() {
                    if let Ok(c) = self.import_kitty_portable_file(&p) {
                        count += c;
                    }
                }
            }
            return Ok(count);
        }

        let content = fs::read_to_string(path)?;
        // Peut être un JSON Cuty-SSH ou un fichier INI/Session KiTTY
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

        let host = kv.get("HostName").cloned().unwrap_or_default();
        if host.is_empty() {
            anyhow::bail!("Aucun HostName trouvé dans le fichier {:?}", path);
        }

        let raw_name = path
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_else(|| "Session KiTTY".to_string());
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
        let username = kv.get("UserName").cloned().unwrap_or_default();
        let ppk_file = kv.get("PublicKeyFile").cloned().unwrap_or_default();
        let startup_command = kv.get("RemoteCommand").cloned().unwrap_or_default();
        let folder = kv
            .get("KiTTYSubFolder")
            .cloned()
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| "Import KiTTY Portable".to_string());

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
}

pub fn url_encode_session_name(name: &str) -> String {
    let mut out = String::with_capacity(name.len());
    for b in name.bytes() {
        if b.is_ascii_alphanumeric() || b == b'-' || b == b'_' || b == b'.' {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{:02X}", b));
        }
    }
    out
}

pub fn url_decode_session_name(encoded: &str) -> String {
    let mut bytes = Vec::with_capacity(encoded.len());
    let raw = encoded.as_bytes();
    let mut i = 0;
    while i < raw.len() {
        if raw[i] == b'%' && i + 2 < raw.len() {
            if let Ok(hex_str) = std::str::from_utf8(&raw[i + 1..i + 3]) {
                if let Ok(val) = u8::from_str_radix(hex_str, 16) {
                    bytes.push(val);
                    i += 3;
                    continue;
                }
            }
        }
        bytes.push(raw[i]);
        i += 1;
    }
    String::from_utf8_lossy(&bytes).to_string()
}

pub fn export_session_to_kitty_ini(s: &SessionProfile) -> String {
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
        "HostName\\{}\\\nPortNumber\\{}\\\nProtocol\\{}\\\nUserName\\{}\\\nPublicKeyFile\\{}\\\nRemoteCommand\\{}\\\nKiTTYSubFolder\\{}\\\nPingIntervalSecs\\{}\\\nCompression\\{}\\\n",
        s.host,
        s.port,
        proto,
        s.username,
        ppk_path,
        s.startup_command,
        s.folder,
        s.keepalive_secs,
        if s.compression { 1 } else { 0 }
    )
}
