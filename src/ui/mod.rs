pub mod audit_modal;
pub mod help_modal;
pub mod known_hosts_modal;
pub mod replay_modal;
pub mod sftp_client;
pub mod terminal_view;
pub mod theme;

use crate::config::{
    AppConfig, AuditLogEntry, EdgeGatewayPreset, ExpectRule, KnownHostEntry, PortForwardRule,
    PortForwardType, PredefinedCommand, ProtocolType, SessionProfile, SshAuthMethod, UiLanguage,
    append_audit_entry, load_audit_log, load_known_hosts, split_user_and_host,
};
use crate::protocols::{
    BackendCommand, BackendEvent, CidrCalculation, HostProbeResult, RemoteServerMetrics,
    SessionHandle, SftpFileEntry, USER_DISCONNECT_REASON, calculate_ipv4_cidr,
    probe_tcp_and_banner,
};
use crate::ssh::ppk::{
    AgentKeyEntry, KeyInspection, export_to_openssh_pem, export_to_ppk_v3, format_openssh_pubkey,
    generate_new_ssh_key, inspect_key_file, launch_pageant_with_keys, list_agent_keys,
    load_private_key_any, resolve_or_create_primary_key,
};
use crate::terminal::{TerminalEmulator, TerminalTheme};
use crate::ui::help_modal::{HelpTopic, tr};
use crate::ui::terminal_view::{format_bytes, protocol_badge_style};
use arboard::Clipboard;
use chrono::Local;
use egui::{
    Align, Color32, Context, Key, Layout, Pos2, RichText, Stroke, Ui, Vec2, ViewportCommand,
    WindowLevel,
};
use std::collections::{BTreeMap, HashSet};
use std::fs::OpenOptions;
use std::io::Write;
use std::path::{Path, PathBuf};
use tokio::sync::mpsc::{UnboundedReceiver, UnboundedSender, unbounded_channel};
use uuid::Uuid;
use zeroize::Zeroize;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TabConnectionState {
    Connecting,
    Connected,
    Disconnected(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SplitMode {
    #[default]
    None,
    /// Side-by-side dual terminal view
    Vertical,
    /// Top-and-bottom dual terminal view
    Horizontal,
}

#[derive(Debug, Clone)]
pub struct SftpTransferProgress {
    pub filename: String,
    pub transferred: u64,
    pub total: u64,
    pub is_upload: bool,
}

/// State of the SFTP "Properties" dialog (chmod, symlink, SHA-256) of one entry.
#[derive(Debug, Clone)]
pub struct SftpPropsDialog {
    pub entry: SftpFileEntry,
    pub mode: u32,
    pub mode_text: String,
    pub link_name: String,
    pub sha256: Option<String>,
    pub hashing: bool,
}

/// State of the SFTP mirror (one-way sync) dialog.
#[derive(Debug, Clone, Default)]
pub struct SftpMirrorDialog {
    pub open: bool,
    /// `false`: local -> remote, `true`: remote -> local.
    pub download: bool,
    pub local_dir: String,
    pub remote_dir: String,
    pub delete_extra: bool,
    pub lines: Vec<String>,
    pub summary: String,
    pub busy: bool,
}

pub struct PendingSecretPrompt {
    pub title: String,
    pub prompt: String,
    pub is_passphrase: bool,
    pub input_value: String,
}

pub struct SessionTab {
    pub tab_id: Uuid,
    pub profile: SessionProfile,
    pub terminal: TerminalEmulator,
    pub handle: SessionHandle,
    pub state: TabConnectionState,
    pub status_line: String,
    pub host_fingerprint: Option<String>,
    pub auth_summary: String,
    pub pending_prompt: Option<PendingSecretPrompt>,

    // Live SSH server telemetry
    pub telemetry: Option<RemoteServerMetrics>,
    pub show_telemetry_bar: bool,

    // Integrated SFTP explorer
    pub show_sftp_panel: bool,
    pub show_sftp_full: bool,
    pub sftp_client: sftp_client::SftpClientState,
    pub sftp_current_path: String,
    pub sftp_path_input: String,
    pub sftp_entries: Vec<SftpFileEntry>,
    pub sftp_status: String,
    pub sftp_mkdir_name: String,
    pub sftp_sort_col: SftpSortColumn,
    pub sftp_sort_dir: SortDirection,
    pub sftp_folders_first: bool,
    pub sftp_progress: Option<SftpTransferProgress>,
    pub sftp_props: Option<SftpPropsDialog>,
    pub sftp_mirror: SftpMirrorDialog,

    // Terminal search
    pub show_search_bar: bool,
    pub search_query: String,

    // Session log file
    pub log_file_path: Option<PathBuf>,

    // Session recording (.cast asciinema v2)
    pub recorder: Option<crate::terminal::recording::SessionRecorder>,
    pub connect_instant: Option<std::time::Instant>,

    // Auto-reconnect
    pub was_connected: bool,
    pub reconnect_attempt: u32,
    pub reconnect_at: Option<std::time::Instant>,

    /// Local port of the one-click SOCKS5 proxy, when running.
    pub socks_port: Option<u16>,
    /// Port used the next time the one-click proxy is started.
    pub socks_listen_port: u16,
}

/// Maximum automatic reconnection attempts before giving up.
const MAX_RECONNECT_ATTEMPTS: u32 = 10;

/// Exponential back-off: 2, 4, 8, 16, 30, 30... seconds.
/// `-rwxr-xr-x (0755)` style rendering of SFTP permission bits.
fn format_unix_mode(mode: u32) -> String {
    let kind = match mode & 0o170000 {
        0o040000 => 'd',
        0o120000 => 'l',
        _ => '-',
    };
    let mut out = String::from(kind);
    for shift in [6u32, 3, 0] {
        for (bit, ch) in [(4u32, 'r'), (2, 'w'), (1, 'x')] {
            out.push(if mode & (bit << shift) != 0 { ch } else { '-' });
        }
    }
    format!("{out} ({:04o})", mode & 0o7777)
}

fn reconnect_delay_secs(attempt: u32) -> u64 {
    (2u64 << attempt.saturating_sub(1).min(4)).min(30)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SftpSortColumn {
    Name,
    Size,
    Date,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SortDirection {
    Ascending,
    Descending,
}

impl SessionTab {
    pub fn sort_sftp_entries(&mut self) {
        let sort_col = self.sftp_sort_col;
        let sort_dir = self.sftp_sort_dir;
        let folders_first = self.sftp_folders_first;

        self.sftp_entries.sort_by(|a, b| {
            if folders_first && a.is_dir != b.is_dir {
                return if a.is_dir {
                    std::cmp::Ordering::Less
                } else {
                    std::cmp::Ordering::Greater
                };
            }

            let cmp = match sort_col {
                SftpSortColumn::Name => a.name.to_lowercase().cmp(&b.name.to_lowercase()),
                SftpSortColumn::Size => a.size.cmp(&b.size),
                SftpSortColumn::Date => a.mtime.cmp(&b.mtime),
            };

            let primary = match sort_dir {
                SortDirection::Ascending => cmp,
                SortDirection::Descending => cmp.reverse(),
            };

            primary.then_with(|| a.name.to_lowercase().cmp(&b.name.to_lowercase()))
        });
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConfigEditorTab {
    ConnectionAndKey,
    Automation,
    PortForwards,
    Appearance,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SessionSortMode {
    #[default]
    NameAsc,
    NameDesc,
    FolderAndName,
    Protocol,
    Latency,
}

impl SessionSortMode {
    pub fn label(self, lang: UiLanguage) -> &'static str {
        match self {
            Self::NameAsc => tr(
                lang,
                "\u{E6EE} Nom (A \u{E06C} Z)",
                "\u{E6EE} Name (A \u{E06C} Z)",
            ),
            Self::NameDesc => tr(
                lang,
                "\u{E6EE} Nom (Z \u{E06C} A)",
                "\u{E6EE} Name (Z \u{E06C} A)",
            ),
            Self::FolderAndName => tr(lang, "\u{E24A} Dossier & Nom", "\u{E24A} Folder & Name"),
            Self::Protocol => tr(lang, "🔌 Protocole", "🔌 Protocol"),
            Self::Latency => tr(lang, "\u{E0F2} Ping / Latence", "\u{E0F2} Ping / Latency"),
        }
    }
}

pub struct CutySshApp {
    pub rt: tokio::runtime::Handle,
    pub config: AppConfig,

    // Sessions sidebar
    pub show_sidebar: bool,
    pub session_filter: String,
    pub quick_host: String,
    pub quick_user: String,
    pub quick_port: u16,
    pub quick_protocol: ProtocolType,
    pub quick_ppk_path: String,

    // Session management & search
    pub show_session_manager: bool,
    pub dashboard_session_query: String,
    pub dashboard_protocol_filter: Option<ProtocolType>,
    pub dashboard_folder_filter: String,
    pub dashboard_tag_filter: String,
    pub dashboard_online_only: bool,
    pub dashboard_offline_only: bool,
    pub dashboard_sort_mode: SessionSortMode,
    pub selected_session_ids: HashSet<Uuid>,
    pub bulk_target_folder: String,
    pub bulk_tag_input: String,
    pub session_tag_input: String,

    // Open session tabs & Split View
    pub tabs: Vec<SessionTab>,
    pub active_tab_idx: usize,
    pub broadcast_mode: bool,
    pub split_mode: SplitMode,
    pub split_secondary_tab: Option<Uuid>,

    // Window state (Roll-up, Always-on-top)
    pub is_rolled_up: bool,
    pub saved_window_size: Vec2,

    // Session editor (Enhanced Configuration Box)
    pub show_session_editor: bool,
    pub editing_session: SessionProfile,
    pub is_new_session: bool,
    pub editor_tab: ConfigEditorTab,
    pub new_expect_trigger: String,
    pub new_expect_response: String,
    pub new_pf_bind_addr: String,
    pub new_pf_bind_port: u16,
    pub new_pf_target_host: String,
    pub new_pf_target_port: u16,
    pub new_pf_is_remote: bool,
    pub new_pf_is_dynamic: bool,

    // PuTTY (.ppk) & Pageant Key Manager
    pub show_key_manager: bool,
    pub inspected_key: Option<KeyInspection>,
    pub key_manager_passphrase: String,
    pub key_manager_status: String,
    pub keygen_algo: String,
    pub keygen_comment: String,
    pub agent_keys: Vec<AgentKeyEntry>,
    pub agent_keys_rx: Option<tokio::sync::oneshot::Receiver<Vec<AgentKeyEntry>>>,

    // Known Hosts (TOFU) Manager
    pub show_known_hosts: bool,
    pub known_hosts: Vec<KnownHostEntry>,
    pub known_hosts_filter: String,

    // Predefined commands manager
    pub show_commands_editor: bool,
    pub new_cmd_label: String,
    pub new_cmd_category: String,
    pub new_cmd_text: String,

    // Command & Session Palette (Ctrl+K)
    pub show_command_palette: bool,
    pub palette_query: String,

    // Network & SSH Diagnostic Toolkit
    pub show_network_tools: bool,
    pub probe_host_input: String,
    pub probe_port_input: u16,
    pub probe_results: Vec<HostProbeResult>,
    pub session_probes: BTreeMap<Uuid, HostProbeResult>,
    pub probe_tx: UnboundedSender<HostProbeResult>,
    pub probe_rx: UnboundedReceiver<HostProbeResult>,
    pub cidr_input: String,
    pub cidr_result: Option<CidrCalculation>,
    pub cidr_error: String,

    // Global notifications
    pub toast_message: Option<(String, std::time::Instant)>,

    // About & Design modal
    pub show_about: bool,

    // Illustrated User Guide & Help modal
    pub show_help: bool,
    pub help_topic: HelpTopic,
    pub cockpit_screenshot_texture: Option<egui::TextureHandle>,

    // Audit & Activity log (📜 Audit)
    pub show_audit_modal: bool,
    pub audit_entries: Vec<AuditLogEntry>,
    pub audit_query: String,
    pub audit_filter_event: Option<String>,

    // Session Replay Player (.cast)
    pub show_replay_modal: bool,
    pub replay_player: Option<crate::terminal::recording::SessionPlayer>,
    pub replay_terminal: Option<crate::terminal::TerminalEmulator>,
    pub replay_file_name: String,
    pub replay_last_tick: Option<std::time::Instant>,

    // Fleet Live Ping Timer
    pub last_fleet_probe_time: Option<std::time::Instant>,
}

impl CutySshApp {
    pub fn new(cc: &eframe::CreationContext<'_>, rt: tokio::runtime::Handle) -> Self {
        theme::apply(&cc.egui_ctx);
        #[cfg(windows)]
        theme::tint_title_bar(cc);
        let demo_stage = std::env::var("CUTY_SSH_DEMO_STAGE").ok();
        let config = if demo_stage.is_some() {
            Self::build_english_showcase_config()
        } else {
            AppConfig::load_or_default()
        };
        let (probe_tx, probe_rx) = unbounded_channel();
        let default_cidr = "10.240.16.0/24".to_string();
        let initial_cidr = calculate_ipv4_cidr(&default_cidr).ok();
        let known_hosts = if demo_stage.is_some() {
            vec![
                KnownHostEntry {
                    host_port: "bastion.corp.example.com:22".to_string(),
                    algorithm: "ssh-ed25519".to_string(),
                    fingerprint_sha256: "SHA256:9xK4mP8vQ2wL7nR3tY6uI1oP5aS8dF0gH2jK4lZ6xC8"
                        .to_string(),
                    public_key_base64: String::new(),
                    first_seen: "2026-10-12 09:15:00".to_string(),
                    last_seen: "2026-10-17 22:40:12".to_string(),
                },
                KnownHostEntry {
                    host_port: "10.240.16.10:22".to_string(),
                    algorithm: "ssh-ed25519".to_string(),
                    fingerprint_sha256: "SHA256:3vB7nM2qW9eR4tY8uI0oP2aS6dF1gH5jK9lZ3xC7vB1"
                        .to_string(),
                    public_key_base64: String::new(),
                    first_seen: "2026-10-14 14:22:05".to_string(),
                    last_seen: "2026-10-17 22:41:00".to_string(),
                },
                KnownHostEntry {
                    host_port: "10.240.16.25:22".to_string(),
                    algorithm: "ecdsa-sha2-nistp256".to_string(),
                    fingerprint_sha256: "SHA256:7pL1kM9jN4bV6cX8zZ2qW5eR0tY3uI7oP9aS2dF4gH6"
                        .to_string(),
                    public_key_base64: String::new(),
                    first_seen: "2026-10-15 18:05:49".to_string(),
                    last_seen: "2026-10-17 21:19:33".to_string(),
                },
            ]
        } else {
            load_known_hosts()
        };

        let mut app = Self {
            rt,
            config,
            show_sidebar: true,
            session_filter: String::new(),
            quick_host: String::new(),
            quick_user: "ops".to_string(),
            quick_port: 22,
            quick_protocol: ProtocolType::Ssh,
            quick_ppk_path: String::new(),
            show_session_manager: false,
            dashboard_session_query: String::new(),
            dashboard_protocol_filter: None,
            dashboard_folder_filter: "Tous".to_string(),
            dashboard_tag_filter: "Tous".to_string(),
            dashboard_online_only: false,
            dashboard_offline_only: false,
            dashboard_sort_mode: SessionSortMode::NameAsc,
            selected_session_ids: HashSet::new(),
            bulk_target_folder: "Production".to_string(),
            bulk_tag_input: String::new(),
            session_tag_input: String::new(),
            tabs: Vec::new(),
            active_tab_idx: 0,
            broadcast_mode: false,
            split_mode: SplitMode::None,
            split_secondary_tab: None,
            is_rolled_up: false,
            saved_window_size: Vec2::new(1340.0, 840.0),
            show_session_editor: false,
            editing_session: SessionProfile::default(),
            is_new_session: false,
            editor_tab: ConfigEditorTab::ConnectionAndKey,
            new_expect_trigger: String::new(),
            new_expect_response: String::new(),
            new_pf_bind_addr: "127.0.0.1".to_string(),
            new_pf_bind_port: 8080,
            new_pf_target_host: "127.0.0.1".to_string(),
            new_pf_target_port: 80,
            new_pf_is_remote: false,
            new_pf_is_dynamic: false,
            show_key_manager: false,
            inspected_key: None,
            key_manager_passphrase: String::new(),
            key_manager_status: String::new(),
            keygen_algo: "ed25519".to_string(),
            keygen_comment: "devops@cuty-ssh".to_string(),
            agent_keys: Vec::new(),
            agent_keys_rx: None,
            show_known_hosts: false,
            known_hosts,
            known_hosts_filter: String::new(),
            show_commands_editor: false,
            new_cmd_label: String::new(),
            new_cmd_category: "General".to_string(),
            new_cmd_text: String::new(),
            show_command_palette: false,
            palette_query: String::new(),
            show_network_tools: false,
            probe_host_input: "10.240.16.10".to_string(),
            probe_port_input: 22,
            probe_results: Vec::new(),
            session_probes: BTreeMap::new(),
            probe_tx,
            probe_rx,
            cidr_input: default_cidr,
            cidr_result: initial_cidr,
            cidr_error: String::new(),
            toast_message: None,
            show_about: false,
            show_help: false,
            help_topic: HelpTopic::Overview,
            cockpit_screenshot_texture: None,
            show_audit_modal: false,
            audit_entries: load_audit_log(),
            audit_query: String::new(),
            audit_filter_event: None,
            show_replay_modal: false,
            replay_player: None,
            replay_terminal: None,
            replay_file_name: String::new(),
            replay_last_tick: None,
            last_fleet_probe_time: Some(std::time::Instant::now()),
        };

        if let Some(stage) = demo_stage {
            app.apply_demo_stage(&stage);
        } else {
            app.resolve_pageant_path();
            app.refresh_agent_keys();
            app.probe_all_sessions();
        }
        app
    }

    fn build_english_showcase_config() -> AppConfig {
        let bastion_id = Uuid::new_v4();
        let k8s_id = Uuid::new_v4();
        let db_id = Uuid::new_v4();
        let redis_id = Uuid::new_v4();
        let cisco_id = Uuid::new_v4();
        let ps_id = Uuid::new_v4();

        let sessions = vec![
            SessionProfile {
                id: bastion_id,
                name: "Bastion Gateway DMZ".to_string(),
                folder: "Infrastructure".to_string(),
                tags: vec![
                    "bastion".to_string(),
                    "dmz".to_string(),
                    "secops".to_string(),
                ],
                protocol: ProtocolType::Ssh,
                host: "bastion.corp.example.com".to_string(),
                port: 22,
                username: "secadmin".to_string(),
                ssh_auth: SshAuthMethod::PrivateKeyFile {
                    key_path: "C:/Keys/corp_bastion_ed25519.ppk".to_string(),
                    passphrase: String::new(),
                    cert_path: String::new(),
                },
                try_pageant: true,
                icon_badge: "🏰".to_string(),
                theme_name: "Cuty Dark (Default)".to_string(),
                ..Default::default()
            },
            SessionProfile {
                id: k8s_id,
                name: "Prod K8s Master-01".to_string(),
                folder: "Production".to_string(),
                tags: vec!["prod".to_string(), "k8s".to_string(), "linux".to_string()],
                protocol: ProtocolType::Ssh,
                host: "10.240.16.10".to_string(),
                port: 22,
                username: "ubuntu".to_string(),
                ssh_auth: SshAuthMethod::PrivateKeyFile {
                    key_path: "C:/Keys/prod_k8s_cluster.ppk".to_string(),
                    passphrase: String::new(),
                    cert_path: String::new(),
                },
                try_pageant: true,
                jump_host_id: Some(bastion_id),
                icon_badge: "☸".to_string(),
                theme_name: "Cuty Dark (Default)".to_string(),
                ..Default::default()
            },
            SessionProfile {
                id: db_id,
                name: "PostgreSQL Replica-02".to_string(),
                folder: "Production".to_string(),
                tags: vec![
                    "prod".to_string(),
                    "database".to_string(),
                    "postgres".to_string(),
                ],
                protocol: ProtocolType::Ssh,
                host: "10.240.16.25".to_string(),
                port: 22,
                username: "postgres".to_string(),
                ssh_auth: SshAuthMethod::Agent {
                    use_pageant: true,
                    use_openssh_agent: true,
                },
                try_pageant: true,
                jump_host_id: Some(bastion_id),
                icon_badge: "🐘".to_string(),
                theme_name: "Dracula".to_string(),
                ..Default::default()
            },
            SessionProfile {
                id: redis_id,
                name: "Staging Redis Cache".to_string(),
                folder: "Staging".to_string(),
                tags: vec![
                    "staging".to_string(),
                    "redis".to_string(),
                    "cache".to_string(),
                ],
                protocol: ProtocolType::Ssh,
                host: "10.240.32.18".to_string(),
                port: 22,
                username: "devops".to_string(),
                ssh_auth: SshAuthMethod::Agent {
                    use_pageant: true,
                    use_openssh_agent: true,
                },
                try_pageant: true,
                icon_badge: "⚡".to_string(),
                theme_name: "Tokyo Night".to_string(),
                ..Default::default()
            },
            SessionProfile {
                id: cisco_id,
                name: "Cisco Core Switch".to_string(),
                folder: "Network".to_string(),
                tags: vec![
                    "network".to_string(),
                    "cisco".to_string(),
                    "telnet".to_string(),
                ],
                protocol: ProtocolType::Telnet,
                host: "192.168.10.254".to_string(),
                port: 23,
                username: "netadmin".to_string(),
                icon_badge: "🔌".to_string(),
                theme_name: "Solarized Dark".to_string(),
                ..Default::default()
            },
            SessionProfile {
                id: ps_id,
                name: "PowerShell Local".to_string(),
                folder: "Local".to_string(),
                tags: vec![
                    "local".to_string(),
                    "shell".to_string(),
                    "windows".to_string(),
                ],
                protocol: ProtocolType::LocalShell,
                local_shell_cmd: "powershell.exe".to_string(),
                icon_badge: "💻".to_string(),
                theme_name: "Cuty Dark (Default)".to_string(),
                ..Default::default()
            },
        ];

        let predefined_commands = vec![
            PredefinedCommand {
                id: Uuid::new_v4(),
                label: "\u{E150} System & Uptime".to_string(),
                category: "Monitoring".to_string(),
                command: "uname -a && uptime && df -h / && free -h".to_string(),
                append_enter: true,
                description: "Kernel, uptime, disk & RAM overview".to_string(),
            },
            PredefinedCommand {
                id: Uuid::new_v4(),
                label: "🐳 Docker PS".to_string(),
                category: "Containers".to_string(),
                command: "docker ps --format \"table {{.Names}}\\t{{.Status}}\\t{{.Ports}}\""
                    .to_string(),
                append_enter: true,
                description: "List running Docker containers".to_string(),
            },
            PredefinedCommand {
                id: Uuid::new_v4(),
                label: "🔥 Listening Ports".to_string(),
                category: "Network".to_string(),
                command: "ss -tulpn".to_string(),
                append_enter: true,
                description: "Show listening TCP/UDP sockets".to_string(),
            },
            PredefinedCommand {
                id: Uuid::new_v4(),
                label: "\u{EB7A} Journald Errors".to_string(),
                category: "Logs".to_string(),
                command: "journalctl -p 3 -xb -n 50".to_string(),
                append_enter: true,
                description: "Latest systemd error logs".to_string(),
            },
            PredefinedCommand {
                id: Uuid::new_v4(),
                label: "👑 Sudo Root".to_string(),
                category: "Admin".to_string(),
                command: "sudo -i".to_string(),
                append_enter: true,
                description: "Switch to interactive root shell".to_string(),
            },
            PredefinedCommand {
                id: Uuid::new_v4(),
                label: "\u{EC54} Clear".to_string(),
                category: "Terminal".to_string(),
                command: "clear".to_string(),
                append_enter: true,
                description: "Clear terminal screen".to_string(),
            },
        ];

        AppConfig {
            language: UiLanguage::English,
            sessions,
            predefined_commands,
            ..Default::default()
        }
    }

    fn apply_demo_stage(&mut self, stage: &str) {
        let latencies = [8u64, 12, 14, 19, 4];
        let banners = [
            "SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13",
            "SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13",
            "SSH-2.0-OpenSSH_9.2p1 Debian-2+deb12u3",
            "SSH-2.0-OpenSSH_9.3p2 Alpine",
            "Cisco IOS Telnet Ready",
        ];
        for (idx, s) in self.config.sessions.iter().enumerate() {
            if s.protocol == ProtocolType::LocalShell {
                continue;
            }
            let probe = HostProbeResult {
                session_id: Some(s.id),
                label: s.name.clone(),
                host: s.host.clone(),
                port: s.port,
                reachable: true,
                latency_ms: latencies[idx % latencies.len()],
                banner: banners[idx % banners.len()].to_string(),
            };
            self.session_probes.insert(s.id, probe.clone());
            self.probe_results.push(probe);
        }

        self.agent_keys = vec![
            AgentKeyEntry {
                source_agent: "Pageant".to_string(),
                algorithm: "ssh-ed25519".to_string(),
                fingerprint_sha256: "SHA256:8kM2pL9vQ4wN7xR1tY5uI3oP6aS0dF2gH8jK4lZ1xC9"
                    .to_string(),
                comment: "corp_bastion_ed25519.ppk".to_string(),
                openssh_public_key:
                    "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIExampleShowcaseKey1 corp_bastion_ed25519"
                        .to_string(),
            },
            AgentKeyEntry {
                source_agent: "OpenSSH Agent".to_string(),
                algorithm: "ssh-ed25519".to_string(),
                fingerprint_sha256: "SHA256:5nB4vM8cX2zL6kP9jH1gF3dS7aQ0wE4rT6yU8iO2pL5"
                    .to_string(),
                comment: "prod_k8s_cluster.ppk".to_string(),
                openssh_public_key:
                    "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIExampleShowcaseKey2 prod_k8s_cluster"
                        .to_string(),
            },
        ];

        match stage {
            "editor" => {
                if let Some(k8s) = self
                    .config
                    .sessions
                    .iter()
                    .find(|s| s.name.contains("K8s"))
                    .cloned()
                {
                    self.editing_session = k8s;
                    self.is_new_session = false;
                    self.editor_tab = ConfigEditorTab::ConnectionAndKey;
                    self.show_session_editor = true;
                }
            }
            "help" => {
                self.show_help = true;
                self.help_topic = HelpTopic::Overview;
            }
            "help_bastion" => {
                self.show_help = true;
                self.help_topic = HelpTopic::Bastion;
            }
            "network" => {
                self.show_network_tools = true;
            }
            "hosts" => {
                self.show_known_hosts = true;
            }
            "keys" => {
                self.show_key_manager = true;
            }
            "manager" => {
                self.show_session_manager = true;
            }
            "palette" => {
                self.show_command_palette = true;
            }
            "about" => {
                self.show_about = true;
            }
            "audit" => {
                self.refresh_audit_entries();
                self.show_audit_modal = true;
            }
            "replay" => {
                self.show_replay_modal = true;
            }
            "snippets" => {
                self.show_commands_editor = true;
            }
            "sftp_props" | "sftp_mirror" => {
                // SSH tab (closed local port) with a fake SFTP listing and one SFTP dialog open.
                self.launch_session(SessionProfile {
                    name: "web-prod-01".to_string(),
                    protocol: ProtocolType::Ssh,
                    host: "127.0.0.1".to_string(),
                    port: 9,
                    username: "deploy".to_string(),
                    ..Default::default()
                });
                if let Some(tab) = self.tabs.last_mut() {
                    let entry = |name: &str, is_dir: bool, size: u64, perm: u32| SftpFileEntry {
                        name: name.to_string(),
                        full_path: format!("/var/www/app/{name}"),
                        is_dir,
                        is_symlink: false,
                        size,
                        permissions: perm,
                        mtime: 1_760_000_000,
                    };
                    // Detach the real (failing) backend so the demo shows a healthy session.
                    let (cmd_tx, _cmd_rx) = unbounded_channel();
                    let (_evt_tx, evt_rx) = unbounded_channel();
                    tab.handle = SessionHandle { cmd_tx, evt_rx };
                    tab.state = TabConnectionState::Connected;
                    tab.status_line = "Connected to web-prod-01".to_string();
                    tab.auth_summary = "Public key".to_string();
                    tab.terminal.feed_str(
                        "Last login: Tue Oct 21 08:12:44 2026 from 10.0.0.12\r\n[deploy@web-prod-01 app]$ ls\r\nreleases  shared  deploy.sh  app.tar.gz  config.yml\r\n[deploy@web-prod-01 app]$ ",
                    );
                    tab.show_sftp_panel = true;
                    tab.sftp_current_path = "/var/www/app".to_string();
                    tab.sftp_path_input = "/var/www/app".to_string();
                    tab.sftp_entries = vec![
                        entry("releases", true, 0, 0o040755),
                        entry("shared", true, 0, 0o040755),
                        entry("deploy.sh", false, 2_048, 0o100755),
                        entry("app.tar.gz", false, 48_300_000, 0o100644),
                        entry("config.yml", false, 1_204, 0o100640),
                    ];
                    tab.sftp_status = "5 items".to_string();
                    if stage == "sftp_props" {
                        let e = entry("deploy.sh", false, 2_048, 0o100755);
                        tab.sftp_props = Some(SftpPropsDialog {
                            mode: e.permissions & 0o7777,
                            mode_text: format!("{:04o}", e.permissions & 0o7777),
                            entry: e,
                            link_name: String::new(),
                            sha256: Some(
                                "9f2c4e1b7a63d8f05b1e94c2a7d03f68b5e1c9a4d27f8036e1b5a9c4d7f20e83"
                                    .to_string(),
                            ),
                            hashing: false,
                        });
                    } else {
                        tab.sftp_mirror = SftpMirrorDialog {
                            open: true,
                            download: false,
                            local_dir: "D:\\builds\\app".to_string(),
                            remote_dir: "/var/www/app".to_string(),
                            delete_extra: false,
                            lines: vec![
                                "+ app.tar.gz".to_string(),
                                "+ config.yml".to_string(),
                                "+ shared/assets/logo.svg".to_string(),
                                "+ releases/2026-10-21/index.html".to_string(),
                            ],
                            summary: "4 planned action(s)".to_string(),
                            busy: false,
                        };
                    }
                }
            }
            "reconnect" => {
                // SSH tab to a closed local port, flagged as a dropped connection with auto-reconnect.
                self.launch_session(SessionProfile {
                    name: "BI-BDD1".to_string(),
                    protocol: ProtocolType::Ssh,
                    host: "127.0.0.1".to_string(),
                    port: 9,
                    username: "root".to_string(),
                    auto_reconnect: true,
                    ..Default::default()
                });
                if let Some(tab) = self.tabs.last_mut() {
                    tab.was_connected = true;
                }
            }
            "telemetry" => {
                // SSH tab to a closed local port, with fake server metrics to check the strip.
                self.launch_session(SessionProfile {
                    name: "BI-BDD1".to_string(),
                    protocol: ProtocolType::Ssh,
                    host: "127.0.0.1".to_string(),
                    port: 9,
                    username: "root".to_string(),
                    ..Default::default()
                });
                if let Some(tab) = self.tabs.last_mut() {
                    tab.show_telemetry_bar = true;
                    tab.telemetry = Some(RemoteServerMetrics {
                        hostname: "BI-BDD1".to_string(),
                        kernel: "5.14.0".to_string(),
                        uptime: "up 3 years, 32 weeks, 2 days, 12 hours, 39 minutes".to_string(),
                        load_avg: "0.08 0.02 0.01".to_string(),
                        cpu_load_1m: 0.08,
                        mem_used_mb: 3446,
                        mem_total_mb: 15672,
                        disk_used_pct: 6.0,
                        disk_summary: "4,8G/91G".to_string(),
                    });
                }
            }
            "tab" => {
                self.launch_session(SessionProfile {
                    name: "PowerShell Local".to_string(),
                    protocol: ProtocolType::LocalShell,
                    local_shell_cmd: "powershell.exe".to_string(),
                    ..Default::default()
                });
            }
            "prompt" => {
                self.launch_session(SessionProfile {
                    name: "PowerShell Local".to_string(),
                    protocol: ProtocolType::LocalShell,
                    local_shell_cmd: "powershell.exe".to_string(),
                    ..Default::default()
                });
                if let Some(tab) = self.tabs.last_mut() {
                    tab.pending_prompt = Some(PendingSecretPrompt {
                        title: "Passphrase de clé PuTTY (.ppk)".to_string(),
                        prompt: "Demo passphrase prompt".to_string(),
                        is_passphrase: true,
                        input_value: String::new(),
                    });
                }
            }
            _ => {}
        }
    }

    /// Opens a saved session from the command line (`--session <name|uuid>`).
    pub fn open_session_by_key(&mut self, key: &str) {
        match self.config.find_session(key).cloned() {
            Ok(profile) => self.launch_session(profile),
            Err(msg) => self.set_toast(msg),
        }
    }

    pub fn set_toast(&mut self, msg: impl Into<String>) {
        self.toast_message = Some((msg.into(), std::time::Instant::now()));
    }

    /// Reachability filter derived from the dashboard toggles (`Some(true)` = online only).
    fn dashboard_reachability_filter(&self) -> Option<bool> {
        if self.dashboard_online_only {
            Some(true)
        } else if self.dashboard_offline_only {
            Some(false)
        } else {
            None
        }
    }

    /// Filters and sorts saved sessions by search query, protocol, folder, tag, reachability, and sort mode.
    pub fn filter_and_sort_sessions(
        &self,
        query: &str,
        proto_filter: Option<ProtocolType>,
        folder_filter: &str,
        tag_filter: &str,
        reachability: Option<bool>,
        sort_mode: SessionSortMode,
    ) -> Vec<SessionProfile> {
        let q = query.trim().to_lowercase();
        let folder_norm = folder_filter.trim();
        let tag_norm = tag_filter.trim();

        let mut list: Vec<SessionProfile> = self
            .config
            .sessions
            .iter()
            .filter(|s| {
                if let Some(proto) = proto_filter
                    && s.protocol != proto
                {
                    return false;
                }
                if !folder_norm.is_empty()
                    && folder_norm != "Tous"
                    && folder_norm != "Tous les dossiers"
                {
                    let s_f = if s.folder.trim().is_empty() {
                        "Général"
                    } else {
                        s.folder.trim()
                    };
                    if !s_f.eq_ignore_ascii_case(folder_norm) {
                        return false;
                    }
                }
                if !tag_norm.is_empty()
                    && tag_norm != "Tous"
                    && tag_norm != "Tous les tags"
                    && !s.tags.iter().any(|t| t.eq_ignore_ascii_case(tag_norm))
                {
                    return false;
                }
                if let Some(want_online) = reachability {
                    // Unprobed sessions (e.g. local shells) match neither filter.
                    let probe = self.session_probes.get(&s.id).map(|p| p.reachable);
                    if probe != Some(want_online) {
                        return false;
                    }
                }
                if !q.is_empty() {
                    let q_tag = q.trim_start_matches('#');
                    let matches = s.name.to_lowercase().contains(&q)
                        || s.host.to_lowercase().contains(&q)
                        || s.folder.to_lowercase().contains(&q)
                        || s.username.to_lowercase().contains(&q)
                        || s.port.to_string().contains(&q)
                        || s.protocol.label().to_lowercase().contains(&q)
                        || s.local_shell_cmd.to_lowercase().contains(&q)
                        || s.tags.iter().any(|t| {
                            let tl = t.to_lowercase();
                            tl.contains(&q) || tl.contains(q_tag)
                        });
                    if !matches {
                        return false;
                    }
                }
                true
            })
            .cloned()
            .collect();

        match sort_mode {
            SessionSortMode::NameAsc => {
                list.sort_by_key(|a| a.name.to_lowercase());
            }
            SessionSortMode::NameDesc => {
                list.sort_by_key(|a| std::cmp::Reverse(a.name.to_lowercase()));
            }
            SessionSortMode::FolderAndName => {
                list.sort_by(|a, b| {
                    let f_a = if a.folder.trim().is_empty() {
                        "Général"
                    } else {
                        a.folder.trim()
                    };
                    let f_b = if b.folder.trim().is_empty() {
                        "Général"
                    } else {
                        b.folder.trim()
                    };
                    f_a.to_lowercase()
                        .cmp(&f_b.to_lowercase())
                        .then_with(|| a.name.to_lowercase().cmp(&b.name.to_lowercase()))
                });
            }
            SessionSortMode::Protocol => {
                list.sort_by(|a, b| {
                    a.protocol
                        .label()
                        .cmp(b.protocol.label())
                        .then_with(|| a.name.to_lowercase().cmp(&b.name.to_lowercase()))
                });
            }
            SessionSortMode::Latency => {
                list.sort_by(|a, b| {
                    let lat_a = self
                        .session_probes
                        .get(&a.id)
                        .map(|p| if p.reachable { p.latency_ms } else { 999_999 })
                        .unwrap_or(999_999);
                    let lat_b = self
                        .session_probes
                        .get(&b.id)
                        .map(|p| if p.reachable { p.latency_ms } else { 999_999 })
                        .unwrap_or(999_999);
                    lat_a
                        .cmp(&lat_b)
                        .then_with(|| a.name.to_lowercase().cmp(&b.name.to_lowercase()))
                });
            }
        }

        list
    }

    pub fn refresh_agent_keys(&mut self) {
        let (tx, rx) = tokio::sync::oneshot::channel();
        self.agent_keys_rx = Some(rx);
        self.rt.spawn(async move {
            let keys = list_agent_keys(true, true).await;
            let _ = tx.send(keys);
        });
    }

    /// Probes TCP reachability, latency (ms), and SSH/Telnet banner for all saved network sessions.
    pub fn probe_all_sessions(&mut self) {
        self.probe_results.clear();
        for s in &self.config.sessions {
            if s.protocol == ProtocolType::LocalShell || s.host.trim().is_empty() {
                continue;
            }
            let tx = self.probe_tx.clone();
            let sid = Some(s.id);
            let label = s.name.clone();
            let host = s.host.clone();
            let port = s.port;
            self.rt.spawn(async move {
                let res = probe_tcp_and_banner(sid, label, host, port).await;
                let _ = tx.send(res);
            });
        }
    }

    /// Probes a single custom host:port from the Network Diagnostic Toolkit.
    pub fn probe_single_target(&mut self, host: String, port: u16) {
        let tx = self.probe_tx.clone();
        let label = format!(" Diagnostic {}:{}", host.trim(), port);
        self.rt.spawn(async move {
            let res = probe_tcp_and_banner(None, label, host, port).await;
            let _ = tx.send(res);
        });
    }

    /// Resolves the Pageant executable path, auto-detecting portable KiTTY / PuTTY installations
    /// and updating `self.config.pageant_path` if the currently configured path does not exist.
    pub fn resolve_pageant_path(&mut self) -> String {
        if !self.config.pageant_path.trim().is_empty()
            && Path::new(&self.config.pageant_path).exists()
        {
            return self.config.pageant_path.clone();
        }
        let mut hints: Vec<&str> = Vec::new();
        if !self.config.kitty_dir.trim().is_empty() {
            hints.push(self.config.kitty_dir.as_str());
        }
        if !self.config.primary_key_path.trim().is_empty() {
            hints.push(self.config.primary_key_path.as_str());
        }
        if !self.quick_ppk_path.trim().is_empty() {
            hints.push(self.quick_ppk_path.as_str());
        }
        let inspected_path_str;
        if let Some(ref info) = self.inspected_key {
            inspected_path_str = info.path.clone();
            if !inspected_path_str.trim().is_empty() {
                hints.push(inspected_path_str.as_str());
            }
        }
        for s in &self.config.sessions {
            if let SshAuthMethod::PrivateKeyFile { key_path, .. } = &s.ssh_auth
                && !key_path.trim().is_empty()
            {
                hints.push(key_path.as_str());
            }
        }
        if let Some(found) = crate::ssh::ppk::resolve_pageant_executable_with_hints(
            &self.config.pageant_path,
            &hints,
        ) {
            let p_str = found.to_string_lossy().to_string();
            self.config.pageant_path = p_str.clone();
            let _ = self.config.save();
            return p_str;
        }
        self.config.pageant_path.clone()
    }

    /// Collects all `.ppk` files configured across saved sessions, primary key, and loads them into Pageant.
    pub fn load_all_session_ppks_into_pageant(&mut self) {
        let mut paths: Vec<String> = Vec::new();
        if !self.config.primary_key_path.trim().is_empty() {
            let pk = self.config.primary_key_path.trim();
            if PathBuf::from(pk).exists() && !paths.iter().any(|p| p.eq_ignore_ascii_case(pk)) {
                paths.push(pk.to_string());
            }
        }
        if !self.quick_ppk_path.trim().is_empty() {
            let mk = self.quick_ppk_path.trim();
            if PathBuf::from(mk).exists() && !paths.iter().any(|p| p.eq_ignore_ascii_case(mk)) {
                paths.push(mk.to_string());
            }
        }
        for s in &self.config.sessions {
            if let SshAuthMethod::PrivateKeyFile { key_path, .. } = &s.ssh_auth {
                let trimmed = key_path.trim();
                if !trimmed.is_empty()
                    && PathBuf::from(trimmed).exists()
                    && !paths.iter().any(|p| p.eq_ignore_ascii_case(trimmed))
                {
                    paths.push(trimmed.to_string());
                }
            }
        }
        if paths.is_empty() {
            self.set_toast("Aucun fichier clé .ppk existant trouvé dans vos sessions.");
            return;
        }
        let pageant_exe = self.resolve_pageant_path();
        match launch_pageant_with_keys(&pageant_exe, &paths) {
            Ok(msg) => {
                self.key_manager_status = msg.clone();
                self.set_toast(msg);
                self.refresh_agent_keys();
            }
            Err(e) => {
                self.set_toast(format!("Erreur Pageant : {}", e));
            }
        }
    }

    pub fn launch_session(&mut self, mut profile: SessionProfile) {
        if profile.protocol != ProtocolType::LocalShell {
            let (user, clean_host) = split_user_and_host(&profile.host, &profile.username);
            profile.username = user;
            profile.host = clean_host;
        }
        let cols = 110;
        let rows = 32;
        let mut terminal =
            TerminalEmulator::new(cols, rows, profile.scrollback_lines, &profile.theme_name);

        let welcome = format!(
            "\x1b[1;36m=== Cuty-SSH — Session : {} ({}) ===\x1b[0m\r\n",
            profile.name,
            profile.protocol.label()
        );
        terminal.feed_str(&welcome);

        let log_file_path = if profile.log_to_file {
            let logs_dir = PathBuf::from("cuty-ssh-portable").join("logs");
            let _ = std::fs::create_dir_all(&logs_dir);
            let ts = Local::now().format("%Y%m%d_%H%M%S");
            Some(logs_dir.join(format!("{}_{}.log", profile.name.replace(' ', "_"), ts)))
        } else {
            None
        };

        let is_ssh = profile.protocol == ProtocolType::Ssh;
        let jump_profile = profile
            .jump_host_id
            .and_then(|jid| self.config.sessions.iter().find(|s| s.id == jid).cloned());
        let handle = SessionHandle::spawn(
            &self.rt,
            profile.clone(),
            jump_profile,
            cols as u16,
            rows as u16,
        );

        let tab = SessionTab {
            tab_id: Uuid::new_v4(),
            profile: profile.clone(),
            terminal,
            handle,
            state: TabConnectionState::Connecting,
            status_line: format!("Connexion vers {}:{}...", profile.host, profile.port),
            host_fingerprint: None,
            auth_summary: String::new(),
            pending_prompt: None,
            telemetry: None,
            show_telemetry_bar: is_ssh,
            show_sftp_panel: false,
            show_sftp_full: false,
            sftp_client: sftp_client::SftpClientState::new(),
            sftp_current_path: "/".to_string(),
            sftp_path_input: "/".to_string(),
            sftp_entries: Vec::new(),
            sftp_status: "Prêt".to_string(),
            sftp_mkdir_name: String::new(),
            sftp_sort_col: SftpSortColumn::Name,
            sftp_sort_dir: SortDirection::Ascending,
            sftp_folders_first: true,
            sftp_progress: None,
            sftp_props: None,
            sftp_mirror: SftpMirrorDialog::default(),
            show_search_bar: false,
            search_query: String::new(),
            log_file_path,
            recorder: None,
            connect_instant: None,
            was_connected: false,
            reconnect_attempt: 0,
            reconnect_at: None,
            socks_port: None,
            socks_listen_port: 1080,
        };

        self.tabs.push(tab);
        self.active_tab_idx = self.tabs.len() - 1;
    }

    pub fn close_tab(&mut self, idx: usize) {
        if idx < self.tabs.len() {
            let removed = self.tabs.remove(idx);
            let _ = removed.handle.cmd_tx.send(BackendCommand::Disconnect);
            if self.active_tab_idx >= self.tabs.len() && !self.tabs.is_empty() {
                self.active_tab_idx = self.tabs.len() - 1;
            }
            if self.tabs.len() < 2 {
                self.split_mode = SplitMode::None;
            }
        }
    }

    /// Respawns the backend of tabs whose reconnect timer elapsed.
    fn process_auto_reconnect(&mut self, ctx: &Context) {
        let now = std::time::Instant::now();
        let mut next_wake: Option<std::time::Duration> = None;
        for idx in 0..self.tabs.len() {
            let Some(at) = self.tabs[idx].reconnect_at else {
                continue;
            };
            if at > now {
                let left = at - now;
                next_wake = Some(next_wake.map_or(left, |w| w.min(left)));
                continue;
            }
            self.reconnect_tab(idx);
        }
        // Keep the countdown label fresh, and wake up when a timer elapses.
        if self.tabs.iter().any(|t| t.reconnect_at.is_some()) {
            ctx.request_repaint_after(
                next_wake
                    .unwrap_or_default()
                    .min(std::time::Duration::from_millis(500)),
            );
        }
    }

    /// Replaces the dead backend of `idx` with a fresh one for the same profile.
    pub fn reconnect_tab(&mut self, idx: usize) {
        let Some(profile) = self.tabs.get(idx).map(|t| t.profile.clone()) else {
            return;
        };
        let jump_profile = profile
            .jump_host_id
            .and_then(|jid| self.config.sessions.iter().find(|s| s.id == jid).cloned());
        let (cols, rows) = {
            let t = &self.tabs[idx].terminal.state;
            (t.cols as u16, t.rows as u16)
        };
        let handle = SessionHandle::spawn(&self.rt, profile.clone(), jump_profile, cols, rows);
        let tab = &mut self.tabs[idx];
        let _ = std::mem::replace(&mut tab.handle, handle)
            .cmd_tx
            .send(BackendCommand::Disconnect);
        tab.reconnect_at = None;
        tab.state = TabConnectionState::Connecting;
        tab.status_line = format!(
            "Reconnexion vers {}:{} (tentative {}/{})...",
            profile.host, profile.port, tab.reconnect_attempt, MAX_RECONNECT_ATTEMPTS
        );
        tab.terminal.feed_str(&format!(
            "\r\n\x1b[1;36m\u{E094} {}\x1b[0m\r\n",
            tab.status_line
        ));
    }

    fn poll_backend_events(&mut self, ctx: &Context) {
        if let Some(rx) = &mut self.agent_keys_rx
            && let Ok(keys) = rx.try_recv()
        {
            self.agent_keys = keys;
            self.agent_keys_rx = None;
        }

        let mut any_activity = false;
        while let Ok(probe) = self.probe_rx.try_recv() {
            any_activity = true;
            if let Some(sid) = probe.session_id {
                self.session_probes.insert(sid, probe.clone());
            }
            if let Some(existing) = self
                .probe_results
                .iter_mut()
                .find(|r| r.host == probe.host && r.port == probe.port && r.label == probe.label)
            {
                *existing = probe;
            } else {
                self.probe_results.push(probe);
            }
        }

        let lang = self.config.language;
        let mut has_active_tab = false;
        let mut refresh_known_hosts = false;
        let mut auto_deploy_tabs: Vec<usize> = Vec::new();
        let mut migrated_sessions: Vec<(Uuid, SessionProfile, String, String, bool)> = Vec::new();

        for (tab_idx, tab) in self.tabs.iter_mut().enumerate() {
            if matches!(
                tab.state,
                TabConnectionState::Connecting | TabConnectionState::Connected
            ) {
                has_active_tab = true;
            }

            while let Ok(evt) = tab.handle.evt_rx.try_recv() {
                any_activity = true;
                match evt {
                    BackendEvent::Connected {
                        banner_info,
                        host_key_fingerprint,
                        auth_used,
                    } => {
                        tab.state = TabConnectionState::Connected;
                        tab.was_connected = true;
                        tab.reconnect_attempt = 0;
                        tab.reconnect_at = None;
                        tab.connect_instant = Some(std::time::Instant::now());
                        tab.host_fingerprint = host_key_fingerprint.clone();
                        tab.auth_summary = auth_used.clone();
                        tab.status_line = format!("Connecté : {} ({})", banner_info, auth_used);
                        if host_key_fingerprint.is_some() {
                            refresh_known_hosts = true;
                        }
                        let msg = if let Some(fp) = &host_key_fingerprint {
                            format!(
                                "\x1b[1;32m\u{E182} Connecté à {} | Auth: {} | HostKey: {}\x1b[0m\r\n",
                                banner_info, auth_used, fp
                            )
                        } else {
                            format!(
                                "\x1b[1;32m\u{E182} Connecté à {} | Mode: {}\x1b[0m\r\n",
                                banner_info, auth_used
                            )
                        };
                        tab.terminal.feed_str(&msg);

                        // Audit log CONNECT
                        append_audit_entry(AuditLogEntry {
                            id: Uuid::new_v4(),
                            timestamp_rfc3339: chrono::Utc::now().to_rfc3339(),
                            session_id: Some(tab.profile.id),
                            session_name: tab.profile.name.clone(),
                            protocol: tab.profile.protocol,
                            target: format!("{}:{}", tab.profile.host, tab.profile.port),
                            event_type: "CONNECT".to_string(),
                            duration_secs: None,
                            details: format!(
                                "Auth: {} | HostKey: {}",
                                auth_used,
                                host_key_fingerprint.as_deref().unwrap_or("none")
                            ),
                        });

                        if tab.profile.deploy_primary_key_on_connect {
                            tab.profile.deploy_primary_key_on_connect = false;
                            auto_deploy_tabs.push(tab_idx);
                        }
                    }
                    BackendEvent::Output(bytes) => {
                        tab.terminal.feed_bytes(&bytes);
                        if let Some(rec) = &mut tab.recorder {
                            rec.record_output(&bytes);
                        }
                        // Forward CPR/DA/etc. responses triggered by input immediately
                        for resp in tab.terminal.take_pending_responses() {
                            let _ = tab.handle.cmd_tx.send(BackendCommand::SendInput(resp));
                        }
                        if let Some(log_path) = &tab.log_file_path
                            && let Ok(mut f) =
                                OpenOptions::new().create(true).append(true).open(log_path)
                        {
                            let _ = f.write_all(&bytes);
                        }
                    }
                    BackendEvent::StatusMessage(msg) => {
                        tab.status_line = msg.clone();
                        tab.terminal
                            .feed_str(&format!("\x1b[36mℹ {}\x1b[0m\r\n", msg));
                    }
                    BackendEvent::ErrorMessage(err) => {
                        tab.status_line = err.clone();
                        tab.terminal
                            .feed_str(&format!("\r\n\x1b[1;31m\u{E4F6} {}\x1b[0m\r\n", err));

                        // Audit log ERROR
                        append_audit_entry(AuditLogEntry {
                            id: Uuid::new_v4(),
                            timestamp_rfc3339: chrono::Utc::now().to_rfc3339(),
                            session_id: Some(tab.profile.id),
                            session_name: tab.profile.name.clone(),
                            protocol: tab.profile.protocol,
                            target: format!("{}:{}", tab.profile.host, tab.profile.port),
                            event_type: "ERROR".to_string(),
                            duration_secs: None,
                            details: err.clone(),
                        });
                    }
                    BackendEvent::PromptSecret {
                        title,
                        prompt,
                        is_passphrase,
                    } => {
                        tab.pending_prompt = Some(PendingSecretPrompt {
                            title,
                            prompt,
                            is_passphrase,
                            input_value: String::new(),
                        });
                    }
                    BackendEvent::PublicKeyDeployed {
                        private_key_path,
                        key_comment,
                        already_present,
                    } => {
                        tab.profile.ssh_auth = SshAuthMethod::PrivateKeyFile {
                            key_path: private_key_path.clone(),
                            passphrase: String::new(),
                            cert_path: String::new(),
                        };
                        tab.profile.password.zeroize();
                        tab.profile.password.clear();
                        tab.profile.auto_password = false;
                        tab.profile.deploy_primary_key_on_connect = false;
                        let key_label = if key_comment.is_empty() {
                            private_key_path.clone()
                        } else {
                            key_comment.clone()
                        };
                        tab.auth_summary = format!(
                            "{} ({})",
                            tr(lang, "Clé Principale", "Primary Key"),
                            key_label
                        );
                        let term_msg = if lang == UiLanguage::French {
                            if already_present {
                                format!(
                                    "\r\n\x1b[1;32m\u{E2D6}\u{E182} Clé publique principale ({}) déjà présente dans ~/.ssh/authorized_keys — Session basculée sur l'authentification par clé (mot de passe supprimé).\x1b[0m\r\n",
                                    key_label
                                )
                            } else {
                                format!(
                                    "\r\n\x1b[1;32m\u{E2D6}\u{E182} Clé publique principale ({}) installée dans ~/.ssh/authorized_keys (ssh-copy-id) ! Session basculée sur votre clé (mot de passe supprimé).\x1b[0m\r\n",
                                    key_label
                                )
                            }
                        } else if already_present {
                            format!(
                                "\r\n\x1b[1;32m\u{E2D6}\u{E182} Primary public key ({}) already in ~/.ssh/authorized_keys — Session switched to key auth (password removed).\x1b[0m\r\n",
                                key_label
                            )
                        } else {
                            format!(
                                "\r\n\x1b[1;32m\u{E2D6}\u{E182} Primary public key ({}) installed in ~/.ssh/authorized_keys (ssh-copy-id)! Session switched to key auth (password removed).\x1b[0m\r\n",
                                key_label
                            )
                        };
                        tab.terminal.feed_str(&term_msg);
                        migrated_sessions.push((
                            tab.profile.id,
                            tab.profile.clone(),
                            private_key_path,
                            key_label,
                            already_present,
                        ));
                    }
                    BackendEvent::SocksState(port) => {
                        tab.socks_port = port;
                    }
                    BackendEvent::TelemetryUpdated(metrics) => {
                        tab.telemetry = Some(metrics);
                    }
                    BackendEvent::SftpDirListed {
                        current_path,
                        entries,
                    } => {
                        tab.sftp_current_path = current_path.clone();
                        tab.sftp_path_input = current_path;
                        tab.sftp_entries = entries;
                        tab.sort_sftp_entries();
                        tab.sftp_status = format!("{} éléments", tab.sftp_entries.len());
                        tab.sftp_client.log(
                            format!(
                                "Dossier distant listé : {} ({} éléments)",
                                tab.sftp_current_path,
                                tab.sftp_entries.len()
                            ),
                            false,
                        );
                    }
                    BackendEvent::SftpStatus(st) => {
                        tab.sftp_client.log(
                            &st,
                            st.contains("Erreur") || st.contains("Error") || st.contains("échec"),
                        );
                        tab.sftp_status = st;
                        tab.sftp_progress = None;
                        if let Some(p) = tab.sftp_props.as_mut() {
                            p.hashing = false;
                        }
                    }
                    BackendEvent::SftpHashResult {
                        remote_path,
                        sha256,
                        size,
                    } => {
                        tab.sftp_status = format!("SHA-256 {remote_path} ({size} B)");
                        if let Some(p) = tab.sftp_props.as_mut()
                            && p.entry.full_path == remote_path
                        {
                            p.sha256 = Some(sha256);
                            p.hashing = false;
                        }
                    }
                    BackendEvent::SftpMirrorReport {
                        lines,
                        summary,
                        dry_run: _,
                    } => {
                        tab.sftp_mirror.lines = lines;
                        tab.sftp_mirror.summary = summary;
                        tab.sftp_mirror.busy = false;
                        tab.sftp_progress = None;
                    }
                    BackendEvent::SftpProgress {
                        filename,
                        transferred,
                        total,
                        is_upload,
                        done,
                    } => {
                        if done || (total > 0 && transferred >= total) {
                            tab.sftp_progress = None;
                            if is_upload {
                                if let Some(task) =
                                    tab.sftp_client.upload_queue.iter_mut().find(|t| {
                                        t.filename == filename
                                            && t.status == sftp_client::QueueTaskStatus::InProgress
                                    })
                                {
                                    task.status = sftp_client::QueueTaskStatus::Completed;
                                    task.transferred = task.size;
                                }
                            } else {
                                if let Some(task) =
                                    tab.sftp_client.download_queue.iter_mut().find(|t| {
                                        t.filename == filename
                                            && t.status == sftp_client::QueueTaskStatus::InProgress
                                    })
                                {
                                    task.status = sftp_client::QueueTaskStatus::Completed;
                                    task.transferred = task.size;
                                }
                                tab.sftp_client.refresh_local();
                            }
                            tab.sftp_client.check_watched_files(
                                ctx,
                                &tab.handle.cmd_tx,
                                self.config.language,
                            );
                            tab.sftp_client
                                .log(format!("Transfert terminé : {filename}"), false);
                        } else {
                            tab.sftp_progress = Some(SftpTransferProgress {
                                filename: filename.clone(),
                                transferred,
                                total,
                                is_upload,
                            });
                            if is_upload {
                                if let Some(task) =
                                    tab.sftp_client.upload_queue.iter_mut().find(|t| {
                                        t.filename == filename
                                            && t.status == sftp_client::QueueTaskStatus::InProgress
                                    })
                                {
                                    task.transferred = transferred;
                                    if total > 0 {
                                        task.size = total;
                                    }
                                }
                            } else {
                                if let Some(task) =
                                    tab.sftp_client.download_queue.iter_mut().find(|t| {
                                        t.filename == filename
                                            && t.status == sftp_client::QueueTaskStatus::InProgress
                                    })
                                {
                                    task.transferred = transferred;
                                    if total > 0 {
                                        task.size = total;
                                    }
                                }
                            }
                        }
                    }
                    BackendEvent::Disconnected(reason) => {
                        tab.state = TabConnectionState::Disconnected(reason.clone());
                        tab.status_line = reason.clone();
                        tab.terminal
                            .feed_str(&format!("\r\n\x1b[1;33m⚠ {}\x1b[0m\r\n", reason));

                        let dropped = tab.was_connected
                            && reason != USER_DISCONNECT_REASON
                            && matches!(
                                tab.profile.protocol,
                                ProtocolType::Ssh | ProtocolType::Telnet | ProtocolType::RawTcp
                            );
                        tab.was_connected = false;
                        if tab.profile.auto_reconnect
                            && (dropped || tab.reconnect_attempt > 0)
                            && reason != USER_DISCONNECT_REASON
                            && tab.reconnect_attempt < MAX_RECONNECT_ATTEMPTS
                        {
                            tab.reconnect_attempt += 1;
                            tab.reconnect_at = Some(
                                std::time::Instant::now()
                                    + std::time::Duration::from_secs(reconnect_delay_secs(
                                        tab.reconnect_attempt,
                                    )),
                            );
                        } else {
                            tab.reconnect_at = None;
                        }

                        let dur_secs = tab.connect_instant.take().map(|i| i.elapsed().as_secs());
                        if let Some(rec) = tab.recorder.take() {
                            let _ = rec.stop();
                        }

                        // Audit log DISCONNECT
                        append_audit_entry(AuditLogEntry {
                            id: Uuid::new_v4(),
                            timestamp_rfc3339: chrono::Utc::now().to_rfc3339(),
                            session_id: Some(tab.profile.id),
                            session_name: tab.profile.name.clone(),
                            protocol: tab.profile.protocol,
                            target: format!("{}:{}", tab.profile.host, tab.profile.port),
                            event_type: "DISCONNECT".to_string(),
                            duration_secs: dur_secs,
                            details: reason.clone(),
                        });
                    }
                }
            }

            // Flush any remaining outbound terminal responses (e.g. from banner or queries)
            for resp in tab.terminal.take_pending_responses() {
                let _ = tab.handle.cmd_tx.send(BackendCommand::SendInput(resp));
            }
        }

        for idx in auto_deploy_tabs {
            self.deploy_primary_key_to_tab(idx);
        }

        if !migrated_sessions.is_empty() {
            for (sid, updated_profile, priv_path, key_label, already_present) in migrated_sessions {
                if let Some(existing) = self.config.sessions.iter_mut().find(|s| s.id == sid) {
                    existing.ssh_auth = SshAuthMethod::PrivateKeyFile {
                        key_path: priv_path.clone(),
                        passphrase: String::new(),
                        cert_path: String::new(),
                    };
                    existing.password.zeroize();
                    existing.password.clear();
                    existing.auto_password = false;
                    existing.deploy_primary_key_on_connect = false;
                } else {
                    self.config.sessions.push(updated_profile);
                }
                let toast = if lang == UiLanguage::French {
                    if already_present {
                        format!(
                            "Clé '{}' vérifiée sur le serveur — session basculée sur la clé (sans mot de passe)",
                            key_label
                        )
                    } else {
                        format!(
                            "Clé publique '{}' installée (ssh-copy-id) — session basculée sur votre clé principale !",
                            key_label
                        )
                    }
                } else if already_present {
                    format!(
                        "Key '{}' verified on server — session switched to key auth (passwordless)",
                        key_label
                    )
                } else {
                    format!(
                        "Public key '{}' installed (ssh-copy-id) — session switched to Primary Key!",
                        key_label
                    )
                };
                self.set_toast(toast);
            }
            let _ = self.config.save();
        }

        if refresh_known_hosts {
            self.known_hosts = crate::config::load_known_hosts();
        }

        if any_activity {
            ctx.request_repaint();
        } else if has_active_tab {
            // Keep polling backend events and responses with low latency when sessions are active
            ctx.request_repaint_after(std::time::Duration::from_millis(25));
        }
    }

    /// Resolves (or generates) the user's Primary SSH Key, pushes its public key (`ssh-copy-id`)
    /// to the active SSH session at `tab_idx`, and switches the session profile to key auth.
    pub fn deploy_primary_key_to_tab(&mut self, tab_idx: usize) {
        let lang = self.config.language;
        match resolve_or_create_primary_key(&self.config.primary_key_path) {
            Ok((key_path, info, newly_created)) => {
                let path_str = key_path.to_string_lossy().to_string();
                if self.config.primary_key_path.trim().is_empty() || newly_created {
                    self.config.primary_key_path = path_str.clone();
                    let _ = self.config.save();
                }
                if let Some(tab) = self.tabs.get_mut(tab_idx) {
                    if newly_created {
                        let gen_msg = if lang == UiLanguage::French {
                            format!(
                                "\x1b[36mℹ Clé principale Ed25519 générée automatiquement : {}\x1b[0m\r\n",
                                path_str
                            )
                        } else {
                            format!(
                                "\x1b[36mℹ Auto-generated Ed25519 Primary Key: {}\x1b[0m\r\n",
                                path_str
                            )
                        };
                        tab.terminal.feed_str(&gen_msg);
                    }
                    let _ = tab.handle.cmd_tx.send(BackendCommand::DeployPublicKey {
                        openssh_public_key: info.openssh_public_key,
                        private_key_path: path_str,
                        key_comment: info.comment,
                    });
                }
            }
            Err(e) => {
                self.set_toast(format!(
                    "{} : {}",
                    tr(
                        lang,
                        "Erreur Clé Principale (ssh-copy-id)",
                        "Primary Key Error (ssh-copy-id)"
                    ),
                    e
                ));
            }
        }
    }

    pub(crate) fn send_bytes_to_active_or_broadcast(&mut self, bytes: &[u8]) {
        if self.broadcast_mode {
            for tab in &mut self.tabs {
                if !tab.profile.read_only && tab.state == TabConnectionState::Connected {
                    if let Some(rec) = &mut tab.recorder {
                        rec.record_input(bytes);
                    }
                    let _ = tab
                        .handle
                        .cmd_tx
                        .send(BackendCommand::SendInput(bytes.to_vec()));
                }
            }
        } else if let Some(tab) = self.tabs.get_mut(self.active_tab_idx)
            && !tab.profile.read_only
        {
            if let Some(rec) = &mut tab.recorder {
                rec.record_input(bytes);
            }
            let _ = tab
                .handle
                .cmd_tx
                .send(BackendCommand::SendInput(bytes.to_vec()));
        }
    }
}

impl eframe::App for CutySshApp {
    fn ui(&mut self, ui: &mut Ui, _frame: &mut eframe::Frame) {
        let ctx = ui.ctx().clone();
        self.poll_backend_events(&ctx);
        self.process_auto_reconnect(&ctx);

        for tab in &mut self.tabs {
            tab.sftp_client
                .check_watched_files(&ctx, &tab.handle.cmd_tx, self.config.language);
        }

        // Global Ctrl+K shortcut for the Command & Session Palette
        if ctx.input(|i| i.modifiers.ctrl && i.key_pressed(Key::K)) {
            self.show_command_palette = !self.show_command_palette;
            if self.show_command_palette {
                self.palette_query.clear();
            }
        }

        self.render_top_toolbar(ui, &ctx);

        if self.is_rolled_up {
            return;
        }

        if self.config.show_command_bar {
            self.render_predefined_commands_bar(ui);
        }

        self.render_bottom_status_bar(ui);

        if self.show_sidebar {
            self.render_left_sidebar(ui);
        }

        // Right-side SFTP panel if active on the current tab
        let show_sftp = self
            .tabs
            .get(self.active_tab_idx)
            .map(|t| t.show_sftp_panel && t.profile.protocol == ProtocolType::Ssh)
            .unwrap_or(false);
        if show_sftp {
            self.render_sftp_side_panel(ui);
        }

        // Central area: tabs + terminal emulator
        egui::CentralPanel::default()
            .frame(egui::Frame::NONE.fill(Color32::from_rgb(11, 14, 20)))
            .show(ui, |ui| {
                if self.tabs.is_empty() {
                    self.render_welcome_dashboard(ui);
                } else {
                    self.render_tabs_bar(ui);
                    let is_sftp_full = self
                        .tabs
                        .get(self.active_tab_idx)
                        .map(|t| t.show_sftp_full && t.profile.protocol == ProtocolType::Ssh)
                        .unwrap_or(false);
                    if is_sftp_full {
                        self.render_sftp_client_full(ui, &ctx);
                    } else {
                        self.render_active_terminal(ui, &ctx);
                    }
                }
            });

        // Modal windows
        if self.show_session_editor {
            self.render_session_editor_modal(&ctx);
        }
        if self.show_key_manager {
            self.render_key_manager_modal(&ctx);
        }
        if self.show_commands_editor {
            self.render_commands_editor_modal(&ctx);
        }
        if self.show_command_palette {
            self.render_command_palette_modal(&ctx);
        }
        if self.show_network_tools {
            self.render_network_tools_modal(&ctx);
        }
        if self.show_about {
            self.render_about_modal(&ctx);
        }
        if self.show_session_manager {
            self.render_session_manager_modal(&ctx);
        }
        if self.show_known_hosts {
            self.render_known_hosts_modal(&ctx);
        }
        if self.show_audit_modal {
            self.render_audit_modal(&ctx);
        }
        if self.show_replay_modal {
            self.render_replay_modal(&ctx);
        }
        if self.show_help {
            self.render_help_modal(&ctx);
        }
        self.render_pending_secret_modal(&ctx);

        // Background non-blocking Fleet Ping refresh every 45 seconds
        if let Some(last_probe) = self.last_fleet_probe_time
            && last_probe.elapsed() > std::time::Duration::from_secs(45)
        {
            self.last_fleet_probe_time = Some(std::time::Instant::now());
            self.probe_all_sessions();
        }
    }
}

impl CutySshApp {
    fn sync_external_sessions(&mut self) {
        let lang = self.config.language;
        let mut total_imported = 0usize;
        #[cfg(windows)]
        if let Ok(n) = self.config.import_from_windows_registry() {
            total_imported += n;
        }
        if let Ok(n) = self.config.import_from_openssh_config(None) {
            total_imported += n;
        }
        if !self.config.kitty_dir.trim().is_empty()
            && let Ok(n) = self
                .config
                .import_from_kitty_dir(Path::new(&self.config.kitty_dir.clone()))
        {
            total_imported += n;
        }
        self.probe_all_sessions();
        self.set_toast(if lang == UiLanguage::French {
            format!(
                "Synchronisation PuTTY + ~/.ssh/config terminée ({} nouvelle(s) session(s)) !",
                total_imported
            )
        } else {
            format!(
                "PuTTY + ~/.ssh/config sync complete ({} new session(s))!",
                total_imported
            )
        });
    }

    fn import_bitvise_profiles(&mut self) {
        let lang = self.config.language;
        let Some(files) = rfd::FileDialog::new()
            .set_title(tr(
                lang,
                "Profils Bitvise SSH Client (.tlp / .bscp)",
                "Bitvise SSH Client profiles (.tlp / .bscp)",
            ))
            .add_filter("Bitvise profile", &["tlp", "bscp"])
            .pick_files()
        else {
            return;
        };
        let report = self.config.import_bitvise_profiles(&files);
        if report.added > 0 {
            let _ = self.config.save();
        }
        let mut msg = format!(
            "{} {}",
            report.added,
            tr(
                lang,
                "profil(s) Bitvise importé(s)",
                "Bitvise profile(s) imported"
            )
        );
        if report.duplicates > 0 {
            msg.push_str(&format!(
                ", {} {}",
                report.duplicates,
                tr(lang, "déjà présent(s)", "already present")
            ));
        }
        if !report.errors.is_empty() {
            msg.push_str(&format!(
                ", {} {} ({})",
                report.errors.len(),
                tr(lang, "ignoré(s)", "skipped"),
                report.errors[0]
            ));
        }
        self.set_toast(msg);
    }

    fn import_kitty_folder(&mut self) {
        let lang = self.config.language;
        let Some(dir) = rfd::FileDialog::new()
            .set_title(tr(
                lang,
                "Dossier KiTTY portable (contenant Sessions)",
                "Portable KiTTY folder (containing Sessions)",
            ))
            .pick_folder()
        else {
            return;
        };
        self.config.kitty_dir = dir.to_string_lossy().to_string();
        let msg = match self.config.import_from_kitty_dir(&dir) {
            Ok(n) => {
                self.probe_all_sessions();
                format!(
                    "{} {}",
                    n,
                    tr(
                        lang,
                        "session(s) KiTTY importée(s) !",
                        "KiTTY session(s) imported!"
                    )
                )
            }
            Err(e) => format!(
                "{} {}",
                tr(lang, "Erreur import KiTTY :", "KiTTY import error:"),
                e
            ),
        };
        let _ = self.config.save();
        self.set_toast(msg);
    }

    fn render_top_toolbar(&mut self, ui: &mut Ui, ctx: &Context) {
        let lang = self.config.language;
        egui::Panel::top("top_toolbar")
            .frame(
                egui::Frame::NONE
                    .fill(theme::TOOLBAR_BG)
                    .inner_margin(egui::Margin::symmetric(10, 6))
                    .stroke(Stroke::new(1.0, Color32::from_rgb(38, 46, 62))),
            )
            .show(ui, |ui| {
                ui.horizontal(|ui| {
                    // --- LEFT: sessions & launch ---
                    if ui
                        .selectable_label(
                            self.show_sidebar,
                            theme::icon_label(theme::icons::SIDEBAR, "Sessions"),
                        )
                        .on_hover_text(tr(
                            lang,
                            "Afficher/Masquer la barre latérale des sessions",
                            "Show/Hide the sessions sidebar",
                        ))
                        .clicked()
                    {
                        self.show_sidebar = !self.show_sidebar;
                    }

                    if theme::primary_button(
                        ui,
                        theme::icons::PLUS,
                        tr(lang, "Nouvelle session", "New Session"),
                    )
                    .on_hover_text(tr(
                        lang,
                        "Créer et configurer une nouvelle session (SSH, Telnet, ConPTY...)",
                        "Create and configure a new session (SSH, Telnet, ConPTY...)",
                    ))
                    .clicked()
                    {
                        self.editing_session = SessionProfile::default();
                        self.is_new_session = true;
                        self.editor_tab = ConfigEditorTab::ConnectionAndKey;
                        self.show_session_editor = true;
                    }

                    if theme::tool_button(ui, theme::icons::LIGHTNING, "Shell")
                        .on_hover_text(tr(
                            lang,
                            "Ouvrir immédiatement un terminal local PowerShell",
                            "Immediately open a local PowerShell ConPTY terminal",
                        ))
                        .clicked()
                    {
                        let p = SessionProfile {
                            name: "PowerShell Local".to_string(),
                            protocol: ProtocolType::LocalShell,
                            local_shell_cmd: "powershell.exe".to_string(),
                            icon_badge: "⚡".to_string(),
                            ..Default::default()
                        };
                        self.launch_session(p);
                    }

                    if theme::tool_button(ui, theme::icons::SEARCH, "Ctrl+K")
                        .on_hover_text(tr(
                            lang,
                            "Recherche et lancement rapide de sessions et commandes (Ctrl+K)",
                            "Quickly search and launch sessions & commands (Ctrl+K)",
                        ))
                        .clicked()
                    {
                        self.show_command_palette = true;
                        self.palette_query.clear();
                    }

                    ui.separator();

                    // --- CENTER: management & tools ---
                    if theme::tool_button(
                        ui,
                        theme::icons::FOLDER,
                        tr(lang, "Gestionnaire", "Manager"),
                    )
                    .on_hover_text(tr(
                        lang,
                        "Gestionnaire avancé de sessions (organisation, dossiers, tags, import/export JSON, actions en lot)",
                        "Advanced session manager (folders, tags, JSON import/export, bulk actions)",
                    ))
                    .clicked()
                    {
                        self.show_session_manager = true;
                    }

                    let keys_label = if self.agent_keys.is_empty() {
                        tr(lang, "Clés PPK", "PPK Keys").to_string()
                    } else {
                        format!("{} ({})", tr(lang, "Clés", "Keys"), self.agent_keys.len())
                    };
                    if theme::tool_button(ui, theme::icons::KEY, &keys_label)
                        .on_hover_text(tr(
                            lang,
                            "Gestionnaire de clés PuTTY (.ppk v2/v3), Pageant, conversion et génération",
                            "PuTTY (.ppk v2/v3) & Pageant key manager, converter and key generator",
                        ))
                        .clicked()
                    {
                        self.refresh_agent_keys();
                        self.show_key_manager = true;
                    }

                    ui.menu_button(
                        theme::icon_label(
                            theme::icons::TOOLS,
                            &format!("{} {}", tr(lang, "Outils", "Tools"), theme::icons::CARET_DOWN),
                        ),
                        |ui| {
                            let kh_label = if self.known_hosts.is_empty() {
                                "Known Hosts".to_string()
                            } else {
                                format!("Known Hosts ({})", self.known_hosts.len())
                            };
                            if theme::tool_button(ui, theme::icons::SHIELD, &kh_label)
                                .on_hover_text(tr(
                                    lang,
                                    "Gestionnaire Known Hosts TOFU (empreintes SHA-256 des serveurs SSH & import ~/.ssh/config)",
                                    "TOFU Known Hosts manager (SSH server SHA-256 fingerprints & ~/.ssh/config import)",
                                ))
                                .clicked()
                            {
                                self.known_hosts = crate::config::load_known_hosts();
                                self.show_known_hosts = true;
                            }

                            if theme::tool_button(
                                ui,
                                theme::icons::NETWORK,
                                tr(lang, "Diagnostic réseau", "Network tools"),
                            )
                            .on_hover_text(tr(
                                lang,
                                "Scanner TCP/SSH, latence ms, bannières et calculateur CIDR",
                                "TCP/SSH port scanner, ms latency, banners and IPv4 CIDR calculator",
                            ))
                            .clicked()
                            {
                                self.show_network_tools = true;
                            }

                            if theme::tool_button(ui, theme::icons::AUDIT, "Audit")
                                .on_hover_text(tr(
                                    lang,
                                    "Journal d'audit des connexions, déconnexions et durées de sessions avec export CSV/JSON",
                                    "Session connections and duration audit log with CSV/JSON export",
                                ))
                                .clicked()
                            {
                                self.refresh_audit_entries();
                                self.show_audit_modal = true;
                            }

                            if theme::tool_button(ui, theme::icons::REPLAY, "Replay")
                                .on_hover_text(tr(
                                    lang,
                                    "Lecteur Replay interactif d'enregistrements de sessions (.cast Asciinema)",
                                    "Interactive Asciinema session replay player (.cast)",
                                ))
                                .clicked()
                            {
                                self.show_replay_modal = true;
                            }
                        },
                    );

                    ui.menu_button(
                        theme::icon_label(
                            theme::icons::DOWNLOAD,
                            &format!("Import {}", theme::icons::CARET_DOWN),
                        ),
                        |ui| {
                            if theme::tool_button(
                                ui,
                                theme::icons::SYNC,
                                "Sync PuTTY + ssh_config",
                            )
                            .on_hover_text(tr(
                                lang,
                                "Synchroniser les sessions depuis le Registre PuTTY et ~/.ssh/config",
                                "Synchronize sessions from Windows PuTTY Registry and ~/.ssh/config",
                            ))
                            .clicked()
                            {
                                self.sync_external_sessions();
                            }

                            if theme::tool_button(ui, theme::icons::FOLDER, "KiTTY…")
                                .on_hover_text(tr(
                                    lang,
                                    "Importer les sessions d'un dossier KiTTY portable (contenant Sessions)",
                                    "Import sessions from a portable KiTTY folder (containing Sessions)",
                                ))
                                .clicked()
                            {
                                self.import_kitty_folder();
                            }

                            if theme::tool_button(ui, theme::icons::FOLDER, "Bitvise…")
                                .on_hover_text(tr(
                                    lang,
                                    "Importer des profils Bitvise SSH Client (.tlp / .bscp) : hôte, port, utilisateur",
                                    "Import Bitvise SSH Client profiles (.tlp / .bscp): host, port, user",
                                ))
                                .clicked()
                            {
                                self.import_bitvise_profiles();
                            }
                        },
                    );

                    if ui
                        .selectable_label(
                            self.config.show_command_bar,
                            theme::icon_label(theme::icons::SNIPPETS, "Snippets"),
                        )
                        .on_hover_text(tr(
                            lang,
                            "Afficher/Masquer le bandeau de commandes et scripts rapides (Snippets)",
                            "Show/Hide the quick command snippets bar",
                        ))
                        .clicked()
                    {
                        self.config.show_command_bar = !self.config.show_command_bar;
                        let _ = self.config.save();
                    }

                    // --- RIGHT: language, window controls, help & about ---
                    ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                        let lang_btn_txt = match lang {
                            UiLanguage::French => "FR",
                            UiLanguage::English => "EN",
                        };
                        if theme::tool_button(ui, theme::icons::GLOBE, lang_btn_txt)
                            .on_hover_text(tr(
                                lang,
                                "Basculer la langue de l'interface en Anglais (English)",
                                "Switch interface language to French (Français)",
                            ))
                            .clicked()
                        {
                            self.config.language = match lang {
                                UiLanguage::French => UiLanguage::English,
                                UiLanguage::English => UiLanguage::French,
                            };
                            let _ = self.config.save();
                            self.set_toast(match self.config.language {
                                UiLanguage::French => "Langue de l'interface : Français 🇫🇷",
                                UiLanguage::English => "Interface language switched to English 🇬🇧",
                            });
                        }

                        if ui
                            .button(theme::icons::PALETTE)
                            .on_hover_text(tr(
                                lang,
                                "À propos de Cuty-SSH, design et identité",
                                "About Cuty-SSH, design system and visual identity",
                            ))
                            .clicked()
                        {
                            self.show_about = true;
                        }

                        if ui
                            .selectable_label(
                                self.show_help,
                                theme::icon_label(theme::icons::BOOK, tr(lang, "Aide", "Help")),
                            )
                            .on_hover_text(tr(
                                lang,
                                "Ouvrir le Guide Utilisateur illustré (Bastion SSH, Tags, Clés .ppk, SFTP, Sécurité...)",
                                "Open the Illustrated User Guide (SSH Bastion, Tags, .ppk Keys, SFTP, Security...)",
                            ))
                            .clicked()
                        {
                            self.show_help = !self.show_help;
                        }

                        if ui
                            .selectable_label(self.config.global_always_on_top, theme::icons::PIN)
                            .on_hover_text(tr(
                                lang,
                                "Maintenir la fenêtre toujours au premier plan",
                                "Keep window always on top",
                            ))
                            .clicked()
                        {
                            self.config.global_always_on_top = !self.config.global_always_on_top;
                            let level = if self.config.global_always_on_top {
                                WindowLevel::AlwaysOnTop
                            } else {
                                WindowLevel::Normal
                            };
                            ctx.send_viewport_cmd(ViewportCommand::WindowLevel(level));
                            let _ = self.config.save();
                        }

                        let rollup_icon = if self.is_rolled_up {
                            theme::icons::CARET_DOWN
                        } else {
                            theme::icons::CARET_UP
                        };
                        if ui
                            .selectable_label(self.is_rolled_up, rollup_icon)
                            .on_hover_text(tr(
                                lang,
                                "Enrouler/dérouler la fenêtre en bandeau compact (Roll-up)",
                                "Roll up / unroll the window into a compact header bar",
                            ))
                            .clicked()
                        {
                            self.is_rolled_up = !self.is_rolled_up;
                            if self.is_rolled_up {
                                if let Some(rect) = ctx.input(|i| i.viewport().inner_rect) {
                                    self.saved_window_size = rect.size();
                                }
                                ctx.send_viewport_cmd(ViewportCommand::InnerSize(Vec2::new(
                                    self.saved_window_size.x.max(600.0),
                                    46.0,
                                )));
                            } else {
                                ctx.send_viewport_cmd(ViewportCommand::InnerSize(
                                    self.saved_window_size,
                                ));
                            }
                        }

                        if !self.tabs.is_empty() {
                            ui.separator();
                            // Icon-only when off: keeps the right-hand group from running into
                            // the left one at the default 1320 px width.
                            let label = if self.broadcast_mode {
                                RichText::new(theme::icon_label(theme::icons::BROADCAST, "ON"))
                                    .color(theme::DANGER)
                                    .strong()
                            } else {
                                RichText::new(theme::icons::BROADCAST)
                            };
                            if ui
                                .selectable_label(self.broadcast_mode, label)
                                .on_hover_text(tr(
                                    lang,
                                    "Envoyer les saisies clavier simultanément à tous les onglets connectés",
                                    "Send keyboard input simultaneously to all connected tabs",
                                ))
                                .clicked()
                            {
                                self.broadcast_mode = !self.broadcast_mode;
                            }
                        }
                    });
                });
            });
    }

    fn render_predefined_commands_bar(&mut self, ui: &mut Ui) {
        let lang = self.config.language;
        egui::Panel::top("command_shortcuts_bar")
            .frame(
                egui::Frame::NONE
                    .fill(Color32::from_rgb(13, 17, 24))
                    .inner_margin(egui::Margin::symmetric(10, 4))
                    .stroke(Stroke::new(1.0, Color32::from_rgb(32, 39, 52))),
            )
            .show(ui, |ui| {
                ui.horizontal(|ui| {
                    ui.label(
                        RichText::new("\u{E2DE} Snippets :")
                            .size(11.0)
                            .strong()
                            .color(Color32::from_rgb(140, 190, 255)),
                    );

                    let mut cmd_to_send: Option<(String, bool)> = None;
                    for cmd in &self.config.predefined_commands {
                        if ui
                            .button(
                                RichText::new(&cmd.label)
                                    .size(11.0)
                                    .color(Color32::from_rgb(220, 225, 235)),
                            )
                            .on_hover_text(format!(
                                "{}\n{}: {}",
                                cmd.description,
                                tr(lang, "Commande", "Command"),
                                cmd.command
                            ))
                            .clicked()
                        {
                            cmd_to_send = Some((cmd.command.clone(), cmd.append_enter));
                        }
                    }

                    if let Some((text, enter)) = cmd_to_send {
                        let payload = if enter { format!("{}\r", text) } else { text };
                        self.send_bytes_to_active_or_broadcast(payload.as_bytes());
                    }

                    ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                        if ui
                            .small_button("\u{E4F6}")
                            .on_hover_text(tr(
                                lang,
                                "Masquer ce bandeau (réactivable via \u{E2DE} Snippets dans la barre supérieure)",
                                "Hide this bar (re-enable via \u{E2DE} Snippets in the top toolbar)",
                            ))
                            .clicked()
                        {
                            self.config.show_command_bar = false;
                            let _ = self.config.save();
                        }

                        if ui
                            .small_button(tr(lang, "\u{E270} Éditer", "\u{E270} Edit"))
                            .on_hover_text(tr(
                                lang,
                                "Ajouter ou modifier les raccourcis de commandes prédéfinies",
                                "Add or edit predefined command shortcuts",
                            ))
                            .clicked()
                        {
                            self.show_commands_editor = true;
                        }
                    });
                });
            });
    }

    fn render_bottom_status_bar(&mut self, ui: &mut Ui) {
        let lang = self.config.language;
        egui::Panel::bottom("bottom_status_bar")
            .frame(
                egui::Frame::NONE
                    .fill(Color32::from_rgb(16, 20, 28))
                    .inner_margin(egui::Margin::symmetric(12, 5))
                    .stroke(Stroke::new(1.0, Color32::from_rgb(38, 46, 62))),
            )
            .show(ui, |ui| {
                ui.horizontal(|ui| {
                    if let Some(tab) = self.tabs.get(self.active_tab_idx) {
                        let dot = match tab.state {
                            TabConnectionState::Connected => {
                                RichText::new(tr(lang, "● Connecté", "● Connected"))
                                    .color(Color32::from_rgb(52, 211, 153))
                            }
                            TabConnectionState::Connecting => {
                                RichText::new(tr(lang, "◐ Connexion...", "◐ Connecting..."))
                                    .color(Color32::from_rgb(210, 153, 34))
                            }
                            TabConnectionState::Disconnected(_) => {
                                if let Some(at) = tab.reconnect_at {
                                    let secs = at
                                        .saturating_duration_since(std::time::Instant::now())
                                        .as_secs()
                                        + 1;
                                    RichText::new(format!(
                                        "{} {}s ({}/{})",
                                        tr(lang, "\u{E094} Reconnexion dans", "\u{E094} Reconnecting in"),
                                        secs,
                                        tab.reconnect_attempt,
                                        MAX_RECONNECT_ATTEMPTS
                                    ))
                                    .color(Color32::from_rgb(210, 153, 34))
                                } else {
                                    RichText::new(tr(lang, "○ Déconnecté", "○ Disconnected"))
                                        .color(Color32::from_rgb(248, 81, 73))
                                }
                            }
                        };
                        ui.label(dot);
                        ui.separator();
                        ui.label(
                            RichText::new(&tab.status_line)
                                .small()
                                .color(Color32::from_rgb(201, 209, 217)),
                        );
                        if let Some(fp) = &tab.host_fingerprint {
                            ui.separator();
                            ui.label(
                                RichText::new(format!("\u{E40C} {}", fp))
                                    .small()
                                    .color(Color32::from_rgb(139, 148, 158)),
                            );
                        }
                        ui.separator();
                        ui.label(
                            RichText::new(format!(
                                "{}x{} | Scrollback: {}",
                                tab.terminal.state.cols,
                                tab.terminal.state.rows,
                                tab.terminal.state.scrollback.len()
                            ))
                            .small()
                            .color(Color32::from_rgb(139, 148, 158)),
                        );
                    } else {
                        ui.label(
                            RichText::new(tr(
                                lang,
                                "Prêt — Mode Portable actif (cuty-ssh-portable/) • Ctrl+K : Palette rapide • \u{E0E6} Aide disponible",
                                "Ready — Portable Mode active (cuty-ssh-portable/) • Ctrl+K: Quick Palette • \u{E0E6} Help available",
                            ))
                            .small()
                            .color(Color32::from_rgb(139, 148, 158)),
                        );
                    }

                    ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                        let pageant_status = if self.agent_keys.is_empty() {
                            tr(
                                lang,
                                "Pageant: 0 clé (ou inactif)",
                                "Pageant: 0 keys (or inactive)",
                            )
                            .to_string()
                        } else if lang == UiLanguage::French {
                            format!("Pageant/Agent: {} clé(s) prête(s)", self.agent_keys.len())
                        } else {
                            format!("Pageant/Agent: {} key(s) ready", self.agent_keys.len())
                        };
                        if ui
                            .small_button(format!("🔐 {}", pageant_status))
                            .on_hover_text(tr(
                                lang,
                                "Cliquer pour ouvrir le gestionnaire Pageant & clés .ppk",
                                "Click to open the Pageant & .ppk Key Manager",
                            ))
                            .clicked()
                        {
                            self.refresh_agent_keys();
                            self.show_key_manager = true;
                        }

                        if let Some((msg, ts)) = &self.toast_message
                            && ts.elapsed().as_secs() < 6
                        {
                            ui.separator();
                            ui.label(
                                RichText::new(format!("\u{E6A2} {}", msg))
                                    .small()
                                    .color(Color32::from_rgb(88, 166, 255)),
                            );
                        }
                    });
                });
            });
    }

    fn render_left_sidebar(&mut self, ui: &mut Ui) {
        let lang = self.config.language;
        egui::Panel::left("sessions_sidebar_v2")
            .resizable(true)
            .default_size(320.0)
            .min_size(240.0)
            .max_size(450.0)
            .frame(
                egui::Frame::NONE
                    .fill(Color32::from_rgb(15, 19, 27))
                    .inner_margin(egui::Margin::same(10))
                    .stroke(Stroke::new(1.0, Color32::from_rgb(38, 46, 62))),
            )
            .show(ui, |ui| {
                ui.horizontal(|ui| {
                    ui.heading(
                        RichText::new("\u{E3FE} Sessions")
                            .size(15.0)
                            .color(Color32::from_rgb(240, 246, 252)),
                    );
                    ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                        if ui
                            .small_button("⏴")
                            .on_hover_text(tr(
                                lang,
                                "Masquer le volet des sessions (rouvrable via le bouton \u{E260} Sessions)",
                                "Hide the sessions sidebar (re-open via \u{E260} Sessions)",
                            ))
                            .clicked()
                        {
                            self.show_sidebar = false;
                        }
                        if ui
                            .small_button("\u{E0F2} Ping")
                            .on_hover_text(tr(
                                lang,
                                "Tester en parallèle la disponibilité et la latence TCP de toutes les sessions",
                                "Probe TCP reachability and latency across all saved sessions in parallel",
                            ))
                            .clicked()
                        {
                            self.probe_all_sessions();
                            self.set_toast(tr(
                                lang,
                                "Scan TCP de toutes les sessions lancé...",
                                "Parallel TCP probe started for all sessions...",
                            ));
                        }
                    });
                });
                ui.add_space(4.0);

                // Session filter
                ui.horizontal(|ui| {
                    ui.label("\u{E30C}");
                    let clear_reserve = if self.session_filter.is_empty() {
                        0.0
                    } else {
                        32.0
                    };
                    ui.add(
                        egui::TextEdit::singleline(&mut self.session_filter)
                            .hint_text(tr(
                                lang,
                                "Filtrer (nom, IP, #tag, dossier)...",
                                "Filter (name, IP, #tag, folder)...",
                            ))
                            .desired_width((ui.available_width() - clear_reserve).max(60.0)),
                    );
                    if !self.session_filter.is_empty() && ui.small_button("\u{E4F6}").clicked() {
                        self.session_filter.clear();
                    }
                });

                ui.add_space(2.0);
                ui.label(
                    RichText::new(tr(
                        lang,
                        "\u{E2DC} Cliquez sur \u{E3FE} Connecter ou sur le nom d'une session",
                        "\u{E2DC} Click \u{E3FE} Connect or any session title to launch",
                    ))
                    .size(10.0)
                    .color(Color32::from_rgb(110, 118, 129)),
                );
                ui.add_space(2.0);

                // Quick action buttons: Nouvelle Session & Gestionnaire de Sessions
                ui.horizontal(|ui| {
                    let avail = ui.available_width();
                    let btn_w = ((avail - 6.0) / 2.0).max(110.0);
                    if ui
                        .add_sized(
                            [btn_w, 24.0],
                            egui::Button::new(
                                RichText::new(tr(
                                    lang,
                                    "\u{E3D4} Nouvelle Session",
                                    "\u{E3D4} New Session",
                                ))
                                .size(11.5)
                                .strong()
                                .color(Color32::from_rgb(63, 185, 80)),
                            ),
                        )
                        .on_hover_text(tr(
                            lang,
                            "Créer et configurer une nouvelle session (SSH, Telnet, ConPTY...)",
                            "Create and configure a new session (SSH, Telnet, ConPTY...)",
                        ))
                        .clicked()
                    {
                        self.editing_session = SessionProfile::default();
                        self.is_new_session = true;
                        self.editor_tab = ConfigEditorTab::ConnectionAndKey;
                        self.show_session_editor = true;
                    }

                    if ui
                        .add_sized(
                            [btn_w, 24.0],
                            egui::Button::new(
                                RichText::new(tr(lang, "\u{E24A} Gestionnaire", "\u{E24A} Manager"))
                                    .size(11.5)
                                    .strong()
                                    .color(Color32::from_rgb(88, 166, 255)),
                            ),
                        )
                        .on_hover_text(tr(
                            lang,
                            "Ouvrir le gestionnaire de sessions (recherche avancée, organisation par dossiers, import/export JSON, actions par lot)",
                            "Open the session manager (advanced search, folders, tags, JSON import/export, bulk actions)",
                        ))
                        .clicked()
                    {
                        self.show_session_manager = true;
                    }
                });

                ui.add_space(6.0);

                // Quick connect with direct .ppk support
                egui::CollapsingHeader::new(
                    RichText::new(tr(lang, "\u{E2DE} Connexion Rapide", "\u{E2DE} Quick Connect"))
                        .color(Color32::from_rgb(165, 214, 255)),
                )
                .default_open(false)
                .show(ui, |ui| {
                    egui::Grid::new("quick_connect_grid")
                        .num_columns(2)
                        .spacing([6.0, 4.0])
                        .show(ui, |ui| {
                            ui.label(tr(lang, "Protocole:", "Protocol:"));
                            egui::ComboBox::from_id_salt("quick_proto")
                                .selected_text(self.quick_protocol.label())
                                .show_ui(ui, |ui| {
                                    for p in [
                                        ProtocolType::Ssh,
                                        ProtocolType::Telnet,
                                        ProtocolType::RawTcp,
                                        ProtocolType::LocalShell,
                                    ] {
                                        if ui
                                            .selectable_value(
                                                &mut self.quick_protocol,
                                                p,
                                                p.label(),
                                            )
                                            .clicked()
                                        {
                                            self.quick_port = p.default_port();
                                        }
                                    }
                                });
                            ui.end_row();

                            if self.quick_protocol != ProtocolType::LocalShell {
                                ui.label(tr(lang, "Hôte / IP:", "Host / IP:"));
                                ui.text_edit_singleline(&mut self.quick_host);
                                ui.end_row();

                                ui.label("Port / User:");
                                ui.horizontal(|ui| {
                                    ui.add(
                                        egui::DragValue::new(&mut self.quick_port)
                                            .range(1..=65535),
                                    );
                                    ui.text_edit_singleline(&mut self.quick_user);
                                });
                                ui.end_row();
                            }

                            if self.quick_protocol == ProtocolType::Ssh {
                                ui.label(tr(lang, "Clé .ppk:", ".ppk Key:"));
                                ui.horizontal(|ui| {
                                    ui.add(
                                        egui::TextEdit::singleline(&mut self.quick_ppk_path)
                                            .hint_text(tr(
                                                lang,
                                                "Optionnel (.ppk ou Pageant)",
                                                "Optional (.ppk or Pageant)",
                                            ))
                                            .desired_width(110.0),
                                    );
                                    if ui
                                        .small_button("\u{E256}")
                                        .on_hover_text(tr(
                                            lang,
                                            "Choisir une clé PuTTY (.ppk) ou OpenSSH",
                                            "Pick a PuTTY (.ppk) or OpenSSH private key",
                                        ))
                                        .clicked()
                                        && let Some(path) = rfd::FileDialog::new()
                                            .add_filter(
                                                "PuTTY & SSH Keys",
                                                &["ppk", "pem", "key", "pub", "*"],
                                            )
                                            .pick_file()
                                    {
                                        self.quick_ppk_path =
                                            path.to_string_lossy().to_string();
                                    }
                                });
                                ui.end_row();
                            }
                        });

                    ui.add_space(4.0);
                    if ui
                        .button(
                            RichText::new(tr(
                                lang,
                                "\u{E3D0} Connecter maintenant",
                                "\u{E3D0} Connect Now",
                            ))
                            .strong()
                            .color(Color32::from_rgb(88, 166, 255)),
                        )
                        .clicked()
                    {
                        let host = if self.quick_host.trim().is_empty() {
                            "127.0.0.1".to_string()
                        } else {
                            self.quick_host.trim().to_string()
                        };
                        let ssh_auth = if !self.quick_ppk_path.trim().is_empty() {
                            SshAuthMethod::PrivateKeyFile {
                                key_path: self.quick_ppk_path.trim().to_string(),
                                passphrase: String::new(),
                                cert_path: String::new(),
                            }
                        } else {
                            SshAuthMethod::Password
                        };
                        let profile = SessionProfile {
                            name: format!("{}@{}", self.quick_user, host),
                            protocol: self.quick_protocol,
                            host,
                            port: self.quick_port,
                            username: self.quick_user.clone(),
                            ssh_auth,
                            try_pageant: true,
                            ..Default::default()
                        };
                        self.launch_session(profile);
                    }
                });

                ui.separator();

                // Session folder tree with rich dark-tech session cards
                let filter_lower = self.session_filter.trim().to_lowercase();
                let mut grouped: BTreeMap<String, Vec<SessionProfile>> = BTreeMap::new();
                for s in &self.config.sessions {
                    if !filter_lower.is_empty() {
                        let filter_tag = filter_lower.trim_start_matches('#');
                        let matches = s.name.to_lowercase().contains(&filter_lower)
                            || s.host.to_lowercase().contains(&filter_lower)
                            || s.folder.to_lowercase().contains(&filter_lower)
                            || s.username.to_lowercase().contains(&filter_lower)
                            || s.tags.iter().any(|t| {
                                let tl = t.to_lowercase();
                                tl.contains(&filter_lower) || tl.contains(filter_tag)
                            });
                        if !matches {
                            continue;
                        }
                    }
                    let folder = if s.folder.trim().is_empty() {
                        tr(lang, "Général", "General").to_string()
                    } else {
                        s.folder.clone()
                    };
                    grouped.entry(folder).or_default().push(s.clone());
                }

                let mut to_launch: Option<SessionProfile> = None;
                let mut to_edit: Option<SessionProfile> = None;
                let mut to_duplicate: Option<SessionProfile> = None;
                let mut to_delete: Option<Uuid> = None;
                let mut ppk_to_load: Option<String> = None;

                egui::ScrollArea::vertical()
                    .auto_shrink([false, false])
                    .show(ui, |ui| {
                        for (folder, list) in grouped {
                            egui::CollapsingHeader::new(
                                RichText::new(format!("\u{E24A} {} ({})", folder, list.len()))
                                    .strong()
                                    .color(Color32::from_rgb(201, 209, 217)),
                            )
                            .default_open(true)
                            .show(ui, |ui| {
                                for s in list {
                                    let probe = self.session_probes.get(&s.id);
                                    let (proto_tag, proto_col) = protocol_badge_style(s.protocol);
                                    let has_bastion =
                                        s.jump_host_id.is_some() || !s.proxy_jump.trim().is_empty();
                                    let has_ppk = match &s.ssh_auth {
                                        SshAuthMethod::PrivateKeyFile { key_path, .. } => {
                                            if key_path.trim().is_empty() {
                                                None
                                            } else {
                                                Some(key_path.trim().to_string())
                                            }
                                        }
                                        _ => None,
                                    };

                                    egui::Frame::NONE
                                        .fill(Color32::from_rgb(21, 27, 38))
                                        .corner_radius(6.0)
                                        .inner_margin(egui::Margin::symmetric(8, 6))
                                        .stroke(Stroke::new(1.0, Color32::from_rgb(38, 46, 62)))
                                        .show(ui, |ui| {
                                            ui.horizontal(|ui| {
                                                let title_btn = ui
                                                    .add(
                                                        egui::Button::new(
                                                            RichText::new(format!(
                                                                "\u{E3D0} {} {}",
                                                                s.icon_badge, s.name
                                                            ))
                                                            .strong()
                                                            .size(13.0)
                                                            .color(Color32::from_rgb(240, 246, 252)),
                                                        )
                                                        .frame(false)
                                                        .truncate(),
                                                    )
                                                    .on_hover_text(tr(
                                                        lang,
                                                        "\u{E3FE} Cliquer ou double-cliquer pour vous connecter",
                                                        "\u{E3FE} Click or double-click to connect",
                                                    ))
                                                    .on_hover_cursor(egui::CursorIcon::PointingHand);
                                                if title_btn.clicked() || title_btn.double_clicked() {
                                                    to_launch = Some(s.clone());
                                                }

                                                ui.with_layout(
                                                    Layout::right_to_left(Align::Center),
                                                    |ui| {
                                                        if ui
                                                            .small_button("\u{E4A6}")
                                                            .on_hover_text(tr(
                                                                lang,
                                                                "Supprimer la session",
                                                                "Delete session",
                                                            ))
                                                            .clicked()
                                                        {
                                                            to_delete = Some(s.id);
                                                        }
                                                        if ui
                                                            .small_button("\u{E710}")
                                                            .on_hover_text(tr(
                                                                lang,
                                                                "Dupliquer la session",
                                                                "Duplicate session",
                                                            ))
                                                            .clicked()
                                                        {
                                                            to_duplicate = Some(s.clone());
                                                        }
                                                        if ui
                                                            .small_button("\u{E270}")
                                                            .on_hover_text(tr(
                                                                lang,
                                                                "Configurer la session",
                                                                "Configure session",
                                                            ))
                                                            .clicked()
                                                        {
                                                            to_edit = Some(s.clone());
                                                        }
                                                    },
                                                );
                                            });

                                            ui.horizontal(|ui| {
                                                egui::Frame::NONE
                                                    .fill(proto_col.gamma_multiply(0.18))
                                                    .corner_radius(egui::CornerRadius::same(3))
                                                    .inner_margin(egui::Margin::symmetric(4, 1))
                                                    .stroke(Stroke::new(0.6, proto_col.gamma_multiply(0.55)))
                                                    .show(ui, |ui| {
                                                        ui.label(
                                                            RichText::new(proto_tag)
                                                                .monospace()
                                                                .size(9.0)
                                                                .strong()
                                                                .color(proto_col),
                                                        );
                                                    });

                                                if has_bastion {
                                                    egui::Frame::NONE
                                                        .fill(Color32::from_rgb(46, 30, 68))
                                                        .corner_radius(egui::CornerRadius::same(3))
                                                        .inner_margin(egui::Margin::symmetric(4, 1))
                                                        .stroke(Stroke::new(0.6, Color32::from_rgb(163, 113, 247)))
                                                        .show(ui, |ui| {
                                                            ui.label(
                                                                RichText::new("\u{E89C} -J")
                                                                    .monospace()
                                                                    .size(9.0)
                                                                    .strong()
                                                                    .color(Color32::from_rgb(210, 168, 255)),
                                                            );
                                                        });
                                                }

                                                let target_desc =
                                                    if s.protocol == ProtocolType::LocalShell {
                                                        s.local_shell_cmd.clone()
                                                    } else if !s.username.trim().is_empty() {
                                                        format!(
                                                            "{}@{}:{}",
                                                            s.username.trim(),
                                                            s.host.trim(),
                                                            s.port
                                                        )
                                                    } else {
                                                        format!("{}:{}", s.host.trim(), s.port)
                                                    };
                                                ui.label(
                                                    RichText::new(target_desc)
                                                        .monospace()
                                                        .small()
                                                        .color(Color32::from_rgb(139, 148, 158)),
                                                );

                                                ui.with_layout(
                                                    Layout::right_to_left(Align::Center),
                                                    |ui| {
                                                        if let Some(p) = probe {
                                                            let (txt, col) = if p.reachable {
                                                                (
                                                                    format!(
                                                                        "● {} ms",
                                                                        p.latency_ms
                                                                    ),
                                                                    Color32::from_rgb(
                                                                        52, 211, 153,
                                                                    ),
                                                                )
                                                            } else {
                                                                (
                                                                    tr(
                                                                        lang,
                                                                        "○ Hors-ligne",
                                                                        "○ Offline",
                                                                    )
                                                                    .to_string(),
                                                                    Color32::from_rgb(
                                                                        248, 81, 73,
                                                                    ),
                                                                )
                                                            };
                                                            ui.label(
                                                                RichText::new(txt)
                                                                    .monospace()
                                                                    .small()
                                                                    .color(col),
                                                            )
                                                            .on_hover_text(&p.banner);
                                                        } else if has_ppk.is_some() {
                                                            ui.label(
                                                                RichText::new("PPK")
                                                                    .monospace()
                                                                    .small()
                                                                    .color(Color32::from_rgb(
                                                                        88, 166, 255,
                                                                    )),
                                                            );
                                                        }
                                                    },
                                                );
                                            });

                                            if !s.tags.is_empty() {
                                                ui.add_space(2.0);
                                                ui.horizontal_wrapped(|ui| {
                                                    for t in &s.tags {
                                                        egui::Frame::NONE
                                                            .fill(Color32::from_rgb(26, 36, 50))
                                                            .corner_radius(egui::CornerRadius::same(3))
                                                            .inner_margin(egui::Margin::symmetric(4, 1))
                                                            .stroke(Stroke::new(0.5, Color32::from_rgb(56, 90, 150)))
                                                            .show(ui, |ui| {
                                                                ui.label(
                                                                    RichText::new(format!("#{}", t))
                                                                        .size(9.0)
                                                                        .color(Color32::from_rgb(140, 190, 255)),
                                                                );
                                                            });
                                                    }
                                                });
                                            }

                                            ui.add_space(4.0);

                                            // Bouton d'action principal bien visible
                                            ui.horizontal(|ui| {
                                                let avail_w = ui.available_width();
                                                let connect_label =
                                                    tr(lang, "\u{E3FE} Connecter", "\u{E3FE} Connect");
                                                if let Some(ppk_path) = &has_ppk {
                                                    let pageant_w = 75.0;
                                                    let conn_w = (avail_w - pageant_w - 6.0).max(110.0);
                                                    let conn_btn = ui.add_sized(
                                                        [conn_w, 23.0],
                                                        egui::Button::new(
                                                            RichText::new(connect_label)
                                                                .size(11.0)
                                                                .strong()
                                                                .color(Color32::from_rgb(88, 166, 255)),
                                                        ),
                                                    );
                                                    if conn_btn
                                                        .on_hover_text(format!(
                                                            "{} '{}'",
                                                            tr(
                                                                lang,
                                                                "Lancer immédiatement la session",
                                                                "Immediately launch session",
                                                            ),
                                                            s.name
                                                        ))
                                                        .on_hover_cursor(egui::CursorIcon::PointingHand)
                                                        .clicked()
                                                    {
                                                        to_launch = Some(s.clone());
                                                    }

                                                    if ui
                                                        .add_sized(
                                                            [pageant_w, 23.0],
                                                            egui::Button::new(
                                                                RichText::new("\u{E2D6} Pageant")
                                                                    .size(10.5)
                                                                    .color(Color32::from_rgb(210, 153, 34)),
                                                            ),
                                                        )
                                                        .on_hover_text(format!(
                                                            "{} :\n{}",
                                                            tr(
                                                                lang,
                                                                "Charger la clé .ppk dans Pageant",
                                                                "Load .ppk key into Pageant",
                                                            ),
                                                            ppk_path
                                                        ))
                                                        .clicked()
                                                    {
                                                        ppk_to_load = Some(ppk_path.clone());
                                                    }
                                                } else {
                                                    let conn_btn = ui.add_sized(
                                                        [avail_w, 23.0],
                                                        egui::Button::new(
                                                            RichText::new(connect_label)
                                                                .size(11.0)
                                                                .strong()
                                                                .color(Color32::from_rgb(88, 166, 255)),
                                                        ),
                                                    );
                                                    if conn_btn
                                                        .on_hover_text(format!(
                                                            "{} '{}'",
                                                            tr(
                                                                lang,
                                                                "Lancer immédiatement la session",
                                                                "Immediately launch session",
                                                            ),
                                                            s.name
                                                        ))
                                                        .on_hover_cursor(egui::CursorIcon::PointingHand)
                                                        .clicked()
                                                    {
                                                        to_launch = Some(s.clone());
                                                    }
                                                }
                                            });
                                        });
                                    ui.add_space(3.0);
                                }
                            });
                        }
                    });

                if let Some(ppk) = ppk_to_load {
                    let pageant_exe = self.resolve_pageant_path();
                    match launch_pageant_with_keys(&pageant_exe, &[ppk]) {
                        Ok(msg) => {
                            self.set_toast(msg);
                            self.refresh_agent_keys();
                        }
                        Err(e) => self.set_toast(format!("Pageant: {}", e)),
                    }
                }
                if let Some(s) = to_launch {
                    self.launch_session(s);
                }
                if let Some(s) = to_edit {
                    self.editing_session = s;
                    self.is_new_session = false;
                    self.editor_tab = ConfigEditorTab::ConnectionAndKey;
                    self.show_session_editor = true;
                }
                if let Some(mut s) = to_duplicate {
                    s.id = Uuid::new_v4();
                    s.name = format!("{} ({})", s.name, tr(lang, "Copie", "Copy"));
                    self.config.sessions.push(s);
                    let _ = self.config.save();
                }
                if let Some(id) = to_delete {
                    self.config.sessions.retain(|x| x.id != id);
                    let _ = self.config.save();
                }
            });
    }

    fn render_tabs_bar(&mut self, ui: &mut Ui) {
        let lang = self.config.language;
        egui::Frame::NONE
            .fill(Color32::from_rgb(16, 20, 28))
            .inner_margin(egui::Margin::symmetric(8, 4))
            .stroke(Stroke::new(1.0, Color32::from_rgb(38, 46, 62)))
            .show(ui, |ui| {
                ui.vertical(|ui| {
                    let mut close_idx: Option<usize> = None;
                    let mut duplicate_profile: Option<SessionProfile> = None;

                    // 1. GAUCHE : Onglets de sessions
                    ui.horizontal(|ui| {
                    for (idx, tab) in self.tabs.iter().enumerate() {
                        let is_active = idx == self.active_tab_idx;
                        let status_icon = match tab.state {
                            TabConnectionState::Connected => "🟢",
                            TabConnectionState::Connecting => "🟡",
                            TabConnectionState::Disconnected(_) => "🔴",
                        };
                        let title = tab
                            .terminal
                            .state
                            .dynamic_title
                            .as_deref()
                            .unwrap_or(&tab.profile.name);
                        let lock_badge = if tab.profile.read_only { " \u{E2FA}" } else { "" };

                        let bg = if is_active {
                            Color32::from_rgb(28, 37, 52)
                        } else {
                            Color32::from_rgb(15, 19, 27)
                        };

                        egui::Frame::NONE
                            .fill(bg)
                            .corner_radius(6.0)
                            .inner_margin(egui::Margin::symmetric(8, 4))
                            .stroke(Stroke::new(
                                1.0,
                                if is_active {
                                    Color32::from_rgb(88, 166, 255)
                                } else {
                                    Color32::from_rgb(38, 46, 62)
                                },
                            ))
                            .show(ui, |ui| {
                                // Dynamic titles (e.g. a full exe path) would push the right-hand
                                // tools over the tabs: cap the label and keep the full text on hover.
                                const MAX_TAB_TITLE: usize = 28;
                                let short_title: String = if title.chars().count() > MAX_TAB_TITLE {
                                    let head: String = title.chars().take(MAX_TAB_TITLE).collect();
                                    format!("{head}\u{2026}")
                                } else {
                                    title.to_string()
                                };
                                if ui
                                    .selectable_label(
                                        is_active,
                                        format!(
                                            "{} {} {}{}",
                                            status_icon,
                                            tab.profile.icon_badge,
                                            short_title,
                                            lock_badge
                                        ),
                                    )
                                    .on_hover_text(title)
                                    .clicked()
                                {
                                    self.active_tab_idx = idx;
                                }
                                if ui
                                    .small_button("\u{E4F6}")
                                    .on_hover_text(tr(
                                        lang,
                                        "Fermer cet onglet",
                                        "Close this tab",
                                    ))
                                    .clicked()
                                {
                                    close_idx = Some(idx);
                                }
                            });
                    }

                    // Bouton '+' : menu des sessions disponibles (avec filtre) pour ouvrir un
                    // nouvel onglet, plus un raccourci vers un shell PowerShell local.
                    let mut session_to_open: Option<SessionProfile> = None;
                    let plus = ui.menu_button(
                        RichText::new("\u{E3D4}")
                            .size(12.0)
                            .color(Color32::from_rgb(139, 148, 158)),
                        |ui| {
                            ui.set_min_width(330.0);
                            let filter_id = egui::Id::unique("tab_plus_menu_filter");
                            let mut query: String =
                                ui.data_mut(|d| d.get_temp(filter_id).unwrap_or_default());
                            ui.horizontal(|ui| {
                                ui.label("\u{E30C}");
                                let resp = ui.add(
                                    egui::TextEdit::singleline(&mut query)
                                        .hint_text(tr(
                                            lang,
                                            "Filtrer (nom, hôte, #tag, dossier)...",
                                            "Filter (name, host, #tag, folder)...",
                                        ))
                                        .desired_width(f32::INFINITY),
                                );
                                if !resp.has_focus() && !ui.input(|i| i.pointer.any_down()) {
                                    resp.request_focus();
                                }
                            });
                            let q = query.trim().to_lowercase();
                            ui.data_mut(|d| d.insert_temp(filter_id, query));
                            ui.separator();

                            if q.is_empty()
                                && ui
                                    .button(tr(
                                        lang,
                                        "\u{E2DE}  Shell PowerShell local",
                                        "\u{E2DE}  Local PowerShell shell",
                                    ))
                                    .clicked()
                            {
                                session_to_open = Some(SessionProfile {
                                    name: "PowerShell Local".to_string(),
                                    protocol: ProtocolType::LocalShell,
                                    local_shell_cmd: "powershell.exe".to_string(),
                                    icon_badge: "⚡".to_string(),
                                    ..Default::default()
                                });
                                ui.close();
                            }

                            let mut matches: Vec<&SessionProfile> = self
                                .config
                                .sessions
                                .iter()
                                .filter(|s| {
                                    q.is_empty()
                                        || s.name.to_lowercase().contains(&q)
                                        || s.host.to_lowercase().contains(&q)
                                        || s.username.to_lowercase().contains(&q)
                                        || s.folder.to_lowercase().contains(&q)
                                        || s.tags
                                            .iter()
                                            .any(|t| format!("#{}", t.to_lowercase()).contains(&q))
                                })
                                .collect();
                            matches.sort_by(|a, b| {
                                a.folder
                                    .to_lowercase()
                                    .cmp(&b.folder.to_lowercase())
                                    .then(a.name.to_lowercase().cmp(&b.name.to_lowercase()))
                            });

                            if matches.is_empty() {
                                ui.label(
                                    RichText::new(tr(lang, "Aucune session", "No matching session"))
                                        .color(Color32::from_rgb(139, 148, 158)),
                                );
                            }
                            egui::ScrollArea::vertical().max_height(380.0).show(ui, |ui| {
                                let mut last_folder: Option<&str> = None;
                                for s in &matches {
                                    if last_folder != Some(s.folder.as_str()) {
                                        last_folder = Some(s.folder.as_str());
                                        ui.label(
                                            RichText::new(format!("\u{E24A} {}", s.folder))
                                                .small()
                                                .color(Color32::from_rgb(139, 148, 158)),
                                        );
                                    }
                                    let (proto_tag, proto_color) = protocol_badge_style(s.protocol);
                                    let target = if s.protocol == ProtocolType::LocalShell {
                                        s.local_shell_cmd.clone()
                                    } else {
                                        format!("{}:{}", s.host, s.port)
                                    };
                                    let clicked = ui
                                        .horizontal(|ui| {
                                            let clicked = ui
                                                .button(format!("{} {}", s.icon_badge, s.name))
                                                .clicked();
                                            ui.label(
                                                RichText::new(proto_tag)
                                                    .small()
                                                    .monospace()
                                                    .color(proto_color),
                                            );
                                            ui.label(
                                                RichText::new(target)
                                                    .small()
                                                    .monospace()
                                                    .color(Color32::from_rgb(139, 148, 158)),
                                            );
                                            clicked
                                        })
                                        .inner;
                                    if clicked {
                                        session_to_open = Some((*s).clone());
                                        ui.close();
                                    }
                                }
                            });
                        },
                    );
                    plus.response.on_hover_text(tr(
                        lang,
                        "Ouvrir une session dans un nouvel onglet",
                        "Open a session in a new tab",
                    ));
                    if let Some(profile) = session_to_open {
                        self.launch_session(profile);
                    }
                    });

                    // 2. Outils de la session active, sur leur propre ligne : ils passent à la
                    // ligne au lieu de recouvrir les onglets quand la zone centrale est étroite
                    // (ex. panneau SFTP ouvert). `horizontal_wrapped` ne consomme que la hauteur
                    // nécessaire, contrairement à un layout right_to_left avec wrap.
                    let can_split = self.tabs.len() >= 2;
                    let mut next_split_mode = self.split_mode;
                    let mut reconnect_now = false;
                    let mut deploy_key_for_active = false;
                    let mut toggle_rec = false;
                    let mut toggle_broadcast = false;
                    if let Some(active_tab) = self.tabs.get_mut(self.active_tab_idx) {
                        ui.horizontal_wrapped(|ui| {
                            if ui
                                .button(tr(lang, "\u{E710} Dupliquer", "\u{E710} Duplicate"))
                                .on_hover_text(tr(
                                    lang,
                                    "Démarrer une session identique (dupliquer la session)",
                                    "Launch an identical session in a new tab",
                                ))
                                .clicked()
                            {
                                duplicate_profile = Some(active_tab.profile.clone());
                            }

                            if can_split {
                                if ui
                                    .selectable_label(
                                        next_split_mode == SplitMode::Horizontal,
                                        "⊟ Split H",
                                    )
                                    .on_hover_text(tr(
                                        lang,
                                        "Diviser l'écran horizontalement (Haut / Bas)",
                                        "Split terminal horizontally (Top / Bottom)",
                                    ))
                                    .clicked()
                                {
                                    next_split_mode = if next_split_mode == SplitMode::Horizontal {
                                        SplitMode::None
                                    } else {
                                        SplitMode::Horizontal
                                    };
                                }
                                if ui
                                    .selectable_label(
                                        next_split_mode == SplitMode::Vertical,
                                        "◫ Split V",
                                    )
                                    .on_hover_text(tr(
                                        lang,
                                        "Diviser l'écran verticalement (Côte-à-côte)",
                                        "Split terminal vertically (Side-by-side)",
                                    ))
                                    .clicked()
                                {
                                    next_split_mode = if next_split_mode == SplitMode::Vertical {
                                        SplitMode::None
                                    } else {
                                        SplitMode::Vertical
                                    };
                                }
                            }

                            if active_tab.profile.protocol != ProtocolType::LocalShell {
                                if ui
                                    .selectable_label(
                                        active_tab.profile.auto_reconnect,
                                        tr(lang, "\u{E094} Auto-reconnexion", "\u{E094} Auto-reconnect"),
                                    )
                                    .on_hover_text(tr(
                                        lang,
                                        "Se reconnecter automatiquement si la connexion tombe",
                                        "Automatically reconnect if the connection drops",
                                    ))
                                    .clicked()
                                {
                                    active_tab.profile.auto_reconnect =
                                        !active_tab.profile.auto_reconnect;
                                    if !active_tab.profile.auto_reconnect {
                                        active_tab.reconnect_at = None;
                                    }
                                }
                                if matches!(active_tab.state, TabConnectionState::Disconnected(_))
                                    && ui
                                        .button(tr(lang, "\u{E094} Reconnecter", "\u{E094} Reconnect"))
                                        .clicked()
                                {
                                    reconnect_now = true;
                                }
                            }

                            if active_tab.profile.protocol == ProtocolType::Ssh {
                                if ui
                                    .selectable_label(
                                        active_tab.show_telemetry_bar,
                                        tr(lang, "\u{E150} Télémétrie", "\u{E150} Telemetry"),
                                    )
                                    .on_hover_text(tr(
                                        lang,
                                        "Monitoring serveur en temps réel (CPU, RAM, Disque, Uptime)",
                                        "Live server telemetry (CPU, RAM, Disk, Uptime)",
                                    ))
                                    .clicked()
                                {
                                    active_tab.show_telemetry_bar = !active_tab.show_telemetry_bar;
                                    if active_tab.show_telemetry_bar {
                                        let _ = active_tab
                                            .handle
                                            .cmd_tx
                                            .send(BackendCommand::RefreshTelemetry);
                                    }
                                }

                                if active_tab.socks_port.is_none() {
                                    ui.add(
                                        egui::DragValue::new(&mut active_tab.socks_listen_port)
                                            .range(1..=65535),
                                    )
                                    .on_hover_text(tr(
                                        lang,
                                        "Port local du proxy SOCKS5 / HTTP",
                                        "Local port of the SOCKS5 / HTTP proxy",
                                    ));
                                }
                                if ui
                                    .selectable_label(
                                        active_tab.socks_port.is_some(),
                                        "SOCKS5/HTTP",
                                    )
                                    .on_hover_text(match active_tab.socks_port {
                                        Some(p) => format!(
                                            "{} 127.0.0.1:{p}",
                                            tr(
                                                lang,
                                                "Proxy SOCKS5 / HTTP CONNECT actif sur",
                                                "SOCKS5 / HTTP CONNECT proxy listening on"
                                            )
                                        ),
                                        None => tr(
                                            lang,
                                            "Démarrer un proxy local SOCKS5 + HTTP CONNECT (127.0.0.1) via cette session",
                                            "Start a local SOCKS5 + HTTP CONNECT proxy (127.0.0.1) through this session",
                                        )
                                        .to_string(),
                                    })
                                    .clicked()
                                {
                                    let _ = active_tab.handle.cmd_tx.send(BackendCommand::ToggleSocks(
                                        active_tab.socks_port.unwrap_or(active_tab.socks_listen_port),
                                    ));
                                }

                                let sftp_is_active = active_tab.show_sftp_full || active_tab.show_sftp_panel;
                                let sftp_btn_label = if active_tab.show_sftp_full {
                                    tr(lang, "\u{E256} SFTP (Actif)", "\u{E256} SFTP (Active)")
                                } else {
                                    "\u{E256} SFTP"
                                };
                                if ui
                                    .selectable_label(sftp_is_active, sftp_btn_label)
                                    .on_hover_text(tr(
                                        lang,
                                        "Ouvrir l'explorateur SFTP Client double-volet complet (remplace WinSCP)",
                                        "Open the full dual-pane SFTP Client explorer (replaces WinSCP)",
                                    ))
                                    .clicked()
                                {
                                    active_tab.show_sftp_full = !active_tab.show_sftp_full;
                                    active_tab.show_sftp_panel = false;
                                    if active_tab.show_sftp_full {
                                        let _ = active_tab.handle.cmd_tx.send(
                                            BackendCommand::SftpListDir(
                                                active_tab.sftp_current_path.clone(),
                                            ),
                                        );
                                        active_tab.sftp_client.refresh_local();
                                    }
                                }

                                let is_pwd_auth = matches!(
                                    active_tab.profile.ssh_auth,
                                    SshAuthMethod::Password | SshAuthMethod::KeyboardInteractive
                                );
                                let btn_label = if is_pwd_auth {
                                    tr(
                                        lang,
                                        "\u{E2D6}\u{E06C}\u{E560} Copier ma Clé (ssh-copy-id)",
                                        "\u{E2D6}\u{E06C}\u{E560} Copy My Key (ssh-copy-id)",
                                    )
                                } else {
                                    tr(lang, "\u{E2D6}\u{E06C}\u{E560} ssh-copy-id", "\u{E2D6}\u{E06C}\u{E560} ssh-copy-id")
                                };
                                let btn_color = if is_pwd_auth {
                                    Color32::from_rgb(63, 185, 80)
                                } else {
                                    Color32::from_rgb(210, 153, 34)
                                };
                                if ui
                                    .button(RichText::new(btn_label).strong().color(btn_color))
                                    .on_hover_text(tr(
                                        lang,
                                        "Installe votre Clé Publique Principale dans ~/.ssh/authorized_keys sur ce serveur et bascule automatiquement la session sur l'authentification par clé (sans mot de passe)",
                                        "Installs your Primary Public Key into ~/.ssh/authorized_keys on this server and automatically switches this session to key authentication (passwordless)",
                                    ))
                                    .clicked()
                                {
                                    deploy_key_for_active = true;
                                }
                            }

                            if ui
                                .selectable_label(
                                    active_tab.profile.read_only,
                                    tr(lang, "\u{E2FA} Verrou", "\u{E2FA} Lock"),
                                )
                                .on_hover_text(tr(
                                    lang,
                                    "Protection clavier : bloquer les saisies accidentelles",
                                    "Keyboard lock: prevent accidental keystrokes",
                                ))
                                .clicked()
                            {
                                active_tab.profile.read_only = !active_tab.profile.read_only;
                            }

                            if ui
                                .button("\u{EB7A} Script")
                                .on_hover_text(tr(
                                    lang,
                                    "Exécuter un script local sur la session distante",
                                    "Execute a local script on the remote session",
                                ))
                                .clicked()
                                && let Some(path) = rfd::FileDialog::new()
                                    .add_filter("Scripts", &["sh", "bash", "txt", "ps1", "bat", "*"])
                                    .pick_file()
                            {
                                let _ = active_tab
                                    .handle
                                    .cmd_tx
                                    .send(BackendCommand::RunLocalScript(path));
                            }

                            if ui
                                .selectable_label(
                                    active_tab.show_search_bar,
                                    tr(lang, "\u{E30C} Chercher", "\u{E30C} Find"),
                                )
                                .on_hover_text(tr(
                                    lang,
                                    "Rechercher dans l'historique du terminal (Ctrl+F)",
                                    "Search in terminal history (Ctrl+F)",
                                ))
                                .clicked()
                            {
                                active_tab.show_search_bar = !active_tab.show_search_bar;
                            }

                            if ui
                                .button(tr(lang, "\u{EC54} Vider", "\u{EC54} Clear"))
                                .on_hover_text(tr(
                                    lang,
                                    "Effacer l'historique du terminal (Clear scrollback)",
                                    "Clear terminal scrollback history",
                                ))
                                .clicked()
                            {
                                active_tab.terminal.clear_scrollback();
                            }

                            if can_split {
                                let bcast_text = if self.broadcast_mode {
                                    RichText::new("\u{E0F2} Broadcast ON").color(Color32::from_rgb(248, 81, 73)).strong()
                                } else {
                                    RichText::new("\u{E0F2} Broadcast")
                                };
                                if ui
                                    .selectable_label(self.broadcast_mode, bcast_text)
                                    .on_hover_text(tr(
                                        lang,
                                        "Envoyer la saisie clavier simultanément à tous les terminaux ouverts",
                                        "Send keyboard input simultaneously to all open terminal panes",
                                    ))
                                    .clicked()
                                {
                                    toggle_broadcast = true;
                                }
                            }

                            // 🔴 REC / ⏹ REC
                            let rec_label = if let Some(rec) = &active_tab.recorder {
                                let elapsed = rec.elapsed().as_secs();
                                let m = elapsed / 60;
                                let s = elapsed % 60;
                                format!("\u{E46C} REC ({:02}:{:02})", m, s)
                            } else {
                                "🔴 REC".to_string()
                            };
                            let rec_color = if active_tab.recorder.is_some() {
                                Color32::from_rgb(248, 81, 73)
                            } else {
                                Color32::from_rgb(201, 209, 217)
                            };
                            if ui
                                .button(RichText::new(rec_label).strong().color(rec_color))
                                .on_hover_text(tr(
                                    lang,
                                    "Démarrer / Arrêter l'enregistrement de la session (Asciinema v2 .cast)",
                                    "Start / Stop session recording (Asciinema v2 .cast format)",
                                ))
                                .clicked()
                            {
                                toggle_rec = true;
                            }
                        });
                    }
                    self.split_mode = next_split_mode;
                    if reconnect_now {
                        let idx = self.active_tab_idx;
                        if let Some(t) = self.tabs.get_mut(idx) {
                            t.reconnect_attempt = 0;
                        }
                        self.reconnect_tab(idx);
                    }

                    if toggle_broadcast {
                        self.broadcast_mode = !self.broadcast_mode;
                    }

                    if toggle_rec
                        && let Some(tab) = self.tabs.get_mut(self.active_tab_idx)
                    {
                        if let Some(rec) = tab.recorder.take() {
                            match rec.stop() {
                                Ok(path) => {
                                    let name = path.file_name().unwrap_or_default().to_string_lossy().to_string();
                                    self.set_toast(format!("Enregistrement sauvegardé : {}", name));
                                    self.load_replay_file(&path);
                                }
                                Err(e) => {
                                    self.set_toast(format!("Erreur enregistrement : {}", e));
                                }
                            }
                        } else {
                            match crate::terminal::recording::SessionRecorder::start(
                                &tab.profile.name,
                                tab.terminal.state.cols,
                                tab.terminal.state.rows,
                            ) {
                                Ok(rec) => {
                                    tab.recorder = Some(rec);
                                    self.set_toast("🔴 Enregistrement session démarré !");
                                }
                                Err(e) => {
                                    self.set_toast(format!("Erreur démarrage REC : {}", e));
                                }
                            }
                        }
                    }

                    if deploy_key_for_active {
                        self.deploy_primary_key_to_tab(self.active_tab_idx);
                    }

                    if let Some(p) = duplicate_profile {
                        self.launch_session(p);
                    }

                    if let Some(idx) = close_idx {
                        self.close_tab(idx);
                    }
                });
            });
    }

    fn render_sftp_side_panel(&mut self, ui: &mut Ui) {
        let lang = self.config.language;
        let Some(tab) = self.tabs.get_mut(self.active_tab_idx) else {
            return;
        };

        // Handle Drag & Drop files from Windows Explorer directly onto SFTP panel
        let dropped_files = ui.ctx().input(|i| i.raw.dropped_files.clone());
        let is_hovering_files = ui.ctx().input(|i| !i.raw.hovered_files.is_empty());
        for dropped in dropped_files {
            let local_file = dropped.path().to_path_buf();
            if !local_file.as_os_str().is_empty() {
                let fname = local_file
                    .file_name()
                    .map(|n| n.to_string_lossy().to_string())
                    .unwrap_or_else(|| "uploaded.bin".to_string());
                let remote_target = if tab.sftp_current_path.ends_with('/') {
                    format!("{}{}", tab.sftp_current_path, fname)
                } else {
                    format!("{}/{}", tab.sftp_current_path, fname)
                };
                let _ = tab.handle.cmd_tx.send(BackendCommand::SftpUpload {
                    local_path: local_file,
                    remote_path: remote_target,
                });
            }
        }

        egui::Panel::right("sftp_explorer_panel_v2")
            .resizable(true)
            .default_size(370.0)
            .min_size(280.0)
            .max_size(550.0)
            .frame(
                egui::Frame::NONE
                    .fill(Color32::from_rgb(13, 17, 23))
                    .inner_margin(egui::Margin::same(10))
                    .stroke(Stroke::new(1.0, Color32::from_rgb(38, 44, 54))),
            )
            .show(ui, |ui| {
                ui.horizontal(|ui| {
                    ui.heading(
                        RichText::new(tr(
                            lang,
                            "\u{E256} Explorateur SFTP",
                            "\u{E256} SFTP Explorer",
                        ))
                        .size(15.0),
                    );
                    ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                        if ui
                            .small_button("\u{E256} Plein écran")
                            .on_hover_text(tr(
                                lang,
                                "Ouvrir l'explorateur SFTP Client double-volet complet",
                                "Open the full dual-pane SFTP Client explorer",
                            ))
                            .clicked()
                        {
                            tab.show_sftp_full = true;
                            tab.show_sftp_panel = false;
                            tab.sftp_client.refresh_local();
                        }
                        if ui
                            .small_button("\u{E3FE} WinSCP")
                            .on_hover_text(tr(
                                lang,
                                "Lancer WinSCP externe sur cette session (intégration WinSCP)",
                                "Launch external WinSCP on this session",
                            ))
                            .clicked()
                        {
                            let url = format!(
                                "sftp://{}@{}:{}{}",
                                tab.profile.username,
                                tab.profile.host,
                                tab.profile.port,
                                tab.sftp_current_path
                            );
                            let _ = std::process::Command::new(&self.config.winscp_path)
                                .arg(url)
                                .spawn();
                        }
                    });
                });

                if is_hovering_files {
                    egui::Frame::NONE
                        .fill(Color32::from_rgb(20, 42, 70))
                        .corner_radius(6.0)
                        .inner_margin(egui::Margin::symmetric(8, 6))
                        .stroke(Stroke::new(1.5, Color32::from_rgb(88, 166, 255)))
                        .show(ui, |ui| {
                            ui.label(
                                RichText::new(format!(
                                    "{} {}",
                                    tr(
                                        lang,
                                        "\u{E20C} Relâchez le fichier ici pour l'uploader dans",
                                        "\u{E20C} Drop file here to upload into",
                                    ),
                                    tab.sftp_current_path
                                ))
                                .strong()
                                .color(Color32::from_rgb(165, 214, 255)),
                            );
                        });
                }

                if let Some(prog) = &tab.sftp_progress {
                    let frac = if prog.total > 0 {
                        (prog.transferred as f32 / prog.total as f32).clamp(0.0, 1.0)
                    } else {
                        0.0
                    };
                    let dir_label = if prog.is_upload { "\u{E4C0} Upload" } else { "\u{E20C} Download" };
                    ui.add_space(3.0);
                    ui.add(
                        egui::ProgressBar::new(frac)
                            .fill(Color32::from_rgb(35, 134, 54))
                            .text(format!(
                                "{} {} — {} / {} ({:.0}%)",
                                dir_label,
                                prog.filename,
                                format_bytes(prog.transferred),
                                format_bytes(prog.total),
                                frac * 100.0
                            )),
                    );
                }

                ui.add_space(4.0);
                ui.horizontal(|ui| {
                    if ui
                        .small_button("\u{E08E}")
                        .on_hover_text(tr(lang, "Dossier parent", "Parent directory"))
                        .clicked()
                    {
                        let parent = if let Some((p, _)) =
                            tab.sftp_current_path.trim_end_matches('/').rsplit_once('/')
                        {
                            if p.is_empty() {
                                "/".to_string()
                            } else {
                                p.to_string()
                            }
                        } else {
                            "/".to_string()
                        };
                        let _ = tab.handle.cmd_tx.send(BackendCommand::SftpListDir(parent));
                    }
                    ui.add(
                        egui::TextEdit::singleline(&mut tab.sftp_path_input).desired_width(200.0),
                    );
                    if ui.small_button(tr(lang, "Aller", "Go")).clicked() {
                        let _ = tab
                            .handle
                            .cmd_tx
                            .send(BackendCommand::SftpListDir(tab.sftp_path_input.clone()));
                    }
                    if ui
                        .small_button("\u{E094}")
                        .on_hover_text(tr(lang, "Rafraîchir", "Refresh"))
                        .clicked()
                    {
                        let _ = tab
                            .handle
                            .cmd_tx
                            .send(BackendCommand::SftpListDir(tab.sftp_current_path.clone()));
                    }
                });

                ui.add_space(4.0);
                ui.horizontal(|ui| {
                    if ui
                        .small_button(tr(lang, "\u{E4C0} Uploader fichier", "\u{E4C0} Upload file"))
                        .clicked()
                        && let Some(local_file) = rfd::FileDialog::new().pick_file()
                    {
                        let fname = local_file
                            .file_name()
                            .map(|n| n.to_string_lossy().to_string())
                            .unwrap_or_else(|| "uploaded.bin".to_string());
                        let remote_target = if tab.sftp_current_path.ends_with('/') {
                            format!("{}{}", tab.sftp_current_path, fname)
                        } else {
                            format!("{}/{}", tab.sftp_current_path, fname)
                        };
                        let _ = tab.handle.cmd_tx.send(BackendCommand::SftpUpload {
                            local_path: local_file,
                            remote_path: remote_target,
                        });
                    }

                    ui.add(
                        egui::TextEdit::singleline(&mut tab.sftp_mkdir_name)
                            .hint_text(tr(lang, "Nouveau dossier...", "New folder..."))
                            .desired_width(110.0),
                    );
                    if ui.small_button("\u{E24A}+").clicked() && !tab.sftp_mkdir_name.trim().is_empty()
                    {
                        let target = if tab.sftp_current_path.ends_with('/') {
                            format!("{}{}", tab.sftp_current_path, tab.sftp_mkdir_name.trim())
                        } else {
                            format!("{}/{}", tab.sftp_current_path, tab.sftp_mkdir_name.trim())
                        };
                        let _ = tab.handle.cmd_tx.send(BackendCommand::SftpMkdir(target));
                        tab.sftp_mkdir_name.clear();
                    }
                });

                ui.horizontal(|ui| {
                    ui.label(
                        RichText::new(&tab.sftp_status)
                            .small()
                            .color(Color32::from_rgb(139, 148, 158)),
                    );
                    ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                        if ui
                            .small_button(tr(lang, "\u{E094} Miroir", "\u{E094} Mirror"))
                            .on_hover_text(tr(
                                lang,
                                "Synchroniser un dossier local et le dossier distant (miroir)",
                                "Mirror a local folder with the remote folder",
                            ))
                            .clicked()
                        {
                            tab.sftp_mirror.open = true;
                            if tab.sftp_mirror.remote_dir.is_empty() {
                                tab.sftp_mirror.remote_dir = tab.sftp_current_path.clone();
                            }
                        }
                        let (ff_icon, ff_tip) = if tab.sftp_folders_first {
                            (
                                tr(lang, "\u{E24A}\u{E08E} Dossiers 1er", "\u{E24A}\u{E08E} Folders 1st"),
                                tr(
                                    lang,
                                    "Dossiers regroupés en haut (Actif) — Cliquez pour mélanger dossiers et fichiers",
                                    "Folders grouped on top (Active) — Click to mix folders and files",
                                ),
                            )
                        } else {
                            (
                                tr(lang, "\u{E24A}⬍ Dossiers mix", "\u{E24A}⬍ Mixed"),
                                tr(
                                    lang,
                                    "Dossiers et fichiers mélangés — Cliquez pour regrouper les dossiers en haut",
                                    "Folders and files mixed — Click to group folders on top",
                                ),
                            )
                        };
                        if ui
                            .small_button(RichText::new(ff_icon).small())
                            .on_hover_text(ff_tip)
                            .clicked()
                        {
                            tab.sftp_folders_first = !tab.sftp_folders_first;
                            tab.sort_sftp_entries();
                        }
                    });
                });

                ui.add_space(2.0);

                // Column Header Bar
                let panel_width = ui.available_width();
                let show_date = panel_width >= 365.0;
                let mut sort_changed = false;

                egui::Frame::NONE
                    .fill(Color32::from_rgb(22, 27, 34))
                    .corner_radius(egui::CornerRadius::same(4))
                    .inner_margin(egui::Margin::symmetric(4, 2))
                    .stroke(Stroke::new(1.0, Color32::from_rgb(38, 44, 54)))
                    .show(ui, |ui| {
                        ui.horizontal(|ui| {
                            // Column 1: Nom
                            let name_arrow = match (tab.sftp_sort_col, tab.sftp_sort_dir) {
                                (SftpSortColumn::Name, SortDirection::Ascending) => " ▲",
                                (SftpSortColumn::Name, SortDirection::Descending) => " ▼",
                                _ => "",
                            };
                            let is_name_active = tab.sftp_sort_col == SftpSortColumn::Name;
                            if ui
                                .selectable_label(
                                    is_name_active,
                                    RichText::new(format!(
                                        "{}{}",
                                        tr(lang, "Nom", "Name"),
                                        name_arrow
                                    ))
                                    .small()
                                    .strong()
                                    .color(if is_name_active {
                                        Color32::from_rgb(88, 166, 255)
                                    } else {
                                        Color32::from_rgb(201, 209, 217)
                                    }),
                                )
                                .on_hover_text(tr(
                                    lang,
                                    "Trier par nom alphabétique",
                                    "Sort alphabetically by name",
                                ))
                                .clicked()
                            {
                                if tab.sftp_sort_col == SftpSortColumn::Name {
                                    tab.sftp_sort_dir = match tab.sftp_sort_dir {
                                        SortDirection::Ascending => SortDirection::Descending,
                                        SortDirection::Descending => SortDirection::Ascending,
                                    };
                                } else {
                                    tab.sftp_sort_col = SftpSortColumn::Name;
                                    tab.sftp_sort_dir = SortDirection::Ascending;
                                }
                                sort_changed = true;
                            }

                            // Right-aligned column headers: Actions (space reserved), Size, Date
                            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                                // Reserve 46px for action buttons (📥 🗑)
                                ui.add_sized(
                                    [68.0, 18.0],
                                    egui::Label::new(
                                        RichText::new("Act.")
                                            .small()
                                            .color(Color32::from_rgb(110, 118, 129)),
                                    ),
                                );

                                // Column 2: Taille
                                let size_arrow = match (tab.sftp_sort_col, tab.sftp_sort_dir) {
                                    (SftpSortColumn::Size, SortDirection::Ascending) => " ▲",
                                    (SftpSortColumn::Size, SortDirection::Descending) => " ▼",
                                    _ => "",
                                };
                                let is_size_active = tab.sftp_sort_col == SftpSortColumn::Size;
                                if ui
                                    .add_sized(
                                        [58.0, 18.0],
                                        egui::Button::new(
                                            RichText::new(format!(
                                                "{}{}",
                                                tr(lang, "Taille", "Size"),
                                                size_arrow
                                            ))
                                            .small()
                                            .strong()
                                            .color(if is_size_active {
                                                Color32::from_rgb(88, 166, 255)
                                            } else {
                                                Color32::from_rgb(201, 209, 217)
                                            }),
                                        )
                                        .fill(if is_size_active {
                                            Color32::from_rgb(33, 40, 52)
                                        } else {
                                            Color32::TRANSPARENT
                                        }),
                                    )
                                    .on_hover_text(tr(
                                        lang,
                                        "Trier par taille de fichier",
                                        "Sort by file size",
                                    ))
                                    .clicked()
                                {
                                    if tab.sftp_sort_col == SftpSortColumn::Size {
                                        tab.sftp_sort_dir = match tab.sftp_sort_dir {
                                            SortDirection::Ascending => SortDirection::Descending,
                                            SortDirection::Descending => SortDirection::Ascending,
                                        };
                                    } else {
                                        tab.sftp_sort_col = SftpSortColumn::Size;
                                        tab.sftp_sort_dir = SortDirection::Descending;
                                    }
                                    sort_changed = true;
                                }

                                // Column 3: Date (shown if panel width >= 340px)
                                if show_date {
                                    let date_arrow = match (tab.sftp_sort_col, tab.sftp_sort_dir) {
                                        (SftpSortColumn::Date, SortDirection::Ascending) => " ▲",
                                        (SftpSortColumn::Date, SortDirection::Descending) => " ▼",
                                        _ => "",
                                    };
                                    let is_date_active = tab.sftp_sort_col == SftpSortColumn::Date;
                                    if ui
                                        .add_sized(
                                            [76.0, 18.0],
                                            egui::Button::new(
                                                RichText::new(format!("Date{}", date_arrow))
                                                    .small()
                                                    .strong()
                                                    .color(if is_date_active {
                                                        Color32::from_rgb(88, 166, 255)
                                                    } else {
                                                        Color32::from_rgb(201, 209, 217)
                                                    }),
                                            )
                                            .fill(if is_date_active {
                                                Color32::from_rgb(33, 40, 52)
                                            } else {
                                                Color32::TRANSPARENT
                                            }),
                                        )
                                        .on_hover_text(tr(
                                            lang,
                                            "Trier par date de modification",
                                            "Sort by modification date",
                                        ))
                                        .clicked()
                                    {
                                        if tab.sftp_sort_col == SftpSortColumn::Date {
                                            tab.sftp_sort_dir = match tab.sftp_sort_dir {
                                                SortDirection::Ascending => SortDirection::Descending,
                                                SortDirection::Descending => SortDirection::Ascending,
                                            };
                                        } else {
                                            tab.sftp_sort_col = SftpSortColumn::Date;
                                            tab.sftp_sort_dir = SortDirection::Descending;
                                        }
                                        sort_changed = true;
                                    }
                                }
                            });
                        });
                    });

                if sort_changed {
                    tab.sort_sftp_entries();
                }

                ui.add_space(2.0);
                ui.separator();

                let mut cd_into: Option<String> = None;
                let mut download_req: Option<(String, String)> = None;
                let mut delete_req: Option<(String, bool)> = None;
                let mut props_req: Option<SftpFileEntry> = None;

                egui::ScrollArea::vertical()
                    .auto_shrink([false, false])
                    .show(ui, |ui| {
                        for entry in &tab.sftp_entries {
                            ui.horizontal(|ui| {
                                let icon = if entry.is_dir {
                                    "\u{E24A}"
                                } else if entry.is_symlink {
                                    "🔗"
                                } else {
                                    "📄"
                                };
                                let btn = ui.add(
                                    egui::Button::new(format!("{} {}", icon, entry.name))
                                        .frame(false)
                                        .truncate(),
                                );
                                if btn.clicked() && entry.is_dir {
                                    cd_into = Some(entry.full_path.clone());
                                }
                                btn.context_menu(|ui| {
                                    if ui
                                        .button(tr(
                                            lang,
                                            "Propriétés / chmod / lien / SHA-256…",
                                            "Properties / chmod / link / SHA-256…",
                                        ))
                                        .clicked()
                                    {
                                        props_req = Some(entry.clone());
                                        ui.close();
                                    }
                                });

                                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                                    // 0. Properties button
                                    if ui
                                        .small_button("\u{2026}")
                                        .on_hover_text(tr(
                                            lang,
                                            "Propriétés : chmod, lien symbolique, SHA-256",
                                            "Properties: chmod, symlink, SHA-256",
                                        ))
                                        .clicked()
                                    {
                                        props_req = Some(entry.clone());
                                    }

                                    // 1. Delete button
                                    if ui
                                        .small_button("\u{E4A6}")
                                        .on_hover_text(tr(
                                            lang,
                                            "Supprimer sur le serveur",
                                            "Delete on remote server",
                                        ))
                                        .clicked()
                                    {
                                        delete_req = Some((entry.full_path.clone(), entry.is_dir));
                                    }

                                    // 2. Download button or 22px spacing for directories
                                    if !entry.is_dir {
                                        if ui
                                            .small_button("\u{E20C}")
                                            .on_hover_text(tr(
                                                lang,
                                                "Télécharger ce fichier",
                                                "Download this file",
                                            ))
                                            .clicked()
                                        {
                                            download_req =
                                                Some((entry.full_path.clone(), entry.name.clone()));
                                        }
                                    } else {
                                        ui.add_space(22.0);
                                    }

                                    // 3. Size column (58px)
                                    let size_str = if entry.is_dir {
                                        "-".to_string()
                                    } else {
                                        format_bytes(entry.size)
                                    };
                                    ui.add_sized(
                                        [58.0, 16.0],
                                        egui::Label::new(
                                            RichText::new(size_str)
                                                .small()
                                                .monospace()
                                                .color(Color32::from_rgb(139, 148, 158)),
                                        ),
                                    );

                                    // 4. Date column (76px if show_date)
                                    if show_date {
                                        let date_str = if entry.mtime > 0 {
                                            chrono::DateTime::from_timestamp(entry.mtime as i64, 0)
                                                .map(|dt| dt.format("%d/%m/%y %H:%M").to_string())
                                                .unwrap_or_else(|| "-".to_string())
                                        } else {
                                            "-".to_string()
                                        };
                                        ui.add_sized(
                                            [76.0, 16.0],
                                            egui::Label::new(
                                                RichText::new(date_str)
                                                    .small()
                                                    .monospace()
                                                    .color(Color32::from_rgb(110, 118, 129)),
                                            ),
                                        );
                                    }
                                });
                            });
                        }
                    });

                if let Some(entry) = props_req {
                    let mode = entry.permissions & 0o7777;
                    tab.sftp_props = Some(SftpPropsDialog {
                        entry,
                        mode,
                        mode_text: format!("{mode:04o}"),
                        link_name: String::new(),
                        sha256: None,
                        hashing: false,
                    });
                }
                if let Some(dir) = cd_into {
                    let _ = tab.handle.cmd_tx.send(BackendCommand::SftpListDir(dir));
                }
                if let Some((remote_path, file_name)) = download_req
                    && let Some(save_path) =
                        rfd::FileDialog::new().set_file_name(&file_name).save_file()
                {
                    let _ = tab.handle.cmd_tx.send(BackendCommand::SftpDownload {
                        remote_path,
                        local_path: save_path,
                    });
                }
                if let Some((remote_path, is_dir)) = delete_req {
                    let _ = tab.handle.cmd_tx.send(BackendCommand::SftpDelete {
                        remote_path,
                        is_dir,
                    });
                }
            });

        Self::render_sftp_dialogs(&ui.ctx().clone(), lang, tab);
    }

    fn render_sftp_client_full(&mut self, ui: &mut Ui, ctx: &Context) {
        let lang = self.config.language;
        let Some(tab) = self.tabs.get_mut(self.active_tab_idx) else {
            return;
        };

        let mut close_requested = false;
        let remote_path = tab.sftp_current_path.clone();
        let remote_entries = tab.sftp_entries.clone();
        let cmd_tx = tab.handle.cmd_tx.clone();

        tab.sftp_client.render(
            ui,
            ctx,
            lang,
            &remote_path,
            &remote_entries,
            &cmd_tx,
            &mut close_requested,
        );

        if let Some(entry) = tab.sftp_client.props_request.take() {
            let mode = entry.permissions & 0o7777;
            tab.sftp_props = Some(SftpPropsDialog {
                entry,
                mode,
                mode_text: format!("{mode:04o}"),
                link_name: String::new(),
                sha256: None,
                hashing: false,
            });
        }

        if tab.sftp_client.mirror_request {
            tab.sftp_client.mirror_request = false;
            tab.sftp_mirror.open = true;
            tab.sftp_mirror.local_dir = tab.sftp_client.local_path.to_string_lossy().to_string();
            tab.sftp_mirror.remote_dir = tab.sftp_current_path.clone();
        }

        if close_requested {
            tab.show_sftp_full = false;
        }

        Self::render_sftp_dialogs(ctx, lang, tab);
    }

    /// SFTP "Properties" (chmod / symlink / SHA-256) and "Mirror" windows of a tab.
    fn render_sftp_dialogs(ctx: &Context, lang: UiLanguage, tab: &mut SessionTab) {
        let cmd_tx = tab.handle.cmd_tx.clone();
        let current_dir = tab.sftp_current_path.clone();

        let mut close_props = false;
        if let Some(props) = tab.sftp_props.as_mut() {
            let mut open = true;
            egui::Window::new(tr(lang, "Propriétés SFTP", "SFTP properties"))
                .open(&mut open)
                .collapsible(false)
                .resizable(false)
                .show(ctx, |ui| {
                    ui.label(RichText::new(&props.entry.full_path).monospace().strong());
                    let date = if props.entry.mtime > 0 {
                        chrono::DateTime::from_timestamp(props.entry.mtime as i64, 0)
                            .map(|dt| dt.format("%Y-%m-%d %H:%M").to_string())
                            .unwrap_or_default()
                    } else {
                        String::new()
                    };
                    ui.label(
                        RichText::new(format!(
                            "{}  {}  {}",
                            if props.entry.is_dir {
                                tr(lang, "Dossier", "Folder").to_string()
                            } else {
                                format_bytes(props.entry.size)
                            },
                            date,
                            format_unix_mode(props.entry.permissions)
                        ))
                        .small()
                        .color(Color32::from_rgb(139, 148, 158)),
                    );
                    ui.separator();

                    ui.label(RichText::new("chmod").strong());
                    egui::Grid::new("sftp_perm_grid").show(ui, |ui| {
                        ui.label("");
                        for h in ["r", "w", "x"] {
                            ui.label(RichText::new(h).monospace());
                        }
                        ui.end_row();
                        for (shift, name) in [
                            (6u32, tr(lang, "Propriétaire", "Owner")),
                            (3, tr(lang, "Groupe", "Group")),
                            (0, tr(lang, "Autres", "Others")),
                        ] {
                            ui.label(name);
                            for bit in [4u32, 2, 1] {
                                let mask = bit << shift;
                                let mut on = props.mode & mask != 0;
                                if ui.checkbox(&mut on, "").changed() {
                                    if on {
                                        props.mode |= mask;
                                    } else {
                                        props.mode &= !mask;
                                    }
                                    props.mode_text = format!("{:04o}", props.mode);
                                }
                            }
                            ui.end_row();
                        }
                    });
                    ui.horizontal(|ui| {
                        ui.label(tr(lang, "Octal :", "Octal:"));
                        if ui
                            .add(
                                egui::TextEdit::singleline(&mut props.mode_text)
                                    .desired_width(54.0)
                                    .font(egui::TextStyle::Monospace),
                            )
                            .changed()
                            && let Ok(m) = u32::from_str_radix(props.mode_text.trim(), 8)
                        {
                            props.mode = m & 0o7777;
                        }
                        if ui.button(tr(lang, "Appliquer", "Apply")).clicked() {
                            let _ = cmd_tx.send(BackendCommand::SftpChmod {
                                remote_path: props.entry.full_path.clone(),
                                mode: props.mode,
                            });
                        }
                    });

                    ui.separator();
                    ui.label(
                        RichText::new(tr(
                            lang,
                            "Lien symbolique vers cet élément",
                            "Symbolic link to this item",
                        ))
                        .strong(),
                    );
                    ui.horizontal(|ui| {
                        ui.add(
                            egui::TextEdit::singleline(&mut props.link_name)
                                .hint_text(tr(lang, "nom-du-lien", "link-name"))
                                .desired_width(180.0),
                        );
                        if ui.button(tr(lang, "Créer", "Create")).clicked()
                            && !props.link_name.trim().is_empty()
                        {
                            let name = props.link_name.trim();
                            let link_path = if current_dir.ends_with('/') {
                                format!("{current_dir}{name}")
                            } else {
                                format!("{current_dir}/{name}")
                            };
                            let _ = cmd_tx.send(BackendCommand::SftpSymlink {
                                target: props.entry.full_path.clone(),
                                link_path,
                            });
                            props.link_name.clear();
                        }
                    });

                    if !props.entry.is_dir {
                        ui.separator();
                        ui.horizontal(|ui| {
                            if ui
                                .add_enabled(
                                    !props.hashing,
                                    egui::Button::new(tr(
                                        lang,
                                        "Calculer SHA-256",
                                        "Compute SHA-256",
                                    )),
                                )
                                .clicked()
                            {
                                props.hashing = true;
                                props.sha256 = None;
                                let _ = cmd_tx.send(BackendCommand::SftpSha256(
                                    props.entry.full_path.clone(),
                                ));
                            }
                            if props.hashing {
                                ui.spinner();
                            }
                        });
                        if let Some(hash) = props.sha256.clone() {
                            ui.add(
                                egui::Label::new(RichText::new(&hash).monospace().small())
                                    .selectable(true)
                                    .wrap(),
                            );
                            if ui.button(tr(lang, "Copier", "Copy")).clicked() {
                                ui.ctx().copy_text(hash);
                            }
                        }
                    }
                });
            close_props = !open;
        }
        if close_props {
            tab.sftp_props = None;
        }

        if tab.sftp_mirror.open {
            let m = &mut tab.sftp_mirror;
            let mut open = true;
            egui::Window::new(tr(lang, "Miroir SFTP", "SFTP mirror"))
                .open(&mut open)
                .collapsible(false)
                .default_width(460.0)
                .show(ctx, |ui| {
                    ui.horizontal(|ui| {
                        ui.radio_value(
                            &mut m.download,
                            false,
                            tr(lang, "Local \u{2192} Distant", "Local \u{2192} Remote"),
                        );
                        ui.radio_value(
                            &mut m.download,
                            true,
                            tr(lang, "Distant \u{2192} Local", "Remote \u{2192} Local"),
                        );
                    });
                    ui.horizontal(|ui| {
                        ui.label(tr(lang, "Dossier local :", "Local folder:"));
                        ui.add(egui::TextEdit::singleline(&mut m.local_dir).desired_width(260.0));
                        if ui.button(tr(lang, "Parcourir", "Browse")).clicked()
                            && let Some(dir) = rfd::FileDialog::new().pick_folder()
                        {
                            m.local_dir = dir.to_string_lossy().to_string();
                        }
                    });
                    ui.horizontal(|ui| {
                        ui.label(tr(lang, "Dossier distant :", "Remote folder:"));
                        ui.add(egui::TextEdit::singleline(&mut m.remote_dir).desired_width(260.0));
                    });
                    let delete_color = if m.delete_extra {
                        Color32::from_rgb(248, 81, 73)
                    } else {
                        Color32::from_rgb(201, 209, 217)
                    };
                    ui.checkbox(
                        &mut m.delete_extra,
                        RichText::new(tr(
                            lang,
                            "Supprimer sur la destination les fichiers absents de la source",
                            "Delete files on the destination that are missing from the source",
                        ))
                        .color(delete_color),
                    );
                    ui.horizontal(|ui| {
                        let ready = !m.busy
                            && !m.local_dir.trim().is_empty()
                            && !m.remote_dir.trim().is_empty();
                        for (label, dry_run) in [
                            (tr(lang, "Prévisualiser", "Preview"), true),
                            (tr(lang, "Synchroniser", "Synchronize"), false),
                        ] {
                            if ui.add_enabled(ready, egui::Button::new(label)).clicked() {
                                m.busy = true;
                                m.summary.clear();
                                m.lines.clear();
                                let _ = cmd_tx.send(BackendCommand::SftpMirror {
                                    local_dir: PathBuf::from(m.local_dir.trim()),
                                    remote_dir: m.remote_dir.trim().to_string(),
                                    upload: !m.download,
                                    delete_extra: m.delete_extra,
                                    dry_run,
                                });
                            }
                        }
                        if m.busy {
                            ui.spinner();
                        }
                        ui.label(&m.summary);
                    });
                    egui::ScrollArea::vertical()
                        .max_height(220.0)
                        .show(ui, |ui| {
                            for line in m.lines.iter().take(500) {
                                ui.label(RichText::new(line).monospace().small());
                            }
                            if m.lines.len() > 500 {
                                ui.label(format!("… +{}", m.lines.len() - 500));
                            }
                        });
                });
            m.open = open;
        }
    }

    fn render_welcome_dashboard(&mut self, ui: &mut Ui) {
        let lang = self.config.language;
        let mut session_to_launch: Option<SessionProfile> = None;
        let mut session_to_edit: Option<SessionProfile> = None;
        let mut session_to_duplicate: Option<Uuid> = None;
        let mut session_to_delete: Option<Uuid> = None;
        let mut ppk_to_load: Option<String> = None;

        egui::ScrollArea::vertical()
            .auto_shrink([false, false])
            .show(ui, |ui| {
                ui.add_space(24.0);
                ui.vertical_centered(|ui| {
                    ui.add(
                        egui::Image::new(egui::include_image!("../../assets/cuty_ssh_icon.png"))
                            .max_width(64.0)
                            .corner_radius(14.0),
                    );
                    ui.add_space(8.0);
                    ui.heading(
                        RichText::new(tr(
                            lang,
                            "\u{E648} Cuty-SSH — Cockpit SysAdmin & Client SSH / Telnet",
                            "\u{E648} Cuty-SSH — SysAdmin Cockpit & SSH / Telnet Client",
                        ))
                        .size(24.0)
                        .strong()
                        .color(Color32::from_rgb(88, 166, 255)),
                    );
                    ui.add_space(6.0);
                    ui.label(
                        RichText::new(tr(
                            lang,
                            "SSH2 • Bastion (-J) • Telnet • Raw TCP • SFTP • ConPTY • Clés PuTTY (.ppk v2/v3) & Pageant • Télémétrie Live",
                            "SSH2 • Bastion (-J) • Telnet • Raw TCP • SFTP • ConPTY • PuTTY Keys (.ppk v2/v3) & Pageant • Live Telemetry",
                        ))
                        .size(13.5)
                        .color(Color32::from_rgb(139, 148, 158)),
                    );
                });

                ui.add_space(18.0);

                // Quick actions: the other tools live in the top toolbar and the palette.
                ui.horizontal_wrapped(|ui| {
                    ui.add_space(16.0);
                    if ui
                        .add_sized(
                            [170.0, 36.0],
                            egui::Button::new(
                                RichText::new(tr(
                                    lang,
                                    "\u{E3D4}  Nouvelle session",
                                    "\u{E3D4}  New Session",
                                ))
                                .strong()
                                .color(Color32::WHITE),
                            )
                            .fill(theme::ACCENT_STRONG)
                            .stroke(Stroke::new(1.0, theme::ACCENT)),
                        )
                        .clicked()
                    {
                        self.editing_session = SessionProfile::default();
                        self.is_new_session = true;
                        self.show_session_editor = true;
                    }
                    if ui
                        .add_sized(
                            [170.0, 36.0],
                            egui::Button::new(tr(
                                lang,
                                "\u{E2D6}  Clés .ppk & Pageant",
                                "\u{E2D6}  .ppk Keys & Pageant",
                            )),
                        )
                        .clicked()
                    {
                        self.refresh_agent_keys();
                        self.show_key_manager = true;
                    }
                    if ui
                        .add_sized(
                            [190.0, 36.0],
                            egui::Button::new(
                                RichText::new(tr(
                                    lang,
                                    "\u{E20C}  Charger .ppk → Pageant",
                                    "\u{E20C}  Load .ppk → Pageant",
                                ))
                                .color(Color32::from_rgb(210, 153, 34)),
                            ),
                        )
                        .on_hover_text(tr(
                            lang,
                            "Charge en 1 clic toutes les clés .ppk de vos sessions sauvegardées dans Pageant.exe",
                            "1-click load all .ppk keys from your saved sessions into Pageant.exe",
                        ))
                        .clicked()
                    {
                        self.load_all_session_ppks_into_pageant();
                        self.show_key_manager = true;
                    }
                    if ui
                        .add_sized(
                            [150.0, 36.0],
                            egui::Button::new(tr(
                                lang,
                                "\u{E0F2}  Ping serveurs",
                                "\u{E0F2}  Ping Servers",
                            )),
                        )
                        .clicked()
                    {
                        self.probe_all_sessions();
                    }
                });

                ui.add_space(20.0);

                let filtered = self.filter_and_sort_sessions(
                    &self.dashboard_session_query,
                    self.dashboard_protocol_filter,
                    &self.dashboard_folder_filter,
                    &self.dashboard_tag_filter,
                    self.dashboard_reachability_filter(),
                    self.dashboard_sort_mode,
                );

                let side_pad = 20.0;
                let spacing = 16.0;
                let frame_pad = 12.0;

                // Section Title + Result count
                ui.horizontal(|ui| {
                    ui.add_space(side_pad);
                    ui.label(
                        RichText::new(format!(
                            "\u{E560} {} ({} / {})",
                            tr(
                                lang,
                                "VOS SESSIONS DISPONIBLES",
                                "AVAILABLE SESSIONS",
                            ),
                            filtered.len(),
                            self.config.sessions.len()
                        ))
                        .size(13.0)
                        .strong()
                        .color(Color32::from_rgb(201, 209, 217)),
                    );
                });
                ui.add_space(10.0);

                // Search & Filter Toolbar on Dashboard
                ui.horizontal_wrapped(|ui| {
                    ui.add_space(side_pad);
                    ui.label("\u{E30C}");
                    ui.add(
                        egui::TextEdit::singleline(&mut self.dashboard_session_query)
                            .hint_text(tr(
                                lang,
                                "Rechercher (nom, IP/hôte, #tag, user, port, dossier)...",
                                "Search (name, IP/host, #tag, user, port, folder)...",
                            ))
                            .desired_width(260.0),
                    );
                    if !self.dashboard_session_query.is_empty() && ui.small_button("\u{E4F6}").clicked() {
                        self.dashboard_session_query.clear();
                    }

                    ui.separator();

                    // Protocol filter pills with counters
                    let proto_filter = self.dashboard_protocol_filter;
                    if ui
                        .selectable_label(
                            proto_filter.is_none(),
                            format!(
                                "{} ({})",
                                tr(lang, "Tous", "All"),
                                self.config.sessions.len()
                            ),
                        )
                        .clicked()
                    {
                        self.dashboard_protocol_filter = None;
                    }
                    for p in [
                        ProtocolType::Ssh,
                        ProtocolType::Telnet,
                        ProtocolType::LocalShell,
                        ProtocolType::RawTcp,
                    ] {
                        let count = self
                            .config
                            .sessions
                            .iter()
                            .filter(|s| s.protocol == p)
                            .count();
                        let is_sel = proto_filter == Some(p);
                        if ui
                            .selectable_label(is_sel, format!("{} ({})", p.badge(), count))
                            .clicked()
                        {
                            if is_sel {
                                self.dashboard_protocol_filter = None;
                            } else {
                                self.dashboard_protocol_filter = Some(p);
                            }
                        }
                    }

                    ui.separator();

                    // Folder filter dropdown
                    let all_folders = self.config.all_folders();
                    let folder_btn_txt = if self.dashboard_folder_filter == "Tous" {
                        tr(lang, "\u{E24A} Tous", "\u{E24A} All Folders").to_string()
                    } else {
                        format!("\u{E24A} {}", self.dashboard_folder_filter)
                    };
                    egui::ComboBox::from_id_salt("dashboard_folder_filter")
                        .selected_text(folder_btn_txt)
                        .show_ui(ui, |ui| {
                            ui.selectable_value(
                                &mut self.dashboard_folder_filter,
                                "Tous".to_string(),
                                tr(lang, "\u{E24A} Tous les dossiers", "\u{E24A} All Folders"),
                            );
                            for f in &all_folders {
                                let f_count = self
                                    .config
                                    .sessions
                                    .iter()
                                    .filter(|s| s.folder.eq_ignore_ascii_case(f))
                                    .count();
                                ui.selectable_value(
                                    &mut self.dashboard_folder_filter,
                                    f.clone(),
                                    format!("\u{E24A} {} ({})", f, f_count),
                                );
                            }
                        });

                    // Tag filter dropdown
                    let all_tags = self.config.all_tags();
                    if !all_tags.is_empty() {
                        egui::ComboBox::from_id_salt("dashboard_tag_filter")
                            .selected_text(if self.dashboard_tag_filter == "Tous" {
                                tr(lang, "\u{E478} Tous les tags", "\u{E478} All Tags").to_string()
                            } else {
                                format!("\u{E478} #{}", self.dashboard_tag_filter)
                            })
                            .show_ui(ui, |ui| {
                                ui.selectable_value(
                                    &mut self.dashboard_tag_filter,
                                    "Tous".to_string(),
                                    tr(lang, "\u{E478} Tous les tags", "\u{E478} All Tags"),
                                );
                                for t in &all_tags {
                                    let t_count = self
                                        .config
                                        .sessions
                                        .iter()
                                        .filter(|s| {
                                            s.tags.iter().any(|st| st.eq_ignore_ascii_case(t))
                                        })
                                        .count();
                                    ui.selectable_value(
                                        &mut self.dashboard_tag_filter,
                                        t.clone(),
                                        format!("\u{E478} #{} ({})", t, t_count),
                                    );
                                }
                            });
                    }

                    // Online-only filter toggle
                    let online_col = if self.dashboard_online_only {
                        Color32::from_rgb(63, 185, 80)
                    } else {
                        Color32::from_rgb(139, 148, 158)
                    };
                    if ui
                        .selectable_label(
                            self.dashboard_online_only,
                            RichText::new(tr(lang, "● En ligne", "● Online")).color(online_col),
                        )
                        .on_hover_text(tr(
                            lang,
                            "Filtrer uniquement les serveurs avec ping réussi",
                            "Show only servers responding to TCP ping",
                        ))
                        .clicked()
                    {
                        self.dashboard_online_only = !self.dashboard_online_only;
                        self.dashboard_offline_only = false;
                    }

                    // Offline-only filter toggle
                    let offline_col = if self.dashboard_offline_only {
                        Color32::from_rgb(248, 81, 73)
                    } else {
                        Color32::from_rgb(139, 148, 158)
                    };
                    if ui
                        .selectable_label(
                            self.dashboard_offline_only,
                            RichText::new(tr(lang, "● Hors ligne", "● Offline")).color(offline_col),
                        )
                        .on_hover_text(tr(
                            lang,
                            "Filtrer uniquement les serveurs injoignables",
                            "Show only unreachable servers",
                        ))
                        .clicked()
                    {
                        self.dashboard_offline_only = !self.dashboard_offline_only;
                        self.dashboard_online_only = false;
                    }

                    // Sort mode ComboBox
                    egui::ComboBox::from_id_salt("dashboard_sort_mode")
                        .selected_text(self.dashboard_sort_mode.label(lang))
                        .show_ui(ui, |ui| {
                            for m in [
                                SessionSortMode::NameAsc,
                                SessionSortMode::NameDesc,
                                SessionSortMode::FolderAndName,
                                SessionSortMode::Protocol,
                                SessionSortMode::Latency,
                            ] {
                                ui.selectable_value(
                                    &mut self.dashboard_sort_mode,
                                    m,
                                    m.label(lang),
                                );
                            }
                        });

                    let has_filter = !self.dashboard_session_query.is_empty()
                        || self.dashboard_protocol_filter.is_some()
                        || (self.dashboard_folder_filter != "Tous"
                            && self.dashboard_folder_filter != "Tous les dossiers")
                        || (self.dashboard_tag_filter != "Tous"
                            && self.dashboard_tag_filter != "Tous les tags")
                        || self.dashboard_online_only
                        || self.dashboard_offline_only;

                    if has_filter
                        && ui
                            .small_button("\u{E094} Reset")
                            .on_hover_text(tr(
                                lang,
                                "Réinitialiser tous les filtres de recherche",
                                "Reset all search filters",
                            ))
                            .clicked()
                    {
                        self.dashboard_session_query.clear();
                        self.dashboard_protocol_filter = None;
                        self.dashboard_folder_filter = "Tous".to_string();
                        self.dashboard_tag_filter = "Tous".to_string();
                        self.dashboard_online_only = false;
                        self.dashboard_offline_only = false;
                    }
                });
                ui.add_space(14.0);

                if filtered.is_empty() {
                    ui.horizontal(|ui| {
                        ui.add_space(side_pad);
                        egui::Frame::NONE
                            .fill(Color32::from_rgb(18, 22, 29))
                            .corner_radius(8.0)
                            .inner_margin(egui::Margin::symmetric(24, 20))
                            .stroke(Stroke::new(1.0, Color32::from_rgb(38, 44, 54)))
                            .show(ui, |ui| {
                                ui.vertical_centered(|ui| {
                                    ui.label(
                                        RichText::new(tr(
                                            lang,
                                            "\u{E30C} Aucune session ne correspond à vos critères de recherche",
                                            "\u{E30C} No session matches your search criteria",
                                        ))
                                        .size(14.0)
                                        .color(Color32::from_rgb(139, 148, 158)),
                                    );
                                    ui.add_space(8.0);
                                    if ui
                                        .button(tr(
                                            lang,
                                            "\u{E094} Réinitialiser tous les filtres",
                                            "\u{E094} Reset all filters",
                                        ))
                                        .clicked()
                                    {
                                        self.dashboard_session_query.clear();
                                        self.dashboard_protocol_filter = None;
                                        self.dashboard_folder_filter = "Tous".to_string();
                                        self.dashboard_tag_filter = "Tous".to_string();
                                        self.dashboard_online_only = false;
                                        self.dashboard_offline_only = false;
                                    }
                                });
                            });
                    });
                } else {
                    let total_avail = ui.available_width();
                    // Cards sit in a horizontal layout: every `add_space` is followed by the
                    // layout's own item spacing, which must be part of the column math.
                    let item_gap = ui.spacing().item_spacing.x;
                    let gap = spacing + item_gap;
                    let net_grid_width = (total_avail - side_pad * 2.0 - item_gap).max(280.0);

                    let min_card_outer = 290.0;
                    let max_card_outer = 380.0;
                    let max_allowed_cols = 4;
                    let cols = (((net_grid_width + gap) / (min_card_outer + gap))
                        .floor() as usize)
                        .clamp(1, max_allowed_cols);

                    let outer_card_width = ((net_grid_width
                        - (cols.saturating_sub(1) as f32 * gap))
                        / cols as f32)
                        .min(max_card_outer);

                    // 1 px stroke on each side is added by the frame on top of its margin.
                    let inner_card_width = (outer_card_width - frame_pad * 2.0 - 2.0).max(220.0);

                    for chunk in filtered.chunks(cols) {
                        ui.horizontal(|ui| {
                            ui.add_space(side_pad);
                            for (i, s) in chunk.iter().enumerate() {
                                if i > 0 {
                                    ui.add_space(spacing);
                                }
                                let (proto_tag, proto_color) = protocol_badge_style(s.protocol);
                                let probe = self.session_probes.get(&s.id);
                                let has_bastion =
                                    s.jump_host_id.is_some() || !s.proxy_jump.trim().is_empty();

                                let card = egui::Frame::NONE
                                    .fill(theme::SURFACE)
                                    .corner_radius(egui::CornerRadius::same(10))
                                    .inner_margin(egui::Margin::same(frame_pad as i8))
                                    .stroke(Stroke::new(1.0, Color32::from_rgb(38, 44, 54)))
                                    .show(ui, |ui| {
                                        ui.set_width(inner_card_width);
                                        ui.vertical(|ui| {
                                            // Row 1: Session Icon + Name (left) and Protocol Badge + Ping (right)
                                            ui.horizontal(|ui| {
                                                ui.label(
                                                    RichText::new(format!(
                                                        "{} {}",
                                                        s.icon_badge, s.name
                                                    ))
                                                    .size(13.5)
                                                    .strong()
                                                    .color(Color32::from_rgb(230, 237, 243)),
                                                );
                                                ui.with_layout(
                                                    Layout::right_to_left(Align::Center),
                                                    |ui| {
                                                        egui::Frame::NONE
                                                            .fill(proto_color.gamma_multiply(0.18))
                                                            .corner_radius(
                                                                egui::CornerRadius::same(4),
                                                            )
                                                            .inner_margin(egui::Margin::symmetric(
                                                                6, 2,
                                                            ))
                                                            .stroke(Stroke::new(
                                                                0.8,
                                                                proto_color.gamma_multiply(0.55),
                                                            ))
                                                            .show(ui, |ui| {
                                                                ui.label(
                                                                    RichText::new(proto_tag)
                                                                        .size(10.0)
                                                                        .monospace()
                                                                        .strong()
                                                                        .color(proto_color),
                                                                );
                                                            });

                                                        if has_bastion {
                                                            egui::Frame::NONE
                                                                .fill(Color32::from_rgb(46, 30, 68))
                                                                .corner_radius(
                                                                    egui::CornerRadius::same(4),
                                                                )
                                                                .inner_margin(
                                                                    egui::Margin::symmetric(5, 2),
                                                                )
                                                                .stroke(Stroke::new(
                                                                    0.8,
                                                                    Color32::from_rgb(
                                                                        163, 113, 247,
                                                                    ),
                                                                ))
                                                                .show(ui, |ui| {
                                                                    ui.label(
                                                                        RichText::new("\u{E89C} Bastion")
                                                                            .size(9.5)
                                                                            .monospace()
                                                                            .strong()
                                                                            .color(Color32::from_rgb(
                                                                                210, 168, 255,
                                                                            )),
                                                                    );
                                                                });
                                                        }

                                                        if let Some(p) = probe {
                                                            let (txt, col) = if p.reachable {
                                                                (
                                                                    format!("● {}ms", p.latency_ms),
                                                                    Color32::from_rgb(63, 185, 80),
                                                                )
                                                            } else {
                                                                (
                                                                    tr(
                                                                        lang,
                                                                        "● Hors-ligne",
                                                                        "● Offline",
                                                                    )
                                                                    .to_string(),
                                                                    Color32::from_rgb(248, 81, 73),
                                                                )
                                                            };
                                                            ui.label(
                                                                RichText::new(txt)
                                                                    .size(10.0)
                                                                    .monospace()
                                                                    .color(col),
                                                            )
                                                            .on_hover_text(&p.banner);
                                                        }
                                                    },
                                                );
                                            });

                                            ui.add_space(4.0);
                                            let subtitle = if s.protocol == ProtocolType::LocalShell
                                            {
                                                s.local_shell_cmd.clone()
                                            } else if s.username.is_empty() {
                                                format!("{}:{}", s.host, s.port)
                                            } else {
                                                format!("{}@{}:{}", s.username, s.host, s.port)
                                            };
                                            ui.label(
                                                RichText::new(subtitle)
                                                    .size(11.0)
                                                    .monospace()
                                                    .color(Color32::from_rgb(139, 148, 158)),
                                            );

                                            let ppk_file = if let SshAuthMethod::PrivateKeyFile {
                                                key_path,
                                                ..
                                            } = &s.ssh_auth
                                            {
                                                if !key_path.is_empty() {
                                                    Some(key_path.clone())
                                                } else {
                                                    None
                                                }
                                            } else {
                                                None
                                            };

                                            if let Some(ref kp) = ppk_file {
                                                let short_name = std::path::Path::new(kp)
                                                    .file_name()
                                                    .map(|f| f.to_string_lossy().to_string())
                                                    .unwrap_or_else(|| kp.clone());
                                                ui.label(
                                                    RichText::new(format!("\u{E2D6} {}", short_name))
                                                        .size(10.5)
                                                        .monospace()
                                                        .color(Color32::from_rgb(210, 153, 34)),
                                                );
                                            } else {
                                                ui.label(
                                                    RichText::new(format!("\u{E24A} {}", s.folder))
                                                        .size(10.5)
                                                        .color(Color32::from_rgb(110, 118, 129)),
                                                );
                                            }

                                            if !s.tags.is_empty() {
                                                ui.add_space(3.0);
                                                ui.horizontal_wrapped(|ui| {
                                                    for t in &s.tags {
                                                        egui::Frame::NONE
                                                            .fill(Color32::from_rgb(26, 36, 50))
                                                            .corner_radius(egui::CornerRadius::same(3))
                                                            .inner_margin(egui::Margin::symmetric(5, 2))
                                                            .stroke(Stroke::new(0.5, Color32::from_rgb(56, 90, 150)))
                                                            .show(ui, |ui| {
                                                                ui.label(
                                                                    RichText::new(format!("#{}", t))
                                                                        .size(9.5)
                                                                        .color(Color32::from_rgb(140, 190, 255)),
                                                                );
                                                            });
                                                    }
                                                });
                                            }

                                            ui.add_space(8.0);
                                            ui.horizontal_wrapped(|ui| {
                                                if ui
                                                    .button(
                                                        RichText::new(tr(
                                                            lang,
                                                            "\u{E3FE} Connecter",
                                                            "\u{E3FE} Connect",
                                                        ))
                                                        .strong()
                                                        .color(Color32::from_rgb(88, 166, 255)),
                                                    )
                                                    .clicked()
                                                {
                                                    session_to_launch = Some((*s).clone());
                                                }
                                                if let Some(kp) = ppk_file
                                                    && ui
                                                        .button("\u{E2D6} → Pageant")
                                                        .on_hover_text(tr(
                                                            lang,
                                                            "Charger cette clé .ppk dans Pageant",
                                                            "Load this .ppk key into Pageant",
                                                        ))
                                                        .clicked()
                                                {
                                                    ppk_to_load = Some(kp);
                                                }
                                                if ui
                                                    .button("\u{E270}")
                                                    .on_hover_text(tr(
                                                        lang,
                                                        "Modifier la session",
                                                        "Edit session",
                                                    ))
                                                    .clicked()
                                                {
                                                    session_to_edit = Some((*s).clone());
                                                }
                                                if ui
                                                    .button("\u{E710}")
                                                    .on_hover_text(tr(
                                                        lang,
                                                        "Dupliquer cette session",
                                                        "Duplicate this session",
                                                    ))
                                                    .clicked()
                                                {
                                                    session_to_duplicate = Some(s.id);
                                                }
                                                if ui
                                                    .button("\u{E4A6}")
                                                    .on_hover_text(tr(
                                                        lang,
                                                        "Supprimer cette session",
                                                        "Delete this session",
                                                    ))
                                                    .clicked()
                                                {
                                                    session_to_delete = Some(s.id);
                                                }
                                            });
                                        });
                                    })
.response;
                                if ui.rect_contains_pointer(card.rect) {
                                    ui.painter().rect_stroke(
                                        card.rect,
                                        egui::CornerRadius::same(10),
                                        Stroke::new(1.0, theme::ACCENT.gamma_multiply(0.6)),
                                        egui::StrokeKind::Inside,
                                    );
                                }
                            }
                        });
                        ui.add_space(spacing);
                    }
                }
            });

        if let Some(s) = session_to_launch {
            self.launch_session(s);
        }
        if let Some(s) = session_to_edit {
            self.editing_session = s;
            self.is_new_session = false;
            self.show_session_editor = true;
        }
        if let Some(id) = session_to_duplicate
            && let Some(dup) = self.config.duplicate_session(id)
        {
            self.set_toast(format!(
                "{} '{}' !",
                tr(lang, "Session dupliquée :", "Duplicated session:"),
                dup.name
            ));
        }
        if let Some(id) = session_to_delete {
            let name = self
                .config
                .sessions
                .iter()
                .find(|s| s.id == id)
                .map(|s| s.name.clone())
                .unwrap_or_default();
            if self.config.delete_session(id) {
                self.set_toast(format!(
                    "{} '{}'.",
                    tr(lang, "Session supprimée :", "Deleted session:"),
                    name
                ));
            }
        }
        if let Some(kp) = ppk_to_load {
            let pageant_exe = self.resolve_pageant_path();
            let _ = launch_pageant_with_keys(&pageant_exe, &[kp]);
            self.refresh_agent_keys();
        }
    }

    fn render_key_manager_modal(&mut self, ctx: &Context) {
        let lang = self.config.language;
        let mut open = self.show_key_manager;
        egui::Window::new(tr(
            lang,
            "\u{E2D6} Gestionnaire Clés PuTTY (.ppk) & Agent Pageant",
            "\u{E2D6} PuTTY Keys (.ppk) & Pageant Agent Manager",
        ))
        .id(egui::Id::unique("key_manager_modal_v2"))
        .open(&mut open)
        .resizable(true)
        .default_size(Vec2::new(880.0, 680.0))
        .min_size(Vec2::new(720.0, 500.0))
        .show(ctx, |ui| {
            // Section 0: Primary SSH Key for 1-click ssh-copy-id (Password -> Key migration)
            egui::Frame::NONE
                .fill(Color32::from_rgb(18, 30, 24))
                .corner_radius(6.0)
                .inner_margin(egui::Margin::same(10))
                .stroke(Stroke::new(1.0, Color32::from_rgb(46, 160, 67)))
                .show(ui, |ui| {
                    ui.horizontal(|ui| {
                        ui.heading(
                            RichText::new(tr(
                                lang,
                                "\u{E46A} Clé SSH Principale (ssh-copy-id — Remplacement du mot de passe)",
                                "\u{E46A} Primary SSH Key (ssh-copy-id — Passwordless Provisioning)",
                            ))
                            .color(Color32::from_rgb(86, 211, 100)),
                        );
                    });
                    ui.label(
                        RichText::new(tr(
                            lang,
                            "Cette clé est envoyée en 1 clic dans ~/.ssh/authorized_keys lorsque vous vous connectez une première fois avec un mot de passe, puis la session bascule automatiquement dessus.",
                            "This key is pushed in 1 click to ~/.ssh/authorized_keys after your first password login, and the session automatically switches to it.",
                        ))
                        .small()
                        .color(Color32::from_rgb(139, 148, 158)),
                    );
                    ui.add_space(4.0);
                    ui.horizontal_wrapped(|ui| {
                        ui.label(tr(lang, "Clé principale :", "Primary Key:"));
                        ui.add(
                            egui::TextEdit::singleline(&mut self.config.primary_key_path)
                                .hint_text(tr(
                                    lang,
                                    "Auto (cuty-ssh-portable/keys/id_cuty_primary.ppk ou ~/.ssh/id_ed25519)",
                                    "Auto (cuty-ssh-portable/keys/id_cuty_primary.ppk or ~/.ssh/id_ed25519)",
                                ))
                                .desired_width(320.0),
                        );
                        if ui
                            .button(tr(lang, "\u{E256} Choisir", "\u{E256} Choose"))
                            .clicked()
                            && let Some(p) = rfd::FileDialog::new()
                                .add_filter("SSH & PuTTY Keys", &["ppk", "pem", "key", "pub", "*"])
                                .pick_file()
                        {
                            self.config.primary_key_path = p.to_string_lossy().to_string();
                            let _ = self.config.save();
                            self.inspected_key = inspect_key_file(&p).ok();
                        }
                        if ui
                            .button(
                                RichText::new(tr(
                                    lang,
                                    "\u{E6A2} Générer / Initialiser ma Clé Principale",
                                    "\u{E6A2} Generate / Initialize Primary Key",
                                ))
                                .color(Color32::from_rgb(86, 211, 100)),
                            )
                            .clicked()
                        {
                            match resolve_or_create_primary_key(&self.config.primary_key_path) {
                                Ok((p, info, created)) => {
                                    self.config.primary_key_path = p.to_string_lossy().to_string();
                                    let _ = self.config.save();
                                    self.inspected_key = Some(info);
                                    self.key_manager_status = if created {
                                        format!(
                                            "{} {}",
                                            tr(
                                                lang,
                                                "Clé principale Ed25519 créée :",
                                                "Primary Ed25519 key created:"
                                            ),
                                            p.display()
                                        )
                                    } else {
                                        format!(
                                            "{} {}",
                                            tr(
                                                lang,
                                                "Clé principale active :",
                                                "Active Primary Key:"
                                            ),
                                            p.display()
                                        )
                                    };
                                }
                                Err(e) => {
                                    self.key_manager_status = format!("Erreur : {e}");
                                }
                            }
                        }
                    });
                });

            ui.add_space(6.0);

            // Auto-resolve pageant path if current configured path does not exist on disk
            if !Path::new(&self.config.pageant_path).exists() {
                self.resolve_pageant_path();
            }

            // Section 1: Pageant ("C:\Program Files\PuTTY\pageant.exe")
            egui::Frame::NONE
                .fill(Color32::from_rgb(18, 22, 29))
                .corner_radius(6.0)
                .inner_margin(egui::Margin::same(10))
                .stroke(Stroke::new(1.0, Color32::from_rgb(38, 44, 54)))
                .show(ui, |ui| {
                    ui.heading(tr(
                        lang,
                        "\u{E40C} Intégration Pageant (PuTTY SSH Agent)",
                        "\u{E40C} Pageant Integration (PuTTY SSH Agent)",
                    ));
                    ui.add_space(4.0);
                    ui.horizontal(|ui| {
                        ui.label(tr(
                            lang,
                            "Exécutable Pageant :",
                            "Pageant Executable:",
                        ));
                        ui.add(
                            egui::TextEdit::singleline(&mut self.config.pageant_path)
                                .desired_width(340.0),
                        );
                        if ui
                            .small_button(tr(lang, "\u{E256} Parcourir", "\u{E256} Browse"))
                            .clicked()
                            && let Some(p) = rfd::FileDialog::new()
                                .add_filter("Executable", &["exe"])
                                .pick_file()
                        {
                            self.config.pageant_path = p.to_string_lossy().to_string();
                            let _ = self.config.save();
                        }
                    });

                    ui.add_space(6.0);
                    ui.horizontal_wrapped(|ui| {
                        if ui
                            .button(tr(lang, "\u{E3FE} Démarrer Pageant", "\u{E3FE} Launch Pageant"))
                            .on_hover_text(tr(
                                lang,
                                "Lance l'exécutable Pageant configuré pour garder vos clés .ppk en mémoire",
                                "Launches the configured Pageant executable to hold .ppk keys in memory",
                            ))
                            .clicked()
                        {
                            let pageant_exe = self.resolve_pageant_path();
                            match launch_pageant_with_keys(&pageant_exe, &[]) {
                                Ok(msg) => {
                                    self.key_manager_status = msg;
                                    self.refresh_agent_keys();
                                }
                                Err(e) => {
                                    self.key_manager_status = format!(
                                        "{} {}",
                                        tr(lang, "Erreur :", "Error:"),
                                        e
                                    )
                                }
                            }
                        }

                        if ui
                            .button(tr(
                                lang,
                                "\u{E3D4} Charger un fichier .ppk dans Pageant",
                                "\u{E3D4} Load .ppk File into Pageant",
                            ))
                            .on_hover_text(tr(
                                lang,
                                "Sélectionne un ou plusieurs fichiers .ppk et les transmet à Pageant.exe",
                                "Select one or more .ppk files and pass them to Pageant.exe",
                            ))
                            .clicked()
                            && let Some(files) = rfd::FileDialog::new()
                                .add_filter("PuTTY Keys (.ppk)", &["ppk"])
                                .pick_files()
                        {
                            let paths: Vec<String> = files
                                .into_iter()
                                .map(|p| p.to_string_lossy().to_string())
                                .collect();
                            let pageant_exe = self.resolve_pageant_path();
                            match launch_pageant_with_keys(&pageant_exe, &paths) {
                                Ok(msg) => {
                                    self.key_manager_status = msg;
                                    self.refresh_agent_keys();
                                }
                                Err(e) => {
                                    self.key_manager_status = format!(
                                        "{} {}",
                                        tr(lang, "Erreur :", "Error:"),
                                        e
                                    )
                                }
                            }
                        }

                        if ui
                            .button(
                                RichText::new(tr(
                                    lang,
                                    "\u{E20C} Charger toutes les clés .ppk des sessions",
                                    "\u{E20C} Load All Session .ppk Keys",
                                ))
                                .color(Color32::from_rgb(210, 153, 34)),
                            )
                            .on_hover_text(tr(
                                lang,
                                "Envoie toutes les clés .ppk configurées dans vos sessions sauvegardées directement à Pageant.exe",
                                "Send all .ppk keys configured across your saved sessions directly to Pageant.exe",
                            ))
                            .clicked()
                        {
                            self.load_all_session_ppks_into_pageant();
                        }

                        if ui
                            .button(tr(lang, "\u{E094} Rafraîchir l'Agent", "\u{E094} Refresh Agent"))
                            .clicked()
                        {
                            self.refresh_agent_keys();
                        }
                    });

                    ui.add_space(6.0);
                    if self.agent_keys.is_empty() {
                        ui.label(
                            RichText::new(tr(
                                lang,
                                "Aucune clé détectée dans Pageant / OpenSSH Agent (Assurez-vous que Pageant est lancé et possède au moins une clé .ppk).",
                                "No keys detected in Pageant / OpenSSH Agent (Ensure Pageant is running and has at least one .ppk key loaded).",
                            ))
                            .small()
                            .color(Color32::from_rgb(210, 153, 34)),
                        );
                    } else {
                        ui.label(
                            RichText::new(format!(
                                "\u{E182} {} {}",
                                self.agent_keys.len(),
                                tr(
                                    lang,
                                    "clé(s) disponible(s) via l'Agent SSH :",
                                    "key(s) available via SSH Agent:"
                                )
                            ))
                            .color(Color32::from_rgb(63, 185, 80)),
                        );
                        for k in &self.agent_keys {
                            ui.horizontal(|ui| {
                                ui.label(
                                    RichText::new(format!(
                                        "• [{}] {} — {} ({})",
                                        k.source_agent,
                                        k.algorithm,
                                        k.fingerprint_sha256,
                                        k.comment
                                    ))
                                    .monospace()
                                    .small(),
                                );
                                if ui
                                    .small_button(tr(
                                        lang,
                                        "\u{E196} Copier clé publique",
                                        "\u{E196} Copy Public Key",
                                    ))
                                    .clicked()
                                {
                                    if let Ok(mut cb) = Clipboard::new() {
                                        let _ = cb.set_text(k.openssh_public_key.clone());
                                    }
                                    self.key_manager_status = tr(
                                        lang,
                                        "Clé publique copiée dans le presse-papiers !",
                                        "Public key copied to clipboard!",
                                    )
                                    .to_string();
                                }
                            });
                        }
                    }
                });

            ui.add_space(8.0);

            // Section 2: Key Inspector & Converter (.ppk <-> OpenSSH)
            egui::Frame::NONE
                .fill(Color32::from_rgb(22, 27, 34))
                .corner_radius(6.0)
                .inner_margin(egui::Margin::same(10))
                .stroke(Stroke::new(1.0, Color32::from_rgb(48, 54, 61)))
                .show(ui, |ui| {
                    ui.heading(tr(
                        lang,
                        "\u{E30C} Inspecteur & Convertisseur de Clés (.ppk v2/v3 \u{E0A0} OpenSSH)",
                        "\u{E30C} Key Inspector & Converter (.ppk v2/v3 \u{E0A0} OpenSSH)",
                    ));
                    ui.add_space(4.0);
                    ui.horizontal(|ui| {
                        if ui
                            .button(tr(
                                lang,
                                "\u{E256} Ouvrir une clé (.ppk / OpenSSH / PEM)",
                                "\u{E256} Open Key File (.ppk / OpenSSH / PEM)",
                            ))
                            .clicked()
                            && let Some(path) = rfd::FileDialog::new()
                                .add_filter(
                                    "SSH & PuTTY Keys",
                                    &["ppk", "pem", "key", "pub", "*"],
                                )
                                .pick_file()
                        {
                            match inspect_key_file(&path) {
                                Ok(info) => {
                                    self.inspected_key = Some(info);
                                    self.key_manager_status = tr(
                                        lang,
                                        "Clé inspectée avec succès.",
                                        "Key inspected successfully.",
                                    )
                                    .to_string();
                                }
                                Err(e) => {
                                    self.key_manager_status = format!(
                                        "{} {}",
                                        tr(lang, "Erreur :", "Error:"),
                                        e
                                    );
                                }
                            }
                        }

                        ui.label(tr(
                            lang,
                            "Passphrase (si chiffrée) :",
                            "Passphrase (if encrypted):",
                        ));
                        ui.add(
                            egui::TextEdit::singleline(&mut self.key_manager_passphrase)
                                .password(true)
                                .desired_width(160.0),
                        );
                    });

                    if let Some(info) = self.inspected_key.clone() {
                        ui.add_space(6.0);
                        egui::Grid::new("inspected_key_grid")
                            .num_columns(2)
                            .spacing([10.0, 4.0])
                            .show(ui, |ui| {
                                ui.label(tr(lang, "Fichier :", "File:"));
                                ui.horizontal(|ui| {
                                    ui.monospace(&info.path);
                                    if ui
                                        .small_button(
                                            RichText::new(tr(
                                                lang,
                                                "\u{E46A} Définir comme Clé Principale",
                                                "\u{E46A} Set as Primary Key",
                                            ))
                                            .color(Color32::from_rgb(86, 211, 100)),
                                        )
                                        .clicked()
                                    {
                                        self.config.primary_key_path = info.path.clone();
                                        let _ = self.config.save();
                                        self.key_manager_status = format!(
                                            "{} {}",
                                            tr(
                                                lang,
                                                "Définie comme Clé Principale :",
                                                "Set as Primary Key:"
                                            ),
                                            info.path
                                        );
                                    }
                                });
                                ui.end_row();

                                ui.label(tr(lang, "Format :", "Format:"));
                                ui.label(
                                    RichText::new(&info.format_name)
                                        .strong()
                                        .color(Color32::from_rgb(88, 166, 255)),
                                );
                                ui.end_row();

                                ui.label(tr(lang, "Algorithme :", "Algorithm:"));
                                ui.monospace(&info.algorithm);
                                ui.end_row();

                                ui.label(tr(lang, "Chiffrement :", "Encryption:"));
                                ui.label(&info.encryption_details);
                                ui.end_row();

                                ui.label(tr(lang, "Empreinte :", "Fingerprint:"));
                                ui.monospace(&info.fingerprint_sha256);
                                ui.end_row();

                                ui.label(tr(lang, "Commentaire :", "Comment:"));
                                ui.label(&info.comment);
                                ui.end_row();
                            });

                        if !info.openssh_public_key.is_empty() {
                            ui.add_space(4.0);
                            ui.horizontal(|ui| {
                                ui.label(tr(
                                    lang,
                                    "Clé publique (authorized_keys) :",
                                    "Public Key (authorized_keys):",
                                ));
                                if ui
                                    .small_button(tr(lang, "\u{E196} Copier", "\u{E196} Copy"))
                                    .clicked()
                                {
                                    if let Ok(mut cb) = Clipboard::new() {
                                        let _ = cb.set_text(info.openssh_public_key.clone());
                                    }
                                    self.key_manager_status = tr(
                                        lang,
                                        "Ligne authorized_keys copiée !",
                                        "authorized_keys line copied!",
                                    )
                                    .to_string();
                                }
                            });
                            let mut pub_ro = info.openssh_public_key.clone();
                            ui.add(
                                egui::TextEdit::multiline(&mut pub_ro)
                                    .desired_rows(2)
                                    .desired_width(f32::INFINITY)
                                    .font(egui::TextStyle::Monospace),
                            );
                        }

                        ui.add_space(6.0);
                        ui.horizontal(|ui| {
                            if ui
                                .button(tr(
                                    lang,
                                    "\u{E094} Convertir & Sauvegarder en OpenSSH (id_rsa / id_ed25519)",
                                    "\u{E094} Convert & Save as OpenSSH (id_rsa / id_ed25519)",
                                ))
                                .clicked()
                            {
                                match load_private_key_any(
                                    std::path::Path::new(&info.path),
                                    Some(&self.key_manager_passphrase),
                                ) {
                                    Ok(priv_key) => {
                                        if let Ok(pem) = export_to_openssh_pem(&priv_key)
                                            && let Some(save_p) = rfd::FileDialog::new()
                                                .set_file_name("id_exported_openssh")
                                                .save_file()
                                        {
                                            let _ = std::fs::write(&save_p, pem);
                                            self.key_manager_status = format!(
                                                "{} {}",
                                                tr(
                                                    lang,
                                                    "Clé convertie au format OpenSSH :",
                                                    "Key converted to OpenSSH format:"
                                                ),
                                                save_p.display()
                                            );
                                        }
                                    }
                                    Err(e) => {
                                        self.key_manager_status = format!(
                                            "{} {}",
                                            tr(lang, "Erreur :", "Error:"),
                                            e
                                        );
                                    }
                                }
                            }

                            if ui
                                .button(tr(
                                    lang,
                                    "\u{E094} Convertir & Sauvegarder en PuTTY (.ppk v3)",
                                    "\u{E094} Convert & Save as PuTTY (.ppk v3)",
                                ))
                                .clicked()
                            {
                                match load_private_key_any(
                                    std::path::Path::new(&info.path),
                                    Some(&self.key_manager_passphrase),
                                ) {
                                    Ok(priv_key) => {
                                        let comment = if info.comment.is_empty() {
                                            "cuty-ssh-key"
                                        } else {
                                            &info.comment
                                        };
                                        match export_to_ppk_v3(&priv_key, comment) {
                                            Ok(ppk_str) => {
                                                if let Some(save_p) = rfd::FileDialog::new()
                                                    .add_filter("PuTTY Private Key", &["ppk"])
                                                    .set_file_name("key_exported.ppk")
                                                    .save_file()
                                                {
                                                    let _ = std::fs::write(&save_p, ppk_str);
                                                    self.key_manager_status = format!(
                                                        "{} {}",
                                                        tr(
                                                            lang,
                                                            "Clé convertie au format PuTTY .ppk :",
                                                            "Key converted to PuTTY .ppk format:"
                                                        ),
                                                        save_p.display()
                                                    );
                                                }
                                            }
                                            Err(e) => {
                                                self.key_manager_status = format!(
                                                    "{} {}",
                                                    tr(
                                                        lang,
                                                        "Erreur export .ppk :",
                                                        ".ppk export error:"
                                                    ),
                                                    e
                                                );
                                            }
                                        }
                                    }
                                    Err(e) => {
                                        self.key_manager_status = format!(
                                            "{} {}",
                                            tr(lang, "Erreur :", "Error:"),
                                            e
                                        );
                                    }
                                }
                            }
                        });
                    }
                });

            ui.add_space(8.0);

            // Section 3: Integrated PuTTYgen key generator
            egui::Frame::NONE
                .fill(Color32::from_rgb(22, 27, 34))
                .corner_radius(6.0)
                .inner_margin(egui::Margin::same(10))
                .stroke(Stroke::new(1.0, Color32::from_rgb(48, 54, 61)))
                .show(ui, |ui| {
                    ui.heading(tr(
                        lang,
                        "\u{E2DE} Générateur de Clés SSH / PuTTYgen intégré",
                        "\u{E2DE} Built-in SSH / PuTTYgen Key Generator",
                    ));
                    ui.add_space(4.0);
                    ui.horizontal(|ui| {
                        ui.label(tr(lang, "Algorithme :", "Algorithm:"));
                        egui::ComboBox::from_id_salt("keygen_algo_cb")
                            .selected_text(&self.keygen_algo)
                            .show_ui(ui, |ui| {
                                ui.selectable_value(
                                    &mut self.keygen_algo,
                                    "ed25519".to_string(),
                                    tr(
                                        lang,
                                        "Ed25519 (Recommandé, rapide & sûr)",
                                        "Ed25519 (Recommended, fast & secure)",
                                    ),
                                );
                                ui.selectable_value(
                                    &mut self.keygen_algo,
                                    "ecdsa-p256".to_string(),
                                    "ECDSA NIST P-256",
                                );
                                ui.selectable_value(
                                    &mut self.keygen_algo,
                                    "rsa-2048".to_string(),
                                    "RSA 2048 bits",
                                );
                            });

                        ui.label(tr(lang, "Commentaire :", "Comment:"));
                        ui.text_edit_singleline(&mut self.keygen_comment);
                    });

                    ui.add_space(4.0);
                    ui.horizontal(|ui| {
                        if ui
                            .button(tr(
                                lang,
                                "\u{E6A2} Générer une nouvelle clé .PPK (PuTTY)",
                                "\u{E6A2} Generate New .PPK Key (PuTTY)",
                            ))
                            .clicked()
                        {
                            match generate_new_ssh_key(&self.keygen_algo, &self.keygen_comment) {
                                Ok(new_key) => {
                                    if let Ok(ppk_content) =
                                        export_to_ppk_v3(&new_key, &self.keygen_comment)
                                        && let Some(save_p) = rfd::FileDialog::new()
                                            .add_filter("PuTTY Private Key (.ppk)", &["ppk"])
                                            .set_file_name("id_cuty.ppk")
                                            .save_file()
                                    {
                                        let _ = std::fs::write(&save_p, &ppk_content);
                                        let pub_str = format_openssh_pubkey(new_key.public_key());
                                        let _ = std::fs::write(
                                            save_p.with_extension("pub"),
                                            &pub_str,
                                        );
                                        self.inspected_key = inspect_key_file(&save_p).ok();
                                        self.key_manager_status = format!(
                                            "{} {}",
                                            tr(
                                                lang,
                                                "Nouvelle clé .ppk générée et sauvegardée :",
                                                "New .ppk key generated and saved:"
                                            ),
                                            save_p.display()
                                        );
                                    }
                                }
                                Err(e) => {
                                    self.key_manager_status = format!(
                                        "{} {}",
                                        tr(lang, "Erreur génération :", "Generation error:"),
                                        e
                                    )
                                }
                            }
                        }
                    });
                });

            if !self.key_manager_status.is_empty() {
                ui.add_space(6.0);
                ui.label(
                    RichText::new(&self.key_manager_status)
                        .color(Color32::from_rgb(88, 166, 255)),
                );
            }
        });
        self.show_key_manager = open;
    }

    fn render_session_editor_modal(&mut self, ctx: &Context) {
        let lang = self.config.language;
        let mut open = self.show_session_editor;
        let title = if self.is_new_session {
            tr(
                lang,
                "\u{E3D4} Nouvelle Session (Configuration Avancée)",
                "\u{E3D4} New Session (Advanced Configuration)",
            )
        } else {
            tr(
                lang,
                "\u{E3B4} Configurer la Session",
                "\u{E3B4} Configure Session",
            )
        };

        egui::Window::new(title)
            .id(egui::Id::unique("session_editor_modal_v2"))
            .open(&mut open)
            .resizable(true)
            .default_size(Vec2::new(760.0, 620.0))
            .min_size(Vec2::new(600.0, 480.0))
            .show(ctx, |ui| {
                ui.horizontal(|ui| {
                    ui.selectable_value(
                        &mut self.editor_tab,
                        ConfigEditorTab::ConnectionAndKey,
                        tr(
                            lang,
                            "🔌 Connexion & Clé .PPK / Pageant",
                            "🔌 Connection & .PPK / Pageant Key",
                        ),
                    );
                    ui.selectable_value(
                        &mut self.editor_tab,
                        ConfigEditorTab::Automation,
                        tr(lang, "🤖 Automatisation", "🤖 Automation"),
                    );
                    ui.selectable_value(
                        &mut self.editor_tab,
                        ConfigEditorTab::PortForwards,
                        tr(lang, "🚇 Tunnels SSH", "🚇 SSH Tunnels"),
                    );
                    ui.selectable_value(
                        &mut self.editor_tab,
                        ConfigEditorTab::Appearance,
                        tr(
                            lang,
                            "\u{E6C8} Apparence & Options",
                            "\u{E6C8} Appearance & Options",
                        ),
                    );
                });
                ui.separator();

                match self.editor_tab {
                    ConfigEditorTab::ConnectionAndKey => {
                        egui::Grid::new("session_conn_grid")
                            .num_columns(2)
                            .spacing([10.0, 6.0])
                            .show(ui, |ui| {
                                ui.label(tr(lang, "Nom de la session :", "Session Name:"));
                                ui.text_edit_singleline(&mut self.editing_session.name);
                                ui.end_row();

                                ui.label(tr(lang, "Dossier (Groupe) :", "Folder (Group):"));
                                ui.horizontal(|ui| {
                                    ui.text_edit_singleline(&mut self.editing_session.folder);
                                    ui.label(tr(lang, "Icône:", "Icon:"));
                                    ui.add(
                                        egui::TextEdit::singleline(
                                            &mut self.editing_session.icon_badge,
                                        )
                                        .desired_width(36.0),
                                    );
                                });
                                ui.end_row();

                                ui.label(tr(lang, "Tags (Étiquettes) :", "Tags (Labels):"));
                                ui.vertical(|ui| {
                                    if !self.editing_session.tags.is_empty() {
                                        ui.horizontal_wrapped(|ui| {
                                            let mut tag_to_remove: Option<usize> = None;
                                            for (idx, tag) in
                                                self.editing_session.tags.iter().enumerate()
                                            {
                                                egui::Frame::NONE
                                                    .fill(Color32::from_rgb(26, 36, 52))
                                                    .corner_radius(egui::CornerRadius::same(3))
                                                    .inner_margin(egui::Margin::symmetric(5, 2))
                                                    .stroke(Stroke::new(
                                                        0.6,
                                                        Color32::from_rgb(56, 110, 190),
                                                    ))
                                                    .show(ui, |ui| {
                                                        ui.horizontal(|ui| {
                                                            ui.label(
                                                                RichText::new(format!("#{}", tag))
                                                                    .size(11.0)
                                                                    .color(Color32::from_rgb(
                                                                        165, 214, 255,
                                                                    )),
                                                            );
                                                            if ui.small_button("\u{E4F6}").clicked() {
                                                                tag_to_remove = Some(idx);
                                                            }
                                                        });
                                                    });
                                            }
                                            if let Some(idx) = tag_to_remove {
                                                self.editing_session.tags.remove(idx);
                                            }
                                        });
                                    }

                                    ui.horizontal(|ui| {
                                        let tag_resp = ui.add(
                                            egui::TextEdit::singleline(
                                                &mut self.session_tag_input,
                                            )
                                            .hint_text(tr(
                                                lang,
                                                "Nouveau tag (ex: prod, web, bdd)...",
                                                "New tag (e.g. prod, web, db)...",
                                            ))
                                            .desired_width(170.0),
                                        );
                                        let enter_pressed = tag_resp.lost_focus()
                                            && ui.input(|i| i.key_pressed(egui::Key::Enter));
                                        if (ui
                                            .button(tr(lang, "\u{E3D4} Ajouter", "\u{E3D4} Add"))
                                            .clicked()
                                            || enter_pressed)
                                            && !self.session_tag_input.trim().is_empty()
                                        {
                                            let clean = self
                                                .session_tag_input
                                                .trim()
                                                .trim_start_matches('#')
                                                .to_string();
                                            if !self
                                                .editing_session
                                                .tags
                                                .iter()
                                                .any(|t| t.eq_ignore_ascii_case(&clean))
                                            {
                                                self.editing_session.tags.push(clean);
                                            }
                                            self.session_tag_input.clear();
                                        }
                                    });

                                    let all_tags = self.config.all_tags();
                                    let unassigned: Vec<_> = all_tags
                                        .into_iter()
                                        .filter(|t| {
                                            !self
                                                .editing_session
                                                .tags
                                                .iter()
                                                .any(|st| st.eq_ignore_ascii_case(t))
                                        })
                                        .collect();
                                    if !unassigned.is_empty() {
                                        ui.horizontal_wrapped(|ui| {
                                            ui.label(
                                                RichText::new(tr(
                                                    lang,
                                                    "Existant :",
                                                    "Existing:",
                                                ))
                                                .small()
                                                .color(Color32::from_rgb(139, 148, 158)),
                                            );
                                            for t in unassigned.into_iter().take(6) {
                                                if ui.small_button(format!("+{}", t)).clicked() {
                                                    self.editing_session.tags.push(t);
                                                }
                                            }
                                        });
                                    }
                                });
                                ui.end_row();

                                ui.label(tr(lang, "Protocole :", "Protocol:"));
                                egui::ComboBox::from_id_salt("edit_proto_cb")
                                    .selected_text(self.editing_session.protocol.label())
                                    .show_ui(ui, |ui| {
                                        for p in [
                                            ProtocolType::Ssh,
                                            ProtocolType::Telnet,
                                            ProtocolType::RawTcp,
                                            ProtocolType::LocalShell,
                                        ] {
                                            if ui
                                                .selectable_value(
                                                    &mut self.editing_session.protocol,
                                                    p,
                                                    p.label(),
                                                )
                                                .clicked()
                                            {
                                                self.editing_session.port = p.default_port();
                                            }
                                        }
                                    });
                                ui.end_row();

                                if self.editing_session.protocol == ProtocolType::LocalShell {
                                    ui.label(tr(lang, "Commande Shell :", "Shell Command:"));
                                    ui.horizontal(|ui| {
                                        ui.text_edit_singleline(
                                            &mut self.editing_session.local_shell_cmd,
                                        );
                                        if ui.small_button("PowerShell").clicked() {
                                            self.editing_session.local_shell_cmd =
                                                "powershell.exe".to_string();
                                        }
                                        if ui.small_button("CMD").clicked() {
                                            self.editing_session.local_shell_cmd =
                                                "cmd.exe".to_string();
                                        }
                                        if ui.small_button("WSL").clicked() {
                                            self.editing_session.local_shell_cmd =
                                                "wsl.exe".to_string();
                                        }
                                    });
                                    ui.end_row();
                                } else {
                                    if self.editing_session.protocol == ProtocolType::Ssh {
                                        ui.label(tr(lang, "Passerelle Edge :", "Edge Gateway:"));
                                        ui.horizontal(|ui| {
                                            for preset in [
                                                EdgeGatewayPreset::None,
                                                EdgeGatewayPreset::ShellHub,
                                                EdgeGatewayPreset::Tailscale,
                                            ] {
                                                if ui
                                                    .selectable_value(
                                                        &mut self.editing_session.edge_preset,
                                                        preset,
                                                        preset.label(),
                                                    )
                                                    .clicked()
                                                {
                                                    match preset {
                                                        EdgeGatewayPreset::ShellHub => {
                                                            if self.editing_session.shellhub_server.trim().is_empty() {
                                                                self.editing_session.shellhub_server = "ssh.shellhub.io".to_string();
                                                            }
                                                            self.editing_session.host = self.editing_session.shellhub_server.clone();
                                                            self.editing_session.port = 22;
                                                        }
                                                        EdgeGatewayPreset::Tailscale => {
                                                            if !self.editing_session.host.ends_with(".ts.net") && !self.editing_session.host.contains('.') {
                                                                self.editing_session.host = format!("{}.ts.net", self.editing_session.host);
                                                            }
                                                            self.editing_session.port = 22;
                                                        }
                                                        EdgeGatewayPreset::None => {}
                                                    }
                                                }
                                            }
                                        });
                                        ui.end_row();

                                        if self.editing_session.edge_preset == EdgeGatewayPreset::ShellHub {
                                            ui.label(tr(lang, "Device ShellHub :", "ShellHub Device:"));
                                            ui.horizontal(|ui| {
                                                let dev_resp = ui.add(
                                                    egui::TextEdit::singleline(&mut self.editing_session.shellhub_device_id)
                                                        .hint_text("Device Name ou ID (ex: debian-edge-01)")
                                                        .desired_width(180.0),
                                                );
                                                ui.label(tr(lang, "Serveur :", "Server:"));
                                                let srv_resp = ui.add(
                                                    egui::TextEdit::singleline(&mut self.editing_session.shellhub_server)
                                                        .desired_width(140.0),
                                                );
                                                if dev_resp.changed() || srv_resp.changed() {
                                                    self.editing_session.host = self.editing_session.shellhub_server.clone();
                                                    let base_user = self.editing_session.username.split('@').next().unwrap_or("root");
                                                    if !self.editing_session.shellhub_device_id.trim().is_empty() {
                                                        self.editing_session.username = format!("{}@{}", base_user, self.editing_session.shellhub_device_id.trim());
                                                    }
                                                }
                                            });
                                            ui.end_row();
                                        }
                                    }

                                    ui.label(tr(lang, "Hôte / Adresse IP :", "Host / IP Address:"));
                                    ui.text_edit_singleline(&mut self.editing_session.host);
                                    ui.end_row();

                                    ui.label(tr(lang, "Port :", "Port:"));
                                    ui.add(
                                        egui::DragValue::new(&mut self.editing_session.port)
                                            .range(1..=65535),
                                    );
                                    ui.end_row();

                                    ui.label(tr(lang, "Utilisateur :", "Username:"));
                                    ui.text_edit_singleline(&mut self.editing_session.username);
                                    ui.end_row();

                                    ui.label(tr(lang, "Mot de passe (Auto) :", "Password (Auto):"));
                                    ui.add(
                                        egui::TextEdit::singleline(
                                            &mut self.editing_session.password,
                                        )
                                        .password(true)
                                        .hint_text(tr(
                                            lang,
                                            "Optionnel (Mot de passe automatique)",
                                            "Optional (Auto-login password)",
                                        )),
                                    );
                                    ui.end_row();
                                }
                            });

                        if self.editing_session.protocol == ProtocolType::Ssh {
                            ui.add_space(8.0);
                            ui.separator();
                            ui.horizontal(|ui| {
                                ui.label(
                                    RichText::new(tr(
                                        lang,
                                        "\u{E89C} Bastion / Jump Host SSH (-J / ProxyJump)",
                                        "\u{E89C} SSH Bastion / Jump Host (-J / ProxyJump)",
                                    ))
                                    .strong(),
                                );
                                if ui
                                    .small_button(tr(
                                        lang,
                                        "\u{E0E6} Comment ça marche ?",
                                        "\u{E0E6} How does it work?",
                                    ))
                                    .clicked()
                                {
                                    self.help_topic = HelpTopic::Bastion;
                                    self.show_help = true;
                                }
                            });
                            egui::Grid::new("jump_host_grid")
                                .num_columns(2)
                                .spacing([8.0, 4.0])
                                .show(ui, |ui| {
                                    ui.label(tr(lang, "Session Bastion :", "Bastion Session:"));
                                    let current_jump_name = self
                                        .editing_session
                                        .jump_host_id
                                        .and_then(|jid| {
                                            self.config
                                                .sessions
                                                .iter()
                                                .find(|s| s.id == jid)
                                                .map(|s| format!("{} ({})", s.name, s.host))
                                        })
                                        .unwrap_or_else(|| {
                                            tr(
                                                lang,
                                                "Aucun (Connexion directe)",
                                                "None (Direct connection)",
                                            )
                                            .to_string()
                                        });

                                    egui::ComboBox::from_id_salt("jump_host_combo")
                                        .selected_text(current_jump_name)
                                        .width(280.0)
                                        .show_ui(ui, |ui| {
                                            ui.selectable_value(
                                                &mut self.editing_session.jump_host_id,
                                                None,
                                                tr(
                                                    lang,
                                                    "Aucun (Connexion directe)",
                                                    "None (Direct connection)",
                                                ),
                                            );
                                            for s in &self.config.sessions {
                                                if s.protocol == ProtocolType::Ssh
                                                    && s.id != self.editing_session.id
                                                {
                                                    ui.selectable_value(
                                                        &mut self.editing_session.jump_host_id,
                                                        Some(s.id),
                                                        format!(
                                                            "{} ({}:{})",
                                                            s.name, s.host, s.port
                                                        ),
                                                    );
                                                }
                                            }
                                        });
                                    ui.end_row();

                                    ui.label(tr(lang, "ProxyJump inline :", "Inline ProxyJump:"));
                                    ui.add(
                                        egui::TextEdit::singleline(
                                            &mut self.editing_session.proxy_jump,
                                        )
                                        .hint_text(tr(
                                            lang,
                                            "Optionnel ex: admin@bastion.corp:22",
                                            "Optional e.g. admin@bastion.corp:22",
                                        )),
                                    );
                                    ui.end_row();
                                });

                            ui.add_space(6.0);
                            ui.separator();
                            ui.label(
                                RichText::new(tr(
                                    lang,
                                    "\u{E2D6} Authentification SSH2, Clé PuTTY (.ppk), Pageant & OpenSSH Agent",
                                    "\u{E2D6} SSH2 Authentication, PuTTY Key (.ppk), Pageant & OpenSSH Agent",
                                ))
                                .strong(),
                            );
                            ui.checkbox(
                                &mut self.editing_session.try_pageant,
                                tr(
                                    lang,
                                    "Tenter automatiquement l'authentification via Pageant & Windows OpenSSH Agent",
                                    "Automatically try authentication via Pageant & Windows OpenSSH Agent",
                                ),
                            );
                            ui.checkbox(
                                &mut self.editing_session.agent_forwarding,
                                tr(
                                    lang,
                                    "Activer le transfert d'agent SSH (Agent Forwarding)",
                                    "Enable SSH Agent Forwarding",
                                ),
                            );

                            let is_ppk_mode = matches!(
                                self.editing_session.ssh_auth,
                                SshAuthMethod::PrivateKeyFile { .. }
                            );
                            let is_agent_mode = matches!(
                                self.editing_session.ssh_auth,
                                SshAuthMethod::Agent { .. }
                            );
                            let is_kbi_mode = matches!(
                                self.editing_session.ssh_auth,
                                SshAuthMethod::KeyboardInteractive
                            );

                            ui.horizontal(|ui| {
                                if ui
                                    .selectable_label(
                                        !is_ppk_mode && !is_agent_mode && !is_kbi_mode,
                                        tr(lang, "Mot de passe", "Password"),
                                    )
                                    .clicked()
                                {
                                    self.editing_session.ssh_auth = SshAuthMethod::Password;
                                }
                                if ui
                                    .selectable_label(
                                        is_ppk_mode,
                                        tr(
                                            lang,
                                            "Fichier Clé (.ppk / OpenSSH)",
                                            "Key File (.ppk / OpenSSH)",
                                        ),
                                    )
                                    .clicked()
                                {
                                    self.editing_session.ssh_auth = SshAuthMethod::PrivateKeyFile {
                                        key_path: String::new(),
                                        passphrase: String::new(),
                                        cert_path: String::new(),
                                    };
                                }
                                if ui
                                    .selectable_label(
                                        is_agent_mode,
                                        tr(
                                            lang,
                                            "Agent Pageant / OpenSSH",
                                            "Pageant / OpenSSH Agent",
                                        ),
                                    )
                                    .clicked()
                                {
                                    self.editing_session.ssh_auth = SshAuthMethod::Agent {
                                        use_pageant: true,
                                        use_openssh_agent: true,
                                    };
                                }
                                if ui
                                    .selectable_label(is_kbi_mode, "Keyboard-Interactive (2FA)")
                                    .clicked()
                                {
                                    self.editing_session.ssh_auth =
                                        SshAuthMethod::KeyboardInteractive;
                                }
                            });

                            if !is_ppk_mode && !is_agent_mode && !is_kbi_mode {
                                ui.add_space(4.0);
                                egui::Frame::NONE
                                    .fill(Color32::from_rgb(18, 30, 24))
                                    .corner_radius(6.0)
                                    .inner_margin(egui::Margin::symmetric(8, 6))
                                    .stroke(Stroke::new(1.0, Color32::from_rgb(46, 160, 67)))
                                    .show(ui, |ui| {
                                        ui.checkbox(
                                            &mut self.editing_session.deploy_primary_key_on_connect,
                                            RichText::new(tr(
                                                lang,
                                                "\u{E2D6}\u{E06C}\u{E560} Copier ma Clé Principale à la 1re connexion (ssh-copy-id) puis ne plus utiliser le mot de passe",
                                                "\u{E2D6}\u{E06C}\u{E560} Copy my Primary Key on 1st login (ssh-copy-id) and switch to passwordless key auth",
                                            ))
                                            .strong()
                                            .color(Color32::from_rgb(86, 211, 100)),
                                        );
                                    });
                            }

                            let mut use_primary_key_clicked = false;
                            if let SshAuthMethod::PrivateKeyFile {
                                key_path,
                                passphrase,
                                cert_path,
                            } = &mut self.editing_session.ssh_auth
                            {
                                egui::Grid::new("ppk_auth_grid")
                                    .num_columns(2)
                                    .spacing([8.0, 4.0])
                                    .show(ui, |ui| {
                                        ui.label(tr(
                                            lang,
                                            "Fichier clé (.ppk / SSH) :",
                                            "Key File (.ppk / SSH):",
                                        ));
                                        ui.horizontal(|ui| {
                                            ui.text_edit_singleline(key_path);
                                            if ui
                                                .button(tr(
                                                    lang,
                                                    "\u{E256} Choisir .ppk",
                                                    "\u{E256} Choose .ppk",
                                                ))
                                                .clicked()
                                                && let Some(p) = rfd::FileDialog::new()
                                                    .add_filter(
                                                        "PuTTY (.ppk) & SSH Keys",
                                                        &["ppk", "pem", "key", "*"],
                                                    )
                                                    .pick_file()
                                            {
                                                *key_path = p.to_string_lossy().to_string();
                                            }
                                            if ui
                                                .button(
                                                    RichText::new(tr(
                                                        lang,
                                                        "\u{E46A} Ma Clé Principale",
                                                        "\u{E46A} My Primary Key",
                                                    ))
                                                    .color(Color32::from_rgb(86, 211, 100)),
                                                )
                                                .clicked()
                                            {
                                                use_primary_key_clicked = true;
                                            }
                                        });
                                        ui.end_row();

                                        ui.label(tr(lang, "Passphrase clé :", "Key Passphrase:"));
                                        ui.add(
                                            egui::TextEdit::singleline(passphrase)
                                                .password(true)
                                                .hint_text(tr(
                                                    lang,
                                                    "Laisser vide pour demander à la connexion",
                                                    "Leave blank to prompt on connect",
                                                )),
                                        );
                                        ui.end_row();

                                        ui.label(tr(
                                            lang,
                                            "Certificat OpenSSH :",
                                            "OpenSSH Certificate:",
                                        ));
                                        ui.add(
                                            egui::TextEdit::singleline(cert_path).hint_text(tr(
                                                lang,
                                                "Optionnel (-cert.pub)",
                                                "Optional (-cert.pub)",
                                            )),
                                        );
                                        ui.end_row();
                                    });
                            }
                            if use_primary_key_clicked
                                && let Ok((p, _, created)) =
                                    resolve_or_create_primary_key(&self.config.primary_key_path)
                            {
                                let p_str = p.to_string_lossy().to_string();
                                if self.config.primary_key_path.trim().is_empty() || created {
                                    self.config.primary_key_path = p_str.clone();
                                    let _ = self.config.save();
                                }
                                if let SshAuthMethod::PrivateKeyFile { key_path, .. } =
                                    &mut self.editing_session.ssh_auth
                                {
                                    *key_path = p_str;
                                }
                            }
                        }
                    }

                    ConfigEditorTab::Automation => {
                        ui.label(
                            RichText::new(tr(
                                lang,
                                "🤖 Automatisation de Connexion",
                                "🤖 Connection Automation",
                            ))
                            .strong(),
                        );
                        ui.checkbox(
                            &mut self.editing_session.auto_login,
                            tr(
                                lang,
                                "Envoyer automatiquement le nom d'utilisateur",
                                "Automatically send username",
                            ),
                        );
                        ui.checkbox(
                            &mut self.editing_session.auto_password,
                            tr(
                                lang,
                                "Envoyer automatiquement le mot de passe",
                                "Automatically send password",
                            ),
                        );

                        ui.add_space(6.0);
                        ui.label(tr(
                            lang,
                            "Commande automatique à l'ouverture de session :",
                            "Startup command on session connect:",
                        ));
                        ui.text_edit_singleline(&mut self.editing_session.startup_command);

                        ui.add_space(6.0);
                        ui.label(tr(
                            lang,
                            "Exécuter un script local sur la session distante :",
                            "Execute a local script on the remote session:",
                        ));
                        ui.horizontal(|ui| {
                            ui.text_edit_singleline(&mut self.editing_session.local_script_path);
                            if ui
                                .button(tr(lang, "\u{E256} Choisir script", "\u{E256} Choose Script"))
                                .clicked()
                                && let Some(p) = rfd::FileDialog::new().pick_file()
                            {
                                self.editing_session.local_script_path =
                                    p.to_string_lossy().to_string();
                            }
                        });

                        ui.add_space(8.0);
                        ui.horizontal(|ui| {
                            ui.label(tr(
                                lang,
                                "Intervalle Keepalive / Anti-Idle (sec) :",
                                "Keepalive / Anti-Idle Interval (sec):",
                            ));
                            ui.add(
                                egui::DragValue::new(&mut self.editing_session.keepalive_secs)
                                    .range(0..=600),
                            );
                            ui.label(tr(lang, "Chaîne Anti-Idle :", "Anti-Idle String:"));
                            ui.text_edit_singleline(&mut self.editing_session.anti_idle_string);
                        });
                        ui.checkbox(
                            &mut self.editing_session.auto_reconnect,
                            tr(
                                lang,
                                "\u{E094} Reconnexion automatique si la connexion tombe",
                                "\u{E094} Reconnect automatically if the connection drops",
                            ),
                        );

                        ui.separator();
                        ui.label(
                            RichText::new(tr(
                                lang,
                                "Règles Expect / Logon Script (attendre un texte puis répondre) :",
                                "Expect / Logon Script Rules (wait for prompt then send response):",
                            ))
                            .strong(),
                        );
                        ui.horizontal(|ui| {
                            ui.label(tr(lang, "Si reçu:", "If received:"));
                            ui.add(
                                egui::TextEdit::singleline(&mut self.new_expect_trigger)
                                    .desired_width(130.0),
                            );
                            ui.label(tr(lang, "Envoyer:", "Send:"));
                            ui.add(
                                egui::TextEdit::singleline(&mut self.new_expect_response)
                                    .desired_width(130.0),
                            );
                            if ui
                                .button(tr(lang, "\u{E3D4} Ajouter règle", "\u{E3D4} Add Rule"))
                                .clicked()
                                && !self.new_expect_trigger.is_empty()
                            {
                                self.editing_session.logon_expect_rules.push(ExpectRule {
                                    enabled: true,
                                    trigger_prompt: self.new_expect_trigger.clone(),
                                    send_response: self.new_expect_response.clone(),
                                    delay_ms: 200,
                                });
                                self.new_expect_trigger.clear();
                                self.new_expect_response.clear();
                            }
                        });

                        let mut remove_rule: Option<usize> = None;
                        for (idx, r) in self
                            .editing_session
                            .logon_expect_rules
                            .iter_mut()
                            .enumerate()
                        {
                            ui.horizontal(|ui| {
                                ui.checkbox(&mut r.enabled, "");
                                ui.monospace(format!(
                                    "{} \"{}\" \u{E06C} {} \"{}\"",
                                    tr(lang, "Attendre", "Expect"),
                                    r.trigger_prompt,
                                    tr(lang, "Envoyer", "Send"),
                                    r.send_response
                                ));
                                if ui.small_button("\u{E4A6}").clicked() {
                                    remove_rule = Some(idx);
                                }
                            });
                        }
                        if let Some(i) = remove_rule {
                            self.editing_session.logon_expect_rules.remove(i);
                        }
                    }

                    ConfigEditorTab::PortForwards => {
                        ui.label(
                            RichText::new(tr(
                                lang,
                                "🚇 Redirection de Ports SSH (Local -L / Remote -R)",
                                "🚇 SSH Port Forwarding (Local -L / Remote -R)",
                            ))
                            .strong(),
                        );
                        ui.horizontal(|ui| {
                            ui.checkbox(
                                &mut self.new_pf_is_remote,
                                tr(lang, "Distant (-R)", "Remote (-R)"),
                            );
                            ui.checkbox(&mut self.new_pf_is_dynamic, "SOCKS5 (-D)");
                            ui.label("Bind:");
                            ui.add(
                                egui::TextEdit::singleline(&mut self.new_pf_bind_addr)
                                    .desired_width(90.0),
                            );
                            ui.add(
                                egui::DragValue::new(&mut self.new_pf_bind_port).range(1..=65535),
                            );
                            ui.label(tr(lang, "\u{E06C} Cible:", "\u{E06C} Target:"));
                            ui.add(
                                egui::TextEdit::singleline(&mut self.new_pf_target_host)
                                    .desired_width(90.0),
                            );
                            ui.add(
                                egui::DragValue::new(&mut self.new_pf_target_port).range(1..=65535),
                            );
                            if ui.button(tr(lang, "\u{E3D4} Ajouter", "\u{E3D4} Add")).clicked() {
                                self.editing_session.port_forwards.push(PortForwardRule {
                                    enabled: true,
                                    forward_type: if self.new_pf_is_dynamic {
                                        PortForwardType::Dynamic
                                    } else if self.new_pf_is_remote {
                                        PortForwardType::Remote
                                    } else {
                                        PortForwardType::Local
                                    },
                                    bind_address: self.new_pf_bind_addr.clone(),
                                    bind_port: self.new_pf_bind_port,
                                    target_host: self.new_pf_target_host.clone(),
                                    target_port: self.new_pf_target_port,
                                });
                            }
                        });

                        ui.separator();
                        let mut rem_pf: Option<usize> = None;
                        for (idx, pf) in self.editing_session.port_forwards.iter_mut().enumerate() {
                            ui.horizontal(|ui| {
                                ui.checkbox(&mut pf.enabled, "");
                                let badge = match pf.forward_type {
                                    PortForwardType::Local => "Local (-L)",
                                    PortForwardType::Remote => "Remote (-R)",
                                    PortForwardType::Dynamic => "SOCKS5 (-D)",
                                };
                                ui.monospace(format!(
                                    "[{}] {}:{} \u{E06C} {}:{}",
                                    badge,
                                    pf.bind_address,
                                    pf.bind_port,
                                    pf.target_host,
                                    pf.target_port
                                ));
                                if ui.small_button("\u{E4A6}").clicked() {
                                    rem_pf = Some(idx);
                                }
                            });
                        }
                        if let Some(i) = rem_pf {
                            self.editing_session.port_forwards.remove(i);
                        }
                    }

                    ConfigEditorTab::Appearance => {
                        egui::Grid::new("appearance_grid")
                            .num_columns(2)
                            .spacing([10.0, 6.0])
                            .show(ui, |ui| {
                                ui.label(tr(
                                    lang,
                                    "\u{E288} Langue de l'application :",
                                    "\u{E288} Application Language:",
                                ));
                                ui.horizontal(|ui| {
                                    if ui
                                        .selectable_value(
                                            &mut self.config.language,
                                            UiLanguage::French,
                                            "🇫🇷 Français",
                                        )
                                        .clicked()
                                    {
                                        let _ = self.config.save();
                                    }
                                    if ui
                                        .selectable_value(
                                            &mut self.config.language,
                                            UiLanguage::English,
                                            "🇬🇧 English",
                                        )
                                        .clicked()
                                    {
                                        let _ = self.config.save();
                                    }
                                });
                                ui.end_row();

                                ui.label(tr(lang, "Thème de couleurs :", "Color Theme:"));
                                egui::ComboBox::from_id_salt("theme_cb")
                                    .selected_text(&self.editing_session.theme_name)
                                    .show_ui(ui, |ui| {
                                        for &t in TerminalTheme::all_themes() {
                                            ui.selectable_value(
                                                &mut self.editing_session.theme_name,
                                                t.to_string(),
                                                t,
                                            );
                                        }
                                    });
                                ui.end_row();

                                ui.label(tr(lang, "Taille de police :", "Font Size:"));
                                ui.add(
                                    egui::Slider::new(
                                        &mut self.editing_session.font_size,
                                        10.0..=24.0,
                                    )
                                    .suffix(" px"),
                                );
                                ui.end_row();

                                ui.label(tr(lang, "Lignes d'historique :", "Scrollback Lines:"));
                                ui.add(
                                    egui::DragValue::new(
                                        &mut self.editing_session.scrollback_lines,
                                    )
                                    .range(500..=100_000),
                                );
                                ui.end_row();
                            });

                        ui.checkbox(
                            &mut self.editing_session.log_to_file,
                            tr(
                                lang,
                                "Enregistrer automatiquement les logs de la session dans cuty-ssh-portable/logs/",
                                "Automatically record session logs to cuty-ssh-portable/logs/",
                            ),
                        );
                        ui.checkbox(
                            &mut self.editing_session.read_only,
                            tr(
                                lang,
                                "Démarrer avec la protection clavier activée (lecture seule)",
                                "Start with keyboard protection enabled (read-only mode)",
                            ),
                        );
                    }
                }

                ui.add_space(10.0);
                ui.separator();
                ui.horizontal_wrapped(|ui| {
                    if ui
                        .button(
                            RichText::new(tr(lang, "\u{E248} Sauvegarder", "\u{E248} Save"))
                                .strong()
                                .color(Color32::from_rgb(63, 185, 80)),
                        )
                        .clicked()
                    {
                        self.save_editing_session();
                        self.show_session_editor = false;
                    }

                    if ui
                        .button(
                            RichText::new(tr(
                                lang,
                                "\u{E3FE} Sauvegarder & Connecter",
                                "\u{E3FE} Save & Connect",
                            ))
                            .strong()
                            .color(Color32::from_rgb(88, 166, 255)),
                        )
                        .clicked()
                    {
                        self.save_editing_session();
                        let s = self.editing_session.clone();
                        self.show_session_editor = false;
                        self.launch_session(s);
                    }

                    if self.editing_session.protocol == ProtocolType::Ssh
                        && ui
                            .button(
                                RichText::new(tr(
                                    lang,
                                    "\u{E2D6}\u{E06C}\u{E560} Connecter (Mdp) & Copier ma Clé Principale (ssh-copy-id)",
                                    "\u{E2D6}\u{E06C}\u{E560} Connect (Pwd) & Push Primary Key (ssh-copy-id)",
                                ))
                                .strong()
                                .color(Color32::from_rgb(86, 211, 100)),
                            )
                            .on_hover_text(tr(
                                lang,
                                "Se connecte une 1re fois avec le mot de passe, copie automatiquement votre Clé Publique Principale dans ~/.ssh/authorized_keys, puis bascule la session sur votre clé (sans mot de passe)",
                                "Connects once using the password, automatically installs your Primary Public Key into ~/.ssh/authorized_keys, and switches the session to passwordless key authentication",
                            ))
                            .clicked()
                    {
                        self.editing_session.ssh_auth = SshAuthMethod::Password;
                        self.editing_session.deploy_primary_key_on_connect = true;
                        self.save_editing_session();
                        let s = self.editing_session.clone();
                        self.show_session_editor = false;
                        self.launch_session(s);
                    }
                });
            });

        if !open {
            self.show_session_editor = false;
        }
    }

    fn save_editing_session(&mut self) {
        if self.editing_session.protocol != ProtocolType::LocalShell {
            let (user, clean_host) =
                split_user_and_host(&self.editing_session.host, &self.editing_session.username);
            self.editing_session.username = user;
            self.editing_session.host = clean_host;
        }
        if self.is_new_session {
            self.config.sessions.push(self.editing_session.clone());
        } else if let Some(existing) = self
            .config
            .sessions
            .iter_mut()
            .find(|s| s.id == self.editing_session.id)
        {
            *existing = self.editing_session.clone();
        }
        let _ = self.config.save();
    }

    fn render_commands_editor_modal(&mut self, ctx: &Context) {
        let lang = self.config.language;
        let mut open = self.show_commands_editor;
        egui::Window::new(tr(
            lang,
            "\u{E2DE} Raccourcis de Commandes Prédéfinies",
            "\u{E2DE} Predefined Command Macros",
        ))
        .open(&mut open)
        .resizable(true)
        .default_width(520.0)
        .show(ctx, |ui| {
            ui.horizontal(|ui| {
                ui.label(tr(lang, "Bouton:", "Label:"));
                ui.add(egui::TextEdit::singleline(&mut self.new_cmd_label).desired_width(110.0));
                ui.label(tr(lang, "Commande:", "Command:"));
                ui.add(egui::TextEdit::singleline(&mut self.new_cmd_text).desired_width(200.0));
                if ui
                    .button(tr(lang, "\u{E3D4} Ajouter", "\u{E3D4} Add"))
                    .clicked()
                    && !self.new_cmd_label.is_empty()
                    && !self.new_cmd_text.is_empty()
                {
                    self.config.predefined_commands.push(PredefinedCommand {
                        id: Uuid::new_v4(),
                        label: self.new_cmd_label.clone(),
                        category: self.new_cmd_category.clone(),
                        command: self.new_cmd_text.clone(),
                        append_enter: true,
                        description: self.new_cmd_text.clone(),
                    });
                    self.new_cmd_label.clear();
                    self.new_cmd_text.clear();
                    let _ = self.config.save();
                }
            });

            ui.separator();
            let mut del_id: Option<Uuid> = None;
            for cmd in &self.config.predefined_commands {
                ui.horizontal(|ui| {
                    ui.strong(&cmd.label);
                    ui.monospace(&cmd.command);
                    if ui.small_button("\u{E4A6}").clicked() {
                        del_id = Some(cmd.id);
                    }
                });
            }
            if let Some(id) = del_id {
                self.config.predefined_commands.retain(|c| c.id != id);
                let _ = self.config.save();
            }
        });
        self.show_commands_editor = open;
    }

    fn render_pending_secret_modal(&mut self, ctx: &Context) {
        let lang = self.config.language;
        let Some(tab) = self.tabs.get_mut(self.active_tab_idx) else {
            return;
        };
        let Some(prompt) = &mut tab.pending_prompt else {
            return;
        };

        let mut submit = false;
        let mut cancel = false;

        egui::Window::new(&prompt.title)
            .collapsible(false)
            .resizable(false)
            .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
            .show(ctx, |ui| {
                ui.label(&prompt.prompt);
                ui.add_space(6.0);
                let resp = ui.add(
                    egui::TextEdit::singleline(&mut prompt.input_value)
                        .password(prompt.is_passphrase)
                        .desired_width(320.0),
                );
                // `lost_focus()` is evaluated live from the focus state: it must be read before
                // `request_focus()` hands the focus back, otherwise Enter is never detected.
                if resp.lost_focus() && ui.input(|i| i.key_pressed(Key::Enter)) {
                    submit = true;
                } else {
                    resp.request_focus();
                }
                ui.add_space(8.0);
                ui.horizontal(|ui| {
                    if ui
                        .button(tr(lang, "\u{E182} Valider", "\u{E182} Submit"))
                        .clicked()
                    {
                        submit = true;
                    }
                    if ui
                        .button(tr(lang, "\u{E4F6} Annuler", "\u{E4F6} Cancel"))
                        .clicked()
                    {
                        cancel = true;
                    }
                });
            });

        if submit {
            if let Some(p) = tab.pending_prompt.take() {
                let _ = tab
                    .handle
                    .cmd_tx
                    .send(BackendCommand::ProvideSecret(p.input_value));
            }
        } else if cancel {
            tab.pending_prompt = None;
            let _ = tab.handle.cmd_tx.send(BackendCommand::Disconnect);
        }
    }

    fn render_command_palette_modal(&mut self, ctx: &Context) {
        let lang = self.config.language;
        let mut open = self.show_command_palette;
        let mut launch_target: Option<SessionProfile> = None;
        let mut action_to_run: Option<PaletteAction> = None;

        egui::Window::new(tr(
            lang,
            "\u{E47C} Palette de Commandes & Sessions (Ctrl+K)",
            "\u{E47C} Command & Session Palette (Ctrl+K)",
        ))
        .open(&mut open)
        .resizable(false)
        .collapsible(false)
        .default_width(560.0)
        .anchor(egui::Align2::CENTER_CENTER, [0.0, -80.0])
        .frame(
            egui::Frame::NONE
                .fill(Color32::from_rgb(18, 22, 29))
                .corner_radius(egui::CornerRadius::same(8))
                .inner_margin(egui::Margin::same(12))
                .stroke(Stroke::new(1.0, Color32::from_rgb(48, 54, 61))),
        )
        .show(ctx, |ui| {
            ui.horizontal(|ui| {
                ui.label(RichText::new("\u{E30C}").size(16.0));
                let resp = ui.add(
                    egui::TextEdit::singleline(&mut self.palette_query)
                        .hint_text(tr(
                            lang,
                            "Filtrer sessions, commandes ou outils réseau...",
                            "Filter sessions, commands, or network tools...",
                        ))
                        .desired_width(f32::INFINITY),
                );
                resp.request_focus();
            });
            ui.add_space(4.0);
            ui.separator();
            ui.add_space(4.0);

            let q = self.palette_query.to_lowercase();

            egui::ScrollArea::vertical()
                .max_height(360.0)
                .show(ui, |ui| {
                    // Section 1: Sessions
                    let matching_sessions: Vec<_> = self
                        .config
                        .sessions
                        .iter()
                        .filter(|s| {
                            q.is_empty()
                                || s.name.to_lowercase().contains(&q)
                                || s.host.to_lowercase().contains(&q)
                                || s.folder.to_lowercase().contains(&q)
                                || s.tags.iter().any(|t| {
                                    let tag_lower = t.to_lowercase();
                                    tag_lower.contains(&q)
                                        || q.trim_start_matches('#').contains(&tag_lower)
                                })
                        })
                        .collect();

                    if !matching_sessions.is_empty() {
                        ui.label(
                            RichText::new("\u{E560} SESSIONS")
                                .size(11.0)
                                .strong()
                                .color(Color32::from_rgb(139, 148, 158)),
                        );
                        for s in matching_sessions {
                            let (badge, color) = protocol_badge_style(s.protocol);
                            let probe = self.session_probes.get(&s.id);
                            ui.horizontal(|ui| {
                                let btn_txt = format!("{} {}", s.icon_badge, s.name);
                                if ui
                                    .button(
                                        RichText::new(btn_txt)
                                            .color(Color32::from_rgb(230, 237, 243)),
                                    )
                                    .clicked()
                                {
                                    launch_target = Some(s.clone());
                                }
                                let sub = if s.protocol == ProtocolType::LocalShell {
                                    s.local_shell_cmd.clone()
                                } else {
                                    format!("{}:{}", s.host, s.port)
                                };
                                ui.label(
                                    RichText::new(sub)
                                        .monospace()
                                        .size(10.5)
                                        .color(Color32::from_rgb(110, 118, 129)),
                                );

                                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                                    ui.label(
                                        RichText::new(badge)
                                            .size(10.0)
                                            .monospace()
                                            .strong()
                                            .color(color),
                                    );
                                    if let Some(p) = probe {
                                        let (txt, col) = if p.reachable {
                                            (
                                                format!("● {}ms", p.latency_ms),
                                                Color32::from_rgb(63, 185, 80),
                                            )
                                        } else {
                                            ("● Off".to_string(), Color32::from_rgb(248, 81, 73))
                                        };
                                        ui.label(
                                            RichText::new(txt)
                                                .size(10.0)
                                                .monospace()
                                                .color(col),
                                        );
                                    }
                                    if !s.tags.is_empty() {
                                        for t in s.tags.iter().take(2) {
                                            ui.label(
                                                RichText::new(format!("#{t}"))
                                                    .size(9.5)
                                                    .color(Color32::from_rgb(88, 166, 255)),
                                            );
                                        }
                                    }
                                });
                            });
                        }
                        ui.add_space(8.0);
                    }

                    // Section 2: Actions & Tools
                    ui.label(
                        RichText::new(tr(lang, "\u{E2DE} ACTIONS & OUTILS", "\u{E2DE} ACTIONS & TOOLS"))
                            .size(11.0)
                            .strong()
                            .color(Color32::from_rgb(139, 148, 158)),
                    );

                    let actions = [
                        (
                            tr(lang, "\u{E3D4} Nouvelle Session", "\u{E3D4} New Session"),
                            tr(
                                lang,
                                "Créer une nouvelle configuration de connexion",
                                "Create a new connection profile",
                            ),
                            PaletteAction::NewSession,
                        ),
                        (
                            tr(
                                lang,
                                "\u{E0E6} Guide Utilisateur & Documentation",
                                "\u{E0E6} User Guide & Documentation",
                            ),
                            tr(
                                lang,
                                "Tutoriels illustrés : Bastion SSH (-J), Tags, Clés .ppk, TOFU & SFTP",
                                "Illustrated tutorials: SSH Bastion (-J), Tags, .ppk Keys, TOFU & SFTP",
                            ),
                            PaletteAction::OpenHelp,
                        ),
                        (
                            tr(
                                lang,
                                "\u{E2D6} Clés PuTTY (.ppk) & Pageant",
                                "\u{E2D6} PuTTY Keys (.ppk) & Pageant",
                            ),
                            tr(
                                lang,
                                "Inspecter, convertir et charger les clés .ppk dans Pageant",
                                "Inspect, convert, and load .ppk keys into Pageant",
                            ),
                            PaletteAction::OpenKeyManager,
                        ),
                        (
                            tr(
                                lang,
                                "\u{E20C} Charger toutes les clés .ppk dans Pageant",
                                "\u{E20C} Load All .ppk Keys into Pageant",
                            ),
                            tr(
                                lang,
                                "Transmettre en 1 clic toutes les clés de vos sessions à Pageant.exe",
                                "Send all keys configured in your sessions to Pageant.exe in 1 click",
                            ),
                            PaletteAction::LoadAllPpksToPageant,
                        ),
                        (
                            tr(
                                lang,
                                "\u{E5D4} Boîte à Outils Réseau & CIDR",
                                "\u{E5D4} Network & CIDR Toolkit",
                            ),
                            tr(
                                lang,
                                "Scanner TCP, bannière SSH, santé des serveurs et calculateur CIDR",
                                "TCP scanner, SSH banner grabber, server health, and CIDR calculator",
                            ),
                            PaletteAction::OpenNetworkTools,
                        ),
                        (
                            tr(
                                lang,
                                "\u{E6C8} Design System & À Propos",
                                "\u{E6C8} Design System & About",
                            ),
                            tr(
                                lang,
                                "Afficher les maquettes graphiques, le logo cyber-cat et la bannière hero",
                                "View UI badges, cyber-cat logo, and hero banner",
                            ),
                            PaletteAction::OpenAbout,
                        ),
                        (
                            tr(
                                lang,
                                "\u{E2DE} Ouvrir PowerShell Local",
                                "\u{E2DE} Open Local PowerShell",
                            ),
                            tr(
                                lang,
                                "Lancer une invite de commandes Windows ConPTY",
                                "Launch a local Windows ConPTY shell",
                            ),
                            PaletteAction::LaunchPowershell,
                        ),
                        (
                            tr(
                                lang,
                                "\u{E0F2} Tester la Santé de tous les Serveurs",
                                "\u{E0F2} Probe All Server Health",
                            ),
                            tr(
                                lang,
                                "Vérifier la joignabilité et la latence TCP en tâche de fond",
                                "Check reachability and TCP latency in the background",
                            ),
                            PaletteAction::ProbeAll,
                        ),
                        (
                            tr(
                                lang,
                                "\u{EB7A} Dupliquer l'Onglet Actif",
                                "\u{EB7A} Duplicate Active Tab",
                            ),
                            tr(
                                lang,
                                "Ouvrir une session identique dans un nouvel onglet",
                                "Open an identical session in a new tab",
                            ),
                            PaletteAction::DuplicateActiveTab,
                        ),
                        (
                            tr(lang, "\u{E4F6} Fermer l'Onglet Actif", "\u{E4F6} Close Active Tab"),
                            tr(
                                lang,
                                "Déconnecter et fermer l'onglet sélectionné",
                                "Disconnect and close the active tab",
                            ),
                            PaletteAction::CloseActiveTab,
                        ),
                    ];

                    for (title, desc, act) in actions {
                        if q.is_empty()
                            || title.to_lowercase().contains(&q)
                            || desc.to_lowercase().contains(&q)
                        {
                            ui.horizontal(|ui| {
                                if ui
                                    .button(
                                        RichText::new(title)
                                            .strong()
                                            .color(Color32::from_rgb(88, 166, 255)),
                                    )
                                    .clicked()
                                {
                                    action_to_run = Some(act);
                                }
                                ui.label(
                                    RichText::new(desc)
                                        .size(11.0)
                                        .color(Color32::from_rgb(139, 148, 158)),
                                );
                            });
                        }
                    }
                });
        });

        self.show_command_palette = open;

        if let Some(s) = launch_target {
            self.show_command_palette = false;
            self.launch_session(s);
        } else if let Some(act) = action_to_run {
            self.show_command_palette = false;
            match act {
                PaletteAction::NewSession => {
                    self.editing_session = SessionProfile::default();
                    self.is_new_session = true;
                    self.show_session_editor = true;
                }
                PaletteAction::OpenHelp => {
                    self.show_help = true;
                }
                PaletteAction::OpenKeyManager => {
                    self.refresh_agent_keys();
                    self.show_key_manager = true;
                }
                PaletteAction::LoadAllPpksToPageant => {
                    self.load_all_session_ppks_into_pageant();
                    self.show_key_manager = true;
                }
                PaletteAction::OpenNetworkTools => {
                    self.show_network_tools = true;
                }
                PaletteAction::OpenAbout => {
                    self.show_about = true;
                }
                PaletteAction::LaunchPowershell => {
                    let p = SessionProfile {
                        name: "PowerShell Local".to_string(),
                        protocol: ProtocolType::LocalShell,
                        local_shell_cmd: "powershell.exe".to_string(),
                        icon_badge: "⚡".to_string(),
                        ..Default::default()
                    };
                    self.launch_session(p);
                }
                PaletteAction::ProbeAll => {
                    self.probe_all_sessions();
                }
                PaletteAction::DuplicateActiveTab => {
                    if let Some(tab) = self.tabs.get(self.active_tab_idx) {
                        let p = tab.profile.clone();
                        self.launch_session(p);
                    }
                }
                PaletteAction::CloseActiveTab => {
                    self.close_tab(self.active_tab_idx);
                }
            }
        }
    }

    fn render_network_tools_modal(&mut self, ctx: &Context) {
        let lang = self.config.language;
        let mut open = self.show_network_tools;
        let mut session_to_launch: Option<SessionProfile> = None;

        let center_pos = ctx
            .input(|i| i.viewport().inner_rect)
            .map(|r| r.center())
            .unwrap_or(Pos2::new(500.0, 400.0));
        egui::Window::new(tr(
            lang,
            "\u{E5D4} Boîte à Outils Diagnostic & Réseau SysAdmin",
            "\u{E5D4} SysAdmin Network & Diagnostic Toolkit",
        ))
        .id(egui::Id::unique("network_tools_modal_v3"))
        .open(&mut open)
        .resizable(true)
        .pivot(egui::Align2::CENTER_CENTER)
        .default_pos(center_pos)
        .default_size(Vec2::new(1040.0, 840.0))
        .min_size(Vec2::new(820.0, 560.0))
        .show(ctx, |ui| {
            egui::ScrollArea::vertical()
                .auto_shrink([false, false])
                .show(ui, |ui| {
                    // Section 1: Scanner TCP & Bannière SSH
                    egui::Frame::NONE
                        .fill(Color32::from_rgb(18, 22, 29))
                        .corner_radius(egui::CornerRadius::same(6))
                        .inner_margin(egui::Margin::same(10))
                        .stroke(Stroke::new(1.0, Color32::from_rgb(38, 44, 54)))
                        .show(ui, |ui| {
                            ui.heading(tr(
                                lang,
                                "\u{E0F2} Scanner TCP & Détection de Bannière (SSH / Telnet)",
                                "\u{E0F2} TCP Port Scanner & Banner Grabber (SSH / Telnet)",
                            ));
                            ui.add_space(4.0);
                            ui.horizontal(|ui| {
                                ui.label(tr(lang, "Hôte / IP :", "Host / IP:"));
                                ui.add(
                                    egui::TextEdit::singleline(&mut self.probe_host_input)
                                        .desired_width(180.0),
                                );
                                ui.label(tr(lang, "Port :", "Port:"));
                                ui.add(
                                    egui::DragValue::new(&mut self.probe_port_input)
                                        .range(1..=65535),
                                );
                                if ui
                                    .button(
                                        RichText::new(tr(
                                            lang,
                                            "\u{E3FE} Scanner le Port",
                                            "\u{E3FE} Scan Port",
                                        ))
                                        .strong()
                                        .color(Color32::from_rgb(88, 166, 255)),
                                    )
                                    .clicked()
                                {
                                    let h = self.probe_host_input.trim().to_string();
                                    let p = self.probe_port_input;
                                    if !h.is_empty() {
                                        self.probe_single_target(h, p);
                                    }
                                }
                            });

                            if !self.probe_results.is_empty() {
                                ui.add_space(6.0);
                                ui.label(
                                    RichText::new(tr(
                                        lang,
                                        "Historique des scans récents :",
                                        "Recent Scan History:",
                                    ))
                                    .size(11.0)
                                    .strong()
                                    .color(Color32::from_rgb(139, 148, 158)),
                                );
                                for r in self.probe_results.iter().rev().take(5) {
                                    ui.horizontal(|ui| {
                                        let (dot, col) = if r.reachable {
                                            (
                                                format!(
                                                    "● {} ({}ms)",
                                                    tr(lang, "Joignable", "Reachable"),
                                                    r.latency_ms
                                                ),
                                                Color32::from_rgb(63, 185, 80),
                                            )
                                        } else {
                                            (
                                                tr(
                                                    lang,
                                                    "● Injoignable / Timeout",
                                                    "● Unreachable / Timeout",
                                                )
                                                .to_string(),
                                                Color32::from_rgb(248, 81, 73),
                                            )
                                        };
                                        ui.label(
                                            RichText::new(format!("{}:{}", r.host, r.port))
                                                .monospace()
                                                .strong(),
                                        );
                                        ui.label(RichText::new(dot).size(11.5).color(col));
                                        if !r.banner.is_empty() {
                                            ui.label(
                                                RichText::new(format!("— {}", r.banner))
                                                    .size(11.0)
                                                    .monospace()
                                                    .color(Color32::from_rgb(139, 148, 158)),
                                            );
                                        }
                                    });
                                }
                            }
                        });

                    ui.add_space(10.0);

                    // Section 2: Tableau de Santé Multi-Serveurs
                    egui::Frame::NONE
                        .fill(Color32::from_rgb(18, 22, 29))
                        .corner_radius(egui::CornerRadius::same(6))
                        .inner_margin(egui::Margin::same(10))
                        .stroke(Stroke::new(1.0, Color32::from_rgb(38, 44, 54)))
                        .show(ui, |ui| {
                            ui.horizontal(|ui| {
                                ui.heading(tr(
                                    lang,
                                    "\u{E560} Santé & Latence des Serveurs Sauvegardés",
                                    "\u{E560} Saved Servers Health & Latency",
                                ));
                                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                                    if ui
                                        .button(
                                            RichText::new(tr(
                                                lang,
                                                "\u{E094} Re-tester Tous les Serveurs",
                                                "\u{E094} Re-probe All Servers",
                                            ))
                                            .strong(),
                                        )
                                        .clicked()
                                    {
                                        self.probe_all_sessions();
                                    }
                                });
                            });
                            ui.add_space(6.0);

                            for s in &self.config.sessions {
                                if s.protocol == ProtocolType::LocalShell {
                                    continue;
                                }
                                let probe = self.session_probes.get(&s.id);
                                let (proto_tag, proto_color) = protocol_badge_style(s.protocol);

                                ui.horizontal(|ui| {
                                    ui.label(
                                        RichText::new(format!("{} {}", s.icon_badge, s.name))
                                            .strong()
                                            .color(Color32::from_rgb(230, 237, 243)),
                                    );
                                    ui.label(
                                        RichText::new(format!("{}:{}", s.host, s.port))
                                            .monospace()
                                            .size(11.0)
                                            .color(Color32::from_rgb(139, 148, 158)),
                                    );
                                    ui.label(
                                        RichText::new(proto_tag)
                                            .size(10.0)
                                            .monospace()
                                            .color(proto_color),
                                    );

                                    ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                                        if ui
                                            .small_button(tr(
                                                lang,
                                                "\u{E3FE} Connecter",
                                                "\u{E3FE} Connect",
                                            ))
                                            .clicked()
                                        {
                                            session_to_launch = Some(s.clone());
                                        }

                                        if let Some(p) = probe {
                                            let (status_text, col) = if p.reachable {
                                                (
                                                    format!("● {} ms", p.latency_ms),
                                                    Color32::from_rgb(63, 185, 80),
                                                )
                                            } else {
                                                (
                                                    tr(lang, "● Injoignable", "● Unreachable")
                                                        .to_string(),
                                                    Color32::from_rgb(248, 81, 73),
                                                )
                                            };
                                            ui.label(
                                                RichText::new(status_text)
                                                    .monospace()
                                                    .size(11.0)
                                                    .color(col),
                                            )
                                            .on_hover_text(&p.banner);
                                        } else {
                                            ui.label(
                                                RichText::new(tr(
                                                    lang,
                                                    "● En attente...",
                                                    "● Pending...",
                                                ))
                                                .size(11.0)
                                                .color(Color32::from_rgb(110, 118, 129)),
                                            );
                                        }
                                    });
                                });
                            }
                        });

                    ui.add_space(10.0);

                    // Section 3: Calculateur de Sous-Réseau CIDR IPv4
                    egui::Frame::NONE
                        .fill(Color32::from_rgb(18, 22, 29))
                        .corner_radius(egui::CornerRadius::same(6))
                        .inner_margin(egui::Margin::same(10))
                        .stroke(Stroke::new(1.0, Color32::from_rgb(38, 44, 54)))
                        .show(ui, |ui| {
                            ui.heading(tr(
                                lang,
                                "\u{E538} Calculateur de Sous-Réseau CIDR IPv4",
                                "\u{E538} IPv4 CIDR Subnet Calculator",
                            ));
                            ui.add_space(4.0);
                            ui.horizontal(|ui| {
                                ui.label(tr(lang, "Bloc CIDR :", "CIDR Block:"));
                                let resp = ui.add(
                                    egui::TextEdit::singleline(&mut self.cidr_input)
                                        .desired_width(170.0)
                                        .hint_text("e.g. 192.168.1.0/24"),
                                );
                                if resp.changed() {
                                    match calculate_ipv4_cidr(&self.cidr_input) {
                                        Ok(res) => {
                                            self.cidr_result = Some(res);
                                            self.cidr_error.clear();
                                        }
                                        Err(e) => {
                                            self.cidr_error = e.to_string();
                                        }
                                    }
                                }

                                for &prefix in &["/24", "/28", "/16", "/30", "/8"] {
                                    if ui.small_button(prefix).clicked() {
                                        let base = self
                                            .cidr_input
                                            .split('/')
                                            .next()
                                            .unwrap_or("192.168.1.0");
                                        self.cidr_input = format!("{}{}", base, prefix);
                                        if let Ok(res) = calculate_ipv4_cidr(&self.cidr_input) {
                                            self.cidr_result = Some(res);
                                            self.cidr_error.clear();
                                        }
                                    }
                                }
                            });

                            if !self.cidr_error.is_empty() {
                                ui.label(
                                    RichText::new(&self.cidr_error)
                                        .size(11.0)
                                        .color(Color32::from_rgb(248, 81, 73)),
                                );
                            } else if let Some(ref c) = self.cidr_result {
                                ui.add_space(6.0);
                                egui::Grid::new("cidr_calc_grid")
                                    .num_columns(2)
                                    .spacing([12.0, 4.0])
                                    .show(ui, |ui| {
                                        ui.label(tr(lang, "Adresse IP :", "IP Address:"));
                                        ui.monospace(&c.input_ip);
                                        ui.end_row();

                                        ui.label(tr(lang, "Masque (Netmask) :", "Netmask:"));
                                        ui.monospace(format!("{} (/{})", c.netmask, c.prefix));
                                        ui.end_row();

                                        ui.label(tr(
                                            lang,
                                            "Masque générique (Wildcard) :",
                                            "Wildcard Mask:",
                                        ));
                                        ui.monospace(&c.wildcard);
                                        ui.end_row();

                                        ui.label(tr(
                                            lang,
                                            "Adresse Réseau (Network) :",
                                            "Network Address:",
                                        ));
                                        ui.monospace(&c.network_address);
                                        ui.end_row();

                                        ui.label(tr(
                                            lang,
                                            "Adresse Broadcast :",
                                            "Broadcast Address:",
                                        ));
                                        ui.monospace(&c.broadcast_address);
                                        ui.end_row();

                                        ui.label(tr(
                                            lang,
                                            "Plage d'Hôtes Utilisables :",
                                            "Usable Host Range:",
                                        ));
                                        ui.label(
                                            RichText::new(format!(
                                                "{}  \u{E06C}  {}",
                                                c.first_usable, c.last_usable
                                            ))
                                            .strong()
                                            .color(Color32::from_rgb(88, 166, 255)),
                                        );
                                        ui.end_row();

                                        ui.label(tr(
                                            lang,
                                            "Nombre total d'hôtes :",
                                            "Total Usable Hosts:",
                                        ));
                                        ui.label(
                                            RichText::new(format!(
                                                "{} {}",
                                                c.usable_hosts,
                                                tr(lang, "hôtes assignables", "assignable hosts")
                                            ))
                                            .color(Color32::from_rgb(63, 185, 80)),
                                        );
                                        ui.end_row();
                                    });
                            }
                        });

                    ui.add_space(10.0);

                    // Section 4: Générateur de Lignes de Commande PuTTY / OpenSSH
                    egui::Frame::NONE
                        .fill(Color32::from_rgb(18, 22, 29))
                        .corner_radius(egui::CornerRadius::same(6))
                        .inner_margin(egui::Margin::same(10))
                        .stroke(Stroke::new(1.0, Color32::from_rgb(38, 44, 54)))
                        .show(ui, |ui| {
                            ui.heading(tr(
                                lang,
                                "\u{E196} Générateur de Lignes de Commande CLI (PuTTY / OpenSSH)",
                                "\u{E196} CLI Command Line Generator (PuTTY / OpenSSH)",
                            ));
                            ui.add_space(4.0);

                            let mut toast_to_set: Option<String> = None;
                            for s in &self.config.sessions {
                                if s.protocol != ProtocolType::Ssh {
                                    continue;
                                }
                                let user_prefix = if s.username.is_empty() {
                                    s.host.clone()
                                } else {
                                    format!("{}@{}", s.username, s.host)
                                };
                                let key_opt =
                                    if let SshAuthMethod::PrivateKeyFile { key_path, .. } =
                                        &s.ssh_auth
                                    {
                                        if !key_path.is_empty() {
                                            format!(" -i \"{}\"", key_path)
                                        } else {
                                            String::new()
                                        }
                                    } else {
                                        String::new()
                                    };

                                let openssh_cmd =
                                    format!("ssh -p {} {}{}", s.port, user_prefix, key_opt);
                                let putty_cmd = format!(
                                    "putty.exe -ssh {} -P {}{}",
                                    user_prefix, s.port, key_opt
                                );

                                ui.horizontal(|ui| {
                                    ui.strong(format!("{} {}", s.icon_badge, s.name));
                                    ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                                        if ui.small_button("\u{E196} PuTTY").clicked() {
                                            if let Ok(mut cb) = Clipboard::new() {
                                                let _ = cb.set_text(&putty_cmd);
                                            }
                                            toast_to_set = Some(
                                                tr(
                                                    lang,
                                                    "Commande PuTTY.exe copiée !",
                                                    "PuTTY.exe command copied!",
                                                )
                                                .to_string(),
                                            );
                                        }
                                        if ui
                                            .small_button(tr(
                                                lang,
                                                "\u{E196} Copier SSH",
                                                "\u{E196} Copy SSH",
                                            ))
                                            .clicked()
                                        {
                                            if let Ok(mut cb) = Clipboard::new() {
                                                let _ = cb.set_text(&openssh_cmd);
                                            }
                                            toast_to_set = Some(
                                                tr(
                                                    lang,
                                                    "Commande OpenSSH copiée !",
                                                    "OpenSSH command copied!",
                                                )
                                                .to_string(),
                                            );
                                        }
                                        ui.monospace(&openssh_cmd);
                                    });
                                });
                            }
                            if let Some(msg) = toast_to_set {
                                self.set_toast(msg);
                            }
                        });
                });
        });

        self.show_network_tools = open;

        if let Some(s) = session_to_launch {
            self.show_network_tools = false;
            self.launch_session(s);
        }
    }

    fn render_about_modal(&mut self, ctx: &Context) {
        let lang = self.config.language;
        let mut open = self.show_about;
        let mut should_close = false;
        egui::Window::new(tr(
            lang,
            "\u{E6C8} Cuty-SSH — Design System & À Propos",
            "\u{E6C8} Cuty-SSH — Design System & About",
        ))
        .open(&mut open)
        .collapsible(false)
        .resizable(true)
        .default_width(760.0)
        .default_height(620.0)
        .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
        .frame(
            egui::Frame::NONE
                .fill(Color32::from_rgb(18, 22, 29))
                .corner_radius(egui::CornerRadius::same(10))
                .inner_margin(egui::Margin::same(16))
                .stroke(Stroke::new(1.0, Color32::from_rgb(48, 54, 61))),
        )
        .show(ctx, |ui| {
            egui::ScrollArea::vertical()
                .auto_shrink([false, false])
                .show(ui, |ui| {
                    // Hero Banner
                    ui.add(
                        egui::Image::new(egui::include_image!("../../assets/cuty_ssh_hero.png"))
                            .max_width(720.0)
                            .corner_radius(12.0),
                    );
                    ui.add_space(14.0);

                    ui.horizontal(|ui| {
                        ui.add(
                            egui::Image::new(egui::include_image!("../../assets/cuty_ssh_icon.png"))
                                .max_width(84.0)
                                .corner_radius(16.0),
                        );
                        ui.add_space(12.0);
                        ui.vertical(|ui| {
                            ui.heading(
                                RichText::new(tr(
                                    lang,
                                    "Cuty-SSH — Cockpit SysAdmin & Client SSH / Telnet",
                                    "Cuty-SSH — SysAdmin Cockpit & SSH / Telnet Client",
                                ))
                                .size(19.0)
                                .strong()
                                .color(Color32::from_rgb(88, 166, 255)),
                            );
                            ui.add_space(4.0);
                            ui.label(
                                RichText::new(format!(
                                    "Version {} (Rust 2024 Edition) • Windows Desktop",
                                    env!("CARGO_PKG_VERSION")
                                ))
                                    .size(13.0)
                                    .color(Color32::from_rgb(139, 148, 158)),
                            );
                            ui.label(
                                RichText::new(tr(
                                    lang,
                                    "Client moderne avec gestion native des clés PuTTY .ppk v2/v3 et Pageant.",
                                    "Modern desktop client with native PuTTY .ppk v2/v3 and Pageant support.",
                                ))
                                .italics()
                                .size(12.5)
                                .color(Color32::from_rgb(201, 209, 217)),
                            );
                        });
                    });

                    ui.add_space(16.0);
                    ui.separator();
                    ui.add_space(10.0);

                    ui.heading(
                        RichText::new("\u{E478} Design System & UI Badges")
                            .size(16.0)
                            .color(Color32::from_rgb(245, 158, 11)),
                    );
                    ui.add_space(6.0);
                    ui.label(
                        RichText::new(tr(
                            lang,
                            "Les maquettes de badges et statuts visuels ci-dessous servent de référence graphique aux composants de l'application :",
                            "The UI badge and status sheets below serve as visual references for the application's components:",
                        ))
                        .color(Color32::from_rgb(139, 148, 158)),
                    );
                    ui.add_space(8.0);
                    ui.add(
                        egui::Image::new(egui::include_image!("../../assets/cuty_ssh_ui_badges.png"))
                            .max_width(720.0)
                            .corner_radius(12.0),
                    );

                    ui.add_space(16.0);
                    ui.separator();
                    ui.add_space(10.0);

                    ui.horizontal(|ui| {
                        if ui
                            .button(tr(
                                lang,
                                "\u{E24A} Ouvrir le dossier des assets",
                                "\u{E24A} Open Assets Folder",
                            ))
                            .clicked()
                        {
                            let _ = open::that("assets");
                        }
                        if ui
                            .button(tr(
                                lang,
                                "\u{E288} Ouvrir README du projet",
                                "\u{E288} Open Project README",
                            ))
                            .clicked()
                        {
                            let _ = open::that("README.md");
                        }
                        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                            if ui
                                .button(RichText::new(tr(lang, "Fermer", "Close")).strong())
                                .clicked()
                            {
                                should_close = true;
                            }
                        });
                    });
                    ui.add_space(8.0);
                });
        });

        self.show_about = if should_close { false } else { open };
    }

    fn render_session_manager_modal(&mut self, ctx: &Context) {
        let lang = self.config.language;
        let mut open = self.show_session_manager;
        let mut close_requested = false;
        let mut session_to_launch: Option<SessionProfile> = None;
        let mut session_to_edit: Option<SessionProfile> = None;
        let mut session_to_dup: Option<Uuid> = None;
        let mut session_to_del: Option<Uuid> = None;
        let mut ppk_to_load: Option<String> = None;

        egui::Window::new(tr(
            lang,
            "\u{E24A} Gestionnaire & Organisation des Sessions",
            "\u{E24A} Session Manager & Bulk Organization",
        ))
        .open(&mut open)
        .resizable(true)
        .default_width(920.0)
        .default_height(600.0)
        .show(ctx, |ui| {
            // Header & Action Bar
            ui.horizontal(|ui| {
                ui.heading(
                    RichText::new(tr(
                        lang,
                        "\u{E24A} Gestion & Organisation des Sessions",
                        "\u{E24A} Session Management & Organization",
                    ))
                    .size(16.0)
                    .color(Color32::from_rgb(88, 166, 255)),
                );
                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                    if ui
                        .button(
                            RichText::new(tr(lang, "\u{E3D4} Nouvelle Session", "\u{E3D4} New Session"))
                                .strong()
                                .color(Color32::from_rgb(63, 185, 80)),
                        )
                        .clicked()
                    {
                        self.editing_session = SessionProfile::default();
                        self.is_new_session = true;
                        self.editor_tab = ConfigEditorTab::ConnectionAndKey;
                        self.show_session_editor = true;
                    }

                    if ui
                        .button(tr(lang, "\u{E4C0} Exporter Tout (JSON)", "\u{E4C0} Export All (JSON)"))
                        .on_hover_text(tr(
                            lang,
                            "Exporter toutes vos sessions dans un fichier JSON",
                            "Export all saved sessions to a JSON file",
                        ))
                        .clicked()
                        && let Ok(json) = self.config.export_sessions_json(None)
                        && let Some(path) = rfd::FileDialog::new()
                            .add_filter("JSON File", &["json"])
                            .set_file_name("cuty_ssh_sessions.json")
                            .save_file()
                        && std::fs::write(&path, json).is_ok()
                    {
                        self.set_toast(format!(
                            "{} {} {:?}",
                            self.config.sessions.len(),
                            tr(
                                lang,
                                "sessions exportées avec succès vers",
                                "sessions exported to"
                            ),
                            path.file_name().unwrap_or_default()
                        ));
                    }

                    if ui
                        .button(tr(lang, "\u{E20C} Importer (JSON)", "\u{E20C} Import (JSON)"))
                        .on_hover_text(tr(
                            lang,
                            "Importer des sessions depuis un fichier JSON",
                            "Import sessions from a JSON file",
                        ))
                        .clicked()
                        && let Some(path) = rfd::FileDialog::new()
                            .add_filter("JSON File", &["json"])
                            .pick_file()
                        && let Ok(data) = std::fs::read_to_string(&path)
                    {
                        match self.config.import_sessions_json(&data) {
                            Ok(n) => self.set_toast(format!(
                                "{} {}",
                                n,
                                tr(
                                    lang,
                                    "session(s) importée(s) avec succès !",
                                    "session(s) imported successfully!"
                                )
                            )),
                            Err(e) => self.set_toast(format!(
                                "{} {}",
                                tr(lang, "Erreur lors de l'import :", "Import error:"),
                                e
                            )),
                        }
                    }

                    if ui
                        .button(tr(lang, "\u{E20C} Sync Registre", "\u{E20C} Sync Registry"))
                        .on_hover_text(tr(
                            lang,
                            "Synchroniser depuis le Registre PuTTY",
                            "Sync from Windows PuTTY Registry",
                        ))
                        .clicked()
                    {
                        #[cfg(windows)]
                        match self.config.import_from_windows_registry() {
                            Ok(n) => {
                                self.probe_all_sessions();
                                self.set_toast(format!(
                                    "{} {}",
                                    n,
                                    tr(
                                        lang,
                                        "nouvelle(s) session(s) importée(s) du Registre !",
                                        "new session(s) imported from Registry!"
                                    )
                                ));
                            }
                            Err(e) => self.set_toast(format!(
                                "{} {}",
                                tr(lang, "Erreur import registre :", "Registry import error:"),
                                e
                            )),
                        }
                    }

                    if ui
                        .button(tr(lang, "\u{E0F2} Tester Tout le Ping", "\u{E0F2} Probe All Ping"))
                        .clicked()
                    {
                        self.probe_all_sessions();
                    }
                });
            });

            ui.add_space(8.0);
            ui.separator();
            ui.add_space(6.0);

            // Search & Filter Toolbar
            ui.horizontal_wrapped(|ui| {
                ui.label("\u{E30C}");
                ui.add(
                    egui::TextEdit::singleline(&mut self.dashboard_session_query)
                        .hint_text(tr(
                            lang,
                            "Filtrer par nom, hôte/IP, user, port, protocole, dossier...",
                            "Filter by name, host/IP, user, port, protocol, folder...",
                        ))
                        .desired_width(260.0),
                );
                if !self.dashboard_session_query.is_empty() && ui.small_button("\u{E4F6}").clicked() {
                    self.dashboard_session_query.clear();
                }

                ui.separator();

                // Protocol chips
                let proto_filter = self.dashboard_protocol_filter;
                if ui
                    .selectable_label(
                        proto_filter.is_none(),
                        format!(
                            "{} ({})",
                            tr(lang, "Tous", "All"),
                            self.config.sessions.len()
                        ),
                    )
                    .clicked()
                {
                    self.dashboard_protocol_filter = None;
                }
                for p in [
                    ProtocolType::Ssh,
                    ProtocolType::Telnet,
                    ProtocolType::LocalShell,
                    ProtocolType::RawTcp,
                ] {
                    let count = self
                        .config
                        .sessions
                        .iter()
                        .filter(|s| s.protocol == p)
                        .count();
                    let is_sel = proto_filter == Some(p);
                    if ui
                        .selectable_label(is_sel, format!("{} ({})", p.badge(), count))
                        .clicked()
                    {
                        if is_sel {
                            self.dashboard_protocol_filter = None;
                        } else {
                            self.dashboard_protocol_filter = Some(p);
                        }
                    }
                }

                ui.separator();

                // Folder filter
                let all_folders = self.config.all_folders();
                egui::ComboBox::from_id_salt("manager_folder_filter")
                    .selected_text(format!("\u{E24A} {}", self.dashboard_folder_filter))
                    .show_ui(ui, |ui| {
                        ui.selectable_value(
                            &mut self.dashboard_folder_filter,
                            "Tous".to_string(),
                            tr(lang, "\u{E24A} Tous les dossiers", "\u{E24A} All Folders"),
                        );
                        for f in &all_folders {
                            ui.selectable_value(
                                &mut self.dashboard_folder_filter,
                                f.clone(),
                                format!("\u{E24A} {}", f),
                            );
                        }
                    });

                // Tag filter
                let all_tags = self.config.all_tags();
                if !all_tags.is_empty() {
                    egui::ComboBox::from_id_salt("manager_tag_filter")
                        .selected_text(if self.dashboard_tag_filter == "Tous" {
                            tr(lang, "\u{E478} Tous les tags", "\u{E478} All Tags").to_string()
                        } else {
                            format!("\u{E478} #{}", self.dashboard_tag_filter)
                        })
                        .show_ui(ui, |ui| {
                            ui.selectable_value(
                                &mut self.dashboard_tag_filter,
                                "Tous".to_string(),
                                tr(lang, "\u{E478} Tous les tags", "\u{E478} All Tags"),
                            );
                            for t in &all_tags {
                                ui.selectable_value(
                                    &mut self.dashboard_tag_filter,
                                    t.clone(),
                                    format!("\u{E478} #{}", t),
                                );
                            }
                        });
                }

                // Reachability filters (shared with the Cockpit)
                let online_col = if self.dashboard_online_only {
                    Color32::from_rgb(63, 185, 80)
                } else {
                    Color32::from_rgb(139, 148, 158)
                };
                if ui
                    .selectable_label(
                        self.dashboard_online_only,
                        RichText::new(tr(lang, "● En ligne", "● Online")).color(online_col),
                    )
                    .on_hover_text(tr(
                        lang,
                        "Filtrer uniquement les serveurs avec ping réussi",
                        "Show only servers responding to TCP ping",
                    ))
                    .clicked()
                {
                    self.dashboard_online_only = !self.dashboard_online_only;
                    self.dashboard_offline_only = false;
                }
                let offline_col = if self.dashboard_offline_only {
                    Color32::from_rgb(248, 81, 73)
                } else {
                    Color32::from_rgb(139, 148, 158)
                };
                if ui
                    .selectable_label(
                        self.dashboard_offline_only,
                        RichText::new(tr(lang, "● Hors ligne", "● Offline")).color(offline_col),
                    )
                    .on_hover_text(tr(
                        lang,
                        "Filtrer uniquement les serveurs injoignables (puis tout sélectionner pour les supprimer)",
                        "Show only unreachable servers (then select all to delete them)",
                    ))
                    .clicked()
                {
                    self.dashboard_offline_only = !self.dashboard_offline_only;
                    self.dashboard_online_only = false;
                }

                // Sort mode
                egui::ComboBox::from_id_salt("manager_sort_mode")
                    .selected_text(self.dashboard_sort_mode.label(lang))
                    .show_ui(ui, |ui| {
                        for m in [
                            SessionSortMode::NameAsc,
                            SessionSortMode::NameDesc,
                            SessionSortMode::FolderAndName,
                            SessionSortMode::Protocol,
                            SessionSortMode::Latency,
                        ] {
                            ui.selectable_value(
                                &mut self.dashboard_sort_mode,
                                m,
                                m.label(lang),
                            );
                        }
                    });
            });

            ui.add_space(8.0);

            // Bulk operations toolbar
            if !self.selected_session_ids.is_empty() {
                egui::Frame::NONE
                    .fill(Color32::from_rgb(26, 36, 52))
                    .corner_radius(6.0)
                    .inner_margin(egui::Margin::symmetric(10, 6))
                    .stroke(Stroke::new(1.0, Color32::from_rgb(56, 110, 190)))
                    .show(ui, |ui| {
                        ui.horizontal(|ui| {
                            ui.label(
                                RichText::new(format!(
                                    "☑ {} {}",
                                    self.selected_session_ids.len(),
                                    tr(
                                        lang,
                                        "session(s) sélectionnée(s)",
                                        "session(s) selected"
                                    )
                                ))
                                .strong()
                                .color(Color32::from_rgb(165, 214, 255)),
                            );

                            ui.separator();

                            ui.label(tr(lang, "Déplacer vers :", "Move to:"));
                            let all_folders = self.config.all_folders();
                            egui::ComboBox::from_id_salt("bulk_move_cb")
                                .selected_text(&self.bulk_target_folder)
                                .show_ui(ui, |ui| {
                                    for f in &all_folders {
                                        ui.selectable_value(
                                            &mut self.bulk_target_folder,
                                            f.clone(),
                                            f,
                                        );
                                    }
                                });
                            ui.add(
                                egui::TextEdit::singleline(&mut self.bulk_target_folder)
                                    .desired_width(100.0)
                                    .hint_text(tr(
                                        lang,
                                        "Nouveau dossier...",
                                        "New folder...",
                                    )),
                            );
                            if ui.button(tr(lang, "\u{E06C} Déplacer", "\u{E06C} Move")).clicked() {
                                let ids: Vec<Uuid> =
                                    self.selected_session_ids.iter().copied().collect();
                                let moved = self
                                    .config
                                    .move_sessions_to_folder(&ids, &self.bulk_target_folder);
                                self.set_toast(format!(
                                    "{} {} '{}' !",
                                    moved,
                                    tr(
                                        lang,
                                        "session(s) déplacée(s) vers",
                                        "session(s) moved to"
                                    ),
                                    self.bulk_target_folder
                                ));
                            }

                            ui.separator();

                            ui.label("Tag :");
                            ui.add(
                                egui::TextEdit::singleline(&mut self.bulk_tag_input)
                                    .desired_width(80.0)
                                    .hint_text("e.g. prod"),
                            );
                            if ui.button("\u{E478} + Tag").clicked()
                                && !self.bulk_tag_input.trim().is_empty()
                            {
                                let ids: Vec<Uuid> =
                                    self.selected_session_ids.iter().copied().collect();
                                let tagged = self
                                    .config
                                    .add_tag_to_sessions(&ids, &self.bulk_tag_input);
                                self.set_toast(format!(
                                    "Tag '{}' \u{E06C} {} session(s) !",
                                    self.bulk_tag_input.trim(),
                                    tagged
                                ));
                                self.bulk_tag_input.clear();
                            }
                            if ui.button("\u{E478} - Tag").clicked()
                                && !self.bulk_tag_input.trim().is_empty()
                            {
                                let ids: Vec<Uuid> =
                                    self.selected_session_ids.iter().copied().collect();
                                let removed = self
                                    .config
                                    .remove_tag_from_sessions(&ids, &self.bulk_tag_input);
                                self.set_toast(format!(
                                    "Tag '{}' \u{E4F6} {} session(s) !",
                                    self.bulk_tag_input.trim(),
                                    removed
                                ));
                                self.bulk_tag_input.clear();
                            }

                            ui.separator();

                            if ui
                                .button(
                                    RichText::new(tr(
                                        lang,
                                        "\u{E2D6} Déployer Clé Principale",
                                        "\u{E2D6} Deploy Primary Key",
                                    ))
                                    .strong()
                                    .color(Color32::from_rgb(63, 185, 80)),
                                )
                                .on_hover_text(tr(
                                    lang,
                                    "Déploie votre clé publique SSH principale sur toutes les sessions SSH sélectionnées et les configure pour l'authentification par clé",
                                    "Deploy your primary SSH public key to all selected SSH sessions and configure them for key authentication",
                                ))
                                .clicked()
                            {
                                match resolve_or_create_primary_key(&self.config.primary_key_path) {
                                    Ok((key_path, info, _)) => {
                                        let path_str = key_path.to_string_lossy().to_string();
                                        if self.config.primary_key_path.trim().is_empty() {
                                            self.config.primary_key_path = path_str.clone();
                                        }
                                        let ids: Vec<Uuid> = self.selected_session_ids.iter().copied().collect();
                                        let mut count = 0;
                                        for s in &mut self.config.sessions {
                                            if ids.contains(&s.id) && s.protocol == ProtocolType::Ssh {
                                                s.ssh_auth = SshAuthMethod::PrivateKeyFile {
                                                    key_path: path_str.clone(),
                                                    passphrase: String::new(),
                                                    cert_path: String::new(),
                                                };
                                                s.deploy_primary_key_on_connect = true;
                                                count += 1;
                                            }
                                        }
                                        let _ = self.config.save();

                                        // Also deploy immediately to any currently connected tabs for these sessions
                                        for tab in &mut self.tabs {
                                            if ids.contains(&tab.profile.id) && tab.state == TabConnectionState::Connected {
                                                let _ = tab.handle.cmd_tx.send(BackendCommand::DeployPublicKey {
                                                    openssh_public_key: info.openssh_public_key.clone(),
                                                    private_key_path: path_str.clone(),
                                                    key_comment: info.comment.clone(),
                                                });
                                            }
                                        }

                                        self.set_toast(format!(
                                            "{} {}",
                                            count,
                                            tr(
                                                lang,
                                                "session(s) SSH configurée(s) avec la clé principale !",
                                                "SSH session(s) configured with primary key!"
                                            )
                                        ));
                                    }
                                    Err(e) => {
                                        self.set_toast(format!("Erreur clé principale : {}", e));
                                    }
                                }
                            }

                            if ui
                                .button(tr(
                                    lang,
                                    "\u{E710} Dupliquer sélection",
                                    "\u{E710} Duplicate Selected",
                                ))
                                .clicked()
                            {
                                let ids: Vec<Uuid> =
                                    self.selected_session_ids.iter().copied().collect();
                                let mut dup_count = 0;
                                for id in ids {
                                    if self.config.duplicate_session(id).is_some() {
                                        dup_count += 1;
                                    }
                                }
                                self.set_toast(format!(
                                    "{} {}",
                                    dup_count,
                                    tr(lang, "session(s) dupliquée(s) !", "session(s) duplicated!")
                                ));
                            }

                            if ui
                                .button(tr(
                                    lang,
                                    "\u{E4C0} Exporter sélection (JSON)",
                                    "\u{E4C0} Export Selected (JSON)",
                                ))
                                .clicked()
                            {
                                let ids: Vec<Uuid> =
                                    self.selected_session_ids.iter().copied().collect();
                                if let Ok(json) = self.config.export_sessions_json(Some(&ids))
                                    && let Some(path) = rfd::FileDialog::new()
                                        .add_filter("JSON File", &["json"])
                                        .set_file_name("sessions_selection.json")
                                        .save_file()
                                    && std::fs::write(&path, json).is_ok()
                                {
                                    self.set_toast(format!(
                                        "{} {} {:?}",
                                        ids.len(),
                                        tr(lang, "sessions exportées vers", "sessions exported to"),
                                        path.file_name().unwrap_or_default()
                                    ));
                                }
                            }

                            if ui
                                .button(
                                    RichText::new(tr(
                                        lang,
                                        "\u{E4A6} Supprimer sélection",
                                        "\u{E4A6} Delete Selected",
                                    ))
                                    .color(Color32::from_rgb(248, 81, 73)),
                                )
                                .clicked()
                            {
                                let ids: Vec<Uuid> =
                                    self.selected_session_ids.iter().copied().collect();
                                let count = self.config.delete_sessions(&ids);
                                self.selected_session_ids.clear();
                                self.set_toast(format!(
                                    "{} {}",
                                    count,
                                    tr(lang, "session(s) supprimée(s) !", "session(s) deleted!")
                                ));
                            }

                            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                                if ui
                                    .button(tr(lang, "\u{E4F6} Désélectionner", "\u{E4F6} Clear Selection"))
                                    .clicked()
                                {
                                    self.selected_session_ids.clear();
                                }
                            });
                        });
                    });
                ui.add_space(6.0);
            }

            // Filter sessions
            let filtered = self.filter_and_sort_sessions(
                &self.dashboard_session_query,
                self.dashboard_protocol_filter,
                &self.dashboard_folder_filter,
                &self.dashboard_tag_filter,
                self.dashboard_reachability_filter(),
                self.dashboard_sort_mode,
            );

            // Table Header
            let all_visible_selected = !filtered.is_empty()
                && filtered
                    .iter()
                    .all(|s| self.selected_session_ids.contains(&s.id));
            egui::Frame::NONE
                .fill(Color32::from_rgb(21, 27, 38))
                .corner_radius(4.0)
                .inner_margin(egui::Margin::symmetric(8, 6))
                .show(ui, |ui| {
                    ui.horizontal(|ui| {
                        let mut chk = all_visible_selected;
                        if ui
                            .checkbox(&mut chk, "")
                            .on_hover_text(tr(
                                lang,
                                "Tout sélectionner / Tout désélectionner",
                                "Select All / Deselect All",
                            ))
                            .changed()
                        {
                            if chk {
                                for s in &filtered {
                                    self.selected_session_ids.insert(s.id);
                                }
                            } else {
                                for s in &filtered {
                                    self.selected_session_ids.remove(&s.id);
                                }
                            }
                        }
                        ui.set_min_width(20.0);
                        ui.label(
                            RichText::new(tr(lang, "Nom / Cible", "Name / Target"))
                                .strong()
                                .color(Color32::from_rgb(201, 209, 217)),
                        );
                        ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                            ui.label(
                                RichText::new("Actions")
                                    .strong()
                                    .color(Color32::from_rgb(201, 209, 217)),
                            );
                            ui.add_space(20.0);
                            ui.label(
                                RichText::new("Ping")
                                    .strong()
                                    .color(Color32::from_rgb(201, 209, 217)),
                            );
                            ui.add_space(20.0);
                            ui.label(
                                RichText::new("Tags")
                                    .strong()
                                    .color(Color32::from_rgb(201, 209, 217)),
                            );
                            ui.add_space(20.0);
                            ui.label(
                                RichText::new(tr(lang, "Dossier", "Folder"))
                                    .strong()
                                    .color(Color32::from_rgb(201, 209, 217)),
                            );
                            ui.add_space(20.0);
                            ui.label(
                                RichText::new(tr(lang, "Protocole", "Protocol"))
                                    .strong()
                                    .color(Color32::from_rgb(201, 209, 217)),
                            );
                        });
                    });
                });

            ui.separator();

            // Table Body
            egui::ScrollArea::vertical()
                .max_height(400.0)
                .auto_shrink([false, false])
                .show(ui, |ui| {
                    if filtered.is_empty() {
                        ui.add_space(30.0);
                        ui.vertical_centered(|ui| {
                            ui.label(
                                RichText::new(tr(
                                    lang,
                                    "\u{E30C} Aucune session ne correspond à vos filtres",
                                    "\u{E30C} No session matches your filters",
                                ))
                                .size(14.0)
                                .color(Color32::from_rgb(139, 148, 158)),
                            );
                            ui.add_space(8.0);
                            if ui
                                .button(tr(
                                    lang,
                                    "\u{E094} Réinitialiser tous les filtres",
                                    "\u{E094} Reset All Filters",
                                ))
                                .clicked()
                            {
                                self.dashboard_session_query.clear();
                                self.dashboard_protocol_filter = None;
                                self.dashboard_folder_filter = "Tous".to_string();
                                self.dashboard_online_only = false;
                                self.dashboard_offline_only = false;
                            }
                        });
                        ui.add_space(30.0);
                    } else {
                        for (idx, s) in filtered.iter().enumerate() {
                            let is_selected = self.selected_session_ids.contains(&s.id);
                            let (proto_tag, proto_color) = protocol_badge_style(s.protocol);
                            let probe = self.session_probes.get(&s.id);
                            let bg = if is_selected {
                                Color32::from_rgb(28, 42, 65)
                            } else if idx % 2 == 0 {
                                Color32::from_rgb(13, 17, 23)
                            } else {
                                Color32::from_rgb(17, 22, 30)
                            };

                            egui::Frame::NONE
                                .fill(bg)
                                .corner_radius(4.0)
                                .inner_margin(egui::Margin::symmetric(8, 6))
                                .stroke(Stroke::new(0.5, Color32::from_rgb(38, 44, 54)))
                                .show(ui, |ui| {
                                    ui.horizontal(|ui| {
                                        let mut sel = is_selected;
                                        if ui.checkbox(&mut sel, "").changed() {
                                            if sel {
                                                self.selected_session_ids.insert(s.id);
                                            } else {
                                                self.selected_session_ids.remove(&s.id);
                                            }
                                        }

                                        // Name + Host info
                                        ui.vertical(|ui| {
                                            ui.horizontal(|ui| {
                                                if ui
                                                    .button(
                                                        RichText::new(format!(
                                                            "{} {}",
                                                            s.icon_badge, s.name
                                                        ))
                                                        .strong()
                                                        .size(13.0)
                                                        .color(Color32::from_rgb(240, 246, 252)),
                                                    )
                                                    .on_hover_text(tr(
                                                        lang,
                                                        "Cliquer pour vous connecter à cette session",
                                                        "Click to connect to this session",
                                                    ))
                                                    .clicked()
                                                {
                                                    session_to_launch = Some((*s).clone());
                                                }
                                            });
                                            let target_info =
                                                if s.protocol == ProtocolType::LocalShell {
                                                    s.local_shell_cmd.clone()
                                                } else if s.username.is_empty() {
                                                    format!("{}:{}", s.host, s.port)
                                                } else {
                                                    format!("{}@{}:{}", s.username, s.host, s.port)
                                                };
                                            ui.label(
                                                RichText::new(target_info)
                                                    .size(10.5)
                                                    .monospace()
                                                    .color(Color32::from_rgb(110, 118, 129)),
                                            );
                                        });

                                        // Right aligned info & actions
                                        ui.with_layout(
                                            Layout::right_to_left(Align::Center),
                                            |ui| {
                                                // Action buttons
                                                if ui
                                                    .small_button("\u{E4A6}")
                                                    .on_hover_text(tr(
                                                        lang,
                                                        "Supprimer la session",
                                                        "Delete session",
                                                    ))
                                                    .clicked()
                                                {
                                                    session_to_del = Some(s.id);
                                                }
                                                if ui
                                                    .small_button("\u{E710}")
                                                    .on_hover_text(tr(
                                                        lang,
                                                        "Dupliquer la session",
                                                        "Duplicate session",
                                                    ))
                                                    .clicked()
                                                {
                                                    session_to_dup = Some(s.id);
                                                }
                                                if ui
                                                    .small_button("\u{E270}")
                                                    .on_hover_text(tr(
                                                        lang,
                                                        "Configurer la session",
                                                        "Configure session",
                                                    ))
                                                    .clicked()
                                                {
                                                    session_to_edit = Some((*s).clone());
                                                }
                                                if let SshAuthMethod::PrivateKeyFile {
                                                    key_path,
                                                    ..
                                                } = &s.ssh_auth
                                                    && !key_path.is_empty()
                                                    && ui
                                                        .small_button("\u{E2D6}")
                                                        .on_hover_text(tr(
                                                            lang,
                                                            "Charger la clé .ppk dans Pageant",
                                                            "Load .ppk key into Pageant",
                                                        ))
                                                        .clicked()
                                                {
                                                    ppk_to_load = Some(key_path.clone());
                                                }
                                                if ui
                                                    .button(
                                                        RichText::new("\u{E3FE}")
                                                            .strong()
                                                            .color(Color32::from_rgb(
                                                                88, 166, 255,
                                                            )),
                                                    )
                                                    .on_hover_text(tr(
                                                        lang,
                                                        "Connecter immédiatement",
                                                        "Connect immediately",
                                                    ))
                                                    .clicked()
                                                {
                                                    session_to_launch = Some((*s).clone());
                                                }

                                                ui.add_space(14.0);

                                                // Ping badge
                                                if let Some(p) = probe {
                                                    let (txt, col) = if p.reachable {
                                                        (
                                                            format!("● {}ms", p.latency_ms),
                                                            Color32::from_rgb(63, 185, 80),
                                                        )
                                                    } else {
                                                        (
                                                            "● Offline".to_string(),
                                                            Color32::from_rgb(248, 81, 73),
                                                        )
                                                    };
                                                    ui.label(
                                                        RichText::new(txt)
                                                            .size(11.0)
                                                            .monospace()
                                                            .color(col),
                                                    )
                                                    .on_hover_text(&p.banner);
                                                } else {
                                                    ui.label(
                                                        RichText::new("○ --")
                                                            .size(11.0)
                                                            .monospace()
                                                            .color(Color32::from_rgb(
                                                                110, 118, 129,
                                                            )),
                                                    );
                                                }

                                                ui.add_space(14.0);

                                                // Tags badges
                                                if !s.tags.is_empty() {
                                                    for t in s.tags.iter().take(2) {
                                                        egui::Frame::NONE
                                                            .fill(Color32::from_rgb(13, 27, 42))
                                                            .corner_radius(egui::CornerRadius::same(
                                                                3,
                                                            ))
                                                            .inner_margin(egui::Margin::symmetric(
                                                                4, 1,
                                                            ))
                                                            .stroke(Stroke::new(
                                                                0.5,
                                                                Color32::from_rgb(40, 75, 99),
                                                            ))
                                                            .show(ui, |ui| {
                                                                ui.label(
                                                                    RichText::new(format!("#{t}"))
                                                                        .size(10.0)
                                                                        .color(Color32::from_rgb(
                                                                            88, 166, 255,
                                                                        )),
                                                                );
                                                            });
                                                    }
                                                    if s.tags.len() > 2 {
                                                        ui.label(
                                                            RichText::new(format!(
                                                                "+{}",
                                                                s.tags.len() - 2
                                                            ))
                                                            .size(10.0)
                                                            .color(Color32::from_rgb(
                                                                110, 118, 129,
                                                            )),
                                                        );
                                                    }
                                                } else {
                                                    ui.label(
                                                        RichText::new("-")
                                                            .size(10.0)
                                                            .color(Color32::from_rgb(
                                                                110, 118, 129,
                                                            )),
                                                    );
                                                }

                                                ui.add_space(14.0);

                                                // Folder badge
                                                ui.label(
                                                    RichText::new(format!("\u{E24A} {}", s.folder))
                                                        .size(11.0)
                                                        .color(Color32::from_rgb(139, 148, 158)),
                                                );

                                                ui.add_space(14.0);

                                                // Protocol badge
                                                egui::Frame::NONE
                                                    .fill(proto_color.gamma_multiply(0.18))
                                                    .corner_radius(egui::CornerRadius::same(3))
                                                    .inner_margin(egui::Margin::symmetric(5, 2))
                                                    .stroke(Stroke::new(
                                                        0.6,
                                                        proto_color.gamma_multiply(0.55),
                                                    ))
                                                    .show(ui, |ui| {
                                                        ui.label(
                                                            RichText::new(proto_tag)
                                                                .size(10.0)
                                                                .monospace()
                                                                .strong()
                                                                .color(proto_color),
                                                        );
                                                    });
                                            },
                                        );
                                    });
                                });
                            ui.add_space(2.0);
                        }
                    }
                });

            ui.add_space(10.0);
            ui.separator();
            ui.horizontal(|ui| {
                ui.label(
                    RichText::new(format!(
                        "{}: {} | {}: {}",
                        tr(lang, "Total", "Total"),
                        self.config.sessions.len(),
                        tr(lang, "Affichées", "Shown"),
                        filtered.len()
                    ))
                    .size(11.5)
                    .color(Color32::from_rgb(139, 148, 158)),
                );
                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                    if ui.button(tr(lang, "Fermer", "Close")).clicked() {
                        close_requested = true;
                    }
                });
            });
        });

        if !open || close_requested {
            self.show_session_manager = false;
        }

        if let Some(s) = session_to_launch {
            self.show_session_manager = false;
            self.launch_session(s);
        }
        if let Some(s) = session_to_edit {
            self.editing_session = s;
            self.is_new_session = false;
            self.editor_tab = ConfigEditorTab::ConnectionAndKey;
            self.show_session_editor = true;
        }
        if let Some(id) = session_to_dup
            && let Some(dup) = self.config.duplicate_session(id)
        {
            self.set_toast(format!(
                "{} '{}' !",
                tr(lang, "Session dupliquée :", "Duplicated session:"),
                dup.name
            ));
        }
        if let Some(id) = session_to_del {
            let name = self
                .config
                .sessions
                .iter()
                .find(|s| s.id == id)
                .map(|s| s.name.clone())
                .unwrap_or_default();
            if self.config.delete_session(id) {
                self.selected_session_ids.remove(&id);
                self.set_toast(format!(
                    "{} '{}'.",
                    tr(lang, "Session supprimée :", "Deleted session:"),
                    name
                ));
            }
        }
        if let Some(kp) = ppk_to_load {
            let pageant_exe = self.resolve_pageant_path();
            match launch_pageant_with_keys(&pageant_exe, &[kp]) {
                Ok(msg) => {
                    self.set_toast(msg);
                    self.refresh_agent_keys();
                }
                Err(e) => self.set_toast(format!(
                    "{} {}",
                    tr(lang, "Erreur Pageant :", "Pageant Error:"),
                    e
                )),
            }
        }
    }
}

#[derive(Clone, Copy)]
enum PaletteAction {
    NewSession,
    OpenHelp,
    OpenKeyManager,
    LoadAllPpksToPageant,
    OpenNetworkTools,
    OpenAbout,
    LaunchPowershell,
    ProbeAll,
    DuplicateActiveTab,
    CloseActiveTab,
}
