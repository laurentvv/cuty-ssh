//! SFTP Client module for cuty-ssh.
//!
//! Provides a full-featured, integrated double-pane SFTP explorer:
//! - Dual-pane browser (Local files on left, Remote files on right)
//! - Upload & Download transfer queues with status and progress
//! - Comprehensive right-click context menu (Download/Upload, Open, Edit,
//!   Choose editor, Move to, Rename, Erase, SHA-256 hashes, Symlinks, Copy path, Properties/Chmod)
//! - Auto-upload on save (Ctrl+S) for edited remote files
//! - External editor configuration (Bitvise #450) with presets & file picker
//! - Collision resolution dialog (Bitvise #415: Overwrite/Resume/Rename/Skip)
//! - Folder Mirror / Synchronization tool (Bitvise #477)
//! - Remote & Local Bookmarks / Signets (WinSCP Bookmarks)
//! - Strict bilingual FR / EN localization (zero mixed languages)

use crate::config::UiLanguage;
use crate::protocols::{BackendCommand, SftpFileEntry};
use crate::ui::help_modal::tr;
use crate::ui::terminal_view::format_bytes;
use egui::{Align, Color32, Context, Layout, RichText, ScrollArea, Stroke, Ui};
use std::collections::HashSet;
use std::path::PathBuf;
use std::time::UNIX_EPOCH;
use tokio::sync::mpsc::UnboundedSender;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SftpClientTab {
    Browse,
    UploadQueue,
    DownloadQueue,
    Log,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransferMode {
    Binary,
    Text,
    Auto,
}

impl TransferMode {
    pub fn label(self, lang: UiLanguage) -> &'static str {
        match (self, lang) {
            (Self::Binary, UiLanguage::French) => "Binaire",
            (Self::Binary, _) => "Binary",
            (Self::Text, UiLanguage::French) => "Texte",
            (Self::Text, _) => "Text",
            (Self::Auto, UiLanguage::French) => "Auto",
            (Self::Auto, _) => "Auto",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExistingFileRule {
    Ask,
    Overwrite,
    Skip,
    Resume,
}

impl ExistingFileRule {
    pub fn label(self, lang: UiLanguage) -> &'static str {
        match self {
            Self::Ask => tr(lang, "Demander si existe", "Ask if file exists"),
            Self::Overwrite => tr(lang, "Écraser", "Overwrite"),
            Self::Skip => tr(lang, "Ignorer", "Skip"),
            Self::Resume => tr(lang, "Reprendre", "Resume"),
        }
    }
}

#[derive(Debug, Clone)]
pub struct LocalFileEntry {
    pub name: String,
    pub path: PathBuf,
    pub is_dir: bool,
    pub is_symlink: bool,
    pub size: u64,
    pub mtime: u64,
    pub file_type: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QueueTaskStatus {
    Pending,
    InProgress,
    Paused,
    Completed,
    Error,
}

#[derive(Debug, Clone)]
pub struct QueueTask {
    pub id: u64,
    pub filename: String,
    pub local_path: PathBuf,
    pub remote_path: String,
    pub size: u64,
    pub transferred: u64,
    pub is_upload: bool,
    pub status: QueueTaskStatus,
}

/// Payload carried by an egui drag-and-drop between the two file panes.
#[derive(Debug, Clone)]
pub struct SftpDragPayload {
    /// Entry names being dragged (the whole selection when the dragged row is part of it).
    pub names: Vec<String>,
    /// `true` when the drag started from the remote pane (drop = download).
    pub from_remote: bool,
}

/// Names a drag should carry: the whole selection when the dragged entry is
/// part of it, otherwise just the dragged entry (file-manager behaviour).
fn dragged_names(selected: &HashSet<String>, name: &str) -> Vec<String> {
    if selected.contains(name) {
        let mut names: Vec<String> = selected.iter().cloned().collect();
        names.sort();
        names
    } else {
        vec![name.to_string()]
    }
}

/// Windows file-manager Shift+click semantics on the visible row list.
///
/// - No anchor (or anchor no longer visible): plain-click behaviour — replace
///   the selection (keep it when `additive`) with the clicked entry, which
///   becomes the new anchor.
/// - Valid anchor: select the inclusive anchor→clicked range in display
///   order. `additive` (Ctrl+Shift+click) extends the existing selection
///   instead of replacing it; the anchor stays put.
fn apply_range_selection(
    selected: &mut HashSet<String>,
    anchor: &mut Option<String>,
    visible: &[String],
    clicked: &str,
    additive: bool,
) {
    let range = anchor
        .as_deref()
        .and_then(|a| visible.iter().position(|n| n == a))
        .zip(visible.iter().position(|n| n == clicked))
        .map(|(a, c)| (a.min(c), a.max(c)));

    match range {
        Some((lo, hi)) => {
            if !additive {
                selected.clear();
            }
            selected.extend(visible[lo..=hi].iter().cloned());
            // Anchor stays at its original position across Shift+clicks.
        }
        None => {
            if !additive {
                selected.clear();
            }
            selected.insert(clicked.to_string());
            *anchor = Some(clicked.to_string());
        }
    }
}

#[derive(Debug, Clone)]
pub struct SftpLogEntry {
    pub timestamp: String,
    pub message: String,
    pub is_error: bool,
}

/// Answer picked in the collision dialog. The `*All` variants apply to the
/// current file AND every queued collision behind it.
#[derive(Debug, Clone)]
enum CollisionChoice {
    Overwrite,
    Resume,
    Rename(String),
    Skip,
    OverwriteAll,
    SkipAll,
}

#[derive(Debug, Clone)]
pub struct RenameModal {
    pub is_remote: bool,
    pub current_full_path: String,
    pub new_name: String,
}

#[derive(Debug, Clone)]
pub struct MoveModal {
    pub is_remote: bool,
    pub current_full_path: String,
    pub destination_dir: String,
}

#[derive(Debug, Clone)]
pub struct SymlinkModal {
    pub target_path: String,
    pub link_name: String,
}

#[derive(Debug, Clone)]
pub struct WatchedEditFile {
    pub local_path: PathBuf,
    pub remote_path: String,
    pub last_mtime: u64,
    pub last_size: u64,
    pub open_editor_when_ready: bool,
    pub use_default_app: bool,
}

#[derive(Debug, Clone)]
pub struct CollisionModal {
    pub is_upload: bool,
    pub filename: String,
    pub local_path: PathBuf,
    pub remote_path: String,
    pub local_size: u64,
    pub local_mtime: u64,
    pub remote_size: u64,
    pub remote_mtime: u64,
    pub new_name: String,
}

pub struct SftpClientState {
    pub active_tab: SftpClientTab,
    pub transfer_mode: TransferMode,
    pub existing_file_rule: ExistingFileRule,
    pub queue_paused: bool,

    // Local pane
    pub local_path: PathBuf,
    pub local_path_input: String,
    pub local_filter: String,
    pub local_entries: Vec<LocalFileEntry>,
    pub local_selected: HashSet<String>,
    /// Shift+click range anchor (entry name), reset on every plain click.
    pub local_anchor: Option<String>,
    pub local_sort_col: SftpCol,
    pub local_sort_asc: bool,
    pub local_folders_first: bool,
    pub local_new_folder_name: String,
    pub show_local_mkdir: bool,
    pub local_bookmarks: Vec<PathBuf>,

    // Remote pane extra controls
    pub remote_filter: String,
    pub remote_selected: HashSet<String>,
    /// Shift+click range anchor (entry name), reset on every plain click.
    pub remote_anchor: Option<String>,
    pub remote_sort_col: SftpCol,
    pub remote_sort_asc: bool,
    pub remote_folders_first: bool,
    pub remote_new_folder_name: String,
    pub show_remote_mkdir: bool,
    pub remote_bookmarks: Vec<String>,

    // Transfer Queues
    pub next_task_id: u64,
    pub upload_queue: Vec<QueueTask>,
    pub download_queue: Vec<QueueTask>,

    // Operation logs
    pub logs: Vec<SftpLogEntry>,

    // Sub-dialogs
    pub rename_modal: Option<RenameModal>,
    pub move_modal: Option<MoveModal>,
    pub symlink_modal: Option<SymlinkModal>,
    pub delete_confirm: Option<(bool, String, bool)>, // (is_remote, path, is_dir)
    pub collision_modal: Option<CollisionModal>,
    /// Collisions waiting for their turn behind the open `collision_modal`
    /// (rule "Ask"): every file of a multi-selection gets resolved, never
    /// silently dropped.
    pub pending_collisions: Vec<CollisionModal>,

    // External editor configuration
    pub editor_path: String,
    pub show_editor_modal: bool,

    // Integration triggers for parent tab
    pub props_request: Option<SftpFileEntry>,
    pub mirror_request: bool,

    // Watched files for auto-upload on save (Ctrl+S)
    pub watched_files: Vec<WatchedEditFile>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SftpCol {
    Name,
    Size,
    Type,
    Date,
}

impl Default for SftpClientState {
    fn default() -> Self {
        Self::new()
    }
}

impl SftpClientState {
    pub fn new() -> Self {
        let initial_local = std::env::var("USERPROFILE")
            .map(PathBuf::from)
            .unwrap_or_else(|_| std::env::current_dir().unwrap_or_else(|_| PathBuf::from("C:\\")));

        let mut local_bms = vec![initial_local.clone()];
        if let Ok(userprofile) = std::env::var("USERPROFILE") {
            let p = PathBuf::from(userprofile);
            let desktop = p.join("Desktop");
            let docs = p.join("Documents");
            let downloads = p.join("Downloads");
            if desktop.exists() {
                local_bms.push(desktop);
            }
            if docs.exists() {
                local_bms.push(docs);
            }
            if downloads.exists() {
                local_bms.push(downloads);
            }
        }

        let mut state = Self {
            active_tab: SftpClientTab::Browse,
            transfer_mode: TransferMode::Binary,
            existing_file_rule: ExistingFileRule::Ask,
            queue_paused: false,

            local_path: initial_local.clone(),
            local_path_input: initial_local.to_string_lossy().to_string(),
            local_filter: String::new(),
            local_entries: Vec::new(),
            local_selected: HashSet::new(),
            local_anchor: None,
            local_sort_col: SftpCol::Name,
            local_sort_asc: true,
            local_folders_first: true,
            local_new_folder_name: String::new(),
            show_local_mkdir: false,
            local_bookmarks: local_bms,

            remote_filter: String::new(),
            remote_selected: HashSet::new(),
            remote_anchor: None,
            remote_sort_col: SftpCol::Name,
            remote_sort_asc: true,
            remote_folders_first: true,
            remote_new_folder_name: String::new(),
            show_remote_mkdir: false,
            remote_bookmarks: vec![
                "/root".to_string(),
                "/var/www".to_string(),
                "/etc".to_string(),
                "/tmp".to_string(),
                "~".to_string(),
            ],

            next_task_id: 1,
            upload_queue: Vec::new(),
            download_queue: Vec::new(),
            logs: Vec::new(),

            rename_modal: None,
            move_modal: None,
            symlink_modal: None,
            delete_confirm: None,
            collision_modal: None,
            pending_collisions: Vec::new(),

            editor_path: "notepad.exe".to_string(),
            show_editor_modal: false,

            props_request: None,
            mirror_request: false,

            watched_files: Vec::new(),
        };

        state.refresh_local();
        state.log("Session SFTP Client initialisée", false);
        state
    }

    pub fn log(&mut self, msg: impl Into<String>, is_error: bool) {
        let now = chrono::Local::now().format("%H:%M:%S").to_string();
        self.logs.push(SftpLogEntry {
            timestamp: now,
            message: msg.into(),
            is_error,
        });
        if self.logs.len() > 500 {
            self.logs.drain(0..100);
        }
    }

    pub fn refresh_local(&mut self) {
        self.local_entries.clear();
        let path = self.local_path.clone();
        self.local_path_input = path.to_string_lossy().to_string();

        if let Ok(dir_entries) = std::fs::read_dir(&path) {
            for entry in dir_entries.flatten() {
                let name = entry.file_name().to_string_lossy().to_string();
                let entry_path = entry.path();
                let meta = entry.metadata().ok();

                let is_dir = meta.as_ref().map(|m| m.is_dir()).unwrap_or(false);
                let is_symlink = meta.as_ref().map(|m| m.is_symlink()).unwrap_or(false);
                let size = if is_dir {
                    0
                } else {
                    meta.as_ref().map(|m| m.len()).unwrap_or(0)
                };

                let mtime = meta
                    .and_then(|m| m.modified().ok())
                    .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
                    .map(|d| d.as_secs())
                    .unwrap_or(0);

                let file_type = if is_dir {
                    "Dossier".to_string()
                } else if let Some(ext) = entry_path.extension() {
                    let ext_str = ext.to_string_lossy().to_lowercase();
                    match ext_str.as_str() {
                        "png" | "jpg" | "jpeg" | "gif" | "webp" | "bmp" => {
                            "Fichier image".to_string()
                        }
                        "pdf" => "Document PDF".to_string(),
                        "txt" | "md" | "rst" | "log" => "Document texte".to_string(),
                        "zip" | "tar" | "gz" | "tgz" | "7z" | "rar" => "Archive".to_string(),
                        "exe" => "Application".to_string(),
                        "dll" => "Extension".to_string(),
                        "lnk" => "Raccourci".to_string(),
                        "rs" | "py" | "js" | "ts" | "c" | "cpp" | "h" | "json" | "toml"
                        | "yaml" | "yml" => "Code source".to_string(),
                        _ => format!("Fichier {}", ext_str.to_uppercase()),
                    }
                } else {
                    "Fichier".to_string()
                };

                self.local_entries.push(LocalFileEntry {
                    name,
                    path: entry_path,
                    is_dir,
                    is_symlink,
                    size,
                    mtime,
                    file_type,
                });
            }
        }

        self.sort_local();
    }

    pub fn sort_local(&mut self) {
        let col = self.local_sort_col;
        let asc = self.local_sort_asc;
        let folders_first = self.local_folders_first;

        self.local_entries.sort_by(|a, b| {
            if folders_first && a.is_dir != b.is_dir {
                return if a.is_dir {
                    std::cmp::Ordering::Less
                } else {
                    std::cmp::Ordering::Greater
                };
            }
            let ord = match col {
                SftpCol::Name => a.name.to_lowercase().cmp(&b.name.to_lowercase()),
                SftpCol::Size => a.size.cmp(&b.size),
                SftpCol::Type => a.file_type.cmp(&b.file_type),
                SftpCol::Date => a.mtime.cmp(&b.mtime),
            };
            if asc { ord } else { ord.reverse() }
        });
    }

    pub fn navigate_local_up(&mut self) {
        if let Some(parent) = self.local_path.parent() {
            self.local_path = parent.to_path_buf();
            self.local_selected.clear();
            self.local_anchor = None;
            self.refresh_local();
        }
    }

    pub fn navigate_local_home(&mut self) {
        if let Ok(home) = std::env::var("USERPROFILE") {
            self.local_path = PathBuf::from(home);
            self.local_selected.clear();
            self.local_anchor = None;
            self.refresh_local();
        }
    }

    /// Checks files being edited: launches editor upon initial download completion,
    /// and automatically re-uploads the file to the remote server whenever saved (Ctrl+S).
    pub fn check_watched_files(
        &mut self,
        ctx: &Context,
        cmd_tx: &UnboundedSender<BackendCommand>,
        lang: UiLanguage,
    ) {
        if self.watched_files.is_empty() {
            return;
        }

        // Request repaint so saves (Ctrl+S) or finished downloads are detected promptly
        ctx.request_repaint_after(std::time::Duration::from_millis(300));

        let mut to_upload: Vec<(PathBuf, String)> = Vec::new();
        let mut to_open: Vec<(PathBuf, bool)> = Vec::new();

        for item in &mut self.watched_files {
            if let Ok(meta) = std::fs::metadata(&item.local_path) {
                let current_mtime = meta
                    .modified()
                    .ok()
                    .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
                    .map(|d| d.as_secs())
                    .unwrap_or(0);
                let current_size = meta.len();

                // If file just finished downloading, launch editor
                if item.open_editor_when_ready {
                    item.open_editor_when_ready = false;
                    item.last_mtime = current_mtime;
                    item.last_size = current_size;
                    to_open.push((item.local_path.clone(), item.use_default_app));
                    continue;
                }

                // If user modified and saved the file (Ctrl+S)
                if current_mtime > item.last_mtime
                    || (current_mtime == item.last_mtime
                        && current_size != item.last_size
                        && current_size > 0)
                {
                    item.last_mtime = current_mtime;
                    item.last_size = current_size;
                    to_upload.push((item.local_path.clone(), item.remote_path.clone()));
                }
            }
        }

        for (path, use_def) in to_open {
            if use_def {
                let _ = open::that(&path);
                self.log(
                    tr(
                        lang,
                        &format!("Fichier ouvert : {}", path.display()),
                        &format!("File opened: {}", path.display()),
                    ),
                    false,
                );
            } else {
                let ed = if self.editor_path.trim().is_empty() {
                    "notepad.exe"
                } else {
                    self.editor_path.trim()
                };
                let _ = std::process::Command::new(ed).arg(&path).spawn();
                self.log(
                    tr(
                        lang,
                        &format!("Éditeur ({ed}) ouvert pour : {}", path.display()),
                        &format!("Editor ({ed}) opened for: {}", path.display()),
                    ),
                    false,
                );
            }
        }

        for (local, remote) in to_upload {
            let _ = cmd_tx.send(BackendCommand::SftpUpload {
                local_path: local.clone(),
                remote_path: remote.clone(),
            });
            let filename = local
                .file_name()
                .map(|n| n.to_string_lossy().to_string())
                .unwrap_or_default();
            self.log(
                tr(
                    lang,
                    &format!("💾 Sauvegarde détectée (Ctrl+S) sur {filename} -> Téléversement automatique vers {remote} !"),
                    &format!("💾 Save detected (Ctrl+S) on {filename} -> Auto-uploading to {remote}!"),
                ),
                false,
            );
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub fn render(
        &mut self,
        ui: &mut Ui,
        ctx: &Context,
        lang: UiLanguage,
        remote_path: &str,
        remote_entries: &[SftpFileEntry],
        cmd_tx: &UnboundedSender<BackendCommand>,
        close_requested: &mut bool,
    ) {
        // Run active edit watcher check
        self.check_watched_files(ctx, cmd_tx, lang);

        // Top Toolbar: Tabs + Mirror / Sync + Refresh + Back to terminal
        egui::Frame::NONE
            .fill(Color32::from_rgb(18, 24, 38))
            .inner_margin(egui::Margin::symmetric(10, 6))
            .stroke(Stroke::new(1.0, Color32::from_rgb(38, 44, 54)))
            .show(ui, |ui| {
                ui.horizontal(|ui| {
                    ui.label(
                        RichText::new("📁 SFTP Client")
                            .strong()
                            .size(15.0)
                            .color(Color32::from_rgb(88, 166, 255)),
                    );

                    ui.add_space(12.0);

                    // Tab buttons
                    let browse_active = self.active_tab == SftpClientTab::Browse;
                    if ui
                        .selectable_label(
                            browse_active,
                            RichText::new(tr(lang, "🔍 Parcourir", "🔍 Browse")).strong(),
                        )
                        .clicked()
                    {
                        self.active_tab = SftpClientTab::Browse;
                    }

                    let up_count = self
                        .upload_queue
                        .iter()
                        .filter(|t| t.status == QueueTaskStatus::InProgress || t.status == QueueTaskStatus::Pending)
                        .count();
                    let up_title = tr(lang, "File d'attente d'envoi", "Upload queue");
                    let up_label = if up_count > 0 {
                        format!("⬆ {up_title} ({up_count})")
                    } else {
                        format!("⬆ {up_title}")
                    };
                    if ui
                        .selectable_label(self.active_tab == SftpClientTab::UploadQueue, up_label)
                        .clicked()
                    {
                        self.active_tab = SftpClientTab::UploadQueue;
                    }

                    let dl_count = self
                        .download_queue
                        .iter()
                        .filter(|t| t.status == QueueTaskStatus::InProgress || t.status == QueueTaskStatus::Pending)
                        .count();
                    let dl_title = tr(lang, "File d'attente de réception", "Download queue");
                    let dl_label = if dl_count > 0 {
                        format!("⬇ {dl_title} ({dl_count})")
                    } else {
                        format!("⬇ {dl_title}")
                    };
                    if ui
                        .selectable_label(self.active_tab == SftpClientTab::DownloadQueue, dl_label)
                        .clicked()
                    {
                        self.active_tab = SftpClientTab::DownloadQueue;
                    }

                    let log_title = tr(lang, "📋 Journal", "📋 Log");
                    if ui
                        .selectable_label(self.active_tab == SftpClientTab::Log, log_title)
                        .clicked()
                    {
                        self.active_tab = SftpClientTab::Log;
                    }

                    ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                        if ui
                            .button(
                                RichText::new(tr(
                                    lang,
                                    "📟 Revenir au Terminal",
                                    "📟 Back to Terminal",
                                ))
                                .color(Color32::from_rgb(201, 209, 217)),
                            )
                            .on_hover_text(tr(
                                lang,
                                "Bascule vers la session terminal (le shell reste actif en tâche de fond)",
                                "Switch back to the terminal (shell continues in the background)",
                            ))
                            .clicked()
                        {
                            *close_requested = true;
                        }

                        if ui
                            .small_button(tr(lang, "🔄 Actualiser", "🔄 Refresh"))
                            .on_hover_text(tr(lang, "Actualiser volet local et distant", "Refresh both panes"))
                            .clicked()
                        {
                            self.refresh_local();
                            let _ = cmd_tx.send(BackendCommand::SftpListDir(remote_path.to_string()));
                            self.log(tr(lang, "Actualisation des dossiers effectuée", "Directories refreshed"), false);
                        }

                        // Mirror / Sync Tool Button
                        if ui
                            .button(RichText::new(tr(lang, "🔄 Miroir / Synchro", "🔄 Mirror / Sync")).color(Color32::from_rgb(56, 189, 248)))
                            .on_hover_text(tr(lang, "Ouvrir l'outil de synchronisation miroir", "Open folder mirror sync tool"))
                            .clicked()
                        {
                            self.mirror_request = true;
                        }

                        // External Editor Button
                        if ui
                            .small_button(tr(lang, "⚙ Éditeur", "⚙ Editor"))
                            .on_hover_text(tr(lang, "Configurer l'éditeur externe", "Configure external editor"))
                            .clicked()
                        {
                            self.show_editor_modal = true;
                        }
                    });
                });
            });

        ui.add_space(4.0);

        match self.active_tab {
            SftpClientTab::Browse => {
                self.render_browse_view(ui, lang, remote_path, remote_entries, cmd_tx);
            }
            SftpClientTab::UploadQueue => {
                self.render_upload_queue_tab(ui, lang);
            }
            SftpClientTab::DownloadQueue => {
                self.render_download_queue_tab(ui, lang);
            }
            SftpClientTab::Log => {
                self.render_log_tab(ui, lang);
            }
        }

        self.render_modals(ctx, lang, cmd_tx);
    }

    #[allow(clippy::too_many_arguments)]
    fn render_browse_view(
        &mut self,
        ui: &mut Ui,
        lang: UiLanguage,
        remote_path: &str,
        remote_entries: &[SftpFileEntry],
        cmd_tx: &UnboundedSender<BackendCommand>,
    ) {
        let mut cd_local_into: Option<PathBuf> = None;
        let mut cd_remote_into: Option<String> = None;
        let mut launch_upload: Option<Vec<PathBuf>> = None;
        let mut launch_download: Option<Vec<String>> = None;

        let total_avail_h = ui.available_height();
        let total_avail_w = ui.available_width();
        let half_w = ((total_avail_w - 8.0) / 2.0).floor();

        // Pre-sort remote entries according to active sort column & direction
        let mut sorted_remote: Vec<&SftpFileEntry> = remote_entries.iter().collect();
        let col = self.remote_sort_col;
        let asc = self.remote_sort_asc;
        let folders_first = self.remote_folders_first;

        sorted_remote.sort_by(|a, b| {
            if folders_first && a.is_dir != b.is_dir {
                return if a.is_dir {
                    std::cmp::Ordering::Less
                } else {
                    std::cmp::Ordering::Greater
                };
            }
            let ord = match col {
                SftpCol::Name => a.name.to_lowercase().cmp(&b.name.to_lowercase()),
                SftpCol::Size => a.size.cmp(&b.size),
                SftpCol::Type => {
                    let a_type = if a.is_dir {
                        "0"
                    } else if a.is_symlink {
                        "1"
                    } else {
                        "2"
                    };
                    let b_type = if b.is_dir {
                        "0"
                    } else if b.is_symlink {
                        "1"
                    } else {
                        "2"
                    };
                    a_type
                        .cmp(b_type)
                        .then_with(|| a.name.to_lowercase().cmp(&b.name.to_lowercase()))
                }
                SftpCol::Date => a.mtime.cmp(&b.mtime),
            };
            if asc { ord } else { ord.reverse() }
        });

        // Use strict 2-column layout with enforced max_width so neither column can push the other
        ui.columns(2, |columns| {
            // ==================== LEFT COLUMN: LOCAL FILES ====================
            let col_left = &mut columns[0];
            col_left.set_max_width(half_w);
            let left_pane = egui::Frame::NONE
                .fill(Color32::from_rgb(13, 17, 23))
                .corner_radius(4.0)
                .inner_margin(egui::Margin::same(6))
                .stroke(Stroke::new(1.0, Color32::from_rgb(38, 44, 54)))
                .show(col_left, |ui| {
                    ui.set_min_height(total_avail_h);

                    // Header: Title & Filter
                    ui.horizontal(|ui| {
                        ui.label(
                            RichText::new(tr(lang, "Fichiers locaux", "Local files"))
                                .strong()
                                .size(13.0)
                                .color(Color32::from_rgb(88, 166, 255)),
                        );
                        ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                            ui.add(
                                egui::TextEdit::singleline(&mut self.local_filter)
                                    .hint_text(tr(lang, "Filtrer...", "Filter..."))
                                    .desired_width(110.0),
                            );
                            ui.label(
                                RichText::new(tr(lang, "Filtre :", "Filter:"))
                                    .small()
                                    .color(Color32::from_rgb(139, 148, 158)),
                            );
                        });
                    });

                    ui.add_space(2.0);

                    // Local Toolbar: Up, New Folder, Refresh, Home, Bookmarks, Path Box
                    ui.horizontal(|ui| {
                        if ui
                            .small_button("\u{E08E}")
                            .on_hover_text(tr(lang, "Dossier parent", "Parent folder"))
                            .clicked()
                        {
                            self.navigate_local_up();
                        }
                        if ui
                            .small_button("\u{E24A}+")
                            .on_hover_text(tr(lang, "Nouveau dossier local", "New local folder"))
                            .clicked()
                        {
                            self.show_local_mkdir = !self.show_local_mkdir;
                        }
                        if ui
                            .small_button("\u{E094}")
                            .on_hover_text(tr(lang, "Rafraîchir", "Refresh"))
                            .clicked()
                        {
                            self.refresh_local();
                        }
                        if ui
                            .small_button("\u{E072}")
                            .on_hover_text(tr(lang, "Home (Profil utilisateur)", "Home directory"))
                            .clicked()
                        {
                            self.navigate_local_home();
                        }

                        // Local Bookmarks Menu
                        ui.menu_button("📑", |ui| {
                            ui.label(RichText::new(tr(lang, "Signets locaux :", "Local bookmarks:")).strong().small());
                            let mut to_nav: Option<PathBuf> = None;
                            let mut to_remove: Option<usize> = None;
                            for (idx, bm) in self.local_bookmarks.iter().enumerate() {
                                ui.horizontal(|ui| {
                                    if ui.button(bm.display().to_string()).clicked() {
                                        to_nav = Some(bm.clone());
                                        ui.close();
                                    }
                                    if ui.small_button("✖").clicked() {
                                        to_remove = Some(idx);
                                    }
                                });
                            }
                            if let Some(target) = to_nav {
                                cd_local_into = Some(target);
                            }
                            if let Some(idx) = to_remove.filter(|&i| i < self.local_bookmarks.len()) {
                                self.local_bookmarks.remove(idx);
                            }
                            ui.separator();
                            if ui.button(tr(lang, "➕ Ajouter le dossier actuel", "➕ Bookmark current folder")).clicked() {
                                if !self.local_bookmarks.contains(&self.local_path) {
                                    self.local_bookmarks.push(self.local_path.clone());
                                }
                                ui.close();
                            }
                        });

                        let text_w = (ui.available_width() - 48.0).max(60.0);
                        let mut p_str = self.local_path_input.clone();
                        let resp =
                            ui.add(egui::TextEdit::singleline(&mut p_str).desired_width(text_w));
                        let enter =
                            resp.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter));
                        self.local_path_input = p_str;

                        if ui.small_button(tr(lang, "Aller", "Go")).clicked() || enter {
                            let p = PathBuf::from(&self.local_path_input);
                            if p.is_dir() {
                                self.local_path = p;
                                self.refresh_local();
                            }
                        }
                    });

                    if self.show_local_mkdir {
                        ui.horizontal(|ui| {
                            ui.label(RichText::new(tr(lang, "Nom :", "Name:")).small());
                            ui.add(
                                egui::TextEdit::singleline(&mut self.local_new_folder_name)
                                    .desired_width(110.0),
                            );
                            if ui.small_button(tr(lang, "Créer", "Create")).clicked()
                                && !self.local_new_folder_name.trim().is_empty()
                            {
                                let new_dir =
                                    self.local_path.join(self.local_new_folder_name.trim());
                                let _ = std::fs::create_dir_all(&new_dir);
                                self.log(
                                    tr(
                                        lang,
                                        &format!("Dossier local créé : {}", new_dir.display()),
                                        &format!("Local folder created: {}", new_dir.display()),
                                    ),
                                    false,
                                );
                                self.local_new_folder_name.clear();
                                self.show_local_mkdir = false;
                                self.refresh_local();
                            }
                        });
                    }

                    ui.add_space(2.0);

                    // Column Headers (Total fixed: 60 + 65 + 100 + spacing + scrollbar = 270)
                    let pane_avail_w = ui.available_width();
                    let name_w = (pane_avail_w - 270.0).max(80.0);

                    ui.horizontal(|ui| {
                        ui.spacing_mut().item_spacing.x = 4.0;
                        let name_arr = if self.local_sort_col == SftpCol::Name {
                            if self.local_sort_asc { " ▲" } else { " ▼" }
                        } else {
                            ""
                        };
                        let name_title = format!("{}{name_arr}", tr(lang, "Nom", "Name"));
                        if ui
                            .add_sized(
                                [name_w, 18.0],
                                egui::Button::new("")
                                    .left_text(name_title)
                                    .selected(self.local_sort_col == SftpCol::Name),
                            )
                            .clicked()
                        {
                            if self.local_sort_col == SftpCol::Name {
                                self.local_sort_asc = !self.local_sort_asc;
                            } else {
                                self.local_sort_col = SftpCol::Name;
                                self.local_sort_asc = true;
                            }
                            self.sort_local();
                        }

                        let size_arr = if self.local_sort_col == SftpCol::Size {
                            if self.local_sort_asc { " ▲" } else { " ▼" }
                        } else {
                            ""
                        };
                        let size_title = format!("{}{size_arr}", tr(lang, "Taille", "Size"));
                        if ui
                            .add_sized(
                                [60.0, 18.0],
                                egui::Button::new(size_title)
                                    .selected(self.local_sort_col == SftpCol::Size),
                            )
                            .clicked()
                        {
                            if self.local_sort_col == SftpCol::Size {
                                self.local_sort_asc = !self.local_sort_asc;
                            } else {
                                self.local_sort_col = SftpCol::Size;
                                self.local_sort_asc = false;
                            }
                            self.sort_local();
                        }

                        let type_arr = if self.local_sort_col == SftpCol::Type {
                            if self.local_sort_asc { " ▲" } else { " ▼" }
                        } else {
                            ""
                        };
                        let type_title = format!("{}{type_arr}", tr(lang, "Type", "Type"));
                        if ui
                            .add_sized(
                                [65.0, 18.0],
                                egui::Button::new(type_title)
                                    .selected(self.local_sort_col == SftpCol::Type),
                            )
                            .clicked()
                        {
                            if self.local_sort_col == SftpCol::Type {
                                self.local_sort_asc = !self.local_sort_asc;
                            } else {
                                self.local_sort_col = SftpCol::Type;
                                self.local_sort_asc = true;
                            }
                            self.sort_local();
                        }

                        let date_arr = if self.local_sort_col == SftpCol::Date {
                            if self.local_sort_asc { " ▲" } else { " ▼" }
                        } else {
                            ""
                        };
                        let date_title = format!("{}{date_arr}", tr(lang, "Modifié le", "Date Mod"));
                        if ui
                            .add_sized(
                                [100.0, 18.0],
                                egui::Button::new(date_title)
                                    .selected(self.local_sort_col == SftpCol::Date),
                            )
                            .clicked()
                        {
                            if self.local_sort_col == SftpCol::Date {
                                self.local_sort_asc = !self.local_sort_asc;
                            } else {
                                self.local_sort_col = SftpCol::Date;
                                self.local_sort_asc = false;
                            }
                            self.sort_local();
                        }
                    });

                    ui.separator();

                    // Table Body with ScrollArea: auto_shrink(false) guarantees consistent full-height alignment
                    let scroll_h = (ui.available_height() - 36.0).max(80.0);
                    ScrollArea::vertical()
                        .id_salt("local_scroll_fixed")
                        .auto_shrink([false, false])
                        .min_scrolled_height(scroll_h)
                        .max_height(scroll_h)
                        .show(ui, |ui| {
                            let filter_lc = self.local_filter.trim().to_lowercase();
                            // Visible rows in display order — the Shift+click range space.
                            let visible_names: Vec<String> = self
                                .local_entries
                                .iter()
                                .filter(|e| {
                                    filter_lc.is_empty()
                                        || e.name.to_lowercase().contains(&filter_lc)
                                })
                                .map(|e| e.name.clone())
                                .collect();
                            for entry in &self.local_entries {
                                if !filter_lc.is_empty()
                                    && !entry.name.to_lowercase().contains(&filter_lc)
                                {
                                    continue;
                                }

                                let is_selected = self.local_selected.contains(&entry.name);
                                let icon = if entry.is_dir { "\u{E24A}" } else { "📄" };
                                let label_text = format!("{} {}", icon, entry.name);

                                ui.horizontal(|ui| {
                                    ui.spacing_mut().item_spacing.x = 4.0;
                                    let btn = ui.add_sized(
                                        [name_w, 18.0],
                                        egui::Button::new("")
                                            .left_text(RichText::new(label_text).color(
                                                if is_selected {
                                                    Color32::from_rgb(88, 166, 255)
                                                } else {
                                                    Color32::from_rgb(201, 209, 217)
                                                },
                                            ))
                                            .frame(is_selected)
                                            .selected(is_selected)
                                            .truncate()
                                            .sense(egui::Sense::click_and_drag()),
                                    );

                                    if btn.clicked() {
                                        let mods = ui.input(|i| i.modifiers);
                                        if mods.shift {
                                            apply_range_selection(
                                                &mut self.local_selected,
                                                &mut self.local_anchor,
                                                &visible_names,
                                                &entry.name,
                                                mods.ctrl,
                                            );
                                        } else if mods.ctrl {
                                            if is_selected {
                                                self.local_selected.remove(&entry.name);
                                            } else {
                                                self.local_selected.insert(entry.name.clone());
                                            }
                                            self.local_anchor = Some(entry.name.clone());
                                        } else {
                                            self.local_selected.clear();
                                            self.local_selected.insert(entry.name.clone());
                                            self.local_anchor = Some(entry.name.clone());
                                        }
                                    }
                                    if btn.double_clicked() && entry.is_dir {
                                        cd_local_into = Some(entry.path.clone());
                                    }

                                    // Drag & drop to the remote pane = upload.
                                    // A click stays a click: egui only decides "drag"
                                    // once the pointer moved past the click threshold.
                                    if btn.drag_started() && !is_selected {
                                        self.local_selected.clear();
                                        self.local_selected.insert(entry.name.clone());
                                        self.local_anchor = Some(entry.name.clone());
                                    }
                                    btn.dnd_set_drag_payload(SftpDragPayload {
                                        names: dragged_names(&self.local_selected, &entry.name),
                                        from_remote: false,
                                    });

                                    // Right-click context menu (Local file) - Strict FR / EN, zero mixed text
                                    btn.context_menu(|ui| {
                                        // Explorer semantics: right-clicking an entry that is
                                        // part of a multi-selection uploads the whole selection.
                                        let sel_count = self.local_selected.len();
                                        let in_selection =
                                            sel_count > 1 && self.local_selected.contains(&entry.name);
                                        let up_label = if in_selection {
                                            tr(
                                                lang,
                                                &format!("⬆ Téléverser la sélection ({sel_count})"),
                                                &format!("⬆ Upload selection ({sel_count})"),
                                            )
                                            .to_string()
                                        } else {
                                            tr(lang, "⬆ Téléverser", "⬆ Upload").to_string()
                                        };
                                        if ui.button(up_label).clicked() {
                                            let names =
                                                dragged_names(&self.local_selected, &entry.name);
                                            launch_upload = Some(
                                                names.into_iter().map(|n| self.local_path.join(n)).collect(),
                                            );
                                            ui.close();
                                        }
                                        if ui.button(tr(lang, "⏸ Mettre en pause dans la file", "⏸ Enqueue paused")).clicked() {
                                            ui.close();
                                        }
                                        ui.separator();
                                        if ui.button(tr(lang, "Ouvrir", "Open")).clicked() {
                                            let _ = open::that(&entry.path);
                                            ui.close();
                                        }
                                        if ui.button(tr(lang, "Éditer", "Edit")).clicked() {
                                            let ed = if self.editor_path.trim().is_empty() {
                                                "notepad.exe"
                                            } else {
                                                self.editor_path.trim()
                                            };
                                            let _ = std::process::Command::new(ed)
                                                .arg(&entry.path)
                                                .spawn();
                                            ui.close();
                                        }
                                        if ui.button(tr(lang, "Choisir l'éditeur...", "Choose editor...")).clicked() {
                                            self.show_editor_modal = true;
                                            ui.close();
                                        }
                                        if ui.button(tr(lang, "Renommer...", "Rename...")).clicked() {
                                            self.rename_modal = Some(RenameModal {
                                                is_remote: false,
                                                current_full_path: entry
                                                    .path
                                                    .to_string_lossy()
                                                    .to_string(),
                                                new_name: entry.name.clone(),
                                            });
                                            ui.close();
                                        }
                                        if ui.button(tr(lang, "Supprimer", "Delete")).clicked() {
                                            self.delete_confirm = Some((
                                                false,
                                                entry.path.to_string_lossy().to_string(),
                                                entry.is_dir,
                                            ));
                                            ui.close();
                                        }
                                        ui.separator();
                                        if ui.button(tr(lang, "Copier le chemin complet", "Copy full path")).clicked()
                                        {
                                            if let Ok(mut clip) = arboard::Clipboard::new() {
                                                let _ = clip.set_text(
                                                    entry.path.to_string_lossy().to_string(),
                                                );
                                            }
                                            ui.close();
                                        }
                                    });

                                    // Size
                                    let size_str = if entry.is_dir {
                                        "-".to_string()
                                    } else {
                                        format_bytes(entry.size)
                                    };
                                    ui.add_sized(
                                        [60.0, 18.0],
                                        egui::Label::new(
                                            RichText::new(size_str)
                                                .small()
                                                .monospace()
                                                .color(Color32::from_rgb(139, 148, 158)),
                                        ),
                                    );

                                    // Type (Localized)
                                    let type_label = format_entry_type(
                                        &entry.file_type,
                                        entry.is_dir,
                                        entry.is_symlink,
                                        lang,
                                    );
                                    ui.add_sized(
                                        [65.0, 18.0],
                                        egui::Label::new(
                                            RichText::new(type_label)
                                                .small()
                                                .color(Color32::from_rgb(110, 118, 129)),
                                        )
                                        .truncate(),
                                    );

                                    // Date
                                    let date_str = if entry.mtime > 0 {
                                        chrono::DateTime::from_timestamp(entry.mtime as i64, 0)
                                            .map(|dt| dt.format("%d/%m/%y %H:%M").to_string())
                                            .unwrap_or_else(|| "-".to_string())
                                    } else {
                                        "-".to_string()
                                    };
                                    ui.add_sized(
                                        [100.0, 18.0],
                                        egui::Label::new(
                                            RichText::new(date_str)
                                                .small()
                                                .monospace()
                                                .color(Color32::from_rgb(110, 118, 129)),
                                        ),
                                    );
                                });
                            }
                        });

                    ui.separator();

                    // Bottom Action Bar (Local) - Pinned to bottom of the pane
                    ui.horizontal(|ui| {
                        let can_upload = !self.local_selected.is_empty();
                        if ui
                            .add_enabled(
                                can_upload,
                                egui::Button::new(RichText::new(tr(lang, "⬆ Téléverser →", "⬆ Upload →")).strong()),
                            )
                            .clicked()
                        {
                            // Visible (sorted) order → deterministic queue order.
                            let paths: Vec<PathBuf> = self
                                .local_entries
                                .iter()
                                .filter(|e| self.local_selected.contains(&e.name))
                                .map(|e| e.path.clone())
                                .collect();
                            launch_upload = Some(paths);
                        }

                        ui.checkbox(&mut self.queue_paused, tr(lang, "Pause", "Pause"));

                        egui::ComboBox::from_id_salt("local_mode_cb_v2")
                            .selected_text(self.transfer_mode.label(lang))
                            .show_ui(ui, |ui| {
                                ui.selectable_value(
                                    &mut self.transfer_mode,
                                    TransferMode::Binary,
                                    TransferMode::Binary.label(lang),
                                );
                                ui.selectable_value(
                                    &mut self.transfer_mode,
                                    TransferMode::Text,
                                    TransferMode::Text.label(lang),
                                );
                                ui.selectable_value(
                                    &mut self.transfer_mode,
                                    TransferMode::Auto,
                                    TransferMode::Auto.label(lang),
                                );
                            });

                        egui::ComboBox::from_id_salt("local_exist_rule_cb_v2")
                            .selected_text(self.existing_file_rule.label(lang))
                            .show_ui(ui, |ui| {
                                ui.selectable_value(
                                    &mut self.existing_file_rule,
                                    ExistingFileRule::Ask,
                                    ExistingFileRule::Ask.label(lang),
                                );
                                ui.selectable_value(
                                    &mut self.existing_file_rule,
                                    ExistingFileRule::Overwrite,
                                    ExistingFileRule::Overwrite.label(lang),
                                );
                                ui.selectable_value(
                                    &mut self.existing_file_rule,
                                    ExistingFileRule::Skip,
                                    ExistingFileRule::Skip.label(lang),
                                );
                                ui.selectable_value(
                                    &mut self.existing_file_rule,
                                    ExistingFileRule::Resume,
                                    ExistingFileRule::Resume.label(lang),
                                );
                            });
                    });
                });

            // Drop zone: entries dragged from the remote pane are downloaded here.
            if let Some(payload) = left_pane
                .response
                .dnd_release_payload::<SftpDragPayload>()
                && payload.from_remote
            {
                let names: Vec<String> = payload.names.clone();
                self.log(
                    tr(
                        lang,
                        &format!(
                            "Dépôt détecté : {} élément(s) distant(s) → téléchargement",
                            names.len()
                        ),
                        &format!(
                            "Drop detected: {} remote item(s) → downloading",
                            names.len()
                        ),
                    ),
                    false,
                );
                launch_download = Some(names);
            }
            if left_pane
                .response
                .dnd_hover_payload::<SftpDragPayload>()
                .is_some_and(|p| p.from_remote)
            {
                col_left.painter().rect_stroke(
                    left_pane.response.rect,
                    4.0,
                    Stroke::new(2.0, Color32::from_rgb(88, 166, 255)),
                    egui::StrokeKind::Inside,
                );
            }

            // ==================== RIGHT COLUMN: REMOTE FILES ====================
            let col_right = &mut columns[1];
            col_right.set_max_width(half_w);
            let right_pane = egui::Frame::NONE
                .fill(Color32::from_rgb(13, 17, 23))
                .corner_radius(4.0)
                .inner_margin(egui::Margin::same(6))
                .stroke(Stroke::new(1.0, Color32::from_rgb(38, 44, 54)))
                .show(col_right, |ui| {
                    ui.set_min_height(total_avail_h);

                    // Header: Title & Filter
                    ui.horizontal(|ui| {
                        ui.label(
                            RichText::new(tr(lang, "Fichiers distants", "Remote files"))
                                .strong()
                                .size(13.0)
                                .color(Color32::from_rgb(46, 160, 67)),
                        );
                        ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                            ui.add(
                                egui::TextEdit::singleline(&mut self.remote_filter)
                                    .hint_text(tr(lang, "Filtrer...", "Filter..."))
                                    .desired_width(110.0),
                            );
                            ui.label(
                                RichText::new(tr(lang, "Filtre :", "Filter:"))
                                    .small()
                                    .color(Color32::from_rgb(139, 148, 158)),
                            );
                        });
                    });

                    ui.add_space(2.0);

                    // Remote Toolbar: Up, New Folder, Refresh, Home, Bookmarks, Path Box
                    ui.horizontal(|ui| {
                        if ui
                            .small_button("\u{E08E}")
                            .on_hover_text(tr(lang, "Dossier parent", "Parent folder"))
                            .clicked()
                        {
                            let parent = if let Some((p, _)) =
                                remote_path.trim_end_matches('/').rsplit_once('/')
                            {
                                if p.is_empty() {
                                    "/".to_string()
                                } else {
                                    p.to_string()
                                }
                            } else {
                                "/".to_string()
                            };
                            cd_remote_into = Some(parent);
                        }
                        if ui
                            .small_button("\u{E24A}+")
                            .on_hover_text(tr(lang, "Nouveau dossier distant", "New remote folder"))
                            .clicked()
                        {
                            self.show_remote_mkdir = !self.show_remote_mkdir;
                        }
                        if ui
                            .small_button("\u{E094}")
                            .on_hover_text(tr(lang, "Rafraîchir", "Refresh"))
                            .clicked()
                        {
                            let _ =
                                cmd_tx.send(BackendCommand::SftpListDir(remote_path.to_string()));
                        }
                        if ui
                            .small_button("\u{E072}")
                            .on_hover_text(tr(lang, "Home (~ /root)", "Home directory"))
                            .clicked()
                        {
                            cd_remote_into = Some(".".to_string());
                        }

                        // Remote Bookmarks Menu (WinSCP Bookmarks style)
                        ui.menu_button("📑", |ui| {
                            ui.label(RichText::new(tr(lang, "Signets distants :", "Remote bookmarks:")).strong().small());
                            let mut to_nav: Option<String> = None;
                            let mut to_remove: Option<usize> = None;
                            for (idx, bm) in self.remote_bookmarks.iter().enumerate() {
                                ui.horizontal(|ui| {
                                    if ui.button(bm).clicked() {
                                        to_nav = Some(bm.clone());
                                        ui.close();
                                    }
                                    if ui.small_button("✖").clicked() {
                                        to_remove = Some(idx);
                                    }
                                });
                            }
                            if let Some(target) = to_nav {
                                cd_remote_into = Some(target);
                            }
                            if let Some(idx) = to_remove.filter(|&i| i < self.remote_bookmarks.len()) {
                                self.remote_bookmarks.remove(idx);
                            }
                            ui.separator();
                            if ui.button(tr(lang, "➕ Ajouter le dossier actuel", "➕ Bookmark current folder")).clicked() {
                                let cur = remote_path.to_string();
                                if !self.remote_bookmarks.contains(&cur) {
                                    self.remote_bookmarks.push(cur);
                                }
                                ui.close();
                            }
                        });

                        let text_w = (ui.available_width() - 48.0).max(60.0);
                        let mut p_str = remote_path.to_string();
                        let resp =
                            ui.add(egui::TextEdit::singleline(&mut p_str).desired_width(text_w));
                        let enter =
                            resp.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter));
                        if ui.small_button(tr(lang, "Aller", "Go")).clicked() || enter {
                            cd_remote_into = Some(p_str);
                        }
                    });

                    if self.show_remote_mkdir {
                        ui.horizontal(|ui| {
                            ui.label(RichText::new(tr(lang, "Nom :", "Name:")).small());
                            ui.add(
                                egui::TextEdit::singleline(&mut self.remote_new_folder_name)
                                    .desired_width(110.0),
                            );
                            if ui.small_button(tr(lang, "Créer", "Create")).clicked()
                                && !self.remote_new_folder_name.trim().is_empty()
                            {
                                let target = if remote_path.ends_with('/') {
                                    format!("{}{}", remote_path, self.remote_new_folder_name.trim())
                                } else {
                                    format!(
                                        "{}/{}",
                                        remote_path,
                                        self.remote_new_folder_name.trim()
                                    )
                                };
                                let _ = cmd_tx.send(BackendCommand::SftpMkdir(target.clone()));
                                self.log(
                                    tr(
                                        lang,
                                        &format!("Création dossier distant : {target}"),
                                        &format!("Creating remote folder: {target}"),
                                    ),
                                    false,
                                );
                                self.remote_new_folder_name.clear();
                                self.show_remote_mkdir = false;
                            }
                        });
                    }

                    ui.add_space(2.0);

                    // Column Headers (Total fixed: 60 + 65 + 100 + spacing + scrollbar = 270)
                    let pane_avail_w = ui.available_width();
                    let name_w = (pane_avail_w - 270.0).max(80.0);

                    ui.horizontal(|ui| {
                        ui.spacing_mut().item_spacing.x = 4.0;
                        let name_arr = if self.remote_sort_col == SftpCol::Name {
                            if self.remote_sort_asc { " ▲" } else { " ▼" }
                        } else {
                            ""
                        };
                        let name_title = format!("{}{name_arr}", tr(lang, "Nom", "Name"));
                        if ui
                            .add_sized(
                                [name_w, 18.0],
                                egui::Button::new("")
                                    .left_text(name_title)
                                    .selected(self.remote_sort_col == SftpCol::Name),
                            )
                            .clicked()
                        {
                            if self.remote_sort_col == SftpCol::Name {
                                self.remote_sort_asc = !self.remote_sort_asc;
                            } else {
                                self.remote_sort_col = SftpCol::Name;
                                self.remote_sort_asc = true;
                            }
                        }

                        let size_arr = if self.remote_sort_col == SftpCol::Size {
                            if self.remote_sort_asc { " ▲" } else { " ▼" }
                        } else {
                            ""
                        };
                        let size_title = format!("{}{size_arr}", tr(lang, "Taille", "Size"));
                        if ui
                            .add_sized(
                                [60.0, 18.0],
                                egui::Button::new(size_title)
                                    .selected(self.remote_sort_col == SftpCol::Size),
                            )
                            .clicked()
                        {
                            if self.remote_sort_col == SftpCol::Size {
                                self.remote_sort_asc = !self.remote_sort_asc;
                            } else {
                                self.remote_sort_col = SftpCol::Size;
                                self.remote_sort_asc = false;
                            }
                        }

                        let type_arr = if self.remote_sort_col == SftpCol::Type {
                            if self.remote_sort_asc { " ▲" } else { " ▼" }
                        } else {
                            ""
                        };
                        let type_title = format!("{}{type_arr}", tr(lang, "Type", "Type"));
                        if ui
                            .add_sized(
                                [65.0, 18.0],
                                egui::Button::new(type_title)
                                    .selected(self.remote_sort_col == SftpCol::Type),
                            )
                            .clicked()
                        {
                            if self.remote_sort_col == SftpCol::Type {
                                self.remote_sort_asc = !self.remote_sort_asc;
                            } else {
                                self.remote_sort_col = SftpCol::Type;
                                self.remote_sort_asc = true;
                            }
                        }

                        let date_arr = if self.remote_sort_col == SftpCol::Date {
                            if self.remote_sort_asc { " ▲" } else { " ▼" }
                        } else {
                            ""
                        };
                        let date_title = format!("{}{date_arr}", tr(lang, "Modifié le", "Date Mod"));
                        if ui
                            .add_sized(
                                [100.0, 18.0],
                                egui::Button::new(date_title)
                                    .selected(self.remote_sort_col == SftpCol::Date),
                            )
                            .clicked()
                        {
                            if self.remote_sort_col == SftpCol::Date {
                                self.remote_sort_asc = !self.remote_sort_asc;
                            } else {
                                self.remote_sort_col = SftpCol::Date;
                                self.remote_sort_asc = false;
                            }
                        }
                    });

                    ui.separator();

                    // Table Body with ScrollArea: auto_shrink(false) guarantees consistent full-height alignment
                    let scroll_h = (ui.available_height() - 36.0).max(80.0);
                    ScrollArea::vertical()
                        .id_salt("remote_scroll_fixed")
                        .auto_shrink([false, false])
                        .min_scrolled_height(scroll_h)
                        .max_height(scroll_h)
                        .show(ui, |ui| {
                            let filter_lc = self.remote_filter.trim().to_lowercase();
                            // Visible rows in display order — the Shift+click range space.
                            let visible_names: Vec<String> = sorted_remote
                                .iter()
                                .filter(|e| {
                                    filter_lc.is_empty()
                                        || e.name.to_lowercase().contains(&filter_lc)
                                })
                                .map(|e| e.name.clone())
                                .collect();
                            for entry in &sorted_remote {
                                if !filter_lc.is_empty()
                                    && !entry.name.to_lowercase().contains(&filter_lc)
                                {
                                    continue;
                                }

                                let is_selected = self.remote_selected.contains(&entry.name);
                                let icon = if entry.is_dir {
                                    "\u{E24A}"
                                } else if entry.is_symlink {
                                    "🔗"
                                } else {
                                    "📄"
                                };
                                let label_text = format!("{} {}", icon, entry.name);

                                ui.horizontal(|ui| {
                                    ui.spacing_mut().item_spacing.x = 4.0;
                                    let btn = ui.add_sized(
                                        [name_w, 18.0],
                                        egui::Button::new("")
                                            .left_text(RichText::new(label_text).color(
                                                if is_selected {
                                                    Color32::from_rgb(88, 166, 255)
                                                } else {
                                                    Color32::from_rgb(201, 209, 217)
                                                },
                                            ))
                                            .frame(is_selected)
                                            .selected(is_selected)
                                            .truncate()
                                            .sense(egui::Sense::click_and_drag()),
                                    );

                                    if btn.clicked() {
                                        let mods = ui.input(|i| i.modifiers);
                                        if mods.shift {
                                            apply_range_selection(
                                                &mut self.remote_selected,
                                                &mut self.remote_anchor,
                                                &visible_names,
                                                &entry.name,
                                                mods.ctrl,
                                            );
                                        } else if mods.ctrl {
                                            if is_selected {
                                                self.remote_selected.remove(&entry.name);
                                            } else {
                                                self.remote_selected.insert(entry.name.clone());
                                            }
                                            self.remote_anchor = Some(entry.name.clone());
                                        } else {
                                            self.remote_selected.clear();
                                            self.remote_selected.insert(entry.name.clone());
                                            self.remote_anchor = Some(entry.name.clone());
                                        }
                                    }
                                    if btn.double_clicked() && entry.is_dir {
                                        cd_remote_into = Some(entry.full_path.clone());
                                    }

                                    // Drag & drop to the local pane = download.
                                    // A click stays a click: egui only decides "drag"
                                    // once the pointer moved past the click threshold.
                                    if btn.drag_started() && !is_selected {
                                        self.remote_selected.clear();
                                        self.remote_selected.insert(entry.name.clone());
                                        self.remote_anchor = Some(entry.name.clone());
                                    }
                                    btn.dnd_set_drag_payload(SftpDragPayload {
                                        names: dragged_names(&self.remote_selected, &entry.name),
                                        from_remote: true,
                                    });

                                    // Context Menu (Remote file) - Strict FR / EN, zero mixed text
                                    btn.context_menu(|ui| {
                                        // Explorer semantics: right-clicking an entry that is
                                        // part of a multi-selection downloads the whole selection.
                                        let sel_count = self.remote_selected.len();
                                        let in_selection =
                                            sel_count > 1 && self.remote_selected.contains(&entry.name);
                                        let dl_label = if in_selection {
                                            tr(
                                                lang,
                                                &format!("⬇ Télécharger la sélection ({sel_count})"),
                                                &format!("⬇ Download selection ({sel_count})"),
                                            )
                                            .to_string()
                                        } else {
                                            tr(lang, "⬇ Télécharger", "⬇ Download").to_string()
                                        };
                                        if ui.button(dl_label).clicked() {
                                            launch_download =
                                                Some(dragged_names(&self.remote_selected, &entry.name));
                                            ui.close();
                                        }
                                        if ui.button(tr(lang, "⏸ Mettre en pause dans la file", "⏸ Enqueue paused")).clicked() {
                                            ui.close();
                                        }
                                        ui.separator();
                                        if ui.button(tr(lang, "Ouvrir", "Open")).clicked() {
                                            let edit_dir = std::env::temp_dir().join("cuty_ssh_edit");
                                            let _ = std::fs::create_dir_all(&edit_dir);
                                            let temp_file = edit_dir.join(&entry.name);
                                            let _ = std::fs::remove_file(&temp_file);
                                            let _ = cmd_tx.send(BackendCommand::SftpDownload {
                                                remote_path: entry.full_path.clone(),
                                                local_path: temp_file.clone(),
                                            });
                                            if let Some(existing) = self.watched_files.iter_mut().find(|w| w.local_path == temp_file) {
                                                existing.remote_path = entry.full_path.clone();
                                                existing.open_editor_when_ready = true;
                                                existing.use_default_app = true;
                                                existing.last_mtime = 0;
                                                existing.last_size = 0;
                                            } else {
                                                self.watched_files.push(WatchedEditFile {
                                                    local_path: temp_file,
                                                    remote_path: entry.full_path.clone(),
                                                    last_mtime: 0,
                                                    last_size: 0,
                                                    open_editor_when_ready: true,
                                                    use_default_app: true,
                                                });
                                            }
                                            self.log(
                                                tr(
                                                    lang,
                                                    &format!("Téléchargement pour ouverture : {}", entry.full_path),
                                                    &format!("Downloading for open: {}", entry.full_path),
                                                ),
                                                false,
                                            );
                                            ui.close();
                                        }
                                        if ui.button(tr(lang, "Éditer", "Edit")).clicked() {
                                            let edit_dir = std::env::temp_dir().join("cuty_ssh_edit");
                                            let _ = std::fs::create_dir_all(&edit_dir);
                                            let temp_file = edit_dir.join(&entry.name);
                                            let _ = std::fs::remove_file(&temp_file);
                                            let _ = cmd_tx.send(BackendCommand::SftpDownload {
                                                remote_path: entry.full_path.clone(),
                                                local_path: temp_file.clone(),
                                            });
                                            if let Some(existing) = self.watched_files.iter_mut().find(|w| w.local_path == temp_file) {
                                                existing.remote_path = entry.full_path.clone();
                                                existing.open_editor_when_ready = true;
                                                existing.use_default_app = false;
                                                existing.last_mtime = 0;
                                                existing.last_size = 0;
                                            } else {
                                                self.watched_files.push(WatchedEditFile {
                                                    local_path: temp_file,
                                                    remote_path: entry.full_path.clone(),
                                                    last_mtime: 0,
                                                    last_size: 0,
                                                    open_editor_when_ready: true,
                                                    use_default_app: false,
                                                });
                                            }
                                            self.log(
                                                tr(
                                                    lang,
                                                    &format!("Téléchargement pour édition (Ctrl+S surveillé) : {}", entry.full_path),
                                                    &format!("Downloading for edit (Ctrl+S monitored): {}", entry.full_path),
                                                ),
                                                false,
                                            );
                                            ui.close();
                                        }
                                        if ui.button(tr(lang, "Choisir l'éditeur...", "Choose editor...")).clicked() {
                                            self.show_editor_modal = true;
                                            ui.close();
                                        }
                                        if ui.button(tr(lang, "Déplacer vers...", "Move to...")).clicked() {
                                            self.move_modal = Some(MoveModal {
                                                is_remote: true,
                                                current_full_path: entry.full_path.clone(),
                                                destination_dir: remote_path.to_string(),
                                            });
                                            ui.close();
                                        }
                                        if ui.button(tr(lang, "Supprimer", "Delete")).clicked() {
                                            self.delete_confirm =
                                                Some((true, entry.full_path.clone(), entry.is_dir));
                                            ui.close();
                                        }
                                        if ui.button(tr(lang, "Renommer...", "Rename...")).clicked() {
                                            self.rename_modal = Some(RenameModal {
                                                is_remote: true,
                                                current_full_path: entry.full_path.clone(),
                                                new_name: entry.name.clone(),
                                            });
                                            ui.close();
                                        }
                                        if ui.button(tr(lang, "Calculer l'empreinte SHA-256", "Calculate SHA-256 hash")).clicked() {
                                            let _ = cmd_tx.send(BackendCommand::SftpSha256(
                                                entry.full_path.clone(),
                                            ));
                                            self.log(
                                                tr(
                                                    lang,
                                                    &format!("Calcul SHA-256 en cours pour {}", entry.full_path),
                                                    &format!("Calculating SHA-256 for {}", entry.full_path),
                                                ),
                                                false,
                                            );
                                            ui.close();
                                        }
                                        ui.separator();
                                        if ui.button(tr(lang, "Créer un lien symbolique...", "Create symbolic link...")).clicked() {
                                            self.symlink_modal = Some(SymlinkModal {
                                                target_path: entry.full_path.clone(),
                                                link_name: format!("{}_link", entry.name),
                                            });
                                            ui.close();
                                        }
                                        if ui.button(tr(lang, "Copier le chemin absolu", "Copy full path")).clicked()
                                        {
                                            if let Ok(mut clip) = arboard::Clipboard::new() {
                                                let _ = clip.set_text(&entry.full_path);
                                            }
                                            ui.close();
                                        }
                                        ui.separator();
                                        // Properties / Chmod Dialog trigger (Bitvise #355)
                                        if ui
                                            .button(tr(lang, "Propriétés (Permissions / Chmod)", "Properties (Permissions / Chmod)"))
                                            .clicked()
                                        {
                                            self.props_request = Some((*entry).clone());
                                            ui.close();
                                        }
                                    });

                                    // Size
                                    let size_str = if entry.is_dir {
                                        "-".to_string()
                                    } else {
                                        format_bytes(entry.size)
                                    };
                                    ui.add_sized(
                                        [60.0, 18.0],
                                        egui::Label::new(
                                            RichText::new(size_str)
                                                .small()
                                                .monospace()
                                                .color(Color32::from_rgb(139, 148, 158)),
                                        ),
                                    );

                                    // Type (Localized)
                                    let type_str = if entry.is_dir {
                                        tr(lang, "Dossier", "Folder").to_string()
                                    } else if entry.is_symlink {
                                        tr(lang, "Lien sym", "Symlink").to_string()
                                    } else {
                                        tr(lang, "Fichier", "File").to_string()
                                    };
                                    ui.add_sized(
                                        [65.0, 18.0],
                                        egui::Label::new(
                                            RichText::new(type_str)
                                                .small()
                                                .color(Color32::from_rgb(110, 118, 129)),
                                        )
                                        .truncate(),
                                    );

                                    // Date
                                    let date_str = if entry.mtime > 0 {
                                        chrono::DateTime::from_timestamp(entry.mtime as i64, 0)
                                            .map(|dt| dt.format("%d/%m/%y %H:%M").to_string())
                                            .unwrap_or_else(|| "-".to_string())
                                    } else {
                                        "-".to_string()
                                    };
                                    ui.add_sized(
                                        [100.0, 18.0],
                                        egui::Label::new(
                                            RichText::new(date_str)
                                                .small()
                                                .monospace()
                                                .color(Color32::from_rgb(110, 118, 129)),
                                        ),
                                    );
                                });
                            }
                        });

                    ui.separator();

                    // Bottom Action Bar (Remote) - Pinned to bottom of the pane
                    ui.horizontal(|ui| {
                        let can_download = !self.remote_selected.is_empty();
                        if ui
                            .add_enabled(
                                can_download,
                                egui::Button::new(RichText::new(tr(lang, "← Télécharger ⬇", "← Download ⬇")).strong()),
                            )
                            .clicked()
                        {
                            // Visible (sorted) order → deterministic queue order.
                            let names: Vec<String> = sorted_remote
                                .iter()
                                .filter(|e| self.remote_selected.contains(&e.name))
                                .map(|e| e.name.clone())
                                .collect();
                            launch_download = Some(names);
                        }

                        ui.checkbox(&mut self.queue_paused, tr(lang, "Pause", "Pause"));

                        egui::ComboBox::from_id_salt("remote_mode_cb_v2")
                            .selected_text(self.transfer_mode.label(lang))
                            .show_ui(ui, |ui| {
                                ui.selectable_value(
                                    &mut self.transfer_mode,
                                    TransferMode::Binary,
                                    TransferMode::Binary.label(lang),
                                );
                                ui.selectable_value(
                                    &mut self.transfer_mode,
                                    TransferMode::Text,
                                    TransferMode::Text.label(lang),
                                );
                                ui.selectable_value(
                                    &mut self.transfer_mode,
                                    TransferMode::Auto,
                                    TransferMode::Auto.label(lang),
                                );
                            });

                        egui::ComboBox::from_id_salt("remote_exist_rule_cb_v2")
                            .selected_text(self.existing_file_rule.label(lang))
                            .show_ui(ui, |ui| {
                                ui.selectable_value(
                                    &mut self.existing_file_rule,
                                    ExistingFileRule::Ask,
                                    ExistingFileRule::Ask.label(lang),
                                );
                                ui.selectable_value(
                                    &mut self.existing_file_rule,
                                    ExistingFileRule::Overwrite,
                                    ExistingFileRule::Overwrite.label(lang),
                                );
                                ui.selectable_value(
                                    &mut self.existing_file_rule,
                                    ExistingFileRule::Skip,
                                    ExistingFileRule::Skip.label(lang),
                                );
                                ui.selectable_value(
                                    &mut self.existing_file_rule,
                                    ExistingFileRule::Resume,
                                    ExistingFileRule::Resume.label(lang),
                                );
                            });
                    });
                });

            // Drop zone: entries dragged from the local pane are uploaded here.
            if let Some(payload) = right_pane
                .response
                .dnd_release_payload::<SftpDragPayload>()
                && !payload.from_remote
            {
                let paths: Vec<PathBuf> = payload
                    .names
                    .iter()
                    .filter_map(|n| {
                        let p = self.local_path.join(n);
                        p.exists().then_some(p)
                    })
                    .collect();
                if !paths.is_empty() {
                    self.log(
                        tr(
                            lang,
                            &format!(
                                "Dépôt détecté : {} élément(s) local(s) → envoi",
                                paths.len()
                            ),
                            &format!("Drop detected: {} local item(s) → uploading", paths.len()),
                        ),
                        false,
                    );
                    launch_upload = Some(paths);
                }
            }
            if right_pane
                .response
                .dnd_hover_payload::<SftpDragPayload>()
                .is_some_and(|p| !p.from_remote)
            {
                col_right.painter().rect_stroke(
                    right_pane.response.rect,
                    4.0,
                    Stroke::new(2.0, Color32::from_rgb(46, 160, 67)),
                    egui::StrokeKind::Inside,
                );
            }
        });

        // Navigation
        if let Some(target) = cd_local_into {
            self.local_path = target;
            self.local_selected.clear();
            self.local_anchor = None;
            self.refresh_local();
        }
        if let Some(target) = cd_remote_into {
            let _ = cmd_tx.send(BackendCommand::SftpListDir(target));
            self.remote_selected.clear();
            self.remote_anchor = None;
        }

        // Upload batch with collision detection
        if let Some(paths) = launch_upload {
            self.enqueue_uploads(&paths, remote_path, remote_entries, cmd_tx, lang);
        }

        // Download batch with collision detection
        if let Some(names) = launch_download {
            self.enqueue_downloads(&names, remote_path, remote_entries, cmd_tx, lang);
        }
    }

    /// Queues an upload batch: per-file collision check against the current
    /// remote listing, then one queue task + one `SftpUpload` command per file.
    /// With the "Ask" rule, colliding files are parked in `pending_collisions`
    /// so every one of them gets its resolution turn — nothing is silently
    /// dropped (multi-selection transfers used to copy only one file).
    fn enqueue_uploads(
        &mut self,
        paths: &[PathBuf],
        remote_path: &str,
        remote_entries: &[SftpFileEntry],
        cmd_tx: &UnboundedSender<BackendCommand>,
        lang: UiLanguage,
    ) {
        for p in paths {
            let filename = p
                .file_name()
                .map(|n| n.to_string_lossy().to_string())
                .unwrap_or_else(|| "file.bin".to_string());
            let remote_target = if remote_path.ends_with('/') {
                format!("{}{}", remote_path, filename)
            } else {
                format!("{}/{}", remote_path, filename)
            };

            let meta = std::fs::metadata(p).ok();
            let local_size = meta.as_ref().map(|m| m.len()).unwrap_or(0);
            let local_is_dir = meta.as_ref().map(|m| m.is_dir()).unwrap_or(false);
            let local_mtime = meta
                .as_ref()
                .and_then(|m| m.modified().ok())
                .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
                .map(|d| d.as_secs())
                .unwrap_or(0);

            // Collision check against remote entries.
            // Directories merge silently: their children go through the same
            // collision rules one by one during the recursive transfer.
            let existing_remote = remote_entries.iter().find(|e| e.name == filename);
            if let (false, Some(existing)) = (local_is_dir, existing_remote) {
                match self.existing_file_rule {
                    ExistingFileRule::Skip => {
                        self.log(
                            tr(
                                lang,
                                &format!("Fichier existant ignoré : {filename}"),
                                &format!("Existing file skipped: {filename}"),
                            ),
                            false,
                        );
                        continue;
                    }
                    ExistingFileRule::Ask => {
                        self.pending_collisions.push(CollisionModal {
                            is_upload: true,
                            filename: filename.clone(),
                            local_path: p.clone(),
                            remote_path: remote_target.clone(),
                            local_size,
                            local_mtime,
                            remote_size: existing.size,
                            remote_mtime: existing.mtime as u64,
                            new_name: format!("{}_new", filename),
                        });
                        continue;
                    }
                    ExistingFileRule::Overwrite | ExistingFileRule::Resume => {}
                }
            }

            let task_id = self.next_task_id;
            self.next_task_id += 1;

            self.upload_queue.push(QueueTask {
                id: task_id,
                filename: filename.clone(),
                local_path: p.clone(),
                remote_path: remote_target.clone(),
                size: local_size,
                transferred: 0,
                is_upload: true,
                status: if self.queue_paused {
                    QueueTaskStatus::Paused
                } else {
                    QueueTaskStatus::InProgress
                },
            });

            if !self.queue_paused {
                let _ = cmd_tx.send(BackendCommand::SftpUpload {
                    local_path: p.clone(),
                    remote_path: remote_target.clone(),
                });
                self.log(
                    tr(
                        lang,
                        &format!("Upload démarré : {filename} -> {remote_target}"),
                        &format!("Upload started: {filename} -> {remote_target}"),
                    ),
                    false,
                );
            }
        }
        self.open_next_collision();
    }

    /// Download mirror of [`Self::enqueue_uploads`].
    fn enqueue_downloads(
        &mut self,
        names: &[String],
        remote_path: &str,
        remote_entries: &[SftpFileEntry],
        cmd_tx: &UnboundedSender<BackendCommand>,
        lang: UiLanguage,
    ) {
        for name in names {
            let remote_src = if remote_path.ends_with('/') {
                format!("{}{}", remote_path, name)
            } else {
                format!("{}/{}", remote_path, name)
            };
            let local_dst = self.local_path.join(name);

            let existing_remote = remote_entries.iter().find(|e| e.name == *name);
            let remote_size = existing_remote.map(|e| e.size).unwrap_or(0);
            let remote_mtime = existing_remote.map(|e| e.mtime).unwrap_or(0);
            let remote_is_dir = existing_remote.map(|e| e.is_dir).unwrap_or(false);

            // Directories merge silently: their children go through the same
            // collision rules one by one during the recursive transfer.
            if local_dst.exists() && !remote_is_dir {
                let meta = std::fs::metadata(&local_dst).ok();
                let local_size = meta.as_ref().map(|m| m.len()).unwrap_or(0);
                let local_mtime = meta
                    .as_ref()
                    .and_then(|m| m.modified().ok())
                    .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
                    .map(|d| d.as_secs())
                    .unwrap_or(0);

                match self.existing_file_rule {
                    ExistingFileRule::Skip => {
                        self.log(
                            tr(
                                lang,
                                &format!("Fichier local existant ignoré : {name}"),
                                &format!("Existing local file skipped: {name}"),
                            ),
                            false,
                        );
                        continue;
                    }
                    ExistingFileRule::Ask => {
                        self.pending_collisions.push(CollisionModal {
                            is_upload: false,
                            filename: name.clone(),
                            local_path: local_dst.clone(),
                            remote_path: remote_src.clone(),
                            local_size,
                            local_mtime,
                            remote_size,
                            remote_mtime: remote_mtime as u64,
                            new_name: format!("{}_new", name),
                        });
                        continue;
                    }
                    ExistingFileRule::Overwrite | ExistingFileRule::Resume => {}
                }
            }

            let task_id = self.next_task_id;
            self.next_task_id += 1;

            self.download_queue.push(QueueTask {
                id: task_id,
                filename: name.clone(),
                local_path: local_dst.clone(),
                remote_path: remote_src.clone(),
                size: remote_size,
                transferred: 0,
                is_upload: false,
                status: if self.queue_paused {
                    QueueTaskStatus::Paused
                } else {
                    QueueTaskStatus::InProgress
                },
            });

            if !self.queue_paused {
                let _ = cmd_tx.send(BackendCommand::SftpDownload {
                    remote_path: remote_src.clone(),
                    local_path: local_dst,
                });
                self.log(
                    tr(
                        lang,
                        &format!("Téléchargement démarré : {name} -> local"),
                        &format!("Download started: {name} -> local"),
                    ),
                    false,
                );
            }
        }
        self.open_next_collision();
    }

    /// Opens the first queued collision, if any, when no modal is already open.
    fn open_next_collision(&mut self) {
        if self.collision_modal.is_none()
            && let Some(next) = self.pending_collisions.first().cloned()
        {
            self.pending_collisions.remove(0);
            self.collision_modal = Some(next);
        }
    }

    /// Applies a collision-dialog answer: the current file's transfer (or
    /// skip), plus the batch variants for every queued collision.
    fn resolve_collision(
        &mut self,
        col_modal: CollisionModal,
        choice: CollisionChoice,
        cmd_tx: &UnboundedSender<BackendCommand>,
        lang: UiLanguage,
    ) {
        match choice {
            CollisionChoice::OverwriteAll => {
                // Current file first, then every queued collision.
                self.launch_collision_transfer(&col_modal, None, cmd_tx);
                let batch: Vec<CollisionModal> = std::mem::take(&mut self.pending_collisions);
                for m in &batch {
                    self.launch_collision_transfer(m, None, cmd_tx);
                }
                self.log(
                    tr(
                        lang,
                        &format!("{} fichier(s) en conflit écrasé(s).", batch.len() + 1),
                        &format!("{} conflicting file(s) overwritten.", batch.len() + 1),
                    ),
                    false,
                );
            }
            CollisionChoice::SkipAll => {
                let skipped = self.pending_collisions.len() + 1;
                self.pending_collisions.clear();
                self.log(
                    tr(
                        lang,
                        &format!("{skipped} fichier(s) en conflit ignoré(s)."),
                        &format!("{skipped} conflicting file(s) skipped."),
                    ),
                    false,
                );
            }
            CollisionChoice::Overwrite | CollisionChoice::Resume => {
                self.launch_collision_transfer(&col_modal, None, cmd_tx);
                self.open_next_collision();
            }
            CollisionChoice::Rename(new_name) => {
                self.launch_collision_transfer(&col_modal, Some(&new_name), cmd_tx);
                self.open_next_collision();
            }
            CollisionChoice::Skip => {
                self.log(
                    tr(
                        lang,
                        &format!("Transfert ignoré (collision) : {}", col_modal.filename),
                        &format!("Transfer skipped (collision): {}", col_modal.filename),
                    ),
                    false,
                );
                self.open_next_collision();
            }
        }
    }

    /// Queues and starts the transfer a collision dialog just resolved.
    /// `renamed` redirects the target to a new name ("Rename" choice).
    fn launch_collision_transfer(
        &mut self,
        m: &CollisionModal,
        renamed: Option<&str>,
        cmd_tx: &UnboundedSender<BackendCommand>,
    ) {
        let task_id = self.next_task_id;
        self.next_task_id += 1;

        if m.is_upload {
            let remote_target = match renamed {
                Some(new_name) => {
                    let parent = m.remote_path.rsplit_once('/').map(|(p, _)| p).unwrap_or("");
                    if parent.ends_with('/') {
                        format!("{}{}", parent, new_name)
                    } else {
                        format!("{}/{}", parent, new_name)
                    }
                }
                None => m.remote_path.clone(),
            };
            let _ = cmd_tx.send(BackendCommand::SftpUpload {
                local_path: m.local_path.clone(),
                remote_path: remote_target.clone(),
            });
            self.upload_queue.push(QueueTask {
                id: task_id,
                filename: match renamed {
                    Some(n) => n.to_string(),
                    None => m.filename.clone(),
                },
                local_path: m.local_path.clone(),
                remote_path: remote_target,
                size: m.local_size,
                transferred: 0,
                is_upload: true,
                status: QueueTaskStatus::InProgress,
            });
        } else {
            let local_dst = match renamed {
                Some(new_name) => m
                    .local_path
                    .parent()
                    .map(|p| p.join(new_name))
                    .unwrap_or_else(|| PathBuf::from(new_name)),
                None => m.local_path.clone(),
            };
            let _ = cmd_tx.send(BackendCommand::SftpDownload {
                remote_path: m.remote_path.clone(),
                local_path: local_dst.clone(),
            });
            self.download_queue.push(QueueTask {
                id: task_id,
                filename: match renamed {
                    Some(n) => n.to_string(),
                    None => m.filename.clone(),
                },
                local_path: local_dst,
                remote_path: m.remote_path.clone(),
                size: m.remote_size,
                transferred: 0,
                is_upload: false,
                status: QueueTaskStatus::InProgress,
            });
        }
    }

    fn render_upload_queue_tab(&mut self, ui: &mut Ui, lang: UiLanguage) {
        ui.heading(tr(lang, "⬆ File d'attente d'envoi", "⬆ Upload queue"));
        ui.add_space(4.0);

        ScrollArea::vertical().show(ui, |ui| {
            if self.upload_queue.is_empty() {
                ui.label(
                    RichText::new(tr(
                        lang,
                        "Aucun transfert d'envoi en attente.",
                        "No upload transfer pending.",
                    ))
                    .color(Color32::from_rgb(139, 148, 158)),
                );
            } else {
                for task in &self.upload_queue {
                    ui.horizontal(|ui| {
                        let icon = match task.status {
                            QueueTaskStatus::Pending => "⏳",
                            QueueTaskStatus::InProgress => "🔄",
                            QueueTaskStatus::Paused => "⏸",
                            QueueTaskStatus::Completed => "✅",
                            QueueTaskStatus::Error => "❌",
                        };
                        ui.label(format!("{} {}", icon, task.filename));
                        ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                            let status_text = match task.status {
                                QueueTaskStatus::Pending => tr(lang, "En attente", "Pending"),
                                QueueTaskStatus::InProgress => tr(lang, "En cours", "In progress"),
                                QueueTaskStatus::Paused => tr(lang, "En pause", "Paused"),
                                QueueTaskStatus::Completed => tr(lang, "Terminé", "Completed"),
                                QueueTaskStatus::Error => tr(lang, "Erreur", "Error"),
                            };
                            ui.label(
                                RichText::new(status_text)
                                    .small()
                                    .color(Color32::from_rgb(139, 148, 158)),
                            );
                            ui.label(RichText::new(format_bytes(task.size)).small().monospace());
                        });
                    });
                }
            }
        });
    }

    fn render_download_queue_tab(&mut self, ui: &mut Ui, lang: UiLanguage) {
        ui.heading(tr(
            lang,
            "⬇ File d'attente de réception",
            "⬇ Download queue",
        ));
        ui.add_space(4.0);

        ScrollArea::vertical().show(ui, |ui| {
            if self.download_queue.is_empty() {
                ui.label(
                    RichText::new(tr(
                        lang,
                        "Aucun téléchargement en attente.",
                        "No download pending.",
                    ))
                    .color(Color32::from_rgb(139, 148, 158)),
                );
            } else {
                for task in &self.download_queue {
                    ui.horizontal(|ui| {
                        let icon = match task.status {
                            QueueTaskStatus::Pending => "⏳",
                            QueueTaskStatus::InProgress => "🔄",
                            QueueTaskStatus::Paused => "⏸",
                            QueueTaskStatus::Completed => "✅",
                            QueueTaskStatus::Error => "❌",
                        };
                        ui.label(format!("{} {}", icon, task.filename));
                        ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                            let status_text = match task.status {
                                QueueTaskStatus::Pending => tr(lang, "En attente", "Pending"),
                                QueueTaskStatus::InProgress => tr(lang, "En cours", "In progress"),
                                QueueTaskStatus::Paused => tr(lang, "En pause", "Paused"),
                                QueueTaskStatus::Completed => tr(lang, "Terminé", "Completed"),
                                QueueTaskStatus::Error => tr(lang, "Erreur", "Error"),
                            };
                            ui.label(
                                RichText::new(status_text)
                                    .small()
                                    .color(Color32::from_rgb(139, 148, 158)),
                            );
                        });
                    });
                }
            }
        });
    }

    fn render_log_tab(&mut self, ui: &mut Ui, lang: UiLanguage) {
        ui.horizontal(|ui| {
            ui.heading(tr(
                lang,
                "📋 Journal des opérations SFTP",
                "📋 SFTP operation log",
            ));
            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                if ui
                    .small_button(tr(lang, "Effacer l'historique", "Clear history"))
                    .clicked()
                {
                    self.logs.clear();
                }
            });
        });

        ui.add_space(4.0);

        ScrollArea::vertical().stick_to_bottom(true).show(ui, |ui| {
            for entry in &self.logs {
                let col = if entry.is_error {
                    Color32::from_rgb(248, 81, 73)
                } else {
                    Color32::from_rgb(201, 209, 217)
                };
                ui.horizontal(|ui| {
                    ui.label(
                        RichText::new(&entry.timestamp)
                            .monospace()
                            .small()
                            .color(Color32::from_rgb(110, 118, 129)),
                    );
                    ui.label(RichText::new(&entry.message).monospace().color(col));
                });
            }
        });
    }

    fn render_modals(
        &mut self,
        ctx: &Context,
        lang: UiLanguage,
        cmd_tx: &UnboundedSender<BackendCommand>,
    ) {
        // 1. Rename Modal
        if let Some(rename) = &mut self.rename_modal {
            let mut close = false;
            let mut execute_rename = false;

            egui::Window::new(tr(lang, "Renommer", "Rename"))
                .collapsible(false)
                .resizable(false)
                .show(ctx, |ui| {
                    ui.label(format!(
                        "{}: {}",
                        tr(lang, "Élément", "Item"),
                        rename.current_full_path
                    ));
                    ui.add_space(4.0);
                    ui.horizontal(|ui| {
                        ui.label(tr(lang, "Nouveau nom :", "New name:"));
                        ui.text_edit_singleline(&mut rename.new_name);
                    });
                    ui.add_space(6.0);
                    ui.horizontal(|ui| {
                        if ui.button("OK").clicked() {
                            execute_rename = true;
                            close = true;
                        }
                        if ui.button(tr(lang, "Annuler", "Cancel")).clicked() {
                            close = true;
                        }
                    });
                });

            if execute_rename {
                let is_remote = rename.is_remote;
                let old = rename.current_full_path.clone();
                let new_name = rename.new_name.trim().to_string();

                if is_remote {
                    let parent = if let Some((p, _)) = old.rsplit_once('/') {
                        if p.is_empty() { "/" } else { p }
                    } else {
                        "/"
                    };
                    let new_path = if parent.ends_with('/') {
                        format!("{}{}", parent, new_name)
                    } else {
                        format!("{}/{}", parent, new_name)
                    };
                    let _ = cmd_tx.send(BackendCommand::SftpRename {
                        old_path: old.clone(),
                        new_path: new_path.clone(),
                    });
                    self.log(
                        tr(
                            lang,
                            &format!("Renommage distant : {old} -> {new_path}"),
                            &format!("Remote rename: {old} -> {new_path}"),
                        ),
                        false,
                    );
                } else {
                    let old_path = PathBuf::from(&old);
                    if let Some(parent) = old_path.parent() {
                        let new_path = parent.join(new_name);
                        let _ = std::fs::rename(&old_path, &new_path);
                        self.log(
                            tr(
                                lang,
                                &format!(
                                    "Renommage local : {} -> {}",
                                    old_path.display(),
                                    new_path.display()
                                ),
                                &format!(
                                    "Local rename: {} -> {}",
                                    old_path.display(),
                                    new_path.display()
                                ),
                            ),
                            false,
                        );
                        self.refresh_local();
                    }
                }
            }

            if close {
                self.rename_modal = None;
            }
        }

        // 2. Move Modal (Bitvise #451)
        if let Some(mv) = &mut self.move_modal {
            let mut close = false;
            let mut execute_move = false;

            egui::Window::new(tr(lang, "Déplacer l'élément", "Move item"))
                .collapsible(false)
                .resizable(false)
                .show(ctx, |ui| {
                    ui.label(format!(
                        "{}: {}",
                        tr(lang, "Source", "Source"),
                        mv.current_full_path
                    ));
                    ui.add_space(4.0);
                    ui.horizontal(|ui| {
                        ui.label(tr(lang, "Dossier cible :", "Target folder:"));
                        ui.text_edit_singleline(&mut mv.destination_dir);
                    });
                    ui.add_space(6.0);
                    ui.horizontal(|ui| {
                        if ui.button(tr(lang, "Déplacer", "Move")).clicked() {
                            execute_move = true;
                            close = true;
                        }
                        if ui.button(tr(lang, "Annuler", "Cancel")).clicked() {
                            close = true;
                        }
                    });
                });

            if execute_move {
                let is_remote = mv.is_remote;
                let old = mv.current_full_path.clone();
                let dest = mv.destination_dir.trim().to_string();
                let file_name = old.rsplit('/').next().unwrap_or(&old);

                if is_remote {
                    let new_path = if dest.ends_with('/') {
                        format!("{}{}", dest, file_name)
                    } else {
                        format!("{}/{}", dest, file_name)
                    };
                    let _ = cmd_tx.send(BackendCommand::SftpRename {
                        old_path: old.clone(),
                        new_path: new_path.clone(),
                    });
                    self.log(
                        tr(
                            lang,
                            &format!("Déplacement distant : {old} -> {new_path}"),
                            &format!("Remote move: {old} -> {new_path}"),
                        ),
                        false,
                    );
                }
            }

            if close {
                self.move_modal = None;
            }
        }

        // 3. Delete Confirm Modal
        if let Some((is_remote, path, is_dir)) = &self.delete_confirm {
            let mut close = false;
            let mut do_delete = false;
            let path_copy = path.clone();
            let is_remote_copy = *is_remote;
            let is_dir_copy = *is_dir;

            egui::Window::new(tr(lang, "Confirmer la suppression", "Confirm deletion"))
                .collapsible(false)
                .resizable(false)
                .show(ctx, |ui| {
                    ui.label(tr(
                        lang,
                        &format!("Voulez-vous vraiment supprimer cet élément ?\n\n{path_copy}"),
                        &format!("Are you sure you want to delete this item?\n\n{path_copy}"),
                    ));
                    ui.add_space(6.0);
                    ui.horizontal(|ui| {
                        if ui
                            .button(
                                RichText::new(tr(lang, "Supprimer", "Delete"))
                                    .color(Color32::from_rgb(248, 81, 73)),
                            )
                            .clicked()
                        {
                            do_delete = true;
                            close = true;
                        }
                        if ui.button(tr(lang, "Annuler", "Cancel")).clicked() {
                            close = true;
                        }
                    });
                });

            if do_delete {
                if is_remote_copy {
                    let _ = cmd_tx.send(BackendCommand::SftpDelete {
                        remote_path: path_copy.clone(),
                        is_dir: is_dir_copy,
                    });
                    self.log(
                        tr(
                            lang,
                            &format!("Suppression distante demandée : {path_copy}"),
                            &format!("Remote deletion requested: {path_copy}"),
                        ),
                        false,
                    );
                } else {
                    let p = PathBuf::from(&path_copy);
                    let res = if is_dir_copy {
                        std::fs::remove_dir_all(&p)
                    } else {
                        std::fs::remove_file(&p)
                    };
                    if res.is_ok() {
                        self.log(
                            tr(
                                lang,
                                &format!("Supprimé localement : {path_copy}"),
                                &format!("Locally deleted: {path_copy}"),
                            ),
                            false,
                        );
                        self.refresh_local();
                    }
                }
            }

            if close {
                self.delete_confirm = None;
            }
        }

        // 4. Symlink Modal (Bitvise #452)
        if let Some(sym) = &mut self.symlink_modal {
            let mut close = false;
            let mut create_sym = false;

            egui::Window::new(tr(lang, "Créer un lien symbolique", "Create symbolic link"))
                .collapsible(false)
                .resizable(false)
                .show(ctx, |ui| {
                    ui.label(format!(
                        "{}: {}",
                        tr(lang, "Cible", "Target"),
                        sym.target_path
                    ));
                    ui.add_space(4.0);
                    ui.horizontal(|ui| {
                        ui.label(tr(lang, "Nom du lien :", "Link name:"));
                        ui.text_edit_singleline(&mut sym.link_name);
                    });
                    ui.add_space(6.0);
                    ui.horizontal(|ui| {
                        if ui
                            .button(tr(lang, "Créer le lien", "Create link"))
                            .clicked()
                        {
                            create_sym = true;
                            close = true;
                        }
                        if ui.button(tr(lang, "Annuler", "Cancel")).clicked() {
                            close = true;
                        }
                    });
                });

            if create_sym {
                let target = sym.target_path.clone();
                let parent = if let Some((p, _)) = target.rsplit_once('/') {
                    if p.is_empty() { "/" } else { p }
                } else {
                    "/"
                };
                let link_path = if parent.ends_with('/') {
                    format!("{}{}", parent, sym.link_name.trim())
                } else {
                    format!("{}/{}", parent, sym.link_name.trim())
                };
                let _ = cmd_tx.send(BackendCommand::SftpSymlink {
                    target: target.clone(),
                    link_path: link_path.clone(),
                });
                self.log(
                    tr(
                        lang,
                        &format!("Création lien symbolique : {link_path} -> {target}"),
                        &format!("Creating symbolic link: {link_path} -> {target}"),
                    ),
                    false,
                );
            }

            if close {
                self.symlink_modal = None;
            }
        }

        // 5. Collision Resolution Modal (Bitvise #415)
        let mut collision_result: Option<CollisionChoice> = None;
        if let Some(col_modal) = &mut self.collision_modal {
            let mut close = false;
            let pending_count = self.pending_collisions.len();

            egui::Window::new(tr(lang, "⚠️ Conflit de fichier existant", "⚠️ File collision conflict"))
                .collapsible(false)
                .resizable(false)
                .default_width(450.0)
                .show(ctx, |ui| {
                    ui.label(RichText::new(tr(
                        lang,
                        "Le fichier de destination existe déjà. Quelle action souhaitez-vous exécuter ?",
                        "Destination file already exists. Which action would you like to take?",
                    )).strong());
                    if pending_count > 0 {
                        ui.label(
                            RichText::new(tr(
                                lang,
                                &format!(
                                    "Ce fichier fait partie d'une sélection : {pending_count} autre(s) conflit(s) suivront."),
                                &format!(
                                    "This file is part of a selection: {pending_count} more conflict(s) will follow."),
                            ))
                            .small()
                            .color(Color32::from_rgb(88, 166, 255)),
                        );
                    }
                    ui.add_space(4.0);

                    // Comparison side-by-side
                    egui::Grid::new("collision_grid").show(ui, |ui| {
                        ui.label("");
                        ui.label(RichText::new(tr(lang, "Taille", "Size")).strong());
                        ui.label(RichText::new(tr(lang, "Date", "Date")).strong());
                        ui.end_row();

                        let src_lbl = if col_modal.is_upload { tr(lang, "Source (Local)", "Source (Local)") } else { tr(lang, "Source (Distant)", "Source (Remote)") };
                        let src_sz = if col_modal.is_upload { col_modal.local_size } else { col_modal.remote_size };
                        let src_mt = if col_modal.is_upload { col_modal.local_mtime } else { col_modal.remote_mtime };
                        let src_d = if src_mt > 0 { chrono::DateTime::from_timestamp(src_mt as i64, 0).map(|d| d.format("%d/%m/%y %H:%M").to_string()).unwrap_or_default() } else { "-".to_string() };

                        ui.label(src_lbl);
                        ui.label(format_bytes(src_sz));
                        ui.label(src_d);
                        ui.end_row();

                        let dst_lbl = if col_modal.is_upload { tr(lang, "Cible (Distant)", "Target (Remote)") } else { tr(lang, "Cible (Local)", "Target (Local)") };
                        let dst_sz = if col_modal.is_upload { col_modal.remote_size } else { col_modal.local_size };
                        let dst_mt = if col_modal.is_upload { col_modal.remote_mtime } else { col_modal.local_mtime };
                        let dst_d = if dst_mt > 0 { chrono::DateTime::from_timestamp(dst_mt as i64, 0).map(|d| d.format("%d/%m/%y %H:%M").to_string()).unwrap_or_default() } else { "-".to_string() };

                        ui.label(dst_lbl);
                        ui.label(format_bytes(dst_sz));
                        ui.label(dst_d);
                        ui.end_row();
                    });

                    ui.add_space(6.0);
                    ui.horizontal(|ui| {
                        ui.label(tr(lang, "Renommer en :", "Rename to:"));
                        ui.text_edit_singleline(&mut col_modal.new_name);
                    });

                    ui.add_space(8.0);
                    ui.horizontal(|ui| {
                        if ui.button(tr(lang, "Écraser", "Overwrite")).clicked() {
                            collision_result = Some(CollisionChoice::Overwrite);
                            close = true;
                        }
                        if ui.button(tr(lang, "Reprendre", "Resume")).clicked() {
                            collision_result = Some(CollisionChoice::Resume);
                            close = true;
                        }
                        if ui.button(tr(lang, "Renommer", "Rename")).clicked() && !col_modal.new_name.trim().is_empty() {
                            collision_result =
                                Some(CollisionChoice::Rename(col_modal.new_name.trim().to_string()));
                            close = true;
                        }
                        if ui.button(tr(lang, "Ignorer", "Skip")).clicked() {
                            collision_result = Some(CollisionChoice::Skip);
                            close = true;
                        }
                    });
                    // Batch answers only make sense when more collisions are queued.
                    if pending_count > 0 {
                        ui.add_space(4.0);
                        ui.horizontal(|ui| {
                            if ui
                                .button(tr(lang, "Écraser tout", "Overwrite all"))
                                .clicked()
                            {
                                collision_result = Some(CollisionChoice::OverwriteAll);
                                close = true;
                            }
                            if ui.button(tr(lang, "Ignorer tout", "Skip all")).clicked() {
                                collision_result = Some(CollisionChoice::SkipAll);
                                close = true;
                            }
                        });
                    }
                });

            if !close {
                collision_result = None;
            }
        }

        let resolved_collision =
            collision_result.and_then(|res| self.collision_modal.take().map(|m| (m, res)));
        if let Some((col_modal, choice)) = resolved_collision {
            self.resolve_collision(col_modal, choice, cmd_tx, lang);
        }

        // 6. External Editor Settings Modal (Bitvise #450)
        if self.show_editor_modal {
            let mut open = self.show_editor_modal;
            let mut close = false;
            let mut current_ed = self.editor_path.clone();

            egui::Window::new(tr(
                lang,
                "⚙ Configuration de l'éditeur externe (Bitvise #450)",
                "⚙ External Editor Configuration (Bitvise #450)",
            ))
            .open(&mut open)
            .collapsible(false)
            .resizable(false)
            .default_width(420.0)
            .show(ctx, |ui| {
                ui.label(tr(
                    lang,
                    "Choisissez le programme pour l'édition des fichiers :",
                    "Choose program for editing files:",
                ));
                ui.add_space(4.0);

                ui.horizontal(|ui| {
                    ui.label(tr(lang, "Exécutable :", "Executable:"));
                    ui.add(egui::TextEdit::singleline(&mut current_ed).desired_width(240.0));
                    if ui.button(tr(lang, "Parcourir...", "Browse...")).clicked() {
                        let picked = rfd::FileDialog::new()
                            .add_filter("Exécutable", &["exe", "cmd", "bat"])
                            .pick_file();
                        if let Some(file) = picked {
                            current_ed = file.to_string_lossy().to_string();
                        }
                    }
                });

                ui.add_space(6.0);
                ui.label(
                    RichText::new(tr(lang, "Préréglages rapides :", "Quick presets:"))
                        .small()
                        .color(Color32::from_rgb(139, 148, 158)),
                );
                ui.horizontal(|ui| {
                    if ui.small_button("Notepad").clicked() {
                        current_ed = "notepad.exe".to_string();
                    }
                    if ui.small_button("VS Code").clicked() {
                        current_ed = "code".to_string();
                    }
                    if ui.small_button("Notepad++").clicked() {
                        current_ed = r"C:\Program Files\Notepad++\notepad++.exe".to_string();
                    }
                });

                ui.add_space(8.0);
                ui.horizontal(|ui| {
                    if ui.button(tr(lang, "Valider", "Apply")).clicked() {
                        self.editor_path = current_ed.trim().to_string();
                        self.log(
                            tr(
                                lang,
                                &format!("Éditeur configuré sur : {}", self.editor_path),
                                &format!("Editor set to: {}", self.editor_path),
                            ),
                            false,
                        );
                        close = true;
                    }
                    if ui.button(tr(lang, "Fermer", "Close")).clicked() {
                        close = true;
                    }
                });
            });

            if close {
                open = false;
            }
            self.show_editor_modal = open;
        }
    }
}

fn format_entry_type(file_type: &str, is_dir: bool, is_symlink: bool, lang: UiLanguage) -> String {
    if is_dir {
        tr(lang, "Dossier", "Folder").to_string()
    } else if is_symlink {
        tr(lang, "Lien sym", "Symlink").to_string()
    } else {
        match file_type {
            "Fichier image" => tr(lang, "Image", "Image").to_string(),
            "Document PDF" => tr(lang, "PDF", "PDF").to_string(),
            "Document texte" => tr(lang, "Texte", "Text").to_string(),
            "Archive" => tr(lang, "Archive", "Archive").to_string(),
            "Application" => tr(lang, "Application", "Application").to_string(),
            "Extension" => tr(lang, "Extension", "Extension").to_string(),
            "Raccourci" => tr(lang, "Raccourci", "Shortcut").to_string(),
            "Code source" => tr(lang, "Code source", "Source code").to_string(),
            _ => {
                if let Some(rest) = file_type.strip_prefix("Fichier ") {
                    format!("{} {rest}", tr(lang, "Fichier", "File"))
                } else {
                    tr(lang, "Fichier", "File").to_string()
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_local_sorting_folders_first() {
        let mut state = SftpClientState::new();
        state.local_entries = vec![
            LocalFileEntry {
                name: "zebra.txt".to_string(),
                path: PathBuf::from("zebra.txt"),
                is_dir: false,
                is_symlink: false,
                size: 100,
                mtime: 1000,
                file_type: "Fichier".to_string(),
            },
            LocalFileEntry {
                name: "alpha_dir".to_string(),
                path: PathBuf::from("alpha_dir"),
                is_dir: true,
                is_symlink: false,
                size: 0,
                mtime: 2000,
                file_type: "Dossier".to_string(),
            },
        ];

        state.sort_local();
        assert_eq!(state.local_entries[0].name, "alpha_dir");
        assert_eq!(state.local_entries[1].name, "zebra.txt");
    }

    #[test]
    fn test_log_bounding() {
        let mut state = SftpClientState::new();
        for i in 0..600 {
            state.log(format!("msg {i}"), false);
        }
        assert!(state.logs.len() <= 500);
    }

    #[test]
    fn test_transfer_mode_and_rule_labels() {
        assert_eq!(TransferMode::Binary.label(UiLanguage::English), "Binary");
        assert_eq!(TransferMode::Binary.label(UiLanguage::French), "Binaire");
        assert_eq!(TransferMode::Text.label(UiLanguage::English), "Text");
        assert_eq!(
            ExistingFileRule::Ask.label(UiLanguage::English),
            "Ask if file exists"
        );
        assert_eq!(
            ExistingFileRule::Ask.label(UiLanguage::French),
            "Demander si existe"
        );
    }

    #[test]
    fn test_watched_file_registration() {
        let mut state = SftpClientState::new();
        state.watched_files.push(WatchedEditFile {
            local_path: PathBuf::from("test.txt"),
            remote_path: "/remote/test.txt".to_string(),
            last_mtime: 12345,
            last_size: 100,
            open_editor_when_ready: false,
            use_default_app: false,
        });
        assert_eq!(state.watched_files.len(), 1);
        assert_eq!(state.watched_files[0].remote_path, "/remote/test.txt");
    }

    #[test]
    fn test_remote_sorting_columns() {
        let entries = [
            SftpFileEntry {
                name: "zeta.txt".to_string(),
                full_path: "/root/zeta.txt".to_string(),
                is_dir: false,
                is_symlink: false,
                size: 500,
                mtime: 200,
                permissions: 0o644,
            },
            SftpFileEntry {
                name: "beta_dir".to_string(),
                full_path: "/root/beta_dir".to_string(),
                is_dir: true,
                is_symlink: false,
                size: 0,
                mtime: 100,
                permissions: 0o755,
            },
            SftpFileEntry {
                name: "alpha.txt".to_string(),
                full_path: "/root/alpha.txt".to_string(),
                is_dir: false,
                is_symlink: false,
                size: 1500,
                mtime: 300,
                permissions: 0o644,
            },
        ];

        let mut sorted: Vec<&SftpFileEntry> = entries.iter().collect();
        let col = SftpCol::Size;
        let asc = true;
        let folders_first = true;
        sorted.sort_by(|a, b| {
            if folders_first && a.is_dir != b.is_dir {
                return if a.is_dir {
                    std::cmp::Ordering::Less
                } else {
                    std::cmp::Ordering::Greater
                };
            }
            let ord = match col {
                SftpCol::Name => a.name.to_lowercase().cmp(&b.name.to_lowercase()),
                SftpCol::Size => a.size.cmp(&b.size),
                SftpCol::Type => {
                    let a_type = if a.is_dir { "0" } else { "1" };
                    let b_type = if b.is_dir { "0" } else { "1" };
                    a_type.cmp(b_type)
                }
                SftpCol::Date => a.mtime.cmp(&b.mtime),
            };
            if asc { ord } else { ord.reverse() }
        });

        assert_eq!(sorted[0].name, "beta_dir");
        assert_eq!(sorted[1].name, "zeta.txt");
        assert_eq!(sorted[2].name, "alpha.txt");
    }

    #[test]
    fn test_bookmarks_and_editor_config() {
        let mut state = SftpClientState::new();
        assert!(!state.remote_bookmarks.is_empty());
        state.remote_bookmarks.push("/opt".to_string());
        assert!(state.remote_bookmarks.contains(&"/opt".to_string()));

        assert_eq!(state.editor_path, "notepad.exe");
        state.editor_path = "code".to_string();
        assert_eq!(state.editor_path, "code");
    }

    #[test]
    fn dragged_entry_outside_selection_carries_only_itself() {
        let selected: HashSet<String> = ["a.txt".to_string(), "b.txt".to_string()]
            .into_iter()
            .collect();
        assert_eq!(dragged_names(&selected, "c.txt"), vec!["c.txt".to_string()]);
    }

    #[test]
    fn dragged_entry_inside_selection_carries_whole_selection_sorted() {
        let selected: HashSet<String> = [
            "c.txt".to_string(),
            "a.txt".to_string(),
            "b.txt".to_string(),
        ]
        .into_iter()
        .collect();
        assert_eq!(
            dragged_names(&selected, "a.txt"),
            vec![
                "a.txt".to_string(),
                "b.txt".to_string(),
                "c.txt".to_string()
            ]
        );
    }

    fn set_of(names: &[&str]) -> HashSet<String> {
        names.iter().map(|n| n.to_string()).collect()
    }

    #[test]
    fn shift_click_selects_range_from_anchor_to_click() {
        let visible: Vec<String> = ["a", "b", "c", "d", "e"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        let mut selected = set_of(&["a"]);
        let mut anchor = Some("a".to_string());
        apply_range_selection(&mut selected, &mut anchor, &visible, "d", false);
        assert_eq!(selected, set_of(&["a", "b", "c", "d"]));
        assert_eq!(anchor, Some("a".to_string()), "anchor stays in place");
    }

    #[test]
    fn shift_click_reverse_range_and_ctrl_shift_extends() {
        let visible: Vec<String> = ["a", "b", "c", "d", "e"]
            .iter()
            .map(|s| s.to_string())
            .collect();

        // Clicking above the anchor selects the same inclusive range.
        let mut selected = set_of(&["d"]);
        let mut anchor = Some("d".to_string());
        apply_range_selection(&mut selected, &mut anchor, &visible, "b", false);
        assert_eq!(selected, set_of(&["b", "c", "d"]));

        // Ctrl+Shift keeps entries selected outside the range.
        let mut selected = set_of(&["a", "d"]);
        let mut anchor = Some("d".to_string());
        apply_range_selection(&mut selected, &mut anchor, &visible, "b", true);
        assert_eq!(selected, set_of(&["a", "b", "c", "d"]));
    }

    #[test]
    fn shift_click_without_anchor_behaves_like_plain_click() {
        let visible: Vec<String> = ["a", "b", "c"].iter().map(|s| s.to_string()).collect();
        let mut selected = set_of(&["a"]);
        let mut anchor = None;
        apply_range_selection(&mut selected, &mut anchor, &visible, "c", false);
        assert_eq!(selected, set_of(&["c"]));
        assert_eq!(anchor, Some("c".to_string()));

        // Anchor no longer visible (renamed/filtered away) → plain click again.
        let mut selected = set_of(&["c"]);
        let mut anchor = Some("zzz".to_string());
        apply_range_selection(&mut selected, &mut anchor, &visible, "a", false);
        assert_eq!(selected, set_of(&["a"]));
        assert_eq!(anchor, Some("a".to_string()));
    }

    fn ui_test_dir(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("cuty_ui_{tag}_{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn remote_entry(name: &str) -> SftpFileEntry {
        SftpFileEntry {
            name: name.to_string(),
            full_path: format!("/remote/{name}"),
            is_dir: false,
            is_symlink: false,
            size: 42,
            permissions: 0o644,
            mtime: 100,
        }
    }

    fn count_sftp_uploads(rx: &mut tokio::sync::mpsc::UnboundedReceiver<BackendCommand>) -> usize {
        let mut n = 0;
        while let Ok(BackendCommand::SftpUpload { .. }) = rx.try_recv() {
            n += 1;
        }
        n
    }

    #[test]
    fn multi_upload_overwrite_sends_all_files() {
        let dir = ui_test_dir("up_all");
        let paths: Vec<PathBuf> = ["f1.txt", "f2.txt", "f3.txt"]
            .iter()
            .map(|n| {
                let p = dir.join(n);
                std::fs::write(&p, n.as_bytes()).unwrap();
                p
            })
            .collect();

        let mut state = SftpClientState::new();
        state.existing_file_rule = ExistingFileRule::Overwrite;
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();

        state.enqueue_uploads(&paths, "/remote", &[], &tx, UiLanguage::English);

        assert_eq!(state.upload_queue.len(), 3, "one queue task per file");
        assert_eq!(count_sftp_uploads(&mut rx), 3, "one command per file");
        assert!(state.pending_collisions.is_empty());
        assert!(state.collision_modal.is_none());

        std::fs::remove_dir_all(dir).ok();
    }

    /// Regression test for "selecting several files only copies the first":
    /// with the default Ask rule, EVERY colliding file must be queued for
    /// resolution — previously all but the last were silently dropped.
    #[test]
    fn multi_upload_ask_queues_every_collision() {
        let dir = ui_test_dir("up_ask");
        let paths: Vec<PathBuf> = ["a.txt", "b.txt"]
            .iter()
            .map(|n| {
                let p = dir.join(n);
                std::fs::write(&p, n.as_bytes()).unwrap();
                p
            })
            .collect();
        let remote = [remote_entry("a.txt"), remote_entry("b.txt")];

        let mut state = SftpClientState::new();
        // Default rule is already Ask; make it explicit.
        state.existing_file_rule = ExistingFileRule::Ask;
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();

        state.enqueue_uploads(&paths, "/remote", &remote, &tx, UiLanguage::English);

        assert_eq!(
            count_sftp_uploads(&mut rx),
            0,
            "nothing sent without a decision"
        );
        assert!(state.upload_queue.is_empty());
        let modal = state
            .collision_modal
            .as_ref()
            .expect("first collision open");
        assert_eq!(modal.filename, "a.txt");
        assert_eq!(
            state.pending_collisions.len(),
            1,
            "the second collision waits its turn"
        );
        assert_eq!(state.pending_collisions[0].filename, "b.txt");

        std::fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn multi_download_ask_queues_every_collision() {
        let dir = ui_test_dir("dl_ask");
        for n in ["a.txt", "b.txt"] {
            std::fs::write(dir.join(n), n.as_bytes()).unwrap();
        }
        let names: Vec<String> = ["a.txt", "b.txt"].iter().map(|s| s.to_string()).collect();
        let remote = [remote_entry("a.txt"), remote_entry("b.txt")];

        let mut state = SftpClientState::new();
        state.local_path = dir.clone();
        state.existing_file_rule = ExistingFileRule::Ask;
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();

        state.enqueue_downloads(&names, "/remote", &remote, &tx, UiLanguage::English);

        let mut downloads = 0;
        while let Ok(BackendCommand::SftpDownload { .. }) = rx.try_recv() {
            downloads += 1;
        }
        assert_eq!(downloads, 0);
        assert!(state.download_queue.is_empty());
        assert_eq!(
            state.collision_modal.as_ref().unwrap().filename,
            "a.txt",
            "first collision open"
        );
        assert_eq!(state.pending_collisions.len(), 1);

        std::fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn overwrite_all_transfers_every_pending_collision() {
        let dir = ui_test_dir("up_all2");
        let paths: Vec<PathBuf> = ["a.txt", "b.txt", "c.txt"]
            .iter()
            .map(|n| {
                let p = dir.join(n);
                std::fs::write(&p, n.as_bytes()).unwrap();
                p
            })
            .collect();
        let remote = [
            remote_entry("a.txt"),
            remote_entry("b.txt"),
            remote_entry("c.txt"),
        ];

        let mut state = SftpClientState::new();
        state.existing_file_rule = ExistingFileRule::Ask;
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
        state.enqueue_uploads(&paths, "/remote", &remote, &tx, UiLanguage::English);
        assert_eq!(state.pending_collisions.len(), 2);

        let current = state.collision_modal.take().unwrap();
        state.resolve_collision(
            current,
            CollisionChoice::OverwriteAll,
            &tx,
            UiLanguage::English,
        );

        assert_eq!(
            state.upload_queue.len(),
            3,
            "current + all pending transferred"
        );
        assert_eq!(count_sftp_uploads(&mut rx), 3);
        assert!(state.pending_collisions.is_empty());
        assert!(state.collision_modal.is_none());

        std::fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn skip_all_clears_pending_and_sends_nothing() {
        let dir = ui_test_dir("skip_all");
        let paths: Vec<PathBuf> = ["a.txt", "b.txt"]
            .iter()
            .map(|n| {
                let p = dir.join(n);
                std::fs::write(&p, n.as_bytes()).unwrap();
                p
            })
            .collect();
        let remote = [remote_entry("a.txt"), remote_entry("b.txt")];

        let mut state = SftpClientState::new();
        state.existing_file_rule = ExistingFileRule::Ask;
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
        state.enqueue_uploads(&paths, "/remote", &remote, &tx, UiLanguage::English);

        let current = state.collision_modal.take().unwrap();
        state.resolve_collision(current, CollisionChoice::SkipAll, &tx, UiLanguage::English);

        assert!(state.upload_queue.is_empty());
        assert_eq!(count_sftp_uploads(&mut rx), 0);
        assert!(state.pending_collisions.is_empty());
        assert!(state.collision_modal.is_none());

        std::fs::remove_dir_all(dir).ok();
    }

    /// Full-path interaction test: renders the real browse view through an
    /// egui context and drives it with synthetic mouse events. A plain click
    /// anchors the selection, Shift+click selects the range, Ctrl+click adds
    /// a single entry — exercising the actual row handlers, not a helper.
    #[test]
    fn shift_click_in_rendered_browse_view_selects_range() {
        let dir = ui_test_dir("headless");
        for i in 1..=5 {
            std::fs::write(dir.join(format!("f{i}.txt")), vec![i as u8; 16]).unwrap();
        }

        let mut state = SftpClientState::new();
        state.local_path = dir.clone();
        state.refresh_local();
        let (tx, _rx) = tokio::sync::mpsc::unbounded_channel();

        let ctx = Context::default();
        let screen = egui::Rect::from_min_size(egui::Pos2::ZERO, egui::vec2(1280.0, 800.0));

        fn run_frame(
            ctx: &Context,
            screen: egui::Rect,
            state: &mut SftpClientState,
            tx: &UnboundedSender<BackendCommand>,
            events: Vec<egui::Event>,
        ) {
            let input = egui::RawInput {
                screen_rect: Some(screen),
                events,
                ..Default::default()
            };
            let mut out = ctx.run_ui(input, |ui| {
                let ctx = ui.ctx().clone();
                let mut close = false;
                egui::CentralPanel::default().show(ui, |ui| {
                    state.render(
                        ui,
                        &ctx,
                        UiLanguage::English,
                        "/remote",
                        &[],
                        tx,
                        &mut close,
                    );
                });
            });
            // Headless: no painter applies them, drop the texture deltas cleanly.
            out.textures_delta.clear();
        }

        fn click(
            ctx: &Context,
            screen: egui::Rect,
            state: &mut SftpClientState,
            tx: &UnboundedSender<BackendCommand>,
            pos: egui::Pos2,
            mods: egui::Modifiers,
        ) {
            // egui only tracks modifiers through ModifiersChanged events.
            run_frame(
                ctx,
                screen,
                state,
                tx,
                vec![
                    egui::Event::ModifiersChanged(mods),
                    egui::Event::PointerMoved(pos),
                ],
            );
            run_frame(
                ctx,
                screen,
                state,
                tx,
                vec![
                    egui::Event::ModifiersChanged(mods),
                    egui::Event::PointerButton {
                        pos,
                        button: egui::PointerButton::Primary,
                        pressed: true,
                        modifiers: mods,
                    },
                ],
            );
            run_frame(
                ctx,
                screen,
                state,
                tx,
                vec![
                    egui::Event::ModifiersChanged(mods),
                    egui::Event::PointerButton {
                        pos,
                        button: egui::PointerButton::Primary,
                        pressed: false,
                        modifiers: mods,
                    },
                ],
            );
            run_frame(
                ctx,
                screen,
                state,
                tx,
                vec![egui::Event::ModifiersChanged(egui::Modifiers::default())],
            );
        }

        // Layout pass.
        run_frame(&ctx, screen, &mut state, &tx, Vec::new());

        // Probe the local pane (left half) to locate one row per file:
        // a plain click selects exactly that row.
        let mut row_y: Vec<(String, f32)> = Vec::new();
        let mut y = 130.0;
        while y < 780.0 {
            click(
                &ctx,
                screen,
                &mut state,
                &tx,
                egui::Pos2::new(300.0, y),
                egui::Modifiers::default(),
            );
            if state.local_selected.len() == 1 {
                let name = state.local_selected.iter().next().unwrap().clone();
                if !row_y.iter().any(|(n, _)| *n == name) {
                    row_y.push((name, y));
                }
            }
            y += 6.0;
        }
        assert_eq!(
            row_y.len(),
            5,
            "probe must find the five file rows, got {row_y:?}"
        );
        // Sorted view: rows appear in name order.
        row_y.sort_by(|a, b| a.0.cmp(&b.0));

        // Plain click on the first row anchors the selection.
        click(
            &ctx,
            screen,
            &mut state,
            &tx,
            egui::Pos2::new(300.0, row_y[0].1),
            egui::Modifiers::default(),
        );
        assert_eq!(state.local_selected, set_of(&["f1.txt"]));

        // Shift+click on the fourth row selects the whole range.
        click(
            &ctx,
            screen,
            &mut state,
            &tx,
            egui::Pos2::new(300.0, row_y[3].1),
            egui::Modifiers {
                shift: true,
                ..Default::default()
            },
        );
        assert_eq!(
            state.local_selected,
            set_of(&["f1.txt", "f2.txt", "f3.txt", "f4.txt"]),
            "Shift+click selects the anchor→clicked range"
        );

        // Ctrl+click on the fifth row extends the selection.
        click(
            &ctx,
            screen,
            &mut state,
            &tx,
            egui::Pos2::new(300.0, row_y[4].1),
            egui::Modifiers {
                ctrl: true,
                ..Default::default()
            },
        );
        assert_eq!(
            state.local_selected,
            set_of(&["f1.txt", "f2.txt", "f3.txt", "f4.txt", "f5.txt"]),
            "Ctrl+click adds the clicked entry"
        );

        std::fs::remove_dir_all(dir).ok();
    }
}
