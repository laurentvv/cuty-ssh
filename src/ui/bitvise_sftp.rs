//! SFTP Client module for cuty-ssh.
//!
//! Provides a full-featured, integrated double-pane SFTP explorer:
//! - Dual-pane browser (Local files on left, Remote files on right)
//! - Upload & Download transfer queues with status and progress
//! - Comprehensive right-click context menu (Download/Upload, Open, Edit,
//!   Move to, Rename, Erase, SHA-256 hashes, Symlinks, Copy path, Properties)
//! - Collision resolution dialog (Rename/Resume/Overwrite/Skip)
//! - Operation activity log

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
    pub fn label(self) -> &'static str {
        match self {
            Self::Binary => "Binary",
            Self::Text => "Text",
            Self::Auto => "Auto",
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum QueueTaskStatus {
    Pending,
    InProgress,
    Paused,
    Completed,
    Error(String),
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

#[derive(Debug, Clone)]
pub struct SftpLogEntry {
    pub timestamp: String,
    pub message: String,
    pub is_error: bool,
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

pub struct BitviseSftpState {
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
    pub local_sort_col: SftpCol,
    pub local_sort_asc: bool,
    pub local_folders_first: bool,
    pub local_new_folder_name: String,
    pub show_local_mkdir: bool,

    // Remote pane extra controls
    pub remote_filter: String,
    pub remote_selected: HashSet<String>,
    pub remote_sort_col: SftpCol,
    pub remote_sort_asc: bool,
    pub remote_folders_first: bool,
    pub remote_new_folder_name: String,
    pub show_remote_mkdir: bool,

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
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SftpCol {
    Name,
    Size,
    Type,
    Date,
}

impl Default for BitviseSftpState {
    fn default() -> Self {
        Self::new()
    }
}

impl BitviseSftpState {
    pub fn new() -> Self {
        let initial_local = std::env::var("USERPROFILE")
            .map(PathBuf::from)
            .unwrap_or_else(|_| std::env::current_dir().unwrap_or_else(|_| PathBuf::from("C:\\")));

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
            local_sort_col: SftpCol::Name,
            local_sort_asc: true,
            local_folders_first: true,
            local_new_folder_name: String::new(),
            show_local_mkdir: false,

            remote_filter: String::new(),
            remote_selected: HashSet::new(),
            remote_sort_col: SftpCol::Name,
            remote_sort_asc: true,
            remote_folders_first: true,
            remote_new_folder_name: String::new(),
            show_remote_mkdir: false,

            next_task_id: 1,
            upload_queue: Vec::new(),
            download_queue: Vec::new(),
            logs: Vec::new(),

            rename_modal: None,
            move_modal: None,
            symlink_modal: None,
            delete_confirm: None,
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
            self.refresh_local();
        }
    }

    pub fn navigate_local_home(&mut self) {
        if let Ok(home) = std::env::var("USERPROFILE") {
            self.local_path = PathBuf::from(home);
            self.local_selected.clear();
            self.refresh_local();
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
        // Top Toolbar: Tabs (Browse, Upload queue, Download queue, Log) + Back to terminal
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
                            RichText::new(tr(lang, "🔍 Parcourir (Browse)", "🔍 Browse")).strong(),
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
                    let up_label = if up_count > 0 {
                        format!("⬆ File Upload ({up_count})")
                    } else {
                        "⬆ Upload queue".to_string()
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
                    let dl_label = if dl_count > 0 {
                        format!("⬇ File Download ({dl_count})")
                    } else {
                        "⬇ Download queue".to_string()
                    };
                    if ui
                        .selectable_label(self.active_tab == SftpClientTab::DownloadQueue, dl_label)
                        .clicked()
                    {
                        self.active_tab = SftpClientTab::DownloadQueue;
                    }

                    if ui
                        .selectable_label(self.active_tab == SftpClientTab::Log, "📋 Log")
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
                            .small_button("🔄 Actualiser")
                            .on_hover_text(tr(lang, "Actualiser volet local et distant", "Refresh both panes"))
                            .clicked()
                        {
                            self.refresh_local();
                            let _ = cmd_tx.send(BackendCommand::SftpListDir(remote_path.to_string()));
                            self.log("Actualisation des dossiers effectuée", false);
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

        // Use strict 2-column layout so neither pane can ever overflow or overlap
        ui.columns(2, |columns| {
            // ==================== LEFT COLUMN: LOCAL FILES ====================
            let col_left = &mut columns[0];
            egui::Frame::NONE
                .fill(Color32::from_rgb(13, 17, 23))
                .corner_radius(4.0)
                .inner_margin(egui::Margin::same(6))
                .stroke(Stroke::new(1.0, Color32::from_rgb(38, 44, 54)))
                .show(col_left, |ui| {
                    // Header: Title & Filter
                    ui.horizontal(|ui| {
                        ui.label(
                            RichText::new("Local files")
                                .strong()
                                .size(13.0)
                                .color(Color32::from_rgb(88, 166, 255)),
                        );
                        ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                            ui.add(
                                egui::TextEdit::singleline(&mut self.local_filter)
                                    .hint_text("Filtrer...")
                                    .desired_width(110.0),
                            );
                            ui.label(
                                RichText::new("Filtre:")
                                    .small()
                                    .color(Color32::from_rgb(139, 148, 158)),
                            );
                        });
                    });

                    ui.add_space(2.0);

                    // Local Toolbar: Up, New Folder, Refresh, Home, Path Box
                    ui.horizontal(|ui| {
                        if ui
                            .small_button("\u{E08E}")
                            .on_hover_text("Dossier parent")
                            .clicked()
                        {
                            self.navigate_local_up();
                        }
                        if ui
                            .small_button("\u{E24A}+")
                            .on_hover_text("Nouveau dossier local")
                            .clicked()
                        {
                            self.show_local_mkdir = !self.show_local_mkdir;
                        }
                        if ui
                            .small_button("\u{E094}")
                            .on_hover_text("Rafraîchir")
                            .clicked()
                        {
                            self.refresh_local();
                        }
                        if ui
                            .small_button("\u{E072}")
                            .on_hover_text("Home (Profil utilisateur)")
                            .clicked()
                        {
                            self.navigate_local_home();
                        }

                        let text_w = (ui.available_width() - 48.0).max(60.0);
                        let mut p_str = self.local_path_input.clone();
                        let resp =
                            ui.add(egui::TextEdit::singleline(&mut p_str).desired_width(text_w));
                        let enter =
                            resp.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter));
                        self.local_path_input = p_str;

                        if ui.small_button("Aller").clicked() || enter {
                            let p = PathBuf::from(&self.local_path_input);
                            if p.is_dir() {
                                self.local_path = p;
                                self.refresh_local();
                            }
                        }
                    });

                    if self.show_local_mkdir {
                        ui.horizontal(|ui| {
                            ui.label(RichText::new("Nom:").small());
                            ui.add(
                                egui::TextEdit::singleline(&mut self.local_new_folder_name)
                                    .desired_width(110.0),
                            );
                            if ui.small_button("Créer").clicked()
                                && !self.local_new_folder_name.trim().is_empty()
                            {
                                let new_dir =
                                    self.local_path.join(self.local_new_folder_name.trim());
                                let _ = std::fs::create_dir_all(&new_dir);
                                self.log(
                                    format!("Dossier local créé : {}", new_dir.display()),
                                    false,
                                );
                                self.local_new_folder_name.clear();
                                self.show_local_mkdir = false;
                                self.refresh_local();
                            }
                        });
                    }

                    ui.add_space(2.0);

                    // Column Headers (Fixed widths: Size 65px, Type 75px, Date 85px, Name takes remaining)
                    let pane_avail_w = ui.available_width();
                    let name_w = (pane_avail_w - 235.0).max(100.0);

                    ui.horizontal(|ui| {
                        let name_arr = if self.local_sort_col == SftpCol::Name {
                            if self.local_sort_asc { " ▲" } else { " ▼" }
                        } else {
                            ""
                        };
                        if ui
                            .add_sized(
                                [name_w, 18.0],
                                egui::Button::new(format!("Name{name_arr}"))
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
                        if ui
                            .add_sized(
                                [65.0, 18.0],
                                egui::Button::new(format!("Size{size_arr}"))
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
                        if ui
                            .add_sized(
                                [75.0, 18.0],
                                egui::Button::new(format!("Type{type_arr}"))
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
                        if ui
                            .add_sized(
                                [85.0, 18.0],
                                egui::Button::new(format!("Date Mod{date_arr}"))
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

                    // Table Body with ScrollArea
                    let list_h = (ui.available_height() - 36.0).max(120.0);
                    ScrollArea::vertical()
                        .id_salt("local_scroll_fixed")
                        .max_height(list_h)
                        .show(ui, |ui| {
                            let filter_lc = self.local_filter.trim().to_lowercase();
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
                                    let btn = ui.add_sized(
                                        [name_w, 18.0],
                                        egui::Button::new(RichText::new(label_text).color(
                                            if is_selected {
                                                Color32::from_rgb(88, 166, 255)
                                            } else {
                                                Color32::from_rgb(201, 209, 217)
                                            },
                                        ))
                                        .frame(is_selected)
                                        .truncate(),
                                    );

                                    if btn.clicked() {
                                        if ui.input(|i| i.modifiers.ctrl) {
                                            if is_selected {
                                                self.local_selected.remove(&entry.name);
                                            } else {
                                                self.local_selected.insert(entry.name.clone());
                                            }
                                        } else {
                                            self.local_selected.clear();
                                            self.local_selected.insert(entry.name.clone());
                                        }
                                    }
                                    if btn.double_clicked() && entry.is_dir {
                                        cd_local_into = Some(entry.path.clone());
                                    }

                                    // Right-click context menu (Local file)
                                    btn.context_menu(|ui| {
                                        if ui.button("⬆ Upload vers serveur distant").clicked() {
                                            launch_upload = Some(vec![entry.path.clone()]);
                                            ui.close();
                                        }
                                        if ui.button("⏸ Enqueue paused").clicked() {
                                            ui.close();
                                        }
                                        ui.separator();
                                        if ui.button("Open (Ouvrir)").clicked() {
                                            let _ = open::that(&entry.path);
                                            ui.close();
                                        }
                                        if ui.button("Edit (Éditer)").clicked() {
                                            let _ = std::process::Command::new("notepad.exe")
                                                .arg(&entry.path)
                                                .spawn();
                                            ui.close();
                                        }
                                        if ui.button("Rename (Renommer)...").clicked() {
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
                                        if ui.button("Erase (Supprimer)").clicked() {
                                            self.delete_confirm = Some((
                                                false,
                                                entry.path.to_string_lossy().to_string(),
                                                entry.is_dir,
                                            ));
                                            ui.close();
                                        }
                                        ui.separator();
                                        if ui.button("Copy full path (Copier le chemin)").clicked()
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
                                        [65.0, 18.0],
                                        egui::Label::new(
                                            RichText::new(size_str)
                                                .small()
                                                .monospace()
                                                .color(Color32::from_rgb(139, 148, 158)),
                                        ),
                                    );

                                    // Type
                                    ui.add_sized(
                                        [75.0, 18.0],
                                        egui::Label::new(
                                            RichText::new(&entry.file_type)
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
                                        [85.0, 18.0],
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

                    // Bottom Action Bar (Local)
                    ui.horizontal(|ui| {
                        let can_upload = !self.local_selected.is_empty();
                        if ui
                            .add_enabled(
                                can_upload,
                                egui::Button::new(RichText::new("⬆ Upload →").strong()),
                            )
                            .clicked()
                        {
                            let paths: Vec<PathBuf> = self
                                .local_selected
                                .iter()
                                .map(|n| self.local_path.join(n))
                                .collect();
                            launch_upload = Some(paths);
                        }

                        ui.checkbox(&mut self.queue_paused, "Pause");

                        egui::ComboBox::from_id_salt("local_mode_cb_v2")
                            .selected_text(self.transfer_mode.label())
                            .show_ui(ui, |ui| {
                                ui.selectable_value(
                                    &mut self.transfer_mode,
                                    TransferMode::Binary,
                                    "Binary",
                                );
                                ui.selectable_value(
                                    &mut self.transfer_mode,
                                    TransferMode::Text,
                                    "Text",
                                );
                                ui.selectable_value(
                                    &mut self.transfer_mode,
                                    TransferMode::Auto,
                                    "Auto",
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

            // ==================== RIGHT COLUMN: REMOTE FILES ====================
            let col_right = &mut columns[1];
            egui::Frame::NONE
                .fill(Color32::from_rgb(13, 17, 23))
                .corner_radius(4.0)
                .inner_margin(egui::Margin::same(6))
                .stroke(Stroke::new(1.0, Color32::from_rgb(38, 44, 54)))
                .show(col_right, |ui| {
                    // Header: Title & Filter
                    ui.horizontal(|ui| {
                        ui.label(
                            RichText::new("Remote files")
                                .strong()
                                .size(13.0)
                                .color(Color32::from_rgb(46, 160, 67)),
                        );
                        ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                            ui.add(
                                egui::TextEdit::singleline(&mut self.remote_filter)
                                    .hint_text("Filtrer...")
                                    .desired_width(110.0),
                            );
                            ui.label(
                                RichText::new("Filtre:")
                                    .small()
                                    .color(Color32::from_rgb(139, 148, 158)),
                            );
                        });
                    });

                    ui.add_space(2.0);

                    // Remote Toolbar: Up, New Folder, Refresh, Home, Path Box
                    ui.horizontal(|ui| {
                        if ui
                            .small_button("\u{E08E}")
                            .on_hover_text("Dossier parent")
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
                            .on_hover_text("Nouveau dossier distant")
                            .clicked()
                        {
                            self.show_remote_mkdir = !self.show_remote_mkdir;
                        }
                        if ui
                            .small_button("\u{E094}")
                            .on_hover_text("Rafraîchir")
                            .clicked()
                        {
                            let _ =
                                cmd_tx.send(BackendCommand::SftpListDir(remote_path.to_string()));
                        }
                        if ui
                            .small_button("\u{E072}")
                            .on_hover_text("Home (~ /root)")
                            .clicked()
                        {
                            cd_remote_into = Some(".".to_string());
                        }

                        let text_w = (ui.available_width() - 48.0).max(60.0);
                        let mut p_str = remote_path.to_string();
                        let resp =
                            ui.add(egui::TextEdit::singleline(&mut p_str).desired_width(text_w));
                        let enter =
                            resp.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter));
                        if ui.small_button("Aller").clicked() || enter {
                            cd_remote_into = Some(p_str);
                        }
                    });

                    if self.show_remote_mkdir {
                        ui.horizontal(|ui| {
                            ui.label(RichText::new("Nom:").small());
                            ui.add(
                                egui::TextEdit::singleline(&mut self.remote_new_folder_name)
                                    .desired_width(110.0),
                            );
                            if ui.small_button("Créer").clicked()
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
                                self.log(format!("Création dossier distant : {target}"), false);
                                self.remote_new_folder_name.clear();
                                self.show_remote_mkdir = false;
                            }
                        });
                    }

                    ui.add_space(2.0);

                    // Column Headers (Fixed widths)
                    let pane_avail_w = ui.available_width();
                    let name_w = (pane_avail_w - 235.0).max(100.0);

                    ui.horizontal(|ui| {
                        let name_arr = if self.remote_sort_col == SftpCol::Name {
                            if self.remote_sort_asc { " ▲" } else { " ▼" }
                        } else {
                            ""
                        };
                        if ui
                            .add_sized(
                                [name_w, 18.0],
                                egui::Button::new(format!("Name{name_arr}"))
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
                        if ui
                            .add_sized(
                                [65.0, 18.0],
                                egui::Button::new(format!("Size{size_arr}"))
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
                        if ui
                            .add_sized(
                                [75.0, 18.0],
                                egui::Button::new(format!("Type{type_arr}"))
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
                        if ui
                            .add_sized(
                                [85.0, 18.0],
                                egui::Button::new(format!("Date Mod{date_arr}"))
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

                    // Table Body with ScrollArea
                    let list_h = (ui.available_height() - 36.0).max(120.0);
                    ScrollArea::vertical()
                        .id_salt("remote_scroll_fixed")
                        .max_height(list_h)
                        .show(ui, |ui| {
                            let filter_lc = self.remote_filter.trim().to_lowercase();
                            for entry in remote_entries {
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
                                    let btn = ui.add_sized(
                                        [name_w, 18.0],
                                        egui::Button::new(RichText::new(label_text).color(
                                            if is_selected {
                                                Color32::from_rgb(88, 166, 255)
                                            } else {
                                                Color32::from_rgb(201, 209, 217)
                                            },
                                        ))
                                        .frame(is_selected)
                                        .truncate(),
                                    );

                                    if btn.clicked() {
                                        if ui.input(|i| i.modifiers.ctrl) {
                                            if is_selected {
                                                self.remote_selected.remove(&entry.name);
                                            } else {
                                                self.remote_selected.insert(entry.name.clone());
                                            }
                                        } else {
                                            self.remote_selected.clear();
                                            self.remote_selected.insert(entry.name.clone());
                                        }
                                    }
                                    if btn.double_clicked() && entry.is_dir {
                                        cd_remote_into = Some(entry.full_path.clone());
                                    }

                                    // Context Menu
                                    btn.context_menu(|ui| {
                                        if ui.button("Download (Télécharger)").clicked() {
                                            launch_download = Some(vec![entry.name.clone()]);
                                            ui.close();
                                        }
                                        if ui.button("Enqueue new downloads paused").clicked() {
                                            ui.close();
                                        }
                                        ui.separator();
                                        if ui.button("Open (Ouvrir)").clicked() {
                                            let temp_file = std::env::temp_dir().join(&entry.name);
                                            let _ = cmd_tx.send(BackendCommand::SftpDownload {
                                                remote_path: entry.full_path.clone(),
                                                local_path: temp_file.clone(),
                                            });
                                            let _ = open::that(&temp_file);
                                            ui.close();
                                        }
                                        if ui.button("Edit (Éditer)").clicked() {
                                            let temp_file = std::env::temp_dir().join(&entry.name);
                                            let _ = cmd_tx.send(BackendCommand::SftpDownload {
                                                remote_path: entry.full_path.clone(),
                                                local_path: temp_file.clone(),
                                            });
                                            let _ = std::process::Command::new("notepad.exe")
                                                .arg(&temp_file)
                                                .spawn();
                                            ui.close();
                                        }
                                        if ui.button("Move to... (Déplacer vers...)").clicked() {
                                            self.move_modal = Some(MoveModal {
                                                is_remote: true,
                                                current_full_path: entry.full_path.clone(),
                                                destination_dir: remote_path.to_string(),
                                            });
                                            ui.close();
                                        }
                                        if ui.button("Erase (Supprimer)").clicked() {
                                            self.delete_confirm =
                                                Some((true, entry.full_path.clone(), entry.is_dir));
                                            ui.close();
                                        }
                                        if ui.button("Rename (Renommer)...").clicked() {
                                            self.rename_modal = Some(RenameModal {
                                                is_remote: true,
                                                current_full_path: entry.full_path.clone(),
                                                new_name: entry.name.clone(),
                                            });
                                            ui.close();
                                        }
                                        if ui.button("Calculate hashes (SHA-256)").clicked() {
                                            let _ = cmd_tx.send(BackendCommand::SftpSha256(
                                                entry.full_path.clone(),
                                            ));
                                            self.log(
                                                format!(
                                                    "Calcul SHA-256 en cours pour {}",
                                                    entry.full_path
                                                ),
                                                false,
                                            );
                                            ui.close();
                                        }
                                        ui.separator();
                                        if ui.button("Create link (Lien symbolique)...").clicked() {
                                            self.symlink_modal = Some(SymlinkModal {
                                                target_path: entry.full_path.clone(),
                                                link_name: format!("{}_link", entry.name),
                                            });
                                            ui.close();
                                        }
                                        if ui.button("Copy full path (Copier le chemin)").clicked()
                                        {
                                            if let Ok(mut clip) = arboard::Clipboard::new() {
                                                let _ = clip.set_text(&entry.full_path);
                                            }
                                            ui.close();
                                        }
                                        ui.separator();
                                        if ui
                                            .button("Properties (Permissions chmod / SHA-256)")
                                            .clicked()
                                        {
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
                                        [65.0, 18.0],
                                        egui::Label::new(
                                            RichText::new(size_str)
                                                .small()
                                                .monospace()
                                                .color(Color32::from_rgb(139, 148, 158)),
                                        ),
                                    );

                                    // Type
                                    let type_str = if entry.is_dir {
                                        "Dossier".to_string()
                                    } else if entry.is_symlink {
                                        "Lien sym".to_string()
                                    } else {
                                        "Fichier".to_string()
                                    };
                                    ui.add_sized(
                                        [75.0, 18.0],
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
                                        [85.0, 18.0],
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

                    // Bottom Action Bar (Remote)
                    ui.horizontal(|ui| {
                        let can_download = !self.remote_selected.is_empty();
                        if ui
                            .add_enabled(
                                can_download,
                                egui::Button::new(RichText::new("← Download ⬇").strong()),
                            )
                            .clicked()
                        {
                            let names: Vec<String> = self.remote_selected.iter().cloned().collect();
                            launch_download = Some(names);
                        }

                        ui.checkbox(&mut self.queue_paused, "Pause");

                        egui::ComboBox::from_id_salt("remote_mode_cb_v2")
                            .selected_text(self.transfer_mode.label())
                            .show_ui(ui, |ui| {
                                ui.selectable_value(
                                    &mut self.transfer_mode,
                                    TransferMode::Binary,
                                    "Binary",
                                );
                                ui.selectable_value(
                                    &mut self.transfer_mode,
                                    TransferMode::Text,
                                    "Text",
                                );
                                ui.selectable_value(
                                    &mut self.transfer_mode,
                                    TransferMode::Auto,
                                    "Auto",
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
        });

        // Navigation
        if let Some(target) = cd_local_into {
            self.local_path = target;
            self.local_selected.clear();
            self.refresh_local();
        }
        if let Some(target) = cd_remote_into {
            let _ = cmd_tx.send(BackendCommand::SftpListDir(target));
            self.remote_selected.clear();
        }

        // Upload batch
        if let Some(paths) = launch_upload {
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

                let meta_len = std::fs::metadata(&p).map(|m| m.len()).unwrap_or(0);
                let task_id = self.next_task_id;
                self.next_task_id += 1;

                self.upload_queue.push(QueueTask {
                    id: task_id,
                    filename: filename.clone(),
                    local_path: p.clone(),
                    remote_path: remote_target.clone(),
                    size: meta_len,
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
                        local_path: p,
                        remote_path: remote_target.clone(),
                    });
                    self.log(
                        format!("Upload démarré : {filename} -> {remote_target}"),
                        false,
                    );
                }
            }
        }

        // Download batch
        if let Some(names) = launch_download {
            for name in names {
                let remote_src = if remote_path.ends_with('/') {
                    format!("{}{}", remote_path, name)
                } else {
                    format!("{}/{}", remote_path, name)
                };
                let local_dst = self.local_path.join(&name);

                let task_id = self.next_task_id;
                self.next_task_id += 1;

                self.download_queue.push(QueueTask {
                    id: task_id,
                    filename: name.clone(),
                    local_path: local_dst.clone(),
                    remote_path: remote_src.clone(),
                    size: 0,
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
                    self.log(format!("Téléchargement démarré : {name} -> local"), false);
                }
            }
        }
    }

    fn render_upload_queue_tab(&mut self, ui: &mut Ui, _lang: UiLanguage) {
        ui.heading("⬆ File d'attente d'Upload (Upload Queue)");
        ui.add_space(4.0);

        ScrollArea::vertical().show(ui, |ui| {
            if self.upload_queue.is_empty() {
                ui.label(
                    RichText::new("Aucun transfert d'upload en attente.")
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
                            QueueTaskStatus::Error(_) => "❌",
                        };
                        ui.label(format!("{} {}", icon, task.filename));
                        ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                            let status_text = match &task.status {
                                QueueTaskStatus::Pending => "En attente".to_string(),
                                QueueTaskStatus::InProgress => "En cours".to_string(),
                                QueueTaskStatus::Paused => "En pause".to_string(),
                                QueueTaskStatus::Completed => "Terminé".to_string(),
                                QueueTaskStatus::Error(e) => format!("Erreur: {e}"),
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

    fn render_download_queue_tab(&mut self, ui: &mut Ui, _lang: UiLanguage) {
        ui.heading("⬇ File d'attente de Téléchargement (Download Queue)");
        ui.add_space(4.0);

        ScrollArea::vertical().show(ui, |ui| {
            if self.download_queue.is_empty() {
                ui.label(
                    RichText::new("Aucun téléchargement en attente.")
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
                            QueueTaskStatus::Error(_) => "❌",
                        };
                        ui.label(format!("{} {}", icon, task.filename));
                        ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                            let status_text = match &task.status {
                                QueueTaskStatus::Pending => "En attente".to_string(),
                                QueueTaskStatus::InProgress => "En cours".to_string(),
                                QueueTaskStatus::Paused => "En pause".to_string(),
                                QueueTaskStatus::Completed => "Terminé".to_string(),
                                QueueTaskStatus::Error(e) => format!("Erreur: {e}"),
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

    fn render_log_tab(&mut self, ui: &mut Ui, _lang: UiLanguage) {
        ui.horizontal(|ui| {
            ui.heading("📋 Journal des opérations SFTP (Log)");
            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                if ui.small_button("Effacer l'historique").clicked() {
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
        _lang: UiLanguage,
        cmd_tx: &UnboundedSender<BackendCommand>,
    ) {
        if let Some(rename) = &mut self.rename_modal {
            let mut close = false;
            let mut execute_rename = false;

            egui::Window::new("Renommer (Rename)")
                .collapsible(false)
                .resizable(false)
                .show(ctx, |ui| {
                    ui.label(format!("Élément : {}", rename.current_full_path));
                    ui.add_space(4.0);
                    ui.horizontal(|ui| {
                        ui.label("Nouveau nom :");
                        ui.text_edit_singleline(&mut rename.new_name);
                    });
                    ui.add_space(6.0);
                    ui.horizontal(|ui| {
                        if ui.button("OK").clicked() {
                            execute_rename = true;
                            close = true;
                        }
                        if ui.button("Annuler").clicked() {
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
                    self.log(format!("Renommage distant : {old} -> {new_path}"), false);
                } else {
                    let old_path = PathBuf::from(&old);
                    if let Some(parent) = old_path.parent() {
                        let new_path = parent.join(new_name);
                        let _ = std::fs::rename(&old_path, &new_path);
                        self.log(
                            format!(
                                "Renommage local : {} -> {}",
                                old_path.display(),
                                new_path.display()
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

        if let Some((is_remote, path, is_dir)) = &self.delete_confirm {
            let mut close = false;
            let mut do_delete = false;
            let path_copy = path.clone();
            let is_remote_copy = *is_remote;
            let is_dir_copy = *is_dir;

            egui::Window::new("Confirmer la suppression (Erase)")
                .collapsible(false)
                .resizable(false)
                .show(ctx, |ui| {
                    ui.label(format!(
                        "Voulez-vous vraiment supprimer cet élément ?\n\n{path_copy}"
                    ));
                    ui.add_space(6.0);
                    ui.horizontal(|ui| {
                        if ui
                            .button(
                                RichText::new("Supprimer").color(Color32::from_rgb(248, 81, 73)),
                            )
                            .clicked()
                        {
                            do_delete = true;
                            close = true;
                        }
                        if ui.button("Annuler").clicked() {
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
                        format!("Suppression distante demandée : {path_copy}"),
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
                        self.log(format!("Supprimé localement : {path_copy}"), false);
                        self.refresh_local();
                    }
                }
            }

            if close {
                self.delete_confirm = None;
            }
        }

        if let Some(sym) = &mut self.symlink_modal {
            let mut close = false;
            let mut create_sym = false;

            egui::Window::new("Créer un lien symbolique (Create link)")
                .collapsible(false)
                .resizable(false)
                .show(ctx, |ui| {
                    ui.label(format!("Cible : {}", sym.target_path));
                    ui.add_space(4.0);
                    ui.horizontal(|ui| {
                        ui.label("Nom du lien :");
                        ui.text_edit_singleline(&mut sym.link_name);
                    });
                    ui.add_space(6.0);
                    ui.horizontal(|ui| {
                        if ui.button("Créer le lien").clicked() {
                            create_sym = true;
                            close = true;
                        }
                        if ui.button("Annuler").clicked() {
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
                    format!("Création lien symbolique : {link_path} -> {target}"),
                    false,
                );
            }

            if close {
                self.symlink_modal = None;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_local_sorting_folders_first() {
        let mut state = BitviseSftpState {
            active_tab: SftpClientTab::Browse,
            transfer_mode: TransferMode::Binary,
            existing_file_rule: ExistingFileRule::Ask,
            queue_paused: false,
            local_path: PathBuf::from("."),
            local_path_input: ".".to_string(),
            local_filter: String::new(),
            local_entries: vec![
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
            ],
            local_selected: HashSet::new(),
            local_sort_col: SftpCol::Name,
            local_sort_asc: true,
            local_folders_first: true,
            local_new_folder_name: String::new(),
            show_local_mkdir: false,
            remote_filter: String::new(),
            remote_selected: HashSet::new(),
            remote_sort_col: SftpCol::Name,
            remote_sort_asc: true,
            remote_folders_first: true,
            remote_new_folder_name: String::new(),
            show_remote_mkdir: false,
            next_task_id: 1,
            upload_queue: Vec::new(),
            download_queue: Vec::new(),
            logs: Vec::new(),
            rename_modal: None,
            move_modal: None,
            symlink_modal: None,
            delete_confirm: None,
        };

        state.sort_local();
        assert_eq!(state.local_entries[0].name, "alpha_dir");
        assert_eq!(state.local_entries[1].name, "zebra.txt");
    }

    #[test]
    fn test_log_bounding() {
        let mut state = BitviseSftpState::new();
        for i in 0..600 {
            state.log(format!("msg {i}"), false);
        }
        assert!(state.logs.len() <= 500);
    }

    #[test]
    fn test_transfer_mode_and_rule_labels() {
        assert_eq!(TransferMode::Binary.label(), "Binary");
        assert_eq!(TransferMode::Text.label(), "Text");
        assert_eq!(
            ExistingFileRule::Ask.label(UiLanguage::English),
            "Ask if file exists"
        );
        assert_eq!(
            ExistingFileRule::Ask.label(UiLanguage::French),
            "Demander si existe"
        );
    }
}
