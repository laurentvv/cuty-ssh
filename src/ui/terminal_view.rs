//! High-performance batched terminal canvas renderer, Split-Pane View, and VT keyboard encoding.

use crate::config::{ProtocolType, UiLanguage};
use crate::protocols::BackendCommand;
use crate::ui::help_modal::tr;
use crate::ui::{CutySshApp, SessionTab, SplitMode};
use arboard::Clipboard;
use egui::{
    Color32, Context, FontFamily, FontId, Key, Modifiers, Pos2, Rect, RichText, Sense, Stroke, Ui,
    Vec2,
};

impl CutySshApp {
    pub fn render_active_terminal(&mut self, ui: &mut Ui, ctx: &Context) {
        if self.tabs.is_empty() {
            return;
        }
        if self.active_tab_idx >= self.tabs.len() {
            self.active_tab_idx = self.tabs.len() - 1;
        }

        // Resolve secondary tab index for Split View if enabled and >= 2 tabs exist
        let secondary_idx = if self.split_mode != SplitMode::None && self.tabs.len() >= 2 {
            let candidate = self
                .split_secondary_tab
                .and_then(|id| self.tabs.iter().position(|t| t.tab_id == id))
                .filter(|&idx| idx != self.active_tab_idx)
                .unwrap_or_else(|| (self.active_tab_idx + 1) % self.tabs.len());
            self.split_secondary_tab = Some(self.tabs[candidate].tab_id);
            Some(candidate)
        } else {
            None
        };

        let modal_open = self.show_session_editor
            || self.show_key_manager
            || self.show_commands_editor
            || self.show_command_palette
            || self.show_network_tools
            || self.show_about
            || self.show_session_manager
            || self.show_known_hosts
            || self.show_help;
        let lang = self.config.language;

        match (self.split_mode, secondary_idx) {
            (SplitMode::Vertical, Some(sec_idx)) => {
                let total = ui.available_size();
                let half_w = ((total.x - 6.0) * 0.5).max(160.0);
                let mut focus_switch: Option<usize> = None;
                let mut outbound_primary: Vec<u8> = Vec::new();
                let mut outbound_secondary: Vec<u8> = Vec::new();

                ui.horizontal(|ui| {
                    ui.allocate_ui(Vec2::new(half_w, total.y), |ui| {
                        let is_focused = true;
                        if let Some(tab) = self.tabs.get_mut(self.active_tab_idx) {
                            render_pane_header(
                                ui,
                                &tab.profile.name,
                                &tab.profile.host,
                                true,
                                lang,
                            );
                            let (clicked, bytes) = render_single_terminal_pane(
                                ui,
                                ctx,
                                tab,
                                TerminalPaneOpts {
                                    copy_on_select: self.config.copy_on_select,
                                    right_click_paste: self.config.right_click_paste,
                                    detect_hyperlinks: self.config.detect_hyperlinks,
                                    capture_keyboard: is_focused && !modal_open,
                                    lang,
                                },
                            );
                            let _ = clicked;
                            outbound_primary = bytes;
                        }
                    });

                    ui.separator();

                    ui.allocate_ui(Vec2::new(half_w, total.y), |ui| {
                        if let Some(tab) = self.tabs.get_mut(sec_idx) {
                            render_pane_header(
                                ui,
                                &tab.profile.name,
                                &tab.profile.host,
                                false,
                                lang,
                            );
                            let (clicked, bytes) = render_single_terminal_pane(
                                ui,
                                ctx,
                                tab,
                                TerminalPaneOpts {
                                    copy_on_select: self.config.copy_on_select,
                                    right_click_paste: self.config.right_click_paste,
                                    detect_hyperlinks: self.config.detect_hyperlinks,
                                    capture_keyboard: false,
                                    lang,
                                },
                            );
                            if clicked {
                                focus_switch = Some(sec_idx);
                            }
                            outbound_secondary = bytes;
                        }
                    });
                });

                if !outbound_primary.is_empty() {
                    if let Some(t) = self.tabs.get_mut(self.active_tab_idx) {
                        t.terminal.state.scroll_offset = 0;
                    }
                    self.send_bytes_to_active_or_broadcast(&outbound_primary);
                }
                if !outbound_secondary.is_empty()
                    && let Some(t) = self.tabs.get_mut(sec_idx)
                    && !t.profile.read_only
                {
                    t.terminal.state.scroll_offset = 0;
                    let _ = t
                        .handle
                        .cmd_tx
                        .send(BackendCommand::SendInput(outbound_secondary));
                }
                if let Some(new_active) = focus_switch {
                    let old_active_id = self.tabs[self.active_tab_idx].tab_id;
                    self.active_tab_idx = new_active;
                    self.split_secondary_tab = Some(old_active_id);
                }
            }
            (SplitMode::Horizontal, Some(sec_idx)) => {
                let total = ui.available_size();
                let half_h = ((total.y - 8.0) * 0.5).max(100.0);
                let mut focus_switch: Option<usize> = None;
                let mut outbound_primary: Vec<u8> = Vec::new();
                let mut outbound_secondary: Vec<u8> = Vec::new();

                ui.vertical(|ui| {
                    ui.allocate_ui(Vec2::new(total.x, half_h), |ui| {
                        if let Some(tab) = self.tabs.get_mut(self.active_tab_idx) {
                            render_pane_header(
                                ui,
                                &tab.profile.name,
                                &tab.profile.host,
                                true,
                                lang,
                            );
                            let (_clicked, bytes) = render_single_terminal_pane(
                                ui,
                                ctx,
                                tab,
                                TerminalPaneOpts {
                                    copy_on_select: self.config.copy_on_select,
                                    right_click_paste: self.config.right_click_paste,
                                    detect_hyperlinks: self.config.detect_hyperlinks,
                                    capture_keyboard: !modal_open,
                                    lang,
                                },
                            );
                            outbound_primary = bytes;
                        }
                    });

                    ui.separator();

                    ui.allocate_ui(Vec2::new(total.x, half_h), |ui| {
                        if let Some(tab) = self.tabs.get_mut(sec_idx) {
                            render_pane_header(
                                ui,
                                &tab.profile.name,
                                &tab.profile.host,
                                false,
                                lang,
                            );
                            let (clicked, bytes) = render_single_terminal_pane(
                                ui,
                                ctx,
                                tab,
                                TerminalPaneOpts {
                                    copy_on_select: self.config.copy_on_select,
                                    right_click_paste: self.config.right_click_paste,
                                    detect_hyperlinks: self.config.detect_hyperlinks,
                                    capture_keyboard: false,
                                    lang,
                                },
                            );
                            if clicked {
                                focus_switch = Some(sec_idx);
                            }
                            outbound_secondary = bytes;
                        }
                    });
                });

                if !outbound_primary.is_empty() {
                    if let Some(t) = self.tabs.get_mut(self.active_tab_idx) {
                        t.terminal.state.scroll_offset = 0;
                    }
                    self.send_bytes_to_active_or_broadcast(&outbound_primary);
                }
                if !outbound_secondary.is_empty()
                    && let Some(t) = self.tabs.get_mut(sec_idx)
                    && !t.profile.read_only
                {
                    t.terminal.state.scroll_offset = 0;
                    let _ = t
                        .handle
                        .cmd_tx
                        .send(BackendCommand::SendInput(outbound_secondary));
                }
                if let Some(new_active) = focus_switch {
                    let old_active_id = self.tabs[self.active_tab_idx].tab_id;
                    self.active_tab_idx = new_active;
                    self.split_secondary_tab = Some(old_active_id);
                }
            }
            _ => {
                let mut outbound: Vec<u8> = Vec::new();
                if let Some(tab) = self.tabs.get_mut(self.active_tab_idx) {
                    let (_clicked, bytes) = render_single_terminal_pane(
                        ui,
                        ctx,
                        tab,
                        TerminalPaneOpts {
                            copy_on_select: self.config.copy_on_select,
                            right_click_paste: self.config.right_click_paste,
                            detect_hyperlinks: self.config.detect_hyperlinks,
                            capture_keyboard: !modal_open,
                            lang,
                        },
                    );
                    outbound = bytes;
                }
                if !outbound.is_empty() {
                    if let Some(t) = self.tabs.get_mut(self.active_tab_idx) {
                        t.terminal.state.scroll_offset = 0;
                    }
                    self.send_bytes_to_active_or_broadcast(&outbound);
                }
            }
        }
    }
}

#[derive(Clone, Copy)]
struct TerminalPaneOpts {
    copy_on_select: bool,
    right_click_paste: bool,
    detect_hyperlinks: bool,
    capture_keyboard: bool,
    lang: UiLanguage,
}

fn render_pane_header(ui: &mut Ui, name: &str, host: &str, is_primary: bool, lang: UiLanguage) {
    let border_col = if is_primary {
        Color32::from_rgb(88, 166, 255)
    } else {
        Color32::from_rgb(48, 54, 61)
    };
    egui::Frame::NONE
        .fill(if is_primary {
            Color32::from_rgb(18, 28, 44)
        } else {
            Color32::from_rgb(15, 19, 26)
        })
        .inner_margin(egui::Margin::symmetric(8, 2))
        .stroke(Stroke::new(1.0, border_col))
        .show(ui, |ui| {
            ui.horizontal(|ui| {
                let badge = if is_primary {
                    tr(lang, "🎯 Focus Actif", "🎯 Active Focus")
                } else {
                    tr(
                        lang,
                        "👁 Vue Secondaire (cliquer pour activer)",
                        "👁 Secondary Pane (click to focus)",
                    )
                };
                ui.label(
                    RichText::new(format!("{} — {} ({})", badge, name, host))
                        .size(11.0)
                        .strong()
                        .color(if is_primary {
                            Color32::from_rgb(165, 214, 255)
                        } else {
                            Color32::from_rgb(139, 148, 158)
                        }),
                );
            });
        });
}

fn render_single_terminal_pane(
    ui: &mut Ui,
    ctx: &Context,
    tab: &mut SessionTab,
    opts: TerminalPaneOpts,
) -> (bool, Vec<u8>) {
    let TerminalPaneOpts {
        copy_on_select,
        right_click_paste,
        detect_hyperlinks,
        capture_keyboard,
        lang,
    } = opts;
    // Live SSH Server Telemetry Strip
    if tab.show_telemetry_bar && tab.profile.protocol == ProtocolType::Ssh {
        egui::Frame::NONE
            .fill(Color32::from_rgb(15, 20, 29))
            .inner_margin(egui::Margin::symmetric(10, 5))
            .stroke(Stroke::new(1.0, Color32::from_rgb(34, 42, 58)))
            .show(ui, |ui| {
                ui.horizontal_wrapped(|ui| {
                    if let Some(m) = &tab.telemetry {
                        ui.label(
                            RichText::new(format!("🖥 {}", m.hostname))
                                .monospace()
                                .strong()
                                .color(Color32::from_rgb(88, 166, 255)),
                        )
                        .on_hover_text(format!("Kernel: {}\nUptime: {}", m.kernel, m.uptime));
                        ui.separator();

                        ui.label(
                            RichText::new(format!("⚡ Load: {}", m.load_avg))
                                .monospace()
                                .small()
                                .color(Color32::from_rgb(201, 209, 217)),
                        );
                        ui.separator();

                        if m.mem_total_mb > 0 {
                            let mem_frac =
                                (m.mem_used_mb as f32 / m.mem_total_mb as f32).clamp(0.0, 1.0);
                            let mem_col = if mem_frac < 0.70 {
                                Color32::from_rgb(52, 211, 153)
                            } else if mem_frac < 0.90 {
                                Color32::from_rgb(210, 153, 34)
                            } else {
                                Color32::from_rgb(248, 81, 73)
                            };
                            ui.label(RichText::new("🧠 RAM:").small());
                            ui.add(
                                egui::ProgressBar::new(mem_frac)
                                    .desired_width(115.0)
                                    .fill(mem_col)
                                    .text(format!(
                                        "{}/{} MB ({:.0}%)",
                                        m.mem_used_mb,
                                        m.mem_total_mb,
                                        mem_frac * 100.0
                                    )),
                            );
                            ui.separator();
                        }

                        if m.disk_used_pct > 0.0 {
                            let disk_frac = (m.disk_used_pct / 100.0).clamp(0.0, 1.0);
                            let disk_col = if disk_frac < 0.75 {
                                Color32::from_rgb(88, 166, 255)
                            } else if disk_frac < 0.90 {
                                Color32::from_rgb(210, 153, 34)
                            } else {
                                Color32::from_rgb(248, 81, 73)
                            };
                            ui.label(RichText::new(tr(lang, "💾 Disque /:", "💾 Disk /:")).small());
                            ui.add(
                                egui::ProgressBar::new(disk_frac)
                                    .desired_width(110.0)
                                    .fill(disk_col)
                                    .text(format!("{:.0}% ({})", m.disk_used_pct, m.disk_summary)),
                            );
                            ui.separator();
                        }

                        ui.label(
                            RichText::new(format!("⏱ {}", m.uptime))
                                .small()
                                .color(Color32::from_rgb(139, 148, 158)),
                        );
                    } else {
                        ui.label(
                            RichText::new(tr(
                                lang,
                                "📊 Télémétrie serveur SSH en attente de collecte...",
                                "📊 Waiting for SSH server telemetry...",
                            ))
                            .small()
                            .color(Color32::from_rgb(139, 148, 158)),
                        );
                    }

                    if ui
                        .small_button(tr(lang, "🔄 Actualiser", "🔄 Refresh"))
                        .on_hover_text(tr(
                            lang,
                            "Actualiser les métriques CPU / RAM / Disque du serveur",
                            "Refresh server CPU / RAM / Disk telemetry metrics",
                        ))
                        .clicked()
                    {
                        let _ = tab.handle.cmd_tx.send(BackendCommand::RefreshTelemetry);
                    }
                });
            });
    }

    if tab.show_search_bar {
        egui::Frame::NONE
            .fill(Color32::from_rgb(24, 30, 42))
            .inner_margin(egui::Margin::symmetric(10, 4))
            .show(ui, |ui| {
                ui.horizontal(|ui| {
                    ui.label(tr(
                        lang,
                        "🔍 Recherche dans le terminal :",
                        "🔍 Search in terminal:",
                    ));
                    ui.text_edit_singleline(&mut tab.search_query);
                    if ui.small_button(tr(lang, "Fermer", "Close")).clicked() {
                        tab.show_search_bar = false;
                        tab.search_query.clear();
                    }
                });
            });
    }

    let font_size = tab.profile.font_size.clamp(10.0, 28.0);
    let font_id = FontId::new(font_size, FontFamily::Monospace);
    let char_width = (font_size * 0.6).max(6.0);
    let line_height = (font_size * 1.25).max(12.0);

    let avail = ui.available_size();
    let new_cols = ((avail.x - 16.0) / char_width).floor().max(20.0) as usize;
    let new_rows = ((avail.y - 12.0) / line_height).floor().max(5.0) as usize;

    if new_cols != tab.terminal.state.cols || new_rows != tab.terminal.state.rows {
        tab.terminal.resize(new_cols, new_rows);
        let _ = tab.handle.cmd_tx.send(BackendCommand::Resize {
            cols: new_cols as u16,
            rows: new_rows as u16,
        });
    }

    let (rect, response) = ui.allocate_exact_size(avail, Sense::click_and_drag());
    let painter = ui.painter_at(rect);

    let theme = &tab.terminal.state.theme;
    painter.rect_filled(rect, 0.0, theme.bg);

    let clicked_pane = response.clicked() || response.drag_started();
    if clicked_pane {
        response.request_focus();
    }

    let origin = rect.min + Vec2::new(6.0, 4.0);
    let vis_start = tab.terminal.state.visible_start_abs_row();

    // Handle scroll wheel in scrollback buffer
    if response.hovered() {
        let scroll_delta = ctx.input(|i| i.smooth_scroll_delta.y);
        if scroll_delta.abs() > 1.0 && !tab.terminal.state.using_alt_screen {
            let lines_delta = (scroll_delta / line_height).round() as isize;
            let max_sb = tab.terminal.state.scrollback.len() as isize;
            let cur = tab.terminal.state.scroll_offset as isize;
            tab.terminal.state.scroll_offset = (cur + lines_delta).clamp(0, max_sb) as usize;
        }
    }

    let pos_to_cell = |pos: Pos2| -> (usize, usize) {
        let rel_x = (pos.x - origin.x).max(0.0);
        let rel_y = (pos.y - origin.y).max(0.0);
        let c = (rel_x / char_width).floor() as usize;
        let r = (rel_y / line_height).floor() as usize;
        (vis_start + r, c)
    };

    if response.drag_started_by(egui::PointerButton::Primary) {
        if let Some(pos) = response.interact_pointer_pos() {
            let cell = pos_to_cell(pos);
            tab.terminal.state.selection_start = Some(cell);
            tab.terminal.state.selection_end = Some(cell);
        }
    } else if response.dragged_by(egui::PointerButton::Primary) {
        if let Some(pos) = response.interact_pointer_pos() {
            tab.terminal.state.selection_end = Some(pos_to_cell(pos));
        }
    } else if response.drag_stopped_by(egui::PointerButton::Primary) {
        if copy_on_select
            && let Some(selected) = tab.terminal.state.extract_selected_text()
            && let Ok(mut cb) = Clipboard::new()
        {
            let _ = cb.set_text(selected);
        }
    } else if response.clicked_by(egui::PointerButton::Primary)
        && let Some(pos) = response.interact_pointer_pos()
    {
        let (abs_r, col) = pos_to_cell(pos);
        let ctrl_held = ctx.input(|i| i.modifiers.ctrl);
        if ctrl_held && detect_hyperlinks {
            if let Some(row_cells) = tab.terminal.state.line_at_absolute(abs_r) {
                for u in tab.terminal.state.detect_urls_in_row(row_cells) {
                    if col >= u.start_col && col <= u.end_col {
                        let _ = open::that(&u.url);
                        break;
                    }
                }
            }
        } else {
            tab.terminal.state.selection_start = None;
            tab.terminal.state.selection_end = None;
        }
    }

    let mut bytes_to_send: Vec<u8> = Vec::new();
    if response.clicked_by(egui::PointerButton::Secondary)
        && right_click_paste
        && let Ok(mut cb) = Clipboard::new()
        && let Ok(text) = cb.get_text()
    {
        if tab.terminal.state.bracketed_paste {
            bytes_to_send.extend_from_slice(b"\x1b[200~");
            bytes_to_send.extend_from_slice(text.as_bytes());
            bytes_to_send.extend_from_slice(b"\x1b[201~");
        } else {
            bytes_to_send.extend_from_slice(text.as_bytes());
        }
    }

    // Render visible terminal rows with Run-Length Text Batching for 60+ FPS performance
    let rows = tab.terminal.state.rows;
    let cols = tab.terminal.state.cols;
    let search_q = tab.search_query.to_lowercase();
    let mut run_text = String::with_capacity(cols);

    for vis_r in 0..rows {
        let abs_r = vis_start + vis_r;
        let y = origin.y + vis_r as f32 * line_height;
        let Some(row_cells) = tab.terminal.state.line_at_absolute(abs_r) else {
            continue;
        };

        let urls = if detect_hyperlinks {
            tab.terminal.state.detect_urls_in_row(row_cells)
        } else {
            Vec::new()
        };

        let row_matches_search = if !search_q.is_empty() {
            row_cells
                .iter()
                .map(|c| c.ch)
                .collect::<String>()
                .to_lowercase()
                .contains(&search_q)
        } else {
            false
        };

        // Pass 1: Backgrounds, selection highlights, search highlights, and underlines
        // Pass 2 (fused): Run-length batching of contiguous foreground glyphs sharing the same Color32
        run_text.clear();
        let mut run_start_col: usize = 0;
        let mut run_fg: Option<Color32> = None;

        for (c_idx, cell) in row_cells.iter().enumerate().take(cols) {
            let x = origin.x + c_idx as f32 * char_width;
            let cell_rect = Rect::from_min_size(
                Pos2::new(x, y),
                Vec2::new(char_width + 0.5, line_height + 0.5),
            );

            let mut fg = cell.fg.to_color32(theme.fg);
            let mut bg = cell.bg.to_color32(theme.bg);
            if cell.inverse() {
                std::mem::swap(&mut fg, &mut bg);
            }

            if bg != theme.bg {
                painter.rect_filled(cell_rect, 0.0, bg);
            }
            if tab.terminal.state.is_cell_selected(abs_r, c_idx) {
                painter.rect_filled(cell_rect, 0.0, theme.selection_bg);
            }
            if row_matches_search {
                painter.rect_filled(
                    cell_rect,
                    0.0,
                    Color32::from_rgba_premultiplied(210, 153, 34, 90),
                );
            }

            let ch = if cell.ch == '\0' { ' ' } else { cell.ch };
            if ch == ' ' {
                // If we have an active non-space glyph run, we can either keep spaces in the same run
                // or flush on runs of spaces. Flushing on space avoids kerning drift across wide gaps!
                if let Some(active_fg) = run_fg.take() {
                    let run_x = origin.x + run_start_col as f32 * char_width;
                    painter.text(
                        Pos2::new(run_x, y),
                        egui::Align2::LEFT_TOP,
                        &run_text,
                        font_id.clone(),
                        active_fg,
                    );
                    run_text.clear();
                }
            } else {
                match run_fg {
                    Some(active_fg) if active_fg == fg => {
                        run_text.push(ch);
                    }
                    Some(active_fg) => {
                        let run_x = origin.x + run_start_col as f32 * char_width;
                        painter.text(
                            Pos2::new(run_x, y),
                            egui::Align2::LEFT_TOP,
                            &run_text,
                            font_id.clone(),
                            active_fg,
                        );
                        run_text.clear();
                        run_start_col = c_idx;
                        run_fg = Some(fg);
                        run_text.push(ch);
                    }
                    None => {
                        run_start_col = c_idx;
                        run_fg = Some(fg);
                        run_text.push(ch);
                    }
                }
            }

            let in_url = urls
                .iter()
                .any(|u| c_idx >= u.start_col && c_idx <= u.end_col);
            if cell.underline() || in_url {
                let line_y = y + line_height - 2.0;
                painter.line_segment(
                    [Pos2::new(x, line_y), Pos2::new(x + char_width, line_y)],
                    Stroke::new(
                        1.0,
                        if in_url {
                            Color32::from_rgb(88, 166, 255)
                        } else {
                            fg
                        },
                    ),
                );
            }
        }

        if let Some(active_fg) = run_fg.take()
            && !run_text.is_empty()
        {
            let run_x = origin.x + run_start_col as f32 * char_width;
            painter.text(
                Pos2::new(run_x, y),
                egui::Align2::LEFT_TOP,
                &run_text,
                font_id.clone(),
                active_fg,
            );
            run_text.clear();
        }
    }

    // Render cursor
    if tab.terminal.state.cursor_visible && tab.terminal.state.scroll_offset == 0 {
        let cx = origin.x + tab.terminal.state.cursor_col as f32 * char_width;
        let cy = origin.y + tab.terminal.state.cursor_row as f32 * line_height;
        let cursor_rect =
            Rect::from_min_size(Pos2::new(cx, cy), Vec2::new(char_width, line_height));
        painter.rect_filled(
            cursor_rect,
            1.0,
            Color32::from_rgba_premultiplied(
                theme.cursor.r(),
                theme.cursor.g(),
                theme.cursor.b(),
                160,
            ),
        );
    }

    if capture_keyboard && tab.pending_prompt.is_none() && !tab.show_search_bar {
        let app_cursor = tab.terminal.state.application_cursor_keys;
        let bracketed = tab.terminal.state.bracketed_paste;

        ctx.input(|input| {
            for event in &input.events {
                match event {
                    egui::Event::Paste(text) => {
                        if bracketed {
                            bytes_to_send.extend_from_slice(b"\x1b[200~");
                            bytes_to_send.extend_from_slice(text.as_bytes());
                            bytes_to_send.extend_from_slice(b"\x1b[201~");
                        } else {
                            bytes_to_send.extend_from_slice(text.as_bytes());
                        }
                    }
                    egui::Event::Text(text) => {
                        bytes_to_send.extend_from_slice(text.as_bytes());
                    }
                    egui::Event::Key {
                        key,
                        pressed: true,
                        modifiers,
                        ..
                    } => {
                        if let Some(seq) = encode_key_to_vt(*key, *modifiers, app_cursor) {
                            bytes_to_send.extend_from_slice(&seq);
                        }
                    }
                    _ => {}
                }
            }
        });
    }

    (clicked_pane, bytes_to_send)
}

pub fn protocol_badge_style(proto: ProtocolType) -> (&'static str, Color32) {
    match proto {
        ProtocolType::Ssh => ("SSH2", Color32::from_rgb(88, 166, 255)),
        ProtocolType::Telnet => ("TELNET", Color32::from_rgb(210, 153, 34)),
        ProtocolType::RawTcp => ("RAW TCP", Color32::from_rgb(163, 113, 247)),
        ProtocolType::LocalShell => ("CONPTY", Color32::from_rgb(63, 185, 80)),
    }
}

pub fn configure_visuals(ctx: &Context) {
    let mut visuals = egui::Visuals::dark();
    visuals.window_fill = Color32::from_rgb(18, 22, 29);
    visuals.panel_fill = Color32::from_rgb(13, 17, 23);
    visuals.faint_bg_color = Color32::from_rgb(22, 27, 34);
    visuals.extreme_bg_color = Color32::from_rgb(11, 14, 20);
    visuals.window_stroke = Stroke::new(1.0, Color32::from_rgb(48, 54, 61));
    visuals.widgets.noninteractive.bg_fill = Color32::from_rgb(18, 22, 29);
    visuals.widgets.noninteractive.bg_stroke = Stroke::new(1.0, Color32::from_rgb(38, 44, 54));
    visuals.widgets.inactive.bg_fill = Color32::from_rgb(22, 27, 34);
    visuals.widgets.inactive.bg_stroke = Stroke::new(1.0, Color32::from_rgb(48, 54, 61));
    visuals.widgets.hovered.bg_fill = Color32::from_rgb(33, 40, 52);
    visuals.widgets.hovered.bg_stroke = Stroke::new(1.0, Color32::from_rgb(88, 166, 255));
    visuals.widgets.active.bg_fill = Color32::from_rgb(40, 50, 66);
    visuals.widgets.active.bg_stroke = Stroke::new(1.0, Color32::from_rgb(88, 166, 255));
    visuals.selection.bg_fill = Color32::from_rgb(31, 75, 145);
    visuals.widgets.inactive.corner_radius = egui::CornerRadius::same(4);
    visuals.widgets.hovered.corner_radius = egui::CornerRadius::same(4);
    visuals.widgets.active.corner_radius = egui::CornerRadius::same(4);
    ctx.set_visuals(visuals);
}

pub fn encode_key_to_vt(key: Key, modifiers: Modifiers, app_cursor: bool) -> Option<Vec<u8>> {
    if modifiers.ctrl && !modifiers.alt {
        match key {
            Key::C => return Some(vec![0x03]),
            Key::D => return Some(vec![0x04]),
            Key::Z => return Some(vec![0x1A]),
            Key::L => return Some(vec![0x0C]),
            Key::A => return Some(vec![0x01]),
            Key::E => return Some(vec![0x05]),
            Key::U => return Some(vec![0x15]),
            Key::K => return Some(vec![0x0B]),
            Key::W => return Some(vec![0x17]),
            Key::R => return Some(vec![0x12]),
            _ => {}
        }
    }

    match key {
        Key::Enter => Some(b"\r".to_vec()),
        Key::Backspace => Some(vec![0x7F]),
        Key::Tab => Some(b"\t".to_vec()),
        Key::Escape => Some(vec![0x1B]),
        Key::ArrowUp => Some(if app_cursor {
            b"\x1bOA".to_vec()
        } else {
            b"\x1b[A".to_vec()
        }),
        Key::ArrowDown => Some(if app_cursor {
            b"\x1bOB".to_vec()
        } else {
            b"\x1b[B".to_vec()
        }),
        Key::ArrowRight => Some(if app_cursor {
            b"\x1bOC".to_vec()
        } else {
            b"\x1b[C".to_vec()
        }),
        Key::ArrowLeft => Some(if app_cursor {
            b"\x1bOD".to_vec()
        } else {
            b"\x1b[D".to_vec()
        }),
        Key::Home => Some(b"\x1b[H".to_vec()),
        Key::End => Some(b"\x1b[F".to_vec()),
        Key::PageUp => Some(b"\x1b[5~".to_vec()),
        Key::PageDown => Some(b"\x1b[6~".to_vec()),
        Key::Insert => Some(b"\x1b[2~".to_vec()),
        Key::Delete => Some(b"\x1b[3~".to_vec()),
        Key::F1 => Some(b"\x1bOP".to_vec()),
        Key::F2 => Some(b"\x1bOQ".to_vec()),
        Key::F3 => Some(b"\x1bOR".to_vec()),
        Key::F4 => Some(b"\x1bOS".to_vec()),
        Key::F5 => Some(b"\x1b[15~".to_vec()),
        Key::F6 => Some(b"\x1b[17~".to_vec()),
        Key::F7 => Some(b"\x1b[18~".to_vec()),
        Key::F8 => Some(b"\x1b[19~".to_vec()),
        Key::F9 => Some(b"\x1b[20~".to_vec()),
        Key::F10 => Some(b"\x1b[21~".to_vec()),
        Key::F11 => Some(b"\x1b[23~".to_vec()),
        Key::F12 => Some(b"\x1b[24~".to_vec()),
        _ => None,
    }
}

pub fn format_bytes(size: u64) -> String {
    if size < 1024 {
        format!("{} B", size)
    } else if size < 1024 * 1024 {
        format!("{:.1} KB", size as f64 / 1024.0)
    } else if size < 1024 * 1024 * 1024 {
        format!("{:.1} MB", size as f64 / (1024.0 * 1024.0))
    } else {
        format!("{:.2} GB", size as f64 / (1024.0 * 1024.0 * 1024.0))
    }
}
