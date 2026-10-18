//! Asciinema v2 (`.cast`) session replay player modal.

use crate::terminal::TerminalEmulator;
use crate::terminal::recording::SessionPlayer;
use crate::ui::CutySshApp;
use egui::{Align, Color32, Context, Layout, RichText, Stroke, Vec2};
use std::path::{Path, PathBuf};
use std::time::Instant;

impl CutySshApp {
    /// Loads a `.cast` file into the active replay player and resets terminal state.
    pub fn load_replay_file(&mut self, path: &Path) {
        match SessionPlayer::load_file(path) {
            Ok(mut player) => {
                let cols = player.header.width.max(40);
                let rows = player.header.height.max(10);
                let mut term = TerminalEmulator::new(cols, rows, 5_000, "Cuty Dark");
                // Pre-render events up to initial position
                let initial_chunks = player.seek_to(0.0);
                for chunk in initial_chunks {
                    term.feed_str(&chunk);
                }
                self.replay_file_name = path
                    .file_name()
                    .map(|f| f.to_string_lossy().to_string())
                    .unwrap_or_else(|| "session.cast".to_string());
                self.replay_player = Some(player);
                self.replay_terminal = Some(term);
                self.replay_last_tick = Some(Instant::now());
                self.show_replay_modal = true;
            }
            Err(e) => {
                self.set_toast(format!("Erreur ouverture .cast : {}", e));
            }
        }
    }

    /// Advances replay playback by the elapsed real time.
    pub fn update_replay_playback(&mut self) {
        let now = Instant::now();
        let dt = if let Some(last) = self.replay_last_tick {
            now.duration_since(last).as_secs_f64()
        } else {
            0.0
        };
        self.replay_last_tick = Some(now);

        if let (Some(player), Some(term)) = (&mut self.replay_player, &mut self.replay_terminal)
            && player.is_playing
        {
            let chunks = player.advance(dt);
            for chunk in chunks {
                term.feed_str(&chunk);
            }
        }
    }

    /// Renders the interactive `.cast` Asciinema Replay Player modal.
    pub fn render_replay_modal(&mut self, ctx: &Context) {
        let lang = self.config.language;
        let tr = |fr: &'static str, en: &'static str| crate::ui::help_modal::tr(lang, fr, en);
        let mut open = self.show_replay_modal;

        self.update_replay_playback();
        if self
            .replay_player
            .as_ref()
            .map(|p| p.is_playing)
            .unwrap_or(false)
        {
            ctx.request_repaint();
        }

        egui::Window::new(tr(
            "▶ Lecteur Replay de Session (.cast)",
            "▶ Session Replay Player (.cast)",
        ))
        .open(&mut open)
        .resizable(true)
        .default_width(900.0)
        .default_height(580.0)
        .show(ctx, |ui| {
            // Header / Controls bar
            ui.horizontal(|ui| {
                ui.heading(
                    RichText::new("🔴 Replay Player")
                        .size(15.0)
                        .color(Color32::from_rgb(248, 81, 73)),
                );

                if !self.replay_file_name.is_empty() {
                    ui.label(
                        RichText::new(&self.replay_file_name)
                            .monospace()
                            .color(Color32::from_rgb(165, 214, 255)),
                    );
                }

                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                    if ui
                        .button(tr("📂 Ouvrir .cast", "📂 Open .cast"))
                        .on_hover_text(tr(
                            "Ouvrir un enregistrement .cast (Asciinema v2)",
                            "Open an Asciinema v2 .cast recording file",
                        ))
                        .clicked()
                    {
                        let base_dir = PathBuf::from("cuty-ssh-portable").join("recordings");
                        let _ = std::fs::create_dir_all(&base_dir);
                        if let Some(path) = rfd::FileDialog::new()
                            .set_directory(&base_dir)
                            .add_filter("Asciinema Cast", &["cast"])
                            .pick_file()
                        {
                            self.load_replay_file(&path);
                        }
                    }

                    // Quick list of available recordings in cuty-ssh-portable/recordings
                    let recordings_dir = PathBuf::from("cuty-ssh-portable").join("recordings");
                    if let Ok(entries) = std::fs::read_dir(recordings_dir) {
                        let mut cast_files: Vec<PathBuf> = entries
                            .filter_map(|e| e.ok().map(|de| de.path()))
                            .filter(|p| {
                                p.extension()
                                    .map(|ext| ext.eq_ignore_ascii_case("cast"))
                                    .unwrap_or(false)
                            })
                            .collect();
                        cast_files.sort();
                        cast_files.reverse();

                        if !cast_files.is_empty() {
                            egui::ComboBox::from_id_salt("recordings_quick_pick")
                                .selected_text(tr("📼 Récents", "📼 Recent"))
                                .show_ui(ui, |ui| {
                                    for p in cast_files.iter().take(10) {
                                        let name = p
                                            .file_name()
                                            .unwrap_or_default()
                                            .to_string_lossy()
                                            .to_string();
                                        if ui.selectable_label(false, &name).clicked() {
                                            self.load_replay_file(p);
                                        }
                                    }
                                });
                        }
                    }
                });
            });

            ui.add_space(6.0);
            ui.separator();
            ui.add_space(6.0);

            let (has_player, is_playing, current_time, total_duration, speed) =
                if let Some(p) = &self.replay_player {
                    (
                        true,
                        p.is_playing,
                        p.current_time,
                        p.total_duration,
                        p.speed,
                    )
                } else {
                    (false, false, 0.0, 0.0, 1.0)
                };

            if !has_player {
                ui.vertical_centered(|ui| {
                    ui.add_space(50.0);
                    ui.label(
                        RichText::new(tr(
                            "Aucun enregistrement .cast n'est actuellement chargé.",
                            "No .cast recording is currently loaded.",
                        ))
                        .color(Color32::from_rgb(139, 148, 158)),
                    );
                    ui.add_space(10.0);
                    if ui
                        .button(
                            RichText::new(tr("📂 Ouvrir un fichier .cast", "📂 Open a .cast file"))
                                .strong()
                                .color(Color32::from_rgb(88, 166, 255)),
                        )
                        .clicked()
                    {
                        let base_dir = PathBuf::from("cuty-ssh-portable").join("recordings");
                        let _ = std::fs::create_dir_all(&base_dir);
                        if let Some(path) = rfd::FileDialog::new()
                            .set_directory(&base_dir)
                            .add_filter("Asciinema Cast", &["cast"])
                            .pick_file()
                        {
                            self.load_replay_file(&path);
                        }
                    }
                });
                return;
            }

            // Timeline & Transport Controls
            ui.horizontal(|ui| {
                // Play / Pause
                let play_btn_text = if is_playing { "⏸ Pause" } else { "▶ Play" };
                if ui
                    .button(
                        RichText::new(play_btn_text)
                            .strong()
                            .color(Color32::from_rgb(63, 185, 80)),
                    )
                    .clicked()
                    && let Some(p) = &mut self.replay_player
                {
                    p.is_playing = !p.is_playing;
                    self.replay_last_tick = Some(Instant::now());
                }

                // Restart
                if ui
                    .button("⏮")
                    .on_hover_text(tr("Recommencer", "Restart"))
                    .clicked()
                    && let (Some(p), Some(term)) =
                        (&mut self.replay_player, &mut self.replay_terminal)
                {
                    p.restart();
                    let cols = p.header.width.max(40);
                    let rows = p.header.height.max(10);
                    *term = TerminalEmulator::new(cols, rows, 5_000, "Cuty Dark");
                    self.replay_last_tick = Some(Instant::now());
                }

                // Time Counter: 00:15 / 02:30
                let cur_str = format_seconds(current_time);
                let tot_str = format_seconds(total_duration);
                ui.label(
                    RichText::new(format!("{} / {}", cur_str, tot_str))
                        .monospace()
                        .color(Color32::from_rgb(201, 209, 217)),
                );

                // Scrubbing Slider
                let mut seek_val = current_time;
                let slider = egui::Slider::new(&mut seek_val, 0.0..=total_duration)
                    .show_value(false)
                    .smart_aim(false);
                let slider_resp = ui.add_sized([ui.available_width() - 140.0, 20.0], slider);

                if slider_resp.changed()
                    && let (Some(p), Some(term)) =
                        (&mut self.replay_player, &mut self.replay_terminal)
                {
                    let cols = p.header.width.max(40);
                    let rows = p.header.height.max(10);
                    *term = TerminalEmulator::new(cols, rows, 5_000, "Cuty Dark");
                    let chunks = p.seek_to(seek_val);
                    for c in chunks {
                        term.feed_str(&c);
                    }
                }

                // Speed buttons
                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                    for s in [4.0f32, 2.0, 1.0, 0.5] {
                        let label = format!("{}x", s);
                        let is_sel = (speed - s).abs() < 0.01;
                        if ui.selectable_label(is_sel, label).clicked()
                            && let Some(p) = &mut self.replay_player
                        {
                            p.speed = s;
                        }
                    }
                });
            });

            ui.add_space(6.0);
            ui.separator();
            ui.add_space(4.0);

            // Replay terminal display
            if let Some(term) = &self.replay_terminal {
                let theme = crate::terminal::TerminalTheme::by_name("Cuty Dark");
                let font_size = 13.5f32;
                let font_id = egui::FontId::new(font_size, egui::FontFamily::Monospace);
                let char_width = (font_size * 0.6).max(6.0);
                let line_height = (font_size * 1.25).max(12.0);

                egui::Frame::NONE
                    .fill(Color32::from_rgb(13, 17, 23))
                    .corner_radius(egui::CornerRadius::same(4))
                    .inner_margin(egui::Margin::symmetric(8, 8))
                    .stroke(Stroke::new(1.0, Color32::from_rgb(48, 54, 61)))
                    .show(ui, |ui| {
                        let avail = ui.available_size();
                        let term_size = Vec2::new(
                            (term.state.cols as f32 * char_width).max(avail.x),
                            (term.state.rows as f32 * line_height).max(avail.y),
                        );

                        egui::ScrollArea::both()
                            .auto_shrink([false, false])
                            .show(ui, |ui| {
                                let (rect, _) =
                                    ui.allocate_exact_size(term_size, egui::Sense::hover());
                                let painter = ui.painter_at(rect);

                                for (r, line) in term.state.grid.iter().enumerate() {
                                    let y = rect.min.y + (r as f32) * line_height;
                                    for (c, cell) in line.iter().enumerate() {
                                        let x = rect.min.x + (c as f32) * char_width;
                                        let char_str = cell.ch.to_string();
                                        if !char_str.trim().is_empty() {
                                            painter.text(
                                                egui::pos2(x, y),
                                                egui::Align2::LEFT_TOP,
                                                &char_str,
                                                font_id.clone(),
                                                theme.fg,
                                            );
                                        }
                                    }
                                }
                            });
                    });
            }
        });

        self.show_replay_modal = open;
    }
}

fn format_seconds(secs: f64) -> String {
    let total_s = secs.max(0.0) as u64;
    let m = total_s / 60;
    let s = total_s % 60;
    format!("{:02}:{:02}", m, s)
}
