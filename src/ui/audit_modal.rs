//! Connection audit trail and activity log modal (`📜 Audit`).

use crate::config::{AuditLogEntry, clear_audit_log, export_audit_csv, load_audit_log};
use crate::ui::CutySshApp;
use egui::{Align, Color32, Context, Layout, RichText, Stroke};

impl CutySshApp {
    /// Refreshes the cached list of audit entries from `cuty-ssh-portable/audit_log.json`.
    pub fn refresh_audit_entries(&mut self) {
        self.audit_entries = load_audit_log();
        // Sort descending: newest events first
        self.audit_entries.reverse();
    }

    /// Renders the Local Session & Audit Log modal dialog.
    pub fn render_audit_modal(&mut self, ctx: &Context) {
        let lang = self.config.language;
        let tr = |fr: &'static str, en: &'static str| crate::ui::help_modal::tr(lang, fr, en);
        let mut open = self.show_audit_modal;

        egui::Window::new(tr(
            "📜 Journal d'Audit & Historique des Connexions",
            "📜 Connection Audit Trail & Activity Log",
        ))
        .open(&mut open)
        .resizable(true)
        .default_width(960.0)
        .default_height(600.0)
        .show(ctx, |ui| {
            // Header bar
            ui.horizontal(|ui| {
                ui.heading(
                    RichText::new(tr(
                        "📜 Journal d'Audit Local",
                        "📜 Local Audit & Activity Trail",
                    ))
                    .size(16.0)
                    .color(Color32::from_rgb(88, 166, 255)),
                );

                ui.label(
                    RichText::new(format!("({} entrées)", self.audit_entries.len()))
                        .small()
                        .color(Color32::from_rgb(139, 148, 158)),
                );

                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                    if ui
                        .button(tr("🧹 Vider le journal", "🧹 Clear Audit Trail"))
                        .on_hover_text(tr(
                            "Effacer définitivement l'historique d'audit local",
                            "Permanently clear the local audit trail",
                        ))
                        .clicked()
                    {
                        clear_audit_log();
                        self.audit_entries.clear();
                        self.set_toast(tr("Journal d'audit vidé !", "Audit trail cleared!"));
                    }

                    if ui
                        .button(tr("📤 Exporter JSON", "📤 Export JSON"))
                        .on_hover_text(tr(
                            "Exporter l'historique complet en fichier JSON",
                            "Export complete audit trail to a JSON file",
                        ))
                        .clicked()
                        && let Ok(json) = serde_json::to_string_pretty(&self.audit_entries)
                        && let Some(path) = rfd::FileDialog::new()
                            .add_filter("JSON File", &["json"])
                            .set_file_name("cuty_ssh_audit_log.json")
                            .save_file()
                        && std::fs::write(&path, json).is_ok()
                    {
                        self.set_toast(tr(
                            "Audit exporté avec succès en JSON !",
                            "Audit trail successfully exported to JSON!",
                        ));
                    }

                    if ui
                        .button(tr("📤 Exporter CSV", "📤 Export CSV"))
                        .on_hover_text(tr(
                            "Exporter l'historique sous forme de tableur CSV",
                            "Export audit trail as a standard CSV spreadsheet",
                        ))
                        .clicked()
                    {
                        let csv = export_audit_csv(&self.audit_entries);
                        if let Some(path) = rfd::FileDialog::new()
                            .add_filter("CSV File", &["csv"])
                            .set_file_name("cuty_ssh_audit_log.csv")
                            .save_file()
                            && std::fs::write(&path, csv).is_ok()
                        {
                            self.set_toast(tr(
                                "Audit exporté avec succès en CSV !",
                                "Audit trail successfully exported to CSV!",
                            ));
                        }
                    }

                    if ui.button("🔄").on_hover_text(tr("Actualiser", "Refresh")).clicked() {
                        self.refresh_audit_entries();
                    }
                });
            });

            ui.add_space(6.0);
            ui.separator();
            ui.add_space(6.0);

            // Filter bar
            ui.horizontal_wrapped(|ui| {
                ui.label("🔍");
                ui.add(
                    egui::TextEdit::singleline(&mut self.audit_query)
                        .hint_text(tr(
                            "Filtrer par session, cible hôte, protocole, détails...",
                            "Filter by session, target host, protocol, details...",
                        ))
                        .desired_width(280.0),
                );
                if !self.audit_query.is_empty() && ui.small_button("✖").clicked() {
                    self.audit_query.clear();
                }

                ui.separator();

                let mut next_ev = self.audit_filter_event.clone();
                let is_all = next_ev.is_none();
                if ui.selectable_label(is_all, tr("Tous", "All")).clicked() {
                    next_ev = None;
                }
                if ui
                    .selectable_label(next_ev.as_deref() == Some("CONNECT"), "🟢 Connect")
                    .clicked()
                {
                    next_ev = Some("CONNECT".to_string());
                }
                if ui
                    .selectable_label(next_ev.as_deref() == Some("DISCONNECT"), "⚪ Disconnect")
                    .clicked()
                {
                    next_ev = Some("DISCONNECT".to_string());
                }
                if ui
                    .selectable_label(next_ev.as_deref() == Some("ERROR"), "🔴 Error")
                    .clicked()
                {
                    next_ev = Some("ERROR".to_string());
                }
                if ui
                    .selectable_label(next_ev.as_deref() == Some("DEPLOY_KEY"), "🔑 Key Deployed")
                    .clicked()
                {
                    next_ev = Some("DEPLOY_KEY".to_string());
                }
                self.audit_filter_event = next_ev;
            });

            ui.add_space(8.0);

            // Filter entries
            let query = self.audit_query.trim().to_lowercase();
            let ev_filter = self.audit_filter_event.as_deref();

            let filtered: Vec<&AuditLogEntry> = self
                .audit_entries
                .iter()
                .filter(|e| {
                    if let Some(ev) = ev_filter
                        && !e.event_type.eq_ignore_ascii_case(ev)
                    {
                        return false;
                    }
                    if !query.is_empty() {
                        let matches_name = e.session_name.to_lowercase().contains(&query);
                        let matches_target = e.target.to_lowercase().contains(&query);
                        let matches_details = e.details.to_lowercase().contains(&query);
                        let matches_proto = e.protocol.label().to_lowercase().contains(&query);
                        if !matches_name && !matches_target && !matches_details && !matches_proto {
                            return false;
                        }
                    }
                    true
                })
                .collect();

            if filtered.is_empty() {
                ui.vertical_centered(|ui| {
                    ui.add_space(40.0);
                    ui.label(
                        RichText::new(tr(
                            "Aucun événement d'audit enregistré pour l'instant.",
                            "No audit log events recorded yet.",
                        ))
                        .color(Color32::from_rgb(139, 148, 158)),
                    );
                    ui.label(
                        RichText::new(tr(
                            "Toutes les connexions, déconnexions et erreurs de sessions seront consignées ici.",
                            "All session connects, disconnects, and errors will be logged here.",
                        ))
                        .small()
                        .color(Color32::from_rgb(110, 118, 129)),
                    );
                });
                return;
            }

            // Scrollable audit table
            egui::ScrollArea::vertical()
                .auto_shrink([false, false])
                .show(ui, |ui| {
                    egui::Grid::new("audit_grid")
                        .striped(true)
                        .spacing([12.0, 6.0])
                        .min_col_width(70.0)
                        .show(ui, |ui| {
                            // Table headers
                            ui.label(RichText::new(tr("Date / Heure", "Timestamp")).strong().color(Color32::from_rgb(201, 209, 217)));
                            ui.label(RichText::new(tr("Événement", "Event")).strong().color(Color32::from_rgb(201, 209, 217)));
                            ui.label(RichText::new(tr("Session", "Session")).strong().color(Color32::from_rgb(201, 209, 217)));
                            ui.label(RichText::new(tr("Protocole", "Protocol")).strong().color(Color32::from_rgb(201, 209, 217)));
                            ui.label(RichText::new(tr("Cible", "Target")).strong().color(Color32::from_rgb(201, 209, 217)));
                            ui.label(RichText::new(tr("Durée", "Duration")).strong().color(Color32::from_rgb(201, 209, 217)));
                            ui.label(RichText::new(tr("Détails / Statut", "Details / Status")).strong().color(Color32::from_rgb(201, 209, 217)));
                            ui.end_row();

                            for entry in filtered {
                                // Timestamp
                                ui.label(
                                    RichText::new(&entry.timestamp_rfc3339)
                                        .monospace()
                                        .small()
                                        .color(Color32::from_rgb(139, 148, 158)),
                                );

                                // Event badge
                                let (badge_text, badge_col, badge_bg) = match entry.event_type.as_str() {
                                    "CONNECT" => ("🟢 CONNECT", Color32::from_rgb(63, 185, 80), Color32::from_rgb(18, 44, 25)),
                                    "DISCONNECT" => ("⚪ DISCONNECT", Color32::from_rgb(165, 214, 255), Color32::from_rgb(22, 34, 52)),
                                    "ERROR" => ("🔴 ERROR", Color32::from_rgb(248, 81, 73), Color32::from_rgb(52, 20, 20)),
                                    "DEPLOY_KEY" => ("🔑 KEY DEPLOY", Color32::from_rgb(220, 185, 80), Color32::from_rgb(45, 38, 16)),
                                    _ => (entry.event_type.as_str(), Color32::from_rgb(201, 209, 217), Color32::from_rgb(30, 36, 46)),
                                };

                                egui::Frame::NONE
                                    .fill(badge_bg)
                                    .corner_radius(egui::CornerRadius::same(3))
                                    .inner_margin(egui::Margin::symmetric(5, 2))
                                    .stroke(Stroke::new(0.6, badge_col.gamma_multiply(0.6)))
                                    .show(ui, |ui| {
                                        ui.label(
                                            RichText::new(badge_text)
                                                .monospace()
                                                .size(10.0)
                                                .strong()
                                                .color(badge_col),
                                        );
                                    });

                                // Session name
                                ui.label(
                                    RichText::new(&entry.session_name)
                                        .strong()
                                        .color(Color32::from_rgb(240, 246, 252)),
                                );

                                // Protocol
                                ui.label(
                                    RichText::new(entry.protocol.badge())
                                        .small()
                                        .color(Color32::from_rgb(165, 214, 255)),
                                );

                                // Target
                                ui.label(
                                    RichText::new(&entry.target)
                                        .monospace()
                                        .small()
                                        .color(Color32::from_rgb(201, 209, 217)),
                                );

                                // Duration
                                let dur_str = match entry.duration_secs {
                                    Some(secs) => format_duration_readable(secs),
                                    None => "—".to_string(),
                                };
                                ui.label(
                                    RichText::new(dur_str)
                                        .monospace()
                                        .small()
                                        .color(Color32::from_rgb(139, 148, 158)),
                                );

                                // Details
                                ui.label(
                                    RichText::new(&entry.details)
                                        .small()
                                        .color(Color32::from_rgb(201, 209, 217)),
                                );

                                ui.end_row();
                            }
                        });
                });
        });

        self.show_audit_modal = open;
    }
}

fn format_duration_readable(secs: u64) -> String {
    let hours = secs / 3600;
    let mins = (secs % 3600) / 60;
    let rem_secs = secs % 60;
    if hours > 0 {
        format!("{}h {:02}m {:02}s", hours, mins, rem_secs)
    } else if mins > 0 {
        format!("{}m {:02}s", mins, rem_secs)
    } else {
        format!("{}s", rem_secs)
    }
}
