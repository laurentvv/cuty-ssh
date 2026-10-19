//! TOFU (`known_hosts.json`) fingerprint manager modal and OpenSSH `~/.ssh/config` UI integration.

use crate::config::{load_known_hosts, remove_known_host};
use crate::ui::CutySshApp;
use arboard::Clipboard;
use egui::{Align, Color32, Context, Layout, RichText, Stroke, Vec2};

impl CutySshApp {
    pub fn refresh_known_hosts(&mut self) {
        self.known_hosts = load_known_hosts();
    }

    pub fn trigger_openssh_config_import(&mut self, pick_custom_file: bool) {
        let custom = if pick_custom_file {
            rfd::FileDialog::new()
                .set_title("Sélectionner un fichier ~/.ssh/config")
                .pick_file()
        } else {
            None
        };
        if pick_custom_file && custom.is_none() {
            return;
        }
        match self.config.import_from_openssh_config(custom.as_deref()) {
            Ok(n) => {
                self.probe_all_sessions();
                self.set_toast(format!(
                    "Import ~/.ssh/config terminé : {} nouvelle(s) session(s) ajoutée(s) !",
                    n
                ));
            }
            Err(_) if !pick_custom_file => {
                // If default ~/.ssh/config was not found, offer file picker
                if let Some(chosen) = rfd::FileDialog::new()
                    .set_title("Sélectionner un fichier OpenSSH config")
                    .pick_file()
                {
                    match self.config.import_from_openssh_config(Some(&chosen)) {
                        Ok(n) => {
                            self.probe_all_sessions();
                            self.set_toast(format!(
                                "Import OpenSSH config : {} nouvelle(s) session(s) !",
                                n
                            ));
                        }
                        Err(e) => self.set_toast(format!("Erreur import config SSH : {}", e)),
                    }
                } else {
                    self.set_toast("Aucun fichier ~/.ssh/config trouvé par défaut.");
                }
            }
            Err(e) => {
                self.set_toast(format!("Erreur import ~/.ssh/config : {}", e));
            }
        }
    }

    pub fn render_known_hosts_modal(&mut self, ctx: &Context) {
        let lang = self.config.language;
        let tr = |fr: &'static str, en: &'static str| crate::ui::help_modal::tr(lang, fr, en);
        let mut open = self.show_known_hosts;
        let mut host_to_revoke: Option<String> = None;
        let mut refresh_requested = false;

        egui::Window::new(tr(
            "\u{E40C} Gestionnaire Known Hosts (TOFU) & Sécurité DPAPI",
            "\u{E40C} Known Hosts Manager (TOFU) & DPAPI Security",
        ))
        .open(&mut open)
        .resizable(true)
        .default_size(Vec2::new(860.0, 520.0))
        .min_size(Vec2::new(640.0, 360.0))
        .show(ctx, |ui| {
            egui::Frame::NONE
                .fill(Color32::from_rgb(16, 26, 38))
                .corner_radius(6.0)
                .inner_margin(egui::Margin::symmetric(12, 8))
                .stroke(Stroke::new(1.0, Color32::from_rgb(45, 90, 145)))
                .show(ui, |ui| {
                    ui.horizontal_wrapped(|ui| {
                        ui.label(
                            RichText::new(tr(
                                "\u{E40C} Protection Anti-MITM (TOFU) & Coffre-fort Windows DPAPI actifs",
                                "\u{E40C} Anti-MITM Protection (TOFU) & Windows DPAPI Vault Active",
                            ))
                            .strong()
                            .color(Color32::from_rgb(88, 166, 255)),
                        );
                        ui.separator();
                        ui.label(
                            RichText::new(tr(
                                "Les empreintes SHA-256 des serveurs SSH sont vérifiées à chaque connexion. Les mots de passe et passphrases sont chiffrés via Windows DPAPI.",
                                "SSH server SHA-256 fingerprints are verified on every connection. Saved passwords and passphrases are encrypted via Windows DPAPI.",
                            ))
                            .small()
                            .color(Color32::from_rgb(180, 195, 210)),
                        );
                    });
                });

            ui.add_space(8.0);
            ui.horizontal(|ui| {
                ui.label(tr(
                    "\u{E30C} Filtrer un hôte ou une empreinte :",
                    "\u{E30C} Filter host or fingerprint:",
                ));
                ui.add(
                    egui::TextEdit::singleline(&mut self.known_hosts_filter)
                        .hint_text("192.168.1.10, ssh-ed25519, SHA256...")
                        .desired_width(260.0),
                );
                if !self.known_hosts_filter.is_empty() && ui.small_button("\u{E4F6}").clicked() {
                    self.known_hosts_filter.clear();
                }

                if ui
                    .button(tr(
                        "\u{E20C} Importer ~/.ssh/config",
                        "\u{E20C} Import ~/.ssh/config",
                    ))
                    .clicked()
                {
                    self.trigger_openssh_config_import(true);
                }

                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                    if ui.button(tr("\u{E094} Actualiser", "\u{E094} Refresh")).clicked() {
                        refresh_requested = true;
                    }
                    ui.label(
                        RichText::new(if lang.is_en() {
                            format!("{} recorded host(s)", self.known_hosts.len())
                        } else {
                            format!("{} hôte(s) enregistré(s)", self.known_hosts.len())
                        })
                        .small()
                        .color(Color32::from_rgb(139, 148, 158)),
                    );
                });
            });

            ui.add_space(6.0);
            ui.separator();

            let q = self.known_hosts_filter.trim().to_lowercase();
            let filtered: Vec<_> = self
                .known_hosts
                .iter()
                .filter(|e| {
                    q.is_empty()
                        || e.host_port.to_lowercase().contains(&q)
                        || e.algorithm.to_lowercase().contains(&q)
                        || e.fingerprint_sha256.to_lowercase().contains(&q)
                })
                .cloned()
                .collect();

            if filtered.is_empty() {
                ui.vertical_centered(|ui| {
                    ui.add_space(36.0);
                    ui.label(
                        RichText::new(tr(
                            "Aucune empreinte SSH enregistrée pour le moment (les clés seront ajoutées automatiquement lors de votre première connexion SSH).",
                            "No SSH host fingerprints recorded yet (keys will be recorded automatically upon your first SSH connection).",
                        ))
                        .color(Color32::from_rgb(139, 148, 158)),
                    );
                    ui.add_space(36.0);
                });
            } else {
                egui::ScrollArea::vertical()
                    .max_height(360.0)
                    .auto_shrink([false, false])
                    .show(ui, |ui| {
                        for (idx, entry) in filtered.iter().enumerate() {
                            let bg = if idx % 2 == 0 {
                                Color32::from_rgb(15, 20, 28)
                            } else {
                                Color32::from_rgb(20, 26, 36)
                            };
                            egui::Frame::NONE
                                .fill(bg)
                                .corner_radius(4.0)
                                .inner_margin(egui::Margin::symmetric(10, 6))
                                .stroke(Stroke::new(0.5, Color32::from_rgb(38, 46, 60)))
                                .show(ui, |ui| {
                                    ui.horizontal(|ui| {
                                        ui.vertical(|ui| {
                                            ui.horizontal(|ui| {
                                                ui.label(
                                                    RichText::new(format!("\u{E560} {}", entry.host_port))
                                                        .strong()
                                                        .monospace()
                                                        .color(Color32::from_rgb(240, 246, 252)),
                                                );
                                                egui::Frame::NONE
                                                    .fill(Color32::from_rgb(24, 48, 36))
                                                    .corner_radius(3.0)
                                                    .inner_margin(egui::Margin::symmetric(5, 1))
                                                    .show(ui, |ui| {
                                                        ui.label(
                                                            RichText::new(&entry.algorithm)
                                                                .size(10.5)
                                                                .monospace()
                                                                .color(Color32::from_rgb(63, 185, 80)),
                                                        );
                                                    });
                                            });
                                            ui.label(
                                                RichText::new(&entry.fingerprint_sha256)
                                                    .size(11.5)
                                                    .monospace()
                                                    .color(Color32::from_rgb(88, 166, 255)),
                                            );
                                            ui.label(
                                                RichText::new(if lang.is_en() {
                                                    format!(
                                                        "First seen: {} • Last verified: {}",
                                                        entry.first_seen, entry.last_seen
                                                    )
                                                } else {
                                                    format!(
                                                        "Première vue : {} • Dernière vérification : {}",
                                                        entry.first_seen, entry.last_seen
                                                    )
                                                })
                                                .size(10.0)
                                                .color(Color32::from_rgb(120, 130, 145)),
                                            );
                                        });

                                        ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                                            if ui
                                                .button(
                                                    RichText::new(tr("\u{E4A6} Révoquer", "\u{E4A6} Revoke"))
                                                        .size(11.5)
                                                        .color(Color32::from_rgb(248, 81, 73)),
                                                )
                                                .on_hover_text(tr(
                                                    "Oublier cette clé d'hôte (à utiliser si le serveur distant a été réinstallé)",
                                                    "Forget this host key (use if the remote server was reinstalled)",
                                                ))
                                                .clicked()
                                            {
                                                host_to_revoke = Some(entry.host_port.clone());
                                            }

                                            if ui
                                                .small_button(tr("\u{E196} Copier SHA256", "\u{E196} Copy SHA256"))
                                                .on_hover_text(tr(
                                                    "Copier l'empreinte SHA256 dans le presse-papiers",
                                                    "Copy SHA256 fingerprint to clipboard",
                                                ))
                                                .clicked()
                                                && let Ok(mut cb) = Clipboard::new()
                                            {
                                                let _ = cb.set_text(entry.fingerprint_sha256.clone());
                                            }
                                        });
                                    });
                                });
                            ui.add_space(3.0);
                        }
                    });
            }
        });

        self.show_known_hosts = open;
        if refresh_requested {
            self.refresh_known_hosts();
        }
        if let Some(hp) = host_to_revoke
            && remove_known_host(&hp)
        {
            self.refresh_known_hosts();
            self.set_toast(if lang.is_en() {
                format!("Revoked host key for {}", hp)
            } else {
                format!("Clé d'hôte révoquée pour {}", hp)
            });
        }
    }
}
