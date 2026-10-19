use crate::config::UiLanguage;
use crate::ui::CutySshApp;
use base64::Engine as _;
use egui::{Align, Color32, Context, Layout, RichText, Stroke, TextureOptions, Vec2};

/// Fast inline bilingual string selector (French / English).
#[inline]
pub fn tr<'a>(lang: UiLanguage, fr: &'a str, en: &'a str) -> &'a str {
    if lang.is_en() { en } else { fr }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum HelpTopic {
    #[default]
    Overview,
    Bastion,
    TagsAndManager,
    KeysAndAgents,
    SecurityAndVault,
    SftpExplorer,
    SplitAndShortcuts,
    NetworkTools,
    FleetAndEdge,
}

impl HelpTopic {
    pub fn all() -> [HelpTopic; 9] {
        [
            HelpTopic::Overview,
            HelpTopic::Bastion,
            HelpTopic::TagsAndManager,
            HelpTopic::KeysAndAgents,
            HelpTopic::SecurityAndVault,
            HelpTopic::SftpExplorer,
            HelpTopic::SplitAndShortcuts,
            HelpTopic::NetworkTools,
            HelpTopic::FleetAndEdge,
        ]
    }

    pub fn label(self, lang: UiLanguage) -> &'static str {
        match self {
            HelpTopic::Overview => tr(
                lang,
                "1. 🖥 Vue d'ensemble & Cockpit",
                "1. 🖥 Overview & Cockpit",
            ),
            HelpTopic::Bastion => tr(
                lang,
                "2. 🏰 Bastion / Jump Host (-J)",
                "2. 🏰 Bastion / Jump Host (-J)",
            ),
            HelpTopic::TagsAndManager => tr(
                lang,
                "3. 🏷 Tags & Gestionnaire",
                "3. 🏷 Tags & Session Manager",
            ),
            HelpTopic::KeysAndAgents => tr(
                lang,
                "4. 🔑 Clés .ppk & Agents SSH",
                "4. 🔑 PuTTY .ppk & SSH Agents",
            ),
            HelpTopic::SecurityAndVault => tr(
                lang,
                "5. 🛡 Sécurité TOFU & DPAPI",
                "5. 🛡 TOFU & DPAPI Vault",
            ),
            HelpTopic::SftpExplorer => {
                tr(lang, "6. 📂 Explorateur SFTP", "6. 📂 SFTP File Explorer")
            }
            HelpTopic::SplitAndShortcuts => tr(
                lang,
                "7. ◫ Split View & Raccourcis",
                "7. ◫ Split View & Shortcuts",
            ),
            HelpTopic::NetworkTools => {
                tr(lang, "8. 🛠 Diagnostic & CIDR", "8. 🛠 Network Tools & CIDR")
            }
            HelpTopic::FleetAndEdge => tr(
                lang,
                "9. 🌐 Fleet, ShellHub & Audit",
                "9. 🌐 Fleet, ShellHub & Audit",
            ),
        }
    }
}

impl CutySshApp {
    pub(crate) fn ensure_cockpit_screenshot_texture(&mut self, ctx: &Context) {
        if self.cockpit_screenshot_texture.is_none() {
            let bytes = include_bytes!("../../assets/screenshot_cockpit.png");
            if let Ok(img) = image::load_from_memory(bytes) {
                let rgba = img.to_rgba8();
                let size = [rgba.width() as usize, rgba.height() as usize];
                let color_image = egui::ColorImage::from_rgba_unmultiplied(
                    size,
                    rgba.as_flat_samples().as_slice(),
                );
                self.cockpit_screenshot_texture = Some(ctx.load_texture(
                    "cuty_ssh_cockpit_screenshot",
                    color_image,
                    TextureOptions::LINEAR,
                ));
            }
        }
    }

    pub fn render_help_modal(&mut self, ctx: &Context) {
        self.ensure_cockpit_screenshot_texture(ctx);
        let lang = self.config.language;
        let mut open = self.show_help;
        let mut close_requested = false;

        let win_title = tr(
            lang,
            "📖 Guide Utilisateur & Documentation Illustrée — Cuty-SSH v0.4",
            "📖 Illustrated User Guide & Documentation — Cuty-SSH v0.4",
        );

        egui::Window::new(win_title)
            .open(&mut open)
            .resizable(true)
            .default_size(Vec2::new(1040.0, 740.0))
            .min_size(Vec2::new(760.0, 500.0))
            .show(ctx, |ui| {
                // Top header bar with language switcher and HTML export
                egui::Frame::NONE
                    .fill(Color32::from_rgb(16, 24, 36))
                    .corner_radius(6.0)
                    .inner_margin(egui::Margin::symmetric(12, 8))
                    .stroke(Stroke::new(1.0, Color32::from_rgb(45, 90, 145)))
                    .show(ui, |ui| {
                        ui.horizontal(|ui| {
                            ui.label(
                                RichText::new(tr(
                                    lang,
                                    "📚 Manuel interactif intégré avec captures d'écran et repères visuels",
                                    "📚 Built-in interactive manual with screenshots and visual callouts",
                                ))
                                .strong()
                                .color(Color32::from_rgb(165, 214, 255)),
                            );

                            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                                if ui
                                    .button(
                                        RichText::new(tr(
                                            lang,
                                            "🌐 Ouvrir dans le navigateur (HTML)",
                                            "🌐 Open in Browser (HTML)",
                                        ))
                                        .color(Color32::from_rgb(88, 166, 255)),
                                    )
                                    .on_hover_text(tr(
                                        lang,
                                        "Générer et ouvrir le guide complet autonome en HTML dans votre navigateur web",
                                        "Generate and open the standalone full HTML guide in your web browser",
                                    ))
                                    .clicked()
                                    && let Ok(path) = self.export_html_user_guide()
                                {
                                    let _ = open::that(&path);
                                }

                                ui.separator();

                                if ui
                                    .selectable_label(lang == UiLanguage::English, "🇬🇧 English")
                                    .clicked()
                                {
                                    self.config.language = UiLanguage::English;
                                    let _ = self.config.save();
                                }
                                if ui
                                    .selectable_label(lang == UiLanguage::French, "🇫🇷 Français")
                                    .clicked()
                                {
                                    self.config.language = UiLanguage::French;
                                    let _ = self.config.save();
                                }
                            });
                        });
                    });

                ui.add_space(6.0);

                // Topic selector tabs
                ui.horizontal_wrapped(|ui| {
                    for topic in HelpTopic::all() {
                        let active = self.help_topic == topic;
                        if ui
                            .selectable_label(
                                active,
                                RichText::new(topic.label(lang)).strong().color(if active {
                                    Color32::from_rgb(88, 166, 255)
                                } else {
                                    Color32::from_rgb(201, 209, 217)
                                }),
                            )
                            .clicked()
                        {
                            self.help_topic = topic;
                        }
                    }
                });

                ui.separator();

                egui::ScrollArea::vertical()
                    .id_salt("help_modal_scroll")
                    .auto_shrink([false, false])
                    .show(ui, |ui| {
                        match self.help_topic {
                            HelpTopic::Overview => self.render_help_overview(ui, lang),
                            HelpTopic::Bastion => self.render_help_bastion(ui, lang),
                            HelpTopic::TagsAndManager => self.render_help_tags(ui, lang),
                            HelpTopic::KeysAndAgents => self.render_help_keys(ui, lang),
                            HelpTopic::SecurityAndVault => self.render_help_security(ui, lang),
                            HelpTopic::SftpExplorer => self.render_help_sftp(ui, lang),
                            HelpTopic::SplitAndShortcuts => self.render_help_split(ui, lang),
                            HelpTopic::NetworkTools => self.render_help_network(ui, lang),
                            HelpTopic::FleetAndEdge => self.render_help_fleet_and_edge(ui, lang),
                        }
                    });

                ui.separator();
                ui.horizontal(|ui| {
                    ui.label(
                        RichText::new(tr(
                            lang,
                            "Astuce : Cliquez sur 🌐 FR / EN dans la barre supérieure pour basculer toute l'application en Français ou Anglais.",
                            "Tip: Click 🌐 FR / EN in the top toolbar to switch the entire application between French and English.",
                        ))
                        .small()
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
            self.show_help = false;
        }
    }

    fn render_help_overview(&self, ui: &mut egui::Ui, lang: UiLanguage) {
        ui.heading(tr(
            lang,
            "🖥 1. Vue d'ensemble du Cockpit & Lancement de Session",
            "🖥 1. Cockpit Overview & Launching a Session",
        ));
        ui.add_space(4.0);

        if let Some(tex) = &self.cockpit_screenshot_texture {
            egui::Frame::NONE
                .fill(Color32::from_rgb(11, 14, 20))
                .corner_radius(8.0)
                .inner_margin(egui::Margin::same(6))
                .stroke(Stroke::new(1.0, Color32::from_rgb(48, 54, 61)))
                .show(ui, |ui| {
                    let avail_w = (ui.available_width() - 16.0).min(960.0);
                    let aspect = tex.size_vec2().y / tex.size_vec2().x.max(1.0);
                    ui.image((tex.id(), Vec2::new(avail_w, avail_w * aspect)));
                });
            ui.add_space(6.0);
        }

        Self::help_card(
            ui,
            tr(
                lang,
                "Repères de l'interface (sur la capture ci-dessus)",
                "Interface Callouts (shown in the screenshot above)",
            ),
            &[
                tr(
                    lang,
                    "① Barre d'outils supérieure : Accès direct à 🗂 Sessions, ➕ Session, ⚡ Shell PowerShell, 🔍 Palette (Ctrl+K), 📁 Gestionnaire, 🔑 Clés .ppk, 🛡 Hosts (TOFU), 🛠 Diagnostic, 📜 Audit, ▶ Replay, 📥 Sync (PuTTY + ~/.ssh/config), 📥 KiTTY (import dossier portable), ⚡ Snippets, 📖 Aide et 🌐 Langue (FR/EN).",
                    "① Top Toolbar: Direct access to 🗂 Sessions, ➕ Session, ⚡ Local Shell, 🔍 Palette (Ctrl+K), 📁 Session Manager, 🔑 .ppk Keys, 🛡 Hosts (TOFU), 🛠 Diagnostics, 📜 Audit, ▶ Replay, 📥 Sync (PuTTY + ~/.ssh/config), 📥 KiTTY (portable folder import), ⚡ Snippets, 📖 Help, and 🌐 Language (FR/EN).",
                ),
                tr(
                    lang,
                    "② Barre latérale gauche : Arborescence par dossiers, filtre instantané, pastilles d'état santé (🟢/🔴/⏳), Connexion Rapide à la volée, et bouton large « 🚀 Connecter » sous chaque session.",
                    "② Left Sidebar: Folder tree, instant filter box, live health dots (🟢/🔴/⏳), ad-hoc Quick Connect, and a full-width '🚀 Connect' button under each session.",
                ),
                tr(
                    lang,
                    "③ Cockpit central & Cartes de sessions : Chaque carte affiche le protocole (SSH2, TELNET, CONPTY), la pastille d'état réseau, la clé .ppk associée, les badges #tag, le badge 🏰 Bastion, et les boutons 🚀 Connecter / 🔑 → Pageant / ⚙ Modifier.",
                    "③ Central Cockpit & Session Cards: Each card displays the protocol badge (SSH2, TELNET, CONPTY), live health status dot, attached .ppk key, #tag pills, 🏰 Bastion badge, and 🚀 Connect / 🔑 → Pageant / ⚙ Edit buttons.",
                ),
            ],
        );
    }

    fn render_help_bastion(&self, ui: &mut egui::Ui, lang: UiLanguage) {
        ui.heading(tr(
            lang,
            "🏰 2. Configurer et utiliser un Bastion / Jump Host SSH (-J / ProxyJump)",
            "🏰 2. Configuring and Using an SSH Bastion / Jump Host (-J / ProxyJump)",
        ));
        ui.add_space(6.0);

        Self::help_card(
            ui,
            tr(
                lang,
                "Méthode A — Depuis l'éditeur de session (➕ Session ou icône ⚙)",
                "Method A — From the Session Editor (➕ Session or ⚙ icon)",
            ),
            &[
                tr(
                    lang,
                    "1. Cliquez sur « ➕ Session » dans la barre supérieure, ou sur l'icône « ⚙ » d'une session existante.",
                    "1. Click '➕ Session' in the top toolbar, or click the '⚙' icon on any existing session.",
                ),
                tr(
                    lang,
                    "2. Dans le premier onglet « 1. Connexion & Clé (.ppk) » (protocole SSH2), descendez jusqu'à l'encadré « 🏰 Bastion / Jump Host SSH (-J / ProxyJump) ».",
                    "2. In the first tab '1. Connection & Key (.ppk)' (with SSH2 selected), scroll to the section '🏰 Bastion / Jump Host SSH (-J / ProxyJump)'.",
                ),
                tr(
                    lang,
                    "3. Option 1 — Menu déroulant « Session Bastion » : Choisissez l'une de vos sessions SSH déjà enregistrées. Cuty-SSH s'authentifiera d'abord sur ce bastion (avec sa clé .ppk ou Pageant), puis ouvrira un canal TCP direct (direct-tcpip) vers votre serveur cible.",
                    "3. Option 1 — 'Bastion Session' dropdown: Pick any saved SSH session as your jump host. Cuty-SSH will authenticate to that bastion first (using its .ppk key or Pageant) and tunnel to the target server via direct-tcpip.",
                ),
                tr(
                    lang,
                    "4. Option 2 — Champ « ProxyJump inline » : Saisissez directement « user@bastion.domaine:22 » sans créer de fiche séparée (authentification via Pageant / OpenSSH Agent).",
                    "4. Option 2 — 'Inline ProxyJump' field: Type 'user@bastion.domain:22' directly without creating a separate session profile (authenticates via Pageant / OpenSSH Agent).",
                ),
                tr(
                    lang,
                    "5. Une fois configuré, un badge violet « 🏰 Bastion » apparaît automatiquement sur la carte de la session dans le Cockpit !",
                    "5. Once configured, a purple '🏰 Bastion' badge automatically appears on the session card in the Cockpit!",
                ),
            ],
        );

        ui.add_space(8.0);
        Self::help_card(
            ui,
            tr(
                lang,
                "Méthode B — Import automatique depuis ~/.ssh/config (📥 Sync)",
                "Method B — Automatic Import from ~/.ssh/config (📥 Sync)",
            ),
            &[
                tr(
                    lang,
                    "• Si votre fichier C:\\Users\\<vous>\\.ssh\\config contient une directive « ProxyJump bastion », cliquez simplement sur « 📥 Sync » dans la barre supérieure.",
                    "• If your C:\\Users\\<you>\\.ssh\\config file contains a 'ProxyJump bastion' directive, simply click '📥 Sync' in the top toolbar.",
                ),
                tr(
                    lang,
                    "• Cuty-SSH importe automatiquement l'hôte et pré-remplit son champ ProxyJump ainsi que le tag #jump.",
                    "• Cuty-SSH automatically imports the host and populates its ProxyJump field along with the #jump tag.",
                ),
            ],
        );
    }

    fn render_help_tags(&self, ui: &mut egui::Ui, lang: UiLanguage) {
        ui.heading(tr(
            lang,
            "🏷 3. Tags de Sessions (#prod, #dmz...) & Gestionnaire en lot",
            "🏷 3. Session Tags (#prod, #dmz...) & Bulk Session Manager",
        ));
        ui.add_space(6.0);

        Self::help_card(
            ui,
            tr(
                lang,
                "Ajouter des tags sur une session individuelle",
                "Adding Tags to a Single Session",
            ),
            &[
                tr(
                    lang,
                    "1. Cliquez sur l'icône « ⚙ » d'une session (ou « ➕ Session »).",
                    "1. Click the '⚙' icon on a session (or '➕ Session').",
                ),
                tr(
                    lang,
                    "2. Dans le premier onglet, repérez la ligne « Tags (filtres) : » juste sous le Dossier.",
                    "2. In the first tab, locate the 'Tags (filters):' row right below Folder.",
                ),
                tr(
                    lang,
                    "3. Tapez un tag (ex: prod, docker, db) et appuyez sur Entrée, ou cliquez sur les suggestions rapides (+prod, +staging, +linux, +dmz...).",
                    "3. Type a tag (e.g., prod, docker, db) and press Enter, or click the quick suggestion pills (+prod, +staging, +linux, +dmz...).",
                ),
            ],
        );

        ui.add_space(8.0);
        Self::help_card(
            ui,
            tr(
                lang,
                "Taguer plusieurs sessions d'un coup & Filtrer par tag",
                "Bulk Tagging Multiple Sessions & Filtering by Tag",
            ),
            &[
                tr(
                    lang,
                    "• En lot : Ouvrez « 📁 Gestionnaire » dans la barre supérieure, cochez les sessions souhaitées, tapez un tag en haut et cliquez sur « 🏷 + Tag ».",
                    "• In bulk: Open '📁 Manager' in the top toolbar, check the desired sessions, type a tag in the top bar, and click '🏷 + Tag'.",
                ),
                tr(
                    lang,
                    "• Filtrer : Sur le Cockpit, utilisez le menu déroulant « 🏷 Tous les tags » ou tapez directement « #prod » dans la barre de recherche ou dans la Palette (Ctrl+K).",
                    "• Filter: On the Cockpit, use the '🏷 All tags' dropdown or type '#prod' directly into the search box or Command Palette (Ctrl+K).",
                ),
            ],
        );
    }

    fn render_help_keys(&self, ui: &mut egui::Ui, lang: UiLanguage) {
        ui.heading(tr(
            lang,
            "🔑 4. Clés PuTTY (.ppk v2/v3), Pageant & Windows OpenSSH Agent",
            "🔑 4. PuTTY Keys (.ppk v2/v3), Pageant & Windows OpenSSH Agent",
        ));
        ui.add_space(6.0);

        Self::help_card(
            ui,
            tr(
                lang,
                "Gestion native des clés .ppk et double Agent SSH",
                "Native .ppk Key Handling & Dual SSH Agent Support",
            ),
            &[
                tr(
                    lang,
                    "• Support direct .ppk v2 & v3 : Aucune conversion préalable requise (RSA, Ed25519, ECDSA, DSA, avec ou sans passphrase Argon2id / AES-256-CBC).",
                    "• Direct .ppk v2 & v3 support: No prior conversion needed (RSA, Ed25519, ECDSA, DSA, plaintext or Argon2id / AES-256-CBC passphrase-encrypted).",
                ),
                tr(
                    lang,
                    "• Pageant + Windows OpenSSH Agent : Cuty-SSH interroge automatiquement Pageant (mémoire partagée Windows) ET le service natif Windows OpenSSH Agent (\\\\.\\pipe\\openssh-ssh-agent).",
                    "• Pageant + Windows OpenSSH Agent: Cuty-SSH automatically queries both Pageant (Windows shared memory) AND the native Windows OpenSSH Agent service (\\\\.\\pipe\\openssh-ssh-agent).",
                ),
                tr(
                    lang,
                    "• Outil PuTTYgen intégré (bouton « 🔑 Clés ») : Inspectez l'empreinte SHA-256 d'une clé, copiez la ligne authorized_keys, convertissez .ppk ↔ OpenSSH, ou générez une nouvelle clé .ppk v3.",
                    "• Built-in PuTTYgen tool ('🔑 Keys' button): Inspect SHA-256 fingerprints, copy the authorized_keys line, convert .ppk ↔ OpenSSH, or generate a new .ppk v3 key.",
                ),
            ],
        );

        ui.add_space(8.0);
        Self::help_card(
            ui,
            tr(
                lang,
                "⭐ Clé Principale & Migration 1-Clic Mot de passe ➡ Clé SSH (ssh-copy-id)",
                "⭐ Primary Key & 1-Click Password ➡ SSH Key Migration (ssh-copy-id)",
            ),
            &[
                tr(
                    lang,
                    "1. Première connexion par mot de passe : Dans l'Éditeur de Session (mode Mot de passe), cochez « 🔑➡🖥 Copier ma Clé Principale à la 1re connexion (ssh-copy-id) » ou cliquez sur le bouton vert « 🔑➡🖥 Connecter (Mdp) & Copier ma Clé Principale ».",
                    "1. First connection with password: In the Session Editor (Password mode), check '🔑➡🖥 Copy my Primary Key on 1st login (ssh-copy-id)' or click the green '🔑➡🖥 Connect (Pwd) & Copy Primary Key' button.",
                ),
                tr(
                    lang,
                    "2. Ou depuis un terminal SSH déjà connecté : Cliquez à tout moment sur « 🔑➡🖥 Copier ma Clé (ssh-copy-id) » dans la barre d'outils en haut à droite du terminal.",
                    "2. Or from an already connected SSH terminal: Click '🔑➡🖥 Copy My Key (ssh-copy-id)' at any time in the top-right terminal toolbar.",
                ),
                tr(
                    lang,
                    "3. Basculement automatique sans mot de passe : Cuty-SSH génère votre Clé Principale Ed25519 si vous n'en avez pas encore, l'installe dans ~/.ssh/authorized_keys (chmod 700/600), bascule automatiquement le profil de session sur votre Clé Principale et efface le mot de passe stocké !",
                    "3. Automatic passwordless switchover: Cuty-SSH auto-generates your Ed25519 Primary Key if needed, installs it into ~/.ssh/authorized_keys (chmod 700/600), automatically switches the session profile to Private Key auth, and wipes the stored password!",
                ),
            ],
        );
    }

    fn render_help_security(&self, ui: &mut egui::Ui, lang: UiLanguage) {
        ui.heading(tr(
            lang,
            "🛡 5. Sécurité : Known Hosts (TOFU) & Coffre-fort Windows DPAPI",
            "🛡 5. Security: Known Hosts (TOFU) & Windows DPAPI Vault",
        ));
        ui.add_space(6.0);

        Self::help_card(
            ui,
            tr(
                lang,
                "Protection anti-MITM (TOFU) & Chiffrement matériel DPAPI",
                "Anti-MITM Protection (TOFU) & Hardware-Backed DPAPI Encryption",
            ),
            &[
                tr(
                    lang,
                    "• Vérification TOFU (Trust On First Use) : Lors de la 1re connexion à un serveur SSH, son empreinte SHA-256 est enregistrée dans cuty-ssh-portable/known_hosts.json.",
                    "• TOFU Verification (Trust On First Use): On first connection to an SSH server, its SHA-256 public key fingerprint is recorded in cuty-ssh-portable/known_hosts.json.",
                ),
                tr(
                    lang,
                    "• Alerte en cas de changement de clé : Si la clé publique d'un serveur change (attaque Man-in-the-Middle ou réinstallation du serveur), la connexion est bloquée. Ouvrez « 🛡 Hosts » dans la barre supérieure pour vérifier ou révoquer l'ancienne clé.",
                    "• Key Mismatch Alert: If a server's public key changes (MITM attack or server reinstall), the connection is blocked. Open '🛡 Hosts' in the top toolbar to inspect or revoke the old key.",
                ),
                tr(
                    lang,
                    "• Coffre-fort DPAPI : Les mots de passe et passphrases enregistrés sont automatiquement chiffrés via l'API cryptographique Windows DPAPI (CryptProtectData, préfixe dpapi:<base64>) liée à votre session Windows.",
                    "• DPAPI Vault: Saved passwords and passphrases are automatically encrypted at rest via Windows DPAPI (CryptProtectData, 'dpapi:<base64>' prefix) bound to your Windows user account.",
                ),
            ],
        );
    }

    fn render_help_sftp(&self, ui: &mut egui::Ui, lang: UiLanguage) {
        ui.heading(tr(
            lang,
            "📂 6. Explorateur SFTP : Drag & Drop, Streaming & WinSCP",
            "📂 6. SFTP Explorer: Drag & Drop, Streaming & WinSCP",
        ));
        ui.add_space(6.0);

        Self::help_card(
            ui,
            tr(
                lang,
                "Transférer des fichiers sur une session SSH active",
                "Transferring Files on an Active SSH Session",
            ),
            &[
                tr(
                    lang,
                    "1. Une fois connecté en SSH, cliquez sur le bouton « 📂 SFTP » en haut à droite de la barre d'onglets du terminal.",
                    "1. Once connected via SSH, click the '📂 SFTP' button on the right side of the terminal tab bar.",
                ),
                tr(
                    lang,
                    "2. Glisser-Déposer (Drag & Drop) : Faites glisser un ou plusieurs fichiers depuis l'Explorateur Windows directement vers la fenêtre Cuty-SSH pour les uploader dans le dossier distant actuel.",
                    "2. Drag & Drop: Drag one or more files from Windows Explorer directly onto the Cuty-SSH window to upload them into the current remote directory.",
                ),
                tr(
                    lang,
                    "3. Barre de progression temps réel : Les transferts utilisent un streaming asynchrone par blocs de 64 Ko avec affichage du pourcentage et du volume transféré.",
                    "3. Real-Time Progress Bar: Transfers stream asynchronously in 64 KB chunks with a live progress bar showing percentage and bytes transferred.",
                ),
                tr(
                    lang,
                    "4. Tri & WinSCP : Cliquez sur les en-têtes Nom / Taille / Date pour trier, sur « 📁⬆ Dossiers 1er » pour grouper les dossiers, ou sur « 🚀 WinSCP » pour ouvrir WinSCP externe.",
                    "4. Sorting & WinSCP: Click Name / Size / Date headers to sort, toggle '📁⬆ Folders 1st', or click '🚀 WinSCP' to launch external WinSCP.",
                ),
            ],
        );
    }

    fn render_help_split(&self, ui: &mut egui::Ui, lang: UiLanguage) {
        ui.heading(tr(
            lang,
            "◫ 7. Split View (Double Terminal), Broadcast & Raccourcis",
            "◫ 7. Split View (Dual Terminal), Broadcast & Shortcuts",
        ));
        ui.add_space(6.0);

        Self::help_card(
            ui,
            tr(
                lang,
                "Travailler sur plusieurs terminaux simultanément",
                "Working Across Multiple Terminals Simultaneously",
            ),
            &[
                tr(
                    lang,
                    "• Split View Vertical (◫ Split V) & Horizontal (⊟ Split H) : Dès que 2 onglets ou plus sont ouverts, ces deux boutons apparaissent dans la barre d'onglets. Cliquez sur l'un des deux panneaux pour lui donner le focus clavier, ou choisissez l'onglet secondaire dans la liste déroulante.",
                    "• Vertical (◫ Split V) & Horizontal (⊟ Split H) Split View: Whenever 2 or more tabs are open, these buttons appear in the tab bar. Click either pane to focus it, or choose which secondary tab to display from the pane header dropdown.",
                ),
                tr(
                    lang,
                    "• Mode Broadcast (📡 Broadcast) : Envoie vos frappes clavier simultanément à tous les terminaux connectés (idéal pour administrer un cluster).",
                    "• Broadcast Mode (📡 Broadcast): Sends your keystrokes simultaneously to all connected terminal tabs (ideal for cluster administration).",
                ),
                tr(
                    lang,
                    "• Raccourcis essentiels : Double-clic = Sélectionner mot/token/URL, Triple-clic = Sélectionner la ligne entière, Ctrl+K (Palette rapide), Glisser souris = Sélectionner (et copier automatiquement), Clic droit = Coller (style PuTTY), Ctrl+Clic sur une URL = Ouvrir dans le navigateur.",
                    "• Essential Shortcuts: Double-click = Select word/token/URL, Triple-click = Select entire line, Ctrl+K (Command Palette), Mouse drag = Select (and auto-copy), Right-click = Paste (PuTTY style), Ctrl+Click on URL = Open in browser.",
                ),
            ],
        );
    }

    fn render_help_network(&self, ui: &mut egui::Ui, lang: UiLanguage) {
        ui.heading(tr(
            lang,
            "🛠 8. Outils Diagnostic Réseau, Scanner TCP/SSH & Calculateur CIDR",
            "🛠 8. Network Diagnostic Toolkit, TCP/SSH Scanner & CIDR Calculator",
        ));
        ui.add_space(6.0);

        Self::help_card(
            ui,
            tr(
                lang,
                "Accessible via le bouton « 🛠 Diagnostic » de la barre supérieure",
                "Accessible via the '🛠 Diagnostic' button in the top toolbar",
            ),
            &[
                tr(
                    lang,
                    "• Scanner TCP & Bannière SSH : Mesure la latence exacte en millisecondes et récupère la bannière d'identification du serveur distant (ex: SSH-2.0-OpenSSH_9.6).",
                    "• TCP Scanner & SSH Banner Grabber: Measures exact roundtrip latency in milliseconds and fetches the remote server banner (e.g., SSH-2.0-OpenSSH_9.6).",
                ),
                tr(
                    lang,
                    "• Calculateur de sous-réseau IPv4 CIDR : Calcule instantanément le masque réseau, le wildcard, l'adresse réseau, le broadcast, la plage d'hôtes utilisables et le nombre total d'IP.",
                    "• IPv4 CIDR Subnet Calculator: Instantly computes netmask, wildcard mask, network address, broadcast address, usable host range, and total assignable hosts.",
                ),
                tr(
                    lang,
                    "• Générateur de commandes CLI : Génère et copie en 1 clic les commandes équivalentes pour OpenSSH (ssh -i ... -J ...), PuTTY, SFTP et SCP.",
                    "• CLI Command Generator: Generates and copies in 1 click equivalent command lines for OpenSSH (ssh -i ... -J ...), PuTTY, SFTP, and SCP.",
                ),
            ],
        );
    }

    fn render_help_fleet_and_edge(&self, ui: &mut egui::Ui, lang: UiLanguage) {
        ui.heading(tr(
            lang,
            "🌐 9. Gestion de Parc, Passerelles Zero-Trust, REC & Audit",
            "🌐 9. Fleet Management, Zero-Trust Gateways, REC & Audit Trail",
        ));
        ui.add_space(6.0);

        Self::help_card(
            ui,
            tr(
                lang,
                "Sondes de santé du parc & Déploiement de clés en lot",
                "Fleet Health Probing & Bulk Key Deployment",
            ),
            &[
                tr(
                    lang,
                    "• Sondes de santé en arrière-plan : Cuty-SSH vérifie automatiquement la disponibilité TCP de tous vos serveurs toutes les 45 secondes. Des pastilles colorées (🟢 En ligne, 🔴 Injoignable, ⏳ Timeout) s'affichent sur le Cockpit et dans la barre latérale. Les boutons « ● En ligne » et « ● Hors ligne » du Cockpit filtrent les serveurs joignables ou injoignables.",
                    "• Background Health Probing: Cuty-SSH automatically checks TCP availability for all configured servers every 45 seconds. Color-coded status dots (🟢 Online, 🔴 Unreachable, ⏳ Timeout) are displayed on the Cockpit and sidebar. The '● Online' and '● Offline' Cockpit toggles show only reachable or only unreachable servers.",
                ),
                tr(
                    lang,
                    "• Rafraîchissement manuel : Cliquez sur « 📡 Ping » dans la barre d'outils du Cockpit pour tester immédiatement l'état de l'ensemble de votre flotte.",
                    "• Manual Refresh: Click '📡 Ping' in the Cockpit toolbar to immediately probe the status of your entire fleet.",
                ),
                tr(
                    lang,
                    "• Déploiement en lot (ssh-copy-id) : Dans « 📁 Gestionnaire », sélectionnez plusieurs sessions et cliquez sur « 🔑 Déployer Clé Principale » pour installer votre clé publique sur tout le parc et basculer automatiquement les sessions sélectionnées en authentification par clé.",
                    "• Bulk Key Deployment (ssh-copy-id): In '📁 Manager', select multiple sessions and click '🔑 Deploy Primary Key' to install your public key across your fleet and automatically switch selected sessions to key auth.",
                ),
            ],
        );

        ui.add_space(8.0);

        Self::help_card(
            ui,
            tr(
                lang,
                "Passerelles Zero-Trust / Edge (ShellHub & Tailscale)",
                "Zero-Trust & Edge Gateways (ShellHub & Tailscale)",
            ),
            &[
                tr(
                    lang,
                    "• Préréglages Edge intégrés : Dans l'éditeur de session (⚙), choisissez ShellHub ou Tailscale pour configurer instantanément l'accès aux serveurs derrière NAT ou pare-feu sans ouverture de port.",
                    "• Built-in Edge Presets: In the Session Editor (⚙), choose ShellHub or Tailscale to instantly configure access to servers behind NAT or firewalls without port forwarding.",
                ),
                tr(
                    lang,
                    "• Intégration ShellHub : Renseignez l'identifiant unique (Device UUID ou nom d'hôte enregistré) et le serveur ShellHub (Cloud ou instance auto-hébergée). Le nom d'hôte de connexion est généré automatiquement selon le protocole SSH ShellHub.",
                    "• ShellHub Integration: Enter the unique Device UUID or registered device name along with the ShellHub server (Cloud or self-hosted). The connection hostname is formatted automatically per the ShellHub SSH protocol.",
                ),
            ],
        );

        ui.add_space(8.0);

        Self::help_card(
            ui,
            tr(
                lang,
                "Enregistrement (.cast), Lecteur Replay & Journal d'Audit",
                "Session Recording (.cast), Replay Player & Audit Trail",
            ),
            &[
                tr(
                    lang,
                    "• Enregistrement de session (🔴 REC) : Cliquez sur le bouton REC dans la barre d'onglets pour démarrer l'enregistrement de la session active au format standard Asciinema v2 (.cast). Compatible avec asciinema play et les outils CLI.",
                    "• Session Recording (🔴 REC): Click the REC button in the tabs bar to record the active session in standard Asciinema v2 (.cast) format. Fully compatible with asciinema play and CLI tools.",
                ),
                tr(
                    lang,
                    "• Lecteur Replay interactif (▶ Replay) : Rejouez vos sessions avec barre de défilement temporelle, sélecteur de vitesse (0.5x, 1x, 2x, 4x) et recherche de fichier d'enregistrement.",
                    "• Interactive Replay Player (▶ Replay): Replay recorded sessions with a timeline scrubber, speed multiplier (0.5x, 1x, 2x, 4x), and recording file selector.",
                ),
                tr(
                    lang,
                    "• Journal d'Audit (📜 Audit) : Journalise localement tous les événements de connexion, déconnexion, durées de session, erreurs et déploiements de clés. Recherche en direct, filtres par type d'événement et exports en 1 clic en CSV ou JSON. Zéro secret ou mot de passe stocké.",
                    "• Audit Trail (📜 Audit): Logs all connect, disconnect, session duration, error, and key deployment events locally. Live search, event type filters, and 1-click CSV/JSON export. Zero secrets or passwords stored.",
                ),
            ],
        );
    }

    fn help_card(ui: &mut egui::Ui, title: &str, bullets: &[&str]) {
        egui::Frame::NONE
            .fill(Color32::from_rgb(18, 23, 33))
            .corner_radius(6.0)
            .inner_margin(egui::Margin::symmetric(12, 10))
            .stroke(Stroke::new(1.0, Color32::from_rgb(38, 46, 62)))
            .show(ui, |ui| {
                ui.label(
                    RichText::new(title)
                        .strong()
                        .size(14.0)
                        .color(Color32::from_rgb(88, 166, 255)),
                );
                ui.add_space(4.0);
                for b in bullets {
                    ui.label(
                        RichText::new(*b)
                            .size(12.5)
                            .color(Color32::from_rgb(209, 217, 224)),
                    );
                    ui.add_space(3.0);
                }
            });
    }

    pub fn export_html_user_guide(&self) -> Result<std::path::PathBuf, String> {
        let lang = self.config.language;
        let screenshot_b64 = base64::engine::general_purpose::STANDARD
            .encode(include_bytes!("../../assets/screenshot_cockpit.png"));

        let title = tr(
            lang,
            "Guide Utilisateur Illustré — Cuty-SSH v0.3",
            "Illustrated User Guide — Cuty-SSH v0.3",
        );
        let subtitle = tr(
            lang,
            "Client SSH2, Bastion (-J), SFTP Drag & Drop, Split View, Clés PuTTY (.ppk v2/v3), Pageant & Sécurité TOFU/DPAPI",
            "SSH2 Client, Bastion (-J), SFTP Drag & Drop, Split View, PuTTY Keys (.ppk v2/v3), Pageant & TOFU/DPAPI Security",
        );

        let html = format!(
            r#"<!DOCTYPE html>
<html lang="{lang_code}">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{title}</title>
<style>
  :root {{
    --bg: #0b0e14;
    --panel: #121721;
    --border: #262e3e;
    --accent: #58a6ff;
    --green: #3fb950;
    --purple: #a371f7;
    --text: #e6edf3;
    --muted: #8b949e;
  }}
  * {{ box-sizing: border-box; }}
  body {{
    margin: 0;
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
    background: var(--bg);
    color: var(--text);
    line-height: 1.6;
  }}
  header {{
    background: linear-gradient(180deg, #161f2e 0%, #0b0e14 100%);
    border-bottom: 1px solid var(--border);
    padding: 32px 24px;
    text-align: center;
  }}
  header h1 {{ margin: 0 0 8px 0; color: var(--accent); font-size: 28px; }}
  header p {{ margin: 0; color: var(--muted); font-size: 15px; }}
  main {{ max-width: 1120px; margin: 28px auto; padding: 0 20px 60px; }}
  .screenshot-box {{
    background: var(--panel);
    border: 1px solid var(--border);
    border-radius: 10px;
    padding: 14px;
    margin-bottom: 24px;
    text-align: center;
  }}
  .screenshot-box img {{
    max-width: 100%;
    border-radius: 6px;
    border: 1px solid #30363d;
  }}
  .grid {{
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(480px, 1fr));
    gap: 18px;
  }}
  .card {{
    background: var(--panel);
    border: 1px solid var(--border);
    border-radius: 8px;
    padding: 18px 20px;
  }}
  .card h2 {{
    margin-top: 0;
    font-size: 18px;
    color: var(--accent);
    border-bottom: 1px solid var(--border);
    padding-bottom: 8px;
  }}
  .card ul {{ padding-left: 20px; margin: 10px 0 0; }}
  .card li {{ margin-bottom: 8px; color: #d1d9e0; }}
  code {{
    background: #1c2433;
    color: #a5d6ff;
    padding: 2px 6px;
    border-radius: 4px;
    font-size: 0.9em;
  }}
</style>
</head>
<body>
<header>
  <h1>🐾 {title}</h1>
  <p>{subtitle}</p>
</header>
<main>
  <div class="screenshot-box">
    <img src="data:image/png;base64,{screenshot_b64}" alt="Cuty-SSH Cockpit Screenshot" />
  </div>
  <div class="grid">
    <div class="card">
      <h2>1. 🖥 Cockpit &amp; {c1_title}</h2>
      <ul>
        <li>{c1_b1}</li>
        <li>{c1_b2}</li>
        <li>{c1_b3}</li>
      </ul>
    </div>
    <div class="card">
      <h2>2. 🏰 Bastion / Jump Host SSH (<code>-J</code> / <code>ProxyJump</code>)</h2>
      <ul>
        <li>{c2_b1}</li>
        <li>{c2_b2}</li>
        <li>{c2_b3}</li>
      </ul>
    </div>
    <div class="card">
      <h2>3. 🏷 Tags (<code>#prod</code>, <code>#dmz</code>) &amp; {c3_title}</h2>
      <ul>
        <li>{c3_b1}</li>
        <li>{c3_b2}</li>
      </ul>
    </div>
    <div class="card">
      <h2>4. 🔑 PuTTY (<code>.ppk</code> v2/v3), Pageant &amp; OpenSSH Agent</h2>
      <ul>
        <li>{c4_b1}</li>
        <li>{c4_b2}</li>
      </ul>
    </div>
    <div class="card">
      <h2>5. 🛡 TOFU <code>known_hosts</code> &amp; Windows DPAPI Vault</h2>
      <ul>
        <li>{c5_b1}</li>
        <li>{c5_b2}</li>
      </ul>
    </div>
    <div class="card">
      <h2>6. 📂 SFTP Drag &amp; Drop + ◫ Split View</h2>
      <ul>
        <li>{c6_b1}</li>
        <li>{c6_b2}</li>
      </ul>
    </div>
    <div class="card">
      <h2>7. 🛠 {c7_title}</h2>
      <ul>
        <li>{c7_b1}</li>
        <li>{c7_b2}</li>
      </ul>
    </div>
    <div class="card">
      <h2>8. 🌐 {c8_title}</h2>
      <ul>
        <li>{c8_b1}</li>
        <li>{c8_b2}</li>
        <li>{c8_b3}</li>
      </ul>
    </div>
  </div>
</main>
</body>
</html>"#,
            lang_code = if lang.is_en() { "en" } else { "fr" },
            title = title,
            subtitle = subtitle,
            screenshot_b64 = screenshot_b64,
            c1_title = tr(lang, "Lancement Rapide", "Quick Launch"),
            c1_b1 = tr(
                lang,
                "Cliquez sur <strong>🚀 Connecter</strong> ou directement sur le titre d'une session pour lancer le terminal.",
                "Click <strong>🚀 Connect</strong> or directly on a session title to launch the terminal."
            ),
            c1_b2 = tr(
                lang,
                "Utilisez <strong>🌐 FR / EN</strong> dans la barre supérieure pour changer la langue de toute l'application à tout moment.",
                "Use <strong>🌐 FR / EN</strong> in the top toolbar to switch the entire UI language at any time."
            ),
            c1_b3 = tr(
                lang,
                "Raccourci <code>Ctrl+K</code> : ouvre la Palette rapide pour chercher une session par nom, IP ou <code>#tag</code>.",
                "Shortcut <code>Ctrl+K</code>: opens the Command Palette to search sessions by name, IP, or <code>#tag</code>."
            ),
            c2_b1 = tr(
                lang,
                "Ouvrez <strong>➕ Session</strong> ou cliquez sur l'icône <strong>⚙</strong> d'une session SSH existante.",
                "Open <strong>➕ Session</strong> or click the <strong>⚙</strong> icon on an existing SSH session."
            ),
            c2_b2 = tr(
                lang,
                "Dans l'onglet <em>1. Connexion &amp; Clé</em>, section <strong>🏰 Bastion / Jump Host SSH</strong> : choisissez une session Bastion dans la liste déroulante ou saisissez <code>user@bastion:22</code> dans <em>ProxyJump inline</em>.",
                "In tab <em>1. Connection &amp; Key</em>, under <strong>🏰 Bastion / Jump Host SSH</strong>: select a saved Bastion session from the dropdown or enter <code>user@bastion:22</code> in <em>Inline ProxyJump</em>."
            ),
            c2_b3 = tr(
                lang,
                "Le bouton <strong>📥 Sync</strong> importe aussi automatiquement les directives <code>ProxyJump</code> de votre fichier <code>~/.ssh/config</code>.",
                "The <strong>📥 Sync</strong> button also automatically imports <code>ProxyJump</code> directives from your <code>~/.ssh/config</code> file."
            ),
            c3_title = tr(lang, "Gestionnaire en lot", "Bulk Session Manager"),
            c3_b1 = tr(
                lang,
                "Ajoutez des tags dans l'éditeur de session (<code>⚙</code>) ou en lot sur plusieurs sessions via <strong>📁 Gestionnaire</strong> (<code>🏷 + Tag</code> / <code>🏷 - Tag</code>).",
                "Add tags inside the Session Editor (<code>⚙</code>) or in bulk across multiple sessions via <strong>📁 Manager</strong> (<code>🏷 + Tag</code> / <code>🏷 - Tag</code>)."
            ),
            c3_b2 = tr(
                lang,
                "Filtrez vos sessions en 1 clic avec le menu déroulant <strong>🏷 Tags</strong> sur le Cockpit.",
                "Filter your sessions in 1 click using the <strong>🏷 Tags</strong> dropdown on the Cockpit."
            ),
            c4_b1 = tr(
                lang,
                "Chargez nativement vos clés <code>.ppk</code> v2/v3 (Argon2id / AES-256-CBC) ou utilisez <strong>🔑 Clés</strong> pour inspecter, convertir (<code>.ppk ↔ OpenSSH</code>) et générer des clés.",
                "Natively load <code>.ppk</code> v2/v3 keys (Argon2id / AES-256-CBC) or open <strong>🔑 Keys</strong> to inspect, convert (<code>.ppk ↔ OpenSSH</code>), and generate keys."
            ),
            c4_b2 = tr(
                lang,
                "Authentification sans saisie via <strong>Pageant</strong> et le service <strong>Windows OpenSSH Agent</strong>.",
                "Zero-prompt authentication via both <strong>Pageant</strong> and the <strong>Windows OpenSSH Agent</strong> service."
            ),
            c5_b1 = tr(
                lang,
                "<strong>🛡 Hosts (TOFU)</strong> : vérifie l'empreinte SHA-256 du serveur SSH à chaque connexion et bloque tout changement suspect de clé publique.",
                "<strong>🛡 Hosts (TOFU)</strong>: verifies the SSH server's SHA-256 fingerprint on every connection and blocks suspicious host key changes."
            ),
            c5_b2 = tr(
                lang,
                "<strong>Windows DPAPI Vault</strong> : chiffre automatiquement vos mots de passe et passphrases sur disque (<code>CryptProtectData</code>).",
                "<strong>Windows DPAPI Vault</strong>: automatically encrypts saved passwords and passphrases on disk (<code>CryptProtectData</code>)."
            ),
            c6_b1 = tr(
                lang,
                "<strong>📂 SFTP</strong> : glissez-déposez des fichiers depuis l'Explorateur Windows directement vers le panneau SFTP avec barre de progression temps réel.",
                "<strong>📂 SFTP</strong>: drag and drop files from Windows Explorer directly onto the SFTP panel with a real-time transfer progress bar."
            ),
            c6_b2 = tr(
                lang,
                "<strong>◫ Split V / ⊟ Split H &amp; 📡 Broadcast</strong> : affichez deux terminaux en écran scindé et diffusez vos frappes simultanément sur toute la flotte.",
                "<strong>◫ Split V / ⊟ Split H &amp; 📡 Broadcast</strong>: view two terminals split-screen and broadcast keystrokes simultaneously across your fleet."
            ),
            c7_title = tr(
                lang,
                "Diagnostic Réseau &amp; CIDR",
                "Network Diagnostics &amp; CIDR"
            ),
            c7_b1 = tr(
                lang,
                "Mesure de latence TCP en millisecondes et récupération de la bannière SSH distante.",
                "Millisecond-accurate TCP roundtrip latency measurement and remote SSH banner grabber."
            ),
            c7_b2 = tr(
                lang,
                "Calculateur IPv4 CIDR (masque, broadcast, plage IP) et générateur de commandes OpenSSH / PuTTY en 1 clic.",
                "IPv4 CIDR subnet calculator (netmask, broadcast, IP range) and 1-click OpenSSH / PuTTY CLI generator."
            ),
            c8_title = tr(
                lang,
                "Fleet, ShellHub, REC &amp; Audit",
                "Fleet, ShellHub, REC &amp; Audit"
            ),
            c8_b1 = tr(
                lang,
                "Sondes de santé du parc automatiques toutes les 45s avec pastilles colorées et rafraîchissement manuel <code>📡 Ping</code>.",
                "Automatic fleet health probes every 45s with color-coded status dots and manual <code>📡 Ping</code> trigger."
            ),
            c8_b2 = tr(
                lang,
                "Préréglages Passerelles Zero-Trust (ShellHub &amp; Tailscale) et déploiement en lot de clé principale (<code>ssh-copy-id</code>).",
                "Zero-Trust Edge Gateway presets (ShellHub &amp; Tailscale) and bulk primary key deployment (<code>ssh-copy-id</code>)."
            ),
            c8_b3 = tr(
                lang,
                "Enregistrement de session <code>🔴 REC</code> (.cast), lecteur Replay interactif et journal d'audit local sans secret.",
                "Session recording <code>🔴 REC</code> (.cast), interactive Replay player, and secret-free local audit trail."
            ),
        );

        let out_dir = crate::config::AppConfig::portable_config_path()
            .parent()
            .map(std::path::Path::to_path_buf)
            .unwrap_or_else(|| std::path::PathBuf::from("cuty-ssh-portable"));
        let _ = std::fs::create_dir_all(&out_dir);
        let out_path = out_dir.join("user-guide.html");
        std::fs::write(&out_path, html).map_err(|e| format!("Erreur écriture guide HTML: {e}"))?;
        Ok(out_path)
    }
}
