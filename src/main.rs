// Release builds are GUI-subsystem binaries (no console window); debug keeps the console for logs.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

pub mod config;
pub mod protocols;
pub mod ssh;
pub mod terminal;
pub mod ui;

use ui::CutySshApp;

/// Re-attach stdout/stderr to the console of the parent process (needed with the GUI subsystem).
#[cfg(windows)]
fn attach_parent_console() {
    use std::os::windows::io::IntoRawHandle;
    use windows_sys::Win32::System::Console::{
        ATTACH_PARENT_PROCESS, AttachConsole, GetStdHandle, STD_ERROR_HANDLE, STD_OUTPUT_HANDLE,
        SetStdHandle,
    };
    unsafe {
        if AttachConsole(ATTACH_PARENT_PROCESS) == 0 {
            return;
        }
        for (std_handle, name) in [
            (STD_OUTPUT_HANDLE, "CONOUT$"),
            (STD_ERROR_HANDLE, "CONOUT$"),
        ] {
            let cur = GetStdHandle(std_handle);
            if (cur.is_null() || cur as isize == -1)
                && let Ok(f) = std::fs::OpenOptions::new().write(true).open(name)
            {
                SetStdHandle(std_handle, f.into_raw_handle() as _);
            }
        }
    }
}

fn main() -> eframe::Result {
    let args: Vec<String> = std::env::args().collect();
    if args.iter().any(|a| a == "-V" || a == "--version") {
        #[cfg(windows)]
        attach_parent_console();
        println!("cuty-ssh {}", env!("CARGO_PKG_VERSION"));
        return Ok(());
    }
    if args.iter().any(|a| a == "-h" || a == "--help") {
        #[cfg(windows)]
        attach_parent_console();
        println!(
            "Cuty-SSH {} — Fast, native Windows SSH2, SFTP, Telnet, Raw TCP & ConPTY connection manager\n",
            env!("CARGO_PKG_VERSION")
        );
        println!("Usage: cuty-ssh.exe [OPTIONS]\n");
        println!("Options:");
        println!("  -V, --version   Print version information");
        println!("  -h, --help      Print help information");
        return Ok(());
    }

    let _ = tracing_subscriber::fmt::try_init();

    let Ok(rt) = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    else {
        return Ok(());
    };

    let handle = rt.handle().clone();

    #[cfg(windows)]
    if std::env::var("WGPU_BACKEND").is_err() {
        unsafe {
            std::env::set_var("WGPU_BACKEND", "dx12");
        }
    }

    let mut wgpu_options = eframe::egui_wgpu::WgpuConfiguration::default();
    #[cfg(windows)]
    {
        let mut create_new = eframe::egui_wgpu::WgpuSetupCreateNew::without_display_handle();
        create_new.instance_descriptor.backends = eframe::egui_wgpu::wgpu::Backends::DX12;
        wgpu_options.wgpu_setup = eframe::egui_wgpu::WgpuSetup::CreateNew(create_new);
    }

    let mut viewport = egui::ViewportBuilder::default()
        .with_title("Cuty-SSH — SSH2 / Telnet / SFTP & PuTTY (.ppk / Pageant) Client")
        .with_inner_size([1320.0, 820.0])
        .with_min_inner_size([600.0, 42.0]);

    if let Some(icon) = load_app_icon() {
        viewport = viewport.with_icon(icon);
    }

    let native_options = eframe::NativeOptions {
        wgpu_options,
        viewport,
        ..Default::default()
    };

    tracing::info!("Starting Cuty-SSH native window with DX12 backend...");
    if let Err(e) = eframe::run_native(
        "Cuty-SSH",
        native_options,
        Box::new(move |cc| {
            egui_extras::install_image_loaders(&cc.egui_ctx);
            tracing::info!("Initializing CutySshApp inside eframe closure...");
            Ok(Box::new(CutySshApp::new(cc, handle)))
        }),
    ) {
        eprintln!("eframe error: {e}");
        let _ = std::fs::write("cuty-ssh-crash.log", format!("eframe error: {e}"));
    }
    Ok(())
}

fn load_app_icon() -> Option<egui::IconData> {
    let png_bytes = include_bytes!("../assets/cuty_ssh_icon.png");
    let img = image::load_from_memory(png_bytes).ok()?;
    let rgba = img.into_rgba8();
    let (width, height) = rgba.dimensions();
    Some(egui::IconData {
        rgba: rgba.into_raw(),
        width,
        height,
    })
}

#[cfg(test)]
mod tests {
    use crate::config::{AppConfig, url_decode_session_name, url_encode_session_name};
    use crate::ssh::ppk::{
        decode_private_key_any, export_to_openssh_pem, export_to_ppk_v3, generate_new_ssh_key,
        inspect_key_content,
    };
    use crate::terminal::TerminalEmulator;

    #[test]
    fn test_ppk_v3_roundtrip_and_inspection() {
        let key = generate_new_ssh_key("ed25519", "test@cuty-ssh").unwrap();
        let ppk_str = export_to_ppk_v3(&key, "test@cuty-ssh").unwrap();
        assert!(ppk_str.starts_with("PuTTY-User-Key-File-3: ssh-ed25519"));

        let info = inspect_key_content(&ppk_str, "memory.ppk").unwrap();
        assert_eq!(info.algorithm, "ssh-ed25519");
        assert!(!info.is_encrypted);
        assert_eq!(info.comment, "test@cuty-ssh");
        assert!(info.fingerprint_sha256.starts_with("SHA256:"));

        let decoded = decode_private_key_any(&ppk_str, None).unwrap();
        assert_eq!(decoded.public_key(), key.public_key());

        let openssh_pem = export_to_openssh_pem(&decoded).unwrap();
        assert!(openssh_pem.contains("BEGIN OPENSSH PRIVATE KEY"));
    }

    #[test]
    fn test_url_session_encoding() {
        let original = "Prod Server #1 (SSH)";
        let encoded = url_encode_session_name(original);
        let decoded = url_decode_session_name(&encoded);
        assert_eq!(original, decoded);
    }

    #[test]
    fn test_terminal_vt100_and_url_detection() {
        let mut term = TerminalEmulator::new(80, 24, 1000, "Cuty Dark");
        term.feed_str("\x1b[1;32mBienvenue sur https://github.com/example/cuty-ssh !\x1b[0m\r\n");
        let urls = term.state.detect_urls_in_row(&term.state.grid[0]);
        assert_eq!(urls.len(), 1);
        assert_eq!(urls[0].url, "https://github.com/example/cuty-ssh");
    }

    #[test]
    fn test_app_config_default_pageant_and_json_roundtrip() {
        let cfg = AppConfig::default();
        assert_eq!(cfg.pageant_path, r"C:\Program Files\PuTTY\pageant.exe");
        assert!(!cfg.sessions.is_empty());
        assert!(!cfg.predefined_commands.is_empty());

        let json = serde_json::to_string_pretty(&cfg).unwrap();
        let parsed: AppConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.pageant_path, cfg.pageant_path);
        assert_eq!(parsed.sessions.len(), cfg.sessions.len());
    }

    #[test]
    fn test_terminal_alt_screen_and_erase() {
        let mut term = TerminalEmulator::new(40, 10, 500, "Dracula");
        term.feed_str("MainScreen");
        term.feed_str("\x1b[?1049hAltScreen");
        assert!(term.state.using_alt_screen);
        term.feed_str("\x1b[2J\x1b[H");
        assert_eq!(term.state.cursor_row, 0);
        assert_eq!(term.state.cursor_col, 0);
        term.feed_str("\x1b[?1049l");
        assert!(!term.state.using_alt_screen);
        let dump = term.state.dump_all_text();
        assert!(dump.contains("MainScreen"));
    }

    #[test]
    fn test_split_user_and_host_from_putty_saved_session() {
        use crate::config::split_user_and_host;
        let (user, host) = split_user_and_host("root@192.168.1.102", "");
        assert_eq!(user, "root");
        assert_eq!(host, "192.168.1.102");

        let (user2, host2) = split_user_and_host("root@192.168.1.102", "custom");
        assert_eq!(user2, "custom");
        assert_eq!(host2, "192.168.1.102");

        let (user3, host3) = split_user_and_host("192.168.1.5", "admin");
        assert_eq!(user3, "admin");
        assert_eq!(host3, "192.168.1.5");

        let cfg = AppConfig::load_or_default();
        for s in &cfg.sessions {
            assert!(
                !s.host.contains('@'),
                "Session '{}' still has '@' in host: {}",
                s.name,
                s.host
            );
            assert_ne!(s.folder, "Import PuTTY/Import PuTTY");
        }
    }

    #[test]
    fn test_ipv4_cidr_calculation() {
        use crate::protocols::calculate_ipv4_cidr;
        let c = calculate_ipv4_cidr("192.168.1.50/24").unwrap();
        assert_eq!(c.input_ip, "192.168.1.50");
        assert_eq!(c.prefix, 24);
        assert_eq!(c.netmask, "255.255.255.0");
        assert_eq!(c.wildcard, "0.0.0.255");
        assert_eq!(c.network_address, "192.168.1.0");
        assert_eq!(c.broadcast_address, "192.168.1.255");
        assert_eq!(c.first_usable, "192.168.1.1");
        assert_eq!(c.last_usable, "192.168.1.254");
        assert_eq!(c.usable_hosts, 254);

        let c16 = calculate_ipv4_cidr("10.0.5.1/16").unwrap();
        assert_eq!(c16.netmask, "255.255.0.0");
        assert_eq!(c16.network_address, "10.0.0.0");
        assert_eq!(c16.broadcast_address, "10.0.255.255");
        assert_eq!(c16.usable_hosts, 65534);

        assert!(calculate_ipv4_cidr("999.1.1.1/24").is_err());
        assert!(calculate_ipv4_cidr("192.168.1.1/33").is_err());
    }

    #[test]
    fn test_sftp_column_sorting_and_folders_first() {
        use crate::protocols::SftpFileEntry;
        use crate::ui::{SftpSortColumn, SortDirection};

        let mut entries = vec![
            SftpFileEntry {
                name: "zebra.txt".to_string(),
                full_path: "/root/zebra.txt".to_string(),
                is_dir: false,
                is_symlink: false,
                size: 500,
                permissions: 0o644,
                mtime: 1700000100,
            },
            SftpFileEntry {
                name: "alpha.txt".to_string(),
                full_path: "/root/alpha.txt".to_string(),
                is_dir: false,
                is_symlink: false,
                size: 2000,
                permissions: 0o644,
                mtime: 1700000300,
            },
            SftpFileEntry {
                name: "beta_dir".to_string(),
                full_path: "/root/beta_dir".to_string(),
                is_dir: true,
                is_symlink: false,
                size: 4096,
                permissions: 0o755,
                mtime: 1700000200,
            },
            SftpFileEntry {
                name: "gamma_dir".to_string(),
                full_path: "/root/gamma_dir".to_string(),
                is_dir: true,
                is_symlink: false,
                size: 4096,
                permissions: 0o755,
                mtime: 1700000050,
            },
        ];

        fn sort_test_entries(
            entries: &mut [SftpFileEntry],
            sort_col: SftpSortColumn,
            sort_dir: SortDirection,
            folders_first: bool,
        ) {
            entries.sort_by(|a, b| {
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

        // Test 1: Name ascending with folders first
        sort_test_entries(
            &mut entries,
            SftpSortColumn::Name,
            SortDirection::Ascending,
            true,
        );
        assert_eq!(entries[0].name, "beta_dir");
        assert_eq!(entries[1].name, "gamma_dir");
        assert_eq!(entries[2].name, "alpha.txt");
        assert_eq!(entries[3].name, "zebra.txt");

        // Test 2: Name descending with folders first (folders still on top, but Z->A inside)
        sort_test_entries(
            &mut entries,
            SftpSortColumn::Name,
            SortDirection::Descending,
            true,
        );
        assert_eq!(entries[0].name, "gamma_dir");
        assert_eq!(entries[1].name, "beta_dir");
        assert_eq!(entries[2].name, "zebra.txt");
        assert_eq!(entries[3].name, "alpha.txt");

        // Test 3: Size descending with folders mixed (folders_first = false)
        sort_test_entries(
            &mut entries,
            SftpSortColumn::Size,
            SortDirection::Descending,
            false,
        );
        assert_eq!(entries[0].size, 4096);
        assert_eq!(entries[1].size, 4096);
        assert_eq!(entries[2].name, "alpha.txt");
        assert_eq!(entries[3].name, "zebra.txt");

        // Test 4: Date descending (most recent first) with folders first
        sort_test_entries(
            &mut entries,
            SftpSortColumn::Date,
            SortDirection::Descending,
            true,
        );
        assert_eq!(entries[0].name, "beta_dir");
        assert_eq!(entries[1].name, "gamma_dir");
        assert_eq!(entries[2].name, "alpha.txt");
        assert_eq!(entries[3].name, "zebra.txt");
    }

    #[test]
    fn test_portable_pty_powershell() {
        use portable_pty::{CommandBuilder, NativePtySystem, PtySize, PtySystem};
        use std::io::{Read, Write};

        let pty_system = NativePtySystem::default();
        let pair = pty_system
            .openpty(PtySize {
                rows: 24,
                cols: 80,
                pixel_width: 0,
                pixel_height: 0,
            })
            .unwrap();

        let cmd = CommandBuilder::new("powershell.exe");
        let mut child = pair.slave.spawn_command(cmd).unwrap();
        drop(pair.slave);

        let mut reader = pair.master.try_clone_reader().unwrap();
        let mut writer = pair.master.take_writer().unwrap();

        let mut term = crate::terminal::TerminalEmulator::new(80, 24, 1000, "Cuty Dark");
        let mut buf = [0u8; 1024];

        // Loop reading from PTY and feeding TerminalEmulator, relaying CPR responses
        let mut got_prompt = false;
        for _ in 0..10 {
            if let Ok(n) = reader.read(&mut buf) {
                if n == 0 {
                    break;
                }
                term.feed_bytes(&buf[..n]);
                for resp in term.take_pending_responses() {
                    let _ = writer.write_all(&resp);
                    let _ = writer.flush();
                }

                // Check visible terminal rows for PowerShell prompt
                for r in 0..term.state.rows {
                    let text = term.state.grid[r].iter().map(|c| c.ch).collect::<String>();
                    if text.contains("PS ") || text.contains("PowerShell") || text.contains('>') {
                        got_prompt = true;
                        break;
                    }
                }
                if got_prompt {
                    break;
                }
            }
            std::thread::sleep(std::time::Duration::from_millis(50));
        }

        assert!(
            got_prompt,
            "PowerShell prompt should appear after terminal replies to cursor queries"
        );
        let _ = child.kill();
    }

    #[test]
    fn test_session_management_and_export_import() {
        use crate::config::{AppConfig, ProtocolType, SessionProfile};
        use uuid::Uuid;

        let mut config = AppConfig::default();
        config.sessions.clear();

        let s1 = SessionProfile {
            id: Uuid::new_v4(),
            name: "Prod Web 1".to_string(),
            protocol: ProtocolType::Ssh,
            host: "192.168.1.10".to_string(),
            port: 22,
            username: "admin".to_string(),
            folder: "Production".to_string(),
            ..Default::default()
        };
        let s2 = SessionProfile {
            id: Uuid::new_v4(),
            name: "Prod DB 1".to_string(),
            protocol: ProtocolType::Ssh,
            host: "192.168.1.20".to_string(),
            port: 22,
            username: "postgres".to_string(),
            folder: "Production".to_string(),
            ..Default::default()
        };
        let s3 = SessionProfile {
            id: Uuid::new_v4(),
            name: "Switch Cisco Core".to_string(),
            protocol: ProtocolType::Telnet,
            host: "10.0.0.1".to_string(),
            port: 23,
            username: "netadmin".to_string(),
            folder: "Network".to_string(),
            ..Default::default()
        };
        let s4 = SessionProfile {
            id: Uuid::new_v4(),
            name: "PowerShell Console".to_string(),
            protocol: ProtocolType::LocalShell,
            local_shell_cmd: "powershell.exe".to_string(),
            folder: "Local".to_string(),
            ..Default::default()
        };

        config.sessions.push(s1.clone());
        config.sessions.push(s2.clone());
        config.sessions.push(s3.clone());
        config.sessions.push(s4.clone());

        // 1. Test all_folders
        let folders = config.all_folders();
        assert_eq!(folders, vec!["Local", "Network", "Production"]);

        // 2. Test duplicate_session
        let dup = config
            .duplicate_session(s1.id)
            .expect("Should duplicate s1");
        assert_eq!(dup.name, "Prod Web 1 (Copie)");
        assert_ne!(dup.id, s1.id);
        assert_eq!(dup.host, "192.168.1.10");
        assert_eq!(dup.folder, "Production");
        assert_eq!(config.sessions.len(), 5);

        // 3. Test move_sessions_to_folder
        let moved = config.move_sessions_to_folder(&[s3.id, dup.id], "Staging");
        assert_eq!(moved, 2);
        assert_eq!(
            config
                .sessions
                .iter()
                .find(|s| s.id == s3.id)
                .unwrap()
                .folder,
            "Staging"
        );
        assert_eq!(
            config
                .sessions
                .iter()
                .find(|s| s.id == dup.id)
                .unwrap()
                .folder,
            "Staging"
        );

        // 4. Test export_sessions_json (filtered and all)
        let json_all = config.export_sessions_json(None).expect("Export all");
        assert!(json_all.contains("Prod Web 1"));
        assert!(json_all.contains("Switch Cisco Core"));

        let json_sel = config
            .export_sessions_json(Some(&[s2.id]))
            .expect("Export selected");
        assert!(json_sel.contains("Prod DB 1"));
        assert!(!json_sel.contains("Switch Cisco Core"));

        // 5. Test import_sessions_json into fresh config
        let mut fresh_config = AppConfig::default();
        fresh_config.sessions.clear();
        let imported_count = fresh_config
            .import_sessions_json(&json_all)
            .expect("Import valid JSON");
        assert_eq!(imported_count, 5);
        assert_eq!(fresh_config.sessions.len(), 5);

        // 6. Test import again with UUID collision handling
        let reimported = fresh_config
            .import_sessions_json(&json_all)
            .expect("Re-import with collision should generate new IDs");
        assert_eq!(reimported, 5);
        assert_eq!(fresh_config.sessions.len(), 10);
        // All IDs must be unique
        let unique_ids: std::collections::HashSet<_> =
            fresh_config.sessions.iter().map(|s| s.id).collect();
        assert_eq!(unique_ids.len(), 10);

        // 7. Test delete_session and delete_sessions
        assert!(config.delete_session(dup.id));
        assert_eq!(config.sessions.len(), 4);

        let bulk_deleted = config.delete_sessions(&[s1.id, s2.id]);
        assert_eq!(bulk_deleted, 2);
        assert_eq!(config.sessions.len(), 2);
    }

    #[test]
    fn test_session_tags_and_bulk_operations() {
        use crate::config::{AppConfig, ProtocolType, SessionProfile};
        use uuid::Uuid;

        let mut config = AppConfig::default();
        config.sessions.clear();

        let s1_id = Uuid::new_v4();
        let s2_id = Uuid::new_v4();
        let s3_id = Uuid::new_v4();

        let s1 = SessionProfile {
            id: s1_id,
            name: "Server Alpha".to_string(),
            protocol: ProtocolType::Ssh,
            host: "10.0.0.1".to_string(),
            tags: vec!["prod".to_string(), "linux".to_string()],
            ..Default::default()
        };
        let s2 = SessionProfile {
            id: s2_id,
            name: "Server Beta".to_string(),
            protocol: ProtocolType::Ssh,
            host: "10.0.0.2".to_string(),
            tags: vec!["staging".to_string(), "linux".to_string(), "db".to_string()],
            ..Default::default()
        };
        let s3 = SessionProfile {
            id: s3_id,
            name: "Router Gateway".to_string(),
            protocol: ProtocolType::Telnet,
            host: "10.0.0.254".to_string(),
            tags: Vec::new(),
            ..Default::default()
        };

        config.sessions.push(s1);
        config.sessions.push(s2);
        config.sessions.push(s3);

        // 1. Test all_tags()
        let tags = config.all_tags();
        assert_eq!(tags, vec!["db", "linux", "prod", "staging"]);

        // 2. Test add_tag_to_sessions (with trimming and case-insensitivity)
        let added = config.add_tag_to_sessions(&[s1_id, s3_id], " critical ");
        assert_eq!(added, 2);
        assert!(config.sessions[0].tags.contains(&"critical".to_string()));
        assert!(config.sessions[2].tags.contains(&"critical".to_string()));

        // Adding an existing tag should not duplicate
        let dup_added = config.add_tag_to_sessions(&[s1_id], "PROD");
        assert_eq!(dup_added, 0);
        assert_eq!(
            config.sessions[0]
                .tags
                .iter()
                .filter(|t| t.eq_ignore_ascii_case("prod"))
                .count(),
            1
        );

        // 3. Test remove_tag_from_sessions
        let removed = config.remove_tag_from_sessions(&[s1_id, s2_id], "linux");
        assert_eq!(removed, 2);
        assert!(!config.sessions[0].tags.iter().any(|t| t == "linux"));
        assert!(!config.sessions[1].tags.iter().any(|t| t == "linux"));

        // 4. Test serde backwards compatibility (JSON without tags field)
        let base = SessionProfile {
            name: "Legacy Session".to_string(),
            ..Default::default()
        };
        let mut value = serde_json::to_value(&base).expect("To JSON value");
        if let Some(obj) = value.as_object_mut() {
            obj.remove("tags");
        }
        let parsed: SessionProfile =
            serde_json::from_value(value).expect("Must parse JSON without tags field");
        assert!(parsed.tags.is_empty());

        // 5. Test JSON serialization and deserialization with tags
        let serialized = serde_json::to_string(&config.sessions[0]).expect("Serialize with tags");
        assert!(serialized.contains(r#""tags":["#));
        let roundtrip: SessionProfile =
            serde_json::from_str(&serialized).expect("Deserialize with tags");
        assert_eq!(roundtrip.tags, config.sessions[0].tags);
    }

    #[test]
    fn test_primary_key_and_ssh_copy_id_script() {
        use crate::ssh::ppk::{build_ssh_copy_id_script, resolve_or_create_primary_key};

        // 1. Resolve or auto-generate Primary Key
        let (path, info, _created) =
            resolve_or_create_primary_key("").expect("Should resolve or create primary key");
        assert!(path.exists());
        assert!(
            info.openssh_public_key.starts_with("ssh-"),
            "Public key must be in OpenSSH format: {}",
            info.openssh_public_key
        );

        // 2. Build idempotent ssh-copy-id POSIX script
        let script = build_ssh_copy_id_script(&info.openssh_public_key)
            .expect("Should build ssh-copy-id script");
        assert!(script.contains("mkdir -p ~/.ssh"));
        assert!(script.contains("chmod 700 ~/.ssh"));
        assert!(script.contains("chmod 600 ~/.ssh/authorized_keys"));
        assert!(script.contains("CUTY_SSH_KEY_INSTALLED_OK"));
        assert!(script.contains("CUTY_SSH_KEY_ALREADY_PRESENT"));

        // 3. Reject empty public key
        assert!(build_ssh_copy_id_script("   ").is_err());
    }
}
