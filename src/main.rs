// Release builds are GUI-subsystem binaries (no console window); debug keeps the console for logs.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

pub mod config;
pub mod protocols;
pub mod ssh;
pub mod terminal;
pub mod ui;

use ui::CutySshApp;

/// Re-attach stdout/stderr to the console of the parent process (needed with the GUI subsystem).
#[cfg(all(windows, not(debug_assertions)))]
pub fn attach_parent_console() {
    use std::os::windows::io::IntoRawHandle;
    use windows_sys::Win32::System::Console::{
        ATTACH_PARENT_PROCESS, AttachConsole, GetStdHandle, STD_ERROR_HANDLE, STD_OUTPUT_HANDLE,
        SetStdHandle,
    };
    unsafe {
        let cur_out = GetStdHandle(STD_OUTPUT_HANDLE);
        let redirected = !cur_out.is_null() && cur_out as isize != -1 && cur_out as isize != 0;
        if !redirected && AttachConsole(ATTACH_PARENT_PROCESS) != 0 {
            if let Ok(f) = std::fs::OpenOptions::new().write(true).open("CONOUT$") {
                SetStdHandle(STD_OUTPUT_HANDLE, f.into_raw_handle() as _);
            }
            if let Ok(f) = std::fs::OpenOptions::new().write(true).open("CONOUT$") {
                SetStdHandle(STD_ERROR_HANDLE, f.into_raw_handle() as _);
            }
        }
    }
}

#[cfg(any(not(windows), debug_assertions))]
pub fn attach_parent_console() {}

/// Target destination requested from the command-line interface.
#[derive(Debug, Clone)]
pub enum CliTarget {
    /// Saved session referenced by name or UUID.
    SavedSession(String),
    /// Ad-hoc connection generated dynamically on the fly.
    AdHoc {
        profile: Box<config::SessionProfile>,
        open_sftp: bool,
    },
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
        println!("Usage: cuty-ssh.exe [OPTIONS] [TARGET] [-- COMMAND...]\n");
        println!("Arguments:");
        println!(
            "  [TARGET]                           Saved session name/UUID, [user@]host[:port], or URI (ssh://, sftp://, telnet://)\n"
        );
        println!("Connection & Session Options:");
        println!("  -s, --session <NAME|UUID>          Open a saved session");
        println!(
            "  -load <NAME|UUID>                  Alias for --session (PuTTY/KiTTY compatibility)"
        );
        println!("  -shell, --shell                    Open a local ConPTY PowerShell shell");
        println!("  -ssh [USER@]HOST                   Connect via SSH2");
        println!("  -telnet HOST                       Connect via Telnet");
        println!("  -raw HOST                          Connect via Raw TCP");
        println!("  -P, --port <PORT>                  Target port number");
        println!("  -l, --user <USER>                  SSH username");
        println!("  -pw <PASSWORD>                     SSH/Telnet login password");
        println!("  -i <KEYFILE>                       SSH private key path (.ppk, OpenSSH, PEM)");
        println!("  -passphrase <PASSPHRASE>           SSH private key passphrase");
        println!("  -J <BASTION>                       Bastion / ProxyJump (user@bastion:port)\n");
        println!("CLI Automation & Remote Execution:");
        println!(
            "  --exec <COMMAND>                   Execute remote SSH command headless and stream output"
        );
        println!(
            "  -m <SCRIPT_FILE>                   Read remote command from local script file and execute"
        );
        println!(
            "  -- COMMAND...                      Execute everything following '--' as remote command"
        );
        println!(
            "  -t                                 Force PTY allocation for remote command execution"
        );
        println!(
            "  --batch                            Strict non-interactive mode (no prompts, fail on unknown host)"
        );
        println!(
            "  --timeout <SECS>                   Connection and execution timeout in seconds\n"
        );
        println!("SFTP Command-Line Transfers:");
        println!(
            "  --sftp-put <LOCAL> <REMOTE>        Upload local file or directory to remote SFTP server"
        );
        println!(
            "  --sftp-get <REMOTE> <LOCAL>        Download remote file or directory from SFTP server"
        );
        println!("  -r, --recursive                    Recursive transfer for directories\n");
        println!("Port Forwarding Tunnel:");
        println!(
            "  --tunnel <[BIND:]PORT:HOST:PORT>   Forward local port to remote destination (Ctrl+C to quit)\n"
        );
        println!("General Options:");
        println!("      --list                         List saved sessions and exit");
        println!("  -V, --version                      Print version information");
        println!("  -h, --help                         Print help information\n");
        println!("Examples:");
        println!("  1. Remote Command Execution:");
        println!("     cuty-ssh -ssh root@host -i key.ppk --exec \"uptime && free -m\"");
        println!("     cuty-ssh -load \"PROD_SERVER\" -- hostname -I\n");
        println!("  2. Local Script Execution:");
        println!("     cuty-ssh -ssh root@host -m ./deploy.sh");
        println!("     cuty-ssh -load \"PROD_SERVER\" -m ./diagnose.sh\n");
        println!("  3. Non-Interactive Batch Mode:");
        println!("     cuty-ssh --batch --exec \"systemctl status nginx\" -load \"PROD_SERVER\"");
        println!(
            "     cuty-ssh --batch --timeout 10 -ssh root@10.0.0.1 -i key.ppk --exec \"df -h\"\n"
        );
        println!("  4. SFTP File & Directory Transfers:");
        println!("     cuty-ssh --sftp-put ./app.tar.gz /var/www/ -load \"PROD_SERVER\"");
        println!("     cuty-ssh --sftp-get /var/log/syslog ./syslog.log -ssh root@host -pw secret");
        println!("     cuty-ssh -r --sftp-put ./dist/ /var/www/html/ -load \"PROD_SERVER\"\n");
        println!("  5. CLI Port Forwarding Tunnel:");
        println!("     cuty-ssh --tunnel 8080:localhost:80 -ssh root@host -i key.ppk");
        println!("     cuty-ssh --tunnel 0.0.0.0:5432:db.internal:5432 -load \"DB_BASTION\"");
        return Ok(());
    }

    let loaded_config = config::AppConfig::load_or_default();

    if args.iter().any(|a| a == "--list") {
        #[cfg(windows)]
        attach_parent_console();
        for s in &loaded_config.sessions {
            println!(
                "{}  [{:^7}]  {:<25}  {}@{}:{}",
                s.id,
                s.protocol.label(),
                s.name,
                s.username,
                s.host,
                s.port
            );
        }
        return Ok(());
    }

    // Headless CLI automation dispatcher (--exec, -m, --sftp-put, --sftp-get, --tunnel, --batch, or --)
    match protocols::cli::parse_cli_invocation(&args, &loaded_config) {
        Ok(Some(invocation)) => {
            #[cfg(windows)]
            attach_parent_console();

            let rt = tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()
                .expect("Failed to initialize Tokio runtime for CLI mode");

            let exit_code = rt.block_on(protocols::cli::run_cli(invocation));
            std::process::exit(exit_code);
        }
        Ok(None) => {}
        Err(e) => {
            #[cfg(windows)]
            attach_parent_console();
            eprintln!("cuty-ssh: Error: {:#}", e);
            std::process::exit(255);
        }
    }

    let startup_target = parse_cli_target(&args, &loaded_config);

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
        .with_title("Cuty-SSH — SSH2 / Telnet / SFTP · PuTTY (.ppk) & Cuty Agent")
        .with_inner_size([1320.0, 820.0])
        // Min width 120 pt lets the resize-to-sliver dismiss gesture trigger
        // (ui/mod.rs minimizes below ~160 pt); min height fits the roll-up
        // banner.
        .with_min_inner_size([120.0, 42.0]);

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
            let mut app = CutySshApp::new(cc, handle);
            if let Some(target) = &startup_target {
                match target {
                    CliTarget::SavedSession(key) => app.open_session_by_key(key),
                    CliTarget::AdHoc { profile, open_sftp } => {
                        app.launch_session((**profile).clone());
                        if *open_sftp && let Some(tab) = app.tabs.last_mut() {
                            tab.show_sftp_full = true;
                            tab.show_sftp_panel = false;
                            let _ = tab.handle.cmd_tx.send(
                                crate::protocols::BackendCommand::SftpListDir(
                                    tab.sftp_current_path.clone(),
                                ),
                            );
                            tab.sftp_client.refresh_local();
                        }
                    }
                }
            }
            Ok(Box::new(app))
        }),
    ) {
        eprintln!("eframe error: {e}");
        let _ = std::fs::write("cuty-ssh-crash.log", format!("eframe error: {e}"));
    }
    Ok(())
}

/// Helper function to parse user@host:port (and optional IPv6 like `[::1]:22`).
fn parse_user_host_port(raw: &str, default_port: u16) -> (Option<String>, String, Option<u16>) {
    let (user, remainder) = if let Some((u, r)) = raw.split_once('@') {
        (Some(u.to_string()), r)
    } else {
        (None, raw)
    };

    let (host, port) = if let Some(stripped) = remainder.strip_prefix('[') {
        if let Some((ipv6, rest)) = stripped.split_once(']') {
            let p = rest
                .strip_prefix(':')
                .and_then(|p_str| p_str.parse::<u16>().ok());
            (ipv6.to_string(), p)
        } else {
            (remainder.to_string(), None)
        }
    } else if let Some((h, p_str)) = remainder.split_once(':') {
        (h.to_string(), p_str.parse::<u16>().ok())
    } else {
        (remainder.to_string(), None)
    };

    (user, host, port.or(Some(default_port)))
}

/// Parses CLI arguments to determine if a saved session or an ad-hoc connection should start.
pub fn parse_cli_target(args: &[String], config: &config::AppConfig) -> Option<CliTarget> {
    let mut it = args.iter().skip(1).peekable();
    let mut session_key: Option<String> = None;
    let mut protocol: Option<config::ProtocolType> = None;
    let mut host: Option<String> = None;
    let mut port: Option<u16> = None;
    let mut user: Option<String> = None;
    let mut password: Option<String> = None;
    let mut key_path: Option<String> = None;
    let mut key_passphrase: Option<String> = None;
    let mut proxy_jump: Option<String> = None;
    let mut open_sftp = false;
    let mut is_local_shell = false;
    let mut positional: Vec<String> = Vec::new();

    while let Some(arg) = it.next() {
        if arg == "-s" || arg == "--session" || arg == "-load" {
            if let Some(v) = it.next() {
                session_key = Some(v.clone());
            }
        } else if let Some(v) = arg.strip_prefix("--session=") {
            session_key = Some(v.to_string());
        } else if let Some(v) = arg.strip_prefix("-load=") {
            session_key = Some(v.to_string());
        } else if arg == "-shell" || arg == "--shell" || arg == "-local" {
            is_local_shell = true;
        } else if arg == "-ssh" {
            protocol = Some(config::ProtocolType::Ssh);
            if it.peek().is_some_and(|next| !next.starts_with('-')) {
                host = it.next().cloned();
            }
        } else if arg == "-telnet" {
            protocol = Some(config::ProtocolType::Telnet);
            if it.peek().is_some_and(|next| !next.starts_with('-')) {
                host = it.next().cloned();
            }
        } else if arg == "-raw" {
            protocol = Some(config::ProtocolType::RawTcp);
            if it.peek().is_some_and(|next| !next.starts_with('-')) {
                host = it.next().cloned();
            }
        } else if arg == "-P" || arg == "--port" {
            if let Some(p_str) = it.next() {
                port = p_str.parse().ok();
            }
        } else if let Some(p_str) = arg.strip_prefix("-P=") {
            port = p_str.parse().ok();
        } else if let Some(p_str) = arg.strip_prefix("--port=") {
            port = p_str.parse().ok();
        } else if arg == "-l" || arg == "--user" {
            if let Some(u_str) = it.next() {
                user = Some(u_str.clone());
            }
        } else if let Some(u_str) = arg.strip_prefix("-l=") {
            user = Some(u_str.to_string());
        } else if let Some(u_str) = arg.strip_prefix("--user=") {
            user = Some(u_str.to_string());
        } else if arg == "-pw" {
            if let Some(pw_str) = it.next() {
                password = Some(pw_str.clone());
            }
        } else if let Some(pw_str) = arg.strip_prefix("-pw=") {
            password = Some(pw_str.to_string());
        } else if arg == "-i" {
            if let Some(i_str) = it.next() {
                key_path = Some(i_str.clone());
            }
        } else if let Some(i_str) = arg.strip_prefix("-i=") {
            key_path = Some(i_str.to_string());
        } else if arg == "-passphrase"
            || arg == "--passphrase"
            || arg == "-keypass"
            || arg == "--keypass"
        {
            if let Some(pp_str) = it.next() {
                key_passphrase = Some(pp_str.clone());
            }
        } else if let Some(pp_str) = arg.strip_prefix("-passphrase=") {
            key_passphrase = Some(pp_str.to_string());
        } else if let Some(pp_str) = arg.strip_prefix("--passphrase=") {
            key_passphrase = Some(pp_str.to_string());
        } else if let Some(pp_str) = arg.strip_prefix("-keypass=") {
            key_passphrase = Some(pp_str.to_string());
        } else if let Some(pp_str) = arg.strip_prefix("--keypass=") {
            key_passphrase = Some(pp_str.to_string());
        } else if arg == "-J" {
            if let Some(j_str) = it.next() {
                proxy_jump = Some(j_str.clone());
            }
        } else if let Some(j_str) = arg.strip_prefix("-J=") {
            proxy_jump = Some(j_str.to_string());
        } else if !arg.starts_with('-') {
            positional.push(arg.clone());
        }
    }

    // 1. Explicit session key provided
    if let Some(k) = session_key {
        return Some(CliTarget::SavedSession(k));
    }

    // 2. Local shell flag
    if is_local_shell {
        let profile = config::SessionProfile {
            name: "Shell Local (ConPTY)".to_string(),
            protocol: config::ProtocolType::LocalShell,
            local_shell_cmd: "powershell.exe".to_string(),
            folder: "Local".to_string(),
            ..Default::default()
        };
        return Some(CliTarget::AdHoc {
            profile: Box::new(profile),
            open_sftp: false,
        });
    }

    // 3. Positional argument handling
    if let Some(first_pos) = positional.first() {
        if first_pos.starts_with("ssh://")
            || first_pos.starts_with("sftp://")
            || first_pos.starts_with("telnet://")
            || first_pos.starts_with("raw://")
        {
            let (proto, scheme_open_sftp, def_port, rest) =
                if let Some(r) = first_pos.strip_prefix("ssh://") {
                    (config::ProtocolType::Ssh, false, 22, r)
                } else if let Some(r) = first_pos.strip_prefix("sftp://") {
                    (config::ProtocolType::Ssh, true, 22, r)
                } else if let Some(r) = first_pos.strip_prefix("telnet://") {
                    (config::ProtocolType::Telnet, false, 23, r)
                } else if let Some(r) = first_pos.strip_prefix("raw://") {
                    (config::ProtocolType::RawTcp, false, 80, r)
                } else {
                    unreachable!()
                };
            open_sftp = scheme_open_sftp;
            protocol = Some(proto);

            let authority = rest.split('/').next().unwrap_or(rest);
            let (u, h, p) = parse_user_host_port(authority, def_port);
            if user.is_none() && u.is_some() {
                user = u;
            }
            host = Some(h);
            if port.is_none() && p.is_some() {
                port = p;
            }
        } else if config.find_session(first_pos).is_ok() {
            return Some(CliTarget::SavedSession(first_pos.clone()));
        } else {
            let (u, h, p) = parse_user_host_port(first_pos, 22);
            if user.is_none() && u.is_some() {
                user = u;
            }
            if host.is_none() {
                host = Some(h);
            }
            if port.is_none() && p.is_some() {
                port = p;
            }
            if protocol.is_none() {
                protocol = Some(config::ProtocolType::Ssh);
            }
        }
    }

    // 4. Construct AdHoc profile if host is present
    if let Some(raw_host) = host {
        let proto = protocol.unwrap_or(config::ProtocolType::Ssh);
        let (u, target_host, p) = parse_user_host_port(&raw_host, proto.default_port());
        if user.is_none() && u.is_some() {
            user = u;
        }
        let final_port = port.or(p).unwrap_or_else(|| proto.default_port());
        let final_user = user.unwrap_or_else(|| "root".to_string());
        let session_name = if proto == config::ProtocolType::Ssh {
            format!("{}@{}:{}", final_user, target_host, final_port)
        } else {
            format!("{}:{}", target_host, final_port)
        };

        let mut profile = config::SessionProfile {
            name: session_name,
            folder: "Ad-hoc".to_string(),
            protocol: proto,
            host: target_host,
            port: final_port,
            username: final_user,
            ..Default::default()
        };

        if let Some(pw) = password {
            profile.password = pw;
            profile.auto_password = true;
            profile.auto_login = true;
        }

        if let Some(kp) = key_path {
            profile.ssh_auth = config::SshAuthMethod::PrivateKeyFile {
                key_path: kp,
                passphrase: key_passphrase.unwrap_or_default(),
                cert_path: String::new(),
            };
        }

        if let Some(pj) = proxy_jump {
            profile.proxy_jump = pj;
        }

        return Some(CliTarget::AdHoc {
            profile: Box::new(profile),
            open_sftp,
        });
    }

    None
}

/// Returns the value of `-s <key>`, `--session <key>` or `--session=<key>`.
#[cfg(test)]
fn parse_session_arg(args: &[String]) -> Option<String> {
    let mut it = args.iter().skip(1);
    while let Some(a) = it.next() {
        if a == "-s" || a == "--session" || a == "-load" {
            return it.next().cloned();
        }
        if let Some(v) = a.strip_prefix("--session=") {
            return Some(v.to_string());
        }
        if let Some(v) = a.strip_prefix("-load=") {
            return Some(v.to_string());
        }
    }
    None
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
        decode_private_key_any, export_to_openssh_pem, export_to_ppk_v3, format_openssh_pubkey,
        generate_new_ssh_key, generate_openssh_key_encrypted, inspect_key_content,
    };
    use crate::terminal::TerminalEmulator;

    #[test]
    fn test_openssh_encrypted_generation_roundtrip() {
        let (pem, pub_line) =
            generate_openssh_key_encrypted("gen@cuty-ssh", "s3cret-pass").unwrap();
        assert!(pem.starts_with("-----BEGIN OPENSSH PRIVATE KEY-----"));
        assert!(pub_line.starts_with("ssh-ed25519 "));
        assert!(pub_line.contains("gen@cuty-ssh"));

        let info = inspect_key_content(&pem, "id_cuty_ed25519").unwrap();
        // The inspector cannot see through encryption: it flags the key as
        // encrypted and hides the algorithm until a passphrase is provided.
        assert!(
            info.is_encrypted,
            "generated key must be passphrase-protected"
        );

        assert!(
            decode_private_key_any(&pem, Some("wrong-pass")).is_err(),
            "a wrong passphrase must be rejected"
        );

        let key = decode_private_key_any(&pem, Some("s3cret-pass")).unwrap();
        assert_eq!(key.algorithm().as_str(), "ssh-ed25519");
        assert_eq!(format_openssh_pubkey(key.public_key()), pub_line);
    }

    /// Opt-in interop check (set `CUTY_E2E_SSH_KEYGEN=1`): the generated
    /// encrypted key must be readable by the reference `ssh-keygen` binary,
    /// and a wrong passphrase must be rejected by it as well.
    #[test]
    fn test_openssh_encrypted_key_matches_real_ssh_keygen() {
        if std::env::var("CUTY_E2E_SSH_KEYGEN").is_err() {
            eprintln!("skipped: set CUTY_E2E_SSH_KEYGEN=1 to run the ssh-keygen interop check");
            return;
        }
        let (pem, pub_line) = generate_openssh_key_encrypted("e2e@cuty-ssh", "e2e-pass").unwrap();
        let key_p = std::env::temp_dir().join("cuty_e2e_id_ed25519");
        std::fs::write(&key_p, pem.as_str()).unwrap();

        let read_pub = |pass: &str| {
            std::process::Command::new("ssh-keygen")
                .args(["-y", "-P", pass, "-f"])
                .arg(&key_p)
                .output()
                .expect("ssh-keygen not found on PATH")
        };

        let ok = read_pub("e2e-pass");
        assert!(
            ok.status.success(),
            "ssh-keygen failed to read our key: {}",
            String::from_utf8_lossy(&ok.stderr)
        );
        // `ssh-keygen -y` prints the public key including the comment it
        // recovers from inside the encrypted payload.
        assert_eq!(String::from_utf8_lossy(&ok.stdout).trim(), pub_line);

        let bad = read_pub("wrong-pass");
        assert!(
            !bad.status.success(),
            "ssh-keygen must reject a wrong passphrase"
        );
        let _ = std::fs::remove_file(&key_p);
    }

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
    fn test_cli_session_arg_and_lookup() {
        let a = |v: &[&str]| v.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        assert_eq!(
            super::parse_session_arg(&a(&["x", "-s", "Prod"])),
            Some("Prod".into())
        );
        assert_eq!(
            super::parse_session_arg(&a(&["x", "--session=db 1"])),
            Some("db 1".into())
        );
        assert_eq!(super::parse_session_arg(&a(&["x"])), None);

        let mut cfg = AppConfig::default();
        cfg.sessions.clear();
        for name in ["Prod Web", "Prod DB", "Staging"] {
            cfg.sessions.push(crate::config::SessionProfile {
                name: name.into(),
                ..Default::default()
            });
        }
        assert_eq!(cfg.find_session("staging").unwrap().name, "Staging");
        assert_eq!(cfg.find_session("prod db").unwrap().name, "Prod DB");
        assert!(cfg.find_session("prod").unwrap_err().contains("ambiguous"));
        assert!(cfg.find_session("nope").is_err());
    }

    #[test]
    fn test_cli_target_advanced_parsing() {
        use super::{CliTarget, parse_cli_target};
        use crate::config::ProtocolType;

        let a = |v: &[&str]| v.iter().map(|s| s.to_string()).collect::<Vec<_>>();

        let mut cfg = AppConfig::default();
        cfg.sessions.clear();
        cfg.sessions.push(crate::config::SessionProfile {
            name: "Staging Server".into(),
            ..Default::default()
        });

        // 1. Saved session via -load or exact name
        match parse_cli_target(&a(&["cuty-ssh", "-load", "Staging Server"]), &cfg) {
            Some(CliTarget::SavedSession(s)) => assert_eq!(s, "Staging Server"),
            _ => panic!("Expected SavedSession"),
        }
        match parse_cli_target(&a(&["cuty-ssh", "Staging Server"]), &cfg) {
            Some(CliTarget::SavedSession(s)) => assert_eq!(s, "Staging Server"),
            _ => panic!("Expected SavedSession"),
        }

        // 2. Ad-hoc SSH user@host
        let target = parse_cli_target(&a(&["cuty-ssh", "admin@192.168.1.1:2222"]), &cfg).unwrap();
        if let CliTarget::AdHoc { profile, open_sftp } = target {
            assert_eq!(profile.protocol, ProtocolType::Ssh);
            assert_eq!(profile.username, "admin");
            assert_eq!(profile.host, "192.168.1.1");
            assert_eq!(profile.port, 2222);
            assert!(!open_sftp);
        } else {
            panic!("Expected AdHoc target");
        }

        // 3. Ad-hoc sftp:// URI
        let target =
            parse_cli_target(&a(&["cuty-ssh", "sftp://root@remote.lan:22"]), &cfg).unwrap();
        if let CliTarget::AdHoc { profile, open_sftp } = target {
            assert_eq!(profile.protocol, ProtocolType::Ssh);
            assert_eq!(profile.username, "root");
            assert_eq!(profile.host, "remote.lan");
            assert_eq!(profile.port, 22);
            assert!(open_sftp);
        } else {
            panic!("Expected AdHoc target with open_sftp");
        }

        // 4. PuTTY style -ssh with -pw and -P
        let target = parse_cli_target(
            &a(&[
                "cuty-ssh",
                "-ssh",
                "10.0.0.1",
                "-P",
                "2200",
                "-l",
                "deploy",
                "-pw",
                "secret123",
            ]),
            &cfg,
        )
        .unwrap();
        if let CliTarget::AdHoc { profile, .. } = target {
            assert_eq!(profile.protocol, ProtocolType::Ssh);
            assert_eq!(profile.host, "10.0.0.1");
            assert_eq!(profile.port, 2200);
            assert_eq!(profile.username, "deploy");
            assert_eq!(profile.password, "secret123");
            assert!(profile.auto_password);
        } else {
            panic!("Expected AdHoc target");
        }

        // 5. Local shell -shell
        let target = parse_cli_target(&a(&["cuty-ssh", "-shell"]), &cfg).unwrap();
        if let CliTarget::AdHoc { profile, .. } = target {
            assert_eq!(profile.protocol, ProtocolType::LocalShell);
            assert_eq!(profile.local_shell_cmd, "powershell.exe");
        } else {
            panic!("Expected AdHoc target");
        }

        // 6. Private key with passphrase (-i and -passphrase)
        let target = parse_cli_target(
            &a(&[
                "cuty-ssh",
                "-ssh",
                "10.0.0.1",
                "-i",
                r"C:\keys\id_rsa.ppk",
                "-passphrase",
                "my_key_pass",
            ]),
            &cfg,
        )
        .unwrap();
        if let CliTarget::AdHoc { profile, .. } = target {
            assert_eq!(profile.protocol, ProtocolType::Ssh);
            assert_eq!(profile.host, "10.0.0.1");
            if let crate::config::SshAuthMethod::PrivateKeyFile {
                key_path,
                passphrase,
                ..
            } = profile.ssh_auth
            {
                assert_eq!(key_path, r"C:\keys\id_rsa.ppk");
                assert_eq!(passphrase, "my_key_pass");
            } else {
                panic!("Expected PrivateKeyFile auth method");
            }
        } else {
            panic!("Expected AdHoc target");
        }

        // 7. Empty args
        assert!(parse_cli_target(&a(&["cuty-ssh"]), &cfg).is_none());
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
