use crate::config::{
    AppConfig, HostKeyCheckResult, SessionProfile, SshAuthMethod, load_known_hosts,
    split_user_and_host, verify_or_record_known_host,
};
use crate::protocols::{parse_inline_proxy_jump, rsa_hash_candidates};
use crate::ssh::ppk::{inspect_key_file, load_private_key_any};
use anyhow::{Context, Result, bail};
use russh::keys::ssh_key::{HashAlg, PublicKey};
use russh::keys::{PrivateKeyWithHashAlg, PublicKeyBase64, PublicKeyOrCertificate};
use russh::{ChannelMsg, client};
use russh_sftp::client::SftpSession;
use russh_sftp::protocol::OpenFlags;
use std::io::{IsTerminal, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// Headless action to perform in CLI automation mode.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CliAction {
    /// Remote command execution via SSH exec channel.
    Exec { command: String, force_pty: bool },
    /// SFTP file/directory upload.
    SftpPut {
        local_path: PathBuf,
        remote_path: String,
        recursive: bool,
    },
    /// SFTP file/directory download.
    SftpGet {
        remote_path: String,
        local_path: PathBuf,
        recursive: bool,
    },
    /// Local port forwarding tunnel.
    Tunnel {
        bind_addr: String,
        bind_port: u16,
        target_host: String,
        target_port: u16,
    },
}

/// Parsed CLI automation invocation.
#[derive(Debug, Clone)]
pub struct CliInvocation {
    pub action: CliAction,
    pub batch: bool,
    pub timeout_secs: Option<u64>,
    pub profile: SessionProfile,
    pub jump_profile: Option<SessionProfile>,
}

/// Parses local port forwarding spec, e.g. "8080:localhost:80" or "0.0.0.0:8080:localhost:80".
pub fn parse_tunnel_spec(spec: &str) -> Result<(String, u16, String, u16)> {
    let parts: Vec<&str> = spec.split(':').collect();
    match parts.len() {
        3 => {
            let local_port: u16 = parts[0]
                .parse()
                .with_context(|| format!("Invalid local port in tunnel spec '{}'", parts[0]))?;
            let remote_host = parts[1].trim().to_string();
            let remote_port: u16 = parts[2]
                .parse()
                .with_context(|| format!("Invalid remote port in tunnel spec '{}'", parts[2]))?;
            if remote_host.is_empty() {
                bail!("Remote host in tunnel spec cannot be empty");
            }
            Ok((
                "127.0.0.1".to_string(),
                local_port,
                remote_host,
                remote_port,
            ))
        }
        4 => {
            let bind_addr = parts[0].trim().to_string();
            let local_port: u16 = parts[1]
                .parse()
                .with_context(|| format!("Invalid local port in tunnel spec '{}'", parts[1]))?;
            let remote_host = parts[2].trim().to_string();
            let remote_port: u16 = parts[3]
                .parse()
                .with_context(|| format!("Invalid remote port in tunnel spec '{}'", parts[3]))?;
            if bind_addr.is_empty() {
                bail!("Bind address in tunnel spec cannot be empty");
            }
            if remote_host.is_empty() {
                bail!("Remote host in tunnel spec cannot be empty");
            }
            Ok((bind_addr, local_port, remote_host, remote_port))
        }
        _ => bail!(
            "Invalid tunnel spec '{}'. Expected 'local_port:remote_host:remote_port' or 'bind_addr:local_port:remote_host:remote_port'",
            spec
        ),
    }
}

/// Helper function to parse user@host:port (and optional IPv6 like `[::1]:22`).
fn parse_target_authority(raw: &str, default_port: u16) -> (Option<String>, String, Option<u16>) {
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

/// Parses CLI arguments to detect if an automation mode is invoked.
/// Returns `Ok(Some(invocation))` if CLI automation is requested,
/// `Ok(None)` if normal GUI operation should continue,
/// or `Err` if invalid options/arguments were specified.
pub fn parse_cli_invocation(args: &[String], config: &AppConfig) -> Result<Option<CliInvocation>> {
    // Separate arguments before and after `--` delimiter
    let (pre_dash, trailing_cmd) = if let Some(pos) = args.iter().position(|a| a == "--") {
        (&args[..pos], Some(&args[pos + 1..]))
    } else {
        (args, None)
    };

    let mut it = pre_dash.iter().skip(1).peekable();

    let mut exec_cmd: Option<String> = None;
    let mut script_file: Option<String> = None;
    let mut sftp_put: Option<(String, String)> = None;
    let mut sftp_get: Option<(String, String)> = None;
    let mut tunnel_spec: Option<String> = None;
    let mut batch = false;
    let mut timeout_secs: Option<u64> = None;
    let mut force_pty = false;
    let mut recursive = false;

    let mut session_key: Option<String> = None;
    let mut ssh_host: Option<String> = None;
    let mut port: Option<u16> = None;
    let mut user: Option<String> = None;
    let mut password: Option<String> = None;
    let mut key_path: Option<String> = None;
    let mut key_passphrase: Option<String> = None;
    let mut proxy_jump: Option<String> = None;
    let mut positional: Vec<String> = Vec::new();

    while let Some(arg) = it.next() {
        if arg == "--exec" {
            if let Some(cmd) = it.next() {
                exec_cmd = Some(cmd.clone());
            } else {
                bail!("Option --exec requires a command argument");
            }
        } else if let Some(cmd) = arg.strip_prefix("--exec=") {
            exec_cmd = Some(cmd.to_string());
        } else if arg == "-m" {
            if let Some(file) = it.next() {
                script_file = Some(file.clone());
            } else {
                bail!("Option -m requires a local script file path");
            }
        } else if let Some(file) = arg.strip_prefix("-m=") {
            script_file = Some(file.to_string());
        } else if arg == "--batch" {
            batch = true;
        } else if arg == "--timeout" {
            if let Some(t_str) = it.next() {
                let secs: u64 = t_str
                    .parse()
                    .with_context(|| format!("Invalid timeout value '{}'", t_str))?;
                timeout_secs = Some(secs);
            } else {
                bail!("Option --timeout requires a duration in seconds");
            }
        } else if let Some(t_str) = arg.strip_prefix("--timeout=") {
            let secs: u64 = t_str
                .parse()
                .with_context(|| format!("Invalid timeout value '{}'", t_str))?;
            timeout_secs = Some(secs);
        } else if arg == "-t" {
            force_pty = true;
        } else if arg == "-r" || arg == "--recursive" {
            recursive = true;
        } else if arg == "--sftp-put" {
            let local = it
                .next()
                .ok_or_else(|| {
                    anyhow::anyhow!("Option --sftp-put requires local_path and remote_path")
                })?
                .clone();
            let remote = it
                .next()
                .ok_or_else(|| {
                    anyhow::anyhow!("Option --sftp-put requires remote_path after local_path")
                })?
                .clone();
            sftp_put = Some((local, remote));
        } else if arg == "--sftp-get" {
            let remote = it
                .next()
                .ok_or_else(|| {
                    anyhow::anyhow!("Option --sftp-get requires remote_path and local_path")
                })?
                .clone();
            let local = it
                .next()
                .ok_or_else(|| {
                    anyhow::anyhow!("Option --sftp-get requires local_path after remote_path")
                })?
                .clone();
            sftp_get = Some((remote, local));
        } else if arg == "--tunnel" {
            if let Some(spec) = it.next() {
                tunnel_spec = Some(spec.clone());
            } else {
                bail!("Option --tunnel requires a specification (e.g. 8080:localhost:80)");
            }
        } else if let Some(spec) = arg.strip_prefix("--tunnel=") {
            tunnel_spec = Some(spec.to_string());
        } else if arg == "-s" || arg == "--session" || arg == "-load" {
            if let Some(v) = it.next() {
                session_key = Some(v.clone());
            }
        } else if let Some(v) = arg.strip_prefix("--session=") {
            session_key = Some(v.to_string());
        } else if let Some(v) = arg.strip_prefix("-load=") {
            session_key = Some(v.to_string());
        } else if arg == "-ssh" {
            if it.peek().is_some_and(|next| !next.starts_with('-')) {
                ssh_host = it.next().cloned();
            }
        } else if let Some(v) = arg.strip_prefix("-ssh=") {
            ssh_host = Some(v.to_string());
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

    // Trailing command after `--`
    if let Some(trailing) = trailing_cmd
        && !trailing.is_empty()
    {
        exec_cmd = Some(trailing.join(" "));
    }

    // Determine if any CLI automation feature was requested
    let has_explicit_action = exec_cmd.is_some()
        || script_file.is_some()
        || sftp_put.is_some()
        || sftp_get.is_some()
        || tunnel_spec.is_some();

    if !has_explicit_action && !batch {
        // No automation requested -> fall through to normal GUI mode!
        return Ok(None);
    }

    // If -m script file is provided, read its contents
    if let Some(ref file_path) = script_file {
        let path = Path::new(file_path);
        let content = std::fs::read_to_string(path)
            .with_context(|| format!("Failed to read script file '{}'", file_path))?;
        exec_cmd = Some(content);
    }

    // Build or find SessionProfile
    let mut profile = if let Some(ref key) = session_key {
        config
            .find_session(key)
            .cloned()
            .map_err(|e| anyhow::anyhow!("Session '{}' not found in configuration: {}", key, e))?
    } else if let Some(ref raw_host) = ssh_host {
        let (u, h, p) = parse_target_authority(raw_host, 22);
        let target_user = user.clone().or(u).unwrap_or_else(|| "root".to_string());
        let target_port = port.or(p).unwrap_or(22);
        SessionProfile {
            name: format!("{}@{}:{}", target_user, h, target_port),
            folder: "CLI".to_string(),
            protocol: crate::config::ProtocolType::Ssh,
            host: h,
            port: target_port,
            username: target_user,
            ..Default::default()
        }
    } else if let Some(first_pos) = positional.first() {
        if let Ok(s) = config.find_session(first_pos) {
            s.clone()
        } else {
            let (u, h, p) = parse_target_authority(first_pos, 22);
            let target_user = user.clone().or(u).unwrap_or_else(|| "root".to_string());
            let target_port = port.or(p).unwrap_or(22);
            SessionProfile {
                name: format!("{}@{}:{}", target_user, h, target_port),
                folder: "CLI".to_string(),
                protocol: crate::config::ProtocolType::Ssh,
                host: h,
                port: target_port,
                username: target_user,
                ..Default::default()
            }
        }
    } else {
        bail!(
            "No target host or session specified. Provide -ssh [user@]host, -load <SESSION>, or [user@]host"
        );
    };

    // Apply CLI overrides on top of session profile
    if let Some(u) = user {
        profile.username = u;
    }
    if let Some(p) = port {
        profile.port = p;
    }
    if let Some(pw) = password {
        profile.password = pw;
        profile.auto_password = true;
    }
    if let Some(kp) = key_path {
        profile.ssh_auth = SshAuthMethod::PrivateKeyFile {
            key_path: kp,
            passphrase: key_passphrase.unwrap_or_default(),
            cert_path: String::new(),
        };
    } else if let Some(pp) = key_passphrase
        && let SshAuthMethod::PrivateKeyFile {
            ref mut passphrase, ..
        } = profile.ssh_auth
    {
        *passphrase = pp;
    }
    if let Some(pj) = proxy_jump {
        profile.proxy_jump = pj;
    }

    // If batch mode and no command action was given yet, check positional tokens
    if exec_cmd.is_none() && sftp_put.is_none() && sftp_get.is_none() && tunnel_spec.is_none() {
        if positional.len() > 1 {
            exec_cmd = Some(positional[1..].join(" "));
        } else if (session_key.is_some() || ssh_host.is_some()) && !positional.is_empty() {
            exec_cmd = Some(positional.join(" "));
        } else {
            bail!(
                "Batch mode requires a command to execute (--exec, -m, --sftp-put, --sftp-get, --tunnel)"
            );
        }
    }

    // Build the Action
    let action = if let Some(cmd) = exec_cmd {
        CliAction::Exec {
            command: cmd,
            force_pty,
        }
    } else if let Some((local, remote)) = sftp_put {
        CliAction::SftpPut {
            local_path: PathBuf::from(local),
            remote_path: remote,
            recursive,
        }
    } else if let Some((remote, local)) = sftp_get {
        CliAction::SftpGet {
            remote_path: remote,
            local_path: PathBuf::from(local),
            recursive,
        }
    } else if let Some(spec) = tunnel_spec {
        let (bind_addr, bind_port, target_host, target_port) = parse_tunnel_spec(&spec)?;
        CliAction::Tunnel {
            bind_addr,
            bind_port,
            target_host,
            target_port,
        }
    } else {
        bail!("No action specified");
    };

    let jump_profile = parse_inline_proxy_jump(&profile.proxy_jump);

    Ok(Some(CliInvocation {
        action,
        batch,
        timeout_secs,
        profile,
        jump_profile,
    }))
}

/// Ssh handler for headless CLI mode.
pub struct CliSshHandler {
    pub host: String,
    pub port: u16,
    pub batch_mode: bool,
    pub server_fingerprint: Arc<Mutex<Option<String>>>,
}

impl client::Handler for CliSshHandler {
    type Error = russh::Error;

    async fn check_server_key(
        &mut self,
        server_public_key: &PublicKeyOrCertificate,
    ) -> Result<bool, Self::Error> {
        let (alg, fp_raw, b64) = match server_public_key {
            PublicKeyOrCertificate::PublicKey { key: pk, .. } => (
                pk.algorithm().to_string(),
                pk.fingerprint(HashAlg::Sha256).to_string(),
                pk.public_key_base64(),
            ),
            PublicKeyOrCertificate::Certificate(cert) => (
                cert.algorithm().to_string(),
                format!("CERT:{}", cert.algorithm()),
                String::new(),
            ),
        };

        if self.batch_mode {
            let entries = load_known_hosts();
            let host_port = if self.port == 22 {
                self.host.trim().to_lowercase()
            } else {
                format!("[{}]:{}", self.host.trim().to_lowercase(), self.port)
            };
            if let Some(existing) = entries.iter().find(|e| e.host_port == host_port) {
                if existing.fingerprint_sha256 == fp_raw {
                    if let Ok(mut guard) = self.server_fingerprint.lock() {
                        *guard = Some(fp_raw);
                    }
                    Ok(true)
                } else {
                    eprintln!(
                        "cuty-ssh: @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@\n\
                         cuty-ssh: @    WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED!     @\n\
                         cuty-ssh: @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@\n\
                         cuty-ssh: Host key for {}:{} ({}) has changed.\n\
                         cuty-ssh: Expected SHA256: {}\n\
                         cuty-ssh: Received SHA256: {}",
                        self.host, self.port, alg, existing.fingerprint_sha256, fp_raw
                    );
                    Ok(false)
                }
            } else {
                eprintln!(
                    "cuty-ssh: Host key verification failed. Host '{}:{}' ({}) is unknown in known_hosts (batch mode prevents automatic acceptance).",
                    self.host, self.port, alg
                );
                Ok(false)
            }
        } else {
            let check_res = verify_or_record_known_host(&self.host, self.port, &alg, &fp_raw, &b64);
            match check_res {
                HostKeyCheckResult::TrustedMatch { fingerprint, .. } => {
                    if let Ok(mut guard) = self.server_fingerprint.lock() {
                        *guard = Some(fingerprint);
                    }
                    Ok(true)
                }
                HostKeyCheckResult::NewlyTrusted {
                    fingerprint,
                    algorithm,
                } => {
                    if let Ok(mut guard) = self.server_fingerprint.lock() {
                        *guard = Some(fingerprint);
                    }
                    eprintln!(
                        "cuty-ssh: Warning: Permanently added '{}:{}' ({}) to known_hosts.",
                        self.host, self.port, algorithm
                    );
                    Ok(true)
                }
                HostKeyCheckResult::Mismatch {
                    expected_fingerprint,
                    actual_fingerprint,
                    algorithm,
                } => {
                    eprintln!(
                        "cuty-ssh: Host key mismatch for {}:{} ({})! Expected {}, received {}.",
                        self.host, self.port, algorithm, expected_fingerprint, actual_fingerprint
                    );
                    Ok(false)
                }
            }
        }
    }
}

/// Prompts user for a secret (password or passphrase) on console without echoing characters.
fn prompt_secret(prompt: &str) -> Result<String> {
    use std::io::BufRead;
    eprint!("{prompt}");
    let _ = std::io::stderr().flush();

    #[cfg(windows)]
    {
        use windows_sys::Win32::System::Console::{
            ENABLE_ECHO_INPUT, GetConsoleMode, GetStdHandle, STD_INPUT_HANDLE, SetConsoleMode,
        };
        unsafe {
            let handle = GetStdHandle(STD_INPUT_HANDLE);
            let mut mode = 0;
            if !handle.is_null() && handle as isize != -1 && GetConsoleMode(handle, &mut mode) != 0
            {
                let prev_mode = mode;
                let _ = SetConsoleMode(handle, mode & !ENABLE_ECHO_INPUT);
                let mut line = String::new();
                let stdin = std::io::stdin();
                let _ = stdin.lock().read_line(&mut line);
                let _ = SetConsoleMode(handle, prev_mode);
                eprintln!();
                return Ok(line.trim_end_matches(['\r', '\n']).to_string());
            }
        }
    }

    let mut line = String::new();
    let stdin = std::io::stdin();
    let _ = stdin.lock().read_line(&mut line);
    eprintln!();
    Ok(line.trim_end_matches(['\r', '\n']).to_string())
}

/// Authenticates a connected SSH session in CLI mode.
pub async fn authenticate_cli_session(
    session: &mut client::Handle<CliSshHandler>,
    profile: &SessionProfile,
    batch_mode: bool,
) -> Result<String> {
    let mut username = profile.username.trim().to_string();
    if username.is_empty() {
        if batch_mode {
            bail!("Batch mode requires an explicit username (-l / --user or user@host)");
        }
        if std::io::stdin().is_terminal() {
            username = prompt_secret(&format!("Username for {}: ", profile.host))?;
        } else {
            bail!(
                "No username provided for {} in non-interactive environment",
                profile.host
            );
        }
    }

    // 1. Try Windows Pageant & OpenSSH Agent
    #[cfg(windows)]
    {
        let should_try_agent = profile.try_pageant
            || matches!(
                profile.ssh_auth,
                SshAuthMethod::Agent {
                    use_pageant: true,
                    ..
                }
            );
        if should_try_agent
            && let Ok(mut agent) = russh::keys::agent::client::AgentClient::connect_pageant().await
            && let Ok(identities) = agent.request_identities().await
        {
            let rsa_hash = session
                .best_supported_rsa_hash()
                .await
                .ok()
                .flatten()
                .flatten();
            for id in identities {
                let pubkey: PublicKey = id.public_key().into_owned();
                let candidates = if pubkey.algorithm().is_rsa() {
                    rsa_hash_candidates(rsa_hash)
                } else {
                    vec![None]
                };
                for hash_alg in candidates {
                    if let Ok(res) = session
                        .authenticate_publickey_with(
                            &username,
                            pubkey.clone(),
                            hash_alg,
                            &mut agent,
                        )
                        .await
                        && res.success()
                    {
                        return Ok("Pageant".to_string());
                    }
                }
            }
        }

        let should_try_openssh = profile.try_pageant
            || matches!(
                profile.ssh_auth,
                SshAuthMethod::Agent {
                    use_openssh_agent: true,
                    ..
                }
            );
        if should_try_openssh
            && let Ok(mut agent) = russh::keys::agent::client::AgentClient::connect_named_pipe(
                r"\\.\pipe\openssh-ssh-agent",
            )
            .await
            && let Ok(identities) = agent.request_identities().await
        {
            let rsa_hash = session
                .best_supported_rsa_hash()
                .await
                .ok()
                .flatten()
                .flatten();
            for id in identities {
                let pubkey: PublicKey = id.public_key().into_owned();
                let candidates = if pubkey.algorithm().is_rsa() {
                    rsa_hash_candidates(rsa_hash)
                } else {
                    vec![None]
                };
                for hash_alg in candidates {
                    if let Ok(res) = session
                        .authenticate_publickey_with(
                            &username,
                            pubkey.clone(),
                            hash_alg,
                            &mut agent,
                        )
                        .await
                        && res.success()
                    {
                        return Ok("OpenSSH Agent".to_string());
                    }
                }
            }
        }
    }

    // 2. Private Key File authentication
    if let SshAuthMethod::PrivateKeyFile {
        ref key_path,
        ref passphrase,
        ref cert_path,
    } = profile.ssh_auth
        && !key_path.trim().is_empty()
    {
        let path = PathBuf::from(key_path.trim());
        let inspection = inspect_key_file(&path)?;

        let mut pass = passphrase.clone();
        if inspection.is_encrypted && pass.is_empty() {
            if batch_mode {
                bail!(
                    "Batch mode: private key '{}' is passphrase-protected and no passphrase was provided",
                    path.display()
                );
            }
            if std::io::stdin().is_terminal() {
                pass = prompt_secret(&format!(
                    "Enter passphrase for key {} ({}): ",
                    path.display(),
                    inspection.format_name
                ))?;
            } else {
                bail!(
                    "Private key '{}' requires a passphrase but standard input is not a terminal",
                    path.display()
                );
            }
        }

        let priv_key = load_private_key_any(&path, Some(&pass))
            .with_context(|| format!("Failed to load private key '{}'", path.display()))?;

        let rsa_hash = session
            .best_supported_rsa_hash()
            .await
            .ok()
            .flatten()
            .flatten();
        let priv_key_arc = Arc::new(priv_key);

        let mut key_accepted = false;
        if !cert_path.trim().is_empty() {
            let cert = russh::keys::load_openssh_certificate(cert_path.trim())?;
            let res = session
                .authenticate_openssh_cert(&username, Arc::clone(&priv_key_arc), cert)
                .await?;
            key_accepted = res.success();
        } else {
            let candidates = if priv_key_arc.algorithm().is_rsa() {
                rsa_hash_candidates(rsa_hash)
            } else {
                vec![None]
            };
            for hash_alg in candidates {
                let res = session
                    .authenticate_publickey(
                        &username,
                        PrivateKeyWithHashAlg::new(Arc::clone(&priv_key_arc), hash_alg),
                    )
                    .await?;
                if res.success() {
                    key_accepted = true;
                    break;
                }
            }
        }

        if key_accepted {
            return Ok(format!("Key [{}]", inspection.fingerprint_sha256));
        }
    }

    // 3. Password / Keyboard-Interactive authentication
    if !profile.password.is_empty() {
        let res = session
            .authenticate_password(&username, &profile.password)
            .await?;
        if res.success() {
            return Ok("Password".to_string());
        }
        // If password was rejected, try keyboard-interactive with the same password
        if let client::AuthResult::Failure {
            remaining_methods, ..
        } = res
            && remaining_methods.contains(&russh::MethodKind::KeyboardInteractive)
        {
            let mut cur = session
                .authenticate_keyboard_interactive_start(&username, None)
                .await?;
            let mut replied = false;
            loop {
                match cur {
                    client::KeyboardInteractiveAuthResponse::Success => {
                        return Ok("Keyboard-Interactive".to_string());
                    }
                    client::KeyboardInteractiveAuthResponse::Failure { .. } => break,
                    client::KeyboardInteractiveAuthResponse::InfoRequest { prompts, .. } => {
                        if !replied {
                            replied = true;
                            let answers = vec![profile.password.clone(); prompts.len()];
                            cur = session
                                .authenticate_keyboard_interactive_respond(answers)
                                .await?;
                        } else {
                            break;
                        }
                    }
                }
            }
        }
    }

    // 4. Interactive password prompt fallback if not batch mode
    if !batch_mode && std::io::stdin().is_terminal() {
        let prompt_pass = prompt_secret(&format!("Password for {}@{}: ", username, profile.host))?;
        let res = session
            .authenticate_password(&username, &prompt_pass)
            .await?;
        if res.success() {
            return Ok("Password".to_string());
        }
    }

    bail!(
        "Authentication failed for user '{}' on host '{}:{}'. Check your key, passphrase, or password.",
        username,
        profile.host,
        profile.port
    )
}

/// Connects and authenticates to the SSH target (with optional Bastion ProxyJump).
pub async fn connect_ssh(
    profile: &SessionProfile,
    jump_profile: Option<&SessionProfile>,
    batch_mode: bool,
) -> Result<(
    client::Handle<CliSshHandler>,
    Option<client::Handle<CliSshHandler>>,
)> {
    let (parsed_user, clean_host) = split_user_and_host(&profile.host, &profile.username);
    let mut target_profile = profile.clone();
    target_profile.username = parsed_user;
    target_profile.host = clean_host;

    let ssh_config = Arc::new(client::Config {
        inactivity_timeout: Some(Duration::from_secs(60)),
        ..Default::default()
    });

    let effective_jump = jump_profile
        .cloned()
        .or_else(|| parse_inline_proxy_jump(&target_profile.proxy_jump));

    let target_server_fp = Arc::new(Mutex::new(None));
    let target_handler = CliSshHandler {
        host: target_profile.host.trim().to_string(),
        port: target_profile.port,
        batch_mode,
        server_fingerprint: Arc::clone(&target_server_fp),
    };

    if let Some(mut bastion) = effective_jump {
        let (b_user, b_host) = split_user_and_host(&bastion.host, &bastion.username);
        bastion.username = b_user;
        bastion.host = b_host;

        let bastion_fp = Arc::new(Mutex::new(None));
        let bastion_handler = CliSshHandler {
            host: bastion.host.trim().to_string(),
            port: bastion.port,
            batch_mode,
            server_fingerprint: bastion_fp,
        };

        let mut bastion_session = client::connect(
            Arc::clone(&ssh_config),
            (&bastion.host[..], bastion.port),
            bastion_handler,
        )
        .await
        .with_context(|| {
            format!(
                "Failed to connect to bastion '{}:{}'",
                bastion.host, bastion.port
            )
        })?;

        authenticate_cli_session(&mut bastion_session, &bastion, batch_mode)
            .await
            .with_context(|| format!("Authentication failed on bastion '{}'", bastion.host))?;

        let jump_ch = bastion_session
            .channel_open_direct_tcpip(
                target_profile.host.trim(),
                target_profile.port as u32,
                "127.0.0.1",
                0,
            )
            .await
            .with_context(|| {
                format!(
                    "Bastion '{}' failed to open direct-tcpip channel to '{}:{}'",
                    bastion.host, target_profile.host, target_profile.port
                )
            })?;

        let mut target_session = client::connect_stream(
            Arc::clone(&ssh_config),
            jump_ch.into_stream(),
            target_handler,
        )
        .await
        .with_context(|| {
            format!(
                "Failed SSH handshake with target '{}:{}' via bastion",
                target_profile.host, target_profile.port
            )
        })?;

        authenticate_cli_session(&mut target_session, &target_profile, batch_mode)
            .await
            .with_context(|| {
                format!(
                    "Authentication failed on target '{}:{}'",
                    target_profile.host, target_profile.port
                )
            })?;

        Ok((target_session, Some(bastion_session)))
    } else {
        let mut target_session = client::connect(
            Arc::clone(&ssh_config),
            (&target_profile.host[..], target_profile.port),
            target_handler,
        )
        .await
        .with_context(|| {
            format!(
                "Failed to connect to SSH server at '{}:{}'",
                target_profile.host, target_profile.port
            )
        })?;

        authenticate_cli_session(&mut target_session, &target_profile, batch_mode)
            .await
            .with_context(|| {
                format!(
                    "Authentication failed on '{}:{}'",
                    target_profile.host, target_profile.port
                )
            })?;

        Ok((target_session, None))
    }
}

/// Executes a remote command and streams stdout/stderr live to local console/pipes.
pub async fn run_cli_exec(
    session: &mut client::Handle<CliSshHandler>,
    command: &str,
    force_pty: bool,
) -> Result<i32> {
    let mut channel = session.channel_open_session().await?;
    if force_pty {
        channel
            .request_pty(true, "xterm-256color", 80, 24, 0, 0, &[])
            .await?;
    }
    channel.exec(true, command).await?;

    let mut exit_code: Option<i32> = None;
    let is_stdin_pipe = !std::io::stdin().is_terminal();

    if is_stdin_pipe {
        let mut stdin = tokio::io::stdin();
        let mut in_buf = [0u8; 8192];
        let mut stdin_eof = false;

        loop {
            tokio::select! {
                read_res = stdin.read(&mut in_buf), if !stdin_eof => {
                    match read_res {
                        Ok(0) => {
                            stdin_eof = true;
                            let _ = channel.eof().await;
                        }
                        Ok(n) => {
                            if channel.data(&in_buf[..n]).await.is_err() {
                                stdin_eof = true;
                            }
                        }
                        Err(_) => {
                            stdin_eof = true;
                            let _ = channel.eof().await;
                        }
                    }
                }
                msg_opt = channel.wait() => {
                    match msg_opt {
                        Some(ChannelMsg::Data { data }) => {
                            let mut out = std::io::stdout().lock();
                            let _ = out.write_all(&data);
                            let _ = out.flush();
                        }
                        Some(ChannelMsg::ExtendedData { data, .. }) => {
                            let mut err = std::io::stderr().lock();
                            let _ = err.write_all(&data);
                            let _ = err.flush();
                        }
                        Some(ChannelMsg::ExitStatus { exit_status }) => {
                            exit_code = Some(exit_status as i32);
                        }
                        Some(ChannelMsg::Eof) | Some(ChannelMsg::Close) => {
                            break;
                        }
                        None => {
                            break;
                        }
                        _ => {}
                    }
                }
            }
        }
    } else {
        while let Some(msg) = channel.wait().await {
            match msg {
                ChannelMsg::Data { data } => {
                    let mut out = std::io::stdout().lock();
                    let _ = out.write_all(&data);
                    let _ = out.flush();
                }
                ChannelMsg::ExtendedData { data, .. } => {
                    let mut err = std::io::stderr().lock();
                    let _ = err.write_all(&data);
                    let _ = err.flush();
                }
                ChannelMsg::ExitStatus { exit_status } => {
                    exit_code = Some(exit_status as i32);
                }
                ChannelMsg::Eof | ChannelMsg::Close => {
                    break;
                }
                _ => {}
            }
        }
    }

    Ok(exit_code.unwrap_or(0))
}

fn format_bytes(bytes: u64) -> String {
    const KB: u64 = 1024;
    const MB: u64 = 1024 * KB;
    const GB: u64 = 1024 * MB;

    if bytes >= GB {
        format!("{:.2} GB", bytes as f64 / GB as f64)
    } else if bytes >= MB {
        format!("{:.2} MB", bytes as f64 / MB as f64)
    } else if bytes >= KB {
        format!("{:.1} KB", bytes as f64 / KB as f64)
    } else {
        format!("{} B", bytes)
    }
}

/// Uploads a single file via SFTP with optional terminal progress.
async fn sftp_put_file(
    sftp: &SftpSession,
    local_path: &Path,
    remote_path: &str,
    show_progress: bool,
) -> Result<()> {
    let mut local_file = tokio::fs::File::open(local_path)
        .await
        .with_context(|| format!("Failed to open local file '{}'", local_path.display()))?;
    let total = local_file.metadata().await?.len();

    let mut remote_file = sftp
        .open_with_flags(
            remote_path,
            OpenFlags::CREATE | OpenFlags::TRUNCATE | OpenFlags::WRITE,
        )
        .await
        .with_context(|| format!("Failed to open remote file '{}' for writing", remote_path))?;

    let filename = local_path
        .file_name()
        .map(|s| s.to_string_lossy().to_string())
        .unwrap_or_else(|| remote_path.to_string());

    let mut buf = vec![0u8; 64 * 1024];
    let mut transferred: u64 = 0;
    let start_time = std::time::Instant::now();

    loop {
        let n = local_file.read(&mut buf).await?;
        if n == 0 {
            break;
        }
        remote_file.write_all(&buf[..n]).await?;
        transferred += n as u64;

        if show_progress && total > 0 {
            let pct = (transferred * 100) / total;
            eprint!(
                "\r[SFTP] Uploading {}: {:>3}% ({}/{})   ",
                filename,
                pct,
                format_bytes(transferred),
                format_bytes(total)
            );
            let _ = std::io::stderr().flush();
        }
    }

    remote_file.flush().await?;
    remote_file.shutdown().await?;

    if show_progress {
        let elapsed = start_time.elapsed().as_secs_f32().max(0.01);
        eprintln!(
            "\r[SFTP] Uploaded {} ({}) in {:.2}s                 ",
            filename,
            format_bytes(total),
            elapsed
        );
    }

    Ok(())
}

/// Downloads a single file via SFTP with optional terminal progress.
async fn sftp_get_file(
    sftp: &SftpSession,
    remote_path: &str,
    local_path: &Path,
    show_progress: bool,
) -> Result<()> {
    let total = sftp
        .metadata(remote_path)
        .await
        .ok()
        .and_then(|m| m.size)
        .unwrap_or(0);

    let mut remote_file = sftp
        .open(remote_path)
        .await
        .with_context(|| format!("Failed to open remote file '{}' for reading", remote_path))?;

    let mut local_file = tokio::fs::File::create(local_path)
        .await
        .with_context(|| format!("Failed to create local file '{}'", local_path.display()))?;

    let filename = local_path
        .file_name()
        .map(|s| s.to_string_lossy().to_string())
        .unwrap_or_else(|| remote_path.to_string());

    let mut buf = vec![0u8; 64 * 1024];
    let mut transferred: u64 = 0;
    let start_time = std::time::Instant::now();

    loop {
        let n = remote_file.read(&mut buf).await?;
        if n == 0 {
            break;
        }
        local_file.write_all(&buf[..n]).await?;
        transferred += n as u64;

        if show_progress && total > 0 {
            let pct = (transferred * 100) / total;
            eprint!(
                "\r[SFTP] Downloading {}: {:>3}% ({}/{})   ",
                filename,
                pct,
                format_bytes(transferred),
                format_bytes(total)
            );
            let _ = std::io::stderr().flush();
        }
    }

    local_file.flush().await?;

    if show_progress {
        let elapsed = start_time.elapsed().as_secs_f32().max(0.01);
        eprintln!(
            "\r[SFTP] Downloaded {} ({}) in {:.2}s                 ",
            filename,
            format_bytes(total),
            elapsed
        );
    }

    Ok(())
}

/// SFTP Put entrypoint (supports single file or recursive directory upload).
pub async fn run_cli_sftp_put(
    session: &mut client::Handle<CliSshHandler>,
    local_path: &Path,
    remote_path: &str,
    recursive: bool,
) -> Result<i32> {
    let sftp_ch = session.channel_open_session().await?;
    sftp_ch.request_subsystem(true, "sftp").await?;
    let sftp = SftpSession::new(sftp_ch.into_stream()).await?;

    let show_progress = std::io::stderr().is_terminal();
    let local_meta = tokio::fs::metadata(local_path)
        .await
        .with_context(|| format!("Local path '{}' not found", local_path.display()))?;

    if local_meta.is_dir() {
        if !recursive {
            bail!(
                "'{}' is a directory. Use -r / --recursive to upload directories.",
                local_path.display()
            );
        }

        let base_remote = remote_path.trim_end_matches('/');
        let _ = sftp.create_dir(base_remote).await;

        let mut dirs = vec![(local_path.to_path_buf(), base_remote.to_string())];
        while let Some((cur_local_dir, cur_remote_dir)) = dirs.pop() {
            let mut read_dir = tokio::fs::read_dir(&cur_local_dir).await?;
            while let Some(entry) = read_dir.next_entry().await? {
                let entry_path = entry.path();
                let file_name = entry.file_name().to_string_lossy().to_string();
                let sub_remote = format!("{}/{}", cur_remote_dir, file_name);

                let entry_meta = entry.metadata().await?;
                if entry_meta.is_dir() {
                    let _ = sftp.create_dir(&sub_remote).await;
                    dirs.push((entry_path, sub_remote));
                } else {
                    sftp_put_file(&sftp, &entry_path, &sub_remote, show_progress).await?;
                }
            }
        }
    } else {
        // Single file upload
        let mut final_remote = remote_path.to_string();
        if final_remote.ends_with('/')
            || sftp
                .metadata(&final_remote)
                .await
                .map(|m| m.is_dir())
                .unwrap_or(false)
        {
            let fname = local_path
                .file_name()
                .map(|s| s.to_string_lossy().to_string())
                .unwrap_or_else(|| "uploaded_file".to_string());
            final_remote = format!("{}/{}", final_remote.trim_end_matches('/'), fname);
        }
        sftp_put_file(&sftp, local_path, &final_remote, show_progress).await?;
    }

    Ok(0)
}

/// SFTP Get entrypoint (supports single file or recursive directory download).
pub async fn run_cli_sftp_get(
    session: &mut client::Handle<CliSshHandler>,
    remote_path: &str,
    local_path: &Path,
    recursive: bool,
) -> Result<i32> {
    let sftp_ch = session.channel_open_session().await?;
    sftp_ch.request_subsystem(true, "sftp").await?;
    let sftp = SftpSession::new(sftp_ch.into_stream()).await?;

    let show_progress = std::io::stderr().is_terminal();
    let remote_meta = sftp
        .metadata(remote_path)
        .await
        .with_context(|| format!("Remote path '{}' not found on SFTP server", remote_path))?;

    if remote_meta.is_dir() {
        if !recursive {
            bail!(
                "Remote path '{}' is a directory. Use -r / --recursive to download directories.",
                remote_path
            );
        }

        tokio::fs::create_dir_all(local_path).await?;
        let mut queue = vec![(
            remote_path.trim_end_matches('/').to_string(),
            local_path.to_path_buf(),
        )];

        while let Some((cur_remote, cur_local)) = queue.pop() {
            let entries = sftp.read_dir(&cur_remote).await?;
            for entry in entries {
                let fname = entry.file_name();
                if fname == "." || fname == ".." {
                    continue;
                }
                let sub_remote = format!("{}/{}", cur_remote, fname);
                let sub_local = cur_local.join(fname);

                if entry.metadata().is_dir() {
                    tokio::fs::create_dir_all(&sub_local).await?;
                    queue.push((sub_remote, sub_local));
                } else {
                    sftp_get_file(&sftp, &sub_remote, &sub_local, show_progress).await?;
                }
            }
        }
    } else {
        // Single file download
        let mut final_local = local_path.to_path_buf();
        if local_path.is_dir()
            || local_path.to_string_lossy().ends_with('/')
            || local_path.to_string_lossy().ends_with('\\')
        {
            let fname = remote_path.rsplit('/').next().unwrap_or("downloaded_file");
            final_local = local_path.join(fname);
        }
        if let Some(parent) = final_local.parent() {
            tokio::fs::create_dir_all(parent).await?;
        }
        sftp_get_file(&sftp, remote_path, &final_local, show_progress).await?;
    }

    Ok(0)
}

/// Runs a local port forwarding tunnel.
pub async fn run_cli_tunnel(
    session: client::Handle<CliSshHandler>,
    bind_addr: &str,
    bind_port: u16,
    target_host: &str,
    target_port: u16,
) -> Result<i32> {
    let bind_spec = format!("{}:{}", bind_addr, bind_port);
    let listener = tokio::net::TcpListener::bind(&bind_spec)
        .await
        .with_context(|| format!("Failed to bind local tunnel port on {}", bind_spec))?;

    eprintln!(
        "cuty-ssh: Tunnel listening on {} -> forwarding to {}:{}",
        bind_spec, target_host, target_port
    );
    eprintln!("cuty-ssh: Forwarding active. Press Ctrl+C to terminate.");

    let session = Arc::new(session);

    loop {
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {
                eprintln!("\ncuty-ssh: Received Ctrl+C. Shutting down tunnel.");
                break;
            }
            res = listener.accept() => {
                match res {
                    Ok((mut client_stream, peer_addr)) => {
                        let sess = Arc::clone(&session);
                        let th = target_host.to_string();
                        tokio::spawn(async move {
                            if let Ok(ch) = sess
                                .channel_open_direct_tcpip(
                                    th,
                                    target_port as u32,
                                    peer_addr.ip().to_string(),
                                    peer_addr.port() as u32,
                                )
                                .await
                            {
                                let mut ch_stream = ch.into_stream();
                                let _ = tokio::io::copy_bidirectional(&mut client_stream, &mut ch_stream).await;
                            }
                        });
                    }
                    Err(e) => {
                        eprintln!("cuty-ssh: Tunnel accept error: {e}");
                        break;
                    }
                }
            }
        }
    }

    Ok(0)
}

/// Main dispatcher for CLI automation tasks.
/// Enforces `--timeout` and returns the process exit code (OpenSSH conventions: 255 on error).
pub async fn run_cli(invocation: CliInvocation) -> i32 {
    let timeout_duration = invocation.timeout_secs.map(Duration::from_secs);
    let batch = invocation.batch;

    let runner = async move {
        let (mut session, _bastion_guard) =
            match connect_ssh(&invocation.profile, invocation.jump_profile.as_ref(), batch).await {
                Ok(sess) => sess,
                Err(e) => {
                    eprintln!("cuty-ssh: SSH error: {:#}", e);
                    return 255;
                }
            };

        match invocation.action {
            CliAction::Exec { command, force_pty } => {
                match run_cli_exec(&mut session, &command, force_pty).await {
                    Ok(code) => code,
                    Err(e) => {
                        eprintln!("cuty-ssh: Command execution error: {:#}", e);
                        255
                    }
                }
            }
            CliAction::SftpPut {
                local_path,
                remote_path,
                recursive,
            } => match run_cli_sftp_put(&mut session, &local_path, &remote_path, recursive).await {
                Ok(code) => code,
                Err(e) => {
                    eprintln!("cuty-ssh: SFTP upload error: {:#}", e);
                    1
                }
            },
            CliAction::SftpGet {
                remote_path,
                local_path,
                recursive,
            } => match run_cli_sftp_get(&mut session, &remote_path, &local_path, recursive).await {
                Ok(code) => code,
                Err(e) => {
                    eprintln!("cuty-ssh: SFTP download error: {:#}", e);
                    1
                }
            },
            CliAction::Tunnel {
                bind_addr,
                bind_port,
                target_host,
                target_port,
            } => {
                match run_cli_tunnel(session, &bind_addr, bind_port, &target_host, target_port)
                    .await
                {
                    Ok(code) => code,
                    Err(e) => {
                        eprintln!("cuty-ssh: Tunnel error: {:#}", e);
                        1
                    }
                }
            }
        }
    };

    if let Some(dur) = timeout_duration {
        match tokio::time::timeout(dur, runner).await {
            Ok(code) => code,
            Err(_) => {
                eprintln!(
                    "cuty-ssh: Operation timed out after {} seconds",
                    dur.as_secs()
                );
                255
            }
        }
    } else {
        runner.await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_tunnel_spec_valid() {
        let (bind, lp, rh, rp) = parse_tunnel_spec("8080:localhost:80").unwrap();
        assert_eq!(bind, "127.0.0.1");
        assert_eq!(lp, 8080);
        assert_eq!(rh, "localhost");
        assert_eq!(rp, 80);

        let (bind, lp, rh, rp) = parse_tunnel_spec("0.0.0.0:3000:internal.db:5432").unwrap();
        assert_eq!(bind, "0.0.0.0");
        assert_eq!(lp, 3000);
        assert_eq!(rh, "internal.db");
        assert_eq!(rp, 5432);
    }

    #[test]
    fn test_parse_tunnel_spec_invalid() {
        assert!(parse_tunnel_spec("invalid").is_err());
        assert!(parse_tunnel_spec("8080:localhost").is_err());
        assert!(parse_tunnel_spec("not_a_port:localhost:80").is_err());
    }

    #[test]
    fn test_parse_cli_invocation_returns_none_for_normal_gui_usage() {
        let config = AppConfig::default();
        let args = vec![
            "cuty-ssh.exe".to_string(),
            "-load".to_string(),
            "mysession".to_string(),
        ];
        let res = parse_cli_invocation(&args, &config).unwrap();
        assert!(
            res.is_none(),
            "Normal GUI args must return None to start GUI unchanged"
        );

        let args2 = vec![
            "cuty-ssh.exe".to_string(),
            "-ssh".to_string(),
            "root@example.com".to_string(),
        ];
        let res2 = parse_cli_invocation(&args2, &config).unwrap();
        assert!(res2.is_none());
    }

    #[test]
    fn test_parse_cli_invocation_exec() {
        let config = AppConfig::default();
        let args = vec![
            "cuty-ssh.exe".to_string(),
            "-ssh".to_string(),
            "root@192.168.1.100:2222".to_string(),
            "--exec".to_string(),
            "uptime && free -m".to_string(),
        ];
        let inv = parse_cli_invocation(&args, &config)
            .unwrap()
            .expect("Should be Some invocation");
        assert_eq!(inv.profile.host, "192.168.1.100");
        assert_eq!(inv.profile.port, 2222);
        assert_eq!(inv.profile.username, "root");
        assert_eq!(
            inv.action,
            CliAction::Exec {
                command: "uptime && free -m".to_string(),
                force_pty: false,
            }
        );
    }

    #[test]
    fn test_parse_cli_invocation_trailing_dash_dash() {
        let config = AppConfig::default();
        let args = vec![
            "cuty-ssh.exe".to_string(),
            "-ssh".to_string(),
            "admin@bastion.corp".to_string(),
            "--".to_string(),
            "hostname".to_string(),
            "-I".to_string(),
        ];
        let inv = parse_cli_invocation(&args, &config)
            .unwrap()
            .expect("Should be Some invocation");
        assert_eq!(
            inv.action,
            CliAction::Exec {
                command: "hostname -I".to_string(),
                force_pty: false,
            }
        );
    }

    #[test]
    fn test_parse_cli_invocation_sftp_and_batch() {
        let config = AppConfig::default();
        let args = vec![
            "cuty-ssh.exe".to_string(),
            "--batch".to_string(),
            "--timeout".to_string(),
            "10".to_string(),
            "--sftp-put".to_string(),
            "local.txt".to_string(),
            "/tmp/dest.txt".to_string(),
            "-ssh".to_string(),
            "root@myserver".to_string(),
        ];
        let inv = parse_cli_invocation(&args, &config)
            .unwrap()
            .expect("Should be Some invocation");
        assert!(inv.batch);
        assert_eq!(inv.timeout_secs, Some(10));
        assert_eq!(
            inv.action,
            CliAction::SftpPut {
                local_path: PathBuf::from("local.txt"),
                remote_path: "/tmp/dest.txt".to_string(),
                recursive: false,
            }
        );
    }

    #[test]
    fn test_parse_cli_invocation_script_file_m() {
        let temp_dir = std::env::temp_dir();
        let script_file = temp_dir.join("test_script_cmd.sh");
        std::fs::write(&script_file, "echo 'hello from script'").unwrap();

        let config = AppConfig::default();
        let args = vec![
            "cuty-ssh.exe".to_string(),
            "-ssh".to_string(),
            "root@myserver".to_string(),
            "-m".to_string(),
            script_file.to_string_lossy().to_string(),
        ];
        let inv = parse_cli_invocation(&args, &config)
            .unwrap()
            .expect("Should be Some invocation");
        assert_eq!(
            inv.action,
            CliAction::Exec {
                command: "echo 'hello from script'".to_string(),
                force_pty: false,
            }
        );
        let _ = std::fs::remove_file(script_file);
    }

    fn find_cuty_ssh_exe() -> PathBuf {
        if let Ok(exe) = std::env::var("CARGO_BIN_EXE_cuty-ssh") {
            return PathBuf::from(exe);
        }
        if let Ok(cur) = std::env::current_exe()
            && let Some(dir) = cur.parent()
        {
            let candidate = dir.join("cuty-ssh.exe");
            if candidate.exists() {
                return candidate;
            }
            if let Some(parent) = dir.parent() {
                let candidate_dbg = parent.join("cuty-ssh.exe");
                if candidate_dbg.exists() {
                    return candidate_dbg;
                }
            }
        }
        let fallback = PathBuf::from("target/debug/cuty-ssh.exe");
        if fallback.exists() {
            return fallback;
        }
        PathBuf::from("cuty-ssh.exe")
    }

    #[test]
    fn test_cli_binary_help() {
        let bin = find_cuty_ssh_exe();
        if !bin.exists() {
            return;
        }
        let output = std::process::Command::new(bin)
            .arg("--help")
            .output()
            .expect("Failed to run cuty-ssh --help");
        assert!(output.status.success());
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(stdout.contains("--exec"));
        assert!(stdout.contains("--batch"));
        assert!(stdout.contains("--timeout"));
        assert!(stdout.contains("--sftp-put"));
        assert!(stdout.contains("--sftp-get"));
        assert!(stdout.contains("--tunnel"));
    }

    #[test]
    fn test_cli_binary_batch_without_command_errors() {
        let bin = find_cuty_ssh_exe();
        if !bin.exists() {
            return;
        }
        let output = std::process::Command::new(bin)
            .args(["--batch", "-ssh", "root@dummy"])
            .output()
            .expect("Failed to run cuty-ssh");
        assert_eq!(output.status.code(), Some(255));
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(stderr.contains("Batch mode requires a command"));
    }

    #[test]
    fn test_cli_binary_batch_unknown_host_fails_with_255() {
        let bin = find_cuty_ssh_exe();
        if !bin.exists() {
            return;
        }
        let output = std::process::Command::new(bin)
            .args([
                "--batch",
                "-ssh",
                "root@unknown-host-12345.invalid",
                "--exec",
                "ls",
            ])
            .output()
            .expect("Failed to run cuty-ssh");
        assert_eq!(output.status.code(), Some(255));
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(stderr.contains("SSH error") || stderr.contains("Failed to connect"));
    }

    #[test]
    fn test_cli_binary_batch_timeout_fails_with_255() {
        let bin = find_cuty_ssh_exe();
        if !bin.exists() {
            return;
        }
        let output = std::process::Command::new(bin)
            .args([
                "--batch",
                "--timeout",
                "1",
                "-ssh",
                "root@10.255.255.1",
                "--exec",
                "ls",
            ])
            .output()
            .expect("Failed to run cuty-ssh");
        assert_eq!(output.status.code(), Some(255));
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(stderr.contains("timed out") || stderr.contains("SSH error"));
    }
}
