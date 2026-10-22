use crate::config::{
    HostKeyCheckResult, PortForwardType, ProtocolType, SessionProfile, SshAuthMethod,
    split_user_and_host, verify_or_record_known_host,
};
use crate::ssh::ppk::{build_ssh_copy_id_script, inspect_key_file, load_private_key_any};
use anyhow::{Context, Result};
use portable_pty::{CommandBuilder, NativePtySystem, PtySize, PtySystem};
use russh::keys::ssh_key::{HashAlg, PublicKey};
use russh::keys::{PrivateKeyWithHashAlg, PublicKeyBase64, PublicKeyOrCertificate};
use russh::{ChannelMsg, Disconnect, client};
use russh_sftp::client::SftpSession;
use russh_sftp::protocol::OpenFlags;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncSeekExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc::{UnboundedReceiver, UnboundedSender, unbounded_channel};
use uuid::Uuid;

#[derive(Debug, Clone)]
pub struct SftpFileEntry {
    pub name: String,
    pub full_path: String,
    pub is_dir: bool,
    pub is_symlink: bool,
    pub size: u64,
    pub permissions: u32,
    pub mtime: u32,
}

#[derive(Debug, Clone, Default)]
pub struct RemoteServerMetrics {
    pub hostname: String,
    pub kernel: String,
    pub uptime: String,
    pub load_avg: String,
    pub cpu_load_1m: f32,
    pub mem_used_mb: u64,
    pub mem_total_mb: u64,
    pub disk_used_pct: f32,
    pub disk_summary: String,
}

#[derive(Debug, Clone)]
pub struct HostProbeResult {
    pub session_id: Option<Uuid>,
    pub label: String,
    pub host: String,
    pub port: u16,
    pub reachable: bool,
    pub latency_ms: u64,
    pub banner: String,
}

#[derive(Debug, Clone)]
pub struct CidrCalculation {
    pub input_ip: String,
    pub prefix: u8,
    pub netmask: String,
    pub wildcard: String,
    pub network_address: String,
    pub broadcast_address: String,
    pub first_usable: String,
    pub last_usable: String,
    pub usable_hosts: u64,
}

pub mod cli;
mod mirror;

/// Disconnect reason emitted when the user asked for the disconnection (never auto-reconnected).
pub const USER_DISCONNECT_REASON: &str = "Déconnecté par l'utilisateur";

#[derive(Debug)]
pub enum BackendCommand {
    SendInput(Vec<u8>),
    Resize {
        cols: u16,
        rows: u16,
    },
    ProvideSecret(String),
    RunLocalScript(PathBuf),
    DeployPublicKey {
        openssh_public_key: String,
        private_key_path: String,
        key_comment: String,
    },
    RefreshTelemetry,
    /// Starts (or stops, when already listening) a local SOCKS5 proxy over the session.
    ToggleSocks(u16),
    SftpListDir(String),
    SftpUpload {
        local_path: PathBuf,
        remote_path: String,
    },
    SftpDownload {
        remote_path: String,
        local_path: PathBuf,
    },
    SftpMkdir(String),
    /// `chmod`: `mode` holds the permission bits (e.g. `0o755`).
    SftpChmod {
        remote_path: String,
        mode: u32,
    },
    /// Creates `link_path` as a symbolic link pointing to `target`.
    SftpSymlink {
        target: String,
        link_path: String,
    },
    /// Computes the SHA-256 of a remote file by streaming it over SFTP.
    SftpSha256(String),
    /// One-way directory mirror (`upload`: local -> remote, otherwise remote -> local).
    SftpMirror {
        local_dir: PathBuf,
        remote_dir: String,
        upload: bool,
        delete_extra: bool,
        dry_run: bool,
    },
    SftpDelete {
        remote_path: String,
        is_dir: bool,
    },
    SftpRename {
        old_path: String,
        new_path: String,
    },
    Disconnect,
}

#[derive(Debug, Clone)]
pub enum BackendEvent {
    Connected {
        banner_info: String,
        host_key_fingerprint: Option<String>,
        auth_used: String,
    },
    Output(Vec<u8>),
    StatusMessage(String),
    ErrorMessage(String),
    PromptSecret {
        title: String,
        prompt: String,
        is_passphrase: bool,
    },
    PublicKeyDeployed {
        private_key_path: String,
        key_comment: String,
        already_present: bool,
    },
    TelemetryUpdated(RemoteServerMetrics),
    /// Port of the active one-click SOCKS5 proxy, `None` when stopped.
    SocksState(Option<u16>),
    SftpDirListed {
        current_path: String,
        entries: Vec<SftpFileEntry>,
    },
    SftpProgress {
        filename: String,
        transferred: u64,
        total: u64,
        is_upload: bool,
        done: bool,
    },
    SftpStatus(String),
    SftpHashResult {
        remote_path: String,
        sha256: String,
        size: u64,
    },
    SftpMirrorReport {
        lines: Vec<String>,
        summary: String,
        dry_run: bool,
    },
    Disconnected(String),
}

pub struct SessionHandle {
    pub cmd_tx: UnboundedSender<BackendCommand>,
    pub evt_rx: UnboundedReceiver<BackendEvent>,
}

impl SessionHandle {
    pub fn spawn(
        rt: &tokio::runtime::Handle,
        profile: SessionProfile,
        jump_profile: Option<SessionProfile>,
        initial_cols: u16,
        initial_rows: u16,
    ) -> Self {
        let (cmd_tx, cmd_rx) = unbounded_channel();
        let (evt_tx, evt_rx) = unbounded_channel();

        match profile.protocol {
            ProtocolType::Ssh => {
                rt.spawn(async move {
                    if let Err(e) = run_ssh_session(
                        profile,
                        jump_profile,
                        initial_cols,
                        initial_rows,
                        cmd_rx,
                        evt_tx.clone(),
                    )
                    .await
                    {
                        let _ = evt_tx
                            .send(BackendEvent::ErrorMessage(format!("Erreur SSH : {:#}", e)));
                        let _ = evt_tx.send(BackendEvent::Disconnected(format!("Échec : {}", e)));
                    }
                });
            }
            ProtocolType::Telnet | ProtocolType::RawTcp => {
                let is_telnet = profile.protocol == ProtocolType::Telnet;
                rt.spawn(async move {
                    if let Err(e) = run_tcp_or_telnet_session(
                        profile,
                        is_telnet,
                        initial_cols,
                        initial_rows,
                        cmd_rx,
                        evt_tx.clone(),
                    )
                    .await
                    {
                        let _ = evt_tx.send(BackendEvent::ErrorMessage(format!(
                            "Erreur {} : {:#}",
                            if is_telnet { "Telnet" } else { "Raw TCP" },
                            e
                        )));
                        let _ = evt_tx.send(BackendEvent::Disconnected(format!("Échec : {}", e)));
                    }
                });
            }
            ProtocolType::LocalShell => {
                std::thread::spawn(move || {
                    if let Err(e) = run_local_pty_session(
                        profile,
                        initial_cols,
                        initial_rows,
                        cmd_rx,
                        evt_tx.clone(),
                    ) {
                        let _ = evt_tx.send(BackendEvent::ErrorMessage(format!(
                            "Erreur Shell Local : {:#}",
                            e
                        )));
                        let _ = evt_tx.send(BackendEvent::Disconnected(format!("Échec : {}", e)));
                    }
                });
            }
        }

        Self { cmd_tx, evt_rx }
    }
}

struct SshClientHandler {
    host: String,
    port: u16,
    server_fingerprint: Arc<Mutex<Option<String>>>,
    evt_tx: UnboundedSender<BackendEvent>,
}

impl client::Handler for SshClientHandler {
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

        let check_res = verify_or_record_known_host(&self.host, self.port, &alg, &fp_raw, &b64);
        match check_res {
            HostKeyCheckResult::TrustedMatch {
                fingerprint,
                algorithm,
            } => {
                let label = format!("🛡 TOFU Vérifié: {} ({})", fingerprint, algorithm);
                if let Ok(mut guard) = self.server_fingerprint.lock() {
                    *guard = Some(label);
                }
                Ok(true)
            }
            HostKeyCheckResult::NewlyTrusted {
                fingerprint,
                algorithm,
            } => {
                let label = format!("🆕 TOFU Enregistré: {} ({})", fingerprint, algorithm);
                if let Ok(mut guard) = self.server_fingerprint.lock() {
                    *guard = Some(label);
                }
                let _ = self.evt_tx.send(BackendEvent::StatusMessage(format!(
                    "🆕 Nouvelle clé d'hôte enregistrée dans known_hosts (TOFU) : {} ({})",
                    fingerprint, algorithm
                )));
                Ok(true)
            }
            HostKeyCheckResult::Mismatch {
                expected_fingerprint,
                actual_fingerprint,
                algorithm,
            } => {
                let _ = self.evt_tx.send(BackendEvent::ErrorMessage(format!(
                    "🚨 ALERTE SÉCURITÉ MITM — La clé SSH de {}:{} ({}) a changé ! Attendu : {} | Reçu : {}. Révoquez l'ancienne clé dans '🛡 Known Hosts' si le serveur a été réinstallé.",
                    self.host, self.port, algorithm, expected_fingerprint, actual_fingerprint
                )));
                Ok(false)
            }
        }
    }
}

async fn wait_for_secret_input(
    cmd_rx: &mut UnboundedReceiver<BackendCommand>,
    evt_tx: &UnboundedSender<BackendEvent>,
    title: &str,
    prompt: &str,
    is_passphrase: bool,
) -> Result<String> {
    let _ = evt_tx.send(BackendEvent::PromptSecret {
        title: title.to_string(),
        prompt: prompt.to_string(),
        is_passphrase,
    });
    while let Some(cmd) = cmd_rx.recv().await {
        match cmd {
            BackendCommand::ProvideSecret(secret) => return Ok(secret),
            BackendCommand::Disconnect => anyhow::bail!("Connexion annulée par l'utilisateur"),
            _ => {}
        }
    }
    anyhow::bail!("Canal fermé en attente de saisie")
}

pub(crate) fn rsa_hash_candidates(preferred: Option<HashAlg>) -> Vec<Option<HashAlg>> {
    let mut list = Vec::with_capacity(4);
    for candidate in [
        preferred,
        Some(HashAlg::Sha512),
        Some(HashAlg::Sha256),
        None,
    ] {
        if !list.contains(&candidate) {
            list.push(candidate);
        }
    }
    list
}

#[cfg(windows)]
async fn try_authenticate_with_pageant(
    session: &mut client::Handle<SshClientHandler>,
    username: &str,
    evt_tx: &UnboundedSender<BackendEvent>,
) -> Option<String> {
    if let Ok(mut agent) = russh::keys::agent::client::AgentClient::connect_pageant().await
        && let Ok(identities) = agent.request_identities().await
        && !identities.is_empty()
    {
        let _ = evt_tx.send(BackendEvent::StatusMessage(format!(
            "Pageant détecté ({} clé(s) chargée(s)) — tentative d'authentification...",
            identities.len()
        )));
        let rsa_hash = session
            .best_supported_rsa_hash()
            .await
            .ok()
            .flatten()
            .flatten();
        for id in identities {
            let pubkey: PublicKey = id.public_key().into_owned();
            let alg_is_rsa = pubkey.algorithm().is_rsa();
            let candidates = if alg_is_rsa {
                rsa_hash_candidates(rsa_hash)
            } else {
                vec![None]
            };
            let comment = id.comment().to_string();
            let fp = pubkey.fingerprint(HashAlg::Sha256).to_string();
            for hash_alg in candidates {
                if let Ok(res) = session
                    .authenticate_publickey_with(username, pubkey.clone(), hash_alg, &mut agent)
                    .await
                    && res.success()
                {
                    return Some(format!(
                        "Pageant (PuTTY Agent) — clé {} [{}]",
                        if comment.is_empty() {
                            "sans nom"
                        } else {
                            &comment
                        },
                        fp
                    ));
                }
            }
        }
    }
    None
}

#[cfg(windows)]
async fn try_authenticate_with_openssh_agent(
    session: &mut client::Handle<SshClientHandler>,
    username: &str,
    evt_tx: &UnboundedSender<BackendEvent>,
) -> Option<String> {
    if let Ok(mut agent) =
        russh::keys::agent::client::AgentClient::connect_named_pipe(r"\\.\pipe\openssh-ssh-agent")
            .await
        && let Ok(identities) = agent.request_identities().await
        && !identities.is_empty()
    {
        let _ = evt_tx.send(BackendEvent::StatusMessage(format!(
            "Agent OpenSSH Windows détecté ({} clé(s))...",
            identities.len()
        )));
        let rsa_hash = session
            .best_supported_rsa_hash()
            .await
            .ok()
            .flatten()
            .flatten();
        for id in identities {
            let pubkey: PublicKey = id.public_key().into_owned();
            let alg_is_rsa = pubkey.algorithm().is_rsa();
            let candidates = if alg_is_rsa {
                rsa_hash_candidates(rsa_hash)
            } else {
                vec![None]
            };
            let fp = pubkey.fingerprint(HashAlg::Sha256).to_string();
            for hash_alg in candidates {
                if let Ok(res) = session
                    .authenticate_publickey_with(username, pubkey.clone(), hash_alg, &mut agent)
                    .await
                    && res.success()
                {
                    return Some(format!("Agent OpenSSH Windows [{}]", fp));
                }
            }
        }
    }
    None
}

pub(crate) fn parse_inline_proxy_jump(spec: &str) -> Option<SessionProfile> {
    let trimmed = spec.trim();
    if trimmed.is_empty() {
        return None;
    }
    let (user_part, host_port_part) = split_user_and_host(
        trimmed,
        &std::env::var("USERNAME").unwrap_or_else(|_| "root".to_string()),
    );
    let (host, port) = if let Some((h, p_str)) = host_port_part.rsplit_once(':')
        && let Ok(p) = p_str.parse::<u16>()
    {
        (h.to_string(), p)
    } else {
        (host_port_part, 22)
    };
    if host.is_empty() {
        return None;
    }
    Some(SessionProfile {
        name: format!("Bastion ({host})"),
        host,
        port,
        username: user_part,
        protocol: ProtocolType::Ssh,
        try_pageant: true,
        ssh_auth: SshAuthMethod::Agent {
            use_pageant: true,
            use_openssh_agent: true,
        },
        ..Default::default()
    })
}

/// Whether a keyboard-interactive prompt asks for the account password (EN/FR/DE/ES).
fn is_password_prompt(prompt: &str) -> bool {
    let p = prompt.to_lowercase();
    ["password", "mot de passe", "passwort", "contraseña"]
        .iter()
        .any(|k| p.contains(k))
}

/// Runs a keyboard-interactive exchange (PAM, OTP, 2FA...). The stored password answers the
/// first password-looking prompt only; any other prompt is asked to the user, masked unless
/// the server allows echo. Returns whether the server accepted the authentication.
async fn run_keyboard_interactive(
    session: &mut client::Handle<SshClientHandler>,
    username: &str,
    stored_password: &str,
    cmd_rx: &mut UnboundedReceiver<BackendCommand>,
    evt_tx: &UnboundedSender<BackendEvent>,
) -> Result<bool> {
    let mut password_used = false;
    let mut cur = session
        .authenticate_keyboard_interactive_start(username, None)
        .await?;
    loop {
        match cur {
            client::KeyboardInteractiveAuthResponse::Success => return Ok(true),
            client::KeyboardInteractiveAuthResponse::Failure { .. } => return Ok(false),
            client::KeyboardInteractiveAuthResponse::InfoRequest {
                name,
                instructions,
                prompts,
            } => {
                let mut answers = Vec::with_capacity(prompts.len());
                for p in prompts {
                    let ans = if !password_used
                        && !stored_password.is_empty()
                        && is_password_prompt(&p.prompt)
                    {
                        password_used = true;
                        stored_password.to_string()
                    } else {
                        wait_for_secret_input(
                            cmd_rx,
                            evt_tx,
                            if name.is_empty() {
                                "Authentification Interactive"
                            } else {
                                &name
                            },
                            &format!("{}\n{}", instructions, p.prompt),
                            !p.echo,
                        )
                        .await?
                    };
                    answers.push(ans);
                }
                cur = session
                    .authenticate_keyboard_interactive_respond(answers)
                    .await?;
            }
        }
    }
}

async fn authenticate_ssh_handle(
    session: &mut client::Handle<SshClientHandler>,
    profile: &SessionProfile,
    cmd_rx: &mut UnboundedReceiver<BackendCommand>,
    evt_tx: &UnboundedSender<BackendEvent>,
) -> Result<(String, String)> {
    let mut username = profile.username.trim().to_string();
    if username.is_empty() {
        username = wait_for_secret_input(
            cmd_rx,
            evt_tx,
            "Identifiant SSH",
            &format!("Nom d'utilisateur pour {} :", profile.host),
            false,
        )
        .await?;
    }

    let mut authenticated_via: Option<String> = None;

    // 1. Try Pageant and/or Windows OpenSSH Agent automatically when enabled
    #[cfg(windows)]
    {
        let should_try_pageant = profile.try_pageant
            || matches!(
                profile.ssh_auth,
                SshAuthMethod::Agent {
                    use_pageant: true,
                    ..
                }
            );
        if should_try_pageant {
            authenticated_via = try_authenticate_with_pageant(session, &username, evt_tx).await;
        }

        let should_try_openssh_agent = profile.try_pageant
            || matches!(
                profile.ssh_auth,
                SshAuthMethod::Agent {
                    use_openssh_agent: true,
                    ..
                }
            );
        if authenticated_via.is_none() && should_try_openssh_agent {
            authenticated_via =
                try_authenticate_with_openssh_agent(session, &username, evt_tx).await;
        }
    }

    // 2. Authenticate with the configured method if Agent/Pageant has not authenticated yet
    if authenticated_via.is_none() {
        match &profile.ssh_auth {
            SshAuthMethod::PrivateKeyFile {
                key_path,
                passphrase,
                cert_path,
            } => {
                if !key_path.trim().is_empty() {
                    let path = PathBuf::from(key_path.trim());
                    let inspection = inspect_key_file(&path)?;
                    let _ = evt_tx.send(BackendEvent::StatusMessage(format!(
                        "Chargement de la clé {} ({})...",
                        inspection.format_name, inspection.algorithm
                    )));

                    let mut pass = passphrase.clone();
                    if inspection.is_encrypted && pass.is_empty() {
                        pass = wait_for_secret_input(
                            cmd_rx,
                            evt_tx,
                            "Passphrase de clé PuTTY (.ppk) / SSH",
                            &format!(
                                "Entrez la passphrase pour déverrouiller la clé\n{} ({}) :",
                                path.display(),
                                inspection.format_name
                            ),
                            true,
                        )
                        .await?;
                    }

                    let priv_key = match load_private_key_any(&path, Some(&pass)) {
                        Ok(k) => k,
                        Err(_) => {
                            let retry_pass = wait_for_secret_input(
                                cmd_rx,
                                evt_tx,
                                "Passphrase requise ou erronée (.ppk / SSH)",
                                &format!("Passphrase pour {} :", path.display()),
                                true,
                            )
                            .await?;
                            load_private_key_any(&path, Some(&retry_pass))?
                        }
                    };

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
                        authenticated_via = Some(format!(
                            "{} [{}]",
                            inspection.format_name, inspection.fingerprint_sha256
                        ));
                    } else {
                        let _ = evt_tx.send(BackendEvent::StatusMessage(
                            "Clé refusée par le serveur, repli sur mot de passe...".to_string(),
                        ));
                    }
                }
            }
            SshAuthMethod::Agent { .. } => {}
            SshAuthMethod::KeyboardInteractive => {
                if let Ok(true) =
                    run_keyboard_interactive(session, &username, &profile.password, cmd_rx, evt_tx)
                        .await
                {
                    authenticated_via = Some("Keyboard-Interactive (PAM/2FA)".to_string());
                }
            }
            SshAuthMethod::Password => {}
        }
    }

    // 3. Password authentication (automatic password or interactive prompt)
    if authenticated_via.is_none() {
        let mut pwd = profile.password.clone();
        if pwd.is_empty() {
            pwd = wait_for_secret_input(
                cmd_rx,
                evt_tx,
                "Mot de passe SSH",
                &format!("Mot de passe pour {}@{} :", username, profile.host),
                true,
            )
            .await?;
        }
        let res = session.authenticate_password(&username, &pwd).await?;
        let kbdint_offered = matches!(
            &res,
            client::AuthResult::Failure { remaining_methods, .. }
                if remaining_methods.contains(&russh::MethodKind::KeyboardInteractive)
        );
        if res.success() {
            authenticated_via = Some(if !profile.password.is_empty() {
                "Mot de passe automatique".to_string()
            } else {
                "Mot de passe SSH".to_string()
            });
        } else if kbdint_offered
            && run_keyboard_interactive(session, &username, &pwd, cmd_rx, evt_tx).await?
        {
            // Many PAM servers refuse `password` but accept the same secret (and a 2FA code)
            // through keyboard-interactive.
            authenticated_via = Some("Keyboard-Interactive (PAM/2FA)".to_string());
        } else {
            let retry_pwd = wait_for_secret_input(
                cmd_rx,
                evt_tx,
                "Échec d'authentification — Réessayer",
                &format!("Mot de passe pour {}@{} :", username, profile.host),
                true,
            )
            .await?;
            let res2 = session.authenticate_password(&username, &retry_pwd).await?;
            if res2.success() {
                authenticated_via = Some("Mot de passe SSH".to_string());
            } else {
                anyhow::bail!(
                    "Authentification SSH refusée pour {}@{}",
                    username,
                    profile.host
                );
            }
        }
    }

    let auth_used = authenticated_via.unwrap_or_else(|| "SSH2".to_string());
    Ok((username, auth_used))
}

async fn run_ssh_session(
    mut profile: SessionProfile,
    jump_profile: Option<SessionProfile>,
    initial_cols: u16,
    initial_rows: u16,
    mut cmd_rx: UnboundedReceiver<BackendCommand>,
    evt_tx: UnboundedSender<BackendEvent>,
) -> Result<()> {
    let (parsed_user, clean_host) = split_user_and_host(&profile.host, &profile.username);
    profile.username = parsed_user;
    profile.host = clean_host;

    let ssh_config = Arc::new(client::Config {
        inactivity_timeout: if profile.keepalive_secs > 0 {
            Some(Duration::from_secs(
                (profile.keepalive_secs as u64 * 3).max(60),
            ))
        } else {
            None
        },
        keepalive_interval: if profile.keepalive_secs > 0 {
            Some(Duration::from_secs(profile.keepalive_secs as u64))
        } else {
            None
        },
        ..Default::default()
    });

    let effective_jump = jump_profile.or_else(|| parse_inline_proxy_jump(&profile.proxy_jump));
    let mut _bastion_guard: Option<client::Handle<SshClientHandler>> = None;

    let server_fp = Arc::new(Mutex::new(None));
    let handler = SshClientHandler {
        host: profile.host.trim().to_string(),
        port: profile.port,
        server_fingerprint: Arc::clone(&server_fp),
        evt_tx: evt_tx.clone(),
    };

    let mut session = if let Some(mut bastion) = effective_jump {
        let (b_user, b_host) = split_user_and_host(&bastion.host, &bastion.username);
        bastion.username = b_user;
        bastion.host = b_host;
        let _ = evt_tx.send(BackendEvent::StatusMessage(format!(
            "🔀 Connexion au Bastion ProxyJump {}:{} ({})...",
            bastion.host, bastion.port, bastion.name
        )));
        let bastion_fp = Arc::new(Mutex::new(None));
        let bastion_handler = SshClientHandler {
            host: bastion.host.trim().to_string(),
            port: bastion.port,
            server_fingerprint: bastion_fp,
            evt_tx: evt_tx.clone(),
        };
        let mut bastion_session = tokio::time::timeout(
            Duration::from_secs(15),
            client::connect(
                Arc::clone(&ssh_config),
                (&bastion.host[..], bastion.port),
                bastion_handler,
            ),
        )
        .await
        .context("Délai dépassé lors de la connexion au Bastion ProxyJump")?
        .context("Échec de connexion SSH au Bastion ProxyJump")?;

        let _ = authenticate_ssh_handle(&mut bastion_session, &bastion, &mut cmd_rx, &evt_tx)
            .await
            .with_context(|| format!("Échec d'authentification sur le Bastion {}", bastion.host))?;

        let _ = evt_tx.send(BackendEvent::StatusMessage(format!(
            "🔀 Tunnel Bastion établi -> ouverture canal direct-tcpip vers {}:{}...",
            profile.host, profile.port
        )));
        let jump_ch = bastion_session
            .channel_open_direct_tcpip(profile.host.trim(), profile.port as u32, "127.0.0.1", 0)
            .await
            .with_context(|| {
                format!(
                    "Le Bastion {} n'a pas pu joindre la cible {}:{}",
                    bastion.host, profile.host, profile.port
                )
            })?;

        let target_sess = tokio::time::timeout(
            Duration::from_secs(15),
            client::connect_stream(Arc::clone(&ssh_config), jump_ch.into_stream(), handler),
        )
        .await
        .context("Délai dépassé lors du handshake SSH à travers le Bastion")?
        .context("Échec de la session SSH à travers le Bastion")?;

        _bastion_guard = Some(bastion_session);
        target_sess
    } else {
        let addr = format!("{}:{}", profile.host.trim(), profile.port);
        let _ = evt_tx.send(BackendEvent::StatusMessage(format!(
            "Connexion SSH2 vers {}...",
            addr
        )));
        tokio::time::timeout(
            Duration::from_secs(15),
            client::connect(
                Arc::clone(&ssh_config),
                (&profile.host[..], profile.port),
                handler,
            ),
        )
        .await
        .context("Délai d'attente dépassé lors de la connexion TCP/SSH")?
        .context("Échec de l'établissement de la session SSH")?
    };

    let (username, auth_used) =
        authenticate_ssh_handle(&mut session, &profile, &mut cmd_rx, &evt_tx).await?;
    let fp = server_fp.lock().ok().and_then(|g| g.clone());

    // Start port forwarding rules (-L / -R)
    let session = Arc::new(session);
    let mut socks_tasks: Vec<tokio::task::JoinHandle<()>> = Vec::new();
    let mut quick_socks: Option<(u16, tokio::task::JoinHandle<()>)> = None;
    for rule in &profile.port_forwards {
        if !rule.enabled {
            continue;
        }
        match rule.forward_type {
            PortForwardType::Local => {
                let bind_addr = format!("{}:{}", rule.bind_address, rule.bind_port);
                let target_host = rule.target_host.clone();
                let target_port = rule.target_port as u32;
                let sess_clone = Arc::clone(&session);
                let evt_clone = evt_tx.clone();
                tokio::spawn(async move {
                    match TcpListener::bind(&bind_addr).await {
                        Ok(listener) => {
                            let _ = evt_clone.send(BackendEvent::StatusMessage(format!(
                                "Tunnel Local actif : {} -> {}:{}",
                                bind_addr, target_host, target_port
                            )));
                            while let Ok((mut local_stream, peer)) = listener.accept().await {
                                let sess_inner = Arc::clone(&sess_clone);
                                let th = target_host.clone();
                                tokio::spawn(async move {
                                    if let Ok(channel) = sess_inner
                                        .channel_open_direct_tcpip(
                                            th,
                                            target_port,
                                            peer.ip().to_string(),
                                            peer.port() as u32,
                                        )
                                        .await
                                    {
                                        let mut ch_stream = channel.into_stream();
                                        let _ = tokio::io::copy_bidirectional(
                                            &mut local_stream,
                                            &mut ch_stream,
                                        )
                                        .await;
                                    }
                                });
                            }
                        }
                        Err(e) => {
                            let _ = evt_clone.send(BackendEvent::ErrorMessage(format!(
                                "Échec tunnel local {} : {}",
                                bind_addr, e
                            )));
                        }
                    }
                });
            }
            PortForwardType::Dynamic => {
                let bind = format!("{}:{}", rule.bind_address, rule.bind_port);
                match start_socks_proxy(Arc::clone(&session), &bind).await {
                    Ok(task) => {
                        socks_tasks.push(task);
                        let _ = evt_tx.send(BackendEvent::StatusMessage(format!(
                            "SOCKS5 actif : {bind}"
                        )));
                    }
                    Err(e) => {
                        let _ = evt_tx.send(BackendEvent::ErrorMessage(format!(
                            "Échec SOCKS5 {bind} : {e}"
                        )));
                    }
                }
            }
            PortForwardType::Remote => {
                if let Err(e) = session
                    .tcpip_forward(&rule.bind_address, rule.bind_port as u32)
                    .await
                {
                    let _ = evt_tx.send(BackendEvent::ErrorMessage(format!(
                        "Échec tunnel distant {}:{} : {}",
                        rule.bind_address, rule.bind_port, e
                    )));
                }
            }
        }
    }

    // Open main PTY + Shell channel
    let mut channel = session.channel_open_session().await?;
    if profile.agent_forwarding {
        let _ = channel.agent_forward(false).await;
    }
    channel
        .request_pty(
            true,
            "xterm-256color",
            initial_cols as u32,
            initial_rows as u32,
            0,
            0,
            &[],
        )
        .await?;
    channel.request_shell(true).await?;

    let _ = evt_tx.send(BackendEvent::Connected {
        banner_info: format!("{}@{}:{}", username, profile.host, profile.port),
        host_key_fingerprint: fp,
        auth_used,
    });

    // Open dedicated background SFTP session for the integrated explorer
    let sftp_session: Arc<tokio::sync::Mutex<Option<SftpSession>>> =
        Arc::new(tokio::sync::Mutex::new(None));
    {
        let sess_sftp = Arc::clone(&session);
        let sftp_holder = Arc::clone(&sftp_session);
        let evt_sftp = evt_tx.clone();
        tokio::spawn(async move {
            if let Ok(sftp_ch) = sess_sftp.channel_open_session().await
                && sftp_ch.request_subsystem(true, "sftp").await.is_ok()
                && let Ok(sftp) = SftpSession::new(sftp_ch.into_stream()).await
            {
                let start_dir = sftp
                    .canonicalize(".")
                    .await
                    .unwrap_or_else(|_| "/".to_string());
                if let Ok(entries) = list_sftp_directory(&sftp, &start_dir).await {
                    let _ = evt_sftp.send(BackendEvent::SftpDirListed {
                        current_path: start_dir,
                        entries,
                    });
                }
                *sftp_holder.lock().await = Some(sftp);
            }
        });
    }

    // Collect initial remote Linux server telemetry in background
    {
        let sess_telem = Arc::clone(&session);
        let evt_telem = evt_tx.clone();
        tokio::spawn(async move {
            if let Some(metrics) = fetch_remote_telemetry(&sess_telem).await {
                let _ = evt_telem.send(BackendEvent::TelemetryUpdated(metrics));
            }
        });
    }

    // Automatic execution of startup command (if configured)
    if !profile.startup_command.trim().is_empty() {
        let cmd_line = format!("{}\n", profile.startup_command.trim());
        let _ = channel.data(cmd_line.as_bytes()).await;
    }

    // Automatic execution of local script on remote session (if configured at startup)
    if !profile.local_script_path.trim().is_empty() {
        let script_path = PathBuf::from(profile.local_script_path.trim());
        if let Ok(script_content) = std::fs::read_to_string(&script_path) {
            let normalized = script_content.replace("\r\n", "\n");
            let _ = channel.data(normalized.as_bytes()).await;
            if !normalized.ends_with('\n') {
                let _ = channel.data(&b"\n"[..]).await;
            }
        }
    }

    let mut expect_rules = profile.logon_expect_rules.clone();
    let mut recent_text_window = String::new();

    let anti_idle_interval = if profile.keepalive_secs > 0 && !profile.anti_idle_string.is_empty() {
        Some(Duration::from_secs(profile.keepalive_secs as u64))
    } else {
        None
    };
    let mut anti_idle_timer =
        tokio::time::interval(anti_idle_interval.unwrap_or(Duration::from_secs(3600)));
    anti_idle_timer.tick().await;

    loop {
        tokio::select! {
            msg_opt = channel.wait() => {
                match msg_opt {
                    Some(ChannelMsg::Data { data }) => {
                        let bytes = data.to_vec();
                        let _ = evt_tx.send(BackendEvent::Output(bytes.clone()));

                        // Evaluate Expect/Logon automation rules
                        if expect_rules.iter().any(|r| r.enabled) {
                            recent_text_window.push_str(&String::from_utf8_lossy(&bytes));
                            if recent_text_window.len() > 2048 {
                                let drain = recent_text_window.len() - 1024;
                                recent_text_window.drain(..drain);
                            }
                            for rule in &mut expect_rules {
                                if rule.enabled && !rule.trigger_prompt.is_empty() && recent_text_window.contains(&rule.trigger_prompt) {
                                    rule.enabled = false; // Execute once per connection
                                    let resp = format!("{}\n", rule.send_response);
                                    if rule.delay_ms > 0 {
                                        tokio::time::sleep(Duration::from_millis(rule.delay_ms)).await;
                                    }
                                    let _ = channel.data(resp.as_bytes()).await;
                                    recent_text_window.clear();
                                }
                            }
                        }
                    }
                    Some(ChannelMsg::ExtendedData { data, .. }) => {
                        let _ = evt_tx.send(BackendEvent::Output(data.to_vec()));
                    }
                    Some(ChannelMsg::ExitStatus { exit_status }) => {
                        let _ = evt_tx.send(BackendEvent::Disconnected(format!(
                            "Session terminée (code de sortie : {})",
                            exit_status
                        )));
                        break;
                    }
                    Some(ChannelMsg::Eof) | Some(ChannelMsg::Close) | None => {
                        let _ = evt_tx.send(BackendEvent::Disconnected(
                            "Connexion SSH fermée par l'hôte distant".to_string(),
                        ));
                        break;
                    }
                    _ => {}
                }
            }
            cmd_opt = cmd_rx.recv() => {
                match cmd_opt {
                    Some(BackendCommand::SendInput(bytes)) => {
                        channel.data(&bytes[..]).await?;
                    }
                    Some(BackendCommand::Resize { cols, rows }) => {
                        let _ = channel.window_change(cols as u32, rows as u32, 0, 0).await;
                    }
                    Some(BackendCommand::ToggleSocks(port)) => {
                        if let Some((p, task)) = quick_socks.take() {
                            task.abort();
                            let _ = evt_tx.send(BackendEvent::SocksState(None));
                            let _ = evt_tx.send(BackendEvent::StatusMessage(format!(
                                "SOCKS5 arrêté (127.0.0.1:{p})"
                            )));
                        } else {
                            let bind = format!("127.0.0.1:{port}");
                            match start_socks_proxy(Arc::clone(&session), &bind).await {
                                Ok(task) => {
                                    quick_socks = Some((port, task));
                                    let _ = evt_tx.send(BackendEvent::SocksState(Some(port)));
                                    let _ = evt_tx.send(BackendEvent::StatusMessage(format!(
                                        "SOCKS5 actif : {bind}"
                                    )));
                                }
                                Err(e) => {
                                    let _ = evt_tx.send(BackendEvent::ErrorMessage(format!(
                                        "Échec SOCKS5 {bind} : {e}"
                                    )));
                                }
                            }
                        }
                    }
                    Some(BackendCommand::RefreshTelemetry) => {
                        let sess_telem = Arc::clone(&session);
                        let evt_telem = evt_tx.clone();
                        tokio::spawn(async move {
                            if let Some(metrics) = fetch_remote_telemetry(&sess_telem).await {
                                let _ = evt_telem.send(BackendEvent::TelemetryUpdated(metrics));
                            }
                        });
                    }
                    Some(BackendCommand::RunLocalScript(path)) => {
                        match std::fs::read_to_string(&path) {
                            Ok(content) => {
                                let normalized = content.replace("\r\n", "\n");
                                channel.data(normalized.as_bytes()).await?;
                                if !normalized.ends_with('\n') {
                                    channel.data(&b"\n"[..]).await?;
                                }
                                let _ = evt_tx.send(BackendEvent::StatusMessage(format!(
                                    "Script local exécuté : {}",
                                    path.display()
                                )));
                            }
                            Err(e) => {
                                let _ = evt_tx.send(BackendEvent::ErrorMessage(format!(
                                    "Impossible de lire le script {:?} : {}",
                                    path, e
                                )));
                            }
                        }
                    }
                    Some(BackendCommand::DeployPublicKey {
                        openssh_public_key,
                        private_key_path,
                        key_comment,
                    }) => {
                        match build_ssh_copy_id_script(&openssh_public_key) {
                            Ok(script) => {
                                let mut exec_done = false;
                                if let Ok(mut exec_ch) = session.channel_open_session().await
                                    && exec_ch.exec(true, script.as_str()).await.is_ok()
                                {
                                    let mut out = Vec::new();
                                    let _ = tokio::time::timeout(Duration::from_secs(6), async {
                                        while let Some(msg) = exec_ch.wait().await {
                                            match msg {
                                                ChannelMsg::Data { data } => {
                                                    out.extend_from_slice(&data);
                                                }
                                                ChannelMsg::Eof | ChannelMsg::Close => break,
                                                _ => {}
                                            }
                                        }
                                    })
                                    .await;
                                    let out_str = String::from_utf8_lossy(&out);
                                    if out_str.contains("CUTY_SSH_KEY_INSTALLED_OK")
                                        || out_str.contains("CUTY_SSH_KEY_ALREADY_PRESENT")
                                    {
                                        exec_done = true;
                                        let already_present =
                                            out_str.contains("CUTY_SSH_KEY_ALREADY_PRESENT");
                                        let _ = evt_tx.send(BackendEvent::PublicKeyDeployed {
                                            private_key_path: private_key_path.clone(),
                                            key_comment: key_comment.clone(),
                                            already_present,
                                        });
                                    }
                                }
                                if !exec_done {
                                    let line = format!("{script}\n");
                                    channel.data(line.as_bytes()).await?;
                                    let _ = evt_tx.send(BackendEvent::PublicKeyDeployed {
                                        private_key_path,
                                        key_comment,
                                        already_present: false,
                                    });
                                }
                            }
                            Err(e) => {
                                let _ = evt_tx.send(BackendEvent::ErrorMessage(format!(
                                    "Erreur ssh-copy-id : {}",
                                    e
                                )));
                            }
                        }
                    }
                    Some(BackendCommand::SftpListDir(dir)) => {
                        let sftp_ref = Arc::clone(&sftp_session);
                        let evt_c = evt_tx.clone();
                        tokio::spawn(async move {
                            let guard = sftp_ref.lock().await;
                            if let Some(sftp) = guard.as_ref() {
                                let resolved = sftp.canonicalize(&dir).await.unwrap_or(dir);
                                match list_sftp_directory(sftp, &resolved).await {
                                    Ok(entries) => {
                                        let _ = evt_c.send(BackendEvent::SftpDirListed {
                                            current_path: resolved,
                                            entries,
                                        });
                                    }
                                    Err(e) => {
                                        let _ = evt_c.send(BackendEvent::SftpStatus(format!(
                                            "Erreur SFTP : {}",
                                            e
                                        )));
                                    }
                                }
                            } else {
                                let _ = evt_c.send(BackendEvent::SftpStatus(
                                    "Sous-système SFTP non disponible sur ce serveur".to_string(),
                                ));
                            }
                        });
                    }
                    Some(BackendCommand::SftpUpload { local_path, remote_path }) => {
                        let sftp_ref = Arc::clone(&sftp_session);
                        let evt_c = evt_tx.clone();
                        tokio::spawn(async move {
                            let guard = sftp_ref.lock().await;
                            if let Some(sftp) = guard.as_ref() {
                                match upload_sftp_file(sftp, &local_path, &remote_path, &evt_c).await {
                                    Ok(bytes_len) => {
                                        let _ = evt_c.send(BackendEvent::SftpStatus(format!(
                                            "Upload réussi : {} ({} octets)",
                                            remote_path, bytes_len
                                        )));
                                        if let Some((parent_dir, _)) = remote_path.rsplit_once('/') {
                                            let dir = if parent_dir.is_empty() { "/" } else { parent_dir };
                                            if let Ok(entries) = list_sftp_directory(sftp, dir).await {
                                                let _ = evt_c.send(BackendEvent::SftpDirListed {
                                                    current_path: dir.to_string(),
                                                    entries,
                                                });
                                            }
                                        }
                                    }
                                    Err(e) => {
                                        let _ = evt_c.send(BackendEvent::SftpStatus(format!(
                                            "Échec upload SFTP : {}",
                                            e
                                        )));
                                    }
                                }
                            }
                        });
                    }
                    Some(BackendCommand::SftpDownload { remote_path, local_path }) => {
                        let sftp_ref = Arc::clone(&sftp_session);
                        let evt_c = evt_tx.clone();
                        tokio::spawn(async move {
                            let guard = sftp_ref.lock().await;
                            if let Some(sftp) = guard.as_ref() {
                                match download_sftp_file(sftp, &remote_path, &local_path, &evt_c).await {
                                    Ok(bytes_len) => {
                                        let _ = evt_c.send(BackendEvent::SftpStatus(format!(
                                            "Téléchargé vers {} ({} octets)",
                                            local_path.display(),
                                            bytes_len
                                        )));
                                    }
                                    Err(e) => {
                                        let _ = evt_c.send(BackendEvent::SftpStatus(format!(
                                            "Échec téléchargement SFTP : {}",
                                            e
                                        )));
                                    }
                                }
                            }
                        });
                    }
                    Some(BackendCommand::SftpChmod { remote_path, mode }) => {
                        let sftp_ref = Arc::clone(&sftp_session);
                        let evt_c = evt_tx.clone();
                        tokio::spawn(async move {
                            let guard = sftp_ref.lock().await;
                            let Some(sftp) = guard.as_ref() else { return };
                            let attrs = russh_sftp::protocol::FileAttributes {
                                permissions: Some(mode & 0o7777),
                                ..Default::default()
                            };
                            match sftp.set_metadata(remote_path.clone(), attrs).await {
                                Ok(()) => {
                                    let _ = evt_c.send(BackendEvent::SftpStatus(format!(
                                        "chmod {:04o} {}",
                                        mode & 0o7777,
                                        remote_path
                                    )));
                                    refresh_parent_listing(sftp, &remote_path, &evt_c).await;
                                }
                                Err(e) => {
                                    let _ = evt_c.send(BackendEvent::SftpStatus(format!(
                                        "Erreur chmod : {e}"
                                    )));
                                }
                            }
                        });
                    }
                    Some(BackendCommand::SftpSymlink { target, link_path }) => {
                        let sftp_ref = Arc::clone(&sftp_session);
                        let evt_c = evt_tx.clone();
                        tokio::spawn(async move {
                            let guard = sftp_ref.lock().await;
                            let Some(sftp) = guard.as_ref() else { return };
                            // OpenSSH's sftp-server reads the first SSH_FXP_SYMLINK field as the
                            // link *target* (the RFC draft names it the other way round).
                            match sftp.symlink(target.clone(), link_path.clone()).await {
                                Ok(()) => {
                                    let _ = evt_c.send(BackendEvent::SftpStatus(format!(
                                        "Lien créé : {link_path} -> {target}"
                                    )));
                                    refresh_parent_listing(sftp, &link_path, &evt_c).await;
                                }
                                Err(e) => {
                                    let _ = evt_c.send(BackendEvent::SftpStatus(format!(
                                        "Erreur lien symbolique : {e}"
                                    )));
                                }
                            }
                        });
                    }
                    Some(BackendCommand::SftpSha256(remote_path)) => {
                        let sftp_ref = Arc::clone(&sftp_session);
                        let evt_c = evt_tx.clone();
                        tokio::spawn(async move {
                            let guard = sftp_ref.lock().await;
                            let Some(sftp) = guard.as_ref() else { return };
                            match sha256_remote_file(sftp, &remote_path).await {
                                Ok((sha256, size)) => {
                                    let _ = evt_c.send(BackendEvent::SftpHashResult {
                                        remote_path,
                                        sha256,
                                        size,
                                    });
                                }
                                Err(e) => {
                                    let _ = evt_c.send(BackendEvent::SftpStatus(format!(
                                        "Erreur SHA-256 : {e}"
                                    )));
                                }
                            }
                        });
                    }
                    Some(BackendCommand::SftpMirror {
                        local_dir,
                        remote_dir,
                        upload,
                        delete_extra,
                        dry_run,
                    }) => {
                        let sftp_ref = Arc::clone(&sftp_session);
                        let evt_c = evt_tx.clone();
                        tokio::spawn(async move {
                            let guard = sftp_ref.lock().await;
                            let Some(sftp) = guard.as_ref() else { return };
                            match mirror::run_mirror(
                                sftp,
                                &local_dir,
                                &remote_dir,
                                upload,
                                delete_extra,
                                dry_run,
                                &evt_c,
                            )
                            .await
                            {
                                Ok(sum) => {
                                    let summary = if dry_run {
                                        format!("{} action(s) prévue(s)", sum.lines.len())
                                    } else {
                                        format!(
                                            "{} copié(s), {} supprimé(s), {} erreur(s)",
                                            sum.copied, sum.deleted, sum.errors
                                        )
                                    };
                                    let _ = evt_c.send(BackendEvent::SftpMirrorReport {
                                        lines: sum.lines,
                                        summary,
                                        dry_run,
                                    });
                                    if !dry_run {
                                        refresh_dir_listing(sftp, &remote_dir, &evt_c).await;
                                    }
                                }
                                Err(e) => {
                                    let _ = evt_c.send(BackendEvent::SftpMirrorReport {
                                        lines: Vec::new(),
                                        summary: format!("Erreur miroir : {e:#}"),
                                        dry_run,
                                    });
                                }
                            }
                        });
                    }
                    Some(BackendCommand::SftpMkdir(remote_dir)) => {
                        let sftp_ref = Arc::clone(&sftp_session);
                        let evt_c = evt_tx.clone();
                        tokio::spawn(async move {
                            let guard = sftp_ref.lock().await;
                            if let Some(sftp) = guard.as_ref() {
                                match sftp.create_dir(&remote_dir).await {
                                    Ok(_) => {
                                        let _ = evt_c.send(BackendEvent::SftpStatus(format!(
                                            "Dossier créé : {}",
                                            remote_dir
                                        )));
                                    }
                                    Err(e) => {
                                        let _ = evt_c.send(BackendEvent::SftpStatus(format!(
                                            "Erreur création dossier : {}",
                                            e
                                        )));
                                    }
                                }
                            }
                        });
                    }
                    Some(BackendCommand::SftpRename { old_path, new_path }) => {
                        let sftp_ref = Arc::clone(&sftp_session);
                        let evt_c = evt_tx.clone();
                        tokio::spawn(async move {
                            let guard = sftp_ref.lock().await;
                            if let Some(sftp) = guard.as_ref() {
                                match sftp.rename(&old_path, &new_path).await {
                                    Ok(_) => {
                                        let _ = evt_c.send(BackendEvent::SftpStatus(format!(
                                            "Renommé : {} -> {}",
                                            old_path, new_path
                                        )));
                                    }
                                    Err(e) => {
                                        let _ = evt_c.send(BackendEvent::SftpStatus(format!(
                                            "Erreur renommage : {}",
                                            e
                                        )));
                                    }
                                }
                            }
                        });
                    }
                    Some(BackendCommand::SftpDelete { remote_path, is_dir }) => {
                        let sftp_ref = Arc::clone(&sftp_session);
                        let evt_c = evt_tx.clone();
                        tokio::spawn(async move {
                            let guard = sftp_ref.lock().await;
                            if let Some(sftp) = guard.as_ref() {
                                let res = if is_dir {
                                    sftp.remove_dir(&remote_path).await
                                } else {
                                    sftp.remove_file(&remote_path).await
                                };
                                match res {
                                    Ok(_) => {
                                        let _ = evt_c.send(BackendEvent::SftpStatus(format!(
                                            "Supprimé : {}",
                                            remote_path
                                        )));
                                    }
                                    Err(e) => {
                                        let _ = evt_c.send(BackendEvent::SftpStatus(format!(
                                            "Erreur suppression : {}",
                                            e
                                        )));
                                    }
                                }
                            }
                        });
                    }
                    Some(BackendCommand::Disconnect) | None => {
                        let _ = channel.eof().await;
                        let _ = session
                            .disconnect(Disconnect::ByApplication, "Closed by user", "fr")
                            .await;
                        let _ = evt_tx
                            .send(BackendEvent::Disconnected(USER_DISCONNECT_REASON.to_string()));
                        break;
                    }
                    _ => {}
                }
            }
            _ = anti_idle_timer.tick(), if anti_idle_interval.is_some() => {
                if !profile.anti_idle_string.is_empty() {
                    let _ = channel.data(profile.anti_idle_string.as_bytes()).await;
                }
            }
        }
    }

    Ok(())
}

/// Minimal SOCKS5 server side (RFC 1928): no authentication, CONNECT only.
/// Returns the requested destination `(host, port)` after answering the greeting.
async fn socks5_negotiate<S>(s: &mut S) -> Result<(String, u16)>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut head = [0u8; 2];
    s.read_exact(&mut head).await?;
    anyhow::ensure!(head[0] == 5, "not a SOCKS5 client");
    let mut methods = vec![0u8; head[1] as usize];
    s.read_exact(&mut methods).await?;
    if !methods.contains(&0) {
        s.write_all(&[5, 0xFF]).await?;
        anyhow::bail!("no acceptable SOCKS5 auth method");
    }
    s.write_all(&[5, 0]).await?;

    let mut req = [0u8; 4];
    s.read_exact(&mut req).await?;
    anyhow::ensure!(req[0] == 5, "bad SOCKS5 request");
    if req[1] != 1 {
        s.write_all(&[5, 7, 0, 1, 0, 0, 0, 0, 0, 0]).await?;
        anyhow::bail!("unsupported SOCKS5 command {}", req[1]);
    }
    let host = match req[3] {
        1 => {
            let mut a = [0u8; 4];
            s.read_exact(&mut a).await?;
            std::net::Ipv4Addr::from(a).to_string()
        }
        3 => {
            let mut len = [0u8; 1];
            s.read_exact(&mut len).await?;
            let mut name = vec![0u8; len[0] as usize];
            s.read_exact(&mut name).await?;
            String::from_utf8(name).context("invalid SOCKS5 host name")?
        }
        4 => {
            let mut a = [0u8; 16];
            s.read_exact(&mut a).await?;
            std::net::Ipv6Addr::from(a).to_string()
        }
        other => {
            s.write_all(&[5, 8, 0, 1, 0, 0, 0, 0, 0, 0]).await?;
            anyhow::bail!("unsupported SOCKS5 address type {other}");
        }
    };
    let mut port = [0u8; 2];
    s.read_exact(&mut port).await?;
    Ok((host, u16::from_be_bytes(port)))
}

/// Parses an HTTP `CONNECT host:port` request head. Only CONNECT is supported.
fn parse_http_connect(head: &str) -> Option<(String, u16)> {
    let line = head.lines().next()?;
    let mut parts = line.split_whitespace();
    if !parts.next()?.eq_ignore_ascii_case("CONNECT") {
        return None;
    }
    let authority = parts.next()?;
    let (host, port) = authority.rsplit_once(':')?;
    let host = host.trim_start_matches('[').trim_end_matches(']');
    if host.is_empty() {
        return None;
    }
    Some((host.to_string(), port.parse().ok()?))
}

/// Reads an HTTP proxy request head (up to the blank line, 8 KiB max) and returns the
/// requested `CONNECT` destination. Other methods get a `405` and an error.
async fn http_connect_negotiate<S>(s: &mut S) -> Result<(String, u16)>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut head = Vec::with_capacity(256);
    let mut byte = [0u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        anyhow::ensure!(head.len() < 8192, "HTTP proxy request too large");
        s.read_exact(&mut byte).await?;
        head.push(byte[0]);
    }
    match parse_http_connect(&String::from_utf8_lossy(&head)) {
        Some(dest) => Ok(dest),
        None => {
            s.write_all(b"HTTP/1.1 405 Method Not Allowed\r\nAllow: CONNECT\r\n\r\n")
                .await?;
            anyhow::bail!("only HTTP CONNECT is supported");
        }
    }
}

/// Binds `bind` and serves SOCKS5 and HTTP CONNECT clients (detected from the first byte)
/// through SSH `direct-tcpip` channels.
async fn start_socks_proxy(
    session: Arc<client::Handle<SshClientHandler>>,
    bind: &str,
) -> Result<tokio::task::JoinHandle<()>> {
    let listener = TcpListener::bind(bind).await?;
    Ok(tokio::spawn(async move {
        while let Ok((mut local, peer)) = listener.accept().await {
            let session = Arc::clone(&session);
            tokio::spawn(async move {
                let mut first = [0u8; 1];
                if local.peek(&mut first).await.unwrap_or(0) == 0 {
                    return;
                }
                let http = first[0] != 5;
                let negotiated = if http {
                    http_connect_negotiate(&mut local).await
                } else {
                    socks5_negotiate(&mut local).await
                };
                let Ok((host, port)) = negotiated else {
                    return;
                };
                match session
                    .channel_open_direct_tcpip(
                        host,
                        port as u32,
                        peer.ip().to_string(),
                        peer.port() as u32,
                    )
                    .await
                {
                    Ok(channel) => {
                        let ok_reply: &[u8] = if http {
                            b"HTTP/1.1 200 Connection Established\r\n\r\n"
                        } else {
                            &[5, 0, 0, 1, 0, 0, 0, 0, 0, 0]
                        };
                        if local.write_all(ok_reply).await.is_ok() {
                            let mut stream = channel.into_stream();
                            let _ = tokio::io::copy_bidirectional(&mut local, &mut stream).await;
                        }
                    }
                    Err(_) => {
                        let fail_reply: &[u8] = if http {
                            b"HTTP/1.1 502 Bad Gateway\r\n\r\n"
                        } else {
                            &[5, 5, 0, 1, 0, 0, 0, 0, 0, 0]
                        };
                        let _ = local.write_all(fail_reply).await;
                    }
                }
            });
        }
    }))
}

async fn list_sftp_directory(sftp: &SftpSession, dir: &str) -> Result<Vec<SftpFileEntry>> {
    let read_dir = sftp.read_dir(dir).await?;
    let mut list = Vec::new();
    for entry in read_dir {
        let meta = entry.metadata();
        let ft = entry.file_type();
        list.push(SftpFileEntry {
            name: entry.file_name(),
            full_path: entry.path(),
            is_dir: ft.is_dir(),
            is_symlink: ft.is_symlink(),
            size: meta.size.unwrap_or(0),
            permissions: meta.permissions.unwrap_or(0),
            mtime: meta.mtime.unwrap_or(0),
        });
    }
    list.sort_by(|a, b| b.is_dir.cmp(&a.is_dir).then_with(|| a.name.cmp(&b.name)));
    Ok(list)
}

/// Suffix of the in-progress file of an SFTP transfer (resumable).
const PART_SUFFIX: &str = ".cutypart";

/// Offset to resume a transfer from: the partial size if it is strictly inside the file.
fn resume_offset(existing: u64, total: u64) -> u64 {
    if existing > 0 && existing < total {
        existing
    } else {
        0
    }
}

/// Streams a remote file through SHA-256. Returns `(hex digest, size)`.
async fn sha256_remote_file(sftp: &SftpSession, remote_path: &str) -> Result<(String, u64)> {
    use sha2::{Digest, Sha256};
    let mut file = sftp.open(remote_path).await?;
    let mut hasher = Sha256::new();
    let mut buf = vec![0u8; 64 * 1024];
    let mut size = 0u64;
    loop {
        let n = file.read(&mut buf).await?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
        size += n as u64;
    }
    Ok((hex::encode(hasher.finalize()), size))
}

/// Re-lists `dir` and publishes it to the UI (errors ignored: purely a refresh).
async fn refresh_dir_listing(
    sftp: &SftpSession,
    dir: &str,
    evt_tx: &UnboundedSender<BackendEvent>,
) {
    if let Ok(entries) = list_sftp_directory(sftp, dir).await {
        let _ = evt_tx.send(BackendEvent::SftpDirListed {
            current_path: dir.to_string(),
            entries,
        });
    }
}

/// Re-lists the folder containing `path`.
async fn refresh_parent_listing(
    sftp: &SftpSession,
    path: &str,
    evt_tx: &UnboundedSender<BackendEvent>,
) {
    if let Some((parent, _)) = path.rsplit_once('/') {
        let dir = if parent.is_empty() { "/" } else { parent };
        refresh_dir_listing(sftp, dir, evt_tx).await;
    }
}

async fn upload_sftp_file(
    sftp: &SftpSession,
    local_path: &Path,
    remote_path: &str,
    evt_tx: &UnboundedSender<BackendEvent>,
) -> Result<u64> {
    let filename = local_path
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_else(|| remote_path.to_string());
    let meta = tokio::fs::metadata(local_path).await?;
    let total = meta.len();
    let mut local_file = tokio::fs::File::open(local_path).await?;

    // Data goes to `<name>.cutypart` and is renamed once complete, so an interrupted
    // transfer can resume from the bytes already on the server.
    let part_path = format!("{remote_path}{PART_SUFFIX}");
    let existing = sftp
        .metadata(&part_path)
        .await
        .ok()
        .and_then(|m| m.size)
        .unwrap_or(0);
    let resume_from = resume_offset(existing, total);
    let mut remote_file = if resume_from > 0 {
        let mut f = sftp.open_with_flags(&part_path, OpenFlags::WRITE).await?;
        f.seek(std::io::SeekFrom::Start(resume_from)).await?;
        local_file
            .seek(std::io::SeekFrom::Start(resume_from))
            .await?;
        f
    } else {
        sftp.open_with_flags(
            &part_path,
            OpenFlags::CREATE | OpenFlags::TRUNCATE | OpenFlags::WRITE,
        )
        .await?
    };

    let mut buf = vec![0u8; 64 * 1024];
    let mut transferred: u64 = resume_from;
    let _ = evt_tx.send(BackendEvent::SftpProgress {
        filename: filename.clone(),
        transferred,
        total,
        is_upload: true,
        done: false,
    });

    loop {
        let n = local_file.read(&mut buf).await?;
        if n == 0 {
            break;
        }
        remote_file.write_all(&buf[..n]).await?;
        transferred += n as u64;
        let _ = evt_tx.send(BackendEvent::SftpProgress {
            filename: filename.clone(),
            transferred,
            total,
            is_upload: true,
            done: false,
        });
    }
    remote_file.flush().await?;
    remote_file.shutdown().await?;
    drop(remote_file);
    if sftp.metadata(remote_path).await.is_ok() {
        let _ = sftp.remove_file(remote_path).await;
    }
    sftp.rename(&part_path, remote_path).await?;
    let _ = evt_tx.send(BackendEvent::SftpProgress {
        filename,
        transferred,
        total,
        is_upload: true,
        done: true,
    });
    Ok(transferred)
}

async fn download_sftp_file(
    sftp: &SftpSession,
    remote_path: &str,
    local_path: &Path,
    evt_tx: &UnboundedSender<BackendEvent>,
) -> Result<u64> {
    let filename = local_path
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_else(|| remote_path.to_string());
    let total = sftp
        .metadata(remote_path)
        .await
        .ok()
        .and_then(|m| m.size)
        .unwrap_or(0);
    let mut remote_file = sftp.open(remote_path).await?;

    // Same scheme as uploads: write to `<name>.cutypart`, resume it if a previous try was cut.
    let mut part_name = local_path.as_os_str().to_owned();
    part_name.push(PART_SUFFIX);
    let part_path = PathBuf::from(part_name);
    let existing = tokio::fs::metadata(&part_path)
        .await
        .map(|m| m.len())
        .unwrap_or(0);
    let resume_from = resume_offset(existing, total);
    let mut local_file = if resume_from > 0 {
        remote_file
            .seek(std::io::SeekFrom::Start(resume_from))
            .await?;
        tokio::fs::OpenOptions::new()
            .append(true)
            .open(&part_path)
            .await?
    } else {
        tokio::fs::File::create(&part_path).await?
    };

    let mut buf = vec![0u8; 64 * 1024];
    let mut transferred: u64 = resume_from;
    let _ = evt_tx.send(BackendEvent::SftpProgress {
        filename: filename.clone(),
        transferred,
        total,
        is_upload: false,
        done: false,
    });

    loop {
        let n = remote_file.read(&mut buf).await?;
        if n == 0 {
            break;
        }
        local_file.write_all(&buf[..n]).await?;
        transferred += n as u64;
        let _ = evt_tx.send(BackendEvent::SftpProgress {
            filename: filename.clone(),
            transferred,
            total: total.max(transferred),
            is_upload: false,
            done: false,
        });
    }
    local_file.flush().await?;
    drop(local_file);
    if tokio::fs::metadata(local_path).await.is_ok() {
        let _ = tokio::fs::remove_file(local_path).await;
    }
    tokio::fs::rename(&part_path, local_path).await?;
    let _ = evt_tx.send(BackendEvent::SftpProgress {
        filename,
        transferred,
        total: total.max(transferred),
        is_upload: false,
        done: true,
    });
    Ok(transferred)
}

/// Telnet connection (RFC 854 IAC, NAWS, TTYPE, SGA + Auto-login) and Raw TCP
async fn run_tcp_or_telnet_session(
    mut profile: SessionProfile,
    is_telnet: bool,
    initial_cols: u16,
    initial_rows: u16,
    mut cmd_rx: UnboundedReceiver<BackendCommand>,
    evt_tx: UnboundedSender<BackendEvent>,
) -> Result<()> {
    let (parsed_user, clean_host) = split_user_and_host(&profile.host, &profile.username);
    profile.username = parsed_user;
    profile.host = clean_host;

    let addr = format!("{}:{}", profile.host.trim(), profile.port);
    let _ = evt_tx.send(BackendEvent::StatusMessage(format!(
        "Connexion {} vers {}...",
        if is_telnet { "Telnet" } else { "Raw TCP" },
        addr
    )));

    let mut stream = tokio::time::timeout(Duration::from_secs(10), TcpStream::connect(&addr))
        .await
        .context("Délai dépassé lors de la connexion TCP")?
        .context("Impossible de se connecter à l'hôte")?;

    let _ = evt_tx.send(BackendEvent::Connected {
        banner_info: addr.clone(),
        host_key_fingerprint: None,
        auth_used: if is_telnet {
            "Telnet RFC 854".to_string()
        } else {
            "Raw TCP".to_string()
        },
    });

    if !profile.startup_command.trim().is_empty() && !is_telnet {
        let cmd = format!("{}\r\n", profile.startup_command.trim());
        let _ = stream.write_all(cmd.as_bytes()).await;
    }

    let mut buf = [0u8; 4096];
    let mut cur_cols = initial_cols;
    let mut cur_rows = initial_rows;
    let mut auto_user_sent = false;
    let mut auto_pass_sent = false;
    let mut recent_text = String::new();

    loop {
        tokio::select! {
            read_res = stream.read(&mut buf) => {
                match read_res {
                    Ok(0) => {
                        let _ = evt_tx.send(BackendEvent::Disconnected("Connexion TCP fermée par l'hôte".to_string()));
                        break;
                    }
                    Ok(n) => {
                        let chunk = &buf[..n];
                        let display_bytes = if is_telnet {
                            process_telnet_iac(chunk, &mut stream, cur_cols, cur_rows).await?
                        } else {
                            chunk.to_vec()
                        };

                        if !display_bytes.is_empty() {
                            let _ = evt_tx.send(BackendEvent::Output(display_bytes.clone()));

                            // Telnet connection automation (auto-login & auto-password)
                            recent_text.push_str(&String::from_utf8_lossy(&display_bytes));
                            if recent_text.len() > 1024 {
                                let drain = recent_text.len() - 512;
                                recent_text.drain(..drain);
                            }
                            let lower = recent_text.to_lowercase();
                            if profile.auto_login && !auto_user_sent && !profile.username.is_empty()
                                && (lower.contains("login:") || lower.contains("username:"))
                            {
                                auto_user_sent = true;
                                let u = format!("{}\r\n", profile.username);
                                let _ = stream.write_all(u.as_bytes()).await;
                                recent_text.clear();
                            } else if profile.auto_password && !auto_pass_sent && !profile.password.is_empty()
                                && lower.contains("password:")
                            {
                                auto_pass_sent = true;
                                let p = format!("{}\r\n", profile.password);
                                let _ = stream.write_all(p.as_bytes()).await;
                                recent_text.clear();
                            }
                        }
                    }
                    Err(e) => {
                        let _ = evt_tx.send(BackendEvent::Disconnected(format!("Erreur lecture TCP : {}", e)));
                        break;
                    }
                }
            }
            cmd_opt = cmd_rx.recv() => {
                match cmd_opt {
                    Some(BackendCommand::SendInput(bytes)) => {
                        stream.write_all(&bytes).await?;
                    }
                    Some(BackendCommand::Resize { cols, rows }) => {
                        cur_cols = cols;
                        cur_rows = rows;
                        if is_telnet {
                            let naws = [
                                255, 250, 31,
                                (cols >> 8) as u8, (cols & 0xFF) as u8,
                                (rows >> 8) as u8, (rows & 0xFF) as u8,
                                255, 240,
                            ];
                            let _ = stream.write_all(&naws).await;
                        }
                    }
                    Some(BackendCommand::Disconnect) | None => {
                        let _ = evt_tx
                            .send(BackendEvent::Disconnected(USER_DISCONNECT_REASON.to_string()));
                        break;
                    }
                    _ => {}
                }
            }
        }
    }
    Ok(())
}

async fn process_telnet_iac(
    input: &[u8],
    stream: &mut TcpStream,
    cols: u16,
    rows: u16,
) -> Result<Vec<u8>> {
    const IAC: u8 = 255;
    const DONT: u8 = 254;
    const DO: u8 = 253;
    const WONT: u8 = 252;
    const WILL: u8 = 251;
    const SB: u8 = 250;
    const SE: u8 = 240;

    const OPT_ECHO: u8 = 1;
    const OPT_SGA: u8 = 3;
    const OPT_TTYPE: u8 = 24;
    const OPT_NAWS: u8 = 31;

    let mut clean = Vec::with_capacity(input.len());
    let mut reply = Vec::new();
    let mut i = 0;

    while i < input.len() {
        if input[i] != IAC {
            clean.push(input[i]);
            i += 1;
            continue;
        }
        if i + 1 >= input.len() {
            break;
        }
        let cmd = input[i + 1];
        if cmd == IAC {
            clean.push(IAC);
            i += 2;
            continue;
        }
        if (cmd == DO || cmd == DONT || cmd == WILL || cmd == WONT) && i + 2 < input.len() {
            let opt = input[i + 2];
            match (cmd, opt) {
                (DO, OPT_TTYPE) => {
                    reply.extend_from_slice(&[IAC, WILL, OPT_TTYPE]);
                }
                (DO, OPT_NAWS) => {
                    reply.extend_from_slice(&[
                        IAC,
                        WILL,
                        OPT_NAWS,
                        IAC,
                        SB,
                        OPT_NAWS,
                        (cols >> 8) as u8,
                        (cols & 0xFF) as u8,
                        (rows >> 8) as u8,
                        (rows & 0xFF) as u8,
                        IAC,
                        SE,
                    ]);
                }
                (DO, OPT_SGA) => {
                    reply.extend_from_slice(&[IAC, WILL, OPT_SGA]);
                }
                (DO, o) => {
                    reply.extend_from_slice(&[IAC, WONT, o]);
                }
                (WILL, OPT_ECHO) | (WILL, OPT_SGA) => {
                    reply.extend_from_slice(&[IAC, DO, opt]);
                }
                (WILL, o) => {
                    reply.extend_from_slice(&[IAC, DONT, o]);
                }
                _ => {}
            }
            i += 3;
        } else if cmd == SB {
            let mut end = i + 2;
            while end + 1 < input.len() && !(input[end] == IAC && input[end + 1] == SE) {
                end += 1;
            }
            if i + 3 < input.len() && input[i + 2] == OPT_TTYPE && input[i + 3] == 1 {
                reply.extend_from_slice(&[IAC, SB, OPT_TTYPE, 0]);
                reply.extend_from_slice(b"xterm-256color");
                reply.extend_from_slice(&[IAC, SE]);
            }
            i = (end + 2).min(input.len());
        } else {
            i += 2;
        }
    }

    if !reply.is_empty() {
        stream.write_all(&reply).await?;
    }
    Ok(clean)
}

/// Windows Local Shell via ConPTY (`portable-pty`): PowerShell, CMD, WSL, Cygwin
fn run_local_pty_session(
    profile: SessionProfile,
    initial_cols: u16,
    initial_rows: u16,
    mut cmd_rx: UnboundedReceiver<BackendCommand>,
    evt_tx: UnboundedSender<BackendEvent>,
) -> Result<()> {
    let pty_system = NativePtySystem::default();
    let pair = pty_system.openpty(PtySize {
        rows: initial_rows.max(5),
        cols: initial_cols.max(20),
        pixel_width: 0,
        pixel_height: 0,
    })?;

    let shell_cmd = if profile.local_shell_cmd.trim().is_empty() {
        "powershell.exe".to_string()
    } else {
        profile.local_shell_cmd.trim().to_string()
    };

    let cmd = CommandBuilder::new(&shell_cmd);
    let mut child = pair
        .slave
        .spawn_command(cmd)
        .with_context(|| format!("Impossible de démarrer le shell local '{}'", shell_cmd))?;
    drop(pair.slave);

    let _ = evt_tx.send(BackendEvent::Connected {
        banner_info: format!("Shell Local ({})", shell_cmd),
        host_key_fingerprint: None,
        auth_used: "Windows ConPTY".to_string(),
    });

    let mut reader = pair.master.try_clone_reader()?;
    let mut writer = pair.master.take_writer()?;

    if !profile.startup_command.trim().is_empty() {
        let line = format!("{}\r\n", profile.startup_command.trim());
        let _ = writer.write_all(line.as_bytes());
    }

    let evt_reader = evt_tx.clone();
    std::thread::spawn(move || {
        let mut buf = [0u8; 4096];
        loop {
            match reader.read(&mut buf) {
                Ok(0) => {
                    let _ = evt_reader.send(BackendEvent::Disconnected(
                        "Processus shell local terminé".to_string(),
                    ));
                    break;
                }
                Ok(n) => {
                    if evt_reader
                        .send(BackendEvent::Output(buf[..n].to_vec()))
                        .is_err()
                    {
                        break;
                    }
                }
                Err(_) => {
                    let _ = evt_reader
                        .send(BackendEvent::Disconnected("Shell local fermé".to_string()));
                    break;
                }
            }
        }
    });

    while let Some(cmd) = cmd_rx.blocking_recv() {
        match cmd {
            BackendCommand::SendInput(bytes) => {
                let _ = writer.write_all(&bytes);
                let _ = writer.flush();
            }
            BackendCommand::Resize { cols, rows } => {
                let _ = pair.master.resize(PtySize {
                    rows: rows.max(5),
                    cols: cols.max(20),
                    pixel_width: 0,
                    pixel_height: 0,
                });
            }
            BackendCommand::RunLocalScript(path) => {
                if let Ok(content) = std::fs::read_to_string(&path) {
                    let _ = writer.write_all(content.as_bytes());
                    let _ = writer.write_all(b"\r\n");
                    let _ = writer.flush();
                }
            }
            BackendCommand::Disconnect => {
                let _ = child.kill();
                break;
            }
            _ => {}
        }
    }

    Ok(())
}

/// Collects non-intrusive system metrics (hostname, kernel, uptime, loadavg, RAM, root disk)
/// over a short-lived SSH exec channel without disturbing the interactive terminal.
async fn fetch_remote_telemetry(
    session: &client::Handle<SshClientHandler>,
) -> Option<RemoteServerMetrics> {
    let mut ch = session.channel_open_session().await.ok()?;
    let script = concat!(
        "hostname 2>/dev/null || echo unknown; ",
        "uname -sr 2>/dev/null || echo Linux; ",
        "uptime -p 2>/dev/null || uptime 2>/dev/null || echo -; ",
        "cat /proc/loadavg 2>/dev/null || echo 0.00; ",
        "free -m 2>/dev/null | awk '/^Mem:/ {print $3, $2}'; ",
        "df -P -h / 2>/dev/null | awk 'NR==2 {print $5, $3 \"/\" $2}'"
    );
    ch.exec(true, script).await.ok()?;

    let mut out = Vec::new();
    let collect_res = tokio::time::timeout(Duration::from_secs(4), async {
        while let Some(msg) = ch.wait().await {
            match msg {
                ChannelMsg::Data { data } => out.extend_from_slice(&data),
                ChannelMsg::Eof | ChannelMsg::Close => break,
                _ => {}
            }
        }
    })
    .await;
    if collect_res.is_err() && out.is_empty() {
        return None;
    }

    let text = String::from_utf8_lossy(&out);
    let lines: Vec<&str> = text
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .collect();
    if lines.is_empty() {
        return None;
    }

    let hostname = lines.first().copied().unwrap_or("remote").to_string();
    let kernel = lines.get(1).copied().unwrap_or("Linux").to_string();
    let uptime = lines.get(2).copied().unwrap_or("-").to_string();
    let load_raw = lines.get(3).copied().unwrap_or("0.00");
    let load_parts: Vec<&str> = load_raw.split_whitespace().collect();
    let cpu_load_1m = load_parts
        .first()
        .and_then(|s| s.parse::<f32>().ok())
        .unwrap_or(0.0);
    let load_avg = if load_parts.len() >= 3 {
        format!("{} {} {}", load_parts[0], load_parts[1], load_parts[2])
    } else {
        load_raw.to_string()
    };

    let (mem_used_mb, mem_total_mb) = lines
        .get(4)
        .map(|l| {
            let mut it = l.split_whitespace();
            let used = it.next().and_then(|v| v.parse::<u64>().ok()).unwrap_or(0);
            let total = it.next().and_then(|v| v.parse::<u64>().ok()).unwrap_or(0);
            (used, total)
        })
        .unwrap_or((0, 0));

    let (disk_used_pct, disk_summary) = lines
        .get(5)
        .map(|l| {
            let mut it = l.split_whitespace();
            let pct_str = it.next().unwrap_or("0%").trim_end_matches('%');
            let pct = pct_str.parse::<f32>().unwrap_or(0.0);
            let summary = it.next().unwrap_or("").to_string();
            (pct, summary)
        })
        .unwrap_or((0.0, String::new()));

    Some(RemoteServerMetrics {
        hostname,
        kernel,
        uptime,
        load_avg,
        cpu_load_1m,
        mem_used_mb,
        mem_total_mb,
        disk_used_pct,
        disk_summary,
    })
}

/// Probes a TCP host/port, measures connection latency in milliseconds, and grabs
/// the server's initial SSH/Telnet protocol banner if sent within 450 ms.
pub async fn probe_tcp_and_banner(
    session_id: Option<Uuid>,
    label: String,
    raw_host: String,
    port: u16,
) -> HostProbeResult {
    let (_, clean_host) = split_user_and_host(&raw_host, "");
    let host = if clean_host.is_empty() {
        raw_host.trim().to_string()
    } else {
        clean_host
    };
    let start = std::time::Instant::now();
    let connect_res = tokio::time::timeout(
        Duration::from_millis(2500),
        TcpStream::connect((host.as_str(), port)),
    )
    .await;

    match connect_res {
        Ok(Ok(mut stream)) => {
            let latency_ms = start.elapsed().as_millis() as u64;
            let mut buf = [0u8; 256];
            let banner =
                match tokio::time::timeout(Duration::from_millis(450), stream.read(&mut buf)).await
                {
                    Ok(Ok(n)) if n > 0 => {
                        let s = String::from_utf8_lossy(&buf[..n]);
                        s.lines()
                            .next()
                            .unwrap_or("")
                            .chars()
                            .filter(|c| !c.is_control())
                            .take(96)
                            .collect::<String>()
                            .trim()
                            .to_string()
                    }
                    _ => "Port TCP ouvert (pas de bannière immédiate)".to_string(),
                };
            HostProbeResult {
                session_id,
                label,
                host,
                port,
                reachable: true,
                latency_ms,
                banner,
            }
        }
        Ok(Err(e)) => HostProbeResult {
            session_id,
            label,
            host,
            port,
            reachable: false,
            latency_ms: start.elapsed().as_millis() as u64,
            banner: format!("Connexion refusée / injoignable ({})", e),
        },
        Err(_) => HostProbeResult {
            session_id,
            label,
            host,
            port,
            reachable: false,
            latency_ms: 2500,
            banner: "Délai d'attente dépassé (Timeout > 2500 ms)".to_string(),
        },
    }
}

/// Calculates IPv4 subnet parameters from a CIDR string (`192.168.1.102/24` or `10.0.0.1`).
pub fn calculate_ipv4_cidr(input: &str) -> Result<CidrCalculation> {
    let trimmed = input.trim();
    let (ip_part, prefix_part) = if let Some((ip, p)) = trimmed.split_once('/') {
        (ip.trim(), p.trim())
    } else {
        (trimmed, "24")
    };

    let octets: Vec<u8> = ip_part
        .split('.')
        .map(|o| o.parse::<u8>())
        .collect::<std::result::Result<Vec<u8>, _>>()
        .context("Adresse IPv4 invalide (attendu: A.B.C.D)")?;
    if octets.len() != 4 {
        anyhow::bail!("Adresse IPv4 invalide : 4 octets requis");
    }

    let prefix: u8 = prefix_part.parse::<u8>().context("Préfixe CIDR invalide")?;
    if prefix > 32 {
        anyhow::bail!("Le préfixe CIDR doit être compris entre 0 et 32");
    }

    let ip_u32 = u32::from_be_bytes([octets[0], octets[1], octets[2], octets[3]]);
    let mask_u32 = if prefix == 0 {
        0
    } else {
        !0u32 << (32 - prefix)
    };
    let wildcard_u32 = !mask_u32;
    let net_u32 = ip_u32 & mask_u32;
    let bcast_u32 = net_u32 | wildcard_u32;

    let (first_u32, last_u32, usable_hosts) = if prefix == 32 {
        (net_u32, net_u32, 1)
    } else if prefix == 31 {
        (net_u32, bcast_u32, 2)
    } else {
        let total = 1u64 << (32 - prefix);
        (net_u32 + 1, bcast_u32 - 1, total.saturating_sub(2))
    };

    let fmt_ip = |v: u32| {
        let b = v.to_be_bytes();
        format!("{}.{}.{}.{}", b[0], b[1], b[2], b[3])
    };

    Ok(CidrCalculation {
        input_ip: fmt_ip(ip_u32),
        prefix,
        netmask: fmt_ip(mask_u32),
        wildcard: fmt_ip(wildcard_u32),
        network_address: fmt_ip(net_u32),
        broadcast_address: fmt_ip(bcast_u32),
        first_usable: fmt_ip(first_u32),
        last_usable: fmt_ip(last_u32),
        usable_hosts,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resume_offset_only_inside_the_file() {
        assert_eq!(resume_offset(0, 100), 0);
        assert_eq!(resume_offset(40, 100), 40);
        assert_eq!(resume_offset(100, 100), 0);
        assert_eq!(resume_offset(150, 100), 0);
    }

    #[tokio::test]
    async fn socks5_negotiate_parses_domain_connect() {
        let (mut client, mut server) = tokio::io::duplex(256);
        let srv = tokio::spawn(async move { socks5_negotiate(&mut server).await });
        client.write_all(&[5, 1, 0]).await.unwrap();
        let mut reply = [0u8; 2];
        client.read_exact(&mut reply).await.unwrap();
        assert_eq!(reply, [5, 0]);
        let host = b"example.org";
        let mut req = vec![5, 1, 0, 3, host.len() as u8];
        req.extend_from_slice(host);
        req.extend_from_slice(&443u16.to_be_bytes());
        client.write_all(&req).await.unwrap();
        assert_eq!(
            srv.await.unwrap().unwrap(),
            ("example.org".to_string(), 443)
        );
    }

    #[test]
    fn http_connect_request_line_is_parsed() {
        assert_eq!(
            parse_http_connect("CONNECT example.org:443 HTTP/1.1\r\nHost: x\r\n\r\n"),
            Some(("example.org".to_string(), 443))
        );
        assert_eq!(
            parse_http_connect("connect [::1]:8080 HTTP/1.1\r\n\r\n"),
            Some(("::1".to_string(), 8080))
        );
        assert_eq!(parse_http_connect("GET http://a/ HTTP/1.1\r\n\r\n"), None);
        assert_eq!(parse_http_connect("CONNECT nohost HTTP/1.1\r\n\r\n"), None);
    }

    #[tokio::test]
    async fn http_connect_negotiate_reads_head_and_rejects_get() {
        let (mut client, mut server) = tokio::io::duplex(512);
        let srv = tokio::spawn(async move { http_connect_negotiate(&mut server).await });
        client
            .write_all(b"CONNECT db.internal:5432 HTTP/1.1\r\nHost: db.internal:5432\r\n\r\n")
            .await
            .unwrap();
        assert_eq!(
            srv.await.unwrap().unwrap(),
            ("db.internal".to_string(), 5432)
        );

        let (mut client, mut server) = tokio::io::duplex(512);
        let srv = tokio::spawn(async move { http_connect_negotiate(&mut server).await });
        client.write_all(b"GET / HTTP/1.1\r\n\r\n").await.unwrap();
        assert!(srv.await.unwrap().is_err());
        let mut reply = [0u8; 12];
        client.read_exact(&mut reply).await.unwrap();
        assert!(reply.starts_with(b"HTTP/1.1 405"));
    }

    #[tokio::test]
    async fn socks5_negotiate_rejects_bind_command() {
        let (mut client, mut server) = tokio::io::duplex(256);
        let srv = tokio::spawn(async move { socks5_negotiate(&mut server).await });
        client.write_all(&[5, 1, 0]).await.unwrap();
        let mut reply = [0u8; 2];
        client.read_exact(&mut reply).await.unwrap();
        client
            .write_all(&[5, 2, 0, 1, 1, 2, 3, 4, 0, 80])
            .await
            .unwrap();
        assert!(srv.await.unwrap().is_err());
    }
}

#[cfg(test)]
mod kbdint_tests {
    use super::is_password_prompt;

    #[test]
    fn password_prompts_are_detected_in_several_languages() {
        for p in ["Password: ", "Mot de passe :", "Passwort:", "Contraseña:"] {
            assert!(is_password_prompt(p), "{p}");
        }
        for p in ["Verification code: ", "One-time token:", "Code OTP"] {
            assert!(!is_password_prompt(p), "{p}");
        }
    }
}
