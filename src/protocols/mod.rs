use crate::config::{PortForwardType, ProtocolType, SessionProfile, SshAuthMethod};
use crate::ssh::ppk::{inspect_key_file, load_private_key_any};
use anyhow::{Context, Result};
use portable_pty::{CommandBuilder, NativePtySystem, PtySize, PtySystem};
use russh::keys::ssh_key::{HashAlg, PublicKey};
use russh::keys::{PrivateKeyWithHashAlg, PublicKeyOrCertificate};
use russh::{ChannelMsg, Disconnect, client};
use russh_sftp::client::SftpSession;
use russh_sftp::protocol::OpenFlags;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc::{UnboundedReceiver, UnboundedSender, unbounded_channel};
use tokio::sync::oneshot;

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

#[derive(Debug)]
pub enum BackendCommand {
    SendInput(Vec<u8>),
    Resize { cols: u16, rows: u16 },
    ProvideSecret(String),
    RunLocalScript(PathBuf),
    SftpListDir(String),
    SftpUpload { local_path: PathBuf, remote_path: String },
    SftpDownload { remote_path: String, local_path: PathBuf },
    SftpMkdir(String),
    SftpDelete { remote_path: String, is_dir: bool },
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
    SftpDirListed {
        current_path: String,
        entries: Vec<SftpFileEntry>,
    },
    SftpStatus(String),
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
        initial_cols: u16,
        initial_rows: u16,
    ) -> Self {
        let (cmd_tx, cmd_rx) = unbounded_channel();
        let (evt_tx, evt_rx) = unbounded_channel();

        match profile.protocol {
            ProtocolType::Ssh => {
                rt.spawn(async move {
                    if let Err(e) =
                        run_ssh_session(profile, initial_cols, initial_rows, cmd_rx, evt_tx.clone())
                            .await
                    {
                        let _ = evt_tx.send(BackendEvent::ErrorMessage(format!(
                            "Erreur SSH : {:#}",
                            e
                        )));
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
    server_fingerprint: Arc<Mutex<Option<String>>>,
}

impl client::Handler for SshClientHandler {
    type Error = russh::Error;

    async fn check_server_key(
        &mut self,
        server_public_key: &PublicKeyOrCertificate,
    ) -> Result<bool, Self::Error> {
        let fp = match server_public_key {
            PublicKeyOrCertificate::PublicKey(pk) => {
                format!("{} ({})", pk.fingerprint(HashAlg::Sha256), pk.algorithm())
            }
            PublicKeyOrCertificate::Certificate(cert) => {
                format!("Certificat SSH ({})", cert.algorithm())
            }
        };
        if let Ok(mut guard) = self.server_fingerprint.lock() {
            *guard = Some(fp);
        }
        Ok(true)
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

#[cfg(windows)]
async fn try_authenticate_with_pageant(
    session: &mut client::Handle<SshClientHandler>,
    username: &str,
    evt_tx: &UnboundedSender<BackendEvent>,
) -> Option<String> {
    if let Ok(mut agent) = russh::keys::agent::client::AgentClient::connect_pageant().await {
        if let Ok(identities) = agent.request_identities().await {
            if !identities.is_empty() {
                let _ = evt_tx.send(BackendEvent::StatusMessage(format!(
                    "Pageant détecté ({} clé(s) chargée(s)) — tentative d'authentification...",
                    identities.len()
                )));
                let rsa_hash = session.best_supported_rsa_hash().await.ok().flatten().flatten();
                for id in identities {
                    let pubkey: PublicKey = id.public_key().into_owned();
                    let alg_is_rsa = pubkey.algorithm().is_rsa();
                    let hash_alg = if alg_is_rsa { rsa_hash } else { None };
                    let comment = id.comment().to_string();
                    let fp = pubkey.fingerprint(HashAlg::Sha256).to_string();
                    if let Ok(res) = session
                        .authenticate_publickey_with(username, pubkey, hash_alg, &mut agent)
                        .await
                    {
                        if res.success() {
                            return Some(format!(
                                "Pageant (PuTTY Agent) — clé {} [{}]",
                                if comment.is_empty() { "sans nom" } else { &comment },
                                fp
                            ));
                        }
                    }
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
    if let Ok(mut agent) = russh::keys::agent::client::AgentClient::connect_named_pipe(
        r"\\.\pipe\openssh-ssh-agent",
    )
    .await
    {
        if let Ok(identities) = agent.request_identities().await {
            if !identities.is_empty() {
                let _ = evt_tx.send(BackendEvent::StatusMessage(format!(
                    "Agent OpenSSH Windows détecté ({} clé(s))...",
                    identities.len()
                )));
                let rsa_hash = session.best_supported_rsa_hash().await.ok().flatten().flatten();
                for id in identities {
                    let pubkey: PublicKey = id.public_key().into_owned();
                    let alg_is_rsa = pubkey.algorithm().is_rsa();
                    let hash_alg = if alg_is_rsa { rsa_hash } else { None };
                    let fp = pubkey.fingerprint(HashAlg::Sha256).to_string();
                    if let Ok(res) = session
                        .authenticate_publickey_with(username, pubkey, hash_alg, &mut agent)
                        .await
                    {
                        if res.success() {
                            return Some(format!("Agent OpenSSH Windows [{}]", fp));
                        }
                    }
                }
            }
        }
    }
    None
}

async fn run_ssh_session(
    profile: SessionProfile,
    initial_cols: u16,
    initial_rows: u16,
    mut cmd_rx: UnboundedReceiver<BackendCommand>,
    evt_tx: UnboundedSender<BackendEvent>,
) -> Result<()> {
    let addr = format!("{}:{}", profile.host.trim(), profile.port);
    let _ = evt_tx.send(BackendEvent::StatusMessage(format!(
        "Connexion SSH2 vers {}...",
        addr
    )));

    let mut ssh_config = client::Config {
        inactivity_timeout: if profile.keepalive_secs > 0 {
            Some(Duration::from_secs((profile.keepalive_secs as u64 * 3).max(60)))
        } else {
            None
        },
        keepalive_interval: if profile.keepalive_secs > 0 {
            Some(Duration::from_secs(profile.keepalive_secs as u64))
        } else {
            None
        },
        ..Default::default()
    };
    let _ = &mut ssh_config;

    let server_fp = Arc::new(Mutex::new(None));
    let handler = SshClientHandler {
        server_fingerprint: Arc::clone(&server_fp),
    };

    let mut session = tokio::time::timeout(
        Duration::from_secs(15),
        client::connect(Arc::new(ssh_config), (&profile.host[..], profile.port), handler),
    )
    .await
    .context("Délai d'attente dépassé lors de la connexion TCP/SSH")?
    .context("Échec de l'établissement de la session SSH")?;

    let mut username = profile.username.trim().to_string();
    if username.is_empty() {
        username = wait_for_secret_input(
            &mut cmd_rx,
            &evt_tx,
            "Identifiant SSH",
            &format!("Nom d'utilisateur pour {} :", profile.host),
            false,
        )
        .await?;
    }

    let mut authenticated_via: Option<String> = None;

    // 1. Si Pageant est activé (try_pageant ou SshAuthMethod::Agent), tenter Pageant automatiquement comme PuTTY/KiTTY !
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
            authenticated_via =
                try_authenticate_with_pageant(&mut session, &username, &evt_tx).await;
        }

        if authenticated_via.is_none() {
            if let SshAuthMethod::Agent {
                use_openssh_agent: true,
                ..
            } = profile.ssh_auth
            {
                authenticated_via =
                    try_authenticate_with_openssh_agent(&mut session, &username, &evt_tx).await;
            }
        }
    }

    // 2. Authentification selon la méthode configurée si Pageant n'a pas encore authentifié
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
                            &mut cmd_rx,
                            &evt_tx,
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
                                &mut cmd_rx,
                                &evt_tx,
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
                    let hash_alg = if priv_key.algorithm().is_rsa() {
                        rsa_hash
                    } else {
                        None
                    };

                    let auth_res = if !cert_path.trim().is_empty() {
                        let cert = russh::keys::load_openssh_certificate(cert_path.trim())?;
                        session
                            .authenticate_openssh_cert(&username, Arc::new(priv_key), cert)
                            .await?
                    } else {
                        session
                            .authenticate_publickey(
                                &username,
                                PrivateKeyWithHashAlg::new(Arc::new(priv_key), hash_alg),
                            )
                            .await?
                    };

                    if auth_res.success() {
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
            SshAuthMethod::Agent { .. } => {
                // Déjà testé ci-dessus, repli sur mot de passe si échec
            }
            SshAuthMethod::KeyboardInteractive => {
                if let Ok(resp) = session
                    .authenticate_keyboard_interactive_start(&username, None)
                    .await
                {
                    let mut cur = resp;
                    loop {
                        match cur {
                            client::KeyboardInteractiveAuthResponse::Success => {
                                authenticated_via =
                                    Some("Keyboard-Interactive (PAM/2FA)".to_string());
                                break;
                            }
                            client::KeyboardInteractiveAuthResponse::Failure { .. } => break,
                            client::KeyboardInteractiveAuthResponse::InfoRequest {
                                name,
                                instructions,
                                prompts,
                            } => {
                                let mut answers = Vec::new();
                                for p in prompts {
                                    let ans = if !profile.password.is_empty()
                                        && p.prompt.to_lowercase().contains("password")
                                    {
                                        profile.password.clone()
                                    } else {
                                        wait_for_secret_input(
                                            &mut cmd_rx,
                                            &evt_tx,
                                            if name.is_empty() {
                                                "Authentification Interactive"
                                            } else {
                                                &name
                                            },
                                            &format!("{}\n{}", instructions, p.prompt),
                                            true,
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
            }
            SshAuthMethod::Password => {}
        }
    }

    // 3. Authentification par mot de passe (automatique KiTTY ou saisie interactive)
    if authenticated_via.is_none() {
        let mut pwd = profile.password.clone();
        if pwd.is_empty() {
            pwd = wait_for_secret_input(
                &mut cmd_rx,
                &evt_tx,
                "Mot de passe SSH",
                &format!("Mot de passe pour {}@{} :", username, profile.host),
                true,
            )
            .await?;
        }
        let res = session.authenticate_password(&username, &pwd).await?;
        if res.success() {
            authenticated_via = Some(if !profile.password.is_empty() {
                "Mot de passe automatique (KiTTY)".to_string()
            } else {
                "Mot de passe SSH".to_string()
            });
        } else {
            // Deuxième essai interactif
            let retry_pwd = wait_for_secret_input(
                &mut cmd_rx,
                &evt_tx,
                "Échec d'authentification — Réessayer",
                &format!("Mot de passe pour {}@{} :", username, profile.host),
                true,
            )
            .await?;
            let res2 = session.authenticate_password(&username, &retry_pwd).await?;
            if res2.success() {
                authenticated_via = Some("Mot de passe SSH".to_string());
            } else {
                anyhow::bail!("Authentification SSH refusée pour {}@{}", username, profile.host);
            }
        }
    }

    let auth_used = authenticated_via.unwrap_or_else(|| "SSH2".to_string());
    let fp = server_fp.lock().ok().and_then(|g| g.clone());

    // Démarrage des règles de redirection de ports (Port Forwarding -L / -R)
    let session = Arc::new(session);
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

    // Ouverture du canal PTY + Shell principal
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

    // Ouverture en tâche de fond d'une session SFTP dédiée pour l'explorateur intégré
    let sftp_session: Arc<tokio::sync::Mutex<Option<SftpSession>>> =
        Arc::new(tokio::sync::Mutex::new(None));
    {
        let sess_sftp = Arc::clone(&session);
        let sftp_holder = Arc::clone(&sftp_session);
        let evt_sftp = evt_tx.clone();
        tokio::spawn(async move {
            if let Ok(sftp_ch) = sess_sftp.channel_open_session().await {
                if sftp_ch.request_subsystem(true, "sftp").await.is_ok() {
                    if let Ok(sftp) = SftpSession::new(sftp_ch.into_stream()).await {
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
                }
            }
        });
    }

    // Exécution automatique de la commande de démarrage KiTTY (si définie)
    if !profile.startup_command.trim().is_empty() {
        let cmd_line = format!("{}\n", profile.startup_command.trim());
        let _ = channel.data(cmd_line.as_bytes()).await;
    }

    // Exécution automatique d'un script local sur la session distante (si défini au démarrage)
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

                        // Analyse des règles d'automatisation Expect/Logon KiTTY
                        if expect_rules.iter().any(|r| r.enabled) {
                            recent_text_window.push_str(&String::from_utf8_lossy(&bytes));
                            if recent_text_window.len() > 2048 {
                                let drain = recent_text_window.len() - 1024;
                                recent_text_window.drain(..drain);
                            }
                            for rule in &mut expect_rules {
                                if rule.enabled && !rule.trigger_prompt.is_empty() && recent_text_window.contains(&rule.trigger_prompt) {
                                    rule.enabled = false; // Une seule exécution par connexion
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
                    Some(BackendCommand::SftpListDir(dir)) => {
                        let sftp_Ref = Arc::clone(&sftp_session);
                        let evt_c = evt_tx.clone();
                        tokio::spawn(async move {
                            let guard = sftp_Ref.lock().await;
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
                        let sftp_Ref = Arc::clone(&sftp_session);
                        let evt_c = evt_tx.clone();
                        tokio::spawn(async move {
                            let guard = sftp_Ref.lock().await;
                            if let Some(sftp) = guard.as_ref() {
                                match upload_sftp_file(sftp, &local_path, &remote_path).await {
                                    Ok(bytes_len) => {
                                        let _ = evt_c.send(BackendEvent::SftpStatus(format!(
                                            "Upload réussi : {} ({} octets)",
                                            remote_path, bytes_len
                                        )));
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
                        let sftp_Ref = Arc::clone(&sftp_session);
                        let evt_c = evt_tx.clone();
                        tokio::spawn(async move {
                            let guard = sftp_Ref.lock().await;
                            if let Some(sftp) = guard.as_ref() {
                                match download_sftp_file(sftp, &remote_path, &local_path).await {
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
                    Some(BackendCommand::SftpMkdir(remote_dir)) => {
                        let sftp_Ref = Arc::clone(&sftp_session);
                        let evt_c = evt_tx.clone();
                        tokio::spawn(async move {
                            let guard = sftp_Ref.lock().await;
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
                    Some(BackendCommand::SftpDelete { remote_path, is_dir }) => {
                        let sftp_Ref = Arc::clone(&sftp_session);
                        let evt_c = evt_tx.clone();
                        tokio::spawn(async move {
                            let guard = sftp_Ref.lock().await;
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
                        let _ = evt_tx.send(BackendEvent::Disconnected(
                            "Déconnecté par l'utilisateur".to_string(),
                        ));
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

async fn upload_sftp_file(
    sftp: &SftpSession,
    local_path: &Path,
    remote_path: &str,
) -> Result<usize> {
    let data = tokio::fs::read(local_path).await?;
    let mut remote_file = sftp
        .open_with_flags(
            remote_path,
            OpenFlags::CREATE | OpenFlags::TRUNCATE | OpenFlags::WRITE,
        )
        .await?;
    remote_file.write_all(&data).await?;
    remote_file.flush().await?;
    remote_file.shutdown().await?;
    Ok(data.len())
}

async fn download_sftp_file(
    sftp: &SftpSession,
    remote_path: &str,
    local_path: &Path,
) -> Result<usize> {
    let mut remote_file = sftp.open(remote_path).await?;
    let mut buf = Vec::new();
    remote_file.read_to_end(&mut buf).await?;
    tokio::fs::write(local_path, &buf).await?;
    Ok(buf.len())
}

/// Connexion Telnet (RFC 854 IAC, NAWS, TTYPE, SGA + Auto-login KiTTY) et Raw TCP
async fn run_tcp_or_telnet_session(
    profile: SessionProfile,
    is_telnet: bool,
    initial_cols: u16,
    initial_rows: u16,
    mut cmd_rx: UnboundedReceiver<BackendCommand>,
    evt_tx: UnboundedSender<BackendEvent>,
) -> Result<()> {
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

                            // Automatisation de connexion Telnet KiTTY (auto-login & auto-password)
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
                        let _ = evt_tx.send(BackendEvent::Disconnected("Déconnecté".to_string()));
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

/// Shell Local Windows via ConPTY (`portable-pty`) : PowerShell, CMD, WSL, Cygwin
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
                    let _ = evt_reader.send(BackendEvent::Disconnected(
                        "Shell local fermé".to_string(),
                    ));
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
