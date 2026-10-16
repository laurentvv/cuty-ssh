use anyhow::{Context, Result};
use base64::Engine;
use hmac::{Hmac, Mac};
use russh::keys::ssh_encoding::Encode;
use russh::keys::ssh_key::{self, Algorithm, HashAlg, Mpint, PrivateKey, PublicKey};
use russh::keys::{PublicKeyBase64, decode_secret_key, parse_public_key_base64};
use sha2::Sha256;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

#[derive(Debug, Clone)]
pub struct KeyInspection {
    pub path: String,
    pub format_name: String,
    pub algorithm: String,
    pub is_encrypted: bool,
    pub encryption_details: String,
    pub comment: String,
    pub fingerprint_sha256: String,
    pub openssh_public_key: String,
}

#[derive(Debug, Clone)]
pub struct AgentKeyEntry {
    pub algorithm: String,
    pub fingerprint_sha256: String,
    pub comment: String,
    pub openssh_public_key: String,
    pub source_agent: String,
}

/// Inspecte un fichier de clé privée (.ppk PuTTY v2/v3, OpenSSH, PEM, PKCS#8)
/// même s'il est chiffré par passphrase (extrait la clé publique en clair des fichiers .ppk !)
pub fn inspect_key_file(path: &Path) -> Result<KeyInspection> {
    let raw = fs::read_to_string(path)
        .with_context(|| format!("Impossible de lire le fichier de clé {:?}", path))?;
    inspect_key_content(&raw, &path.to_string_lossy())
}

pub fn inspect_key_content(raw: &str, source_label: &str) -> Result<KeyInspection> {
    let normalized = raw.replace("\r\n", "\n");
    let first_line = normalized.lines().next().unwrap_or("").trim();

    if let Some(rest) = first_line.strip_prefix("PuTTY-User-Key-File-") {
        let (ver, alg) = rest.split_once(':').unwrap_or(("3", "unknown"));
        let version = ver.trim();
        let algorithm = alg.trim().to_string();

        let mut encryption = "none".to_string();
        let mut comment = String::new();
        let mut kdf = String::new();
        let mut pub_b64 = String::new();

        let mut lines = normalized.lines();
        while let Some(line) = lines.next() {
            if let Some((k, v)) = line.split_once(':') {
                let k = k.trim();
                let v = v.trim();
                match k {
                    "Encryption" => encryption = v.to_string(),
                    "Comment" => comment = v.to_string(),
                    "Key-Derivation" => kdf = v.to_string(),
                    "Public-Lines" => {
                        if let Ok(n) = v.parse::<usize>() {
                            for _ in 0..n {
                                if let Some(pline) = lines.next() {
                                    pub_b64.push_str(pline.trim());
                                }
                            }
                        }
                    }
                    _ => {}
                }
            }
        }

        let is_encrypted = encryption != "none" && !encryption.is_empty();
        let encryption_details = if is_encrypted {
            if kdf.is_empty() {
                format!("{} (PPK v{} SHA-1)", encryption, version)
            } else {
                format!("{} ({} PPK v{})", encryption, kdf, version)
            }
        } else {
            "Aucune (Clé en clair)".to_string()
        };

        let mut fingerprint_sha256 = "Non disponible".to_string();
        let mut openssh_public_key = String::new();

        if !pub_b64.is_empty() {
            if let Ok(pubkey) = parse_public_key_base64(&pub_b64) {
                fingerprint_sha256 = pubkey.fingerprint(HashAlg::Sha256).to_string();
                let b64 = pubkey.public_key_base64();
                openssh_public_key = if comment.is_empty() {
                    format!("{} {}", algorithm, b64)
                } else {
                    format!("{} {} {}", algorithm, b64, comment)
                };
            }
        }

        return Ok(KeyInspection {
            path: source_label.to_string(),
            format_name: format!("PuTTY Private Key (.ppk v{})", version),
            algorithm,
            is_encrypted,
            encryption_details,
            comment,
            fingerprint_sha256,
            openssh_public_key,
        });
    }

    // Clé OpenSSH / PEM / PKCS#8
    let format_name = if normalized.contains("BEGIN OPENSSH PRIVATE KEY") {
        "OpenSSH Private Key".to_string()
    } else if normalized.contains("BEGIN RSA PRIVATE KEY") {
        "PEM PKCS#1 RSA Key".to_string()
    } else if normalized.contains("BEGIN ENCRYPTED PRIVATE KEY") {
        "PKCS#8 Encrypted Private Key".to_string()
    } else if normalized.contains("BEGIN PRIVATE KEY") {
        "PKCS#8 Private Key".to_string()
    } else {
        "Format de clé SSH".to_string()
    };

    match decode_secret_key(&normalized, None) {
        Ok(priv_key) => {
            let pubkey = priv_key.public_key();
            let alg = priv_key.algorithm().to_string();
            let comment = pubkey.comment().to_string();
            let fp = pubkey.fingerprint(HashAlg::Sha256).to_string();
            let b64 = pubkey.public_key_base64();
            let openssh_pub = if comment.is_empty() {
                format!("{} {}", alg, b64)
            } else {
                format!("{} {} {}", alg, b64, comment)
            };
            Ok(KeyInspection {
                path: source_label.to_string(),
                format_name,
                algorithm: alg,
                is_encrypted: false,
                encryption_details: "Aucune (Clé en clair)".to_string(),
                comment,
                fingerprint_sha256: fp,
                openssh_public_key: openssh_pub,
            })
        }
        Err(_) => Ok(KeyInspection {
            path: source_label.to_string(),
            format_name,
            algorithm: "Chiffrée (Passphrase requise)".to_string(),
            is_encrypted: true,
            encryption_details: "Chiffrée par passphrase".to_string(),
            comment: String::new(),
            fingerprint_sha256: "Déverrouillez avec la passphrase pour voir l'empreinte".to_string(),
            openssh_public_key: String::new(),
        }),
    }
}

/// Charge une clé privée (.ppk PuTTY v2/v3, OpenSSH, PEM, PKCS#8) avec passphrase optionnelle
pub fn load_private_key_any(path: &Path, passphrase: Option<&str>) -> Result<PrivateKey> {
    let raw = fs::read_to_string(path)
        .with_context(|| format!("Impossible d'ouvrir le fichier de clé {:?}", path))?;
    decode_private_key_any(&raw, passphrase)
}

pub fn decode_private_key_any(raw: &str, passphrase: Option<&str>) -> Result<PrivateKey> {
    let normalized = raw.replace("\r\n", "\n");
    let pass_opt = passphrase.filter(|p| !p.is_empty());

    match decode_secret_key(&normalized, pass_opt) {
        Ok(key) => Ok(key),
        Err(e) => {
            let err_msg = e.to_string();
            if err_msg.contains("encrypted") || err_msg.contains("Encrypted") {
                anyhow::bail!("Cette clé (.ppk / SSH) est protégée par une passphrase.");
            } else if err_msg.contains("MAC") || err_msg.contains("IncorrectMac") {
                anyhow::bail!("Passphrase incorrecte pour cette clé PuTTY (.ppk) !");
            } else {
                anyhow::bail!("Erreur de décodage de la clé : {}", err_msg);
            }
        }
    }
}

/// Génère une nouvelle paire de clés SSH (Ed25519 ou RSA)
pub fn generate_new_ssh_key(algorithm_choice: &str, comment: &str) -> Result<PrivateKey> {
    let mut rng = russh::keys::ssh_key::rand_core::OsRng;
    let mut key = match algorithm_choice {
        "rsa-2048" => PrivateKey::random(&mut rng, Algorithm::Rsa { hash: None })
            .context("Échec de génération RSA")?,
        "ecdsa-p256" => PrivateKey::random(
            &mut rng,
            Algorithm::Ecdsa {
                curve: ssh_key::EcdsaCurve::NistP256,
            },
        )
        .context("Échec de génération ECDSA P-256")?,
        _ => PrivateKey::random(&mut rng, Algorithm::Ed25519)
            .context("Échec de génération Ed25519")?,
    };
    key.set_comment(comment);
    Ok(key)
}

/// Exporte n'importe quelle PrivateKey au format PuTTY Private Key v3 (.ppk) compatible Pageant & PuTTY
pub fn export_to_ppk_v3(key: &PrivateKey, comment: &str) -> Result<String> {
    let alg_str = key.algorithm().as_str();

    let mut pub_blob = Vec::new();
    key.public_key()
        .key_data()
        .encode(&mut pub_blob)
        .context("Encodage public blob PPK")?;

    let mut priv_blob = Vec::new();
    match key.key_data() {
        ssh_key::private::KeypairData::Ed25519(kp) => {
            kp.private
                .as_slice()
                .encode(&mut priv_blob)
                .context("Encodage Ed25519 private blob")?;
        }
        ssh_key::private::KeypairData::Rsa(kp) => {
            kp.private.d.encode(&mut priv_blob)?;
            kp.private.p.encode(&mut priv_blob)?;
            kp.private.q.encode(&mut priv_blob)?;
            kp.private.iqmp.encode(&mut priv_blob)?;
        }
        ssh_key::private::KeypairData::Ecdsa(kp) => {
            let scalar_bytes = match kp {
                ssh_key::private::EcdsaKeypair::NistP256 { private, .. } => private.as_slice(),
                ssh_key::private::EcdsaKeypair::NistP384 { private, .. } => private.as_slice(),
                ssh_key::private::EcdsaKeypair::NistP521 { private, .. } => private.as_slice(),
            };
            Mpint::from_positive_bytes(scalar_bytes)?
                .encode(&mut priv_blob)
                .context("Encodage ECDSA private blob")?;
        }
        ssh_key::private::KeypairData::Dsa(kp) => {
            kp.private.encode(&mut priv_blob)?;
        }
        _ => anyhow::bail!("Type de clé non supporté pour l'export .ppk"),
    }

    let mut mac_buffer = Vec::new();
    alg_str.as_bytes().encode(&mut mac_buffer)?;
    b"none".as_slice().encode(&mut mac_buffer)?;
    comment.as_bytes().encode(&mut mac_buffer)?;
    pub_blob.encode(&mut mac_buffer)?;
    priv_blob.encode(&mut mac_buffer)?;

    let mut hmac = Hmac::<Sha256>::new_from_slice(&[]).expect("HMAC key init");
    hmac.update(&mac_buffer);
    let mac_hex = hex::encode(hmac.finalize().into_bytes());

    let b64_engine = base64::engine::general_purpose::STANDARD;
    let pub_b64_lines = wrap_base64_lines(&b64_engine.encode(&pub_blob), 64);
    let priv_b64_lines = wrap_base64_lines(&b64_engine.encode(&priv_blob), 64);

    let mut out = String::new();
    out.push_str(&format!("PuTTY-User-Key-File-3: {}\r\n", alg_str));
    out.push_str("Encryption: none\r\n");
    out.push_str(&format!("Comment: {}\r\n", comment));
    out.push_str(&format!("Public-Lines: {}\r\n", pub_b64_lines.len()));
    for l in &pub_b64_lines {
        out.push_str(l);
        out.push_str("\r\n");
    }
    out.push_str(&format!("Private-Lines: {}\r\n", priv_b64_lines.len()));
    for l in &priv_b64_lines {
        out.push_str(l);
        out.push_str("\r\n");
    }
    out.push_str(&format!("Private-MAC: {}\r\n", mac_hex));

    Ok(out)
}

/// Exporte une PrivateKey au format OpenSSH (`-----BEGIN OPENSSH PRIVATE KEY-----`)
pub fn export_to_openssh_pem(key: &PrivateKey) -> Result<String> {
    let openssh_doc = key
        .to_openssh(ssh_key::LineEnding::LF)
        .context("Impossible d'encoder la clé au format OpenSSH")?;
    Ok(openssh_doc.to_string())
}

pub fn format_openssh_pubkey(pubkey: &PublicKey) -> String {
    let alg = pubkey.algorithm().to_string();
    let b64 = pubkey.public_key_base64();
    let comment = pubkey.comment();
    if comment.is_empty() {
        format!("{} {}", alg, b64)
    } else {
        format!("{} {} {}", alg, b64, comment)
    }
}

fn wrap_base64_lines(s: &str, width: usize) -> Vec<String> {
    if s.is_empty() {
        return vec![String::new()];
    }
    s.as_bytes()
        .chunks(width)
        .map(|c| String::from_utf8_lossy(c).to_string())
        .collect()
}

/// Résout le chemin vers `pageant.exe` en vérifiant `"C:\Program Files\PuTTY\pageant.exe"` en priorité
pub fn resolve_pageant_executable(configured_path: &str) -> Option<PathBuf> {
    let candidates = [
        configured_path,
        r"C:\Program Files\PuTTY\pageant.exe",
        r"C:\Program Files (x86)\PuTTY\pageant.exe",
    ];
    for c in candidates {
        let p = PathBuf::from(c);
        if p.exists() {
            return Some(p);
        }
    }
    None
}

/// Lance Pageant (`C:\Program Files\PuTTY\pageant.exe`) avec une liste optionnelle de fichiers `.ppk`
/// Note : Si Pageant tourne déjà, `pageant.exe fichier.ppk` lui transmet automatiquement la clé !
pub fn launch_pageant_with_keys(configured_path: &str, ppk_files: &[String]) -> Result<String> {
    let exe = resolve_pageant_executable(configured_path).unwrap_or_else(|| {
        if configured_path.trim().is_empty() {
            PathBuf::from(r"C:\Program Files\PuTTY\pageant.exe")
        } else {
            PathBuf::from(configured_path)
        }
    });

    if !exe.exists() {
        anyhow::bail!(
            "Exécutable Pageant introuvable à l'emplacement : {:?}. Vérifiez que PuTTY est installé dans \"C:\\Program Files\\PuTTY\\pageant.exe\".",
            exe
        );
    }

    let mut cmd = Command::new(&exe);
    for f in ppk_files {
        if !f.trim().is_empty() {
            cmd.arg(f);
        }
    }
    cmd.spawn()
        .with_context(|| format!("Impossible de lancer {:?}", exe))?;

    if ppk_files.is_empty() {
        Ok(format!("Pageant démarré ({})", exe.display()))
    } else {
        Ok(format!(
            "Pageant ({}) invoqué avec {} clé(s) .ppk",
            exe.display(),
            ppk_files.len()
        ))
    }
}

/// Interroge Pageant (et optionnellement l'agent OpenSSH Windows) pour lister toutes les clés chargées en mémoire
pub async fn list_agent_keys(check_pageant: bool, check_openssh: bool) -> Vec<AgentKeyEntry> {
    let mut entries = Vec::new();

    #[cfg(windows)]
    if check_pageant {
        if let Ok(mut agent) = russh::keys::agent::client::AgentClient::connect_pageant().await {
            if let Ok(identities) = agent.request_identities().await {
                for id in identities {
                    let pubkey = id.public_key();
                    entries.push(AgentKeyEntry {
                        algorithm: pubkey.algorithm().to_string(),
                        fingerprint_sha256: pubkey.fingerprint(HashAlg::Sha256).to_string(),
                        comment: id.comment().to_string(),
                        openssh_public_key: format_openssh_pubkey(&pubkey),
                        source_agent: "Pageant (PuTTY Agent)".to_string(),
                    });
                }
            }
        }
    }

    #[cfg(windows)]
    if check_openssh {
        if let Ok(mut agent) = russh::keys::agent::client::AgentClient::connect_named_pipe(
            r"\\.\pipe\openssh-ssh-agent",
        )
        .await
        {
            if let Ok(identities) = agent.request_identities().await {
                for id in identities {
                    let pubkey = id.public_key();
                    entries.push(AgentKeyEntry {
                        algorithm: pubkey.algorithm().to_string(),
                        fingerprint_sha256: pubkey.fingerprint(HashAlg::Sha256).to_string(),
                        comment: id.comment().to_string(),
                        openssh_public_key: format_openssh_pubkey(&pubkey),
                        source_agent: "Windows OpenSSH Agent".to_string(),
                    });
                }
            }
        }
    }

    entries
}
