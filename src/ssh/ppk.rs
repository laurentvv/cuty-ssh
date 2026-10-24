//! PuTTY Private Key (`.ppk` v2/v3) and OpenSSH key inspection, conversion, generation, and Pageant integration.

use anyhow::{Context, Result};
use base64::Engine as _;
use hmac::{Hmac, KeyInit, Mac};
use russh::keys::ssh_encoding::Encode;
use russh::keys::ssh_key::private::{Ed25519Keypair, KeypairData};
use russh::keys::ssh_key::{self, HashAlg, Mpint, PrivateKey, PublicKey};
use russh::keys::{PublicKeyBase64, decode_secret_key, parse_public_key_base64};
use sha2::Sha256;
use std::fs;
use std::path::{Path, PathBuf};
use uuid::Uuid;
use zeroize::{Zeroize, Zeroizing};

/// Metadata extracted from a private key file (`.ppk` v2/v3, OpenSSH, PEM, or PKCS#8).
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

/// Public key entry reported by a running SSH agent (Pageant or Windows OpenSSH Agent).
#[derive(Debug, Clone)]
pub struct AgentKeyEntry {
    pub algorithm: String,
    pub fingerprint_sha256: String,
    pub comment: String,
    pub openssh_public_key: String,
    pub source_agent: String,
}

/// Inspects a private or public key file on disk and extracts its metadata and public key (even for encrypted `.ppk` files).
pub fn inspect_key_file(path: &Path) -> Result<KeyInspection> {
    let raw = Zeroizing::new(
        fs::read_to_string(path).with_context(|| format!("Failed to read key file {:?}", path))?,
    );
    let mut info = inspect_key_content(&raw, &path.to_string_lossy())?;
    if info.openssh_public_key.is_empty() {
        let pub_candidate_1 = path.with_extension("pub");
        let pub_candidate_2 = PathBuf::from(format!("{}.pub", path.display()));
        for cand in [pub_candidate_1, pub_candidate_2] {
            if cand.exists()
                && let Ok(pub_raw) = fs::read_to_string(&cand)
            {
                let line = pub_raw
                    .lines()
                    .map(str::trim)
                    .find(|l| !l.is_empty() && !l.starts_with('#'))
                    .unwrap_or("");
                if !line.is_empty() {
                    info.openssh_public_key = line.to_string();
                    let parts: Vec<&str> = line.split_whitespace().collect();
                    if let Some(b64) = parts.get(1)
                        && let Ok(pk) = parse_public_key_base64(b64)
                    {
                        info.fingerprint_sha256 = pk.fingerprint(HashAlg::Sha256).to_string();
                        info.algorithm = pk.algorithm().to_string();
                    }
                    if let Some(c) = parts.get(2)
                        && info.comment.is_empty()
                    {
                        info.comment = (*c).to_string();
                    }
                    break;
                }
            }
        }
    }
    Ok(info)
}

/// Inspects raw key text and returns its format, algorithm, encryption state, and SHA256 fingerprint.
pub fn inspect_key_content(raw: &str, source_label: &str) -> Result<KeyInspection> {
    let normalized = Zeroizing::new(raw.replace("\r\n", "\n"));
    let first_line = normalized.lines().next().unwrap_or("").trim();

    if first_line.starts_with("ssh-") || first_line.starts_with("ecdsa-sha2-") {
        let parts: Vec<&str> = first_line.split_whitespace().collect();
        let alg = parts.first().copied().unwrap_or("ssh-key").to_string();
        let b64 = parts.get(1).copied().unwrap_or("");
        let comment = if parts.len() >= 3 {
            parts[2..].join(" ")
        } else {
            String::new()
        };
        let fp = parse_public_key_base64(b64)
            .map(|pk| pk.fingerprint(HashAlg::Sha256).to_string())
            .unwrap_or_else(|_| "Non disponible".to_string());
        return Ok(KeyInspection {
            path: source_label.to_string(),
            format_name: "OpenSSH Public Key (.pub)".to_string(),
            algorithm: alg,
            is_encrypted: false,
            encryption_details: "Clé publique OpenSSH".to_string(),
            comment,
            fingerprint_sha256: fp,
            openssh_public_key: first_line.to_string(),
        });
    }

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
                format!("{encryption} (PPK v{version} SHA-1)")
            } else {
                format!("{encryption} ({kdf} PPK v{version})")
            }
        } else {
            "Aucune (Clé en clair)".to_string()
        };

        let mut fingerprint_sha256 = "Non disponible".to_string();
        let mut openssh_public_key = String::new();

        if !pub_b64.is_empty()
            && let Ok(pubkey) = parse_public_key_base64(&pub_b64)
        {
            fingerprint_sha256 = pubkey.fingerprint(HashAlg::Sha256).to_string();
            let b64 = pubkey.public_key_base64();
            openssh_public_key = if comment.is_empty() {
                format!("{algorithm} {b64}")
            } else {
                format!("{algorithm} {b64} {comment}")
            };
        }

        return Ok(KeyInspection {
            path: source_label.to_string(),
            format_name: format!("PuTTY Private Key (.ppk v{version})"),
            algorithm,
            is_encrypted,
            encryption_details,
            comment,
            fingerprint_sha256,
            openssh_public_key,
        });
    }

    let format_name = if normalized.contains("BEGIN OPENSSH PRIVATE KEY") {
        "OpenSSH Private Key".to_string()
    } else if normalized.contains("BEGIN RSA PRIVATE KEY") {
        "PEM PKCS#1 RSA Key".to_string()
    } else if normalized.contains("BEGIN ENCRYPTED PRIVATE KEY") {
        "PKCS#8 Encrypted Private Key".to_string()
    } else if normalized.contains("BEGIN PRIVATE KEY") {
        "PKCS#8 Private Key".to_string()
    } else {
        "SSH Private Key".to_string()
    };

    match decode_secret_key(&normalized, None) {
        Ok(priv_key) => {
            let pubkey = priv_key.public_key();
            let alg = priv_key.algorithm().to_string();
            let comment = pubkey.comment().to_string();
            let fp = pubkey.fingerprint(HashAlg::Sha256).to_string();
            let b64 = pubkey.public_key_base64();
            let openssh_pub = if comment.is_empty() {
                format!("{alg} {b64}")
            } else {
                format!("{alg} {b64} {comment}")
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
            fingerprint_sha256: "Déverrouillez avec la passphrase pour voir l'empreinte"
                .to_string(),
            openssh_public_key: String::new(),
        }),
    }
}

/// Loads and decodes a private key file (`.ppk` v2/v3, OpenSSH, PEM, or PKCS#8) with an optional passphrase.
pub fn load_private_key_any(path: &Path, passphrase: Option<&str>) -> Result<PrivateKey> {
    let raw = Zeroizing::new(
        fs::read_to_string(path)
            .with_context(|| format!("Failed to open private key file {:?}", path))?,
    );
    decode_private_key_any(&raw, passphrase)
}

/// Decodes a private key from text content (`.ppk` v2/v3, OpenSSH, PEM, or PKCS#8).
pub fn decode_private_key_any(raw: &str, passphrase: Option<&str>) -> Result<PrivateKey> {
    let normalized = Zeroizing::new(raw.replace("\r\n", "\n"));
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
                anyhow::bail!("Erreur de décodage de la clé : {err_msg}");
            }
        }
    }
}

/// Generates a new Ed25519 SSH keypair ready for export as `.ppk` (v3) or OpenSSH PEM.
pub fn generate_new_ssh_key(_algorithm_choice: &str, comment: &str) -> Result<PrivateKey> {
    let u1 = Uuid::new_v4();
    let u2 = Uuid::new_v4();
    let mut seed = Zeroizing::new([0u8; 32]);
    seed[..16].copy_from_slice(u1.as_bytes());
    seed[16..].copy_from_slice(u2.as_bytes());
    // Clear the sign bit and ensure non-zero leading byte so 32-byte wire encoding matches both Mpint and PuTTY string
    seed[0] = (seed[0] & 0x7F).max(1);

    let keypair = Ed25519Keypair::from_seed(&seed);
    let key = PrivateKey::new(KeypairData::Ed25519(keypair), comment)
        .context("Failed to construct Ed25519 private key")?;
    Ok(key)
}

/// Generates a new Ed25519 keypair and serializes it as a passphrase-protected
/// OpenSSH private key (bcrypt KDF + AES256-CTR), returning the PEM document
/// (zeroized on drop) and the `authorized_keys` public line.
pub fn generate_openssh_key_encrypted(
    comment: &str,
    passphrase: &str,
) -> Result<(Zeroizing<String>, String)> {
    let key = generate_new_ssh_key("ed25519", comment)?;
    // The crate's default `PrivateKey::encrypt` needs a live RNG (rand_core);
    // UUID v4 bytes are OS entropy, so the dependency set stays unchanged.
    // 16-byte salt and 16 rounds match OpenSSH's ssh-keygen defaults.
    let salt: Vec<u8> = Uuid::new_v4().as_bytes().to_vec();
    let check = *Uuid::new_v4().as_bytes();
    let checkint = u32::from_be_bytes([check[0], check[1], check[2], check[3]]);
    let mut encrypted = key
        .encrypt_with(
            ssh_key::Cipher::Aes256Ctr,
            ssh_key::Kdf::Bcrypt { salt, rounds: 16 },
            checkint,
            passphrase,
        )
        .context("Failed to encrypt the generated key")?;
    // Upstream quirk: encrypt_with rebuilds the public key from the key data
    // alone and drops the comment (it stays encoded inside the encrypted
    // payload) — restore it so the .pub line and inspector stay consistent.
    encrypted.set_comment(comment);
    let pem = encrypted
        .to_openssh(ssh_key::LineEnding::LF)
        .context("Failed to encode key in OpenSSH format")?;
    let pub_line = format_openssh_pubkey(encrypted.public_key());
    Ok((pem, pub_line))
}

/// Exports any `PrivateKey` to PuTTY Private Key v3 (`.ppk`) format compatible with `pageant.exe` and `putty.exe`.
pub fn export_to_ppk_v3(key: &PrivateKey, comment: &str) -> Result<String> {
    let alg = key.algorithm();
    let alg_str = alg.as_str();

    let mut pub_blob = Vec::new();
    Encode::encode(key.public_key().key_data(), &mut pub_blob)
        .context("Failed to encode public key blob for PPK")?;

    let mut priv_blob = Zeroizing::new(Vec::new());
    match key.key_data() {
        KeypairData::Ed25519(kp) => {
            let mp = Mpint::from_positive_bytes(kp.private.as_ref());
            Encode::encode(&mp, &mut *priv_blob)
                .context("Failed to encode Ed25519 private blob")?;
        }
        KeypairData::Rsa(kp) => {
            Encode::encode(kp.private().d(), &mut *priv_blob)?;
            Encode::encode(kp.private().p(), &mut *priv_blob)?;
            Encode::encode(kp.private().q(), &mut *priv_blob)?;
            Encode::encode(kp.private().iqmp(), &mut *priv_blob)?;
        }
        KeypairData::Ecdsa(kp) => {
            let scalar_bytes = match kp {
                ssh_key::private::EcdsaKeypair::NistP256 { private, .. } => private.as_slice(),
                ssh_key::private::EcdsaKeypair::NistP384 { private, .. } => private.as_slice(),
                ssh_key::private::EcdsaKeypair::NistP521 { private, .. } => private.as_slice(),
            };
            let mp = Mpint::from_positive_bytes(scalar_bytes);
            Encode::encode(&mp, &mut *priv_blob).context("Failed to encode ECDSA private blob")?;
        }
        KeypairData::Dsa(kp) => {
            Encode::encode(kp.private(), &mut *priv_blob)?;
        }
        _ => anyhow::bail!("Unsupported key algorithm for .ppk export"),
    }

    let mut mac_buffer = Zeroizing::new(Vec::new());
    Encode::encode(&alg_str.as_bytes(), &mut *mac_buffer)?;
    Encode::encode(&b"none".as_slice(), &mut *mac_buffer)?;
    Encode::encode(&comment.as_bytes(), &mut *mac_buffer)?;
    Encode::encode(&pub_blob, &mut *mac_buffer)?;
    Encode::encode(&*priv_blob, &mut *mac_buffer)?;

    let mut hmac = Hmac::<Sha256>::new_from_slice(&[])
        .map_err(|_| anyhow::anyhow!("Failed to initialize HMAC-SHA256"))?;
    hmac.update(&mac_buffer);
    let mac_hex = hex::encode(hmac.finalize().into_bytes());

    let b64_engine = base64::engine::general_purpose::STANDARD;
    let pub_b64_lines = wrap_base64_lines(&b64_engine.encode(&pub_blob), 64);
    let mut priv_b64_encoded = Zeroizing::new(b64_engine.encode(&*priv_blob));
    let mut priv_b64_lines = wrap_base64_lines(&priv_b64_encoded, 64);
    priv_b64_encoded.zeroize();

    let mut out = String::new();
    out.push_str(&format!("PuTTY-User-Key-File-3: {alg_str}\r\n"));
    out.push_str("Encryption: none\r\n");
    out.push_str(&format!("Comment: {comment}\r\n"));
    out.push_str(&format!("Public-Lines: {}\r\n", pub_b64_lines.len()));
    for l in &pub_b64_lines {
        out.push_str(l);
        out.push_str("\r\n");
    }
    out.push_str(&format!("Private-Lines: {}\r\n", priv_b64_lines.len()));
    for l in &mut priv_b64_lines {
        out.push_str(l);
        out.push_str("\r\n");
        l.zeroize();
    }
    out.push_str(&format!("Private-MAC: {mac_hex}\r\n"));

    Ok(out)
}

/// Exports a `PrivateKey` to OpenSSH PEM format (`-----BEGIN OPENSSH PRIVATE KEY-----`).
pub fn export_to_openssh_pem(key: &PrivateKey) -> Result<String> {
    let openssh_doc = key
        .to_openssh(ssh_key::LineEnding::LF)
        .context("Failed to encode key in OpenSSH format")?;
    Ok(openssh_doc.to_string())
}

pub fn format_openssh_pubkey(pubkey: &PublicKey) -> String {
    let alg = pubkey.algorithm().to_string();
    let b64 = pubkey.public_key_base64();
    let comment = pubkey.comment();
    if comment.is_empty() {
        format!("{alg} {b64}")
    } else {
        format!("{alg} {b64} {comment}")
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

/// Resolves the path to `pageant.exe` or `kageant.exe` using configured path, provided hints,
/// standard install directories, KiTTY paths, and the system PATH.
pub fn resolve_pageant_executable_with_hints(
    configured_path: &str,
    hints: &[&str],
) -> Option<PathBuf> {
    // 1. Direct configured path if valid
    let trimmed = configured_path.trim();
    if !trimmed.is_empty() {
        let p = PathBuf::from(trimmed);
        if p.exists() {
            return Some(p);
        }
    }

    // 2. Check hints (directory, file parent, grandparent) for pageant.exe / kageant.exe
    for hint in hints {
        let h_trim = hint.trim();
        if h_trim.is_empty() {
            continue;
        }
        let hint_path = PathBuf::from(h_trim);
        let mut dirs_to_check = Vec::new();
        if hint_path.is_dir() {
            dirs_to_check.push(hint_path.clone());
        } else if let Some(parent) = hint_path.parent() {
            dirs_to_check.push(parent.to_path_buf());
            if let Some(grandparent) = parent.parent() {
                dirs_to_check.push(grandparent.to_path_buf());
            }
        }
        for dir in dirs_to_check {
            for exe_name in ["pageant.exe", "kageant.exe"] {
                let candidate = dir.join(exe_name);
                if candidate.exists() {
                    return Some(candidate);
                }
            }
        }
    }

    // 3. Known standard & portable paths
    let standard_candidates = [
        r"C:\Program Files\PuTTY\pageant.exe",
        r"C:\Program Files (x86)\PuTTY\pageant.exe",
        r"C:\Program Files\KiTTY\pageant.exe",
        r"C:\Program Files (x86)\KiTTY\pageant.exe",
        r"C:\Program Files\KiTTY\kageant.exe",
        r"C:\Program Files (x86)\KiTTY\kageant.exe",
        r"D:\Doc\Kitty\pageant.exe",
        r"C:\Tools\kitty\pageant.exe",
        r"C:\Tools\putty\pageant.exe",
        r"D:\Tools\kitty\pageant.exe",
        r"D:\Tools\putty\pageant.exe",
        r"C:\Program Files\TortoiseGit\bin\pageant.exe",
        r"C:\Program Files\Git\usr\bin\pageant.exe",
    ];
    for c in standard_candidates {
        let p = PathBuf::from(c);
        if p.exists() {
            return Some(p);
        }
    }

    // 4. Check PATH environment variable
    if let Ok(path_var) = std::env::var("PATH") {
        for dir in std::env::split_paths(&path_var) {
            for exe_name in ["pageant.exe", "kageant.exe"] {
                let p = dir.join(exe_name);
                if p.exists() {
                    return Some(p);
                }
            }
        }
    }

    // 5. Check next to current executable
    if let Ok(exe) = std::env::current_exe()
        && let Some(dir) = exe.parent()
    {
        for exe_name in ["pageant.exe", "kageant.exe"] {
            let p = dir.join(exe_name);
            if p.exists() {
                return Some(p);
            }
            if let Some(parent) = dir.parent() {
                let p2 = parent.join(exe_name);
                if p2.exists() {
                    return Some(p2);
                }
            }
        }
    }

    None
}

/// Resolves the path to `pageant.exe`, prioritizing `configured_path` then standard paths.
/// Per-agent diagnostic for the key list query. An empty key list is ambiguous
/// ("no keys loaded" vs "agent unreachable") — this carries the why.
#[derive(Debug, Clone, Default)]
pub struct AgentProbeReport {
    /// Pageant hidden window visible in this session (WM-message transport probe).
    pub pageant_running: bool,
    /// Pageant connect/query failure, when the agent is visible but the query failed.
    pub pageant_error: Option<String>,
    /// Windows OpenSSH Agent connect/query failure (pipe absent when service stopped).
    pub openssh_error: Option<String>,
}

/// Queries the integrated Cuty Agent and the external fallback agents
/// (pageant.exe window, Windows OpenSSH Agent) to list all public keys
/// currently loaded in memory, plus a diagnostic report for honest status
/// rendering. When Cuty Agent answers, the Pageant probe is skipped: the
/// hidden "Pageant" window then belongs to cuty-ssh itself, so probing it
/// would list the very same keys twice.
pub async fn list_agent_keys(
    check_native: bool,
    check_pageant: bool,
    check_openssh: bool,
) -> (Vec<AgentKeyEntry>, AgentProbeReport) {
    let mut entries = Vec::new();
    let mut report = AgentProbeReport::default();

    #[cfg(windows)]
    {
        let mut native_reachable = false;
        if check_native
            && let Ok(mut agent) = russh::keys::agent::client::AgentClient::connect_named_pipe(
                crate::ssh::agent_server::pipe_name(),
            )
            .await
        {
            native_reachable = true;
            match agent.request_identities().await {
                Ok(identities) => {
                    for id in identities {
                        let pubkey = id.public_key();
                        entries.push(AgentKeyEntry {
                            algorithm: pubkey.algorithm().to_string(),
                            fingerprint_sha256: pubkey.fingerprint(HashAlg::Sha256).to_string(),
                            comment: id.comment().to_string(),
                            openssh_public_key: format_openssh_pubkey(&pubkey),
                            source_agent: "Cuty Agent (intégré)".to_string(),
                        });
                    }
                }
                Err(e) => {
                    tracing::warn!("native agent query failed: {e}");
                }
            }
        }

        if check_pageant && !native_reachable {
            report.pageant_running = pageant::wmmessage::is_pageant_running();
            match russh::keys::agent::client::AgentClient::connect_pageant().await {
                Ok(mut agent) => match agent.request_identities().await {
                    Ok(identities) => {
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
                    Err(e) => report.pageant_error = Some(format!("request: {e}")),
                },
                Err(e) => report.pageant_error = Some(format!("connect: {e}")),
            }
        }

        if check_openssh {
            match russh::keys::agent::client::AgentClient::connect_named_pipe(
                r"\\.\pipe\openssh-ssh-agent",
            )
            .await
            {
                Ok(mut agent) => match agent.request_identities().await {
                    Ok(identities) => {
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
                    Err(e) => report.openssh_error = Some(format!("request: {e}")),
                },
                // Service stopped = pipe absent; normal state, keep quiet unless asked.
                Err(e) => report.openssh_error = Some(format!("connect: {e}")),
            }
        }
    }

    #[cfg(not(windows))]
    let _ = (check_native, check_pageant, check_openssh);

    (entries, report)
}

/// Reads the executable's embedded FileVersion version resource (e.g. PuTTY's
/// « Release 0.78 ») through the Windows version APIs — a pure metadata probe:
/// the file is never launched. Returns None when the file is unreadable or
/// carries no version info.
#[cfg(windows)]
pub fn query_exe_file_version(path: &Path) -> Option<String> {
    use windows_sys::Win32::Storage::FileSystem::{
        GetFileVersionInfoSizeW, GetFileVersionInfoW, VerQueryValueW,
    };

    let wide: Vec<u16> = path
        .as_os_str()
        .to_string_lossy()
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();
    unsafe {
        let size = GetFileVersionInfoSizeW(wide.as_ptr(), std::ptr::null_mut());
        if size == 0 {
            return None;
        }
        let mut data = vec![0u8; size as usize];
        if GetFileVersionInfoW(wide.as_ptr(), 0, size, data.as_mut_ptr() as *mut _) == 0 {
            return None;
        }

        // Resolves a \Block\ path inside the version resource; the returned
        // pointer aliases `data`, which outlives every use below.
        let query_ptr = |subblock: &str| -> Option<(*const u8, u32)> {
            let key: Vec<u16> = subblock.encode_utf16().chain(std::iter::once(0)).collect();
            let mut ptr: *mut std::ffi::c_void = std::ptr::null_mut();
            let mut len = 0u32;
            if VerQueryValueW(data.as_ptr() as *const _, key.as_ptr(), &mut ptr, &mut len) != 0
                && !ptr.is_null()
            {
                Some((ptr as *const u8, len))
            } else {
                None
            }
        };

        // Language/code page pairs actually embedded in the resource.
        let mut lang_keys: Vec<String> = match query_ptr("\\VarFileInfo\\Translation") {
            Some((ptr, len)) => {
                let bytes = std::slice::from_raw_parts(ptr, len as usize);
                bytes
                    .as_chunks::<4>()
                    .0
                    .iter()
                    .map(|c| {
                        let lang = u16::from_le_bytes([c[0], c[1]]);
                        let codepage = u16::from_le_bytes([c[2], c[3]]);
                        format!("\\StringFileInfo\\{lang:04x}{codepage:04x}\\FileVersion")
                    })
                    .collect()
            }
            None => Vec::new(),
        };
        // Common US-English fallbacks (Unicode then ANSI code page).
        lang_keys.push("\\StringFileInfo\\040904b0\\FileVersion".to_string());
        lang_keys.push("\\StringFileInfo\\040904e4\\FileVersion".to_string());

        for key in lang_keys {
            if let Some((ptr, _)) = query_ptr(&key) {
                let mut units: Vec<u16> = Vec::new();
                let mut i = 0;
                loop {
                    let u = *(ptr as *const u16).add(i);
                    if u == 0 || i > 512 {
                        break;
                    }
                    units.push(u);
                    i += 1;
                }
                let s = String::from_utf16_lossy(&units).trim().to_string();
                if !s.is_empty() {
                    return Some(s);
                }
            }
        }
    }
    None
}

#[cfg(not(windows))]
pub fn query_exe_file_version(_path: &Path) -> Option<String> {
    None
}

/// Resolves the user's Primary SSH Key from `configured_primary_path` or standard fallback locations,
/// or automatically generates a new Ed25519 Primary Key (`cuty-ssh-portable/keys/id_cuty_primary.ppk`)
/// if none exists yet. Returns `(private_key_path, KeyInspection, newly_generated)`.
pub fn resolve_or_create_primary_key(
    configured_primary_path: &str,
) -> Result<(PathBuf, KeyInspection, bool)> {
    let trimmed = configured_primary_path.trim();
    if !trimmed.is_empty() {
        let p = PathBuf::from(trimmed);
        if p.exists()
            && let Ok(info) = inspect_key_file(&p)
            && !info.openssh_public_key.is_empty()
        {
            return Ok((p, info, false));
        }
    }

    let mut candidates = vec![
        PathBuf::from("cuty-ssh-portable")
            .join("keys")
            .join("id_cuty_primary.ppk"),
    ];
    if let Ok(profile) = std::env::var("USERPROFILE") {
        let ssh_dir = PathBuf::from(profile).join(".ssh");
        candidates.push(ssh_dir.join("id_ed25519"));
        candidates.push(ssh_dir.join("id_rsa"));
    }

    for cand in candidates {
        if cand.exists()
            && let Ok(info) = inspect_key_file(&cand)
            && !info.openssh_public_key.is_empty()
        {
            return Ok((cand, info, false));
        }
    }

    // Automatically generate a fresh Ed25519 Primary Key in cuty-ssh-portable/keys/
    let keys_dir = PathBuf::from("cuty-ssh-portable").join("keys");
    fs::create_dir_all(&keys_dir)
        .context("Failed to create cuty-ssh-portable/keys directory for Primary Key")?;
    let user = std::env::var("USERNAME").unwrap_or_else(|_| "admin".to_string());
    let comment = format!("{user}@cuty-ssh-primary");
    let priv_key = generate_new_ssh_key("ed25519", &comment)?;
    let ppk_str = export_to_ppk_v3(&priv_key, &comment)?;
    let openssh_pem = export_to_openssh_pem(&priv_key)?;
    let pub_line = format_openssh_pubkey(priv_key.public_key());

    let ppk_path = keys_dir.join("id_cuty_primary.ppk");
    let pem_path = keys_dir.join("id_cuty_primary");
    let pub_path = keys_dir.join("id_cuty_primary.pub");

    fs::write(&ppk_path, &ppk_str)?;
    let _ = fs::write(&pem_path, &openssh_pem);
    let _ = fs::write(&pub_path, format!("{pub_line}\n"));

    let info = inspect_key_file(&ppk_path)?;
    Ok((ppk_path, info, true))
}

/// Builds a safe, idempotent POSIX shell command (`ssh-copy-id` equivalent) that installs
/// `openssh_pubkey` into `~/.ssh/authorized_keys` with strict `700`/`600` permissions without
/// duplicating existing keys.
pub fn build_ssh_copy_id_script(openssh_pubkey: &str) -> Result<String> {
    let clean = openssh_pubkey
        .lines()
        .map(str::trim)
        .find(|l| !l.is_empty() && !l.starts_with('#'))
        .unwrap_or("")
        .trim();

    if clean.is_empty() || (!clean.starts_with("ssh-") && !clean.starts_with("ecdsa-")) {
        anyhow::bail!(
            "Format de clé publique OpenSSH invalide (attendu: ssh-ed25519 / ssh-rsa / ecdsa-...)"
        );
    }

    // Escape single quotes for safe single-quoted POSIX shell embedding
    let escaped = clean.replace('\'', "'\\''");
    let script = format!(
        "umask 077 && mkdir -p ~/.ssh && chmod 700 ~/.ssh && touch ~/.ssh/authorized_keys && chmod 600 ~/.ssh/authorized_keys && if grep -qxF '{escaped}' ~/.ssh/authorized_keys 2>/dev/null; then echo CUTY_SSH_KEY_ALREADY_PRESENT; else printf '\\n%s\\n' '{escaped}' >> ~/.ssh/authorized_keys && chmod 600 ~/.ssh/authorized_keys && echo CUTY_SSH_KEY_INSTALLED_OK; fi"
    );
    Ok(script)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_exe_version_probe_reads_system_binary_and_rejects_missing() {
        // A Windows system binary always carries a version resource.
        let notepad = std::path::Path::new(r"C:\Windows\System32\notepad.exe");
        if notepad.exists() {
            let version = query_exe_file_version(notepad);
            assert!(version.is_some(), "notepad.exe must expose a FileVersion");
            assert!(!version.unwrap().trim().is_empty());
        }
        assert!(
            query_exe_file_version(std::path::Path::new(
                r"C:\definitely\missing\cuty-probe.exe"
            ))
            .is_none()
        );
    }

    #[test]
    fn test_resolve_pageant_executable_with_hints_finds_in_key_dir() {
        let temp_dir =
            std::env::temp_dir().join(format!("cuty_test_pageant_{}", uuid::Uuid::new_v4()));
        let sub_key_dir = temp_dir.join("key");
        fs::create_dir_all(&sub_key_dir).unwrap();

        let fake_pageant = temp_dir.join("pageant.exe");
        fs::write(&fake_pageant, b"MZ").unwrap();

        let fake_key = sub_key_dir.join("test.ppk");
        fs::write(&fake_key, b"fake ppk").unwrap();

        let resolved = resolve_pageant_executable_with_hints(
            r"C:\NonExistent\pageant.exe",
            &[fake_key.to_str().unwrap()],
        );

        assert_eq!(resolved, Some(fake_pageant));
        let _ = fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_resolve_pageant_executable_direct_valid_path() {
        let temp_dir =
            std::env::temp_dir().join(format!("cuty_test_pageant_direct_{}", uuid::Uuid::new_v4()));
        fs::create_dir_all(&temp_dir).unwrap();
        let fake_pageant = temp_dir.join("custom_pageant.exe");
        fs::write(&fake_pageant, b"MZ").unwrap();

        let resolved = resolve_pageant_executable_with_hints(fake_pageant.to_str().unwrap(), &[]);

        assert_eq!(resolved, Some(fake_pageant));
        let _ = fs::remove_dir_all(&temp_dir);
    }
}
