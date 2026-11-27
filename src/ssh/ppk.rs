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
use zeroize::{Zeroize, Zeroizing};

/// Maximum key file size read into memory (512 KiB).
const MAX_KEY_FILE_BYTES: u64 = 512 * 1024;
/// Maximum `Public-Lines` count accepted in a `.ppk` header.
const MAX_PPK_LINES: usize = 1024;
/// Maximum Argon2 memory (256 MiB in KiB) accepted when decoding untrusted `.ppk` v3 files.
const MAX_PPK_ARGON2_MEMORY_KIB: u64 = 262_144;
/// Maximum Argon2 passes accepted when decoding untrusted `.ppk` v3 files.
const MAX_PPK_ARGON2_PASSES: u64 = 100;

/// Fills `dst` with cryptographically secure random bytes from the OS CSPRNG.
pub(crate) fn fill_os_random(dst: &mut [u8]) -> Result<()> {
    #[cfg(windows)]
    {
        use windows_sys::Win32::Security::Cryptography::{
            BCRYPT_USE_SYSTEM_PREFERRED_RNG, BCryptGenRandom,
        };
        let len = u32::try_from(dst.len()).context("random buffer too large")?;
        let status = unsafe {
            BCryptGenRandom(
                std::ptr::null_mut(),
                dst.as_mut_ptr(),
                len,
                BCRYPT_USE_SYSTEM_PREFERRED_RNG,
            )
        };
        if status != 0 {
            anyhow::bail!("BCryptGenRandom failed with NTSTATUS 0x{status:08x}");
        }
        Ok(())
    }
    #[cfg(not(windows))]
    {
        use std::io::Read;
        let mut f = fs::File::open("/dev/urandom").context("Failed to open /dev/urandom")?;
        f.read_exact(dst)
            .context("Failed to read OS random bytes")?;
        Ok(())
    }
}

/// Writes private key material to `path` with an explicit owner-only NTFS DACL
/// (`D:P(A;;FA;;;{current_user_sid})`) on Windows so other local accounts cannot read it.
pub fn write_private_key_file(path: &Path, content: &[u8]) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    #[cfg(windows)]
    {
        use std::io::Write;
        use std::os::windows::io::FromRawHandle;
        use windows_sys::Win32::Foundation::{INVALID_HANDLE_VALUE, LocalFree};
        use windows_sys::Win32::Security::Authorization::{
            ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
        };
        use windows_sys::Win32::Security::{PSECURITY_DESCRIPTOR, SECURITY_ATTRIBUTES};
        use windows_sys::Win32::Storage::FileSystem::{
            CREATE_ALWAYS, CreateFileW, FILE_ATTRIBUTE_NORMAL,
        };

        const WIN32_GENERIC_WRITE: u32 = 0x4000_0000;

        let sid = crate::ssh::agent_server::current_user_sid_string().ok_or_else(|| {
            anyhow::anyhow!("Failed to resolve current user SID for private key ACL")
        })?;
        let sddl = format!("D:P(A;;FA;;;{sid})");
        let sddl_w: Vec<u16> = sddl.encode_utf16().chain(std::iter::once(0)).collect();
        let path_w: Vec<u16> = path
            .as_os_str()
            .to_string_lossy()
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect();

        // Remove any preexisting file first so inherited ACLs cannot persist on overwrite.
        let _ = fs::remove_file(path);

        let handle = unsafe {
            let mut sd: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
            if ConvertStringSecurityDescriptorToSecurityDescriptorW(
                sddl_w.as_ptr(),
                SDDL_REVISION_1,
                &mut sd,
                std::ptr::null_mut(),
            ) == 0
                || sd.is_null()
            {
                return Err(anyhow::anyhow!(
                    "Failed to build owner-only DACL for {}: {}",
                    path.display(),
                    std::io::Error::last_os_error()
                ));
            }
            let sa = SECURITY_ATTRIBUTES {
                nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
                lpSecurityDescriptor: sd.cast(),
                bInheritHandle: 0,
            };
            let h = CreateFileW(
                path_w.as_ptr(),
                WIN32_GENERIC_WRITE,
                0,
                &sa,
                CREATE_ALWAYS,
                FILE_ATTRIBUTE_NORMAL,
                std::ptr::null_mut(),
            );
            let _ = LocalFree(sd as _);
            h
        };
        if handle == INVALID_HANDLE_VALUE {
            return Err(anyhow::anyhow!(
                "Failed to create private key file {}: {}",
                path.display(),
                std::io::Error::last_os_error()
            ));
        }
        let mut file = unsafe { fs::File::from_raw_handle(handle as _) };
        file.write_all(content)?;
        file.sync_all()?;
        Ok(())
    }
    #[cfg(not(windows))]
    {
        fs::write(path, content)?;
        Ok(())
    }
}

fn read_bounded_key_file(path: &Path) -> Result<Zeroizing<String>> {
    let meta = fs::metadata(path).with_context(|| format!("Failed to stat key file {:?}", path))?;
    if meta.len() > MAX_KEY_FILE_BYTES {
        anyhow::bail!(
            "Key file {:?} exceeds maximum allowed size ({} bytes)",
            path,
            MAX_KEY_FILE_BYTES
        );
    }
    Ok(Zeroizing::new(fs::read_to_string(path).with_context(
        || format!("Failed to read key file {:?}", path),
    )?))
}

fn validate_ppk_kdf_limits(normalized: &str) -> Result<()> {
    if !normalized.starts_with("PuTTY-User-Key-File-") {
        return Ok(());
    }
    for line in normalized.lines().take(64) {
        if let Some((k, v)) = line.split_once(':') {
            match k.trim() {
                "Argon2-Memory" => {
                    let mem = v
                        .trim()
                        .parse::<u64>()
                        .context("Invalid Argon2-Memory header in .ppk file")?;
                    if mem > MAX_PPK_ARGON2_MEMORY_KIB {
                        anyhow::bail!(
                            "Refusing .ppk file with excessive Argon2-Memory ({mem} KiB > {MAX_PPK_ARGON2_MEMORY_KIB} KiB)"
                        );
                    }
                }
                "Argon2-Passes" => {
                    let passes = v
                        .trim()
                        .parse::<u64>()
                        .context("Invalid Argon2-Passes header in .ppk file")?;
                    if passes > MAX_PPK_ARGON2_PASSES {
                        anyhow::bail!(
                            "Refusing .ppk file with excessive Argon2-Passes ({passes} > {MAX_PPK_ARGON2_PASSES})"
                        );
                    }
                }
                _ => {}
            }
        }
    }
    Ok(())
}

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
    let raw = read_bounded_key_file(path)?;
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
                            for pline in lines.by_ref().take(n.min(MAX_PPK_LINES)) {
                                pub_b64.push_str(pline.trim());
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
    let raw = read_bounded_key_file(path)?;
    decode_private_key_any(&raw, passphrase)
}

/// Decodes a private key from text content (`.ppk` v2/v3, OpenSSH, PEM, or PKCS#8).
pub fn decode_private_key_any(raw: &str, passphrase: Option<&str>) -> Result<PrivateKey> {
    let normalized = Zeroizing::new(raw.replace("\r\n", "\n"));
    validate_ppk_kdf_limits(&normalized)?;
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

/// Generates a new Ed25519 SSH keypair using uniform OS CSPRNG bytes.
pub fn generate_new_ssh_key(_algorithm_choice: &str, comment: &str) -> Result<PrivateKey> {
    let mut seed = Zeroizing::new([0u8; 32]);
    fill_os_random(&mut *seed)?;

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
    // 16-byte OS CSPRNG salt and 16 bcrypt rounds match OpenSSH's ssh-keygen defaults.
    let mut salt = vec![0u8; 16];
    fill_os_random(&mut salt)?;
    let mut check = [0u8; 4];
    fill_os_random(&mut check)?;
    let checkint = u32::from_be_bytes(check);
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
/// Returns a `Zeroizing<String>` so plaintext private key material is wiped on drop.
pub fn export_to_ppk_v3(key: &PrivateKey, comment: &str) -> Result<Zeroizing<String>> {
    let alg = key.algorithm();
    let alg_str = alg.as_str();
    let clean_comment: String = comment
        .chars()
        .filter(|c| !matches!(c, '\r' | '\n' | '\0'))
        .collect();

    let mut pub_blob = Vec::new();
    Encode::encode(key.public_key().key_data(), &mut pub_blob)
        .context("Failed to encode public key blob for PPK")?;

    let mut priv_blob = Zeroizing::new(Vec::new());
    match key.key_data() {
        KeypairData::Ed25519(kp) => {
            // PuTTY PPK v3 encodes the Ed25519 private seed as a 32-byte SSH `string` (not `mpint`).
            Encode::encode(&kp.private.as_ref().as_slice(), &mut *priv_blob)
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
    Encode::encode(&clean_comment.as_bytes(), &mut *mac_buffer)?;
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

    let mut out = Zeroizing::new(String::new());
    out.push_str(&format!("PuTTY-User-Key-File-3: {alg_str}\r\n"));
    out.push_str("Encryption: none\r\n");
    out.push_str(&format!("Comment: {clean_comment}\r\n"));
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
/// Returns a `Zeroizing<String>` so plaintext private key material is wiped on drop.
pub fn export_to_openssh_pem(key: &PrivateKey) -> Result<Zeroizing<String>> {
    key.to_openssh(ssh_key::LineEnding::LF)
        .context("Failed to encode key in OpenSSH format")
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

    // 2. Check hints (directory, direct parent, or grandparent ONLY for portable `key`/`keys` subfolders)
    for hint in hints {
        let h_trim = hint.trim();
        if h_trim.is_empty() {
            continue;
        }
        let hint_path = PathBuf::from(h_trim);
        let mut dirs_to_check = Vec::new();
        if hint_path.is_dir() {
            dirs_to_check.push(hint_path);
        } else if let Some(parent) = hint_path.parent() {
            dirs_to_check.push(parent.to_path_buf());
            let is_key_subdir = parent
                .file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|n| n.eq_ignore_ascii_case("key") || n.eq_ignore_ascii_case("keys"));
            if is_key_subdir && let Some(grandparent) = parent.parent() {
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

    // 3. Known standard Program Files install paths only
    let standard_candidates = [
        r"C:\Program Files\PuTTY\pageant.exe",
        r"C:\Program Files (x86)\PuTTY\pageant.exe",
        r"C:\Program Files\KiTTY\pageant.exe",
        r"C:\Program Files (x86)\KiTTY\pageant.exe",
        r"C:\Program Files\KiTTY\kageant.exe",
        r"C:\Program Files (x86)\KiTTY\kageant.exe",
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

    // 5. Check next to current executable (same directory only)
    if let Ok(exe) = std::env::current_exe()
        && let Some(dir) = exe.parent()
    {
        for exe_name in ["pageant.exe", "kageant.exe"] {
            let p = dir.join(exe_name);
            if p.exists() {
                return Some(p);
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

        let data_start = data.as_ptr() as usize;
        let data_end = data_start + data.len();
        for key in lang_keys {
            if let Some((ptr, len)) = query_ptr(&key) {
                let addr = ptr as usize;
                if addr < data_start || addr >= data_end {
                    continue;
                }
                let avail_u16 = (data_end - addr) / std::mem::size_of::<u16>();
                let max_units = (len as usize).min(avail_u16).min(512);
                let mut units: Vec<u16> = Vec::with_capacity(max_units);
                for i in 0..max_units {
                    let u = std::ptr::read_unaligned((ptr as *const u16).add(i));
                    if u == 0 {
                        break;
                    }
                    units.push(u);
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

    let portable_keys_dir = crate::config::AppConfig::portable_dir().join("keys");
    let mut candidates = vec![portable_keys_dir.join("id_cuty_primary.ppk")];
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

    // Automatically generate a fresh Ed25519 Primary Key in portable_dir()/keys/
    let keys_dir = portable_keys_dir;
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

    write_private_key_file(&ppk_path, ppk_str.as_bytes())?;
    let _ = write_private_key_file(&pem_path, openssh_pem.as_bytes());
    let _ = fs::write(&pub_path, format!("{pub_line}\n"));

    let info = inspect_key_file(&ppk_path)?;
    Ok((ppk_path, info, true))
}

/// Builds a safe, idempotent POSIX shell command (`ssh-copy-id` equivalent) that installs
/// `openssh_pubkey` into `~/.ssh/authorized_keys` with strict `700`/`600` permissions without
/// duplicating existing keys.
///
/// Strictly parses the public key via `ssh_key::PublicKey::from_openssh` and sanitizes the
/// comment to `[A-Za-z0-9._@+-]` so untrusted keys/comments cannot inject shell commands.
pub fn build_ssh_copy_id_script(openssh_pubkey: &str) -> Result<String> {
    let raw_line = openssh_pubkey
        .lines()
        .map(str::trim)
        .find(|l| !l.is_empty() && !l.starts_with('#'))
        .unwrap_or("")
        .trim();

    if raw_line.is_empty() || raw_line.contains('\r') || raw_line.contains('\0') {
        anyhow::bail!(
            "Format de clé publique OpenSSH invalide (attendu: ssh-ed25519 / ssh-rsa / ecdsa-...)"
        );
    }

    let parsed = PublicKey::from_openssh(raw_line).map_err(|_| {
        anyhow::anyhow!(
            "Format de clé publique OpenSSH invalide (attendu: ssh-ed25519 / ssh-rsa / ecdsa-...)"
        )
    })?;
    let alg = parsed.algorithm().to_string();
    let b64 = parsed.public_key_base64();
    let safe_comment: String = parsed
        .comment()
        .as_str()
        .unwrap_or("")
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '@' | '+' | '-'))
        .take(128)
        .collect();
    let canonical = if safe_comment.is_empty() {
        format!("{alg} {b64}")
    } else {
        format!("{alg} {b64} {safe_comment}")
    };

    // `canonical` contains exclusively `[A-Za-z0-9+/= .@_+-]` — zero quotes, backslashes, or shell metacharacters.
    let script = format!(
        "umask 077 && mkdir -p ~/.ssh && chmod 700 ~/.ssh && touch ~/.ssh/authorized_keys && chmod 600 ~/.ssh/authorized_keys && if grep -qxF -- '{canonical}' ~/.ssh/authorized_keys 2>/dev/null; then echo CUTY_SSH_KEY_ALREADY_PRESENT; else printf '\\n%s\\n' '{canonical}' >> ~/.ssh/authorized_keys && chmod 600 ~/.ssh/authorized_keys && echo CUTY_SSH_KEY_INSTALLED_OK; fi"
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

    #[test]
    fn test_ppk_public_lines_huge_count_does_not_hang() {
        let crafted = "PuTTY-User-Key-File-3: ssh-ed25519\nEncryption: none\nPublic-Lines: 18446744073709551615\n";
        let info = inspect_key_content(crafted, "crafted.ppk").expect("should return promptly");
        assert_eq!(info.algorithm, "ssh-ed25519");
    }

    #[test]
    fn test_ppk_v3_ed25519_high_msb_roundtrip_and_comment_newline_strip() {
        let mut seed = [0xFFu8; 32];
        seed[31] = 0x42;
        let kp = Ed25519Keypair::from_seed(&seed);
        let key = PrivateKey::new(KeypairData::Ed25519(kp), "hi").unwrap();
        let ppk = export_to_ppk_v3(&key, "user\r\nPrivate-MAC: fake").unwrap();
        assert!(!ppk.lines().any(|l| l == "Private-MAC: fake"));
        assert_eq!(
            ppk.lines()
                .filter(|l| l.starts_with("Private-MAC:"))
                .count(),
            1
        );
        let decoded = decode_private_key_any(&ppk, None).expect("high-MSB Ed25519 PPK roundtrip");
        assert_eq!(
            decoded.public_key().fingerprint(HashAlg::Sha256),
            key.public_key().fingerprint(HashAlg::Sha256)
        );
    }

    #[test]
    fn test_ssh_copy_id_rejects_injection_and_sanitizes_comment() {
        let key = generate_new_ssh_key("ed25519", "ok").unwrap();
        let pub_b64 = key.public_key().public_key_base64();
        let malicious = format!("ssh-ed25519 {pub_b64} user\\'$(id);whoami");
        let script =
            build_ssh_copy_id_script(&malicious).expect("valid pubkey with sanitized comment");
        assert!(!script.contains("$("));
        assert!(!script.contains(";whoami"));
        assert!(!script.contains("\\'"));
        assert!(build_ssh_copy_id_script("ssh-ed25519 NOT_A_REAL_KEY").is_err());
        assert!(build_ssh_copy_id_script(&format!("ssh-ed25519 {pub_b64}\rid")).is_err());
    }
}
