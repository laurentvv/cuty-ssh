//! Native integrated SSH agent — a complete in-process Pageant replacement.
//!
//! cuty-ssh holds the decrypted keys in its own memory (never on disk) and serves
//! the standard ssh-agent wire protocol, so both cuty-ssh sessions and external
//! PuTTY/KiTTY/WinSCP clients can authenticate without `pageant.exe`.
//!
//! Protocol references (behaviour mirrored, not copied code):
//! - draft-miller-ssh-agent (message numbers, RSA SHA-2 signature flags)
//! - PuTTY `pageant.c` / `windows/pageant.c` (WM_COPYDATA transport semantics,
//!   "reject any flag bits we don't understand", owner-SID check on file mappings)
//!
//! Why a custom dispatcher instead of `russh::keys::agent::server::serve`:
//! the russh 0.64 server drops key comments in `IDENTITIES_ANSWER` and signs
//! RSA with SHA-1 regardless of the client's `SSH_AGENT_RSA_SHA2_*` flags, which
//! modern OpenSSH servers reject. This core keeps comments and honours the flags
//! through `ssh-key`'s `(&RsaKeypair, Option<HashAlg>)` signer.

use russh::keys::signature::Signer;
use russh::keys::ssh_encoding::{Decode, Encode};
use russh::keys::ssh_key::private::KeypairData;
use russh::keys::ssh_key::public::KeyData;
use russh::keys::ssh_key::{HashAlg, PrivateKey};
use std::sync::{Arc, RwLock};
use std::time::{Duration, SystemTime};
use zeroize::Zeroizing;

pub const SSH_AGENT_FAILURE: u8 = 5;
pub const SSH_AGENT_SUCCESS: u8 = 6;
pub const SSH2_AGENT_IDENTITIES_ANSWER: u8 = 12;
pub const SSH2_AGENT_SIGN_RESPONSE: u8 = 14;

pub const SSH2_AGENTC_REQUEST_IDENTITIES: u8 = 11;
pub const SSH2_AGENTC_SIGN_REQUEST: u8 = 13;
pub const SSH2_AGENTC_ADD_IDENTITY: u8 = 17;
pub const SSH2_AGENTC_REMOVE_IDENTITY: u8 = 18;
pub const SSH2_AGENTC_REMOVE_ALL_IDENTITIES: u8 = 19;
pub const SSH_AGENTC_LOCK: u8 = 22;
pub const SSH_AGENTC_UNLOCK: u8 = 23;
pub const SSH2_AGENTC_ADD_ID_CONSTRAINED: u8 = 25;

/// draft-miller-ssh-agent §7.3: ask for RSA-SHA256 signatures.
pub const SSH_AGENT_RSA_SHA2_256: u32 = 2;
/// draft-miller-ssh-agent §7.3: ask for RSA-SHA512 signatures.
pub const SSH_AGENT_RSA_SHA2_512: u32 = 4;

/// Same cap as russh's agent server and PuTTY's `AGENT_MAX_MSGLEN`.
pub const MAX_AGENT_FRAME_LEN: usize = 256 * 1024;

const CONSTRAIN_LIFETIME: u8 = 1;
const CONSTRAIN_CONFIRM: u8 = 2;

/// Wire-encoded public key blob — the protocol-level key handle.
fn public_blob(kd: &KeyData) -> Vec<u8> {
    let mut v = Vec::new();
    let _ = kd.encode(&mut v);
    v
}

/// Cloneable snapshot of one loaded key, for UI rendering.
#[derive(Debug, Clone)]
pub struct LoadedKeyInfo {
    pub algorithm: String,
    pub fingerprint_sha256: String,
    pub comment: String,
    pub source_path: String,
    /// Wire-encoded public key blob — the handle used to remove this key.
    pub blob: Vec<u8>,
}

struct LoadedKey {
    key: Arc<PrivateKey>,
    blob: Vec<u8>,
    comment: String,
    source_path: String,
    /// Lazy expiry deadline from a constrained ADD_IDENTITY (`ssh-add -t`).
    expires_at: Option<SystemTime>,
}

impl LoadedKey {
    fn info(&self) -> LoadedKeyInfo {
        let pk = self.key.public_key();
        LoadedKeyInfo {
            algorithm: pk.algorithm().to_string(),
            fingerprint_sha256: pk.fingerprint(HashAlg::Sha256).to_string(),
            comment: self.comment.clone(),
            source_path: self.source_path.clone(),
            blob: self.blob.clone(),
        }
    }
}

/// In-memory key vault + ssh-agent protocol dispatcher. Shared by every
/// transport (named pipe, WM_COPYDATA), so all clients see one key set.
pub struct NativeAgentCore {
    keys: RwLock<Vec<LoadedKey>>,
    /// Agent lock passphrase (pageant lock feature); empty = unlocked.
    lock_passphrase: RwLock<Zeroizing<Vec<u8>>>,
}

impl Default for NativeAgentCore {
    fn default() -> Self {
        Self::new()
    }
}

impl NativeAgentCore {
    pub fn new() -> Self {
        Self {
            keys: RwLock::new(Vec::new()),
            lock_passphrase: RwLock::new(Zeroizing::new(Vec::new())),
        }
    }

    pub fn is_locked(&self) -> bool {
        self.lock_passphrase
            .read()
            .map(|p| !p.is_empty())
            .unwrap_or(true)
    }

    /// Adds (or replaces, when the same public key is already loaded) a key.
    /// Returns whether an existing key was replaced.
    pub fn add_key(&self, key: PrivateKey, comment: &str, source_path: &str) -> bool {
        let blob = public_blob(key.public_key().key_data());
        if blob.is_empty() {
            return false;
        }
        let comment = if comment.is_empty() {
            key.public_key().comment().to_string()
        } else {
            comment.to_string()
        };
        let loaded = LoadedKey {
            key: Arc::new(key),
            blob,
            comment,
            source_path: source_path.to_string(),
            expires_at: None,
        };
        let mut keys = self.keys.write().unwrap_or_else(|e| e.into_inner());
        let replaced = keys.iter().position(|k| k.blob == loaded.blob).is_some();
        keys.retain(|k| k.blob != loaded.blob);
        keys.push(loaded);
        replaced
    }

    pub fn remove_by_blob(&self, blob: &[u8]) -> bool {
        let mut keys = self.keys.write().unwrap_or_else(|e| e.into_inner());
        let before = keys.len();
        keys.retain(|k| k.blob != blob);
        before != keys.len()
    }

    /// Drops every key from memory (private material is zeroized by `ssh-key`
    /// on drop). Returns how many keys were removed.
    pub fn remove_all(&self) -> usize {
        let mut keys = self.keys.write().unwrap_or_else(|e| e.into_inner());
        let count = keys.len();
        keys.clear();
        count
    }

    pub fn key_count(&self) -> usize {
        self.prune_expired();
        self.keys.read().map(|k| k.len()).unwrap_or(0)
    }

    pub fn list(&self) -> Vec<LoadedKeyInfo> {
        self.prune_expired();
        self.keys
            .read()
            .map(|k| k.iter().map(LoadedKey::info).collect())
            .unwrap_or_default()
    }

    fn prune_expired(&self) {
        let mut keys = match self.keys.write() {
            Ok(k) => k,
            Err(e) => e.into_inner(),
        };
        let now = SystemTime::now();
        let before = keys.len();
        keys.retain(|k| k.expires_at.is_none_or(|t| t > now));
        if before != keys.len() {
            tracing::debug!(
                "native agent: expired {} constrained key(s)",
                before - keys.len()
            );
        }
    }

    /// Processes one ssh-agent request payload (without the 4-byte length
    /// prefix) and returns the response payload. Never panics on malformed
    /// input — worst case it answers `SSH_AGENT_FAILURE`.
    pub fn process(&self, payload: &[u8]) -> Vec<u8> {
        let Some((&msg_type, rest)) = payload.split_first() else {
            return vec![SSH_AGENT_FAILURE];
        };
        let mut rest: &[u8] = rest;
        let mut out = Vec::with_capacity(64);
        // Everything but UNLOCK fails while the agent is locked (pageant and
        // russh server behaviour).
        let locked = self.is_locked();

        let ok = match msg_type {
            SSH2_AGENTC_REQUEST_IDENTITIES if !locked => self.handle_request_identities(&mut out),
            SSH2_AGENTC_SIGN_REQUEST if !locked => self.handle_sign_request(&mut rest, &mut out),
            SSH2_AGENTC_ADD_IDENTITY if !locked => {
                self.handle_add_identity(&mut rest, false, &mut out)
            }
            SSH2_AGENTC_ADD_ID_CONSTRAINED if !locked => {
                self.handle_add_identity(&mut rest, true, &mut out)
            }
            SSH2_AGENTC_REMOVE_IDENTITY if !locked => {
                self.handle_remove_identity(&mut rest, &mut out)
            }
            SSH2_AGENTC_REMOVE_ALL_IDENTITIES if !locked => self.handle_remove_all(&mut out),
            SSH_AGENTC_LOCK if !locked => match Zeroizing::new(decode_bytes(&mut rest)) {
                pass if !pass.is_empty() => {
                    *self
                        .lock_passphrase
                        .write()
                        .unwrap_or_else(|e| e.into_inner()) = pass;
                    out.push(SSH_AGENT_SUCCESS);
                    true
                }
                _ => false,
            },
            SSH_AGENTC_UNLOCK if self.is_locked() => {
                let attempt = Zeroizing::new(decode_bytes(&mut rest));
                let mut stored = self
                    .lock_passphrase
                    .write()
                    .unwrap_or_else(|e| e.into_inner());
                let matches = constant_time_eq(&attempt, &stored);
                if matches {
                    stored.clear();
                    out.push(SSH_AGENT_SUCCESS);
                } else {
                    out.push(SSH_AGENT_FAILURE);
                }
                true
            }
            // SSH1-era messages and anything unknown: not our message, mate.
            _ => false,
        };
        if !ok {
            out.clear();
            out.push(SSH_AGENT_FAILURE);
        }
        out
    }

    fn handle_request_identities(&self, out: &mut Vec<u8>) -> bool {
        self.prune_expired();
        let Ok(keys) = self.keys.read() else {
            return false;
        };
        out.push(SSH2_AGENT_IDENTITIES_ANSWER);
        let count = keys.len() as u32;
        let _ = count.encode(out);
        for k in keys.iter() {
            let _ = k.blob.encode(out);
            let _ = k.comment.as_bytes().encode(out);
        }
        true
    }

    fn handle_sign_request(&self, rest: &mut &[u8], out: &mut Vec<u8>) -> bool {
        let blob = decode_bytes(rest);
        let data = decode_bytes(rest);
        // "That hasn't always been there, so we don't complain if we don't
        // find it" — pageant.c: absent flags default to 0.
        let flags = u32::decode(rest).unwrap_or(0);

        let key = {
            self.prune_expired();
            let Ok(keys) = self.keys.read() else {
                return false;
            };
            let Some(k) = keys.iter().find(|k| k.blob == blob) else {
                return false;
            };
            k.key.clone()
        };

        let Some(signature) = sign_agent_request(&key, &data, flags) else {
            return false;
        };
        out.push(SSH2_AGENT_SIGN_RESPONSE);
        // SIGN_RESPONSE body = string(signature); the signature itself is the
        // standard string(alg) + string(blob) encoding, so it gets wrapped in
        // an outer length-prefixed string.
        let mut sig_buf = Vec::with_capacity(96);
        let _ = signature.encode(&mut sig_buf);
        let _ = sig_buf.encode(out);
        true
    }

    fn handle_add_identity(&self, rest: &mut &[u8], constrained: bool, out: &mut Vec<u8>) -> bool {
        let Ok(key_data) = KeypairData::decode(rest) else {
            return false;
        };
        let Ok(comment) = String::decode(rest) else {
            return false;
        };
        let mut expires_at = None;
        if constrained {
            // Lifetime seconds schedule a lazy expiry; confirm constraints are
            // accepted but auto-confirmed (same policy as russh's agent server).
            while let Ok(tag) = u8::decode(rest) {
                match tag {
                    CONSTRAIN_LIFETIME => {
                        let Ok(seconds) = u32::decode(rest) else {
                            return false;
                        };
                        expires_at =
                            SystemTime::now().checked_add(Duration::from_secs(seconds as u64));
                    }
                    CONSTRAIN_CONFIRM => {}
                    _ => return false,
                }
            }
        }
        let Ok(key) = PrivateKey::new(key_data, comment.clone()) else {
            return false;
        };
        let blob = public_blob(key.public_key().key_data());
        if blob.is_empty() {
            return false;
        }
        let loaded = LoadedKey {
            key: Arc::new(key),
            blob,
            comment,
            source_path: String::new(),
            expires_at,
        };
        let mut keys = self.keys.write().unwrap_or_else(|e| e.into_inner());
        keys.retain(|k| k.blob != loaded.blob);
        keys.push(loaded);
        out.push(SSH_AGENT_SUCCESS);
        true
    }

    fn handle_remove_identity(&self, rest: &mut &[u8], out: &mut Vec<u8>) -> bool {
        let blob = decode_bytes(rest);
        let removed = self.remove_by_blob(&blob);
        out.push(if removed {
            SSH_AGENT_SUCCESS
        } else {
            SSH_AGENT_FAILURE
        });
        true
    }

    fn handle_remove_all(&self, out: &mut Vec<u8>) -> bool {
        self.remove_all();
        out.push(SSH_AGENT_SUCCESS);
        true
    }
}

/// Maps draft-miller signature flags to an RSA hash, rejecting unknown bits —
/// "We MUST reject any message containing flags we don't understand" (pageant.c).
fn rsa_hash_from_flags(algorithm: &russh::keys::Algorithm, flags: u32) -> Option<Option<HashAlg>> {
    let russh::keys::Algorithm::Rsa { .. } = algorithm else {
        // Non-RSA keys carry no flags today; unknown bits are still rejected.
        return (flags == 0).then_some(None);
    };
    match flags {
        0 => Some(None), // legacy ssh-rsa / SHA-1
        SSH_AGENT_RSA_SHA2_256 => Some(Some(HashAlg::Sha256)),
        SSH_AGENT_RSA_SHA2_512 => Some(Some(HashAlg::Sha512)),
        _ => None,
    }
}

fn sign_agent_request(
    key: &PrivateKey,
    data: &[u8],
    flags: u32,
) -> Option<russh::keys::ssh_key::Signature> {
    let hash = rsa_hash_from_flags(&key.algorithm(), flags)?;
    let kd = key.key_data();
    match kd {
        KeypairData::Rsa(rsa) => {
            // Explicit hash so SSH_AGENT_RSA_SHA2_* flags are honoured;
            // `None` falls back to legacy ssh-rsa (SHA-1) like pageant.c.
            let pair = (rsa, hash);
            Signer::try_sign(&pair, data).ok()
        }
        other => Signer::try_sign(other, data).ok(),
    }
}

fn decode_bytes(r: &mut &[u8]) -> Vec<u8> {
    <Vec<u8> as Decode>::decode(r).unwrap_or_default()
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ssh::ppk::generate_new_ssh_key;

    fn frame(payload: &[u8]) -> Vec<u8> {
        let mut f = Vec::with_capacity(4 + payload.len());
        f.extend_from_slice(&(payload.len() as u32).to_be_bytes());
        f.extend_from_slice(payload);
        f
    }

    fn add_ed25519_wire(core: &NativeAgentCore, comment: &str) {
        let key = generate_new_ssh_key("ed25519", comment).unwrap();
        let mut body = vec![SSH2_AGENTC_ADD_IDENTITY];
        Encode::encode(key.key_data(), &mut body).unwrap();
        Encode::encode(comment.as_bytes(), &mut body).unwrap();
        let resp = core.process(&frame(&body)[4..]);
        assert_eq!(resp, vec![SSH_AGENT_SUCCESS]);
    }

    #[test]
    fn empty_agent_lists_zero_identities() {
        let core = NativeAgentCore::new();
        let resp = core.process(&[SSH2_AGENTC_REQUEST_IDENTITIES]);
        assert_eq!(resp[0], SSH2_AGENT_IDENTITIES_ANSWER);
        assert_eq!(&resp[1..5], &0u32.to_be_bytes());
    }

    #[test]
    fn add_and_list_preserves_comment() {
        let core = NativeAgentCore::new();
        add_ed25519_wire(&core, "test@cuty");
        let resp = core.process(&[SSH2_AGENTC_REQUEST_IDENTITIES]);
        assert_eq!(resp[0], SSH2_AGENT_IDENTITIES_ANSWER);
        assert_eq!(&resp[1..5], &1u32.to_be_bytes());
        let rest = &resp[5..];
        let mut r: &[u8] = rest;
        let blob = <Vec<u8> as Decode>::decode(&mut r).unwrap();
        let comment = String::decode(&mut r).unwrap();
        assert!(!blob.is_empty());
        assert_eq!(comment, "test@cuty");
    }

    #[test]
    fn sign_request_roundtrip_verifies() {
        let core = NativeAgentCore::new();
        let key = generate_new_ssh_key("ed25519", "sign-test").unwrap();
        core.add_key(key.clone(), "sign-test", "memory");
        let blob = public_blob(key.public_key().key_data());

        let mut body = vec![SSH2_AGENTC_SIGN_REQUEST];
        Encode::encode(&blob, &mut body).unwrap();
        Encode::encode(b"auth payload".as_slice(), &mut body).unwrap();
        Encode::encode(&0u32, &mut body).unwrap();
        let resp = core.process(&body);
        assert_eq!(resp[0], SSH2_AGENT_SIGN_RESPONSE);
        let mut r: &[u8] = &resp[1..];
        let sig_bytes = <Vec<u8> as Decode>::decode(&mut r).unwrap();
        let sig = russh::keys::ssh_key::Signature::decode(&mut sig_bytes.as_slice()).unwrap();
        use russh::keys::signature::Verifier;
        key.public_key()
            .key_data()
            .verify(b"auth payload", &sig)
            .expect("signature must verify");
    }

    #[test]
    fn rsa_flags_mapping_rejects_unknown_bits() {
        use russh::keys::Algorithm;
        let rsa = Algorithm::Rsa { hash: None };
        assert_eq!(rsa_hash_from_flags(&rsa, 0), Some(None));
        assert_eq!(
            rsa_hash_from_flags(&rsa, SSH_AGENT_RSA_SHA2_256),
            Some(Some(HashAlg::Sha256))
        );
        assert_eq!(
            rsa_hash_from_flags(&rsa, SSH_AGENT_RSA_SHA2_512),
            Some(Some(HashAlg::Sha512))
        );
        assert_eq!(rsa_hash_from_flags(&rsa, 8), None);
        assert_eq!(rsa_hash_from_flags(&rsa, 2 | 4), None);
        let ed = Algorithm::Ed25519;
        assert_eq!(rsa_hash_from_flags(&ed, 0), Some(None));
        assert_eq!(rsa_hash_from_flags(&ed, 2), None);
    }

    #[test]
    fn lock_blocks_operations_until_unlock() {
        let core = NativeAgentCore::new();
        add_ed25519_wire(&core, "locked");
        let mut lock = vec![SSH_AGENTC_LOCK];
        Encode::encode(b"secret".as_slice(), &mut lock).unwrap();
        assert_eq!(core.process(&lock), vec![SSH_AGENT_SUCCESS]);
        assert!(core.is_locked());
        assert_eq!(
            core.process(&[SSH2_AGENTC_REQUEST_IDENTITIES]),
            vec![SSH_AGENT_FAILURE]
        );

        let mut bad = vec![SSH_AGENTC_UNLOCK];
        Encode::encode(b"wrong".as_slice(), &mut bad).unwrap();
        assert_eq!(core.process(&bad), vec![SSH_AGENT_FAILURE]);

        let mut good = vec![SSH_AGENTC_UNLOCK];
        Encode::encode(b"secret".as_slice(), &mut good).unwrap();
        assert_eq!(core.process(&good), vec![SSH_AGENT_SUCCESS]);
        assert!(!core.is_locked());
    }

    #[test]
    fn remove_identity_and_remove_all() {
        let core = NativeAgentCore::new();
        let k1 = generate_new_ssh_key("ed25519", "k1").unwrap();
        core.add_key(k1.clone(), "k1", "a");
        let blob = public_blob(k1.public_key().key_data());
        assert_eq!(core.key_count(), 1);

        let mut rm = vec![SSH2_AGENTC_REMOVE_IDENTITY];
        Encode::encode(&blob, &mut rm).unwrap();
        assert_eq!(core.process(&rm), vec![SSH_AGENT_SUCCESS]);
        assert_eq!(core.key_count(), 0);
        assert_eq!(core.process(&rm), vec![SSH_AGENT_FAILURE]);

        core.add_key(k1, "k1", "a");
        assert_eq!(
            core.process(&[SSH2_AGENTC_REMOVE_ALL_IDENTITIES]),
            vec![SSH_AGENT_SUCCESS]
        );
        assert_eq!(core.key_count(), 0);
    }

    #[test]
    fn unknown_and_ssh1_messages_fail() {
        let core = NativeAgentCore::new();
        assert_eq!(core.process(&[1]), vec![SSH_AGENT_FAILURE]);
        assert_eq!(core.process(&[99]), vec![SSH_AGENT_FAILURE]);
        assert_eq!(core.process(&[]), vec![SSH_AGENT_FAILURE]);
    }

    #[test]
    fn constrained_lifetime_expires_lazily() {
        let core = NativeAgentCore::new();
        let key = generate_new_ssh_key("ed25519", "shortlived").unwrap();
        let mut body = vec![SSH2_AGENTC_ADD_ID_CONSTRAINED];
        Encode::encode(key.key_data(), &mut body).unwrap();
        Encode::encode("shortlived".as_bytes(), &mut body).unwrap();
        body.push(CONSTRAIN_LIFETIME);
        Encode::encode(&1u32, &mut body).unwrap();
        assert_eq!(core.process(&body), vec![SSH_AGENT_SUCCESS]);
        assert_eq!(core.key_count(), 1);
        std::thread::sleep(Duration::from_millis(1100));
        assert_eq!(core.key_count(), 0);
    }

    #[test]
    fn add_key_replaces_same_public_key() {
        let core = NativeAgentCore::new();
        let key = generate_new_ssh_key("ed25519", "dup").unwrap();
        assert!(!core.add_key(key.clone(), "first", "a"));
        assert!(core.add_key(key, "second", "b"));
        assert_eq!(core.key_count(), 1);
        assert_eq!(core.list()[0].comment, "second");
    }
}
