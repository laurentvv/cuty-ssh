//! Standalone probe for the native integrated agent of a *running* cuty-ssh.
//!
//! Usage: `cargo run --example agent_probe`
//! or `cargo run --example agent_probe -- add <keyfile> [passphrase]` to load
//! a key into the running agent first.
//!
//! Queries both transports exactly like external clients would:
//! - named pipe `\\.\pipe\cuty-agent.<user>` (russh agent client)
//! - legacy `Pageant` window via WM_COPYDATA (pageant crate client)
//!
//! Prints the identities seen on each transport; useful for diagnosing the
//! manual test checklist without launching PuTTY.

use russh::keys::signature::Verifier;
use russh::keys::ssh_encoding::Decode;
use russh::keys::ssh_key::HashAlg;
use zeroize::Zeroizing;

fn main() {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("runtime");

    // Optional: `agent_probe add <path.ppk> [passphrase]` loads a key first.
    let mut args = std::env::args().skip(1);
    if args.next().as_deref() == Some("add") {
        let path = args
            .next()
            .expect("usage: agent_probe add <keyfile> [pass]");
        let pass = args.next();
        let key = cuty_ssh_load_key(&path, pass.as_deref()).expect("load key");
        rt.block_on(async {
            let pipe_name = cuty_ssh_pipe_name();
            let mut client =
                russh::keys::agent::client::AgentClient::connect_named_pipe(&pipe_name)
                    .await
                    .expect("connect to cuty-ssh agent pipe");
            client
                .add_identity(&key, &[])
                .await
                .expect("ADD_IDENTITY rejected by the agent");
            println!("[add] key loaded into the running agent: {}", path);
        });
    }

    // 1. Named pipe transport
    let pipe_name = cuty_ssh_pipe_name();
    println!("[pipe] connecting to {pipe_name}");
    let pipe_keys = rt.block_on(async {
        match russh::keys::agent::client::AgentClient::connect_named_pipe(&pipe_name).await {
            Ok(mut client) => match client.request_identities().await {
                Ok(ids) => {
                    println!("[pipe] OK — {} key(s):", ids.len());
                    for id in &ids {
                        let pk: russh::keys::ssh_key::PublicKey = id.public_key().into_owned();
                        println!(
                            "  - {} [{}] comment={:?}",
                            pk.algorithm(),
                            pk.fingerprint(HashAlg::Sha256),
                            id.comment()
                        );
                    }
                    // Round-trip signature check through the real agent.
                    if let Some(id) = ids.first() {
                        let pk: russh::keys::ssh_key::PublicKey = id.public_key().into_owned();
                        match client
                            .sign_request_signature(&pk, None, b"cuty-ssh probe payload")
                            .await
                        {
                            Ok(sig) => {
                                let ok = pk
                                    .key_data()
                                    .verify(b"cuty-ssh probe payload", &sig)
                                    .is_ok();
                                println!(
                                    "[pipe] signature over the wire: {} (verified={ok})",
                                    sig.algorithm()
                                );
                            }
                            Err(e) => println!("[pipe] sign FAILED: {e}"),
                        }
                    }
                    ids
                }
                Err(e) => {
                    println!("[pipe] connect OK but list failed: {e}");
                    Vec::new()
                }
            },
            Err(e) => {
                println!("[pipe] FAILED to connect: {e}");
                Vec::new()
            }
        }
    });

    // 2. WM_COPYDATA transport (pageant crate = what PuTTY/WinSCP do)
    println!("[wm] querying 'Pageant' window via WM_COPYDATA");
    match pageant::wmmessage::query_pageant_direct(
        uuid::Uuid::new_v4().simple().to_string(),
        &framed(&[11]), // SSH2_AGENTC_REQUEST_IDENTITIES
    ) {
        Ok(answer) => {
            // answer = u32 length prefix + body; the message type is body[0].
            let msg_type = answer.get(4).copied().unwrap_or(0);
            println!("[wm] OK — answer len={} msg_type={msg_type}", answer.len());
            if msg_type == 12 {
                let mut r: &[u8] = &answer[5..];
                let count = u32::decode(&mut r).unwrap_or(0);
                println!("[wm] {count} key(s):");
                for _ in 0..count {
                    let blob = <Vec<u8> as Decode>::decode(&mut r).unwrap_or_default();
                    let comment = String::decode(&mut r).unwrap_or_default();
                    match russh::keys::key::parse_public_key(&blob) {
                        Ok(pk) => println!(
                            "  - {} [{}] comment={comment:?}",
                            pk.algorithm(),
                            pk.fingerprint(HashAlg::Sha256)
                        ),
                        Err(_) => println!("  - <blob {} bytes> comment={comment:?}", blob.len()),
                    }
                }
                if count > 0 && count as usize == pipe_keys.len() {
                    println!(
                        "[wm] key counts match the pipe transport — both transports serve the same vault"
                    );
                }
            } else if msg_type == 5 {
                println!("[wm] agent answered FAILURE (locked or empty)");
            }
        }
        Err(e) => println!("[wm] FAILED: {e}"),
    }
}

fn cuty_ssh_load_key(
    path: &str,
    passphrase: Option<&str>,
) -> anyhow::Result<russh::keys::PrivateKey> {
    // russh's loader decodes every format cuty-ssh serves (.ppk v2/v3 included).
    let raw = std::fs::read_to_string(path)?;
    let raw = Zeroizing::new(raw.replace("\r\n", "\n"));
    Ok(russh::keys::decode_secret_key(&raw, passphrase)?)
}

fn framed(payload: &[u8]) -> Vec<u8> {
    let mut f = Vec::with_capacity(4 + payload.len());
    f.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    f.extend_from_slice(payload);
    f
}

/// Mirror of `agent_server::pipe_name()` without depending on cuty-ssh internals
/// (the example builds against the same crate, but keep it standalone-safe).
fn cuty_ssh_pipe_name() -> String {
    let user = std::env::var("USERNAME").unwrap_or_else(|_| "user".to_string());
    let clean: String = user
        .chars()
        .take(48)
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.') {
                c
            } else {
                '_'
            }
        })
        .collect();
    let clean = if clean.is_empty() { "user" } else { &clean };
    format!(r"\\.\pipe\cuty-agent.{clean}")
}
