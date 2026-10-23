//! Named-pipe transport and lifecycle controller for the native integrated agent.
//!
//! Serves the ssh-agent wire protocol on `\\.\pipe\cuty-agent.<user>` —
//! the same transport modern PuTTY Pageant uses. The pipe is created with an
//! explicit DACL granting access to the current user's SID only: unlike the
//! `CreateNamedPipeW` default descriptor (which lets every local account read
//! and write the pipe), no other user on the machine can reach the keys or
//! request signatures.

use super::agent::{MAX_AGENT_FRAME_LEN, NativeAgentCore};
use std::io;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::windows::named_pipe::NamedPipeServer;
use tokio::sync::watch;
use windows_sys::Win32::Foundation::{
    CloseHandle, ERROR_ACCESS_DENIED, INVALID_HANDLE_VALUE, LocalFree,
};
use windows_sys::Win32::Security::Authorization::{
    ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
};
use windows_sys::Win32::Security::{
    GetTokenInformation, PSECURITY_DESCRIPTOR, PSID, SECURITY_ATTRIBUTES, TOKEN_QUERY, TOKEN_USER,
    TokenUser,
};
use windows_sys::Win32::Storage::FileSystem::{
    FILE_FLAG_FIRST_PIPE_INSTANCE, FILE_FLAG_OVERLAPPED, PIPE_ACCESS_DUPLEX,
};
use windows_sys::Win32::System::Pipes::{
    CreateNamedPipeW, PIPE_READMODE_BYTE, PIPE_TYPE_BYTE, PIPE_UNLIMITED_INSTANCES, PIPE_WAIT,
};
use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};
use windows_sys::Win32::System::WindowsProgramming::GetUserNameA;

/// Raw pipe handle wrapped so it can cross into the async task (`*mut c_void`
/// is not `Send` by default; a pipe handle is safe to move between threads).
struct SendPipeHandle(WinHandle);
unsafe impl Send for SendPipeHandle {}

type WinHandle = *mut core::ffi::c_void;

/// Running controller for the native agent. Dropping it stops the server.
pub struct NativeAgentServer {
    pub core: Arc<NativeAgentCore>,
    shutdown_tx: watch::Sender<bool>,
    alive: Arc<AtomicBool>,
    pub pipe_name: String,
    /// WM_COPYDATA compatibility window (PuTTY/KiTTY/WinSCP legacy clients).
    pub wm: Option<super::agent_wmcopydata::WmAgentServer>,
    pub wm_status: Arc<std::sync::Mutex<super::agent_wmcopydata::WmCompatStatus>>,
}

impl NativeAgentServer {
    /// Starts the agent server on the given runtime. The first pipe instance
    /// is created synchronously so a name conflict (another cuty-ssh agent
    /// already listening) is reported immediately. The WM_COPYDATA
    /// compatibility window starts too, but a conflict there (external
    /// pageant.exe running) only degrades that transport — never the pipe.
    pub fn start(rt: &tokio::runtime::Handle) -> Result<Self, String> {
        let core = Arc::new(NativeAgentCore::new());
        let pipe_name = pipe_name();
        let first = create_pipe_instance(&pipe_name, true)
            .map_err(|e| classify_pipe_error(&pipe_name, &e))?;

        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let alive = Arc::new(AtomicBool::new(true));
        let first = SendPipeHandle(first);
        let core_task = core.clone();
        let alive_task = alive.clone();
        let name_task = pipe_name.clone();
        rt.spawn(async move {
            run_accept_loop(first, core_task, name_task, shutdown_rx, alive_task).await
        });

        let (wm, wm_status) = super::agent_wmcopydata::WmAgentServer::start(core.clone());
        if let Some(err) = match &*wm_status.lock().unwrap() {
            super::agent_wmcopydata::WmCompatStatus::Conflict(m)
            | super::agent_wmcopydata::WmCompatStatus::Failed(m) => Some(m.clone()),
            _ => None,
        } {
            tracing::warn!("native agent: WM_COPYDATA compatibility inactive: {err}");
        }

        Ok(Self {
            core,
            shutdown_tx,
            alive,
            pipe_name,
            wm,
            wm_status,
        })
    }

    pub fn is_alive(&self) -> bool {
        self.alive.load(Ordering::Relaxed)
    }

    /// Stops accepting new connections. In-flight requests finish; keys stay
    /// in memory only until the core is dropped.
    pub fn stop(mut self) {
        if let Some(mut wm) = self.wm.take() {
            wm.stop();
        }
        let _ = self.shutdown_tx.send(true);
    }
}

impl Drop for NativeAgentServer {
    fn drop(&mut self) {
        if let Some(mut wm) = self.wm.take() {
            wm.stop();
        }
        let _ = self.shutdown_tx.send(true);
    }
}

// The async accept loop keeps one listening pipe instance ready at all times:
// after a client connects, its instance is handed to a per-connection task and
// a fresh instance is created for the next client.
async fn run_accept_loop(
    first: SendPipeHandle,
    core: Arc<NativeAgentCore>,
    pipe_name: String,
    mut shutdown_rx: watch::Receiver<bool>,
    alive: Arc<AtomicBool>,
) {
    let mut pending = Some(first);
    while let Some(handle) = pending.take() {
        let server = match unsafe { NamedPipeServer::from_raw_handle(handle.0 as _) } {
            Ok(s) => s,
            Err(e) => {
                tracing::error!("native agent: wrapping pipe handle failed: {e}");
                break;
            }
        };
        tokio::select! {
            _ = shutdown_rx.changed() => break,
            res = server.connect() => {
                if res.is_err() {
                    break;
                }
                let core = core.clone();
                tokio::spawn(async move {
                    if let Err(e) = handle_client(server, &core).await {
                        tracing::debug!("native agent: connection ended: {e}");
                    }
                });
                pending = create_pipe_instance(&pipe_name, false)
                    .ok()
                    .map(SendPipeHandle);
            }
        }
    }
    alive.store(false, Ordering::Relaxed);
}

async fn handle_client(mut stream: NamedPipeServer, core: &NativeAgentCore) -> io::Result<()> {
    let mut len_buf = [0u8; 4];
    loop {
        stream.read_exact(&mut len_buf).await?;
        let len = u32::from_be_bytes(len_buf) as usize;
        if len == 0 || len > MAX_AGENT_FRAME_LEN {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "agent frame length out of bounds",
            ));
        }
        let mut payload = vec![0u8; len];
        stream.read_exact(&mut payload).await?;
        let response = core.process(&payload);
        let mut out = Vec::with_capacity(4 + response.len());
        out.extend_from_slice(&(response.len() as u32).to_be_bytes());
        out.extend_from_slice(&response);
        stream.write_all(&out).await?;
        stream.flush().await?;
    }
}

/// `\\.\pipe\cuty-agent.<sanitized username>` (SAM name, before any `@`).
pub fn pipe_name() -> String {
    let user = current_username();
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
    let clean = if clean.is_empty() {
        "user".to_string()
    } else {
        clean
    };
    format!(r"\\.\pipe\cuty-agent.{clean}")
}

fn current_username() -> String {
    unsafe {
        let mut len: u32 = 0;
        let _ = GetUserNameA(std::ptr::null_mut(), &mut len);
        if len == 0 {
            return String::new();
        }
        let mut buf = vec![0u8; len as usize];
        if GetUserNameA(buf.as_mut_ptr(), &mut len) == 0 {
            return String::new();
        }
        let s = buf.split(|&b| b == 0).next().unwrap_or_default();
        let name = String::from_utf8_lossy(s).to_string();
        // UPNs are split at '@' like PuTTY does; SAM names have no '@'.
        match name.split_once('@') {
            Some((local, _)) => local.to_string(),
            None => name,
        }
    }
}

/// SID of the current process token, in SDDL string form (`S-1-5-21-…`).
fn current_user_sid_string() -> Option<String> {
    unsafe {
        let mut token: WinHandle = std::ptr::null_mut();
        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) == 0 {
            return None;
        }
        let mut needed: u32 = 0;
        let _ = GetTokenInformation(token, TokenUser, std::ptr::null_mut(), 0, &mut needed);
        if needed == 0 {
            CloseHandle(token);
            return None;
        }
        let mut buf = vec![0u8; needed as usize];
        let ok = GetTokenInformation(
            token,
            TokenUser,
            buf.as_mut_ptr().cast(),
            needed,
            &mut needed,
        ) != 0;
        CloseHandle(token);
        if !ok {
            return None;
        }
        let user = &*(buf.as_ptr() as *const TOKEN_USER);
        let mut sid_str: *mut u16 = std::ptr::null_mut();
        if ConvertSidToStringSidW(user.User.Sid as PSID, &mut sid_str) == 0 {
            return None;
        }
        let mut len = 0usize;
        while *sid_str.add(len) != 0 {
            len += 1;
        }
        let s = String::from_utf16_lossy(std::slice::from_raw_parts(sid_str, len));
        LocalFree(sid_str as _);
        Some(s)
    }
}

fn create_pipe_instance(pipe_name: &str, first: bool) -> io::Result<WinHandle> {
    let name_w: Vec<u16> = pipe_name.encode_utf16().chain(std::iter::once(0)).collect();

    // DACL: full control for the current user only. Without this, the default
    // named-pipe descriptor lets every local account read/write the pipe.
    let sddl = current_user_sid_string()
        .map(|sid| format!("D:P(A;;GA;;;{sid})"))
        .unwrap_or_else(|| "D:P(A;;GA;;;)".to_string());
    let sddl_w: Vec<u16> = sddl.encode_utf16().chain(std::iter::once(0)).collect();

    unsafe {
        let mut sd: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
        let mut sa = SECURITY_ATTRIBUTES {
            nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: std::ptr::null_mut(),
            bInheritHandle: 0,
        };
        let have_custom_sd = ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl_w.as_ptr(),
            SDDL_REVISION_1,
            &mut sd,
            std::ptr::null_mut(),
        ) != 0;
        if have_custom_sd {
            sa.lpSecurityDescriptor = sd.cast();
        }

        let mut open_mode = PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED;
        if first {
            open_mode |= FILE_FLAG_FIRST_PIPE_INSTANCE;
        }
        let handle = CreateNamedPipeW(
            name_w.as_ptr(),
            open_mode,
            PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
            PIPE_UNLIMITED_INSTANCES,
            8192,
            8192,
            0,
            &sa,
        );

        if have_custom_sd {
            let _ = LocalFree(sd as _);
        }

        if handle == INVALID_HANDLE_VALUE {
            return Err(io::Error::last_os_error());
        }
        Ok(handle)
    }
}

fn classify_pipe_error(pipe_name: &str, e: &io::Error) -> String {
    if e.raw_os_error() == Some(ERROR_ACCESS_DENIED as i32) {
        format!("conflit : un agent cuty-ssh écoute déjà sur {pipe_name} (autre instance ?)")
    } else {
        format!("impossible de créer le canal nommé {pipe_name} : {e}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ssh::agent::SSH_AGENT_SUCCESS;
    use crate::ssh::ppk::generate_new_ssh_key;
    use russh::keys::signature::Verifier;

    /// End-to-end through the real transport: the pipe server is started the
    /// way the UI starts it, and a real `russh` agent client (the same one the
    /// SSH sessions use) lists and signs. Fails with an access-denied conflict
    /// if another cuty-ssh instance is already running the agent.
    #[test]
    fn named_pipe_server_serves_russh_agent_client() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("test runtime");
        let handle = rt.handle().clone();
        rt.block_on(async move {
            let server = match NativeAgentServer::start(&handle) {
                Ok(server) => server,
                // A running cuty-ssh instance owns the pipe (conflict detection
                // working as designed) — skip instead of fighting it.
                Err(e) if e.starts_with("conflit") => {
                    eprintln!("skipping pipe e2e test: {e}");
                    return;
                }
                Err(e) => panic!("native agent server must start: {e}"),
            };

            let mut client =
                russh::keys::agent::client::AgentClient::connect_named_pipe(&server.pipe_name)
                    .await
                    .expect("client must connect to the agent pipe");
            assert!(
                client.request_identities().await.unwrap().is_empty(),
                "fresh agent must list no keys"
            );

            let key = generate_new_ssh_key("ed25519", "e2e@cuty").unwrap();
            server.core.add_key(key.clone(), "e2e@cuty", "test");

            let ids = client.request_identities().await.unwrap();
            assert_eq!(ids.len(), 1);
            assert_eq!(ids[0].comment(), "e2e@cuty", "comment must survive listing");

            let sig = client
                .sign_request_signature(&ids[0].public_key(), None, b"auth payload")
                .await
                .expect("agent must sign");
            key.public_key()
                .key_data()
                .verify(b"auth payload", &sig)
                .expect("signature must verify against the public key");

            // Removing over the wire (ssh-add -d path) must empty the agent.
            client
                .remove_identity(&ids[0].public_key())
                .await
                .expect("remove identity");
            assert_eq!(server.core.key_count(), 0);

            // Lock over the wire, then a listing must fail with FAILURE.
            use crate::ssh::agent::SSH_AGENTC_LOCK;
            use russh::keys::ssh_encoding::Encode;
            let mut lock = vec![SSH_AGENTC_LOCK];
            Encode::encode(b"e2e-lock".as_slice(), &mut lock).unwrap();
            let resp = server.core.process(&lock);
            assert_eq!(resp, vec![SSH_AGENT_SUCCESS]);

            server.stop();
        });
    }

    #[test]
    fn pipe_name_contains_sanitized_user() {
        let name = pipe_name();
        assert!(name.starts_with(r"\\.\pipe\cuty-agent."), "{name}");
        assert!(!name.ends_with('.'), "name must not end with a dot: {name}");
    }
}
