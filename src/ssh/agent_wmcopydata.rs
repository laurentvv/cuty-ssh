//! WM_COPYDATA Pageant-compatibility server for the native integrated agent.
//!
//! PuTTY, KiTTY and WinSCP still discover the agent through the legacy
//! WM_COPYDATA IPC: they `FindWindowW("Pageant", "Pageant")`, create a
//! `PageantRequest<cookie>` file mapping, write the ssh-agent frame into it and
//! `SendMessage(WM_COPYDATA)` with `dwData = 0x804E50BA`. This module creates
//! that hidden window on a dedicated thread so those clients work with the
//! integrated agent without any configuration — no pageant.exe involved.
//!
//! Behaviour mirrors PuTTY's `windows/pageant.c` (0.81): the mapping's owner
//! SID must equal our token user SID, a request whose length field exceeds the
//! mapping gets an in-band `SSH_AGENT_FAILURE`, and the answer is written back
//! into the same mapping before the wndproc returns 1.

use super::agent::{NativeAgentCore, SSH_AGENT_FAILURE};
use std::sync::{Arc, Mutex};
use windows_sys::Win32::Foundation::{CloseHandle, HANDLE, HWND, LPARAM, LRESULT, WPARAM};
use windows_sys::Win32::Security::Authorization::GetSecurityInfo;
use windows_sys::Win32::Security::Authorization::SE_KERNEL_OBJECT;
use windows_sys::Win32::Security::{
    EqualSid, GetTokenInformation, OWNER_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, PSID,
    TOKEN_QUERY, TOKEN_USER, TokenUser,
};
use windows_sys::Win32::System::DataExchange::COPYDATASTRUCT;
use windows_sys::Win32::System::LibraryLoader::GetModuleHandleW;
use windows_sys::Win32::System::Memory::{
    FILE_MAP_ALL_ACCESS, FILE_MAP_WRITE, MEMORY_BASIC_INFORMATION, MEMORY_MAPPED_VIEW_ADDRESS,
    MapViewOfFile, OpenFileMappingW, UnmapViewOfFile, VirtualQuery,
};
use windows_sys::Win32::System::Threading::{
    GetCurrentProcess, GetCurrentThreadId, OpenProcessToken,
};
use windows_sys::Win32::UI::WindowsAndMessaging::{
    CREATESTRUCTW, CreateWindowExW, DefWindowProcW, DestroyWindow, DispatchMessageW, FindWindowW,
    GWLP_USERDATA, GetMessageW, GetWindowLongPtrW, MSG, PostQuitMessage, PostThreadMessageW,
    RegisterClassW, SetWindowLongPtrW, ShowWindow, TranslateMessage, UnregisterClassW, WM_COPYDATA,
    WM_DESTROY, WM_NCCREATE, WM_QUIT, WNDCLASSW, WS_OVERLAPPEDWINDOW,
};

/// PuTTY's AGENT_COPYDATA_ID (`0x804E50BA`).
const AGENT_COPYDATA_ID: u64 = 0x804E_50BA;
const SW_HIDE: i32 = 0;

/// Lifecycle state of the WM_COPYDATA compatibility window, surfaced in the UI.
#[derive(Debug, Clone)]
pub enum WmCompatStatus {
    Starting,
    Running,
    /// A real Pageant window already exists — we did not register ours, so
    /// legacy WM clients keep talking to the external pageant.exe.
    Conflict(String),
    Failed(String),
}

struct WmCtx {
    core: Arc<NativeAgentCore>,
}

/// Running WM_COPYDATA server handle. Dropping it (or `stop()`) posts WM_QUIT
/// to the window thread and joins it.
pub struct WmAgentServer {
    thread_id: u32,
    join: Option<std::thread::JoinHandle<()>>,
    pub status: Arc<Mutex<WmCompatStatus>>,
}

impl WmAgentServer {
    /// Spawns the window thread and waits (max 2 s) for it to confirm that the
    /// hidden window exists. Returns `(None, status)` on conflict or failure —
    /// the pipe server keeps running regardless.
    pub fn start(core: Arc<NativeAgentCore>) -> (Option<Self>, Arc<Mutex<WmCompatStatus>>) {
        let status = Arc::new(Mutex::new(WmCompatStatus::Starting));
        let (tx, rx) = std::sync::mpsc::channel::<Result<(), String>>();
        let thread_status = status.clone();

        let join = std::thread::Builder::new()
            .name("cuty-agent-wm".to_string())
            .spawn(move || wm_thread_main(core, &thread_status, &tx))
            .expect("spawn WM agent thread");

        match rx.recv_timeout(std::time::Duration::from_secs(2)) {
            Ok(Ok(())) => {
                let thread_id = WM_THREAD_ID.lock().unwrap().unwrap_or(0);
                *status.lock().unwrap() = WmCompatStatus::Running;
                (
                    Some(Self {
                        thread_id,
                        join: Some(join),
                        status: status.clone(),
                    }),
                    status,
                )
            }
            Ok(Err(e)) => {
                let conflicted = e.starts_with("conflit");
                *status.lock().unwrap() = if conflicted {
                    WmCompatStatus::Conflict(e)
                } else {
                    WmCompatStatus::Failed(e)
                };
                let _ = join.join();
                (None, status)
            }
            Err(_) => {
                *status.lock().unwrap() = WmCompatStatus::Failed(
                    "la fenêtre Pageant n'a pas confirmé son démarrage".to_string(),
                );
                tracing::error!("native agent WM thread did not confirm startup");
                (None, status)
            }
        }
    }

    pub fn stop(&mut self) {
        unsafe {
            PostThreadMessageW(self.thread_id, WM_QUIT, 0, 0);
        }
        if let Some(join) = self.join.take() {
            let _ = join.join();
        }
    }
}

impl Drop for WmAgentServer {
    fn drop(&mut self) {
        self.stop();
    }
}

/// Thread id of the live WM window thread, set right before it confirms
/// startup and cleared when its message loop ends.
static WM_THREAD_ID: Mutex<Option<u32>> = Mutex::new(None);

/// Creates the hidden window, signals the outcome through `tx` once it exists,
/// then runs the message loop until WM_QUIT.
fn wm_thread_main(
    core: Arc<NativeAgentCore>,
    status: &Mutex<WmCompatStatus>,
    tx: &std::sync::mpsc::Sender<Result<(), String>>,
) {
    unsafe {
        let tid = GetCurrentThreadId();
        let class_name: Vec<u16> = "Pageant".encode_utf16().chain(std::iter::once(0)).collect();

        if !FindWindowW(class_name.as_ptr(), class_name.as_ptr()).is_null() {
            let _ = tx.send(Err(
                "conflit : une fenêtre Pageant existe déjà (pageant.exe externe en cours ?)"
                    .to_string(),
            ));
            return;
        }

        let hinst = GetModuleHandleW(std::ptr::null());
        let wc = WNDCLASSW {
            style: 0,
            lpfnWndProc: Some(wndproc),
            cbClsExtra: 0,
            cbWndExtra: 0,
            hInstance: hinst,
            hIcon: std::ptr::null_mut(),
            hCursor: std::ptr::null_mut(),
            hbrBackground: std::ptr::null_mut(),
            lpszMenuName: std::ptr::null(),
            lpszClassName: class_name.as_ptr(),
        };
        if RegisterClassW(&wc) == 0 {
            let _ = tx.send(Err(format!(
                "RegisterClassW échoué : {}",
                std::io::Error::last_os_error()
            )));
            return;
        }

        let ctx = Box::into_raw(Box::new(WmCtx { core }));
        let hwnd = CreateWindowExW(
            0,
            class_name.as_ptr(),
            class_name.as_ptr(),
            WS_OVERLAPPEDWINDOW,
            windows_sys::Win32::UI::WindowsAndMessaging::CW_USEDEFAULT,
            windows_sys::Win32::UI::WindowsAndMessaging::CW_USEDEFAULT,
            100,
            100,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            hinst,
            ctx as *const core::ffi::c_void,
        );
        if hwnd.is_null() {
            drop(Box::from_raw(ctx));
            let _ = tx.send(Err(format!(
                "CreateWindowExW échoué : {}",
                std::io::Error::last_os_error()
            )));
            return;
        }
        ShowWindow(hwnd, SW_HIDE);

        // The window exists: publish the thread id and confirm startup.
        *WM_THREAD_ID.lock().unwrap() = Some(tid);
        *status.lock().unwrap() = WmCompatStatus::Running;
        let _ = tx.send(Ok(()));

        let mut msg: MSG = std::mem::zeroed();
        while GetMessageW(&mut msg, std::ptr::null_mut(), 0, 0) > 0 {
            let _ = TranslateMessage(&msg);
            DispatchMessageW(&msg);
        }

        DestroyWindow(hwnd);
        // Unregister so a later start/stop/start cycle in the same process can
        // register the class again (RegisterClassW fails on duplicates).
        let _ = UnregisterClassW(class_name.as_ptr(), hinst);
        drop(Box::from_raw(ctx));
        *WM_THREAD_ID.lock().unwrap() = None;
    }
}

unsafe extern "system" fn wndproc(hwnd: HWND, msg: u32, wp: WPARAM, lp: LPARAM) -> LRESULT {
    unsafe {
        match msg {
            WM_NCCREATE => {
                let cs = lp as *const CREATESTRUCTW;
                SetWindowLongPtrW(hwnd, GWLP_USERDATA, (*cs).lpCreateParams as isize);
                DefWindowProcW(hwnd, msg, wp, lp)
            }
            WM_COPYDATA => {
                let ctx = GetWindowLongPtrW(hwnd, GWLP_USERDATA) as *mut WmCtx;
                if ctx.is_null() {
                    return 0;
                }
                let cds = lp as *const COPYDATASTRUCT;
                if (*cds).dwData != AGENT_COPYDATA_ID as usize {
                    return 0; // not our message, mate
                }
                let cb = (*cds).cbData as usize;
                let name_ptr = (*cds).lpData as *const u8;
                if cb == 0 || name_ptr.is_null() || *name_ptr.add(cb - 1) != 0 {
                    return 0; // failure to be ASCIZ!
                }
                let name_len = (0..cb - 1).take_while(|&i| *name_ptr.add(i) != 0).count();
                let mapname = std::slice::from_raw_parts(name_ptr, name_len);
                if answer_filemapping(&(*ctx).core, mapname) {
                    1
                } else {
                    0
                }
            }
            WM_DESTROY => {
                PostQuitMessage(0);
                0
            }
            _ => DefWindowProcW(hwnd, msg, wp, lp),
        }
    }
}

/// Owns the file-mapping resources of one WM_COPYDATA transaction.
struct MappingGuard {
    map: HANDLE,
    view: MEMORY_MAPPED_VIEW_ADDRESS,
    sd: PSECURITY_DESCRIPTOR,
}

impl Drop for MappingGuard {
    fn drop(&mut self) {
        unsafe {
            if !self.view.Value.is_null() {
                let _ = UnmapViewOfFile(self.view);
            }
            if !self.sd.is_null() {
                let _ = windows_sys::Win32::Foundation::LocalFree(self.sd as _);
            }
            if !self.map.is_null() {
                let _ = CloseHandle(self.map);
            }
        }
    }
}

/// Opens the client's `PageantRequest<cookie>` mapping, checks its owner SID,
/// processes the request and writes the answer back. Mirrors PuTTY's
/// `answer_filemapping_message`. Returns false to make the wndproc answer 0.
unsafe fn answer_filemapping(core: &NativeAgentCore, mapname: &[u8]) -> bool {
    unsafe {
        let mut guard = MappingGuard {
            map: std::ptr::null_mut(),
            view: MEMORY_MAPPED_VIEW_ADDRESS::default(),
            sd: std::ptr::null_mut(),
        };

        let name_w: Vec<u16> = mapname
            .iter()
            .map(|&b| b as u16)
            .chain(std::iter::once(0))
            .collect();
        guard.map = OpenFileMappingW(FILE_MAP_ALL_ACCESS, 0, name_w.as_ptr());
        if guard.map.is_null() {
            return false;
        }

        // Security: the mapping must be owned by our own user SID, exactly
        // like pageant's owner check (`EqualSid(mapsid, expectedsid)`).
        let mut owner: PSID = std::ptr::null_mut();
        if GetSecurityInfo(
            guard.map,
            SE_KERNEL_OBJECT,
            OWNER_SECURITY_INFORMATION,
            &mut owner,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            &mut guard.sd,
        ) != 0
        {
            return false;
        }
        let Some(own_sid) = token_user_sid_bytes() else {
            return false;
        };
        if EqualSid(owner, own_sid.as_ptr() as PSID) == 0 {
            return false; // wrong owning SID of file mapping
        }

        guard.view = MapViewOfFile(guard.map, FILE_MAP_WRITE, 0, 0, 0);
        if guard.view.Value.is_null() {
            return false;
        }
        let mut mbi = MEMORY_BASIC_INFORMATION {
            BaseAddress: std::ptr::null_mut(),
            AllocationBase: std::ptr::null_mut(),
            AllocationProtect: 0,
            PartitionId: 0,
            RegionSize: 0,
            State: 0,
            Protect: 0,
            Type: 0,
        };
        if VirtualQuery(
            guard.view.Value,
            &mut mbi,
            std::mem::size_of::<MEMORY_BASIC_INFORMATION>(),
        ) == 0
        {
            return false;
        }
        let mapsize = mbi.RegionSize;
        if mapsize < 5 {
            return false; // mapping smaller than smallest possible request
        }
        let view_bytes = guard.view.Value as *mut u8;

        let write_answer = |resp: &[u8]| {
            std::ptr::copy_nonoverlapping(
                (resp.len() as u32).to_be_bytes().as_ptr(),
                view_bytes,
                4,
            );
            std::ptr::copy_nonoverlapping(resp.as_ptr(), view_bytes.add(4), resp.len());
        };

        let msglen = u32::from_be_bytes([
            *view_bytes,
            *view_bytes.add(1),
            *view_bytes.add(2),
            *view_bytes.add(3),
        ]) as usize;
        if msglen == 0 || msglen > mapsize - 4 {
            // Emit a failure response without even trying to handle the request.
            write_answer(&[SSH_AGENT_FAILURE]);
        } else {
            let payload = std::slice::from_raw_parts(view_bytes.add(4), msglen);
            let response = core.process(payload);
            if response.len() + 4 <= mapsize {
                write_answer(&response);
            } else {
                write_answer(&[SSH_AGENT_FAILURE]);
            }
        }
        true
    }
}

/// Raw bytes of the current token's user SID, for `EqualSid` comparison.
unsafe fn token_user_sid_bytes() -> Option<Vec<u8>> {
    unsafe {
        let mut token: HANDLE = std::ptr::null_mut();
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
        let sid = user.User.Sid as *const u8;
        // SID layout: Revision(1) + SubAuthorityCount(1) + IdentifierAuthority(6)
        // + 4 bytes per sub-authority — the second byte is the COUNT, not the size.
        let sub_count = *sid.add(1) as usize;
        let len = 8 + 4 * sub_count;
        if len == 0 || len > buf.len() {
            return None;
        }
        Some(std::slice::from_raw_parts(sid, len).to_vec())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ssh::agent::{
        NativeAgentCore, SSH_AGENT_FAILURE, SSH2_AGENT_IDENTITIES_ANSWER,
        SSH2_AGENTC_REQUEST_IDENTITIES,
    };
    use crate::ssh::ppk::generate_new_ssh_key;
    use russh::keys::ssh_encoding::Decode;

    fn framed(payload: &[u8]) -> Vec<u8> {
        let mut f = Vec::with_capacity(4 + payload.len());
        f.extend_from_slice(&(payload.len() as u32).to_be_bytes());
        f.extend_from_slice(payload);
        f
    }

    /// End-to-end through the real legacy transport, one window for all
    /// scenarios (the "Pageant" class is process-global, so parallel servers
    /// would race): our hidden window is queried with the `pageant` crate —
    /// the exact client implementation PuTTY-ecosystem tools use (FindWindow +
    /// WM_COPYDATA + file mapping). Skipped when an external pageant.exe
    /// window is present (conflict).
    #[test]
    fn wm_window_answers_pageant_client_queries() {
        let core = Arc::new(NativeAgentCore::new());
        let key = generate_new_ssh_key("ed25519", "wm-e2e").unwrap();
        core.add_key(key.clone(), "wm-e2e", "test");

        let (mut server, status) = WmAgentServer::start(core.clone());
        if !matches!(*status.lock().unwrap(), WmCompatStatus::Running) {
            eprintln!(
                "skipping WM e2e test: window not running ({:?}) — external Pageant present?",
                *status.lock().unwrap()
            );
            if let Some(s) = server.as_mut() {
                s.stop();
            }
            return;
        }

        // Scenario 1: identity listing with comment preservation.
        let cookie = uuid::Uuid::new_v4().simple().to_string();
        let answer = pageant::wmmessage::query_pageant_direct(
            cookie,
            &framed(&[SSH2_AGENTC_REQUEST_IDENTITIES]),
        )
        .expect("Pageant WM query must be answered by our window");
        assert_eq!(answer[4], SSH2_AGENT_IDENTITIES_ANSWER);
        let mut r: &[u8] = &answer[5..];
        assert_eq!(u32::decode(&mut r).unwrap(), 1, "one key expected");
        let blob = <Vec<u8> as Decode>::decode(&mut r).unwrap();
        assert!(!blob.is_empty());
        assert_eq!(String::decode(&mut r).unwrap(), "wm-e2e");

        // Scenario 2: a locked agent answers FAILURE over WM too.
        use russh::keys::ssh_encoding::Encode;
        let mut lock = vec![crate::ssh::agent::SSH_AGENTC_LOCK];
        Encode::encode(b"wm-lock".as_slice(), &mut lock).unwrap();
        assert_eq!(
            core.process(&lock),
            vec![crate::ssh::agent::SSH_AGENT_SUCCESS]
        );
        let cookie = uuid::Uuid::new_v4().simple().to_string();
        let answer = pageant::wmmessage::query_pageant_direct(
            cookie,
            &framed(&[SSH2_AGENTC_REQUEST_IDENTITIES]),
        )
        .expect("locked listing must still answer");
        assert_eq!(answer[4], SSH_AGENT_FAILURE);

        // Scenario 3: stop and restart in the same process must re-register
        // the class (UnregisterClassW on shutdown).
        if let Some(s) = server.as_mut() {
            s.stop();
        }
        let (mut server2, status2) = WmAgentServer::start(core.clone());
        assert!(
            matches!(*status2.lock().unwrap(), WmCompatStatus::Running),
            "restart must re-register the Pageant window class"
        );
        if let Some(s) = server2.as_mut() {
            s.stop();
        }
    }
}
