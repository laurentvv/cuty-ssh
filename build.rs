fn main() {
    // Embed the application icon in the .exe so the taskbar, pinned shortcuts and Explorer show it.
    #[cfg(windows)]
    {
        let mut res = winresource::WindowsResource::new();
        res.set_icon("assets/cuty_ssh_icon.ico");
        if let Err(e) = res.compile() {
            println!("cargo:warning=failed to embed icon: {e}");
        }
    }
    println!("cargo:rerun-if-changed=assets/cuty_ssh_icon.ico");
}
