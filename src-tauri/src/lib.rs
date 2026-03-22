pub mod ipc;
pub mod ssh;
pub mod iptables;
pub mod ipset;
pub mod safety;
pub mod host;
pub mod snapshot;
pub mod activity;
pub mod export;
pub mod temporary;
pub mod sysctl;

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
