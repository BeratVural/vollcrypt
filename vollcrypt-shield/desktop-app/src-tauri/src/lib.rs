mod viewer;

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .invoke_handler(tauri::generate_handler![
            viewer::inspect_agent,
            viewer::inspect_offline_package
        ])
        .run(tauri::generate_context!())
        .expect("error while running Vollcrypt Shield Viewer");
}
