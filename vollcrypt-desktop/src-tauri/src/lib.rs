mod commands;

use commands::*;

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        .plugin(tauri_plugin_dialog::init())
        .invoke_handler(tauri::generate_handler![
            generate_keypair,
            encrypt_file_password,
            decrypt_file_password,
            encrypt_file_recipient,
            decrypt_file_recipient,
            encrypt_text_password,
            decrypt_text_password,
            encrypt_text_recipient,
            decrypt_text_recipient,
            save_text_file,
            load_text_file,
            save_bin_file,
            load_bin_file
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
