// Hide console window on Windows in Release builds.
// In Debug builds, we keep it so you can read log::info! output.
#![cfg_attr(
    all(target_os = "windows", not(debug_assertions)),
    windows_subsystem = "windows"
)]

mod embed;
mod ipc;
mod lib;
mod sys;

use anyhow::Result;
use log::{error, info};

fn main() -> Result<()> {
    // 1. Initialize Logger
    // If we are in "windows_subsystem" mode (Release), this logs to nothing
    // unless you add a file logger. For now, it's fine.
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info"))
        .format_timestamp_millis()
        .init();

    // 2. BOOTSTRAP (The Matryoshka Magic)
    let engine_path = match lib::bootstrap::ensure_engine() {
        Ok(path) => path,
        Err(e) => {
            error!("Fatal: Failed to bootstrap capture engine: {}", e);
            // On Windows Release, this exit won't be seen, but the app will just close.
            std::process::exit(1);
        }
    };

    info!("Engine ready at: {:?}", engine_path);

    // --- LINUX PATH (One-Shot) ---
    #[cfg(target_os = "linux")]
    {
        info!("Linux mode: Executing capture immediately...");
        match lib::launcher::run_capture(&engine_path) {
            Ok(image_path) => {
                info!("Capture successful: {:?}", image_path);
                ipc::tauri::open_editor(&image_path)?;
            }
            Err(e) => error!("Capture failed: {}", e),
        }
        return Ok(());
    }

    // --- WIN/MAC PATH (Daemon) ---
    #[cfg(not(target_os = "linux"))]
    {
        // 3. Start Guards
        sys::monitors::start_monitor();

        info!("Daemon started. Waiting for Hotkey...");

        // 4. Start Listener
        sys::hotkey::listen(move || {
            // A. Acquire Lock (Single Instance per user)
            if let Err(_) = lib::lock::try_lock() {
                log::warn!("Capture already in progress. Ignoring hotkey.");
                return;
            }

            // B. Mute Audio (The Silencer)
            let _audio_guard = sys::audio::AudioGuard::new();

            // C. Run Capture
            match lib::capture::run(&engine_path) {
                Ok(image_path) => {
                    info!("Capture complete. Handing off to Tauri...");
                    if let Err(e) = ipc::tauri::open_editor(&image_path) {
                        error!("Failed to open editor: {}", e);
                    }
                }
                Err(e) => error!("Capture execution failed: {}", e),
            }
        });
    }

    Ok(())
}
