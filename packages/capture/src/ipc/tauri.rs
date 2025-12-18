// src/ipc/tauri.rs

use anyhow::Result;
use std::path::Path;
use std::process::Command;

pub fn open_editor(image_path: &Path) -> Result<()> {
    // 1. Locate the Main App (SpatialShot)
    // In production, this daemon sits inside the app bundle or next to the exe.
    
    // TODO: Phase 4 - We need to robustly find the "Main App" based on where this daemon is running.
    // For now, let's assume standard Tauri `open` behavior or a URL scheme.
    
    // STRATEGY A: Custom Protocol (spatialshot://open?path=...)
    // This is the cleanest way to wake up an existing instance on Mac/Win.
    
    #[cfg(target_os = "macos")]
    {
        Command::new("open")
            .arg(format!("spatialshot://open?path={}", image_path.to_string_lossy()))
            .spawn()?;
    }

    #[cfg(target_os = "windows")]
    {
        // Start-Process "spatialshot:..."
        Command::new("cmd")
            .args(&["/C", "start", &format!("spatialshot://open?path={}", image_path.to_string_lossy())])
            .spawn()?;
    }
    
    #[cfg(target_os = "linux")]
    {
        Command::new("xdg-open")
            .arg(format!("spatialshot://open?path={}", image_path.to_string_lossy()))
            .spawn()?;
    }

    Ok(())
}