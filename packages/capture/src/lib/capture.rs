// src/lib/capture.rs

use crate::lib::paths::get_temp_image_path;
use crate::sys::set_capture_pid;
use anyhow::{anyhow, Result};
use log::info;
use std::process::Command;
use std::path::{Path, PathBuf};

pub fn run(executable: &Path) -> Result<PathBuf> {
    let output_path = get_temp_image_path();
    
    // Clean up previous run to ensure we don't return a stale image
    if output_path.exists() {
        let _ = std::fs::remove_file(&output_path);
    }

    info!("Launching capture engine: {:?}", executable);

    // We pass the desired output path to the C++ engine as an argument.
    // Ensure your Qt app reads argv[1] and saves the image there!
    let mut child = Command::new(executable)
        .arg(output_path.to_string_lossy().to_string()) 
        .spawn()
        .map_err(|e| anyhow!("Failed to spawn process: {}", e))?;

    // Register PID for the MonitorGuard (Ghost Buster) so it can kill this specific process
    set_capture_pid(child.id());

    let status = child.wait()?;
    
    // Reset PID since process is dead
    set_capture_pid(0);

    if !status.success() {
        return Err(anyhow!("Capture process exited with code: {:?}", status.code()));
    }

    // Verify the file was actually created by the C++ engine
    if !output_path.exists() {
        return Err(anyhow!("Capture succeeded but image file is missing at {:?}", output_path));
    }

    Ok(output_path)
}