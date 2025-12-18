// src/lib/lock.rs

use anyhow::{Context, Result};
use fs2::FileExt;
use std::fs::File;
use std::path::PathBuf;

// We leak the file handle intentionally so the lock persists 
// until the process (daemon thread) decides to drop it.
static mut LOCK_FILE: Option<File> = None;

pub fn try_lock() -> Result<()> {
    let temp_dir = std::env::temp_dir();
    let lock_path = temp_dir.join("spatialshot.lock");

    let file = File::create(&lock_path).context("Failed to create lock file")?;
    
    // Try to lock exclusively. If it fails, someone else holds it.
    file.try_lock_exclusive().context("Capture is already running")?;

    unsafe {
        LOCK_FILE = Some(file);
    }

    Ok(())
}

pub fn unlock() {
    unsafe {
        if let Some(file) = LOCK_FILE.take() {
            let _ = file.unlock();
            // File drops here, closing the handle
        }
    }
}