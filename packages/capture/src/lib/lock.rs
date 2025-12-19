// packages/capture/src/lib/lock.rs

use anyhow::{Context, Result};
use fs2::FileExt;
use std::fs::File;
use once_cell::sync::OnceCell;

static LOCK_FILE: OnceCell<File> = OnceCell::new();

pub fn try_lock() -> Result<()> {
    let temp_dir = std::env::temp_dir();
    let lock_path = temp_dir.join("spatialshot.lock");

    let file = File::create(&lock_path)?;
    file.try_lock_exclusive().context("Capture is already running")?;

    // store the file so it lives until process exit or explicit unlock
    LOCK_FILE.set(file).ok(); // ignore if already set (shouldn't happen)
    Ok(())
}

pub fn unlock() {
    if let Some(file) = LOCK_FILE.get() {
        let _ = file.unlock();
        // don't remove the file; OS will clean or next run will reuse.
    }
}
