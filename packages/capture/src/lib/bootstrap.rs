// src/lib/bootstrap.rs

use crate::embed::{ENGINE_VERSION, PAYLOAD_ZIP};
use anyhow::{Context, Result};
use fs2::FileExt;
use sha2::{Digest, Sha256};
use std::fs::File;
use std::io::Cursor;
use std::path::{Path, PathBuf};
use uuid::Uuid;

/// Ensures the capture engine is extracted and ready to run.
/// Returns the path to the executable binary.
pub fn ensure_engine() -> Result<PathBuf> {
    let data_dir = dirs::data_local_dir()
        .ok_or_else(|| anyhow::anyhow!("Could not determine AppData directory"))?
        .join("SpatialShot");

    let engine_dir = data_dir.join("engine");
    let version_marker = engine_dir.join("version.txt");

    // 1. Validate Payload Integrity BEFORE anything else
    // This protects against a corrupt binary being compiled in.
    let actual_hash = hex::encode(Sha256::digest(PAYLOAD_ZIP));
    if actual_hash != ENGINE_VERSION {
         return Err(anyhow::anyhow!("Embedded engine corrupted! Expected: {}, Got: {}", ENGINE_VERSION, actual_hash));
    }

    if let Some(parent) = engine_dir.parent() {
        std::fs::create_dir_all(parent)?;
    }

    // 2. Fast Path: Check if valid version exists
    if engine_dir.exists() {
        if let Ok(current_ver) = std::fs::read_to_string(&version_marker) {
            if current_ver.trim() == ENGINE_VERSION {
                return get_binary_path(&engine_dir);
            }
        }
    }

    // 3. Slow Path: Needs Extraction
    // Acquire lock to prevent two daemons extracting simultaneously
    let lock_path = data_dir.join("engine_install.lock");
    let lock_file = File::create(&lock_path).context("Failed to create install lock file")?;
    
    // Acquire exclusive lock (blocks until we get it)
    // On Unix, this uses flock. On Windows, LockFileEx.
    lock_file.lock_exclusive().context("Failed to acquire extraction lock")?;
    
    // Ensure we always release lock at function exit
    let _guard = scopeguard::guard(lock_file, |f| {
        let _ = f.unlock();
    });

    // Double-Checked Locking: Check again after acquiring lock
    if engine_dir.exists() {
        if let Ok(current_ver) = std::fs::read_to_string(&version_marker) {
            if current_ver.trim() == ENGINE_VERSION {
                return get_binary_path(&engine_dir);
            }
        }
        // Invalid or old version, remove it
        let _ = std::fs::remove_dir_all(&engine_dir);
    }

    log::info!("Extracting Capture Engine ({}) to {:?}", ENGINE_VERSION, engine_dir);

    // 4. Atomic Extraction Strategy
    // Extract to "engine-tmp-UUID" inside the same parent dir
    // This ensures 'rename' is atomic (same partition).
    let parent_dir = engine_dir.parent().unwrap();
    let tmp_dir_name = format!("engine-tmp-{}", Uuid::new_v4());
    let tmp_dir = parent_dir.join(tmp_dir_name);

    if tmp_dir.exists() {
        let _ = std::fs::remove_dir_all(&tmp_dir);
    }
    std::fs::create_dir_all(&tmp_dir)?;

    let mut archive = zip::ZipArchive::new(Cursor::new(PAYLOAD_ZIP))?;
    for i in 0..archive.len() {
        let mut file = archive.by_index(i)?;
        let outpath = match file.enclosed_name() {
            Some(p) => tmp_dir.join(p),
            None => continue,
        };

        if file.name().ends_with('/') {
            std::fs::create_dir_all(&outpath)?;
            continue;
        }

        if let Some(p) = outpath.parent() {
            std::fs::create_dir_all(p)?;
        }

        let mut outfile = std::fs::File::create(&outpath)?;
        std::io::copy(&mut file, &mut outfile)?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if let Some(mode) = file.unix_mode() {
                std::fs::set_permissions(&outpath, std::fs::Permissions::from_mode(mode))?;
            }
        }
    }

    // macOS quarantine removal (best-effort)
    #[cfg(target_os = "macos")]
    {
        let _ = remove_quarantine(&tmp_dir);
    }

    // 5. Atomic Rename (The Commit)
    // Windows rename fails if target exists, but we removed it above inside the lock.
    // However, just to be safe if something re-created it:
    if engine_dir.exists() {
        std::fs::remove_dir_all(&engine_dir).context("Failed to clean old engine dir")?;
    }
    
    std::fs::rename(&tmp_dir, &engine_dir).context("Failed to finalize engine extraction")?;

    // Write version marker
    std::fs::write(&version_marker, ENGINE_VERSION)?;

    get_binary_path(&engine_dir)
}

fn get_binary_path(base_dir: &std::path::Path) -> Result<PathBuf> {
    if cfg!(target_os = "windows") {
        let p = base_dir.join("capture.exe");
        // If dist structure is flat or has subfolders, check:
        if p.exists() { return Ok(p); }
        Ok(base_dir.join("capture.exe")) // Fallback
    } else if cfg!(target_os = "macos") {
        let app = base_dir.join("capture.app").join("Contents").join("MacOS").join("capture");
        if app.exists() { return Ok(app); }
        Ok(base_dir.join("capture")) // Fallback to raw binary
    } else {
        // Linux: Prefer top-level runner, then bin/capture-bin
        let runner = base_dir.join("capture");
        if runner.exists() { return Ok(runner); }
        
        let bin = base_dir.join("bin").join("capture-bin");
        if bin.exists() { return Ok(bin); }
        
        Ok(base_dir.join("capture-bin")) // Fallback
    }
}

#[cfg(target_os = "macos")]
fn remove_quarantine(path: &std::path::Path) -> Result<()> {
    let _ = std::process::Command::new("xattr")
        .arg("-r").arg("-d").arg("com.apple.quarantine").arg(path)
        .status(); 
    Ok(())
}