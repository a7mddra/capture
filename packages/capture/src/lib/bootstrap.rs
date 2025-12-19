// packages/capture/src/lib/bootstrap.rs

use crate::embed::{ENGINE_VERSION, PAYLOAD_ZIP};
use anyhow::{Context, Result};
use fs2::FileExt;
use std::fs::File;
use std::io::Cursor;
use std::path::PathBuf;
use tempfile::tempdir_in;

/// Ensures the capture engine is extracted and ready to run.
/// Returns the path to the executable binary.
pub fn ensure_engine() -> Result<PathBuf> {
    let data_dir = dirs::data_local_dir()
        .ok_or_else(|| anyhow::anyhow!("Could not determine AppData directory"))?
        .join("SpatialShot");

    let engine_dir = data_dir.join("engine");
    let version_marker = engine_dir.join("version.txt");

    // Create parent dir
    if let Some(parent) = engine_dir.parent() {
        std::fs::create_dir_all(parent)?;
    }

    // Lock file path (next to engine dir)
    let lock_path = data_dir.join("engine_extract.lock");
    let lock_file = File::create(&lock_path).context("Failed to create lock file")?;
    // Acquire exclusive lock (blocks until we get it)
    lock_file.lock_exclusive().context("Failed to acquire extraction lock")?;

    // Ensure we always release lock at function exit
    let _guard = scopeguard::guard(lock_file, |f| {
        let _ = f.unlock();
    });

    // If engine exists and matches version -> return
    if engine_dir.exists() {
        if let Ok(current_ver) = std::fs::read_to_string(&version_marker) {
            if current_ver.trim() == ENGINE_VERSION {
                return get_binary_path(&engine_dir);
            } else {
                log::warn!(
                    "Engine version mismatch (found {}, target {}). Reinstalling.",
                    current_ver.trim(),
                    ENGINE_VERSION
                );
                let _ = std::fs::remove_dir_all(&engine_dir);
            }
        } else {
            log::warn!("Engine exists but version file unreadable. Reinstalling.");
            let _ = std::fs::remove_dir_all(&engine_dir);
        }
    }

    // Extract to temporary directory in same parent (so rename is atomic)
    let parent_dir = engine_dir
        .parent()
        .ok_or_else(|| anyhow::anyhow!("Engine dir parent missing"))?;
    let tmp = tempdir_in(parent_dir)?;
    let tmp_engine = tmp.path().join("engine_tmp");

    // Perform extraction into tmp_engine
    std::fs::create_dir_all(&tmp_engine)?;
    let mut archive = zip::ZipArchive::new(Cursor::new(PAYLOAD_ZIP))?;
    for i in 0..archive.len() {
        let mut file = archive.by_index(i)?;
        let outpath = match file.enclosed_name() {
            Some(p) => tmp_engine.join(p),
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
        let _ = remove_quarantine(&tmp_engine);
    }

    // Atomic rename into place
    if engine_dir.exists() {
        std::fs::remove_dir_all(&engine_dir)?;
    }
    std::fs::rename(&tmp_engine, &engine_dir)?;

    // Write version marker
    std::fs::write(engine_dir.join("version.txt"), ENGINE_VERSION)?;

    get_binary_path(&engine_dir)
}

fn get_binary_path(base_dir: &std::path::Path) -> Result<PathBuf> {
    if cfg!(target_os = "windows") {
        Ok(base_dir.join("capture.exe"))
    } else if cfg!(target_os = "macos") {
        Ok(base_dir.join("capture.app").join("Contents").join("MacOS").join("capture"))
    } else {
        Ok(base_dir.join("capture-bin"))
    }
}

#[cfg(target_os = "macos")]
fn remove_quarantine(path: &std::path::Path) -> Result<()> {
    let _ = std::process::Command::new("xattr")
        .arg("-r").arg("-d").arg("com.apple.quarantine").arg(path)
        .status(); 
    Ok(())
}
