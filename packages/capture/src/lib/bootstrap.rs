// src/lib/bootstrap.rs

use crate::embed::{ENGINE_VERSION, PAYLOAD_ZIP};
use anyhow::{Context, Result};
use log::{info, warn};
use std::fs;
use std::io::Cursor;
use std::path::PathBuf;

/// Ensures the capture engine is extracted and ready to run.
/// Returns the path to the executable binary.
pub fn ensure_engine() -> Result<PathBuf> {
    let data_dir = dirs::data_local_dir()
        .ok_or_else(|| anyhow::anyhow!("Could not determine AppData directory"))?
        .join("SpatialShot");

    let engine_dir = data_dir.join("engine");
    let version_marker = engine_dir.join("version.txt");

    // 1. Check if valid version exists
    if engine_dir.exists() {
        if let Ok(current_ver) = fs::read_to_string(&version_marker) {
            if current_ver.trim() == ENGINE_VERSION {
                // Determine binary path
                return get_binary_path(&engine_dir);
            } else {
                warn!("Engine version mismatch (Found: {}, Target: {}). Updating...", current_ver, ENGINE_VERSION);
            }
        } else {
            warn!("Engine corrupted or missing version file. Re-installing.");
        }
        // Nuke old version
        let _ = fs::remove_dir_all(&engine_dir);
    }

    // 2. Perform Extraction
    info!("Extracting capture engine ({}) to {:?}", ENGINE_VERSION, engine_dir);
    install_engine(&engine_dir)?;

    // 3. Write Version Marker
    fs::write(&version_marker, ENGINE_VERSION)?;

    get_binary_path(&engine_dir)
}

fn install_engine(target_dir: &std::path::Path) -> Result<()> {
    // Atomic Strategy: Extract to a temp folder first? 
    // For simplicity in this daemon, we extract directly but verify errors.
    // (A true atomic swap is harder on Windows due to file locks).
    
    fs::create_dir_all(target_dir)?;

    let mut archive = zip::ZipArchive::new(Cursor::new(PAYLOAD_ZIP))?;

    for i in 0..archive.len() {
        let mut file = archive.by_index(i)?;
        
        // ZIP SLIP PROTECTION
        let outpath = match file.enclosed_name() {
            Some(path) => target_dir.join(path),
            None => continue,
        };

        if file.name().ends_with('/') {
            fs::create_dir_all(&outpath)?;
        } else {
            if let Some(p) = outpath.parent() {
                if !p.exists() {
                    fs::create_dir_all(p)?;
                }
            }
            let mut outfile = fs::File::create(&outpath)?;
            std::io::copy(&mut file, &mut outfile)?;
        }

        // Unix Permissions
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if let Some(mode) = file.unix_mode() {
                fs::set_permissions(&outpath, fs::Permissions::from_mode(mode))?;
            }
        }
    }

    // macOS Quarantine Fix
    #[cfg(target_os = "macos")]
    {
        remove_quarantine(target_dir)?;
    }

    Ok(())
}

fn get_binary_path(base_dir: &std::path::Path) -> Result<PathBuf> {
    if cfg!(target_os = "windows") {
        Ok(base_dir.join("capture.exe"))
    } else if cfg!(target_os = "macos") {
        // MACOS: Point to the inner Mach-O
        Ok(base_dir.join("capture.app").join("Contents").join("MacOS").join("capture"))
    } else {
        // Linux
        Ok(base_dir.join("capture-bin"))
    }
}

#[cfg(target_os = "macos")]
fn remove_quarantine(path: &std::path::Path) -> Result<()> {
    // recursively remove the "com.apple.quarantine" attribute
    // This prevents "App is damaged" or "Downloaded from internet" popups
    let status = std::process::Command::new("xattr")
        .arg("-r")
        .arg("-d")
        .arg("com.apple.quarantine")
        .arg(path)
        .status()?;
        
    if !status.success() {
        return Err(anyhow::anyhow!("Failed to strip quarantine attributes"));
    }
    Ok(())
}