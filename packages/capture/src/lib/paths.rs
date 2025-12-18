// src/lib/paths.rs

use anyhow::{anyhow, Result};
use std::path::PathBuf;

pub fn get_app_data_dir() -> Result<PathBuf> {
    dirs::data_local_dir()
        .ok_or_else(|| anyhow!("Could not determine local data directory"))
        .map(|p| p.join("SpatialShot"))
}

pub fn get_temp_image_path() -> PathBuf {
    // MUST match the hardcoded string in DrawView.cpp
    std::env::temp_dir().join("spatial_capture.png") 
}