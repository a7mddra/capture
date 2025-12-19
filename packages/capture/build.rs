// packages/capture/build.rs

use std::env;
use std::fs::{self, File};
use std::io::{BufReader, Read, Write};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::SystemTime;
use walkdir::WalkDir;
use zip::write::FileOptions;
use zip::DateTime;
use sha2::{Digest, Sha256};

fn main() {
    let manifest_dir = env::var("CARGO_MANIFEST_DIR").unwrap();
    let root = Path::new(&manifest_dir);
    let dist_path = root.join("dist");
    let src_qt = root.join("src-qt");
    let embed_dir = root.join("src").join("embed");
    let output_zip = embed_dir.join("capture_engine.zip");
    let version_file = embed_dir.join("version_hash.rs");

    // 1. WATCHTRIGGERS
    println!("cargo:rerun-if-changed=build.rs");
    
    // Recursive watch for src-qt
    if src_qt.exists() {
        for entry in WalkDir::new(&src_qt).into_iter().filter_map(|e| e.ok()) {
            if entry.file_type().is_file() {
                println!("cargo:rerun-if-changed={}", entry.path().display());
            }
        }
    } else {
        println!("cargo:rerun-if-changed={}", src_qt.display());
    }
    
    // Recursive watch for dist
    if dist_path.exists() {
        for entry in WalkDir::new(&dist_path).into_iter().filter_map(|e| e.ok()) {
            if entry.file_type().is_file() {
                println!("cargo:rerun-if-changed={}", entry.path().display());
            }
        }
    } else {
        println!("cargo:rerun-if-changed={}", dist_path.display());
    }

    // 2. BUILD ORCHESTRATION
    if should_rebuild_cpp(&src_qt, &dist_path) {
        println!("cargo:warning=Orchestrating C++ Build...");
        
        let script_name = if cfg!(target_os = "windows") { "PKGBUILD.ps1" } else { "PKGBUILD" };
        let script_path = root.join(script_name);

        let status = if cfg!(target_os = "windows") {
             Command::new("powershell")
                .arg("-ExecutionPolicy").arg("Bypass")
                .arg("-File").arg(&script_path)
                .current_dir(root)
                .status()
        } else {
             Command::new(&script_path)
                .current_dir(root)
                .status()
        };

        match status {
            Ok(s) if s.success() => println!("cargo:warning=C++ Build Successful."),
            _ => {
                if env::var("PROFILE").unwrap() == "release" {
                    panic!("⛔ FATAL: C++ Build Failed. Check logs.");
                }
                println!("cargo:warning=C++ Build Failed. Using DUMMY payload for Debug.");
                create_dummy_zip(&output_zip);
                write_version_file(&version_file, "dummy-error-fallback");
                return;
            }
        }
    }

    // 3. COMPRESS
    if !embed_dir.exists() {
        fs::create_dir_all(&embed_dir).expect("Failed to create embed dir");
    }

    compress_dist(&dist_path, &output_zip);

    // 4. HASH
    let hash = calculate_sha256(&output_zip);
    write_version_file(&version_file, &hash);
}

fn should_rebuild_cpp(src: &Path, dist: &Path) -> bool {
    if !dist.exists() { return true; }
    
    // If src doesn't exist, we can't build it anyway
    if !src.exists() { return false; }

    let src_mtime = max_mtime(src).unwrap_or(SystemTime::UNIX_EPOCH);
    let dist_mtime = min_mtime(dist).unwrap_or(SystemTime::now());
    
    src_mtime > dist_mtime
}

fn max_mtime(path: &Path) -> Option<SystemTime> {
    WalkDir::new(path).into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().is_file())
        .filter_map(|e| e.metadata().ok())
        .filter_map(|m| m.modified().ok())
        .max()
}

fn min_mtime(path: &Path) -> Option<SystemTime> {
    WalkDir::new(path).into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().is_file())
        .filter_map(|e| e.metadata().ok())
        .filter_map(|m| m.modified().ok())
        .min()
}

fn write_version_file(path: &Path, version: &str) {
    let content = format!("pub const ENGINE_VERSION: &str = \"{}\";", version);
    let mut file = File::create(path).expect("Failed to create version file");
    file.write_all(content.as_bytes()).expect("Failed to write version file");
}

fn calculate_sha256(path: &Path) -> String {
    let f = File::open(path).expect("Failed to open zip for hashing");
    let mut reader = BufReader::new(f);
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 8192];
    loop {
        match reader.read(&mut buffer) {
            Ok(0) => break,
            Ok(n) => hasher.update(&buffer[..n]),
            Err(e) => panic!("Failed to read zip for hashing: {}", e),
        }
    }
    hex::encode(hasher.finalize())
}

fn compress_dist(src_dir: &Path, dst_file: &Path) {
    if !src_dir.exists() {
        // If dist is missing (e.g. failed build but proceeding to dummy), ensure we don't crash
        // But logic above handles this. If we get here, dist SHOULD exist or we made dummy.
        // If dist is missing here, it means build failed and we are in release.
        panic!("dist folder missing: {}", src_dir.display());
    }

    let file = File::create(dst_file).expect("Failed to create zip file");
    let mut zip = zip::ZipWriter::new(file);

    // FIXED: Constant time for determinism
    // Using 1980-01-01 00:00:00 as default for zip
    let options = FileOptions::default()
        .compression_method(zip::CompressionMethod::Deflated)
        .last_modified_time(DateTime::default()) 
        .unix_permissions(0o755);

    let walk = WalkDir::new(src_dir);
    let mut buffer = Vec::new(); // Fix: proper buffer allocation

    // 1. Collect entries first
    let mut entries: Vec<_> = walk.into_iter()
        .filter_map(|e| e.ok())
        .collect();

    // 2. Sort by path (Crucial for deterministic SHA256)
    entries.sort_by(|a, b| a.path().cmp(b.path()));

    for entry in entries {
        let path = entry.path();
        if path == src_dir { continue; }
        
        let name = path.strip_prefix(src_dir).unwrap().to_str().unwrap().replace("\\", "/");

        if path.is_file() {
            #[cfg(unix)]
            let mut options = options;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                if let Ok(meta) = fs::metadata(path) {
                    options = options.unix_permissions(meta.permissions().mode());
                }
            }

            zip.start_file(name, options).expect("zip start_file failed");
            let mut f = File::open(path).expect("open source file failed");
            buffer.clear();
            f.read_to_end(&mut buffer).expect("read file failed");
            zip.write_all(&buffer).expect("zip write failed");
        } else if !name.is_empty() {
            zip.add_directory(name, options).expect("add_directory failed");
        }
    }
    zip.finish().expect("Failed to finish zip");
}

fn create_dummy_zip(dst_file: &Path) {
    if let Some(parent) = dst_file.parent() { fs::create_dir_all(parent).unwrap(); }
    let file = File::create(dst_file).unwrap();
    let mut zip = zip::ZipWriter::new(file);
    zip.start_file("README.txt", FileOptions::default()).unwrap();
    zip.write_all(b"Dummy payload.").unwrap();
    zip.finish().unwrap();
}