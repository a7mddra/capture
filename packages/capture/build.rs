// packages/capture/build.rs

use std::env;
use std::fs::File;
use std::io::{BufReader, Read, Write};
use std::path::Path;
use std::process::Command;
use walkdir::WalkDir;
use zip::write::FileOptions;
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
    // Re-run if C++ source changes
    println!("cargo:rerun-if-changed={}", src_qt.display());
    
    // Re-run if any file in dist changes (Manual intervention or previous build artifact)
    if dist_path.exists() {
        for entry in WalkDir::new(&dist_path).into_iter().filter_map(|e| e.ok()) {
            if entry.file_type().is_file() {
                println!("cargo:rerun-if-changed={}", entry.path().display());
            }
        }
    } else {
        println!("cargo:rerun-if-changed={}", dist_path.display());
    }


    // 2. BUILD ORCHESTRATION (The "Construction" Phase)
    // If dist is missing OR we are in release mode and src-qt changed, rebuild C++.
    if !dist_path.exists() || should_rebuild_cpp(&src_qt, &dist_path) {
        println!("cargo:warning=Orchestrating C++ Build (this may take a while)...");
        
        let status = if cfg!(target_os = "windows") {
             Command::new("powershell")
                .arg("-ExecutionPolicy").arg("Bypass")
                .arg("-File").arg("PKGBUILD.ps1")
                .current_dir(root)
                .status()
        } else {
             Command::new("./PKGBUILD")
                .current_dir(root)
                .status()
        };

        match status {
            Ok(s) if s.success() => println!("cargo:warning=C++ Build Successful."),
            _ => {
                // In Debug, we can fallback to dummy. In Release, we die.
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

    // 3. COMPRESS (The "Encapsulation" Phase)
    if !embed_dir.exists() {
        std::fs::create_dir_all(&embed_dir).expect("Failed to create embed dir");
    }

    // Ensure we compress the FRESH dist
    compress_dist(&dist_path, &output_zip);

    // 4. HASH
    let hash = calculate_sha256(&output_zip);
    write_version_file(&version_file, &hash);
}

// Simple logic: If any file in src-qt is newer than dist, rebuild.
fn should_rebuild_cpp(src: &Path, dist: &Path) -> bool {
    // Basic check: if dist is empty, rebuild
    if !dist.exists() { return true; }
    // In a real scenario, you might compare mtimes, but for now, 
    // we assume if the user ran cargo build, they might want to sync.
    // However, C++ builds are slow, so we rely on explicit 'dist' existence usually.
    // For now, strictly rely on dist existence to avoid infinite build loops 
    // unless you implement a sophisticated mtime walker.
    false 
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
    let file = File::create(dst_file).expect("Failed to create zip file");
    let mut zip = zip::ZipWriter::new(file);
    // Use stored (0) compression for speed since the binary will be zipped again by the installer usually
    // Or Deflate for smaller binary size.
    let options = FileOptions::default()
        .compression_method(zip::CompressionMethod::Deflated) 
        .unix_permissions(0o755);

    let walk = WalkDir::new(src_dir);
    let buffer = &mut Vec::new();

    for entry in walk.into_iter().filter_map(|e| e.ok()) {
        let path = entry.path();
        if path == src_dir { continue; }
        
        // Fix for Windows paths in zip
        let name = path.strip_prefix(src_dir).unwrap().to_str().unwrap().replace("\\", "/");

        if path.is_file() {
            #[cfg(unix)]
            let options = {
                use std::os::unix::fs::PermissionsExt;
                let meta = std::fs::metadata(path).unwrap();
                options.unix_permissions(meta.permissions().mode())
            };
            zip.start_file(name, options).unwrap();
            let mut f = File::open(path).unwrap();
            f.read_to_end(buffer).unwrap();
            zip.write_all(buffer).unwrap();
            buffer.clear();
        } else if !name.is_empty() {
            zip.add_directory(name, options).unwrap();
        }
    }
    zip.finish().unwrap();
}

fn create_dummy_zip(dst_file: &Path) {
    if let Some(parent) = dst_file.parent() { std::fs::create_dir_all(parent).unwrap(); }
    let file = File::create(dst_file).unwrap();
    let mut zip = zip::ZipWriter::new(file);
    zip.start_file("README.txt", FileOptions::default()).unwrap();
    zip.write_all(b"Dummy payload.").unwrap();
    zip.finish().unwrap();
}
