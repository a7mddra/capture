// build.rs

use std::env;
use std::fs::File;
use std::io::{Read, Write};
use std::path::Path;
use walkdir::WalkDir;
use zip::write::FileOptions;

fn main() {
    // 1. Define Paths
    let manifest_dir = env::var("CARGO_MANIFEST_DIR").unwrap();
    let dist_path = Path::new(&manifest_dir).join("dist");
    let embed_dir = Path::new(&manifest_dir).join("src").join("embed");
    let output_zip = embed_dir.join("capture_engine.zip");

    // 2. Trigger Re-run only if 'dist' changes
    println!("cargo:rerun-if-changed=dist");

    // 3. Validation
    if !dist_path.exists() {
        // If dist doesn't exist, we might be in a "clean" state or just starting.
        // We create a dummy zip to allow 'cargo check' to pass, but warn heavily.
        println!("cargo:warning=DIST FOLDER MISSING. Creating dummy payload.");
        create_dummy_zip(&output_zip);
        return;
    }

    // 4. Create the Embed Directory if missing
    if !embed_dir.exists() {
        std::fs::create_dir_all(&embed_dir).expect("Failed to create embed dir");
    }

    // 5. Compress 'dist' contents into the zip
    compress_dist(&dist_path, &output_zip);
}

fn compress_dist(src_dir: &Path, dst_file: &Path) {
    let file = File::create(dst_file).expect("Failed to create zip file");
    let mut zip = zip::ZipWriter::new(file);
    let options = FileOptions::default()
        .compression_method(zip::CompressionMethod::Stored) // Faster extract, slightly larger
        .unix_permissions(0o755); // Ensure executable

    let walk = WalkDir::new(src_dir);
    let buffer = &mut Vec::new();

    for entry in walk.into_iter().filter_map(|e| e.ok()) {
        let path = entry.path();
        
        // Skip the root dir itself
        if path == src_dir { continue; }

        let name = path.strip_prefix(src_dir).unwrap().to_str().unwrap();

        // Write entry
        if path.is_file() {
            // Preserve executable permissions on Unix/Mac
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
    if let Some(parent) = dst_file.parent() {
        std::fs::create_dir_all(parent).unwrap();
    }
    let file = File::create(dst_file).unwrap();
    let mut zip = zip::ZipWriter::new(file);
    zip.start_file("README.txt", FileOptions::default()).unwrap();
    zip.write_all(b"Dummy payload. Run Qt build first.").unwrap();
    zip.finish().unwrap();
}