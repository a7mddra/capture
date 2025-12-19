i'm building a hybrid screenshot utility with native c++ and rust carrier.
Spatialshot is an open-source "Circle to Search" desktop utility that brings the power of AI vision directly to your screen. It provides seamless screen capture by drawing not rect, analysis, and visual search capabilities with a single hotkey.

tauri is done and production ready for shipping but before this we need it to ship some bags with him before leaving:

### The Matryoshka Blueprint: From Source to Hotkey

Here is the architectural flow of how I ship three worlds in one package without the user ever knowing.

#### Phase 1: Construction (The Inner Doll 🪆)

**Goal:** Turn the raw C++ code in `src-qt/` into a portable, standalone folder.

1. **The Trigger:** I run `cargo build` inside `packages/capture`.
2. **The Orchestrator:** `build.rs` wakes up first. It notices that `src-qt/` exists.
3. **The Heavy Lifting:**
* On **Windows**, `build.rs` executes `PKGBUILD.ps1`. This compiles `src-qt/` and runs `windeployqt` to gather all DLLs.
* On **Unix**, `build.rs` executes `PKGBUILD`. This compiles `src-qt/` via CMake and gathers `.so`/`.dylib` dependencies using my custom dependency walker.


4. **The Artifact:** The result is a folder named `dist/` containing the executable and all its libraries. This folder is "portable"—it can run anywhere.

#### Phase 2: Encapsulation (The Middle Doll 🪆)

**Goal:** Bake the portable `dist/` folder inside the Rust binary so it is invisible to the outside world.

1. **The Compression:** `build.rs` (still running) takes the verified `dist/` folder and compresses it into a single blob: `src/embed/capture_kit.zip`.
2. **The Embedding:** The Rust compiler (`rustc`) takes over. It compiles `src/main.rs`.
3. **The Ingestion:** Inside `src/lib/bootstrap.rs`, the compiler finds the `include_bytes!` macro pointing to that zip file. It literally copies the zeros and ones of the zip file into the data segment of the Rust executable.
4. **The Result:** I now have **one single binary** (let's call it `daemon`). It looks like a normal Rust program, but it is "pregnant" with the C++ engine.

#### Phase 3: Shipping (The Outer Doll 🪆)

**Goal:** Deliver this pregnant daemon to the user via Tauri.

1. **The Handover:** I configure `packages/app` (Tauri) to treat my new `daemon` binary as an `externalBin`.
2. **The Installer:** Tauri builds the installer (`.msi`, `.dmg`, `.deb`). It takes my `daemon` binary and places it inside the installation folder (e.g., inside `Program Files/SpatialShot/` or `SpatialShot.app/Contents/MacOS/`).
3. **The Signing:** Since the C++ code is hidden inside the Rust binary, I only need to sign the Rust binary and the Tauri binary. (Note: On Mac, the internal signature remains valid because I signed it during Phase 1).

#### Phase 4: Runtime (The Birth 🐣)

**Goal:** The user runs the app, and the daemon deploys the capture engine just-in-time.

1. **Startup:** The user opens SpatialShot. Tauri launches the `daemon` in the background.
    NOTE: on linux: `daemon` isnt a background service. rdev works only for windows and macos as hotkey listener. instead tauri will run linux_hotkey_installer.sh in the installation step one time. it will add spatialshot in settings custome shortcuts so the OS is the background service that listens for hotkeys not daemon. but the hotkey will launch the daemon as orchestrator: daemon extracts c++ and mutes sound and captures and passes to tauri so it's the same as window/macos but without the hotkey part. also i have a robust bash script bundled in tauri (finished app) so put your focus on rust code.
2. **The Check (Idempotency):** `src/main.rs` starts and calls `lib/bootstrap.rs`. It asks: *"Does `AppData/SpatialShot/capture-v1/` exist?"*
3. **The Birth:**
* **First Run:** "No." -> The daemon reads its own internal memory, extracts the zip to that `AppData` folder (we use appdata bcause AVs treat externalbin in %Temp% or sys32 as trojan virus), and sets execute permissions (and fixes Mac quarantine by xattr).
* **Subsequent Runs:** "Yes." -> The daemon skips extraction immediately.


4. **The Watch:** `sys/hotkey.rs` starts the global hotkey listener.
5. **The Strike:**
* User presses **Cmd/Win + shift + A**.
* `sys/hotkey.rs` detects it OR linux detects <Super> + shift + A.
* `src/main.rs` tells the OS to run the **C++ executable** sitting in `AppData`.
* The C++ process spawns, freezes the screen, handles the "squiggle," saves the image, and dies.
* `src/main.rs` picks up the result and sends it to Tauri.



**Summary:** I compile three languages, but I ship one file. The user installs one app, but gets a complete suite. This is the Matryoshka Blueprint.

---

i asked 5 senior devs to review the current codebase and i want you to apply there fixes.

senior 1:
===
This is a solid execution of the "dropper" pattern. You have correctly identified the three distinct phases.

**Architecture Rating: 9/10**
You are trading **disk space** and **initial startup time** for **guaranteed environmental consistency**. This is the correct trade-off for a visual tool that relies on specific Qt versions and system libraries.

However, I found **3 Critical Bugs** in your Rust code that will cause the app to hang, leave users with broken installations, or fail silently.

### 🔍 Critical Review Findings

1. **The Hotkey Deadlock (Severity: High):**
In `src/sys/hotkey.rs`, you run the callback inside the `rdev` listen loop. `lib::capture::run` blocks the thread for up to 30 seconds (waiting for C++).
* *Result:* While the screenshot is happening, the OS input event queue might get backed up, or the listener will simply stop responding to subsequent key releases (like releasing Shift), leaving the `AtomicBool` flags stuck in `true`.


2. **Non-Atomic Extraction (Severity: Medium):**
In `src/lib/bootstrap.rs`, you extract files one by one into the live `engine` folder.
* *Result:* If the user forces close or the app crashes during unzip (byte 50 of 100MB), the next time they open it, `version.txt` might exist (or not), but the binaries will be half-written. The app will crash repeatedly.


3. **The Build Script "Lie" (Severity: Low/DevOps):**
Your description said "`build.rs` executes `PKGBUILD`". Your code **does not**. It only checks if `dist` exists and panics if missing in Release.
* *Result:* You have to manually run the shell script every time you change C++ code. I will fix this to make it actually orchestrate the build.



---

### 🛠️ The Fixes

Here are the corrected files. Copy these over to fix the logic flaws.

#### 1. Fixed `packages/capture/build.rs`

*Now actually acts as an Orchestrator. It detects OS and runs the C++ build script automatically if `dist` is missing or `src-qt` changed.*

```rust
// packages/capture/build.rs

use std::env;
use std::fs::File;
use std::io::{Read, Write};
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

    // 1. WATCH TRIGGERS
    println!("cargo:rerun-if-changed=build.rs");
    // Re-run if C++ source changes
    println!("cargo:rerun-if-changed={}", src_qt.display());
    // Re-run if dist changes (manual intervention)
    println!("cargo:rerun-if-changed={}", dist_path.display());

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
    let mut file = File::open(path).expect("Failed to open zip for hashing");
    let mut hasher = Sha256::new();
    std::io::copy(&mut file, &mut hasher).expect("Failed to read zip for hashing");
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

```

#### 2. Fixed `packages/capture/src/lib/bootstrap.rs`

*Implements Atomic Extraction (The Transactional Birth). Checks hash, unzips to temp, swaps folder.*

```rust
// packages/capture/src/lib/bootstrap.rs

use crate::embed::{ENGINE_VERSION, PAYLOAD_ZIP};
use anyhow::{Context, Result};
use log::{info, warn};
use std::fs;
use std::io::Cursor;
use std::path::{Path, PathBuf};

pub fn ensure_engine() -> Result<PathBuf> {
    let data_dir = dirs::data_local_dir()
        .ok_or_else(|| anyhow::anyhow!("Could not determine AppData directory"))?
        .join("SpatialShot");

    let engine_dir = data_dir.join("engine");
    let version_marker = engine_dir.join("version.txt");

    // 1. IDEMPOTENCY CHECK
    // If version matches, we are good.
    if engine_dir.exists() {
        if let Ok(current_ver) = fs::read_to_string(&version_marker) {
            if current_ver.trim() == ENGINE_VERSION {
                return get_binary_path(&engine_dir);
            }
        }
    }

    // 2. ATOMIC EXTRACTION STRATEGY
    // Extract to "engine_tmp_RANDOM" first.
    let temp_dir = data_dir.join(format!("engine_tmp_{}", uuid::Uuid::new_v4()));
    
    // Clean up any old temps from previous failed runs
    cleanup_old_temps(&data_dir);

    info!("Extracting engine ({}) to temporary location...", ENGINE_VERSION);
    
    match install_engine(&temp_dir) {
        Ok(_) => {
            // Write version inside temp before swap
            fs::write(temp_dir.join("version.txt"), ENGINE_VERSION)?;

            // 3. THE SWAP
            if engine_dir.exists() {
                // Windows rename fails if target exists, so we must remove first
                let _ = fs::remove_dir_all(&engine_dir); 
            }
            
            // Rename is atomic on POSIX, usually atomic on Windows (if no locks)
            fs::rename(&temp_dir, &engine_dir).context("Failed to finalize engine extraction")?;
            
            info!("Engine deployment complete.");
            get_binary_path(&engine_dir)
        }
        Err(e) => {
            // Cleanup temp on failure
            let _ = fs::remove_dir_all(&temp_dir);
            Err(e)
        }
    }
}

fn cleanup_old_temps(base: &Path) {
    if let Ok(entries) = fs::read_dir(base) {
        for entry in entries.flatten() {
            let path = entry.path();
            if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
                if name.starts_with("engine_tmp_") {
                    let _ = fs::remove_dir_all(path);
                }
            }
        }
    }
}

// ... [install_engine and get_binary_path remain mostly the same, ensuring ZIP SLIP check matches previous file] ...
// CRITICAL: Ensure install_engine handles the ZIP extraction exactly as you had it, 
// just ensure target_dir is the temp_dir passed in.

fn install_engine(target_dir: &Path) -> Result<()> {
    fs::create_dir_all(target_dir)?;
    let mut archive = zip::ZipArchive::new(Cursor::new(PAYLOAD_ZIP))?;

    for i in 0..archive.len() {
        let mut file = archive.by_index(i)?;
        let outpath = match file.enclosed_name() {
            Some(path) => target_dir.join(path),
            None => continue,
        };

        if file.name().ends_with('/') {
            fs::create_dir_all(&outpath)?;
        } else {
            if let Some(p) = outpath.parent() {
                if !p.exists() { fs::create_dir_all(p)?; }
            }
            let mut outfile = fs::File::create(&outpath)?;
            std::io::copy(&mut file, &mut outfile)?;
        }

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if let Some(mode) = file.unix_mode() {
                fs::set_permissions(&outpath, fs::Permissions::from_mode(mode))?;
            }
        }
    }

    #[cfg(target_os = "macos")]
    {
        remove_quarantine(target_dir)?;
    }

    Ok(())
}

fn get_binary_path(base_dir: &Path) -> Result<PathBuf> {
    if cfg!(target_os = "windows") {
        Ok(base_dir.join("capture.exe"))
    } else if cfg!(target_os = "macos") {
        Ok(base_dir.join("capture.app").join("Contents").join("MacOS").join("capture"))
    } else {
        Ok(base_dir.join("capture-bin"))
    }
}

#[cfg(target_os = "macos")]
fn remove_quarantine(path: &Path) -> Result<()> {
    let status = std::process::Command::new("xattr")
        .arg("-r").arg("-d").arg("com.apple.quarantine").arg(path)
        .status(); // Don't check error rigorously, as it might not have the attr
    Ok(())
}

```

*Note: You need to add `uuid = { version = "1.0", features = ["v4"] }` to Cargo.toml for the temp folder naming.*

#### 3. Fixed `packages/capture/src/sys/hotkey.rs`

*Fixes the Deadlock. Spawns a new thread for the heavy lifting so `rdev` can keep processing events.*

```rust
// packages/capture/src/sys/hotkey.rs

use log::{error, info};
use std::thread;

#[cfg(not(target_os = "linux"))]
pub fn listen<F>(callback_fn: F)
where
    F: Fn() + Send + Sync + 'static,
{
    use rdev::{EventType, Key};
    use std::sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    };
    use std::time::{Duration, Instant};

    info!("Starting Global Hotkey Listener (rdev)...");

    let meta_down = Arc::new(AtomicBool::new(false));
    let shift_down = Arc::new(AtomicBool::new(false));
    let last_trigger = Arc::new(parking_lot::Mutex::new(
        Instant::now() - Duration::from_secs(10),
    ));

    let callback = Arc::new(callback_fn);

    let m = meta_down.clone();
    let s = shift_down.clone();
    let t = last_trigger.clone();

    if let Err(error) = rdev::listen(move |event| {
        match event.event_type {
            EventType::KeyPress(key) => {
                match key {
                    Key::MetaLeft | Key::MetaRight => m.store(true, Ordering::SeqCst),
                    Key::ShiftLeft | Key::ShiftRight => s.store(true, Ordering::SeqCst),
                    Key::KeyA => {
                        if m.load(Ordering::SeqCst) && s.load(Ordering::SeqCst) {
                            let mut last = t.lock();
                            if last.elapsed() >= Duration::from_millis(500) {
                                info!("Hotkey Detected: Meta+Shift+A");
                                *last = Instant::now();

                                // CRITICAL FIX: Spawn logic in a new thread.
                                // Do not block the input listener!
                                let cb_clone = callback.clone();
                                thread::spawn(move || {
                                    (cb_clone)();
                                });
                            }
                        }
                    }
                    _ => {}
                }
            }
            EventType::KeyRelease(key) => match key {
                Key::MetaLeft | Key::MetaRight => m.store(false, Ordering::SeqCst),
                Key::ShiftLeft | Key::ShiftRight => s.store(false, Ordering::SeqCst),
                _ => {}
            },
            _ => {}
        }
    }) {
        error!("Global listener error: {:?}", error);
    }
}

```

### 📦 Deployment Checklist

1. **Dependencies:** Add `uuid` to your `packages/capture/Cargo.toml`.
2. **Linux Shortcuts:** Since you are relying on `linux_hotkey_installer.sh` via Tauri, ensure your Tauri installer actually runs this post-install.
* *Tip:* In `.deb`, use a `postinst` script. In AppImage, it's harder; you might need to run the check inside Tauri `main.rs` on startup ("Is shortcut registered? If not, register it").


3. **MacOS Signing:** In your `distribute.yml`, you are signing `dist/capture.app` before embedding. **This is good.**
* *Warning:* When `bootstrap.rs` extracts the app on the user's machine, the signature is preserved, BUT the `com.apple.quarantine` attribute invalidates it.
* *Verification:* Your `remove_quarantine` function is the hero here. Ensure that `xattr` is available on the target user's path (it usually is /usr/bin/xattr).



This architecture is robust. The Rust carrier acting as a "Just-In-Time" installer for the C++ engine solves the dependency hell of C++ distribution gracefully. Good luck shipping.
===

senior 2:
===
Excellent architecture! Your **Matryoshka Blueprint** is well-designed. I've analyzed your code and found several critical bugs and improvements needed. Here's my review:

## 🚨 **CRITICAL BUGS TO FIX IMMEDIATELY**

### **1. Race Condition in `lock.rs` - UNSAFE!**
```rust
// BUG: This is UNSAFE! Multiple threads can access this simultaneously
static mut LOCK_FILE: Option<File> = None;  // ❌ NEVER use `static mut`

pub fn try_lock() -> Result<()> {
    // ... racing threads could create multiple lock files
}
```

**Fix with `OnceLock` or `Mutex`:**
```rust
use std::sync::OnceLock;
use parking_lot::Mutex;

struct LockState {
    file: Option<File>,
    path: PathBuf,
}

static LOCK_STATE: OnceLock<Mutex<LockState>> = OnceLock::new();

pub fn try_lock() -> Result<LockGuard> {
    let state = LOCK_STATE.get_or_init(|| {
        let path = std::env::temp_dir().join("spatialshot.lock");
        Mutex::new(LockState { file: None, path })
    });
    
    let mut guard = state.lock();
    if guard.file.is_some() {
        return Err(anyhow!("Already locked"));
    }
    
    let file = File::create(&guard.path)?;
    file.try_lock_exclusive()?;
    guard.file = Some(file);
    
    Ok(LockGuard)  // Custom guard that unlocks on drop
}
```

### **2. `CAPTURE_PID` Race Condition**
```rust
// In sys/mod.rs - This has a race condition!
pub fn set_capture_pid(pid: u32) {
    CAPTURE_PID.store(pid, Ordering::SeqCst);  // ❌ What if old process isn't dead?
}
```

**Fix with PID tracking and validation:**
```rust
use sysinfo::{Pid, System};

pub fn set_capture_pid(pid: u32) {
    let old_pid = CAPTURE_PID.swap(pid, Ordering::SeqCst);
    
    // Clean up any stale process
    if old_pid != 0 && old_pid != pid {
        let sys = System::new_all();
        if sys.process(Pid::from_u32(old_pid)).is_some() {
            let _ = kill_process(old_pid);
        }
    }
}
```

### **3. **ZIP SLIP VULNERABILITY** in `bootstrap.rs`**
Your code is vulnerable! Attackers could write files outside the target directory:

```rust
// ❌ VULNERABLE: `enclosed_name()` doesn't prevent all attacks
let outpath = match file.enclosed_name() {
    Some(path) => target_dir.join(path),  // Still dangerous!
    None => continue,
};
```

**Fix with canonicalization check:**
```rust
use std::path::Path;

fn is_safe_path(base: &Path, candidate: &Path) -> bool {
    let base_canon = base.canonicalize().unwrap_or_default();
    let cand_canon = candidate.canonicalize().unwrap_or_default();
    cand_canon.starts_with(&base_canon)
}

// In extraction loop:
let outpath = target_dir.join(file.name());
if !is_safe_path(&target_dir, &outpath) {
    return Err(anyhow!("Zip slip attempt detected: {}", file.name()));
}
```

## 🐛 **MAJOR FUNCTIONALITY BUGS**

### **4. Linux Hotkey Script Missing**
Your architecture says Linux uses a bash script, but it's not implemented:

```rust
// Add this file: packages/capture/scripts/linux-hotkey-installer.sh
#!/bin/bash
# Registers Super+Shift+A with the desktop environment

if command -v gsettings &> /dev/null; then
    # GNOME
    gsettings set org.gnome.settings-daemon.plugins.media-keys custom-keybindings \
        "$(gsettings get org.gnome.settings-daemon.plugins.media-keys custom-keybindings | sed "s/\]/, '/org.gnome.settings-daemon.plugins.media-keys.custom-keybinding:/custom99']/")"
    gsettings set org.gnome.settings-daemon.plugins.media-keys.custom-keybinding:/custom99/ name "'SpatialShot'"
    gsettings set org.gnome.settings-daemon.plugins.media-keys.custom-keybinding:/custom99/ command "'/usr/bin/spatialshot-daemon --trigger'"
    gsettings set org.gnome.settings-daemon.plugins.media-keys.custom-keybinding:/custom99/ binding "'<Super><Shift>a'"
fi
```

### **5. Audio Guard Doesn't Restore State Properly**
```rust
// BUG: AudioGuard might restore incorrectly if system was already muted
fn try_backend(&mut self, cmd: &'static str, check_args: &[&str], mute_args: &[&str]) -> bool {
    // ... what if we fail to check but succeed in muting?
}
```

**Fix with state persistence:**
```rust
use serde_json;
use std::fs;

struct AudioState {
    backend: String,
    was_muted: bool,
    timestamp: u64,
}

impl AudioGuard {
    fn save_state(&self) -> Result<()> {
        let state = AudioState {
            backend: self.backend.unwrap_or("unknown").to_string(),
            was_muted: self.was_previously_muted,
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)?
                .as_secs(),
        };
        
        let state_path = dirs::cache_dir()
            .unwrap()
            .join("spatialshot-audio-state.json");
        fs::write(state_path, serde_json::to_string(&state)?)?;
        Ok(())
    }
}
```

### **6. Monitor Count on Linux is Wrong**
```rust
// BUG: `xrandr --listmonitors` output format varies
fn get_monitor_count() -> i32 {
    String::from_utf8_lossy(&out.stdout).lines().count() as i32 - 1
    // This counts lines, not monitors!
}
```

**Fix with proper parsing:**
```rust
#[cfg(target_os = "linux")]
fn get_monitor_count() -> i32 {
    use std::process::Command;
    
    // Method 1: XRandR
    if let Ok(output) = Command::new("xrandr").arg("--listmonitors").output() {
        let out = String::from_utf8_lossy(&output.stdout);
        for line in out.lines() {
            if line.starts_with("Monitors: ") {
                if let Some(count) = line.split_whitespace().nth(1) {
                    return count.parse().unwrap_or(1);
                }
            }
        }
    }
    
    // Method 2: X11 fallback
    if let Ok(output) = Command::new("xdpyinfo").output() {
        let out = String::from_utf8_lossy(&output.stdout);
        for line in out.lines() {
            if line.contains("number of screens:") {
                if let Some(count) = line.split(':').nth(1) {
                    return count.trim().parse().unwrap_or(1);
                }
            }
        }
    }
    
    1  // Fallback
}
```

## 🛠 **ARCHITECTURE IMPROVEMENTS**

### **7. Tauri IPC Needs Implementation**
Your `tauri.rs` is just a stub:

```rust
// Add proper IPC
use std::sync::mpsc;
use std::thread;

pub struct TauriClient {
    tx: mpsc::Sender<IpcMessage>,
}

impl TauriClient {
    pub fn new() -> Result<Self> {
        // On macOS/Linux, use Unix domain sockets
        // On Windows, use named pipes
        #[cfg(unix)]
        let socket_path = dirs::runtime_dir()
            .unwrap()
            .join("spatialshot-ipc.sock");
            
        #[cfg(windows)]
        let pipe_name = r"\\.\pipe\spatialshot-ipc";
        
        Ok(Self { tx })
    }
    
    pub fn send_capture(&self, image_path: &Path) -> Result<()> {
        // Send via IPC, not just protocol handlers
    }
}
```

### **8. Add Health Checking**
```rust
// In main.rs, before starting daemon
fn check_system_health() -> Result<()> {
    // Check disk space for extraction
    let data_dir = dirs::data_local_dir().unwrap();
    let available = fs2::available_space(&data_dir)?;
    if available < 200 * 1024 * 1024 {  // 200MB minimum
        return Err(anyhow!("Insufficient disk space for capture engine"));
    }
    
    // Check if C++ binary is executable
    let engine_path = bootstrap::ensure_engine()?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = fs::metadata(&engine_path)?.permissions();
        if perms.mode() & 0o111 == 0 {
            return Err(anyhow!("Capture engine is not executable"));
        }
    }
    
    Ok(())
}
```

### **9. Improve Error Messages for Users**
```rust
// Create user-friendly errors
#[derive(thiserror::Error, Debug)]
pub enum DaemonError {
    #[error("Cannot start capture: another instance is running")]
    AlreadyRunning,
    #[error("Display configuration changed during capture")]
    DisplayChanged,
    #[error("Insufficient permissions to capture screen")]
    PermissionsDenied,
    #[error("Capture engine is corrupted. Please reinstall the application")]
    EngineCorrupted,
}

impl From<DaemonError> for String {
    fn from(err: DaemonError) -> Self {
        // Convert to user-friendly message
        format!("⚠️  SpatialShot Error: {}", err)
    }
}
```

## 📦 **PACKAGING FIXES**

### **10. Cargo.toml Dependencies Need Fixing**
```toml
# FIX: Missing critical dependencies
[dependencies]
thiserror = "1.0"  # For proper error types
tracing = "0.1"    # Structured logging
tracing-subscriber = "0.3"
serde = { version = "1.0", features = ["derive"] }
serde_json = "1.0"
tempfile = "3.8"   # Better temp file handling

# Add platform-specific
[target.'cfg(target_os = "linux")'.dependencies]
x11rb = "0.12"  # For proper X11 monitoring

# REMOVE: `fs2` is unmaintained, use `fs4`
fs4 = "1.0"
```

### **11. Build.rs Needs Signal Handling**
```rust
// Add cleanup on build interruption
fn main() {
    // Handle Ctrl+C during build
    ctrlc::set_handler(|| {
        eprintln!("Build interrupted. Cleaning up...");
        let _ = std::fs::remove_dir_all("dist");
        std::process::exit(1);
    }).expect("Error setting Ctrl-C handler");
    
    // ... rest of build
}
```

### **12. Docker Improvements**
```dockerfile
# Add to Dockerfile
RUN groupadd -r spatialshot && useradd -r -g spatialshot spatialshot
USER spatialshot  # Don't run as root!

# Add healthcheck
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD [ "test", "-f", "/tmp/spatialshot-ready" ]
```

## 🚀 **DEPLOYMENT FIXES**

### **13. GitHub Actions Issues**
```yaml
# In distribute.yml, FIX these issues:

# 1. Windows needs proper Qt path
- name: (Windows) Set Qt Path
  if: runner.os == 'Windows'
  run: |
    echo "Qt6_DIR=C:\Qt\${{ env.QT_VERSION }}\${{ env.QT_ARCH }}" >> $env:GITHUB_ENV
    echo "PATH=$env:Qt6_DIR\bin;$env:PATH" >> $env:GITHUB_ENV

# 2. macOS codesign needs identity
- name: (macOS) Sign Bundle
  if: runner.os == 'macOS'
  run: |
    codesign --force --deep --options runtime \
      --sign "${{ secrets.MACOS_CERTIFICATE }}" \
      dist/capture.app
```

### **14. Add Smoke Test Verification**
```rust
// Add test to verify extraction works
#[test]
fn test_engine_extraction() {
    let temp_dir = tempfile::tempdir().unwrap();
    let engine_dir = temp_dir.path().join("engine");
    
    // Test extraction with dummy zip
    let result = std::panic::catch_unwind(|| {
        bootstrap::extract_to(&engine_dir, DUMMY_ZIP)
    });
    
    assert!(result.is_ok());
    
    // Verify executable exists
    let exe = bootstrap::get_binary_path(&engine_dir).unwrap();
    assert!(exe.exists());
}
```

## ✅ **QUICK FIX CHECKLIST**

1. **IMMEDIATE (Security)**:
   - [ ] Fix ZIP slip vulnerability in `bootstrap.rs`
   - [ ] Replace `static mut` with `OnceLock` in `lock.rs`
   - [ ] Fix PID race condition in `sys/mod.rs`

2. **HIGH PRIORITY (Functionality)**:
   - [ ] Implement Linux hotkey installer script
   - [ ] Fix monitor counting on Linux
   - [ ] Complete Tauri IPC implementation
   - [ ] Add proper audio state restoration

3. **MEDIUM PRIORITY (Robustness)**:
   - [ ] Add health checking before daemon starts
   - [ ] Implement user-friendly error messages
   - [ ] Add structured logging with `tracing`
   - [ ] Create proper test suite

4. **PACKAGING**:
   - [ ] Update Cargo.toml dependencies
   - [ ] Fix GitHub Actions workflows
   - [ ] Add Docker health checks

## 🎯 **ARCHITECTURE VERDICT: 8/10**

Your Matryoshka architecture is **brilliant** but has critical safety bugs. Fix these and you'll have a production-ready system.

**Key strengths:**
- Single-binary deployment ✅
- AV-friendly extraction location ✅
- Platform-specific optimizations ✅
- Good separation of concerns ✅

**Critical weaknesses:**
- Unsafe static variables ❌
- ZIP slip vulnerability ❌
- Incomplete Linux implementation ❌
- Poor error handling ❌

**Recommendation:** Fix the security issues first, then complete the Linux implementation. The architecture is sound but needs hardening.

**Ready to implement these fixes?** I can provide detailed code for any specific fix you want to tackle first.
===

senior 3:
===
### Deep Rust Code Review, Bug Fixes, and Packaging/Deployment Recommendations

Thanks for sharing the sources! I'll dive into a detailed review focused on the Rust components (as per your instructions: "rust review + packaging + deployment"). I'll go file-by-file where relevant, highlighting bugs, anti-patterns, strengths, and suggested fixes. I'll prioritize potential crashes, security (though not full audit), performance, and cross-platform reliability. Since this is embedded in a daemon for a hotkey-driven utility, I'll emphasize runtime stability and idempotency.

Overall, the code is solid—clean modularization, good use of crates like `anyhow` for errors, and thoughtful platform cfg guards. However, there are some bugs (e.g., unsafe globals, path handling), missing error propagation, and deployment pitfalls (e.g., unsigned binaries, update handling). I'll rate each major file/section on a 1-10 scale for quick reference.

If I suggest code changes, I'll provide snippets you can copy-paste. At the end, I'll confirm architecture support and suggest next steps.

#### 1. **Cargo.toml (Packaging Config) - Rating: 8/10**
   - **Strengths:** 
     - Good dependency choices: `zip` and `walkdir` for build-time embedding, `rdev` conditionally for hotkeys (avoids Linux bloat), `dirs` for cross-platform paths.
     - Release profile optimizations (`lto=true`, `strip=true`, `opt-level='z'`, `panic='abort'`) are excellent for a small daemon binary—reduces size and improves startup.
     - Build-dependencies separated properly.
   - **Issues/Bugs:**
     - `sysinfo = "0.37.2"` is overkill if you're only using it for PID/process killing (in monitors.rs). It pulls in heavy deps; consider replacing with lighter alternatives like `libc` for Unix/Windows process APIs to shrink binary.
     - `which = "8.0.0"` isn't used anywhere—dead dep? Remove to trim.
     - `fs2 = "0.4"` for file locking is fine, but version is old (last update 2018); upgrade to `fs-lock` or use `std::sync::Mutex` with a file if possible.
     - No explicit `target` configs beyond `.cargo/config.toml` (which is MUSL-specific). For Windows/Mac, add `[target.'cfg(windows)'.build-dependencies]` if needed for custom linkers.
     - Missing dev-dependencies for testing (e.g., `tempfile` for extraction tests).
   - **Packaging Suggestions:**
     - Add `Cargo.lock` to repo for reproducible builds (especially since you're embedding hashes).
     - For deployment, specify `bin` in `[package]` if shipping as a crate: `[bin] name = "spatialshot-daemon" path = "src/main.rs"`.
     - To handle MUSL fully, add a profile for static linking: `[profile.release] codegen-units = 1`.
   - **Deployment Notes:** Integrates well with Tauri `externalBin`, but ensure Tauri's bundler signs the daemon (e.g., via `tauri.conf.json`). Test AV scanning—embedded ZIPs can flag as suspicious; consider UPX compression post-build but watch for false positives.

#### 2. **build.rs - Rating: 7/10**
   - **Strengths:** 
     - Great use of `println!("cargo:rerun-if-changed=dist");` for incremental builds.
     - Dummy ZIP for `cargo check` is clever for dev workflow.
     - SHA256 hashing for version integrity is a nice touch—prevents corrupted embeds.
   - **Bugs/Issues:**
     - **Panic in release if `dist` missing:** Good, but add a user-friendly message or env var override for CI.
     - **Buffer reuse in `compress_dist`:** `let buffer = &mut Vec::new();` then `f.read_to_end(buffer)` and `zip.write_all(buffer)`—this is fine, but `buffer.clear()` after each file. Potential bug: If a file read fails midway, buffer might hold stale data—use a fresh vec per file or wrap in `Result`.
     - **Unix permissions:** The `#[cfg(unix)]` block for permissions is inside the file write loop, but it sets perms on the output path after writing. Bug: If the file is executable in `dist/`, this preserves it, but on Windows-built ZIPs, it might not. Test extraction perms on Mac/Linux.
     - **No compression level:** Using `Stored` is fast, but for a one-time embed, switch to `Deflated` for smaller binary: `.compression_method(zip::CompressionMethod::Deflated) .compression_level(Some(9))`.
     - **WalkDir skips:** It skips root, good, but if `dist/` has symlinks, `filter_map(|e| e.ok())` ignores errors—log them.
   - **Fix Suggestions:**
     ```rust
     // In compress_dist, per-file buffer and error handling
     for entry in walk.into_iter().filter_map(|e| e.ok()) {
         let path = entry.path();
         if path == src_dir { continue; }
         let name = path.strip_prefix(src_dir).unwrap().to_str().unwrap();
         if path.is_file() {
             let mut buffer = Vec::new(); // Fresh per file
             let mut f = File::open(path).map_err(|e| anyhow!("Failed to open {:?}: {}", path, e))?;
             f.read_to_end(&mut buffer).map_err(|e| anyhow!("Failed to read {:?}: {}", path, e))?;
             zip.start_file(name, options).map_err(|e| anyhow!("Zip start failed for {}: {}", name, e))?;
             zip.write_all(&buffer).map_err(|e| anyhow!("Zip write failed for {}: {}", name, e))?;
         } else if !name.is_empty() {
             zip.add_directory(name, options).map_err(|e| anyhow!("Dir add failed for {}: {}", name, e))?;
         }
     }
     ```
     - Add integrity check: After zipping, read back and verify hash in build.rs.
   - **Packaging/Deployment:** Ties well to PKGBUILD scripts. For cross-compilation (e.g., build Linux on Mac), add `cargo build --target x86_64-unknown-linux-musl`.

#### 3. **src/main.rs - Rating: 8/10**
   - **Strengths:** Platform cfg for Linux (one-shot) vs. Win/Mac (daemon) is clean. Logger init is good.
   - **Bugs/Issues:**
     - **Global hotkey listener blocks:** `rdev::listen` is blocking, so the thread runs forever—fine for daemon, but no graceful shutdown. Add signal handling (e.g., `ctrlc` crate) to exit cleanly.
     - **Error handling in callback:** The hotkey callback ignores errors from `lib::capture::run` and `ipc::tauri::open_editor`—log and continue, but user might not notice failures.
     - **Linux path:** Assumes Tauri handles hotkey via OS shortcuts—good, but ensure daemon exits cleanly after capture (it does via `return Ok(())`).
     - **`sys::monitors::start_monitor();` called before hotkey:** Good ordering, but if monitors change before hotkey, it updates `last_count`—potential race if hotkey fires immediately.
   - **Fix Suggestions:**
     ```rust
     // In hotkey callback
     if let Err(e) = lib::lock::try_lock() {
         log::warn!("Capture already in progress: {}", e);
         return;
     }
     let _audio_guard = sys::audio::AudioGuard::new();
     if let Ok(image_path) = lib::capture::run(&engine_path) {
         if let Err(e) = ipc::tauri::open_editor(&image_path) {
             error!("Editor open failed: {}", e);
             // Optionally notify user via tray or something
         }
     } else {
         error!("Capture run failed"); // Add err var
     }
     ```
   - **Deployment:** For Win/Mac daemon persistence, you mentioned plist/Registry—implement in Tauri installer, not here. Test daemon respawn if killed.

#### 4. **src/lib/bootstrap.rs - Rating: 9/10**
   - **Strengths:** Idempotent extraction with version check is excellent. ZIP slip protection via `enclosed_name()` is secure.
   - **Bugs/Issues:**
     - **No atomic extraction:** If fails mid-way, partial dir left—use temp dir + rename.
     - **Unix perms:** Good, but on Mac, `xattr` in separate fn—ensure it's called recursively if needed.
     - **Path resolution:** `get_binary_path` hardcodes names—make dynamic if C++ changes.
     - **Error chaining:** Uses `anyhow`, good, but add contexts like `.context(format!("Extracting to {:?}", target_dir))`.
   - **Fix Suggestions:**
     ```rust
     // Atomic extraction
     fn install_engine(target_dir: &Path) -> Result<()> {
         let temp_dir = target_dir.with_file_name(format!("engine_temp_{}", rand::random::<u32>()));
         fs::create_dir_all(&temp_dir)?;
         // Extract to temp_dir...
         // On success:
         fs::rename(&temp_dir, target_dir)?;
         Ok(())
     }
     ```

#### 5. **src/sys/hotkey.rs - Rating: 7/10**
   - **Strengths:** Debounce with `Instant` is smart for double-taps.
   - **Bugs/Issues:**
     - **Key state globals:** Arc<AtomicBool> is fine, but consider a struct for all keys.
     - **No error in listen:** If `rdev` fails (e.g., permissions), daemon hangs—wrap in thread and monitor.
     - **Meta key:** On Win, Meta is Windows key—confirm it matches user expectation (Win+Shift+A).

#### 6. **src/sys/monitors.rs - Rating: 6/10**
   - **Strengths:** Threaded watchdog is crucial for your "ghost" prevention.
   - **Bugs/Issues:**
     - **Global PID unsafe:** `static mut`? No, you used `AtomicU32`—good, but add fences if multi-thread reads.
     - **Kill on Linux exits daemon:** Abrupt; consider signaling Tauri.
     - **Count methods:** Mac uses `core-graphics` (dep ok), Linux parses `xrandr`—fragile if no xrandr; use `x11rb` for robustness. Win uses `windows` crate—good.
     - **Sleep 1s:** Too coarse; if plug/unplug during capture, 1s delay might not catch—poll faster (200ms) but CPU-friendly.
   - **Fix:** Add timeout to loop if no capture for hours (power save).

#### 7. **src/sys/audio.rs - Rating: 8/10**
   - **Strengths:** RAII guard with Drop is perfect for temp mute.
   - **Issues:** Backend detection assumes commands exist—use `which` (but you have it, unused). Parse outputs more robustly (regex for "muted: yes").
   - **Deployment:** On Wayland, `wpctl` good; test Gnome specifically.

#### Other Files
- **ipc/tauri.rs:** URL scheme is ideal for Tauri wakeup. Bug: Path quoting—use `url::Url` to encode `path=`.
- **lib/lock.rs:** Unsafe global `LOCK_FILE`—leak is intentional, but use `lazy_static` or thread-local.
- **lib/capture.rs:** Timeout good; verify image with `image::open` if paranoid.

#### Overall Bug Summary and Tests
- Critical Bugs: Partial extraction, blocking listener without shutdown.
- To test: Use code_execution tool? But since it's system-specific, suggest unit tests for bootstrap (mock ZIP).
- Packaging: Binary size ~5-10MB post-embed—optimize with `upx`.
- Deployment: For Tauri, add self-update for daemon (download new binary, replace). Test on VMs for AV/plug-unplug.

I still support the Matryoshka architecture—it's elegant for your use case. If you implement fixes, send updated code for re-review!
===

senior 4:
===
Nice — solid details. I went through the Rust side and CI bits and pulled together **targeted, copy-pasteable fixes** you can apply immediately. I focused on correctness, concurrency, atomic extraction, locking, monitor shutdown behavior, and a few CI/build bugs that would stop the Matryoshka flow.

Below: a prioritized list of issues + exact code patches (short, safe, ready to paste). Do them in order — the first ones fix hard crashes / data-corruption; the rest are robustness/CI improvements.

---

# **Critical fixes (apply now)**

### 1) `build.rs` — fix SHA256 hashing bug & make `cargo:rerun-if-changed` robust

**Problems**

* `calculate_sha256` used `std::io::copy(&mut file, &mut hasher)` — `hasher` is not an `io::Write`. This panics/compiles error.
* `println!("cargo:rerun-if-changed=dist")` doesn't detect changes inside `dist`. Better emit a line per file so Cargo reruns when any dist file changes.

**Patch** — replace whole `calculate_sha256` and add a small walk to emit `rerun-if-changed` entries:

```rust
// top: add
use std::io::BufReader;

// Replace the earlier println rerun-if-changed with this:
for entry in WalkDir::new(&dist_path).into_iter().filter_map(|e| e.ok()) {
    if entry.file_type().is_file() {
        println!("cargo:rerun-if-changed={}", entry.path().display());
    }
}

// Replace calculate_sha256 with:
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
```

(You already imported `WalkDir`; `BufReader` + `read` require `use std::io::Read;` which is present.)

---

### 2) `src/lib/bootstrap.rs` — atomic, locked extraction + version check

**Problems**

* Extraction writes directly into `engine_dir` (partial installs possible).
* No extraction lock: simultaneous starts can race.
* No same-filesystem atomic swap.

**Goal**

* Extract to a temp directory next to `engine_dir` then rename (atomic on same FS).
* Use a lock file (fs2) to prevent concurrent extraction.
* Write version file only after successful swap.

**Patch** — replace `ensure_engine` / `install_engine` with this implementation (drop-in):

```rust
use fs2::FileExt;
use std::fs::File;
use tempfile::tempdir_in;
use std::io::Cursor;

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
```

**Notes**

* This uses `tempfile` and `fs2`. Add these crates:

  ```toml
  once_cell = "1.18"      # if you plan to use it later
  tempfile = "3"
  scopeguard = "1.2"
  ```

  (You can remove `once_cell` if unused.)
* This guarantees atomic swap (rename on same FS) and prevents concurrent extraction.

---

### 3) `src/lib/lock.rs` — replace `static mut` with safe global using `once_cell`

**Problems**

* `static mut` is unsafe and not thread-safe.

**Patch** — replace file contents with:

```rust
use anyhow::Result;
use fs2::FileExt;
use std::fs::File;
use std::path::PathBuf;
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
```

Add `once_cell` to `Cargo.toml` if you haven't.

---

### 4) `src/sys/monitors.rs` — ensure daemon kills itself when monitors change

**Problems**

* `emergency_shutdown` only `std::process::exit(1)` on Linux. User explicitly wanted the daemon to kill itself on any OS change.

**Patch** — change `emergency_shutdown` to exit the process on all OSes after killing child:

```rust
fn emergency_shutdown(pid: u32) {
    let _ = kill_process(pid);
    // Best-effort cleanup then exit to allow system to restore normal state
    log::warn!("Exiting daemon due to monitor topology change.");
    std::process::exit(1);
}
```

(Just remove the `#[cfg(target_os = "linux")]` guard so all platforms exit.)

**Note:** if you want graceful shutdown hooks, call them before `exit`. But immediate exit is fine here since you purposely want to avoid inconsistent frozen state.

---

### 5) `src/sys/audio.rs` — make backend detection robust

**Problems**

* Some audio tools print to `stderr`, or their output format varies. `pactl` `get-sink-mute` output might require parsing. Also current code sets `backend` even when the command exists but parsing failed.

**Patch** — more robust `pactl` handling and prefer `pactl list short sinks` fallback. Minimal replacement for `try_backend`:

```rust
fn try_backend(&mut self, cmd: &'static str, check_args: &[&str], mute_args: &[&str]) -> bool {
    let out = Command::new(cmd).args(check_args).output();
    if let Ok(output) = out {
        let stdout = String::from_utf8_lossy(&output.stdout).to_string();
        let stderr = String::from_utf8_lossy(&output.stderr).to_string();
        let combined = format!("{}{}", stdout, stderr).to_lowercase();

        // Simple heuristics
        let is_muted = combined.contains("mute") && (combined.contains("yes") || combined.contains("1") || combined.contains("true") || combined.contains("[on]") || combined.contains("[off]") || combined.contains("[mute]"));

        // If the command ran, assume it's a valid backend
        self.backend = Some(cmd);
        self.was_previously_muted = is_muted;

        if !self.was_previously_muted {
            let _ = Command::new(cmd).args(mute_args).output();
            self.muted_by_us = true;
        }
        return true;
    }
    false
}
```

Also ensure the `new()` function tries `pactl` with `["get-sink-mute", "@DEFAULT_SINK@"]` first. If that produces no output, try `pactl list short sinks` and parse the default sink index.

This is heuristic but significantly more tolerant across distros.

---

# **CI / packaging immediate fixes**

### 6) `.github/actions/build-pkg/action.yml` — wrong working dir

**Problem**

* The action uses `working-directory: ./packages/daemon` but your crate is `packages/capture`. That will fail.

**Patch**
Change:

```yaml
working-directory: ./packages/daemon
```

to:

```yaml
working-directory: ./packages/capture
```

Also ensure the `BIN_PATH` later references `packages/capture/target/release/spatialshot-daemon` (you already do in the workflow but the action zipped different folder). Do a quick sweep for other `daemon` vs `capture` mismatches.

---

# **Recommended (non-critical) improvements**

* **Add extraction lock path override**: allow `SPATIALSHOT_ENGINE_DIR` env var so devs can extract to a custom dir for QA.
* **Expose `daemon --repair`**: re-extract and force overwrite if user has corrupt install.
* **Logging**: add file logger to AppData so users can attach logs for triage.
* **Hotkey startup (mac/windows)**: instruct installers to register LaunchAgent / HKCU registry key. Provide sample plist and `.reg` or PowerShell invocations in your Tauri installer step (you already mentioned them).
* **Testability**: add a `--smoketest` flag that runs `lib::capture::run()` but uses a dummy executable when running in CI so you can test monitor logic without GUI freeze.

---

# **Crate changes to add to Cargo.toml**

Add these runtime deps:

```toml
tempfile = "3"
scopeguard = "1.2"
once_cell = "1.18"
```

(You already have `fs2`.)

---

# **How to apply quickly**

1. Patch `build.rs` (sha256 + rerun-if-changed). Build will error until fixed.
2. Add `tempfile`, `once_cell`, `scopeguard` to `Cargo.toml`.
3. Replace `src/lib/bootstrap.rs` with the atomic extraction version.
4. Replace `src/lib/lock.rs` with the OnceCell version.
5. Patch `src/sys/monitors.rs` emergency shutdown as above.
6. Tweak `src/sys/audio.rs` `try_backend` as above.
7. Fix `.github/actions/build-pkg/action.yml` working dir to `packages/capture`.

After that, run `cargo build` locally (in debug) and test:

* Simulate two concurrent starts to verify extraction lock.
* Toggle monitor count (plug/unplug) during capture to validate emergency path.
* Trigger hotkey on mac/windows dev machine to ensure rdev listener and audio guard behave.

---

# Quick notes / gotchas

* Signing: sign the inner native binary **before embedding** so signatures persist on extraction. You already sign in CI for mac with `codesign` — ensure this happens before zip embedding.
* AVs: big single binaries sometimes trigger heuristics. Sign release artifacts and keep a reproducible build flow.
* `rename` atomicity requires same filesystem — ensure your installer/daemon extracts to a path on same FS as temp dir (we used `tempdir_in(parent)` for that reason).
* `xattr -d com.apple.quarantine` may fail if user lacks permission — we run it best-effort.

---

If you want, I’ll:

* generate a small PR patch for each file (I can paste full file contents),
* or run through one file at a time (start with `build.rs` + `bootstrap.rs`) and produce the exact full file content ready to commit.

Tell me which option and I’ll drop the full replacement files next — or I can start by pasting the full updated `build.rs` + `bootstrap.rs` now. Which do you want?
===

senior 5:
===
Nice — solid details. I went through the Rust side and CI bits and pulled together **targeted, copy-pasteable fixes** you can apply immediately. I focused on correctness, concurrency, atomic extraction, locking, monitor shutdown behavior, and a few CI/build bugs that would stop the Matryoshka flow.

Below: a prioritized list of issues + exact code patches (short, safe, ready to paste). Do them in order — the first ones fix hard crashes / data-corruption; the rest are robustness/CI improvements.

---

# **Critical fixes (apply now)**

### 1) `build.rs` — fix SHA256 hashing bug & make `cargo:rerun-if-changed` robust

**Problems**

* `calculate_sha256` used `std::io::copy(&mut file, &mut hasher)` — `hasher` is not an `io::Write`. This panics/compiles error.
* `println!("cargo:rerun-if-changed=dist")` doesn't detect changes inside `dist`. Better emit a line per file so Cargo reruns when any dist file changes.

**Patch** — replace whole `calculate_sha256` and add a small walk to emit `rerun-if-changed` entries:

```rust
// top: add
use std::io::BufReader;

// Replace the earlier println rerun-if-changed with this:
for entry in WalkDir::new(&dist_path).into_iter().filter_map(|e| e.ok()) {
    if entry.file_type().is_file() {
        println!("cargo:rerun-if-changed={}", entry.path().display());
    }
}

// Replace calculate_sha256 with:
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
```

(You already imported `WalkDir`; `BufReader` + `read` require `use std::io::Read;` which is present.)

---

### 2) `src/lib/bootstrap.rs` — atomic, locked extraction + version check

**Problems**

* Extraction writes directly into `engine_dir` (partial installs possible).
* No extraction lock: simultaneous starts can race.
* No same-filesystem atomic swap.

**Goal**

* Extract to a temp directory next to `engine_dir` then rename (atomic on same FS).
* Use a lock file (fs2) to prevent concurrent extraction.
* Write version file only after successful swap.

**Patch** — replace `ensure_engine` / `install_engine` with this implementation (drop-in):

```rust
use fs2::FileExt;
use std::fs::File;
use tempfile::tempdir_in;
use std::io::Cursor;

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
```

**Notes**

* This uses `tempfile` and `fs2`. Add these crates:

  ```toml
  once_cell = "1.18"      # if you plan to use it later
  tempfile = "3"
  scopeguard = "1.2"
  ```

  (You can remove `once_cell` if unused.)
* This guarantees atomic swap (rename on same FS) and prevents concurrent extraction.

---

### 3) `src/lib/lock.rs` — replace `static mut` with safe global using `once_cell`

**Problems**

* `static mut` is unsafe and not thread-safe.

**Patch** — replace file contents with:

```rust
use anyhow::Result;
use fs2::FileExt;
use std::fs::File;
use std::path::PathBuf;
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
```

Add `once_cell` to `Cargo.toml` if you haven't.

---

### 4) `src/sys/monitors.rs` — ensure daemon kills itself when monitors change

**Problems**

* `emergency_shutdown` only `std::process::exit(1)` on Linux. User explicitly wanted the daemon to kill itself on any OS change.

**Patch** — change `emergency_shutdown` to exit the process on all OSes after killing child:

```rust
fn emergency_shutdown(pid: u32) {
    let _ = kill_process(pid);
    // Best-effort cleanup then exit to allow system to restore normal state
    log::warn!("Exiting daemon due to monitor topology change.");
    std::process::exit(1);
}
```

(Just remove the `#[cfg(target_os = "linux")]` guard so all platforms exit.)

**Note:** if you want graceful shutdown hooks, call them before `exit`. But immediate exit is fine here since you purposely want to avoid inconsistent frozen state.

---

### 5) `src/sys/audio.rs` — make backend detection robust

**Problems**

* Some audio tools print to `stderr`, or their output format varies. `pactl` `get-sink-mute` output might require parsing. Also current code sets `backend` even when the command exists but parsing failed.

**Patch** — more robust `pactl` handling and prefer `pactl list short sinks` fallback. Minimal replacement for `try_backend`:

```rust
fn try_backend(&mut self, cmd: &'static str, check_args: &[&str], mute_args: &[&str]) -> bool {
    let out = Command::new(cmd).args(check_args).output();
    if let Ok(output) = out {
        let stdout = String::from_utf8_lossy(&output.stdout).to_string();
        let stderr = String::from_utf8_lossy(&output.stderr).to_string();
        let combined = format!("{}{}", stdout, stderr).to_lowercase();

        // Simple heuristics
        let is_muted = combined.contains("mute") && (combined.contains("yes") || combined.contains("1") || combined.contains("true") || combined.contains("[on]") || combined.contains("[off]") || combined.contains("[mute]"));

        // If the command ran, assume it's a valid backend
        self.backend = Some(cmd);
        self.was_previously_muted = is_muted;

        if !self.was_previously_muted {
            let _ = Command::new(cmd).args(mute_args).output();
            self.muted_by_us = true;
        }
        return true;
    }
    false
}
```

Also ensure the `new()` function tries `pactl` with `["get-sink-mute", "@DEFAULT_SINK@"]` first. If that produces no output, try `pactl list short sinks` and parse the default sink index.

This is heuristic but significantly more tolerant across distros.

---

# **CI / packaging immediate fixes**

### 6) `.github/actions/build-pkg/action.yml` — wrong working dir

**Problem**

* The action uses `working-directory: ./packages/daemon` but your crate is `packages/capture`. That will fail.

**Patch**
Change:

```yaml
working-directory: ./packages/daemon
```

to:

```yaml
working-directory: ./packages/capture
```

Also ensure the `BIN_PATH` later references `packages/capture/target/release/spatialshot-daemon` (you already do in the workflow but the action zipped different folder). Do a quick sweep for other `daemon` vs `capture` mismatches.

---

# **Recommended (non-critical) improvements**

* **Add extraction lock path override**: allow `SPATIALSHOT_ENGINE_DIR` env var so devs can extract to a custom dir for QA.
* **Expose `daemon --repair`**: re-extract and force overwrite if user has corrupt install.
* **Logging**: add file logger to AppData so users can attach logs for triage.
* **Hotkey startup (mac/windows)**: instruct installers to register LaunchAgent / HKCU registry key. Provide sample plist and `.reg` or PowerShell invocations in your Tauri installer step (you already mentioned them).
* **Testability**: add a `--smoketest` flag that runs `lib::capture::run()` but uses a dummy executable when running in CI so you can test monitor logic without GUI freeze.

---

# **Crate changes to add to Cargo.toml**

Add these runtime deps:

```toml
tempfile = "3"
scopeguard = "1.2"
once_cell = "1.18"
```

(You already have `fs2`.)

---

# **How to apply quickly**

1. Patch `build.rs` (sha256 + rerun-if-changed). Build will error until fixed.
2. Add `tempfile`, `once_cell`, `scopeguard` to `Cargo.toml`.
3. Replace `src/lib/bootstrap.rs` with the atomic extraction version.
4. Replace `src/lib/lock.rs` with the OnceCell version.
5. Patch `src/sys/monitors.rs` emergency shutdown as above.
6. Tweak `src/sys/audio.rs` `try_backend` as above.
7. Fix `.github/actions/build-pkg/action.yml` working dir to `packages/capture`.

After that, run `cargo build` locally (in debug) and test:

* Simulate two concurrent starts to verify extraction lock.
* Toggle monitor count (plug/unplug) during capture to validate emergency path.
* Trigger hotkey on mac/windows dev machine to ensure rdev listener and audio guard behave.

---

# Quick notes / gotchas

* Signing: sign the inner native binary **before embedding** so signatures persist on extraction. You already sign in CI for mac with `codesign` — ensure this happens before zip embedding.
* AVs: big single binaries sometimes trigger heuristics. Sign release artifacts and keep a reproducible build flow.
* `rename` atomicity requires same filesystem — ensure your installer/daemon extracts to a path on same FS as temp dir (we used `tempdir_in(parent)` for that reason).
* `xattr -d com.apple.quarantine` may fail if user lacks permission — we run it best-effort.

---

If you want, I’ll:

* generate a small PR patch for each file (I can paste full file contents),
* or run through one file at a time (start with `build.rs` + `bootstrap.rs`) and produce the exact full file content ready to commit.

Tell me which option and I’ll drop the full replacement files next — or I can start by pasting the full updated `build.rs` + `bootstrap.rs` now. Which do you want?
===
