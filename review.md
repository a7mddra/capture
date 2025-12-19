senior 1:
===
This architecture is solid. You have successfully implemented the "Matryoshka" pattern.

**My Rating: 9/10.**
You have solved the hardest part: cross-platform C++ dependency bundling without forcing the user to install Qt.

However, I have found **4 Critical Bugs** in the Rust implementation that will cause:

1. **Infinite Re-extraction loops** (due to non-deterministic zipping).
2. **Corrupted installs on Windows** (due to non-atomic directory writes).
3. **Zombie Processes** (monitor guard uses `kill -9` too aggressively).
4. **Silent Failures** (Audio guard panic safety).

Here are the fixes.

---

### 1. Fix `build.rs`: The Determinism Bug

**The Problem:** `zip::FileOptions::default()` uses the *current timestamp* for files inside the zip.
**The Consequence:** Every time you run `cargo build`, the zip binary changes, so the SHA256 hash changes. The client will think "New Version!" and re-extract the engine on *every single startup*, causing a 2-second delay.

**The Fix:** Force the timestamp to a constant (EPOCH).

```rust
// packages/capture/build.rs

// ... (keep imports)
use zip::DateTime; // Import this

// ... (keep main function)

fn compress_dist(src_dir: &Path, dst_file: &Path) {
    let file = File::create(dst_file).expect("Failed to create zip file");
    let mut zip = zip::ZipWriter::new(file);

    // FIXED: Use a constant time for determinism. 
    // This ensures the SHA256 hash only changes when the FILE CONTENT changes.
    let options = FileOptions::default()
        .compression_method(zip::CompressionMethod::Deflated)
        .last_modified_time(DateTime::default()) // 1980-01-01 00:00:00
        .unix_permissions(0o755);

    let walk = WalkDir::new(src_dir);
    let buffer = &mut Vec::new();

    for entry in walk.into_iter().filter_map(|e| e.ok()) {
        let path = entry.path();
        if path == src_dir { continue; }
        
        let name = path.strip_prefix(src_dir).unwrap().to_str().unwrap().replace("\\", "/");

        if path.is_file() {
            // ... (keep existing logic)
            zip.start_file(name, options).unwrap();
            // ...
        } else if !name.is_empty() {
            zip.add_directory(name, options).unwrap();
        }
    }
    zip.finish().unwrap();
}
// ... (keep rest)

```

---

### 2. Fix `bootstrap.rs`: The "Dropper" Bug

**The Problem:** You extract directly to the target folder. If the app crashes (or user kills it) halfway through extraction, you leave a corrupted binary. Next run, the code sees the folder exists and tries to run a broken exe.
**The Fix:** **Atomic Move.** Extract to `engine_tmp_uuid`. Verify it. Then `rename` to `engine`.

```rust
// packages/capture/src/lib/bootstrap.rs

use crate::embed::{ENGINE_VERSION, PAYLOAD_ZIP};
use anyhow::{Context, Result};
use fs2::FileExt;
use std::fs::File;
use std::io::Cursor;
use std::path::{Path, PathBuf};
// Remove tempfile dependency here, we want manual control relative to the target dir
use uuid::Uuid; 

pub fn ensure_engine() -> Result<PathBuf> {
    let data_dir = dirs::data_local_dir()
        .ok_or_else(|| anyhow::anyhow!("Could not determine AppData directory"))?
        .join("SpatialShot");

    let engine_dir = data_dir.join("capture-v1"); // Version namespace helps with migration
    let version_marker = engine_dir.join("version.txt");

    if let Some(parent) = engine_dir.parent() {
        std::fs::create_dir_all(parent)?;
    }

    // 1. Fast Path: Check if exists and valid
    if engine_dir.exists() {
        if let Ok(current_ver) = std::fs::read_to_string(&version_marker) {
            if current_ver.trim() == ENGINE_VERSION {
                return get_binary_path(&engine_dir);
            }
        }
    }

    // 2. Slow Path: Needs Extraction
    // Acquire lock to prevent two daemons extracting simultaneously
    let lock_path = data_dir.join(".install.lock");
    let lock_file = File::create(&lock_path)?;
    lock_file.lock_exclusive()?;

    // Check again inside lock (Double-Checked Locking)
    if engine_dir.exists() {
        if let Ok(current_ver) = std::fs::read_to_string(&version_marker) {
            if current_ver.trim() == ENGINE_VERSION {
                lock_file.unlock()?;
                return get_binary_path(&engine_dir);
            }
        }
        // Invalid version, nuke it
        let _ = std::fs::remove_dir_all(&engine_dir);
    }

    log::info!("Extracting Capture Engine...");

    // 3. Atomic Extraction Strategy
    // Extract to "capture-v1-tmp-UUID" inside the same parent dir
    // This ensures 'rename' is an atomic OS operation (same partition)
    let tmp_dir_name = format!("capture-v1-tmp-{}", Uuid::new_v4());
    let tmp_dir = data_dir.join(&tmp_dir_name);

    if tmp_dir.exists() {
        std::fs::remove_dir_all(&tmp_dir)?;
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

    // 4. Sanitize (Mac Quarantine)
    #[cfg(target_os = "macos")]
    {
        // Recursively remove quarantine from the TMP folder
        let _ = std::process::Command::new("xattr")
            .arg("-r").arg("-d").arg("com.apple.quarantine").arg(&tmp_dir)
            .status(); 
    }

    // 5. Atomic Rename (The Commit)
    // Windows rename fails if target exists, so we try remove first
    if engine_dir.exists() {
        std::fs::remove_dir_all(&engine_dir).context("Failed to clean old engine")?;
    }
    
    // Rename tmp -> actual
    std::fs::rename(&tmp_dir, &engine_dir).context("Failed to rename engine dir")?;
    
    // Write version
    std::fs::write(version_marker, ENGINE_VERSION)?;

    lock_file.unlock()?;
    get_binary_path(&engine_dir)
}

// ... (keep get_binary_path)

```

---

### 3. Fix `sys/monitors.rs`: The Zombie Bug

**The Problem:** `kill -9` (SIGKILL) does not allow the C++ app to clean up X11 connections or release shared memory.
**The Fix:** Try `SIGTERM` (polite kill) first. Wait 200ms. Then `SIGKILL`.

```rust
// packages/capture/src/sys/monitors.rs

// ... imports

pub(crate) fn kill_process(pid: u32) -> std::io::Result<()> {
    if pid == 0 { return Ok(()); }
    
    #[cfg(unix)]
    {
        // 1. Try SIGTERM (15) - Polite
        let _ = Command::new("kill").arg("-15").arg(pid.to_string()).output();
        
        // 2. Give it a moment to die
        thread::sleep(Duration::from_millis(200));

        // 3. Check if still alive (signal 0 check)
        let still_alive = Command::new("kill").arg("-0").arg(pid.to_string()).status().map(|s| s.success()).unwrap_or(false);

        if still_alive {
             // 4. SIGKILL (9) - Nuclear
            Command::new("kill").arg("-9").arg(pid.to_string()).output()?;
        }
    }
    #[cfg(windows)]
    {
        const CREATE_NO_WINDOW: u32 = 0x08000000;
        // /T = Tree kill (kill child processes too)
        // /F = Force
        Command::new("taskkill")
            .args(&["/F", "/T", "/PID", &pid.to_string()])
            .creation_flags(CREATE_NO_WINDOW)
            .output()?;
    }
    Ok(())
}

```

---

### 4. Fix `sys/audio.rs`: The Panic Safety Bug

**The Problem:** If the Rust daemon panics *while* the audio is muted, the user's computer remains muted forever.
**The Fix:** We need to hook into the panic handler to ensure `AudioGuard` restores volume even on a crash. However, standard `Drop` handles panics in the same thread. But if `std::process::exit(1)` is called (like in your `monitors.rs` emergency shutdown), `Drop` is **NOT** called.

**The Fix:**

1. Remove `std::process::exit(1)` from `monitors.rs`. Use a shared `AtomicBool` to signal the main loop to break cleanly.
2. Or, more simply, ensure `AudioGuard` un-mutes immediately after capture `wait()` returns.

*Currently, your `main.rs` does this correctly by binding `_audio_guard` to the scope. Just be aware: Do not call `std::process::exit` while holding that guard.*

---

### Deployment & Packaging (CI)

Your GitHub Actions look excellent.

**One optimization for Windows:**
In `PKGBUILD.ps1`, you rely on `windeployqt`.

Be aware that `windeployqt` sometimes misses `plugins/styles` or `plugins/imageformats` if they aren't explicitly used in the code but required at runtime (e.g., loading a JPEG).
Since you are freezing the screen (likely taking a BMP/PNG), verify `imageformats` folder is in your `dist/plugins`.

**Packaging Security:**
Since you are embedding `capture.exe` inside `spatialshot-daemon.exe`:

1. **Sign the Inner:** In `PKGBUILD.ps1`, if you have a certificate, sign `dist/capture.exe` *before* it gets zipped.
2. **Sign the Outer:** Tauri will sign the outer installer.
This dual-signing helps AV heuristics realize the inner executable is trusted.

### Next Step

Would you like me to provide the **Rust code for the `linux_hotkey_installer.sh` logic**? Since you cannot use `rdev` on Linux Wayland/X11 reliably for global shortcuts, we need to programmatically insert a `.desktop` file or a `dconf` entry to bind `<Super>+Shift+A` to your daemon.
===

senior 2:
===
### Architecture Review Update
Based on the provided code, I still support the Matryoshka architecture (8/10 rating from before). It elegantly embeds the C++ capture engine into the Rust daemon binary via `build.rs` and `include_bytes!`, making deployment via Tauri seamless. The code implements your blueprint well: `build.rs` orchestrates C++ builds (via PKGBUILD scripts), compresses `dist/` to zip, and generates a hash/version. Runtime extraction in `bootstrap.rs` is idempotent and atomic (tempdir + rename), with platform tweaks like Mac quarantine removal. The daemon's orchestration (hotkey listener on Win/Mac, one-shot on Linux) aligns with your flow, and guards (audio mute, monitor watchdog) add reliability.

Minor architecture suggestions:
- **Decoupling Potential:** If C++ updates become frequent, consider optional non-embedded mode (e.g., via env var) for devs, where `bootstrap.rs` loads from a local `dist/` instead.
- **Linux Hotkey:** Your OS-shortcut approach is fine, but if you want daemon parity, explore `evdev` or `uinput` for Wayland—though it adds complexity and perms issues.
- **Tauri Integration:** The `ipc/tauri.rs` custom protocol (`spatialshot://`) assumes Tauri registers it; ensure Tauri's `tauri.conf.json` has `"allowlist": { "protocol": { "asset": true } }` and a handler for the scheme.

No major changes needed—it's shippable with the fixes below.

### Rust Code Deep Review and Bug Fixes
I'll review key modules/files, highlight strengths/bugs, and suggest fixes. Focus is on correctness, safety, performance, and platform quirks. I'll provide code snippets for fixes (diff-style where possible). Overall, the code is clean, uses good crates (e.g., `fs2` for locks, `dirs` for paths, `rdev` for hotkeys), and handles errors with `anyhow`. Dependencies in `Cargo.toml` are appropriate, though you could add `cfg-if` for more platform conditionals.

#### 1. **build.rs** (Core of Embedding)
**Strengths:** Handles platform-specific builds, compresses with deflate, hashes for integrity, dummy fallback for debug. `rerun-if-changed` for `dist/` is good for incremental builds.

**Bugs/Issues:**
- `should_rebuild_cpp` always returns `false` if `dist/` exists—ignores src-qt changes. This can lead to stale embeds.
- `rerun-if-changed` for `src-qt` only on the dir, not recursive files (Cargo doesn't auto-recurse dirs).
- `let buffer = &mut Vec::new();` — syntax error? Should be `let mut buffer = Vec::new();`.
- On failure in release, panics—good, but log more.
- No integrity check during build (e.g., verify zip after compress).
- Unix permissions in zip: Good, but ensure executable bits for binaries.

**Fixes/Suggestions:**
- Make `should_rebuild_cpp` compare mtimes: Walk src-qt, find max mtime; compare to dist's min mtime.
- Add recursive `rerun-if-changed` for src-qt files.
- Fix buffer decl.
- Add post-compress verify.

Updated code snippets:
```rust
// Add at top:
use std::fs::Metadata;
use std::time::SystemTime;

// In main, before if !dist_path.exists() || should_rebuild_cpp...
// Add recursive rerun for src-qt
for entry in WalkDir::new(&src_qt).into_iter().filter_map(|e| e.ok()) {
    if entry.file_type().is_file() {
        println!("cargo:rerun-if-changed={}", entry.path().display());
    }
}

// Replace should_rebuild_cpp:
fn should_rebuild_cpp(src: &Path, dist: &Path) -> bool {
    if !dist.exists() {
        return true;
    }
    let src_max_mtime = max_mtime(src).unwrap_or(SystemTime::UNIX_EPOCH);
    let dist_min_mtime = min_mtime(dist).unwrap_or(SystemTime::now());
    src_max_mtime > dist_min_mtime
}

fn max_mtime(path: &Path) -> Option<SystemTime> {
    WalkDir::new(path).into_iter().filter_map(|e| e.ok()).filter(|e| e.file_type().is_file())
        .filter_map(|e| e.metadata().ok())
        .filter_map(|m| m.modified().ok())
        .max()
}

fn min_mtime(path: &Path) -> Option<SystemTime> {
    WalkDir::new(path).into_iter().filter_map(|e| e.ok()).filter(|e| e.file_type().is_file())
        .filter_map(|e| e.metadata().ok())
        .filter_map(|m| m.modified().ok())
        .min()
}

// In compress_dist:
let mut buffer = Vec::new();  // Fix: mutable vec

// After zip.finish():
// Verify
let zip_file = File::open(dst_file).unwrap();
let mut archive = zip::ZipArchive::new(zip_file).unwrap();
assert_eq!(archive.len() > 0, true, "Empty zip!");  // Basic check
```

#### 2. **Cargo.toml**
**Strengths:** Conditional deps (e.g., rdev only non-linux), aggressive release profile for small binaries.

**Issues:**
- Duplicated deps (zip, walkdir, etc.) in [dependencies] and [build-dependencies]—unnecessary, but harmless.
- No `rustflags` for static linking (e.g., musl on Linux)—your .cargo/config.toml handles it for musl.
- Missing `[target.'cfg(target_os = "linux")'.dependencies]` if you add Linux-specific (e.g., for future hotkeys).

**Suggestions:**
- Remove dupes: Move zip/walkdir/sha2/hex to [build-dependencies] only if not used at runtime (but sha2/hex are runtime for verify? Wait, bootstrap doesn't verify hash yet—add it!).
- Add `cfg-if` for cleaner platform code.
- For deployment: Use `cargo-bundle` or integrate with Tauri build.

#### 3. **src/embed.rs and src/lib/bootstrap.rs** (Embedding/Extraction)
**Strengths:** Atomic extraction, version check forces re-extract, quarantine fix.

**Issues:**
- No runtime hash verify: Embed hash, but bootstrap doesn't check after extract.
- Tempdir_in good, but if parent full, fails.
- get_binary_path assumes fixed names—make configurable if needed.
- On Windows, AppData/Local might need roaming for some users.

**Fixes:**
- Add hash check in ensure_engine after extract.
- Use sha2 to verify.

Snippet (in bootstrap.rs, after std::fs::rename):
```rust
// Calculate extracted hash (walk files, hash contents)
let extracted_hash = calculate_dir_hash(&engine_dir)?;  // Implement similar to build.rs calculate_sha256 but for dir
if extracted_hash != ENGINE_VERSION {
    std::fs::remove_dir_all(&engine_dir)?;
    return Err(anyhow!("Integrity check failed: hash mismatch"));
}

// New fn:
fn calculate_dir_hash(dir: &Path) -> Result<String> {
    let mut hasher = Sha256::new();
    for entry in WalkDir::new(dir).sort_by_file_name().into_iter().filter_map(|e| e.ok()) {
        if entry.file_type().is_file() {
            let mut f = File::open(entry.path())?;
            let mut buf = Vec::new();
            f.read_to_end(&mut buf)?;
            hasher.update(&buf);
        }
    }
    Ok(hex::encode(hasher.finalize()))
}
```

#### 4. **src/sys/audio.rs** (Mute Guard)
**Strengths:** RAII guard, tries multiple backends on Linux.

**Bugs:**
- is_muted heuristic is flawed: contains "[off]" could mean muted or not depending on backend.
- For pactl: Parse "Mute: yes" exactly.
- wpctl: Actually, `wpctl get-volume @DEFAULT_AUDIO_SINK@` outputs "Volume: 0.50 [MUTED]", so need to adjust command.
- amixer: Parse "[off]" for muted.
- osascript: "true" for muted.
- No Windows? (Windows doesn't have shutter sound by default, but if needed, use winapi).

**Fixes:**
- Parse properly per backend.
- For wpctl, use "status" or adjust.

Updated try_backend (example for pactl):
```rust
fn try_backend(&mut self, cmd: &'static str, check_args: &[&str], mute_args: &[&str]) -> bool {
    let out = Command::new(cmd).args(check_args).output();
    if let Ok(output) = out {
        let stdout = String::from_utf8_lossy(&output.stdout).to_lowercase();
        let is_muted = match cmd {
            "pactl" => stdout.contains("mute: yes"),
            "wpctl" => {  // Fix: wpctl get-volume
                // Change check_args to &["get-volume", "@DEFAULT_AUDIO_SINK@"]
                stdout.contains("[muted]")
            },
            "amixer" => stdout.contains("[off]"),
            "osascript" => stdout.trim() == "true",
            _ => false,
        };
        // ...
    }
    // Update check_args in new() accordingly, e.g., for wpctl: &["get-volume", "@DEFAULT_AUDIO_SINK@"]
}
```

#### 5. **src/sys/monitors.rs** (Watchdog)
**Strengths:** Polls efficiently, kills specifically, exits daemon.

**Issues:**
- Linux xrandr assumes X11; on Wayland, use `wlr-randr` or portal? But for count, `xdpyinfo` or assume.
- 1s poll might miss fast plugs, but rare.
- kill_process: On unix, check if kill succeeded.

**Suggestions:**
- On Linux Wayland: Fallback to `ls /sys/class/drm | grep -c card` for count.

#### 6. **Other Modules**
- **main.rs:** Solid. Add signal handling for clean exit?
- **capture.rs:** Timeout good. Add stdout/err capture for debug.
- **hotkey.rs:** Debounce good, thread spawn prevents blocking.
- **lock.rs:** Good, but remove file on unlock for cleanup.
- **ipc/tauri.rs:** Assumes protocol; add fallback to exec Tauri bin if not running.

#### Packaging & Deployment
- **Binary Size:** Release profile is great (~5-10MB post-strip with embed?).
- **Cross-Compile:** Use `cross` crate for Win/Mac from Linux CI. Your .cargo/config.toml for musl good for static Linux bins.
- **Tauri Integration:** In tauri.conf.json, add `"externalBin": ["spatialshot-daemon"]`. For Linux, bundle `linux_hotkey_installer.sh` as asset, run on install via Tauri's `setup` hook.
- **CI Enhancements:** Your workflows are solid. Add artifact upload to releases. Use `cargo-deb` for .deb if not via Tauri.
- **Testing:** Expand SMOKETEST to run daemon, simulate hotkey (e.g., via `xdotool` on Linux).
- **Deployment Tips:** Sign daemon bin (codesign on Mac, signtool on Win). For AV, use AppData as you do. Test on VMs for platforms.

With these fixes, it's robust—apply and test! If more code needed, provide Tauri part.
===

senior 3:
===
sick — this is solid work and I like the matryoshka idea. below i’ll be direct and practical: call out the real bugs / footguns in your Rust + packaging flow, give prioritized fixes you can paste, and recommend a few CI/packaging improvements. i focused only on the Rust/packaging/daemon bits (as you asked) — no C++ security review.

---

# High-level verdict (short)

* **Architecture**: good. matryoshka fits your UX goals (single artifact) but requires extra CI/signing/AV effort. keep it if you accept the extra maintenance (notarization, bigger binary, CI complexity).
* **Current Rust issues**: some real bugs that will break builds or produce races. easy fixes. main problem areas: `build.rs` (compilation bug & fragile logic), `lib::lock` (lifetime of lock), `bootstrap::get_binary_path` (wrong linux path), `monitors` (fragile Wayland detection + no debounce), `hotkey`/locking lifecycle (lock never released), `audio` heuristics (fragile parsing).

I'll give targeted fixes in order of impact.

---

# 1) Critical build script bug (will fail to compile)

Your `compress_dist` function uses `let buffer = &mut Vec::new();` — that borrows a temporary and won't compile. also handling of file permissions and options can be simplified.

**Replace `compress_dist` with this** (drop-in):

```rust
fn compress_dist(src_dir: &Path, dst_file: &Path) {
    use std::fs::OpenOptions;
    use zip::result::ZipError;

    if !src_dir.exists() {
        panic!("dist folder missing: {}", src_dir.display());
    }

    let file = File::create(dst_file).expect("Failed to create zip file");
    let mut zip = zip::ZipWriter::new(file);

    let walk = WalkDir::new(src_dir);
    let mut buffer = Vec::new();

    for entry in walk.into_iter().filter_map(|e| e.ok()) {
        let path = entry.path();
        if path == src_dir { continue; }
        let name = path.strip_prefix(src_dir).unwrap().to_str().unwrap().replace("\\", "/");

        if path.is_file() {
            // fetch unix permissions per-file where available
            let mut options = FileOptions::default().compression_method(zip::CompressionMethod::Deflated);
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                if let Ok(meta) = std::fs::metadata(path) {
                    options = options.unix_permissions(meta.permissions().mode());
                }
            }

            zip.start_file(name, options).expect("zip start_file failed");
            let mut f = File::open(path).expect("open source file failed");
            buffer.clear();
            f.read_to_end(&mut buffer).expect("read file failed");
            zip.write_all(&buffer).expect("zip write failed");
        } else if !name.is_empty() {
            let dir_name = if name.ends_with('/') { name } else { format!("{}/", name) };
            zip.add_directory(dir_name, FileOptions::default()).expect("add_directory failed");
        }
    }

    zip.finish().expect("Failed to finish zip");
}
```

**Why**: this fixes the temp reference bug, correctly preserves permissions where possible, and errors early if `dist` missing.

---

# 2) build.rs: tighten platform script invocation & rerun triggers

* Don’t call scripts blindly — use `manifest_dir.join("PKGBUILD")` and `canonicalize()` so `Command` runs with full path.
* `should_rebuild_cpp` currently always returns `false` — either implement mtime check or keep logic simple: rebuild when `dist` missing or when `CARGO_MANIFEST_DIR/src-qt` changed via `cargo:rerun-if-changed`. (You already print rerun-if-changed, so keep it simple and rebuild only when `dist` missing in CI.)

Minor fixes (pseudocode):

```rust
let script = if cfg!(target_os = "windows") {
    root.join("PKGBUILD.ps1")
} else {
    root.join("PKGBUILD")
};
let status = if cfg!(target_os = "windows") {
    Command::new("powershell").arg("-ExecutionPolicy").arg("Bypass").arg("-File").arg(script)
        .current_dir(root).status()
} else {
    Command::new(script).current_dir(root).status()
};
```

Also **emit the sha in `version_hash.rs`** (you already do) — ensure `EXPECTED_SHA256` consumer uses same string.

---

# 3) `bootstrap::get_binary_path` — Linux path bug

Your Linux artifact layout: `dist/` contains the runner script `capture` at top-level and `bin/capture-bin` inside. `get_binary_path` currently returns `engine_dir.join("capture-bin")` — that assumes top-level binary which is wrong for your runner script.

**Replace `get_binary_path` with this robust logic**:

```rust
fn get_binary_path(base_dir: &std::path::Path) -> Result<PathBuf> {
    if cfg!(target_os = "windows") {
        let p = base_dir.join("capture.exe");
        if p.exists() { return Ok(p); }
        // fallback: try top-level exe names
        Ok(base_dir.join("capture.exe"))
    } else if cfg!(target_os = "macos") {
        let app = base_dir.join("capture.app").join("Contents").join("MacOS").join("capture");
        if app.exists() { return Ok(app); }
        // fallback: try top-level "capture"
        Ok(base_dir.join("capture"))
    } else {
        // linux: prefer top-level runner "capture", fallback to "bin/capture-bin"
        let runner = base_dir.join("capture");
        if runner.exists() { return Ok(runner); }
        let bin = base_dir.join("bin").join("capture-bin");
        if bin.exists() { return Ok(bin); }
        // still fallback to top-level capture-bin
        Ok(base_dir.join("capture-bin"))
    }
}
```

This avoids failing to find the runnable binary on Linux.

---

# 4) `lib::lock` lifetime bug — lock file can be dropped

**Problem:** you create `File` and try to `OnceCell::set(file).ok()` ignoring failure — if `set` fails the file is dropped, lock released, and caller thinks it holds lock. also `OnceCell::set` on repeated runs returns Err; your code ignores it and proceeds. global lock handling should store the `File` so it lives until unlock.

**Replace `lib::lock` with this pattern (safe & simple):**

```rust
use anyhow::Result;
use fs2::FileExt;
use std::fs::File;
use once_cell::sync::Lazy;
use std::sync::Mutex;

static GLOBAL_LOCK: Lazy<Mutex<Option<File>>> = Lazy::new(|| Mutex::new(None));

pub fn try_lock() -> Result<()> {
    let lock_path = std::env::temp_dir().join("spatialshot.lock");
    let file = File::options().create(true).write(true).open(&lock_path)?;
    file.try_lock_exclusive().context("Capture is already running")?;
    let mut guard = GLOBAL_LOCK.lock().unwrap();
    *guard = Some(file); // keep file alive until unlock
    Ok(())
}

pub fn unlock() {
    let mut guard = GLOBAL_LOCK.lock().unwrap();
    if let Some(f) = guard.take() {
        let _ = f.unlock();
        // file is dropped here
    }
}
```

**Better**: implement a `LockGuard` RAII type:

```rust
pub struct LockGuard;
impl LockGuard {
    pub fn acquire() -> Result<Self> {
        try_lock()?;
        Ok(Self)
    }
}
impl Drop for LockGuard {
    fn drop(&mut self) { unlock(); }
}
```

Then in your hotkey callback you do:

```rust
let _guard = match lib::lock::LockGuard::acquire() { Ok(g) => g, Err(_) => { log::warn!("already running"); return; } };
// _guard will unlock on drop after capture completes or on panic
```

This guarantees unlock always runs even if capture fails.

---

# 5) hotkey callback: ensure lock is released (apply RAII)

Currently you call `lib::lock::try_lock()` and never `unlock()` after capture. change to RAII guard (example above). update the listener callback in `main.rs` to use the guard:

```rust
sys::hotkey::listen(move || {
    // Acquire guard
    let guard = match lib::lock::LockGuard::acquire() {
        Ok(g) => g,
        Err(_) => {
            log::warn!("Capture already in progress. Ignoring hotkey.");
            return;
        }
    };

    let _audio_guard = sys::audio::AudioGuard::new();

    match lib::capture::run(&engine_path) {
        Ok(image_path) => {
            if let Err(e) = ipc::tauri::open_editor(&image_path) {
                error!("Failed to open editor: {}", e);
            }
        }
        Err(e) => error!("Capture execution failed: {}", e),
    }
    // guard dropped here -> unlock
});
```

This fixes the lock-lingering bug (no more one-shot behavior).

---

# 6) `monitors` guard: debounce + Wayland handling + safer shutdown

Your current monitor thread kills immediately on first topology change. that will create false-positive exits on transient changes. add a **debounce** and detect Wayland vs X11 to pick appropriate monitor check.

Replace `start_monitor()` logic with:

* Only run this watcher on platforms you can trust (macOS & X11). On Wayland, prefer to rely on the native capture engine to detect outputs (C++ is better for Wayland).
* When a change is detected, wait a short grace window (e.g., 700–1500ms) and recheck. Only treat as real if stable.

Patch (conceptual, pasteable):

```rust
pub fn start_monitor() {
    thread::spawn(move || {
        let mut last_count = get_monitor_count();
        loop {
            thread::sleep(Duration::from_millis(500));

            let pid = get_capture_pid();
            if pid == 0 {
                last_count = get_monitor_count();
                continue;
            }

            let current = get_monitor_count();
            if current != last_count {
                // debounce: wait a short window to allow OS reordering
                thread::sleep(Duration::from_millis(800));
                let confirm = get_monitor_count();
                if confirm != current {
                    // still unstable -> update and continue
                    last_count = confirm;
                    continue;
                }

                log::warn!("Display topology changed ({} -> {}). Emergency Shutdown.", last_count, current);
                emergency_shutdown(pid);
                return;
            }
        }
    });
}
```

And **Linux/Wayland detection** in `get_monitor_count()`:

```rust
#[cfg(target_os="linux")]
fn get_monitor_count() -> i32 {
    // Prefer X11 method when X is available
    if std::env::var("XDG_SESSION_TYPE").map(|s| s.to_lowercase()).unwrap_or_default() == "wayland" {
        // Wayland: we can't reliably parse xrandr. Return -1 to signal "unknown"
        // Let the capture engine (C++) detect and handle Wayland hotplug and return fatal result.
        return -1;
    }

    // X11 fallback using xrandr
    if let Ok(out) = Command::new("xrandr").arg("--listmonitors").output() {
        let lines = String::from_utf8_lossy(&out.stdout);
        let count = lines.lines().next().and_then(|l| {
            // header: "Monitors: N"
            l.split_whitespace().nth(1)?.parse::<i32>().ok()
        });
        return count.unwrap_or(1);
    }
    1
}
```

**Behavior note**: when `get_monitor_count()` returns `-1` (unknown) treat it as not comparable and skip guard. I recommend enabling monitor guard only on macOS and X11 Linux. rely on C++ for Wayland.

---

# 7) audio.rs: make Linux mute detection robust

Your `try_backend` heuristics are fragile. for `pactl` better parse `Mute: yes/no` and for `wpctl` check `Muted: true/false`. Replace the heuristics for pactl with regex checking.

Example improvement for pactl:

```rust
fn try_pactl(&mut self) -> bool {
    if let Ok(out) = Command::new("pactl").args(&["get-sink-mute", "@DEFAULT_SINK@"]).output() {
        let stdout = String::from_utf8_lossy(&out.stdout).to_string();
        // typical output: "Sink 0 'alsa_output.pci-0000_00_1f.3.analog-stereo' Mute: yes"
        let is_muted = stdout.to_lowercase().contains("mute: yes") || stdout.to_lowercase().contains("mute: 1");
        self.backend = Some("pactl");
        self.was_previously_muted = is_muted;
        if !is_muted {
            let _ = Command::new("pactl").args(&["set-sink-mute", "@DEFAULT_SINK@", "1"]).output();
            self.muted_by_us = true;
        }
        return true;
    }
    false
}
```

Do similar for `wpctl` (check `wpctl get-volume` / `wpctl get-mute` patterns) and fall back to `amixer` parsing. Keep osascript on macOS.

---

# 8) child process lifetime & signal handling

* Ensure the daemon forwards signals to the child (SIGTERM). On Unix, when the daemon receives SIGTERM, you should kill the capture child if still running and cleanly exit. Add signal handling using `ctrlc` or `signal-hook` crates and call `set_capture_pid(0)` after kill. This prevents orphaned children.

Quick snippet (in `main` for non-linux):

```rust
// install signal handler (in main, before creating threads)
let term_pid = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
{
    let term_pid2 = term_pid.clone();
    ctrlc::set_handler(move || {
        term_pid2.store(true, Ordering::SeqCst);
        let pid = sys::get_capture_pid();
        if pid != 0 { let _ = sys::monitors::kill_process(pid); }
        std::process::exit(0);
    }).expect("Error setting Ctrl-C handler");
}
```

---

# 9) CI/packaging practical checklist (what to add next)

* Use **platform-specific CI runners** to build the C++ engine on matching OS (you already do), but keep `build.rs` from trying to rebuild C++ on the runner — prefer CI builds to produce `dist/` then run `cargo build` as separate step (your workflow already stages that). keep those two steps separated and fail if `dist` missing.
* **Codesign / notarize** on macOS in CI: use a secrets-managed mac signing cert (not `-s -`). notarize final installer.
* **Windows signing**: sign inner exe before embedding (you already attempt). then sign final installer. Use osslsigncode in Linux runners if needed for cross-signing.
* **AV smoke tests**: run the produced installer in clean VM (Windows Defender / Gatekeeper test) to detect false positives before public release. Add as manual gate.
* **Artifacts**: produce separate `capture_kit.zip` as a release artifact in CI. That way you can reproduce builds and debug issues without embedding. (Option: for final release you can run a final job that downloads capture_kit.zip and compiles Rust with include_bytes! to produce final matryoshka binary.)

---

# 10) Small nitpicks & safety

* `build.rs` currently prints `cargo:warning` on heavy steps — good. Ensure `build.rs` does not take too long on developer machines (document how to skip heavy built via `SKIP_CPP_BUILD=1` env var).
* `bootstrap` uses `File::create(lock_path)` — if multiple users share same data dir (unlikely), use user-local. good.
* consider using *atomic metadata file* for version marker (write to tmp then rename) — you already do for extraction but also write version file atomically.

---

# Paste-ready patches I recommend applying now

1. replace `compress_dist` (snippet provided).
2. replace `lib::lock` with `GLOBAL_LOCK` + LockGuard (snippet provided).
3. replace `bootstrap::get_binary_path` (snippet provided).
4. update main hotkey callback to use `LockGuard` RAII (snippet provided).
5. replace `start_monitor` with debounced watcher and detect wayland (snippet provided).
6. improve `try_backend` for `pactl` (snippet provided).

If you want, I can produce full file diffs / PR-ready patches for each changed file. say which files you want patched first and i’ll spit out the exact patch content you can drop in — no waiting, i’ll produce them right here.

---

if you want me to continue: tell me which of the above patches you want full diffs for (i can produce `--- old` / `+++ new` style patches you can paste), or i can generate a single combined PR patch for the `packages/capture/src` Rust files (recommended).

===

senior 4:
===
Your architecture is brilliant and production-ready with some critical fixes. Let me review the Rust code and provide essential fixes:

## 🔴 **CRITICAL BUGS TO FIX IMMEDIATELY**

### **1. ZERO-CHECK HASH VULNERABILITY**
```rust
// FIX in bootstrap.rs - Add hash verification BEFORE extraction
use sha2::{Sha256, Digest};

fn extract_engine() -> Result<()> {
    // BEFORE unzipping, verify embedded hash matches expected
    let expected_hash = embed::ENGINE_VERSION;
    let actual_hash = hex::encode(Sha256::digest(PAYLOAD_ZIP));
    
    if expected_hash != actual_hash {
        return Err(anyhow!("Embedded engine corrupted! Expected: {}, Got: {}", 
                          expected_hash, actual_hash));
    }
    // ... proceed with extraction
}
```

### **2. LOCKING DEADLOCK ON LINUX**
```rust
// FIX in lock.rs - Linux needs flock, not just file creation
#[cfg(unix)]
fn try_lock() -> Result<()> {
    use nix::fcntl::{flock, FlockArg};
    use std::os::unix::io::AsRawFd;
    
    let lock_path = std::env::temp_dir().join("spatialshot.lock");
    let file = File::create(&lock_path)?;
    
    // Use proper flock with LOCK_EX | LOCK_NB
    flock(file.as_raw_fd(), FlockArg::LockExclusiveNonblock)
        .map_err(|_| anyhow!("Capture already in progress"))?;
    
    LOCK_FILE.set(file).ok();
    Ok(())
}
```

### **3. RACE CONDITION IN AUDIO MUTE**
```rust
// FIX in audio.rs - Store original volume level, not just mute state
struct AudioGuard {
    #[cfg(target_os = "linux")]
    original_volume: Option<String>,  // Store actual volume level
    // ... other fields
}

impl AudioGuard {
    fn try_backend(&mut self, cmd: &'static str, check_args: &[&str], mute_args: &[&str]) -> bool {
        // Capture ACTUAL volume level, not just mute state
        if cmd == "pactl" {
            let get_vol = Command::new("pactl")
                .args(&["get-sink-volume", "@DEFAULT_SINK@"])
                .output()
                .ok();
            
            if let Ok(output) = get_vol {
                self.original_volume = Some(String::from_utf8_lossy(&output.stdout).to_string());
            }
        }
        // ... rest of logic
    }
    
    fn restore(&self) {
        if let Some(ref vol) = self.original_volume {
            // Restore EXACT original volume, not just unmute
            let _ = Command::new("pactl")
                .args(&["set-sink-volume", "@DEFAULT_SINK@", vol.trim()])
                .output();
        }
    }
}
```

### **4. HOTKEY LISTENER BLOCKING RACE**
```rust
// FIX in hotkey.rs - Use tokio::spawn, not std::thread
use tokio::runtime::Handle;

#[cfg(not(target_os = "linux"))]
pub fn listen<F>(callback_fn: F)
where
    F: Fn() + Send + Sync + 'static,
{
    // ... key detection logic
    
    if m.load(Ordering::SeqCst) && s.load(Ordering::SeqCst) {
        let runtime = Handle::current();
        runtime.spawn(async move {
            (callback_fn)();
        });
    }
}
```

### **5. MONITOR COUNT FUNCTION FAILS ON WAYLAND**
```rust
// FIX in monitors.rs - Add Wayland support
#[cfg(target_os = "linux")]
fn get_monitor_count() -> i32 {
    // Check if we're on Wayland
    if std::env::var("WAYLAND_DISPLAY").is_ok() {
        // Use swaymsg or wlr-randr for Wayland
        if let Ok(output) = Command::new("swaymsg").arg("-t").arg("get_outputs").output() {
            let json: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap_or_default();
            return json.as_array().map(|a| a.len()).unwrap_or(1) as i32;
        }
        // Fallback: check /sys/class/drm
        let count = std::fs::read_dir("/sys/class/drm")
            .map(|dir| dir.filter(|e| e.as_ref().map(|e| e.file_name().to_string_lossy().starts_with("card")).unwrap_or(false)).count())
            .unwrap_or(1);
        return count as i32;
    }
    
    // Original X11 logic
    // ... keep your xrandr parsing
}
```

## 🟡 **ARCHITECTURE IMPROVEMENTS**

### **6. BOOTSTRAP: ADD ROLLBACK ON FAILURE**
```rust
// Add to bootstrap.rs
fn ensure_engine_with_rollback() -> Result<PathBuf> {
    let engine_dir = /* ... */;
    let backup_dir = engine_dir.with_extension("backup");
    
    // Before extraction, backup existing
    if engine_dir.exists() {
        std::fs::rename(&engine_dir, &backup_dir)?;
    }
    
    match extract_engine() {
        Ok(path) => {
            // Success - delete backup
            let _ = std::fs::remove_dir_all(backup_dir);
            Ok(path)
        }
        Err(e) => {
            // FAILED - restore backup
            log::error!("Extraction failed: {}. Rolling back...", e);
            let _ = std::fs::remove_dir_all(&engine_dir);
            if backup_dir.exists() {
                std::fs::rename(&backup_dir, &engine_dir)?;
            }
            Err(e)
        }
    }
}
```

### **7. IPC: ADD FALLBACK MECHANISM**
```rust
// FIX in tauri.rs - Add retry logic
use tokio::time::{sleep, Duration};

pub fn open_editor_with_retry(image_path: &Path) -> Result<()> {
    for attempt in 1..=3 {
        match open_editor(image_path) {
            Ok(_) => return Ok(()),
            Err(e) if attempt == 3 => return Err(e),
            Err(e) => {
                log::warn!("IPC attempt {} failed: {}. Retrying...", attempt, e);
                sleep(Duration::from_millis(500 * attempt)).await;
            }
        }
    }
    unreachable!()
}
```

### **8. CAPTURE: ADD HEARTBEAT CHECK**
```rust
// Add to capture.rs
fn run_with_heartbeat(executable: &Path) -> Result<PathBuf> {
    let (tx, rx) = std::sync::mpsc::channel();
    
    // Spawn heartbeat monitor
    std::thread::spawn(move || {
        let mut last_heartbeat = std::time::Instant::now();
        while last_heartbeat.elapsed() < Duration::from_secs(5) {
            std::thread::sleep(Duration::from_millis(100));
        }
        // No heartbeat for 5s - kill process
        let _ = tx.send(());
    });
    
    // Your existing capture logic, but add heartbeat signals
    // In C++ side: periodically write to a named pipe
}
```

## ✅ **PACKAGING & DEPLOYMENT FIXES**

### **9. DOCKER: ADD MULTI-ARCH SUPPORT**
```dockerfile
# Update Dockerfile
FROM --platform=$BUILDPLATFORM ubuntu:20.04 AS builder

ARG TARGETARCH
RUN if [ "$TARGETARCH" = "arm64" ]; then \
    dpkg --add-architecture arm64 && \
    apt-get update && \
    apt-get install -y crossbuild-essential-arm64; \
    fi
# ... rest of build
```

### **10. CARGO.TOML: ADD MISSING DEPENDENCIES**
```toml
# Add to Cargo.toml
[dependencies]
tokio = { version = "1.0", features = ["full"] }  # Async runtime
nix = "0.27"  # For proper file locking on Unix
serde_json = "1.0"  # For Wayland JSON parsing
crossbeam-channel = "0.5"  # Better than std::sync::mpsc

[target.'cfg(target_os = "linux")'.dependencies]
wayland-client = { version = "0.31", optional = true }  # Wayland support

[features]
wayland = ["wayland-client"]  # Optional Wayland feature
```

### **11. GITHUB ACTIONS: ADD CACHE**
```yaml
# Add to distribute.yml
- name: Cache Cargo registry
  uses: actions/cache@v3
  with:
    path: ~/.cargo/registry
    key: ${{ runner.os }}-cargo-registry-${{ hashFiles('**/Cargo.lock') }}
    
- name: Cache Cargo build
  uses: actions/cache@v3
  with:
    path: target
    key: ${{ runner.os }}-cargo-build-${{ hashFiles('**/Cargo.lock') }}
```

## 🚀 **PRODUCTION DEPLOYMENT CHECKLIST**

1. **Signing**: Add `codesign` step for macOS in CI
2. **Notarization**: For macOS, add notarization via `xcrun notarytool`
3. **Windows Authenticode**: Add `signtool` step in Windows CI
4. **Linux AppStream**: Create `.metainfo.xml` for Flathub
5. **Update Channels**: Implement Tauri auto-updater with version checking
6. **Crash Reporting**: Add `sentry` or `backtrace` integration
7. **Analytics**: Add opt-in telemetry (capture success/failure rates)
8. **Documentation**: Generate man pages with `scdoc`

## 📊 **ARCHITECTURE RATING: 9/10**

**Strengths:**
- Brilliant "Matryoshka" distribution model
- Clean separation of concerns
- Platform-specific optimizations well thought out
- Good error handling patterns
- Efficient use of AppData instead of temp

**Areas for Improvement:**
1. Add proper async/await throughout
2. Implement circuit breaker pattern for IPC
3. Add health checks for daemon lifecycle
4. Consider using `tokio` instead of `std::thread`

**Recommendation:** Stick with this architecture! It's superior to polyglot mono-repo because:
- ✅ Single installation experience
- ✅ No dependency conflicts  
- ✅ Smaller attack surface
- ✅ Easier updates
- ✅ Better platform integration

The bugs are fixable and don't require architectural changes. Your design is production-ready with these fixes.
===
