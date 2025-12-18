// src/sys/mod.rs

pub mod audio;
pub mod hotkey;
pub mod monitors;

use std::sync::atomic::{AtomicU32, Ordering};

/// Global PID of the currently running C++ capture engine.
/// Used by MonitorGuard to kill the specific process if screens change.
pub static CAPTURE_PID: AtomicU32 = AtomicU32::new(0);

pub fn set_capture_pid(pid: u32) {
    CAPTURE_PID.store(pid, Ordering::SeqCst);
}

pub fn get_capture_pid() -> u32 {
    CAPTURE_PID.load(Ordering::SeqCst)
}