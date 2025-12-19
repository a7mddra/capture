// src/sys/monitors.rs

use crate::sys::get_capture_pid;
use std::process::Command;
use std::thread;
use std::time::Duration;

pub fn start_monitor() {
    thread::spawn(move || {
        let mut last_count = get_monitor_count();
        loop {
            thread::sleep(Duration::from_millis(1000));

            let pid = get_capture_pid();
            if pid == 0 {
                // No capture running, just update count and wait
                last_count = get_monitor_count();
                continue;
            }

            let current_count = get_monitor_count();
            if current_count != last_count {
                log::warn!(
                    "Display topology changed ({} -> {}). Emergency Shutdown.",
                    last_count,
                    current_count
                );
                emergency_shutdown(pid);
                return;
            }
        }
    });
}

fn emergency_shutdown(pid: u32) {
    let _ = kill_process(pid);
    // Best-effort cleanup then exit to allow system to restore normal state
    log::warn!("Exiting daemon due to monitor topology change.");
    std::process::exit(1);
}

pub(crate) fn kill_process(pid: u32) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        // Polite kill
        let _ = Command::new("kill").arg(pid.to_string()).output();
        thread::sleep(Duration::from_millis(100));
        // Force kill
        Command::new("kill")
            .arg("-9")
            .arg(pid.to_string())
            .output()?;
    }
    #[cfg(windows)]
    {
        const CREATE_NO_WINDOW: u32 = 0x08000000;
        Command::new("taskkill")
            .args(&["/F", "/PID", &pid.to_string()])
            .creation_flags(CREATE_NO_WINDOW)
            .output()?;
    }
    Ok(())
}

// --- Platform Specific Counters ---

#[cfg(target_os = "macos")]
fn get_monitor_count() -> i32 {
    // Requires: core-graphics crate
    use core_graphics::display::CGDisplay;
    match CGDisplay::active_displays() {
        Ok(d) => d.len() as i32,
        Err(_) => 1,
    }
}

#[cfg(target_os = "linux")]
fn get_monitor_count() -> i32 {
    // Parsing xrandr is ugly but reliable for this specific edge case
    let output = Command::new("xrandr").arg("--listmonitors").output().ok();
    if let Some(out) = output {
        // "Monitors: 2" -> line 1. Plus one line per monitor.
        // xrandr output usually has a header line.
        String::from_utf8_lossy(&out.stdout).lines().count() as i32 - 1
    } else {
        1
    }
}

#[cfg(target_os = "windows")]
fn get_monitor_count() -> i32 {
    // Requires: windows crate with Win32_UI_WindowsAndMessaging feature
    use windows::Win32::UI::WindowsAndMessaging::{GetSystemMetrics, SM_CMONITORS};
    unsafe { GetSystemMetrics(SM_CMONITORS) }
}
