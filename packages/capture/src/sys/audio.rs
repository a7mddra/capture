// src/sys/audio.rs

use std::process::Command;

pub struct AudioGuard {
    backend: Option<&'static str>,
    was_previously_muted: bool,
    muted_by_us: bool,
}

impl AudioGuard {
    pub fn new() -> Self {
        let mut guard = AudioGuard {
            backend: None,
            was_previously_muted: false,
            muted_by_us: false,
        };
        guard.mute();
        guard
    }

    fn mute(&mut self) {
        if cfg!(target_os = "macos") {
            self.try_backend(
                "osascript",
                &["-e", "output muted of (get volume settings)"],
                &["-e", "set volume with output muted"],
            );
        } else if cfg!(target_os = "linux") {
            // Try PulseAudio first (most common)
            if !self.try_backend(
                "pactl",
                &["get-sink-mute", "@DEFAULT_SINK@"],
                &["set-sink-mute", "@DEFAULT_SINK@", "1"],
            ) {
                // Try WirePlumber (newer pipes)
                if !self.try_backend(
                    "wpctl",
                    &["get-mute", "@DEFAULT_AUDIO_SINK@"],
                    &["set-mute", "@DEFAULT_AUDIO_SINK@", "1"],
                ) {
                    // Fallback to ALSA
                    self.try_backend(
                        "amixer",
                        &["get", "Master"],
                        &["-q", "sset", "Master", "mute"],
                    );
                }
            }
        }
    }

    fn try_backend(&mut self, cmd: &'static str, check_args: &[&str], mute_args: &[&str]) -> bool {
        if let Ok(output) = Command::new(cmd).args(check_args).output() {
            let out = String::from_utf8_lossy(&output.stdout).to_lowercase();

            // Check if already muted
            let is_muted = out.contains("true")
                || out.contains("yes")
                || out.contains("on")
                || out.contains("[off]")
                || out.contains("[mute]");

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

    fn restore(&self) {
        if !self.muted_by_us {
            return;
        }

        if let Some(cmd) = self.backend {
            let args: &[&str] = match cmd {
                "osascript" => &["-e", "set volume without output muted"],
                "pactl" => &["set-sink-mute", "@DEFAULT_SINK@", "0"],
                "wpctl" => &["set-mute", "@DEFAULT_AUDIO_SINK@", "0"],
                "amixer" => &["-q", "sset", "Master", "unmute"],
                _ => &[],
            };

            if !args.is_empty() {
                let _ = Command::new(cmd).args(args).output();
            }
        }
    }
}

impl Drop for AudioGuard {
    fn drop(&mut self) {
        self.restore();
    }
}
