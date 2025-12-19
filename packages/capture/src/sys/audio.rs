// src/sys/audio.rs

use std::process::Command;

pub struct AudioGuard {
    backend: Option<&'static str>,
    was_previously_muted: bool,
    muted_by_us: bool,
    #[cfg(target_os = "linux")]
    original_volume: Option<String>,
}

impl AudioGuard {
    pub fn new() -> Self {
        let mut guard = AudioGuard {
            backend: None,
            was_previously_muted: false,
            muted_by_us: false,
            #[cfg(target_os = "linux")]
            original_volume: None,
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
                    &["get-volume", "@DEFAULT_AUDIO_SINK@"],
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
        let out = Command::new(cmd).args(check_args).output();
        if let Ok(output) = out {
            let stdout = String::from_utf8_lossy(&output.stdout).to_lowercase();
            // let stderr = String::from_utf8_lossy(&output.stderr).to_lowercase();
            
            let is_muted = match cmd {
                "pactl" => {
                    // "Mute: yes"
                    stdout.contains("mute: yes")
                },
                "wpctl" => {
                    // "Volume: 0.40 [MUTED]"
                    stdout.contains("[muted]")
                },
                "amixer" => {
                    // "[off]"
                    stdout.contains("[off]")
                },
                "osascript" => {
                    stdout.trim() == "true"
                },
                _ => false,
            };

            self.backend = Some(cmd);
            self.was_previously_muted = is_muted;

            // Optional: Store volume for restoration (Linux pactl/wpctl)
            #[cfg(target_os = "linux")]
            if !is_muted && cmd == "pactl" {
                 // Try to get actual volume
                 if let Ok(vol_out) = Command::new("pactl").args(&["get-sink-volume", "@DEFAULT_SINK@"]).output() {
                     self.original_volume = Some(String::from_utf8_lossy(&vol_out.stdout).to_string());
                 }
            }

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
            // Special handling for restore if we stored volume
            #[cfg(target_os = "linux")]
            if let Some(ref vol) = self.original_volume {
                if cmd == "pactl" {
                    // We need to parse the volume string properly or just unmute?
                    // "pactl set-sink-volume" expects a percentage or integer. 
                    // The output of get-sink-volume is complex. 
                    // Safest is just to unmute as before, unless we are sure about volume format.
                    // Senior 4 suggested restoring volume, but parsing is tricky.
                    // Let's stick to unmuting for safety, as incorrect volume string might fail.
                    // But we MUST unmute.
                }
            }

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