// src/sys/hotkey.rs

use log::{error, info};

#[cfg(not(target_os = "linux"))]
pub fn listen<F>(callback_fn: F)
where
    F: Fn() + Send + Sync + 'static,
{
    use rdev::{Event, EventType, Key};
    use std::sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    };
    use std::time::{Duration, Instant};

    info!("Starting Global Hotkey Listener (rdev)...");

    // Global atomic state for keys
    let meta_down = Arc::new(AtomicBool::new(false));
    let shift_down = Arc::new(AtomicBool::new(false));

    // Debounce guard (prevent accidental double-taps)
    let last_trigger = Arc::new(parking_lot::Mutex::new(
        Instant::now() - Duration::from_secs(10),
    ));

    let callback = Arc::new(callback_fn);

    let m = meta_down.clone();
    let s = shift_down.clone();
    let t = last_trigger.clone();

    // The rdev listener blocks the thread, so we run it here
    if let Err(error) = rdev::listen(move |event| {
        match event.event_type {
            EventType::KeyPress(key) => {
                match key {
                    // Windows: Key::MetaLeft/Right is the Windows Logo Key
                    // macOS: Key::MetaLeft/Right is Command (⌘)
                    Key::MetaLeft | Key::MetaRight => m.store(true, Ordering::SeqCst),
                    Key::ShiftLeft | Key::ShiftRight => s.store(true, Ordering::SeqCst),
                    Key::KeyA => {
                        // Check if modifiers are held
                        if m.load(Ordering::SeqCst) && s.load(Ordering::SeqCst) {
                            let mut last = t.lock();
                            // 500ms debounce
                            if last.elapsed() >= Duration::from_millis(500) {
                                info!("Hotkey Detected: Meta+Shift+A");
                                *last = Instant::now();

                                // Fire the callback (which runs the capture)
                                (callback)();
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
