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