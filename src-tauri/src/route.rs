//! Which view a session's events and frames go to (ADR-0013 detach / attach).
//!
//! A session always has a `main` view (the sinks it was opened with, replaced by a later
//! `session_attach` from `main`) and at most one `detached-<sessionId>` view. Exactly one of
//! them is attached. The session task writes through [`Route::event_sink`] and
//! [`Route::frame_out`], which follow the attached view:
//!
//! * `session_attach` from another view moves both sinks there, sends `detached` to the view
//!   that lost the session and resets frame credits (the next message is a full frame).
//! * `window_attach`, or the detached view going away (its channel fails, its window closes),
//!   moves the session back to `main` and sends `attached` there.
//! * `closed` always reaches `main` as well, so a detached tab never stays open in `main`.

use std::sync::{Arc, Mutex};

use crate::frame_pump::FrameOut;
use crate::guard::DETACHED_PREFIX;
use crate::navigation::MAIN_WINDOW;
use crate::sessions::{EventSink, WireEvent};

/// The sinks of one view.
#[derive(Clone)]
pub struct Sinks {
    /// `onEvent`.
    pub events: EventSink,
    /// `onFrame` (RDP / VNC only).
    pub frames: Option<FrameOut>,
}

impl std::fmt::Debug for Sinks {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Sinks").field("frames", &self.frames.is_some()).finish_non_exhaustive()
    }
}

/// Called when the attached view changes: drop frame credits, send a full frame next.
pub type OnSwitch = Arc<dyn Fn() + Send + Sync>;

struct Inner {
    main: Sinks,
    /// `(label, sinks)` of the detached view, while it exists.
    detached: Option<(String, Sinks)>,
    /// Whether the detached view (not `main`) is attached.
    on_detached: bool,
    on_switch: Option<OnSwitch>,
}

/// The routing state of one session.
pub struct Route(Mutex<Inner>);

impl std::fmt::Debug for Route {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Route").field("view", &self.view()).finish_non_exhaustive()
    }
}

impl Route {
    /// A route attached to `main`.
    pub fn new(main: Sinks) -> Arc<Self> {
        Arc::new(Self(Mutex::new(Inner {
            main,
            detached: None,
            on_detached: false,
            on_switch: None,
        })))
    }

    /// Install the frame reset hook (graphical sessions).
    pub fn set_on_switch(&self, hook: OnSwitch) {
        if let Ok(mut g) = self.0.lock() {
            g.on_switch = Some(hook);
        }
    }

    /// Label of the attached view.
    pub fn view(&self) -> String {
        self.0.lock().ok().map_or_else(
            || MAIN_WINDOW.to_owned(),
            |g| match (&g.detached, g.on_detached) {
                (Some((label, _)), true) => label.clone(),
                _ => MAIN_WINDOW.to_owned(),
            },
        )
    }

    /// Label of the detached view, attached or not.
    pub fn detached_label(&self) -> Option<String> {
        self.0.lock().ok().and_then(|g| g.detached.as_ref().map(|(l, _)| l.clone()))
    }

    /// The attached sinks, and whether they are the detached view's.
    fn current(&self) -> Option<(Sinks, Option<Sinks>)> {
        let g = self.0.lock().ok()?;
        Some(match (&g.detached, g.on_detached) {
            (Some((_, d)), true) => (d.clone(), Some(g.main.clone())),
            _ => (g.main.clone(), None),
        })
    }

    /// Attach `label` (`main` or `detached-…`) with fresh sinks. The view that loses the
    /// session (if another one) receives `detached`. Frame credits are reset either way.
    pub fn attach(&self, label: &str, sinks: Sinks) {
        let (lost, hook) = {
            let Ok(mut g) = self.0.lock() else { return };
            let before = match (&g.detached, g.on_detached) {
                (Some((l, s)), true) => (l.clone(), s.clone()),
                _ => (MAIN_WINDOW.to_owned(), g.main.clone()),
            };
            if label.starts_with(DETACHED_PREFIX) {
                g.detached = Some((label.to_owned(), sinks));
                g.on_detached = true;
            } else {
                g.main = sinks;
                g.on_detached = false;
            }
            let lost = (before.0 != label).then_some(before.1);
            (lost, g.on_switch.clone())
        };
        if let Some(old) = lost {
            (old.events)(WireEvent::Detached);
        }
        if let Some(h) = hook {
            h();
        }
    }

    /// Forget the detached view and attach `main` again. Returns the detached label if there
    /// was one (the caller closes that window); `main` then receives `attached`.
    pub fn back_to_main(&self) -> Option<String> {
        let (label, main, hook) = {
            let mut g = self.0.lock().ok()?;
            let (label, _) = g.detached.take()?;
            g.on_detached = false;
            (label, g.main.clone(), g.on_switch.clone())
        };
        (main.events)(WireEvent::Attached);
        if let Some(h) = hook {
            h();
        }
        Some(label)
    }

    /// Deliver an event to the attached view. A failed detached view falls back to `main`.
    /// `closed` reaches `main` too.
    pub fn send_event(&self, event: WireEvent) -> bool {
        let Some((sinks, main)) = self.current() else { return false };
        let closed = matches!(event, WireEvent::Closed { .. });
        match main {
            None => (sinks.events)(event),
            Some(main) => {
                let delivered = (sinks.events)(event.clone());
                if closed {
                    return (main.events)(event) || delivered;
                }
                if delivered {
                    return true;
                }
                self.back_to_main();
                (main.events)(event)
            }
        }
    }

    /// Deliver an MFR1 message to the attached view. When a detached view is gone the session
    /// returns to `main` (which gets a full frame next), so the pump keeps running.
    pub fn send_frame(&self, bytes: Vec<u8>) -> bool {
        let Some((sinks, main)) = self.current() else { return false };
        let Some(out) = sinks.frames else {
            return main.is_some() && self.back_to_main().is_some();
        };
        if out(bytes) {
            return true;
        }
        main.is_some() && self.back_to_main().is_some()
    }

    /// The session task's event sink.
    pub fn event_sink(self: &Arc<Self>) -> EventSink {
        let route = Arc::clone(self);
        Arc::new(move |e| route.send_event(e))
    }

    /// The frame pump's output.
    pub fn frame_out(self: &Arc<Self>) -> FrameOut {
        let route = Arc::clone(self);
        Arc::new(move |bytes| route.send_frame(bytes))
    }
}

#[cfg(test)]
#[path = "route_tests.rs"]
mod tests;
