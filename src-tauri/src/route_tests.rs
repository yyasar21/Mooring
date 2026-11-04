//! Route state machine: attach moves sinks, the old view gets `detached`, a dead detached
//! view falls back to `main`, `closed` reaches both.

use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use super::*;

/// A recording view; `alive` false makes its sinks fail like a closed window.
struct View {
    events: Arc<Mutex<Vec<String>>>,
    frames: Arc<Mutex<Vec<Vec<u8>>>>,
    alive: Arc<AtomicBool>,
}

impl View {
    fn new() -> Self {
        Self {
            events: Arc::default(),
            frames: Arc::default(),
            alive: Arc::new(AtomicBool::new(true)),
        }
    }

    fn sinks(&self, with_frames: bool) -> Sinks {
        let (ev, alive) = (Arc::clone(&self.events), Arc::clone(&self.alive));
        let events: EventSink = Arc::new(move |e| {
            let kind = serde_json::to_value(&e).expect("json")["kind"].as_str().unwrap_or("").to_owned();
            alive.load(Ordering::SeqCst) && {
                ev.lock().expect("m").push(kind);
                true
            }
        });
        let (fr, alive) = (Arc::clone(&self.frames), Arc::clone(&self.alive));
        let frames: Option<FrameOut> = with_frames.then(|| {
            let out: FrameOut = Arc::new(move |b| {
                alive.load(Ordering::SeqCst) && {
                    fr.lock().expect("m").push(b);
                    true
                }
            });
            out
        });
        Sinks { events, frames }
    }

    fn kinds(&self) -> Vec<String> {
        self.events.lock().expect("m").clone()
    }

    fn frames(&self) -> usize {
        self.frames.lock().expect("m").len()
    }
}

fn bytes() -> WireEvent {
    WireEvent::Bytes { data: "eA==".into() }
}

const D: &str = "detached-7f9c2ba4-e88f-4f0a-9e5b-2f6f1d3c8a11";

#[test]
fn detach_then_window_attach() {
    let (main, det) = (View::new(), View::new());
    let route = Route::new(main.sinks(true));
    let resets = Arc::new(AtomicUsize::new(0));
    let r = Arc::clone(&resets);
    route.set_on_switch(Arc::new(move || {
        r.fetch_add(1, Ordering::SeqCst);
    }));
    let (sink, out) = (route.event_sink(), route.frame_out());
    assert!(sink(bytes()) && out(vec![1]));
    assert_eq!((main.kinds(), main.frames()), (vec!["bytes".to_owned()], 1));
    assert_eq!(route.view(), "main");

    route.attach(D, det.sinks(true));
    assert_eq!(route.view(), D);
    assert_eq!(route.detached_label().as_deref(), Some(D));
    assert_eq!(main.kinds(), ["bytes", "detached"], "the old view is told");
    assert_eq!(resets.load(Ordering::SeqCst), 1, "credits reset, full frame next");
    assert!(sink(bytes()) && out(vec![2]));
    assert_eq!((det.kinds(), det.frames()), (vec!["bytes".to_owned()], 1));
    assert_eq!(main.frames(), 1, "main gets nothing while detached");

    assert_eq!(route.back_to_main().as_deref(), Some(D));
    assert_eq!(route.back_to_main(), None, "idempotent");
    assert_eq!(route.view(), "main");
    assert_eq!(main.kinds(), ["bytes", "detached", "attached"]);
    assert_eq!(resets.load(Ordering::SeqCst), 2);
    assert!(sink(bytes()) && out(vec![3]));
    assert_eq!(main.frames(), 2);
    assert_eq!(det.kinds(), ["bytes"], "nothing after attach");
}

#[test]
fn main_reattach_replaces_its_channels_without_detached() {
    let (old, new) = (View::new(), View::new());
    let route = Route::new(old.sinks(false));
    route.attach("main", new.sinks(false));
    assert!(route.event_sink()(bytes()));
    assert!(old.kinds().is_empty(), "same view: no `detached` to its old channel");
    assert_eq!(new.kinds(), ["bytes"]);
}

/// U3: a detached view attaching again (React StrictMode double mount) tells only its
/// previous channel; the fresh one never sees `detached`.
#[test]
fn detached_reattach_tells_only_the_previous_channel() {
    let (main, first, second) = (View::new(), View::new(), View::new());
    let route = Route::new(main.sinks(false));
    route.attach(D, first.sinks(false));
    route.attach(D, second.sinks(false));
    assert_eq!(main.kinds(), ["detached"], "main is told once");
    assert_eq!(first.kinds(), ["detached"], "the previous channel is told");
    assert!(second.kinds().is_empty(), "the fresh channel is not");
    assert!(route.event_sink()(bytes()));
    assert_eq!(second.kinds(), ["bytes"]);
    assert_eq!(route.view(), D);
}

#[test]
fn main_can_take_the_session_back_from_a_detached_view() {
    let (main, det, main2) = (View::new(), View::new(), View::new());
    let route = Route::new(main.sinks(false));
    route.attach(D, det.sinks(false));
    route.attach("main", main2.sinks(false));
    assert_eq!(det.kinds(), ["detached"]);
    assert_eq!(route.view(), "main");
    assert!(route.event_sink()(bytes()));
    assert_eq!(main2.kinds(), ["bytes"]);
    // The detached window is still known so window_attach / its close can tidy up.
    assert_eq!(route.back_to_main().as_deref(), Some(D));
}

#[test]
fn a_dead_detached_view_falls_back_to_main() {
    let (main, det) = (View::new(), View::new());
    let route = Route::new(main.sinks(true));
    route.attach(D, det.sinks(true));
    det.alive.store(false, Ordering::SeqCst);
    assert!(route.event_sink()(bytes()), "delivered to main instead");
    assert_eq!(main.kinds(), ["detached", "attached", "bytes"]);
    assert_eq!(route.view(), "main");

    route.attach(D, det.sinks(true));
    assert!(route.frame_out()(vec![9]), "the pump keeps running");
    assert_eq!(route.view(), "main");
    assert_eq!(main.frames(), 0, "that frame is dropped; a full one follows");
    main.alive.store(false, Ordering::SeqCst);
    assert!(!route.event_sink()(bytes()), "main gone: the UI is gone");
}

#[test]
fn closed_reaches_main_too() {
    let (main, det) = (View::new(), View::new());
    let route = Route::new(main.sinks(false));
    route.attach(D, det.sinks(false));
    let closed = WireEvent::Closed { reason: "bye".into(), code: mooring_core::CloseCode::User };
    assert!(route.event_sink()(closed));
    assert_eq!(det.kinds(), ["closed"]);
    assert_eq!(main.kinds(), ["detached", "closed"]);
}

#[test]
fn new_wire_events_serialise_as_bare_kinds() {
    assert_eq!(serde_json::to_string(&WireEvent::Detached).expect("j"), r#"{"kind":"detached"}"#);
    assert_eq!(serde_json::to_string(&WireEvent::Attached).expect("j"), r#"{"kind":"attached"}"#);
}
