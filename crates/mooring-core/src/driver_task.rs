//! The event stream of a protocol driver task (review 5 L-21), shared by RDP and VNC.
//!
//! Each graphical session runs its driver (`IronRDP`, our RFB decoders) in its own
//! `tokio::spawn`, so a panic there is isolated. But the session also keeps the event sender
//! (inside its shared state), so a panicked driver would leave `recv` waiting forever, and a
//! plain "stream ended" would read as `ServerEnded`, which the Tauri layer retries six times.
//! [`next_driver_event`] watches the task too: a driver that ends without a `Closed` becomes
//! `Closed { protocol_error }` (not retried), logged without its panic payload.

use tokio::sync::mpsc;
use tokio::task::JoinHandle;

use crate::session::{CloseCode, SessionEvent};

/// The next event, or a synthesized `Closed { protocol_error }` when the driver task ended
/// (panicked) without sending one. `task` is taken once it has finished. `what` names the
/// decoder in the reason, e.g. `"RDP"`.
pub async fn next_driver_event(
    events: &mut mpsc::Receiver<SessionEvent>,
    task: &mut Option<JoinHandle<()>>,
    what: &'static str,
) -> Option<SessionEvent> {
    let Some(handle) = task.as_mut() else {
        return events.recv().await;
    };
    let joined = tokio::select! {
        biased;
        event = events.recv() => return event,
        joined = handle => joined,
    };
    *task = None;
    // A driver that finished normally sent `Closed` before it returned.
    if let Ok(event) = events.try_recv() {
        return Some(event);
    }
    match joined {
        Err(e) if e.is_panic() => {
            tracing::error!(protocol = what, "session driver panicked");
        }
        _ => tracing::error!(protocol = what, "session driver ended without a close event"),
    }
    Some(SessionEvent::Closed {
        reason: format!("internal error in the {what} decoder"),
        code: CloseCode::ProtocolError,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn a_panicking_driver_becomes_one_protocol_error() {
        let (tx, mut rx) = mpsc::channel(4);
        let keep = tx.clone(); // the session's own copy: recv alone would never end
        let mut task = Some(tokio::spawn(async move {
            let ev = SessionEvent::DesktopResized { width: 1, height: 1 };
            tx.send(ev).await.expect("send");
            panic!("decoder bug");
        }));
        let first = next_driver_event(&mut rx, &mut task, "RDP").await;
        assert!(matches!(first, Some(SessionEvent::DesktopResized { .. })), "{first:?}");
        let closed = next_driver_event(&mut rx, &mut task, "RDP").await;
        let Some(SessionEvent::Closed { code, reason }) = closed else { panic!("{closed:?}") };
        assert_eq!(code, CloseCode::ProtocolError);
        assert!(!code.is_retryable());
        assert_eq!(reason, "internal error in the RDP decoder");
        assert!(task.is_none());
        drop(keep);
    }

    #[tokio::test]
    async fn a_normal_close_is_passed_through() {
        let (tx, mut rx) = mpsc::channel(4);
        let keep = tx.clone();
        let mut task = Some(tokio::spawn(async move {
            let ev = SessionEvent::Closed { reason: "bye".into(), code: CloseCode::ServerEnded };
            tx.send(ev).await.expect("send");
        }));
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        let ev = next_driver_event(&mut rx, &mut task, "VNC").await;
        assert!(matches!(ev, Some(SessionEvent::Closed { code: CloseCode::ServerEnded, .. })));
        drop(keep);
    }
}
