//! The interactive shell channel: PTY `xterm-256color`, output streaming, resize.

use nexus_core::session::{SessionEvent, Size};
use russh::client::{Handle, Msg};
use russh::{Channel, ChannelMsg, ChannelReadHalf, ChannelWriteHalf};
use tokio::sync::mpsc;

use crate::handler::ClientHandler;

/// Largest `SessionEvent::Bytes` payload.
pub const MAX_CHUNK: usize = 64 * 1024;
/// Terminal type requested for the PTY.
pub const TERM: &str = "xterm-256color";

/// Commands from the `SshSession` front to the driver.
#[derive(Debug)]
pub(crate) enum Command {
    Data(Vec<u8>),
    Resize(Size),
    Close,
}

/// Why the pump stopped. All reasons are safe to show.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum PumpEnd {
    ClosedByUser,
    RemoteClosed(Option<u32>),
    ConnectionLost,
    UiGone,
}

impl PumpEnd {
    pub(crate) fn reason(&self) -> String {
        match self {
            Self::ClosedByUser | Self::UiGone => "closed by user".to_owned(),
            Self::RemoteClosed(Some(code)) => format!("session ended (exit status {code})"),
            Self::RemoteClosed(None) => "session ended".to_owned(),
            Self::ConnectionLost => "connection lost".to_owned(),
        }
    }
}

/// Open a session channel with a PTY and start the login shell.
pub(crate) async fn open_shell(
    handle: &Handle<ClientHandler>,
    size: Size,
) -> Result<Channel<Msg>, russh::Error> {
    let channel = handle.channel_open_session().await?;
    channel.request_pty(true, TERM, size.width, size.height, 0, 0, &[]).await?;
    channel.request_shell(true).await?;
    Ok(channel)
}

/// Forward remote output in ≤ [`MAX_CHUNK`] pieces. The bounded event channel applies
/// back-pressure: while the UI is not reading, we stop reading the SSH channel, and russh
/// stops granting window to the server.
async fn forward(events: &mpsc::Sender<SessionEvent>, data: &[u8]) -> bool {
    for chunk in data.chunks(MAX_CHUNK) {
        let event = SessionEvent::Bytes { data: chunk.to_vec() };
        if events.send(event).await.is_err() {
            return false;
        }
    }
    true
}

async fn on_command(write: &ChannelWriteHalf<Msg>, cmd: Option<Command>) -> Option<PumpEnd> {
    match cmd {
        None => Some(PumpEnd::UiGone),
        Some(Command::Close) => Some(PumpEnd::ClosedByUser),
        Some(Command::Data(bytes)) => {
            write.data_bytes(bytes).await.err().map(|_| PumpEnd::ConnectionLost)
        }
        Some(Command::Resize(size)) => write
            .window_change(size.width, size.height, 0, 0)
            .await
            .err()
            .map(|_| PumpEnd::ConnectionLost),
    }
}

/// Run the shell until either side ends it.
pub(crate) async fn pump(
    channel: Channel<Msg>,
    commands: &mut mpsc::Receiver<Command>,
    events: &mpsc::Sender<SessionEvent>,
) -> PumpEnd {
    let (mut read, write): (ChannelReadHalf, ChannelWriteHalf<Msg>) = channel.split();
    let mut exit_status = None;
    loop {
        tokio::select! {
            cmd = commands.recv() => {
                if let Some(end) = on_command(&write, cmd).await {
                    if end == PumpEnd::ClosedByUser || end == PumpEnd::UiGone {
                        let _ = write.eof().await;
                        let _ = write.close().await;
                    }
                    return end;
                }
            }
            msg = read.wait() => match msg {
                None => {
                    return if exit_status.is_some() {
                        PumpEnd::RemoteClosed(exit_status)
                    } else {
                        PumpEnd::ConnectionLost
                    };
                }
                Some(ChannelMsg::Data { data } | ChannelMsg::ExtendedData { data, .. }) => {
                    if !forward(events, &data).await {
                        return PumpEnd::UiGone;
                    }
                }
                Some(ChannelMsg::ExitStatus { exit_status: code }) => exit_status = Some(code),
                Some(ChannelMsg::Close) => return PumpEnd::RemoteClosed(exit_status),
                Some(_) => {}
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn forward_splits_into_bounded_chunks() {
        let (tx, mut rx) = mpsc::channel(8);
        let data = vec![7u8; MAX_CHUNK * 2 + 10];
        assert!(forward(&tx, &data).await);
        let mut sizes = Vec::new();
        while let Ok(SessionEvent::Bytes { data }) = rx.try_recv() {
            sizes.push(data.len());
        }
        assert_eq!(sizes, vec![MAX_CHUNK, MAX_CHUNK, 10]);
    }

    #[tokio::test]
    async fn forward_reports_a_gone_ui() {
        let (tx, rx) = mpsc::channel(1);
        drop(rx);
        assert!(!forward(&tx, b"x").await);
    }

    #[test]
    fn reasons_are_generic() {
        assert_eq!(PumpEnd::RemoteClosed(Some(3)).reason(), "session ended (exit status 3)");
        assert_eq!(PumpEnd::ConnectionLost.reason(), "connection lost");
        assert_eq!(PumpEnd::UiGone.reason(), "closed by user");
    }
}
