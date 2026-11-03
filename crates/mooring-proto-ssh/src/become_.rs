//! Privilege escalation after login (`sudo_become`, ADR-0009 §3).
//!
//! Once the shell is open the driver types one fixed command (`sudo`, `su` or `doas` to the
//! target user). The become password is written to the channel only when the remote password
//! prompt is detected after that command, and at most once; it is never echoed into the UI
//! stream by us (the remote tty has echo off while it reads a password).
//!
//! Review 3, M-6:
//! - The tty echoes the typed command, prompt text included. Matching starts only after the
//!   first `\n` of the output (the end of that echo), and the `sudo` prompt is typed as
//!   `[mooring]%%` so the printed prompt (`%%` becomes `%`) never appears in the echo.
//! - After the password is sent, the next 4 KiB are watched for failure (`Sorry, try again`,
//!   `incorrect password`, `Authentication failure`, `not in the sudoers`, or the prompt again).
//!   Then `^C` is sent once, the password is never resent, and the session stays the login user.
//!
//! `su` / `doas` prompts are matched on `password` + `:` at the end of the output.

use mooring_core::credential::BecomeMethod;
use mooring_core::session::Become;
use mooring_core::MooringError;
use secrecy::{ExposeSecret, SecretString};
use zeroize::Zeroizing;

/// The prompt as typed into `sudo -p` (sudo expands `%%` to `%`).
pub(crate) const SUDO_PROMPT_ARG: &str = "[mooring]%% become password: ";
/// The prompt as `sudo` prints it; never part of the echoed command line.
pub(crate) const SUDO_PROMPT: &str = "[mooring]% become password:";
/// Output inspected for a prompt (and, after sending, for a failure) before giving up.
const WATCH_LIMIT: usize = 4096;
/// Longest target user name.
const MAX_USER: usize = 64;
/// Output that means the escalation was refused (compared lower-case).
const FAILURES: &[&str] =
    &["sorry, try again", "incorrect password", "authentication failure", "not in the sudoers"];
/// Interrupt: ends the remote password read without sending anything else.
pub(crate) const CTRL_C: &[u8] = b"\x03";
/// Shown in the terminal after a failed escalation (our text, not the server's).
pub(crate) const FAILED_NOTICE: &[u8] =
    b"\r\n[mooring] become failed; the session continues as the login user\r\n";

/// A target user is a POSIX-portable name: it is typed into a remote shell, so nothing that a
/// shell would interpret is accepted.
pub(crate) fn check(b: &Become) -> Result<(), MooringError> {
    let u = b.user.as_str();
    let ok = !u.is_empty()
        && u.len() <= MAX_USER
        && !u.starts_with('-')
        && u.bytes().all(|c| c.is_ascii_alphanumeric() || matches!(c, b'.' | b'_' | b'-'));
    if ok {
        Ok(())
    } else {
        Err(MooringError::Invalid {
            field: "become_user",
            reason: "must be letters, digits, '.', '_' or '-'".to_owned(),
        })
    }
}

/// The command line typed after login (user already checked by [`check`]).
pub(crate) fn command(b: &Become) -> String {
    match b.method {
        BecomeMethod::Sudo => format!("sudo -p '{SUDO_PROMPT_ARG}' -i -u {}\n", b.user),
        BecomeMethod::Su => format!("su - {}\n", b.user),
        BecomeMethod::Doas => format!("doas -u {} -s\n", b.user),
    }
}

/// What the pump must do after feeding output to the [`Watcher`].
#[derive(PartialEq, Eq)]
pub(crate) enum Action {
    /// Nothing.
    None,
    /// Write this password line (once).
    Send(Zeroizing<Vec<u8>>),
    /// The escalation failed: write [`CTRL_C`], show [`FAILED_NOTICE`], audit `become_failed`.
    Failed,
}

impl std::fmt::Debug for Action {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::None => "None",
            Self::Send(_) => "Send(..)",
            Self::Failed => "Failed",
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Phase {
    /// Skipping the tty echo of the typed command (until the first `\n`).
    Echo,
    /// Waiting for the password prompt.
    Prompt,
    /// Password sent; watching for a failure.
    Sent,
    /// Finished (succeeded, failed or gave up).
    Done,
}

/// Watches shell output for the become password prompt, then for a failure.
pub(crate) struct Watcher {
    method: BecomeMethod,
    password: Option<SecretString>,
    phase: Phase,
    tail: Vec<u8>,
    seen: usize,
}

impl std::fmt::Debug for Watcher {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Watcher")
            .field("method", &self.method)
            .field("phase", &self.phase)
            .field("armed", &self.password.is_some())
            .finish_non_exhaustive()
    }
}

impl Watcher {
    pub(crate) fn new(b: Become) -> Self {
        // Without a stored password the user answers any prompt; there is nothing to watch.
        let phase = if b.password.is_some() { Phase::Echo } else { Phase::Done };
        Self { method: b.method, password: b.password, phase, tail: Vec::new(), seen: 0 }
    }

    /// The user typed into the session: once our password is sent, later output is theirs
    /// (for example `passwd`), so the failure watch ends.
    pub(crate) fn user_input(&mut self) {
        if self.phase == Phase::Sent {
            self.finish();
        }
    }

    /// Whether the watcher still needs output.
    pub(crate) fn active(&self) -> bool {
        self.phase != Phase::Done
    }

    /// Feed remote output.
    pub(crate) fn feed(&mut self, data: &[u8]) -> Action {
        let mut data = data;
        if self.phase == Phase::Echo {
            let Some(i) = data.iter().position(|&b| b == b'\n') else {
                self.count(data.len());
                return Action::None;
            };
            self.phase = Phase::Prompt;
            data = &data[i + 1..];
        }
        if self.phase == Phase::Done {
            return Action::None;
        }
        self.tail.extend_from_slice(data);
        if self.tail.len() > 256 {
            self.tail.drain(..self.tail.len() - 256);
        }
        let action = match self.phase {
            Phase::Prompt if self.failed() => self.fail(),
            Phase::Prompt if self.is_prompt() => {
                let Some(pw) = self.password.take() else { return self.fail() };
                let mut line = Zeroizing::new(pw.expose_secret().as_bytes().to_vec());
                line.push(b'\n');
                self.phase = Phase::Sent;
                self.tail.clear();
                self.seen = 0;
                return Action::Send(line);
            }
            Phase::Sent if self.failed() || self.is_prompt() => self.fail(),
            _ => Action::None,
        };
        if action == Action::None {
            self.count(data.len());
        }
        action
    }

    fn count(&mut self, n: usize) {
        self.seen = self.seen.saturating_add(n);
        if self.seen > WATCH_LIMIT {
            if self.phase != Phase::Sent {
                tracing::debug!("no become password prompt seen; password dropped unused");
            }
            self.finish();
        }
    }

    fn fail(&mut self) -> Action {
        tracing::info!("become failed; interrupting the escalation");
        self.finish();
        Action::Failed
    }

    fn finish(&mut self) {
        self.phase = Phase::Done;
        self.password = None;
        self.tail.clear();
    }

    fn failed(&self) -> bool {
        let text = String::from_utf8_lossy(&self.tail).to_lowercase();
        FAILURES.iter().any(|f| text.contains(f))
    }

    fn is_prompt(&self) -> bool {
        let text = String::from_utf8_lossy(&self.tail);
        let end = text.trim_end_matches([' ', '\t']);
        match self.method {
            BecomeMethod::Sudo => end.ends_with(SUDO_PROMPT),
            BecomeMethod::Su | BecomeMethod::Doas => {
                let last = end.rsplit(['\n', '\r']).next().unwrap_or_default().to_lowercase();
                last.ends_with(':') && last.contains("password")
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn become_(method: BecomeMethod, user: &str, pw: Option<&str>) -> Become {
        Become {
            method,
            user: user.to_owned(),
            password: pw.map(|p| SecretString::from(p.to_owned())),
        }
    }

    fn sent(a: Action) -> Option<Vec<u8>> {
        match a {
            Action::Send(line) => Some(line.to_vec()),
            _ => None,
        }
    }

    #[test]
    fn user_names_cannot_inject() {
        for bad in ["", "root; rm -rf /", "-c", "a b", "$(id)", "x`id`", &"a".repeat(65)] {
            assert!(check(&become_(BecomeMethod::Sudo, bad, None)).is_err(), "{bad:?}");
        }
        for ok in ["root", "svc-app", "deploy_1", "a.b"] {
            assert!(check(&become_(BecomeMethod::Su, ok, None)).is_ok(), "{ok}");
        }
        assert_eq!(
            command(&become_(BecomeMethod::Sudo, "root", None)),
            "sudo -p '[mooring]%% become password: ' -i -u root\n"
        );
        assert_eq!(command(&become_(BecomeMethod::Doas, "app", None)), "doas -u app -s\n");
    }

    #[test]
    fn printed_prompt_never_appears_in_the_typed_command() {
        let cmd = command(&become_(BecomeMethod::Sudo, "root", None));
        assert!(!cmd.contains(SUDO_PROMPT), "{cmd}");
        assert_eq!(SUDO_PROMPT_ARG.replace("%%", "%").trim_end(), SUDO_PROMPT);
    }

    #[test]
    fn password_is_sent_once_on_the_prompt() {
        let mut w = Watcher::new(become_(BecomeMethod::Sudo, "root", Some("test-become-pw")));
        assert_eq!(w.feed(b"sudo -p '[mooring]%% become password: ' -i -u root\r\n"), Action::None);
        let line = sent(w.feed(b"[mooring]% become password: ")).expect("prompt");
        assert_eq!(line.as_slice(), b"test-become-pw\n");
        assert!(sent(w.feed(b"\r\nroot# ")).is_none(), "only once");
        assert!(!format!("{w:?}").contains("test-become-pw"));
    }

    #[test]
    fn echo_split_at_every_offset_never_triggers() {
        // The echo of the typed command (with the older prompt form too), cut at every byte, plus
        // a readline redraw without a newline: nothing is sent before the echo has ended.
        let typed = command(&become_(BecomeMethod::Sudo, "root", None));
        let legacy = "sudo -p '[mooring] become password: ' -i -u root";
        for echo in [typed.trim_end().to_owned(), legacy.to_owned()] {
            let echo = format!("{echo}\r\n");
            for cut in 0..echo.len() {
                let mut w = Watcher::new(become_(BecomeMethod::Sudo, "root", Some("pw")));
                assert_eq!(w.feed(&echo.as_bytes()[..cut]), Action::None, "cut {cut}");
                assert_eq!(w.feed(&echo.as_bytes()[cut..]), Action::None, "cut {cut}");
                assert!(sent(w.feed(SUDO_PROMPT.as_bytes())).is_some(), "real prompt after echo");
            }
        }
        // su/doas: an echoed line that ends in "password:" before the newline is not a prompt
        let mut w = Watcher::new(become_(BecomeMethod::Su, "root", Some("pw")));
        assert_eq!(w.feed(b"echo password:"), Action::None);
        assert!(sent(w.feed(b"\r\nPassword: ")).is_some());
    }

    #[test]
    fn failure_interrupts_once_and_never_resends() {
        for failure in [
            "\r\nSorry, try again.\r\n[mooring]% become password: ",
            "\r\nsudo: 3 incorrect password attempts\r\n$ ",
            "\r\nalice is not in the sudoers file.\r\n$ ",
            "\r\nsu: Authentication failure\r\n$ ",
            "\r\n[mooring]% become password: ",
        ] {
            let mut w = Watcher::new(become_(BecomeMethod::Sudo, "root", Some("pw")));
            w.feed(b"sudo ...\r\n");
            assert!(sent(w.feed(SUDO_PROMPT.as_bytes())).is_some());
            // split the failure output in two to cover a pty read boundary
            let (a, b) = failure.as_bytes().split_at(failure.len() / 2);
            let first = w.feed(a);
            let second = if first == Action::None { w.feed(b) } else { Action::None };
            assert!(first == Action::Failed || second == Action::Failed, "{failure:?}");
            assert!(!w.active());
            assert_eq!(w.feed(SUDO_PROMPT.as_bytes()), Action::None, "no second password");
        }
        // not in sudoers before any prompt: interrupt too
        let mut w = Watcher::new(become_(BecomeMethod::Doas, "root", Some("pw")));
        w.feed(b"doas -u root -s\r\n");
        assert_eq!(w.feed(b"doas: Authentication failure\r\n"), Action::Failed);
    }

    #[test]
    fn success_and_user_input_end_the_watch_quietly() {
        let mut w = Watcher::new(become_(BecomeMethod::Sudo, "root", Some("pw")));
        w.feed(b"sudo ...\r\n");
        assert!(sent(w.feed(SUDO_PROMPT.as_bytes())).is_some());
        assert_eq!(w.feed(b"\r\nroot# "), Action::None);
        w.user_input();
        assert!(!w.active(), "the user typing ends the failure watch");
        assert_eq!(w.feed(b"passwd\r\nNew password: "), Action::None);
    }

    #[test]
    fn su_prompt_heuristic_and_give_up() {
        let mut w = Watcher::new(become_(BecomeMethod::Su, "root", Some("pw")));
        assert_eq!(w.feed(b"su - root\r\n"), Action::None);
        assert!(sent(w.feed(b"Password: ")).is_some());
        let mut w = Watcher::new(become_(BecomeMethod::Su, "root", Some("pw")));
        assert_eq!(w.feed(b"\r\n"), Action::None);
        assert_eq!(w.feed(&vec![b'x'; WATCH_LIMIT + 1]), Action::None);
        assert_eq!(w.feed(b"\nPassword: "), Action::None, "disarmed after the watch limit");
        let mut none = Watcher::new(become_(BecomeMethod::Sudo, "root", None));
        none.feed(b"sudo\r\n");
        assert_eq!(none.feed(SUDO_PROMPT.as_bytes()), Action::None, "no password, nothing sent");
    }
}
