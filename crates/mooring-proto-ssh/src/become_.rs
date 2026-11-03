//! Privilege escalation after login (`sudo_become`, ADR-0009 §3).
//!
//! Once the shell is open the driver types one fixed command (`sudo`, `su` or `doas` to the
//! target user). The become password is written to the channel only when the remote password
//! prompt is detected in the first output after that command, and at most once; it is never
//! echoed into the UI stream by us (the remote tty has echo off while it reads a password).
//! For `sudo` the prompt is fixed with `-p`, so detection is exact; `su` / `doas` prompts are
//! matched on `password` + `:` at the end of the output.

use mooring_core::credential::BecomeMethod;
use mooring_core::session::Become;
use mooring_core::MooringError;
use secrecy::{ExposeSecret, SecretString};
use zeroize::Zeroizing;

/// The prompt `sudo -p` prints; matched exactly.
pub(crate) const SUDO_PROMPT: &str = "[mooring] become password: ";
/// Output inspected for a prompt before the password is dropped unused.
const WATCH_LIMIT: usize = 4096;
/// Longest target user name.
const MAX_USER: usize = 64;

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
        BecomeMethod::Sudo => format!("sudo -p '{SUDO_PROMPT}' -i -u {}\n", b.user),
        BecomeMethod::Su => format!("su - {}\n", b.user),
        BecomeMethod::Doas => format!("doas -u {} -s\n", b.user),
    }
}

/// Watches shell output for the become password prompt.
pub(crate) struct Watcher {
    method: BecomeMethod,
    password: Option<SecretString>,
    tail: Vec<u8>,
    seen: usize,
}

impl std::fmt::Debug for Watcher {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Watcher")
            .field("method", &self.method)
            .field("armed", &self.password.is_some())
            .finish_non_exhaustive()
    }
}

impl Watcher {
    pub(crate) fn new(b: Become) -> Self {
        Self { method: b.method, password: b.password, tail: Vec::new(), seen: 0 }
    }

    /// Feed remote output; returns the password line to send when the prompt appears.
    pub(crate) fn feed(&mut self, data: &[u8]) -> Option<Zeroizing<Vec<u8>>> {
        self.password.as_ref()?;
        self.seen = self.seen.saturating_add(data.len());
        self.tail.extend_from_slice(data);
        if self.tail.len() > 256 {
            self.tail.drain(..self.tail.len() - 256);
        }
        if self.is_prompt() {
            let pw = self.password.take()?;
            let mut line = Zeroizing::new(pw.expose_secret().as_bytes().to_vec());
            line.push(b'\n');
            return Some(line);
        }
        if self.seen > WATCH_LIMIT {
            tracing::debug!("no become password prompt seen; password dropped unused");
            self.password = None;
        }
        None
    }

    fn is_prompt(&self) -> bool {
        let text = String::from_utf8_lossy(&self.tail);
        let end = text.trim_end_matches([' ', '\t']);
        match self.method {
            BecomeMethod::Sudo => end.ends_with(SUDO_PROMPT.trim_end()),
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
            "sudo -p '[mooring] become password: ' -i -u root\n"
        );
        assert_eq!(command(&become_(BecomeMethod::Doas, "app", None)), "doas -u app -s\n");
    }

    #[test]
    fn password_is_sent_once_on_the_prompt() {
        let mut w = Watcher::new(become_(BecomeMethod::Sudo, "root", Some("test-become-pw")));
        assert!(w.feed(b"sudo -p ... -i -u root\r\n").is_none());
        let line = w.feed(SUDO_PROMPT.as_bytes()).expect("prompt");
        assert_eq!(line.as_slice(), b"test-become-pw\n");
        assert!(w.feed(SUDO_PROMPT.as_bytes()).is_none(), "only once");
        assert!(!format!("{w:?}").contains("test-become-pw"));
    }

    #[test]
    fn su_prompt_heuristic_and_give_up() {
        let mut w = Watcher::new(become_(BecomeMethod::Su, "root", Some("pw")));
        assert!(w.feed(b"Password: ").is_some());
        let mut w = Watcher::new(become_(BecomeMethod::Su, "root", Some("pw")));
        assert!(w.feed(&vec![b'x'; WATCH_LIMIT + 1]).is_none());
        assert!(w.feed(b"\nPassword: ").is_none(), "disarmed after the watch limit");
        let mut none = Watcher::new(become_(BecomeMethod::Sudo, "root", None));
        assert!(none.feed(SUDO_PROMPT.as_bytes()).is_none(), "no password, nothing sent");
    }
}
