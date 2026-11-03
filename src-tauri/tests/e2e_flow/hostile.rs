//! IPC hostile-input tests (ADR-0003: the WebView is untrusted). Every command plain function
//! gets oversized strings, control and bidi characters, bad UUIDs, out-of-range numbers and
//! base64 garbage. Each call must return `Ok` or an `IpcError` with a known code, never panic,
//! never echo the hostile value in `message`, and never poison shared state.
//!
//! The random part is a seeded xorshift generator (no new dev-dependency): failures print the
//! seed and the input, so they replay exactly.

use std::panic::AssertUnwindSafe;

use mooring_core::session::Size;
use secrecy::SecretString;

use crate::commands::credential_copy;
use crate::commands::credentials::{self, NewCredential, WireSecrets};
use crate::commands::sessions::{self as sess, WireInput};
use crate::commands::tree::{self, ConnectionFields};
use crate::commands::{audit, vault};
use crate::error::IpcResult;
use crate::state::testing;
use crate::state::AppState;
use crate::support::{b64, sink};

/// Codes ADR-0008 lists plus the extra ones the Tauri handoff documents.
pub const KNOWN_CODES: &[&str] = &[
    "vault.locked",
    "vault.unlock",
    "vault.weak_password",
    "vault.missing",
    "vault.exists",
    "vault.password_too_long",
    "tree.root",
    "tree.cycle",
    "tree.not_found",
    "tree.invalid",
    "input.invalid",
    "credential.not_found",
    "credential.incompatible",
    "credential.kind_unsupported",
    "credential.secret_missing",
    "credential.kubeconfig_rejected",
    "store.corrupt",
    "session.not_found",
    "session.failed",
    "store.io",
    "ipc.unknown",
];

/// Embedded in every hostile string so an echoed value is easy to spot.
pub const MARK: &str = "ZQXMARKQZ";

/// Hand-picked hostile strings. Each contains `MARK` except the empty/blank ones.
fn corpus() -> Vec<String> {
    let mut v = vec![
        String::new(),
        " ".into(),
        "\t\n\r".into(),
        MARK.into(),
        format!("{MARK}\0nul"),
        format!("\x1b[31m{MARK}\x1b[0m"),
        format!("{MARK}\u{202e}gpj.exe"),
        format!("{MARK}\u{200b}\u{feff}"),
        format!("../../../../etc/passwd{MARK}"),
        format!("'; DROP TABLE connection; --{MARK}"),
        format!("\" OR 1=1 NEAR(a b) * ^ -x col:{MARK}"),
        format!("{MARK}%s%n%x"),
        format!("{{{{{MARK}}}}}<script>alert(1)</script>"),
        format!("-oProxyCommand=sh{MARK}"),
        format!("00000000-0000-0000-0000-00000000000{MARK}"),
        "00000000-0000-0000-0000-000000000000".into(),
        format!(" 6f9619ff-8b86-d011-b42d-00cf4fc964ff{MARK}"),
        format!("{MARK}{}", "🦀".repeat(130)),
        format!("{MARK}{}", "a".repeat(121)),
        format!("{MARK}{}", "b".repeat(2049)),
        format!("{MARK}{}", "c".repeat(64 * 1024 + 1)),
        format!("{MARK}{}", "d".repeat(1024 * 1024)),
    ];
    v.push(format!("{MARK}{}", "\u{0301}".repeat(500)));
    v
}

/// Seeded xorshift64*: deterministic random strings over a hostile alphabet.
pub struct Rng(pub u64);

impl Rng {
    pub fn next(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_f491_4f6c_dd1d)
    }

    pub fn below(&mut self, n: u64) -> u64 {
        self.next() % n
    }

    fn string(&mut self) -> String {
        const ALPHABET: &[char] = &[
            'a',
            'Z',
            '0',
            '9',
            '-',
            '_',
            '.',
            '/',
            '\\',
            ':',
            '"',
            '\'',
            '*',
            '^',
            '(',
            ')',
            ' ',
            '\t',
            '\n',
            '\0',
            '\x1b',
            '\x7f',
            '\u{85}',
            '\u{202e}',
            '\u{200b}',
            '\u{feff}',
            'ç',
            'İ',
            '🦀',
            '\u{10ffff}',
            '%',
            '{',
            '}',
            '<',
            '>',
            '|',
            '=',
        ];
        let len = match self.below(10) {
            0 => 0,
            1 => 200 + self.below(5000),
            _ => self.below(40),
        };
        let mut s: String = (0..len)
            .map(|_| ALPHABET[usize::try_from(self.below(ALPHABET.len() as u64)).unwrap_or(0)])
            .collect();
        s.push_str(MARK);
        s
    }
}

#[track_caller]
pub fn check<T>(what: &str, input: &str, r: &IpcResult<T>) {
    if let Err(e) = r {
        assert!(
            KNOWN_CODES.contains(&e.code),
            "{what}: unknown code {} for input {:?}",
            e.code,
            preview(input)
        );
        assert!(
            !e.message.contains(MARK),
            "{what}: message echoes the input: {:?}",
            preview(&e.message)
        );
        assert!(e.message.len() <= 256, "{what}: message is {} bytes", e.message.len());
    }
}

pub fn preview(s: &str) -> String {
    s.chars().take(80).collect()
}

/// Run one synchronous command, failing the test on a panic; checks the error contract.
fn catch<T>(what: &str, input: &str, f: impl FnOnce() -> IpcResult<T>) {
    let r = std::panic::catch_unwind(AssertUnwindSafe(f))
        .unwrap_or_else(|_| panic!("{what} panicked on {:?}", preview(input)));
    check(what, input, &r);
}

pub struct Ids {
    pub root: String,
    pub folder: String,
    pub cred: String,
    pub conn: String,
}

pub fn seed(st: &AppState) -> Ids {
    let root = tree::list(st).expect("tree").folders[0].id.clone();
    let folder = tree::create_folder(st, &root, "seed").expect("folder").id;
    let cred = credentials::create(st, NewCredential::password_for_tests("seed")).expect("c").id;
    let conn = tree::create_connection(st, fields(&folder, "seed", "ssh", "seed.example", None))
        .expect("conn")
        .id;
    Ids { root, folder, cred, conn }
}

pub fn fields(
    folder: &str,
    name: &str,
    protocol: &str,
    host: &str,
    port: Option<u32>,
) -> ConnectionFields {
    ConnectionFields { port, ..ConnectionFields::basic(folder, name, protocol, host) }
}

/// Every string-taking command with `s` in each string position.
fn hit_all_string_args(st: &AppState, ids: &Ids, s: &str) {
    catch("folder_create.parentId", s, || tree::create_folder(st, s, "x"));
    catch("folder_create.name", s, || tree::create_folder(st, &ids.folder, s));
    catch("folder_rename.id", s, || tree::rename_folder(st, s, "x"));
    catch("folder_rename.name", s, || tree::rename_folder(st, &ids.folder, s));
    catch("folder_move.id", s, || tree::move_folder(st, s, &ids.root));
    catch("folder_move.parentId", s, || tree::move_folder(st, &ids.folder, s));
    catch("folder_set_default_credential.id", s, || tree::set_default_credential(st, s, None));
    catch("folder_set_default_credential.credentialId", s, || {
        tree::set_default_credential(st, &ids.folder, Some(s))
    });
    catch("folder_delete.id", s, || tree::delete_folder(st, s));
    for (pos, f) in [
        ("folderId", fields(s, "n", "ssh", "h", None)),
        ("name", fields(&ids.folder, s, "ssh", "h", None)),
        ("protocol", fields(&ids.folder, "n", s, "h", None)),
        ("host", fields(&ids.folder, "n", "ssh", s, None)),
        (
            "credentialId",
            ConnectionFields {
                credential_id: Some(s.into()),
                ..fields(&ids.folder, "n", "ssh", "h", None)
            },
        ),
        (
            "tags",
            ConnectionFields { tags: vec![s.into()], ..fields(&ids.folder, "n", "ssh", "h", None) },
        ),
        (
            "usernameOverride",
            ConnectionFields {
                credential_id: Some(ids.cred.clone()),
                username_override: Some(s.into()),
                ..fields(&ids.folder, "n", "ssh", "h", None)
            },
        ),
        (
            "domainOverride",
            ConnectionFields {
                credential_id: Some(ids.cred.clone()),
                domain_override: Some(s.into()),
                ..fields(&ids.folder, "n", "ssh", "h", None)
            },
        ),
        (
            "gatewayCredentialId",
            ConnectionFields {
                gateway_credential_id: Some(s.into()),
                ..fields(&ids.folder, "n", "rdp", "h", None)
            },
        ),
        (
            "becomeCredentialId",
            ConnectionFields {
                become_credential_id: Some(s.into()),
                ..fields(&ids.folder, "n", "ssh", "h", None)
            },
        ),
    ] {
        catch(&format!("connection_create.{pos}"), s, || tree::create_connection(st, f.clone()));
        catch(&format!("connection_update.{pos}"), s, || tree::update_connection(st, &ids.conn, f));
    }
    catch("connection_update.id", s, || {
        tree::update_connection(st, s, fields(&ids.folder, "n", "ssh", "h", None))
    });
    catch("connection_move.id", s, || tree::move_connection(st, s, &ids.folder));
    catch("connection_move.folderId", s, || tree::move_connection(st, &ids.conn, s));
    catch("connection_delete.id", s, || tree::delete_connection(st, s));
    catch("connection_search.query", s, || tree::search(st, s, 10));
    hit_credential_args(st, ids, s);
    catch("vault_lock.reason", s, || vault::lock(st, Some(s)));
    catch("vault_unlock.password", s, || {
        vault::password_from_ipc(s.to_owned()).and_then(|p| vault::unlock(st, p))
    });
    catch("vault_change_password.next", s, || {
        vault::password_from_ipc(s.to_owned()).and_then(|p| {
            vault::change_password(st, SecretString::from("not the master".to_owned()), p)
        })
    });
    // Keep the vault unlocked for the next position (vault_lock above locked it).
    vault::unlock(st, SecretString::from(testing::MASTER.to_owned())).expect("re-unlock");
}

/// The ADR-0009 credential commands with `s` in each string position.
fn hit_credential_args(st: &AppState, ids: &Ids, s: &str) {
    let pw = NewCredential::password_for_tests;
    let field = |k: &str| serde_json::json!({ "username": "u", k: s });
    for (pos, c) in [
        ("name", NewCredential { name: s.into(), ..pw("x") }),
        ("kind", NewCredential { kind: s.into(), ..pw("x") }),
        (
            "fields.username",
            NewCredential { fields: serde_json::json!({"username": s}), ..pw("x") },
        ),
        ("fields.domain", NewCredential { fields: field("domain"), ..pw("x") }),
        ("fields.<key>", NewCredential { fields: serde_json::json!({ s: "x" }), ..pw("x") }),
        (
            "secrets.password",
            NewCredential { secrets: WireSecrets::of(&[("password", s)]), ..pw("x") },
        ),
        (
            "secrets.otp_seed",
            NewCredential {
                secrets: WireSecrets::of(&[("password", "p"), ("otp_seed", s)]),
                ..pw("x")
            },
        ),
        ("secrets.<name>", NewCredential { secrets: WireSecrets::of(&[(s, "p")]), ..pw("x") }),
        (
            "kubeconfig_yaml",
            NewCredential {
                kind: "kubeconfig".into(),
                fields: serde_json::json!({}),
                secrets: WireSecrets::of(&[("kubeconfig_yaml", s)]),
                ..pw("x")
            },
        ),
    ] {
        catch(&format!("credential_create.{pos}"), s, || credentials::create(st, c));
    }
    catch("credential_update_fields.id", s, || {
        credentials::update_fields(st, s, "x", &field("domain"))
    });
    catch("credential_update_fields.name", s, || {
        credentials::update_fields(st, &ids.cred, s, &serde_json::json!({"username": "u"}))
    });
    catch("credential_update_fields.fields", s, || {
        credentials::update_fields(st, &ids.cred, "x", &field("domain"))
    });
    catch("credential_replace_secrets.id", s, || {
        credentials::replace_secrets(st, s, &WireSecrets::of(&[("password", "x")]), &[])
    });
    catch("credential_replace_secrets.set", s, || {
        credentials::replace_secrets(st, &ids.cred, &WireSecrets::of(&[("password", s)]), &[])
    });
    catch("credential_replace_secrets.clear", s, || {
        credentials::replace_secrets(st, &ids.cred, &WireSecrets::default(), &[s.to_owned()])
    });
    catch("credential_delete.id", s, || credentials::delete(st, s));
    catch("credential_copy_secret.id", s, || credential_copy::copy_secret(st, s, "password"));
    catch("credential_copy_secret.name", s, || credential_copy::copy_secret(st, &ids.cred, s));
    catch("credential_copy_otp.id", s, || credential_copy::copy_otp(st, s));
    catch("credential_parse_account.input", s, || credentials::parse_account_input(s));
    catch("connection_set_role_credential.id", s, || {
        tree::set_role_credential(st, s, "become", None)
    });
    catch("connection_set_role_credential.role", s, || {
        tree::set_role_credential(st, &ids.conn, s, None)
    });
    catch("connection_set_role_credential.credentialId", s, || {
        tree::set_role_credential(st, &ids.conn, "become", Some(s))
    });
}

async fn hit_session_ids(st: &AppState, s: &str) {
    let owned = s.to_owned();
    let r = sess::send(st, &owned, WireInput::Bytes { data: b64(b"x") }).await;
    check("session_send.sessionId", s, &r);
    assert!(r.is_err(), "unknown session accepted");
    let r = sess::close(st, &owned).await;
    check("session_close.sessionId", s, &r);
    let (sk, _rx) = sink();
    let r = sess::open(st, &owned, Size { width: 80, height: 24 }, sk).await;
    check("session_open.connectionId", s, &r);
    assert!(r.is_err());
    check("window_detach", s, &sess::window_detach(owned));
}

pub fn assert_state_healthy(st: &AppState) {
    assert!(st.vault.lock().is_ok(), "vault mutex poisoned");
    assert!(st.store.lock().is_ok(), "store mutex poisoned");
    assert!(st.audit.lock().is_ok(), "audit mutex poisoned");
    assert!(st.sessions.lock().is_ok(), "sessions mutex poisoned");
    tree::list(st).expect("tree_list still works");
    let v = audit::verify(st).expect("verify");
    assert!(v.ok, "audit chain broken by hostile input: {v:?}");
}

#[tokio::test]
async fn corpus_against_every_command() {
    let f = testing::unlocked();
    let st = &f.state;
    let ids = seed(st);
    for s in corpus() {
        hit_all_string_args(st, &ids, &s);
        hit_session_ids(st, &s).await;
    }
    assert_state_healthy(st);
    // Nothing hostile was stored as a name: every stored name passed validate_name.
    let t = tree::list(st).expect("tree");
    for n in t.folders.iter().map(|x| &x.name).chain(t.connections.iter().map(|c| &c.name)) {
        assert!(!n.chars().any(char::is_control), "control character stored in {n:?}");
        assert!(n.chars().count() <= 120);
    }
}

#[tokio::test]
async fn random_strings_against_every_command() {
    let f = testing::unlocked();
    let st = &f.state;
    let ids = seed(st);
    let base: u64 = std::env::var("MOORING_HOSTILE_SEED")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(0x05ee_da1c_0de5);
    let rounds: u64 =
        std::env::var("MOORING_HOSTILE_ROUNDS").ok().and_then(|s| s.parse().ok()).unwrap_or(60);
    let mut rng = Rng(base | 1);
    for _ in 0..rounds {
        let s = rng.string();
        hit_all_string_args(st, &ids, &s);
        hit_session_ids(st, &s).await;
    }
    assert_state_healthy(st);
}
