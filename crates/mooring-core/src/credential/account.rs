//! Windows account forms: down-level `DOMAIN\user` and UPN `user@suffix` (ADR-0009 §1).

use serde::{Deserialize, Serialize};

use super::text::is_forbidden;
use super::CredentialError;

/// Longest user part (bytes).
pub const MAX_USER: usize = 256;
/// Longest DNS domain (bytes).
pub const MAX_DNS: usize = 253;
/// Longest `NetBIOS` domain (characters).
pub const MAX_NETBIOS: usize = 15;
/// Characters a `NetBIOS` domain may not contain.
const NETBIOS_FORBIDDEN: &[char] = &['\\', '/', ':', '*', '?', '"', '<', '>', '|'];

/// Which form an account was written in.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AccountForm {
    /// `DOMAIN\user`.
    Netbios,
    /// `user@domain`.
    Upn,
}

/// A split account.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Account {
    /// Form it was written in.
    pub form: AccountForm,
    /// User part.
    pub user: String,
    /// Domain part (`NetBIOS` name or DNS suffix).
    pub domain: String,
}

impl Account {
    /// The inverse of [`parse_account`].
    #[must_use]
    pub fn render(&self) -> String {
        match self.form {
            AccountForm::Netbios => format!("{}\\{}", self.domain, self.user),
            AccountForm::Upn => format!("{}@{}", self.user, self.domain),
        }
    }

    /// What `CredSSP` / NTLM get: `(user, domain)` for `NetBIOS`, `(upn, "")` for UPN.
    #[must_use]
    pub fn for_credssp(&self) -> (String, String) {
        match self.form {
            AccountForm::Netbios => (self.user.clone(), self.domain.clone()),
            AccountForm::Upn => (self.render(), String::new()),
        }
    }

    /// Validate an already split account (used when the UI sends `user`/`domain`/`form`).
    pub fn validate(form: AccountForm, user: &str, domain: &str) -> Result<Self, CredentialError> {
        let user = check_user(user.trim())?;
        let domain = domain.trim();
        match form {
            AccountForm::Netbios => check_netbios(domain)?,
            AccountForm::Upn => check_dns(domain)?,
        }
        Ok(Self { form, user, domain: domain.to_owned() })
    }
}

fn bad(reason: &str) -> CredentialError {
    CredentialError::invalid("account", reason)
}

fn check_user(user: &str) -> Result<String, CredentialError> {
    if user.is_empty() {
        return Err(bad("the user part is empty"));
    }
    if user.len() > MAX_USER {
        return Err(bad("the user name is longer than 256 bytes"));
    }
    if user.contains('\\') {
        return Err(bad("use one backslash between domain and user"));
    }
    Ok(user.to_owned())
}

fn check_netbios(domain: &str) -> Result<(), CredentialError> {
    if domain.is_empty() {
        return Err(bad("the domain before \\ is empty"));
    }
    if domain.chars().count() > MAX_NETBIOS {
        return Err(bad("a NetBIOS domain has at most 15 characters"));
    }
    if domain.contains(NETBIOS_FORBIDDEN) || domain.chars().any(char::is_whitespace) {
        return Err(bad("a NetBIOS domain cannot contain \\ / : * ? \" < > | or spaces"));
    }
    Ok(())
}

/// DNS name: 1..=253 bytes, labels 1..=63 of `[A-Za-z0-9-]`, no leading/trailing hyphen.
pub(crate) fn check_dns(domain: &str) -> Result<(), CredentialError> {
    let ok = !domain.is_empty()
        && domain.len() <= MAX_DNS
        && domain.split('.').all(|l| {
            !l.is_empty()
                && l.len() <= 63
                && !l.starts_with('-')
                && !l.ends_with('-')
                && l.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
        });
    if ok {
        Ok(())
    } else {
        Err(bad("the domain must be a DNS name such as corp.example"))
    }
}

/// Split `DOMAIN\user` or `user@domain`. Never guesses: input without a separator is an error.
/// The error never echoes the input.
pub fn parse_account(input: &str) -> Result<Account, CredentialError> {
    let s = input.trim();
    if s.is_empty() {
        return Err(bad("enter DOMAIN\\user or user@domain"));
    }
    if s.len() > MAX_USER + MAX_DNS + 1 {
        return Err(bad("the account is too long"));
    }
    if s.chars().any(is_forbidden) {
        return Err(bad("the account contains a control or invisible character"));
    }
    if let Some((domain, user)) = s.split_once('\\') {
        check_netbios(domain)?;
        let user = check_user(user)?;
        return Ok(Account { form: AccountForm::Netbios, user, domain: domain.to_owned() });
    }
    if let Some((user, domain)) = s.rsplit_once('@') {
        let user = check_user(user)?;
        check_dns(domain)?;
        return Ok(Account { form: AccountForm::Upn, user, domain: domain.to_owned() });
    }
    Err(bad("add a domain: DOMAIN\\user or user@domain"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid_vectors_and_inverse() {
        for (input, form, user, domain) in [
            ("CORP\\alice", AccountForm::Netbios, "alice", "CORP"),
            ("  CORP\\alice  ", AccountForm::Netbios, "alice", "CORP"),
            ("ABCDEFGHIJKLMNO\\bob", AccountForm::Netbios, "bob", "ABCDEFGHIJKLMNO"),
            ("alice@corp.example", AccountForm::Upn, "alice", "corp.example"),
            ("first.last@sub.corp.example", AccountForm::Upn, "first.last", "sub.corp.example"),
            ("a@b@corp.example", AccountForm::Upn, "a@b", "corp.example"),
            ("administrator@vsphere.local", AccountForm::Upn, "administrator", "vsphere.local"),
        ] {
            let a = parse_account(input).expect(input);
            assert_eq!((a.form, a.user.as_str(), a.domain.as_str()), (form, user, domain));
            assert_eq!(parse_account(&a.render()).expect("inverse"), a);
        }
    }

    #[test]
    fn invalid_vectors() {
        for input in [
            "",
            "   ",
            "alice",
            "\\alice",
            "CORP\\",
            "ABCDEFGHIJKLMNOP\\bob", // 16-char NetBIOS
            "CO:RP\\alice",
            "CO RP\\alice",
            "CORP\\al\\ice",
            "@corp.example",
            "alice@",
            "alice@corp..example",
            "alice@-corp.example",
            "alice@corp_example",
            "ali\u{202e}ce@corp.example",
            "CORP\\a\u{0}b",
        ] {
            let e = parse_account(input).expect_err(input);
            if input.len() > 3 {
                assert!(!e.to_string().contains(input.trim()), "no echo of {input:?}");
            }
        }
        assert!(parse_account(&format!("CORP\\{}", "u".repeat(257))).is_err());
        assert!(parse_account(&format!("u@{}.example", "d".repeat(250))).is_err());
    }

    #[test]
    fn credssp_shape() {
        let n = parse_account("CORP\\alice").expect("netbios");
        assert_eq!(n.for_credssp(), ("alice".to_owned(), "CORP".to_owned()));
        let u = parse_account("alice@corp.example").expect("upn");
        assert_eq!(u.for_credssp(), ("alice@corp.example".to_owned(), String::new()));
    }

    #[test]
    fn split_validation() {
        assert!(Account::validate(AccountForm::Netbios, "alice", "CORP").is_ok());
        assert!(Account::validate(AccountForm::Netbios, "alice", "corp.example.test").is_err());
        assert!(Account::validate(AccountForm::Upn, "alice", "corp.example").is_ok());
        assert!(Account::validate(AccountForm::Upn, "", "corp.example").is_err());
    }
}
