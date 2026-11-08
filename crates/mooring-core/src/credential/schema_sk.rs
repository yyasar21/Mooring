//! Kind row of `ssh_sk_key` (ADR-0024 §1): SSH sign-in only. The key-handle file is stored
//! under the `private_key` secret name (it is the OpenSSH private key file of an `sk-*` key),
//! so an `ssh_key` row converted to this kind keeps its sealed values unchanged.

use super::{ml, opts, ph, plain, sec, v, FieldFormat, KindSchema, K, KIB, SSH_ONLY, USERNAME};

/// `ssh_sk_key`.
pub(super) const SSH_SK_KEY: KindSchema = KindSchema {
    kind: K::SshSkKey,
    label: "SSH security key (FIDO2)",
    group: "SSH",
    protocols: SSH_ONLY,
    consumers: &[],
    supports_otp: false,
    fields: &[
        USERNAME,
        ml(ph(
            plain("public_key", "Public key", true, v(16 * KIB, FieldFormat::Text)),
            "sk-ssh-ed25519@openssh.com AAAA… (from id_ed25519_sk.pub)",
        )),
        opts(plain("backend", "Signing", false, v(8, FieldFormat::Enum)), &["agent", "helper"]),
        opts(plain("resident", "Resident key", false, v(5, FieldFormat::Enum)), &["false", "true"]),
        ml(ph(
            sec(
                plain("private_key", "Key handle file", false, v(64 * KIB, FieldFormat::Pem)),
                false,
            ),
            "-----BEGIN OPENSSH PRIVATE KEY----- (id_ed25519_sk, optional)",
        )),
        ph(
            sec(
                plain("passphrase", "Key handle passphrase", false, v(4 * KIB, FieldFormat::Text)),
                false,
            ),
            "optional",
        ),
        ml(ph(
            plain("certificate", "OpenSSH certificate", false, v(64 * KIB, FieldFormat::Text)),
            "sk-ssh-ed25519-cert-v01@openssh.com AAAA… (optional)",
        )),
    ],
};

/// `smart_card` (ADR-0027 §2): SSH through the ssh-agent holding the card's key. No secret
/// field: the PIN is asked at every use (`purpose: smart_card_pin`) and never stored. RDP
/// smart-card logon needs Kerberos PKINIT (matrix footnote).
pub(super) const SMART_CARD: KindSchema = KindSchema {
    kind: K::SmartCard,
    label: "Smart card / PIV",
    group: "Smart card",
    protocols: SSH_ONLY,
    consumers: &[],
    supports_otp: false,
    fields: &[
        ph(plain("username", "Username", false, v(256, FieldFormat::Text)), "alice (hint)"),
        ph(plain("domain", "Domain", false, v(253, FieldFormat::Text)), "optional"),
        ph(
            plain("reader_hint", "Reader", false, v(128, FieldFormat::Text)),
            "Yubico YubiKey (optional)",
        ),
        ml(ph(
            plain("public_key", "Public key", false, v(16 * KIB, FieldFormat::Text)),
            "ecdsa-sha2-nistp256 AAAA… (from ssh-keygen -D <module>)",
        )),
        opts(
            plain("pkcs11_module", "PKCS#11 module", false, v(16, FieldFormat::Enum)),
            &["opensc", "ykcs11", "cryptoapi"],
        ),
    ],
};
