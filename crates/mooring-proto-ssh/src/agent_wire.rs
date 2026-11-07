//! Bounded parsers for the ssh-agent replies the FIDO2 path reads itself (ADR-0024 §2,
//! draft-miller-ssh-agent §3.4/§3.6) and for `sk-*` signature blobs. Every reply is hostile:
//! counts and lengths are capped before allocation, trailing bytes are refused, nothing
//! panics. Fuzz entry: [`fuzz_agent_identities`].

use mooring_core::credential::sk_key::{Reader, SkAlgorithm, SK_FLAG_USER_PRESENCE};

/// `SSH_AGENT_FAILURE`.
pub(crate) const FAILURE: u8 = 5;
/// `SSH_AGENTC_REQUEST_IDENTITIES`.
pub(crate) const REQUEST_IDENTITIES: u8 = 11;
/// `SSH_AGENT_IDENTITIES_ANSWER`.
pub(crate) const IDENTITIES_ANSWER: u8 = 12;
/// `SSH_AGENTC_SIGN_REQUEST`.
pub(crate) const SIGN_REQUEST: u8 = 13;
/// `SSH_AGENT_SIGN_RESPONSE`.
pub(crate) const SIGN_RESPONSE: u8 = 14;
/// Largest agent message we read (bytes).
pub(crate) const MAX_AGENT_MESSAGE: usize = 256 * 1024;
/// Identities read from one answer; the rest are ignored.
pub(crate) const MAX_IDENTITIES: usize = 64;
const MAX_BLOB: usize = 16 * 1024;
const MAX_COMMENT: usize = 1024;
const MAX_SIGNATURE: usize = 1024;

/// Why an agent reply was refused. Never carries agent bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum WireError {
    /// Malformed, truncated, oversized or with trailing bytes.
    Malformed,
    /// `SSH_AGENT_FAILURE`.
    Failure,
    /// The signature is not an `sk-*` signature of the expected type.
    WrongType,
    /// The authenticator did not report user presence (UP flag unset).
    NoPresence,
}

/// One listed identity: the key (or certificate) blob, as the agent sent it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Identity {
    pub(crate) blob: Vec<u8>,
}

fn reader(buf: &[u8]) -> Reader<'_> {
    Reader::new(buf, "agent reply")
}

/// `SSH_AGENT_IDENTITIES_ANSWER` body (type byte included).
pub(crate) fn parse_identities(msg: &[u8]) -> Result<Vec<Identity>, WireError> {
    let mut r = reader(msg);
    match r.u8().map_err(|_| WireError::Malformed)? {
        IDENTITIES_ANSWER => {}
        FAILURE => return Err(WireError::Failure),
        _ => return Err(WireError::Malformed),
    }
    let n = r.u32().map_err(|_| WireError::Malformed)?;
    let mut out = Vec::new();
    for _ in 0..n {
        let blob = r.string(MAX_BLOB).map_err(|_| WireError::Malformed)?;
        let _comment = r.string(MAX_COMMENT).map_err(|_| WireError::Malformed)?;
        if out.len() < MAX_IDENTITIES {
            out.push(Identity { blob: blob.to_vec() });
        }
    }
    r.finish().map_err(|_| WireError::Malformed)?;
    Ok(out)
}

/// `SSH_AGENT_SIGN_RESPONSE` body (type byte included) → the signature blob.
pub(crate) fn parse_sign_response(msg: &[u8]) -> Result<Vec<u8>, WireError> {
    let mut r = reader(msg);
    match r.u8().map_err(|_| WireError::Malformed)? {
        SIGN_RESPONSE => {}
        FAILURE => return Err(WireError::Failure),
        _ => return Err(WireError::Malformed),
    }
    let sig = r.string(MAX_SIGNATURE).map_err(|_| WireError::Malformed)?.to_vec();
    r.finish().map_err(|_| WireError::Malformed)?;
    Ok(sig)
}

/// Facts of a checked `sk-*` signature.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct SkSignature {
    pub(crate) flags: u8,
    pub(crate) counter: u32,
}

/// Check an `sk-*` signature blob: `string alg, string sig, byte flags, uint32 counter`, the
/// algorithm of `expected` and the user-presence flag set (a signature without a touch is
/// refused before it is sent, whatever the server would accept).
pub(crate) fn check_sk_signature(
    sig: &[u8],
    expected: SkAlgorithm,
) -> Result<SkSignature, WireError> {
    let mut r = reader(sig);
    let alg = r.string(64).map_err(|_| WireError::Malformed)?;
    if SkAlgorithm::parse(alg) != Some(expected) {
        return Err(WireError::WrongType);
    }
    let raw = r.string(256).map_err(|_| WireError::Malformed)?;
    let ok_len = match expected {
        SkAlgorithm::Ed25519 => raw.len() == 64,
        SkAlgorithm::EcdsaP256 => (8..=80).contains(&raw.len()),
    };
    if !ok_len {
        return Err(WireError::Malformed);
    }
    let flags = r.u8().map_err(|_| WireError::Malformed)?;
    let counter = r.u32().map_err(|_| WireError::Malformed)?;
    r.finish().map_err(|_| WireError::Malformed)?;
    if flags & SK_FLAG_USER_PRESENCE == 0 {
        return Err(WireError::NoPresence);
    }
    Ok(SkSignature { flags, counter })
}

/// SSH `string` encoding.
pub(crate) fn put_string(out: &mut Vec<u8>, b: &[u8]) {
    out.extend_from_slice(&u32::try_from(b.len()).unwrap_or(u32::MAX).to_be_bytes());
    out.extend_from_slice(b);
}

/// Fuzz entry `agent_identities` (qa wires it in `fuzz/`): the identities, sign-response and
/// `sk-*` signature parsers on the same bytes. Never panics.
pub fn fuzz_agent_identities(data: &[u8]) {
    let _ = parse_identities(data);
    let _ = parse_sign_response(data);
    let _ = check_sk_signature(data, SkAlgorithm::Ed25519);
    let _ = check_sk_signature(data, SkAlgorithm::EcdsaP256);
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn sig(alg: &str, raw: &[u8], flags: u8) -> Vec<u8> {
        let mut s = Vec::new();
        put_string(&mut s, alg.as_bytes());
        put_string(&mut s, raw);
        s.push(flags);
        s.extend_from_slice(&7u32.to_be_bytes());
        s
    }

    #[test]
    fn identities_answer() {
        let mut m = vec![IDENTITIES_ANSWER];
        m.extend_from_slice(&2u32.to_be_bytes());
        for b in [&b"one"[..], b"two"] {
            put_string(&mut m, b);
            put_string(&mut m, b"comment");
        }
        let ids = parse_identities(&m).expect("parses");
        assert_eq!(
            ids,
            vec![Identity { blob: b"one".to_vec() }, Identity { blob: b"two".to_vec() }]
        );
        for n in 0..m.len() {
            assert!(parse_identities(&m[..n]).is_err(), "truncated at {n}");
        }
        let mut trailing = m.clone();
        trailing.push(0);
        assert_eq!(parse_identities(&trailing), Err(WireError::Malformed));
        assert_eq!(parse_identities(&[FAILURE]), Err(WireError::Failure));
        let mut huge = vec![IDENTITIES_ANSWER];
        huge.extend_from_slice(&u32::MAX.to_be_bytes());
        assert_eq!(parse_identities(&huge), Err(WireError::Malformed), "count beyond the data");
    }

    #[test]
    fn identities_are_capped() {
        let mut m = vec![IDENTITIES_ANSWER];
        m.extend_from_slice(&100u32.to_be_bytes());
        for _ in 0..100 {
            put_string(&mut m, b"k");
            put_string(&mut m, b"");
        }
        assert_eq!(parse_identities(&m).expect("parses").len(), MAX_IDENTITIES);
    }

    #[test]
    fn sk_signatures() {
        let ok = sig("sk-ssh-ed25519@openssh.com", &[1; 64], 0x01);
        let s = check_sk_signature(&ok, SkAlgorithm::Ed25519).expect("ok");
        assert_eq!((s.flags, s.counter), (1, 7));
        let no_up = sig("sk-ssh-ed25519@openssh.com", &[1; 64], 0x04);
        assert_eq!(check_sk_signature(&no_up, SkAlgorithm::Ed25519), Err(WireError::NoPresence));
        let plain = sig("ssh-ed25519", &[1; 64], 0x01);
        assert_eq!(check_sk_signature(&plain, SkAlgorithm::Ed25519), Err(WireError::WrongType));
        assert_eq!(check_sk_signature(&ok, SkAlgorithm::EcdsaP256), Err(WireError::WrongType));
        let short = sig("sk-ssh-ed25519@openssh.com", &[1; 63], 0x01);
        assert_eq!(check_sk_signature(&short, SkAlgorithm::Ed25519), Err(WireError::Malformed));
        for n in 0..ok.len() {
            assert!(check_sk_signature(&ok[..n], SkAlgorithm::Ed25519).is_err(), "truncated {n}");
        }
        let mut trailing = ok;
        trailing.push(0);
        assert_eq!(check_sk_signature(&trailing, SkAlgorithm::Ed25519), Err(WireError::Malformed));
        let mut resp = vec![SIGN_RESPONSE];
        put_string(&mut resp, b"blob");
        assert_eq!(parse_sign_response(&resp).expect("resp"), b"blob");
        assert_eq!(parse_sign_response(&[FAILURE]), Err(WireError::Failure));
    }

    proptest! {
        #[test]
        fn never_panics(data in proptest::collection::vec(any::<u8>(), 0..512)) {
            fuzz_agent_identities(&data);
        }
    }
}
