//! Bounded identifiers and strings of the vCenter wire format (ADR-0015 §1): managed-object
//! ids ≤ 64 B of `[a-z0-9-]`, names ≤ 255 B without control characters, and a
//! length-checked sequence deserializer that refuses an array before it grows past its cap.

use std::fmt;
use std::marker::PhantomData;

use serde::de::{self, Deserializer, SeqAccess, Visitor};
use serde::{Deserialize, Serialize};

use crate::error::VsphereError;

/// Longest managed-object id.
pub const MAX_ID: usize = 64;
/// Longest object / guest name.
pub const MAX_NAME: usize = 255;

fn valid_id(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= MAX_ID
        && s.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        && !s.starts_with('-')
}

/// A vSphere managed-object id (`vm-42`, `host-7`, `domain-c8`, `datacenter-3`). Safe to put
/// into a path or a query without encoding: the alphabet excludes `/ ? & # % .` and spaces.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(transparent)]
pub struct MoId(String);

impl MoId {
    /// Validate `s`.
    pub fn new(s: &str) -> Result<Self, VsphereError> {
        if valid_id(s) {
            Ok(Self(s.to_owned()))
        } else {
            Err(VsphereError::Invalid("managed-object id must be 1..=64 of [a-z0-9-]"))
        }
    }

    /// The id.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for MoId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(&self.0, f)
    }
}

impl fmt::Display for MoId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for MoId {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = <std::borrow::Cow<'de, str>>::deserialize(d)?;
        if valid_id(&s) {
            Ok(Self(s.into_owned()))
        } else {
            Err(de::Error::custom("invalid managed-object id"))
        }
    }
}

/// An inventory / guest name: ≤ 255 bytes, no C0/C1 control or bidi-override characters.
/// The store sanitises further (`model::is_forbidden`, 120 chars) when it writes the tree.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(transparent)]
pub struct Name(String);

pub(crate) fn valid_name(s: &str) -> bool {
    s.len() <= MAX_NAME
        && !s.chars().any(|c| {
            c.is_control() || matches!(c, '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}')
        })
}

impl Name {
    /// Validate `s`.
    pub fn new(s: &str) -> Result<Self, VsphereError> {
        if valid_name(s) {
            Ok(Self(s.to_owned()))
        } else {
            Err(VsphereError::Invalid("name must be ≤ 255 bytes without control characters"))
        }
    }

    /// The name.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for Name {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(&self.0, f)
    }
}

impl<'de> Deserialize<'de> for Name {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = <std::borrow::Cow<'de, str>>::deserialize(d)?;
        if valid_name(&s) {
            Ok(Self(s.into_owned()))
        } else {
            Err(de::Error::custom("invalid name"))
        }
    }
}

/// A canonical lower-case UUID (`8-4-4-4-12` hex), e.g. the vCenter instance UUID.
pub fn is_uuid(s: &str) -> bool {
    let b = s.as_bytes();
    b.len() == 36
        && b.iter().enumerate().all(|(i, c)| match i {
            8 | 13 | 18 | 23 => *c == b'-',
            _ => c.is_ascii_digit() || (b'a'..=b'f').contains(c),
        })
}

/// A JSON array of at most `N` kept elements. Elements past the cap are skipped without
/// being decoded or stored (`IgnoredAny`, no allocation) and `overflow` is set, so the caller
/// can fail with [`VsphereError::TooLarge`] instead of a decode error.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Capped<T, const N: usize> {
    /// The first `N` elements.
    pub items: Vec<T>,
    /// More than `N` elements were present.
    pub overflow: bool,
}

impl<T, const N: usize> Capped<T, N> {
    /// The elements, or `TooLarge(what)` when the array exceeded `N`.
    pub fn into_vec(self, what: &'static str) -> Result<Vec<T>, VsphereError> {
        if self.overflow {
            Err(VsphereError::TooLarge(what))
        } else {
            Ok(self.items)
        }
    }
}

impl<'de, T: Deserialize<'de>, const N: usize> Deserialize<'de> for Capped<T, N> {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct V<T, const N: usize>(PhantomData<T>);
        impl<'de, T: Deserialize<'de>, const N: usize> Visitor<'de> for V<T, N> {
            type Value = Capped<T, N>;
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "an array")
            }
            fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
                let mut items = Vec::with_capacity(seq.size_hint().unwrap_or(0).min(N).min(1024));
                while items.len() < N {
                    match seq.next_element()? {
                        Some(x) => items.push(x),
                        None => return Ok(Capped { items, overflow: false }),
                    }
                }
                let mut overflow = false;
                while seq.next_element::<de::IgnoredAny>()?.is_some() {
                    overflow = true;
                }
                Ok(Capped { items, overflow })
            }
        }
        d.deserialize_seq(V::<T, N>(PhantomData))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ids_refuse_injection() {
        for ok in ["vm-42", "host-7", "domain-c8", "datacenter-3", "a"] {
            assert!(MoId::new(ok).is_ok(), "{ok}");
        }
        for bad in [
            "",
            "VM-1",
            "vm-1/power",
            "vm-1?action=stop",
            "vm 1",
            "../vm",
            "vm-1&x=y",
            "-vm",
            "vm-1#",
            "vm%2f1",
            "vm.1",
            "vm-1\n",
            &"a".repeat(65),
        ] {
            assert!(MoId::new(bad).is_err(), "{bad:?}");
            assert!(serde_json::from_value::<MoId>(serde_json::json!(bad)).is_err());
        }
    }

    #[test]
    fn names_are_bounded() {
        assert!(Name::new("web-01 (prod) — ü").is_ok());
        assert!(Name::new(&"x".repeat(255)).is_ok());
        assert!(Name::new(&"x".repeat(256)).is_err());
        assert!(Name::new("a\u{1b}[31m").is_err());
        assert!(Name::new("a\u{202e}b").is_err());
        assert!(serde_json::from_str::<Name>("12").is_err());
    }

    #[test]
    fn uuid_form() {
        assert!(is_uuid("6f1b2c3d-0000-4abc-9def-0123456789ab"));
        assert!(!is_uuid("6F1B2C3D-0000-4abc-9def-0123456789ab"));
        assert!(!is_uuid("6f1b2c3d-0000-4abc-9def-0123456789a/"));
        assert!(!is_uuid("6f1b2c3d00000-4abc-9def-0123456789ab"));
    }

    #[test]
    fn capped_arrays() {
        let ok = serde_json::from_str::<Capped<u8, 3>>("[1,2,3]").expect("ok");
        assert_eq!(ok.into_vec("x").expect("vec"), [1, 2, 3]);
        let over = serde_json::from_str::<Capped<u8, 3>>(r#"[1,2,3,"skipped",{"a":[]}]"#);
        assert_eq!(
            over.expect("parsed").into_vec("x").map_err(|e| e.code()),
            Err("vsphere.too_large")
        );
        assert!(serde_json::from_str::<Capped<u8, 3>>("{}").is_err());
        assert!(serde_json::from_str::<Capped<u8, 3>>("[1,\"a\"]").is_err());
    }
}
