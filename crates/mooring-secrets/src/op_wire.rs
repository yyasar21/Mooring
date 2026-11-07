//! 1Password Connect response shapes (ADR-0026 §3): vault and item summaries, one item with
//! its sections and fields. Hand-written capped lists; field values go straight into
//! [`SecretValue`]. Then the mapping of an item onto a target kind: fields by label or id
//! (the kind's names, or `fieldMap` renames), `username` / `password` by purpose and the TOTP
//! seed by field type as fallbacks. A top-level field wins over a sectioned one; two fields
//! answering one name at the same level is ambiguous and refused.

use std::collections::BTreeMap;
use std::fmt;
use std::marker::PhantomData;

use mooring_core::credential::external::{kv_key, target_names};
use mooring_core::credential::OpReference;
use mooring_core::CredentialKind;
use serde::de::{self, Deserializer, SeqAccess, Visitor};
use serde::Deserialize;

use crate::error::SecretsError;
use crate::wire::{SecretMap, SecretValue};

/// Most vaults / items a filter may return.
pub const MAX_SUMMARIES: usize = 1000;
/// Most fields of one item.
pub const MAX_FIELDS: usize = 256;
/// Most sections of one item.
pub const MAX_SECTIONS: usize = 64;
/// Longest id / label / title we keep.
pub const MAX_LABEL: usize = 256;

/// A list of at most `N` elements.
#[derive(Debug)]
pub(crate) struct Capped<T, const N: usize>(pub Vec<T>);

struct CappedVisitor<T, const N: usize>(PhantomData<T>);

impl<'de, T: Deserialize<'de>, const N: usize> Visitor<'de> for CappedVisitor<T, N> {
    type Value = Capped<T, N>;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "a list of at most {N} entries")
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
        let mut out = Vec::new();
        while let Some(v) = seq.next_element::<T>()? {
            if out.len() == N {
                return Err(de::Error::custom("too many entries"));
            }
            out.push(v);
        }
        Ok(Capped(out))
    }
}

impl<'de, T: Deserialize<'de>, const N: usize> Deserialize<'de> for Capped<T, N> {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        d.deserialize_seq(CappedVisitor(PhantomData))
    }
}

impl<T, const N: usize> Default for Capped<T, N> {
    fn default() -> Self {
        Self(Vec::new())
    }
}

/// A short visible string (id, label, title, type).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub(crate) struct Label(pub String);

impl<'de> Deserialize<'de> for Label {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        if s.len() > MAX_LABEL || s.chars().any(char::is_control) {
            return Err(de::Error::custom("bad label"));
        }
        Ok(Self(s))
    }
}

/// `GET /v1/vaults` entry.
#[derive(Debug, Deserialize)]
pub(crate) struct VaultSummary {
    pub id: Label,
    #[serde(default)]
    pub name: Label,
}

/// `GET /v1/vaults/{id}/items` entry.
#[derive(Debug, Deserialize)]
pub(crate) struct ItemSummary {
    pub id: Label,
    #[serde(default)]
    pub title: Label,
}

#[derive(Debug, Deserialize)]
pub(crate) struct SectionRef {
    pub id: Label,
}

#[derive(Debug, Deserialize)]
pub(crate) struct Section {
    pub id: Label,
    #[serde(default)]
    pub label: Option<Label>,
}

/// One item field.
#[derive(Debug, Deserialize)]
pub(crate) struct Field {
    pub id: Label,
    #[serde(default, rename = "type")]
    pub kind: Label,
    #[serde(default)]
    pub purpose: Option<Label>,
    #[serde(default)]
    pub label: Option<Label>,
    #[serde(default)]
    pub value: Option<SecretValue>,
    #[serde(default)]
    pub section: Option<SectionRef>,
}

/// `GET /v1/vaults/{id}/items/{id}`.
#[derive(Debug, Deserialize)]
pub(crate) struct Item {
    pub id: Label,
    #[serde(default)]
    pub sections: Capped<Section, MAX_SECTIONS>,
    #[serde(default)]
    pub fields: Capped<Field, MAX_FIELDS>,
}

fn label_is(l: Option<&Label>, want: &str) -> bool {
    l.is_some_and(|l| l.0 == want)
}

impl Field {
    fn named(&self, key: &str) -> bool {
        self.id.0 == key || label_is(self.label.as_ref(), key)
    }

    fn in_section(&self, section: Option<&str>) -> bool {
        match (section, &self.section) {
            (None, _) => true,
            (Some(s), Some(r)) => r.id.0 == s,
            (Some(_), None) => false,
        }
    }
}

/// The value of an `OTP` field as a base32 seed (`otpauth://…?secret=…` is unwrapped).
fn otp_seed(v: &SecretValue) -> SecretValue {
    let s = v.expose();
    if let Some(q) = s.strip_prefix("otpauth://").and_then(|r| r.split_once('?')).map(|(_, q)| q) {
        if let Some(secret) = q.split('&').find_map(|kv| kv.strip_prefix("secret=")) {
            return SecretValue(zeroize::Zeroizing::new(secret.to_ascii_uppercase()));
        }
    }
    v.clone()
}

/// The one required name of `kind`, when it has exactly one (a one-field reference fills it).
pub(crate) fn single_name(kind: CredentialKind) -> Option<&'static str> {
    let schema = kind.schema();
    let mut req =
        target_names(kind).filter(|n| schema.fields.iter().any(|f| f.name == *n && f.required));
    match (req.next(), req.next()) {
        (Some(n), None) => Some(n),
        _ => None,
    }
}

fn ambiguous(key: &str) -> SecretsError {
    SecretsError::shape(format!("{}: two fields have this label", sanitize(key)))
}

fn sanitize(k: &str) -> String {
    k.chars().map(|c| if c.is_ascii_graphic() || c == ' ' { c } else { '?' }).take(64).collect()
}

fn one<'a>(
    mut hits: impl Iterator<Item = &'a Field>,
    key: &str,
) -> Result<Option<&'a Field>, SecretsError> {
    match (hits.next(), hits.next()) {
        (Some(_), Some(_)) => Err(ambiguous(key)),
        (hit, _) => Ok(hit),
    }
}

/// The one field matching `pred`: a top-level field (no section) wins over sectioned ones,
/// as `op read` does; two candidates at the same level are ambiguous.
fn pick<'a>(
    fields: &'a [Field],
    key: &str,
    pred: impl Fn(&Field) -> bool,
) -> Result<Option<&'a Field>, SecretsError> {
    if let Some(f) = one(fields.iter().filter(|f| f.section.is_none() && pred(f)), key)? {
        return Ok(Some(f));
    }
    one(fields.iter().filter(|f| pred(f)), key)
}

/// Map `item` onto the names of `kind` as `r` and `field_map` say.
pub(crate) fn item_values(
    item: &Item,
    r: &OpReference,
    kind: CredentialKind,
    field_map: Option<&BTreeMap<String, String>>,
) -> Result<SecretMap, SecretsError> {
    let fields = &item.fields.0;
    if let Some(want) = &r.field {
        let name = single_name(kind).ok_or(SecretsError::Engine(
            "a one-field reference fits kinds with one required value",
        ))?;
        let section = match &r.section {
            None => None,
            Some(s) => {
                let mut hits = item
                    .sections
                    .0
                    .iter()
                    .filter(|x| x.id.0 == *s || label_is(x.label.as_ref(), s));
                match (hits.next(), hits.next()) {
                    (Some(_), Some(_)) => return Err(ambiguous(s)),
                    (Some(x), None) => Some(x.id.0.as_str()),
                    (None, _) => return Err(SecretsError::NotFound),
                }
            }
        };
        let f = match section {
            Some(_) => one(fields.iter().filter(|f| f.named(want) && f.in_section(section)), want)?,
            None => pick(fields, want, |f| f.named(want))?,
        }
        .ok_or(SecretsError::NotFound)?;
        let v = f
            .value
            .clone()
            .ok_or_else(|| SecretsError::shape(format!("{}: empty field", sanitize(want))))?;
        return Ok(SecretMap::from_values(vec![(name.to_owned(), v)]));
    }
    let mut out = Vec::new();
    for name in target_names(kind) {
        let key = kv_key(field_map, name);
        let mut hit = pick(fields, key, |f| f.named(key))?;
        if hit.is_none() && key == name {
            let purpose = match name {
                "username" => Some("USERNAME"),
                "password" => Some("PASSWORD"),
                _ => None,
            };
            hit = match (name, purpose) {
                ("otp_seed", _) => pick(fields, key, |f| f.kind.0 == "OTP")?,
                (_, Some(p)) => pick(fields, key, |f| label_is(f.purpose.as_ref(), p))?,
                _ => None,
            };
        }
        let Some(f) = hit else { continue };
        let Some(v) = &f.value else { continue };
        if v.expose().is_empty() {
            continue;
        }
        let v = if name == "otp_seed" { otp_seed(v) } else { v.clone() };
        out.push((name.to_owned(), v));
    }
    Ok(SecretMap::from_values(out))
}
