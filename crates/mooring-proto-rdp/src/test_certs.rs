//! Test certificates (rcgen, ring). `example.test` names and RFC 5737 addresses only.

use rcgen::{BasicConstraints, CertificateParams, IsCa, Issuer, KeyPair};

fn names(n: &[&str]) -> Vec<String> {
    n.iter().map(|s| (*s).to_owned()).collect()
}

/// A self-signed leaf for `n` and its key.
pub(crate) fn self_signed(n: &[&str]) -> (Vec<u8>, KeyPair) {
    let key = KeyPair::generate().expect("key");
    let cert = CertificateParams::new(names(n)).expect("params").self_signed(&key).expect("cert");
    (cert.der().to_vec(), key)
}

/// A test CA: its PEM (for `caPem`) and an issuer to sign leaves with.
pub(crate) fn ca() -> (String, Issuer<'static, KeyPair>) {
    let key = KeyPair::generate().expect("key");
    let mut params = CertificateParams::new(Vec::<String>::new()).expect("params");
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.distinguished_name.push(rcgen::DnType::CommonName, "Mooring Test CA");
    let cert = params.self_signed(&key).expect("ca cert");
    (cert.pem(), Issuer::new(params, key))
}

/// A leaf for `n` signed by `issuer`.
pub(crate) fn signed_by(n: &[&str], issuer: &Issuer<'_, KeyPair>) -> (Vec<u8>, KeyPair) {
    let key = KeyPair::generate().expect("key");
    let cert =
        CertificateParams::new(names(n)).expect("params").signed_by(&key, issuer).expect("leaf");
    (cert.der().to_vec(), key)
}
