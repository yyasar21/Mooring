//! VNC Authentication (DES challenge) and the VeNCrypt 0.2 sub-negotiation.

use std::sync::Arc;

use des::cipher::{Array, BlockCipherEncrypt, KeyInit};
use des::Des;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use super::conn::{BoxIo, HsError};
use super::{RfbConfig, VeNCryptSub};

/// RFB VNC Authentication response: DES-ECB of the 16-byte challenge under the password
/// (first 8 bytes, NUL padded) with every key byte bit-reversed (RFC 6143 §7.2.2 + errata).
pub fn vnc_auth_response(password: &[u8], challenge: &[u8; 16]) -> [u8; 16] {
    let mut key = [0u8; 8];
    for (k, p) in key.iter_mut().zip(password.iter()) {
        *k = p.reverse_bits();
    }
    let cipher = Des::new(&Array::from(key));
    let mut out = [0u8; 16];
    for (i, chunk) in challenge.as_chunks::<8>().0.iter().enumerate() {
        let mut block = Array::from([
            chunk[0], chunk[1], chunk[2], chunk[3], chunk[4], chunk[5], chunk[6], chunk[7],
        ]);
        cipher.encrypt_block(&mut block);
        out[i * 8..i * 8 + 8].copy_from_slice(&block);
    }
    out
}

/// Sends a challenge and checks the response. `Ok(false)` = wrong password.
pub(crate) async fn vnc_auth(io: &mut BoxIo, cfg: &RfbConfig) -> Result<bool, HsError> {
    let challenge = cfg.fixed_challenge.unwrap_or_else(|| {
        let mut c = [0u8; 16];
        rand_core::RngCore::fill_bytes(&mut rand_core::OsRng, &mut c);
        c
    });
    io.write_all(&challenge).await?;
    let mut resp = [0u8; 16];
    io.read_exact(&mut resp).await?;
    let pw = cfg.password.as_deref().unwrap_or("");
    Ok(vnc_auth_response(pw.as_bytes(), &challenge) == resp)
}

/// Reads a VeNCrypt Plain username/password and compares it with the configured pair.
async fn plain_auth(io: &mut BoxIo, cfg: &RfbConfig) -> Result<bool, HsError> {
    let ulen = io.read_u32().await?;
    let plen = io.read_u32().await?;
    if ulen > 4096 || plen > 4096 {
        return Err(HsError::Protocol(format!("plain credentials too long ({ulen}, {plen})")));
    }
    let mut user = vec![0u8; ulen as usize];
    let mut pass = vec![0u8; plen as usize];
    io.read_exact(&mut user).await?;
    io.read_exact(&mut pass).await?;
    Ok(cfg
        .plain_user
        .as_ref()
        .is_some_and(|(u, p)| u.as_bytes() == user.as_slice() && p.as_bytes() == pass.as_slice()))
}

/// Runs the VeNCrypt negotiation. Returns the (possibly TLS-wrapped) stream, the chosen
/// subtype and whether the inner authentication succeeded.
pub(crate) async fn negotiate(
    mut io: BoxIo,
    cfg: &RfbConfig,
    subs: &[VeNCryptSub],
    tls: Option<&Arc<rustls::ServerConfig>>,
) -> Result<(BoxIo, u32, bool), HsError> {
    io.write_all(&[0, 2]).await?;
    let mut version = [0u8; 2];
    io.read_exact(&mut version).await?;
    if version != [0, 2] {
        io.write_all(&[1]).await?;
        return Err(HsError::Protocol(format!("VeNCrypt version {}.{}", version[0], version[1])));
    }
    io.write_all(&[0]).await?;
    let mut list = vec![u8::try_from(subs.len()).unwrap_or(u8::MAX)];
    for s in subs {
        list.extend_from_slice(&s.code().to_be_bytes());
    }
    io.write_all(&list).await?;
    let code = io.read_u32().await?;
    let Some(sub) = VeNCryptSub::from_code(code).filter(|s| subs.contains(s)) else {
        return Err(HsError::Protocol(format!("VeNCrypt subtype {code} not offered")));
    };
    io.write_all(&[1]).await?;
    io.flush().await?;
    let mut io = if sub == VeNCryptSub::Plain {
        io
    } else {
        let config = tls.ok_or_else(|| HsError::Protocol("no TLS config".to_owned()))?;
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::clone(config));
        let stream =
            acceptor.accept(io).await.map_err(|e| HsError::Protocol(format!("TLS accept: {e}")))?;
        Box::new(stream) as BoxIo
    };
    let ok = match sub {
        VeNCryptSub::TlsNone | VeNCryptSub::X509None => true,
        VeNCryptSub::TlsVnc | VeNCryptSub::X509Vnc => vnc_auth(&mut io, cfg).await?,
        VeNCryptSub::Plain | VeNCryptSub::TlsPlain | VeNCryptSub::X509Plain => {
            plain_auth(&mut io, cfg).await?
        }
    };
    Ok((io, code, ok))
}

#[cfg(test)]
mod tests {
    use super::vnc_auth_response;

    #[test]
    fn des_response_vector() {
        // Known answer: password "password", challenge 0x00..0x0f. Reference computed
        // independently with `openssl enc -des-ecb -nopad -K 0e86ceceeef64e26` (the
        // bit-reversed key bytes of "password").
        let challenge: [u8; 16] = core::array::from_fn(|i| u8::try_from(i).expect("small"));
        let r = vnc_auth_response(b"password", &challenge);
        let expected = [
            0xb8, 0x66, 0x92, 0x41, 0x25, 0xc8, 0xee, 0xbb, 0x9d, 0xeb, 0xc1, 0xdb, 0x61, 0xc5,
            0x38, 0xe2,
        ];
        assert_eq!(r, expected);
        // Only the first 8 password bytes matter.
        assert_eq!(r, vnc_auth_response(b"passwordEXTRA", &challenge));
        assert_ne!(r, vnc_auth_response(b"Password", &challenge));
    }
}
