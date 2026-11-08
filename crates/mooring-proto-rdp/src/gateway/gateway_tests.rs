use proptest::prelude::*;

use super::pdu::{self, server, Packet, PduError};
use super::*;

#[test]
fn client_packets_have_the_spec_layout() {
    let h = pdu::handshake_request();
    assert_eq!(h, [1, 0, 0, 0, 14, 0, 0, 0, 1, 0, 0, 0, 0, 0]);
    let t = pdu::tunnel_create();
    assert_eq!(&t[..8], &[4, 0, 0, 0, 16, 0, 0, 0]);
    assert_eq!(&t[8..12], &pdu::CAPS_IDLE_TIMEOUT.to_le_bytes());
    let a = pdu::tunnel_auth("MY-PC");
    let (ty, body) = pdu::split(&a).expect("split");
    assert_eq!(ty, pdu::ty::TUNNEL_AUTH);
    assert_eq!(&body[..4], &[0, 0, 12, 0], "no fields, 6 UTF-16 units incl. NUL");
    let c = pdu::channel_create("rdp.example.test", 3389).expect("cc");
    let (_, body) = pdu::split(&c).expect("split");
    assert_eq!(pdu::parse_channel_create(body).expect("parse"), ("rdp.example.test".into(), 3389));
    assert!(pdu::channel_create("", 3389).is_none());
    assert!(pdu::channel_create(&"a".repeat(pdu::MAX_RESOURCE + 1), 1).is_none());
    assert!(pdu::channel_create("a\nb", 1).is_none());
    assert_eq!(pdu::decode(&pdu::keepalive()).expect("ka"), Packet::Keepalive);
}

#[test]
fn client_name_is_sanitised_to_32() {
    assert_eq!(pdu::sanitise_client_name("my pc;<x>"), "mypcx");
    assert_eq!(pdu::sanitise_client_name("ü€"), "MOORING");
    assert_eq!(pdu::sanitise_client_name(&"A".repeat(80)).len(), pdu::MAX_CLIENT_NAME);
}

#[test]
fn server_packets_decode() {
    assert_eq!(
        pdu::decode(&server::handshake_response(0, 1)).expect("hs"),
        Packet::HandshakeResponse {
            error: 0,
            major: 1,
            minor: 0,
            server_version: 0,
            extended_auth: 0
        }
    );
    assert_eq!(
        pdu::decode(&server::tunnel_response(0, 7)).expect("tr"),
        Packet::TunnelResponse {
            status: 0,
            tunnel_id: Some(7),
            caps: Some(pdu::CAPS_IDLE_TIMEOUT)
        }
    );
    assert_eq!(
        pdu::decode(&server::tunnel_auth_response(0x8007_59DA)).expect("ta"),
        Packet::TunnelAuthResponse { error: 0x8007_59DA, idle_timeout_minutes: Some(30) }
    );
    assert_eq!(
        pdu::decode(&server::channel_response(0, 9)).expect("cr"),
        Packet::ChannelResponse { error: 0, channel_id: Some(9) }
    );
    assert_eq!(pdu::decode(&pdu::data(b"abc")).expect("d"), Packet::Data(b"abc".to_vec()));
    assert_eq!(
        pdu::decode(&server::service_message("hi")).expect("svc"),
        Packet::ServiceMessage { len: 6 }
    );
    assert_eq!(pdu::decode(&server::raw(0x99, b"zz")).expect("other"), Packet::Other { ty: 0x99 });
}

#[test]
fn hostile_packets_are_refused() {
    // Header length below 8, above the cap, disagreeing with the buffer.
    let mut short = pdu::keepalive();
    short[4] = 7;
    assert_eq!(pdu::peek_len(&short), Err(PduError::BadLength));
    let mut huge = pdu::keepalive();
    huge[4..8].copy_from_slice(&u32::try_from(pdu::MAX_PACKET + 1).expect("u32").to_le_bytes());
    assert_eq!(pdu::peek_len(&huge), Err(PduError::BadLength));
    assert_eq!(pdu::decode(&pdu::keepalive()[..7]), Err(PduError::BadLength));
    // DATA claiming more than it carries; trailing bytes after a fixed packet.
    assert_eq!(pdu::decode(&server::raw(pdu::ty::DATA, &[10, 0, 1])), Err(PduError::Truncated));
    assert_eq!(pdu::decode(&server::raw(pdu::ty::KEEPALIVE, &[1])), Err(PduError::Truncated));
    // TUNNEL_RESPONSE announcing a SOH request it does not carry.
    let mut tr = 0u16.to_le_bytes().to_vec();
    tr.extend_from_slice(&0u32.to_le_bytes());
    tr.extend_from_slice(&0x04u16.to_le_bytes());
    tr.extend_from_slice(&0u16.to_le_bytes());
    assert_eq!(pdu::decode(&server::raw(pdu::ty::TUNNEL_RESPONSE, &tr)), Err(PduError::Truncated));
    assert!(
        pdu::parse_channel_create(&[1, 0, 1, 0, 3, 0, 3, 0, b'a', 0, 0]).is_err(),
        "odd length"
    );
}

proptest! {
    #[test]
    fn data_round_trips(payload in proptest::collection::vec(any::<u8>(), 0..2048)) {
        prop_assert_eq!(pdu::decode(&pdu::data(&payload)).expect("data"), Packet::Data(payload));
    }

    #[test]
    fn fuzz_entries_never_panic(bytes in proptest::collection::vec(any::<u8>(), 0..512)) {
        fuzz_rdg_pdu(&bytes);
        fuzz_rdg_http_response(&bytes);
    }
}

#[test]
fn fuzz_seeds_run() {
    let mut seed = server::handshake_response(0, 1);
    seed.extend(server::tunnel_response(0, 1));
    seed.extend(pdu::channel_create("h", 1).expect("cc"));
    fuzz_rdg_pdu(&seed);
    fuzz_rdg_pdu(&ws::encode(ws::op::BINARY, &seed, Some([1, 2, 3, 4])));
    fuzz_rdg_http_response(
        b"HTTP/1.1 401 x\r\nWWW-Authenticate: NTLM Zm9v\r\nContent-Length: 0\r\n\r\n",
    );
}

#[test]
fn account_debug_is_redacted() {
    let a = GatewayAccount {
        username: "alice".into(),
        domain: None,
        password: "hunter2".to_owned().into(),
    };
    let shown = format!("{a:?}");
    assert!(shown.contains("alice") && !shown.contains("hunter2"));
}
