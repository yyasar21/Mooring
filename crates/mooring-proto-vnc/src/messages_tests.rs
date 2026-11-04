use super::*;
use crate::handshake::PixelFormat;

#[test]
fn server_messages() {
    assert_eq!(
        parse_server_message(&[0, 0, 0, 3]).expect("fu"),
        Parsed::Done(ServerMessage::FramebufferUpdate { rects: 3 }, 4)
    );
    assert_eq!(parse_server_message(&[0, 0]).expect("fu"), Parsed::Need(4));
    assert_eq!(parse_server_message(&[2]).expect("bell"), Parsed::Done(ServerMessage::Bell, 1));
    assert_eq!(
        parse_server_message(&[1, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0]).expect("cmap"),
        Parsed::Done(ServerMessage::SetColourMapEntries, 12)
    );
    assert_eq!(parse_server_message(&[1, 0, 0, 0, 0, 2]).expect("cmap"), Parsed::Need(18));
    assert!(parse_server_message(&[150]).is_err(), "continuous updates not enabled");
    assert!(parse_server_message(&[77]).is_err());
}

#[test]
fn cut_text_latin1_and_cap() {
    let mut m = vec![3, 0, 0, 0, 0, 0, 0, 5];
    m.extend_from_slice(&[b'c', 0xe9, 0x00, b'\n', 0x1b]);
    assert_eq!(
        parse_server_message(&m).expect("cut"),
        Parsed::Done(ServerMessage::CutText("c\u{e9}\n".into()), 13)
    );
    assert_eq!(parse_server_message(&m[..10]).expect("cut"), Parsed::Need(13));
    let over = [3, 0, 0, 0, 0, 0x10, 0, 1];
    assert_eq!(
        parse_server_message(&over).expect("over"),
        Parsed::Done(ServerMessage::CutTextTooLong { len: MAX_CUT_TEXT + 1 }, 8)
    );
    // Extended-clipboard style negative length is just "too long".
    let neg = [3, 0, 0, 0, 0xff, 0xff, 0xff, 0xf0];
    assert!(matches!(
        parse_server_message(&neg).expect("neg"),
        Parsed::Done(ServerMessage::CutTextTooLong { .. }, 8)
    ));
    assert_eq!(string_to_latin1("caf\u{e9}"), Some(vec![b'c', b'a', b'f', 0xe9]));
    assert_eq!(string_to_latin1("\u{20ac}"), None, "euro sign is refused, not replaced");
    let s: String = (0u8..=255).map(char::from).filter(|c| !c.is_control()).collect();
    assert_eq!(latin1_to_string(&string_to_latin1(&s).expect("l1")), s, "round trip");
}

#[test]
fn client_message_bytes() {
    assert_eq!(client::set_pixel_format(&PixelFormat::RGBX)[..4], [0, 0, 0, 0]);
    assert_eq!(client::set_pixel_format(&PixelFormat::RGBX).len(), 20);
    let e = client::set_encodings(&enc::ADVERTISED);
    assert_eq!(&e[..4], &[2, 0, 0, 9]);
    assert_eq!(&e[4..8], &1i32.to_be_bytes());
    assert_eq!(&e[8..12], &16i32.to_be_bytes());
    assert!(!enc::ADVERTISED.iter().any(|e| (-32..=-23).contains(e)), "no JPEG quality");
    assert_eq!(
        client::update_request(true, Rect::new(0, 0, 1024, 768)),
        vec![3, 1, 0, 0, 0, 0, 4, 0, 3, 0]
    );
    assert_eq!(client::key_event(true, 0xff0d), vec![4, 1, 0, 0, 0, 0, 0xff, 0x0d]);
    assert_eq!(client::pointer_event(1, 10, 20), vec![5, 1, 0, 10, 0, 20]);
    assert_eq!(client::cut_text(b"hi"), vec![6, 0, 0, 0, 0, 0, 0, 2, b'h', b'i']);
    assert_eq!(
        client::qemu_key_event(true, 0x61, 0x1e),
        vec![255, 0, 0, 1, 0, 0, 0, 0x61, 0, 0, 0, 0x1e]
    );
    let d = client::set_desktop_size(1280, 720, 7, 0);
    assert_eq!(d.len(), 24);
    assert_eq!(&d[..8], &[251, 0, 5, 0, 2, 208, 1, 0]);
}
