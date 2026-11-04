use super::*;
use crate::frame::{decode_mfr1, encode_update, MAX_DIM};
use proptest::prelude::*;

#[test]
fn bounds_are_enforced() {
    let mut fb = Framebuffer::new(10, 5).expect("new");
    assert!(fb.fill(Rect::new(0, 0, 10, 5), [1; 4]).is_ok());
    assert!(fb.fill(Rect::new(9, 0, 2, 1), [1; 4]).is_err());
    assert!(fb.fill(Rect::new(u16::MAX, u16::MAX, u16::MAX, u16::MAX), [1; 4]).is_err());
    assert!(fb.copy(Rect::new(0, 0, 5, 5), 6, 0).is_err(), "source outside");
    assert!(fb.blit(Rect::new(0, 0, 2, 2), &[0; 16], 7, PixelOrder::Rgba).is_err(), "stride");
    assert!(fb.blit(Rect::new(0, 0, 2, 2), &[0; 15], 8, PixelOrder::Rgba).is_err(), "short");
    assert!(fb.blit(Rect::new(0, 0, 2, 2), &[0; 12], 4, PixelOrder::Rgba).is_err());
    assert!(fb.blit(Rect::new(0, 0, 2, 2), &[0; 16], 8, PixelOrder::Rgba).is_ok());
    assert!(fb.blit(Rect::new(3, 3, 0, 9), &[], 0, PixelOrder::Rgba).is_err(), "h out");
    assert!(fb.blit(Rect::new(3, 3, 0, 1), &[], 0, PixelOrder::Rgba).is_ok(), "empty no-op");
    assert!(Framebuffer::new(MAX_DIM + 1, 1).is_err());
    assert!(fb.resize(1, MAX_DIM + 1).is_err());
    assert_eq!((fb.width(), fb.height()), (10, 5), "failed resize keeps the old size");
}

#[test]
fn pixel_orders_convert_to_rgba() {
    let mut fb = Framebuffer::new(1, 1).expect("new");
    for (order, want) in [
        (PixelOrder::Rgba, [1, 2, 3, 4]),
        (PixelOrder::Bgra, [3, 2, 1, 4]),
        (PixelOrder::Rgbx, [1, 2, 3, 255]),
        (PixelOrder::Bgrx, [3, 2, 1, 255]),
    ] {
        fb.blit(Rect::new(0, 0, 1, 1), &[1, 2, 3, 4], 4, order).expect("blit");
        assert_eq!(fb.pixels(), &want, "{order:?}");
    }
}

#[test]
fn overlapping_copy_is_memmove() {
    let mut fb = Framebuffer::new(4, 4).expect("new");
    for y in 0..4u8 {
        for x in 0..4u8 {
            fb.fill(Rect::new(u16::from(x), u16::from(y), 1, 1), [x, y, 0, 255]).expect("fill");
        }
    }
    // Move a 3x3 block down-right by one: rows must be copied bottom-up.
    fb.copy(Rect::new(1, 1, 3, 3), 0, 0).expect("copy");
    let px = |fb: &Framebuffer, x: usize, y: usize| {
        fb.pixels()[(y * 4 + x) * 4..(y * 4 + x) * 4 + 2].to_vec()
    };
    assert_eq!(px(&fb, 1, 1), vec![0, 0]);
    assert_eq!(px(&fb, 3, 3), vec![2, 2]);
    // And back up-left.
    fb.copy(Rect::new(0, 0, 3, 3), 1, 1).expect("copy");
    assert_eq!(px(&fb, 0, 0), vec![0, 0]);
    assert_eq!(px(&fb, 2, 2), vec![2, 2]);
}

#[test]
fn dirty_rects_merge_and_escalate_to_full() {
    let mut fb = Framebuffer::new(100, 100).expect("new");
    let _ = fb.take_update();
    fb.mark_dirty(Rect::new(0, 0, 10, 10));
    fb.mark_dirty(Rect::new(5, 5, 10, 10));
    fb.mark_dirty(Rect::new(50, 50, 1, 1));
    let u = fb.take_update();
    assert!(!u.full && !u.resized);
    assert_eq!(u.rects.len(), 2);
    assert!(u.rects.contains(&Rect::new(0, 0, 15, 15)));

    // > 32 disjoint rects → one full rect.
    for i in 0..33u16 {
        fb.mark_dirty(Rect::new(i * 3, 0, 1, 1));
    }
    let u = fb.take_update();
    assert!(u.full);
    assert_eq!(u.rects, vec![Rect::new(0, 0, 100, 100)]);

    // > 60 % of the area → full.
    fb.mark_dirty(Rect::new(0, 0, 100, 61));
    assert!(fb.take_update().full);
    fb.mark_dirty(Rect::new(0, 0, 100, 60));
    assert!(!fb.take_update().full, "exactly 60 % is still incremental");

    // Clipped, not refused, and an empty fb has no rects.
    fb.mark_dirty(Rect::new(95, 95, 50, 50));
    assert_eq!(fb.take_update().rects, vec![Rect::new(95, 95, 5, 5)]);
    let mut empty = Framebuffer::default();
    empty.resize(0, 0).expect("0x0");
    let u = empty.take_update();
    assert!(u.full && u.rects.is_empty());
}

#[test]
fn resize_clears_and_flags() {
    let mut fb = Framebuffer::new(2, 2).expect("new");
    let _ = fb.take_update();
    fb.mark_dirty(Rect::new(0, 0, 1, 1));
    fb.resize(3, 1).expect("resize");
    let u = fb.take_update();
    assert!(u.full && u.resized);
    assert_eq!(u.rects, vec![Rect::new(0, 0, 3, 1)]);
    assert_eq!(fb.pixels(), &[0, 0, 0, 255, 0, 0, 0, 255, 0, 0, 0, 255]);
    fb.resize(3, 1).expect("same size");
    assert!(!fb.has_pending(), "same-size resize is a no-op");
}

#[test]
fn invalid_cursor_becomes_default() {
    let mut fb = Framebuffer::new(1, 1).expect("new");
    fb.set_cursor(Cursor::Sprite { hot_x: 0, hot_y: 0, w: 2, h: 2, rgba: vec![0; 15] });
    assert_eq!(fb.take_update().cursor, Some(Cursor::Default));
    fb.set_cursor(Cursor::Sprite { hot_x: 2, hot_y: 0, w: 2, h: 1, rgba: vec![0; 8] });
    assert_eq!(fb.take_update().cursor, Some(Cursor::Default), "hot spot outside");
    let big = Cursor::Sprite { hot_x: 0, hot_y: 0, w: 385, h: 1, rgba: vec![0; 385 * 4] };
    fb.set_cursor(big);
    assert_eq!(fb.take_update().cursor, Some(Cursor::Default), "over 384");
    let ok = Cursor::Sprite { hot_x: 1, hot_y: 0, w: 2, h: 1, rgba: vec![7; 8] };
    fb.set_cursor(ok.clone());
    assert_eq!(fb.take_update().cursor, Some(ok));
}

#[derive(Debug, Clone)]
enum Op {
    Fill(Rect, [u8; 4]),
    Blit(Rect, u8, PixelOrder),
    Copy(Rect, u16, u16),
    Resize(u16, u16),
    Take,
}

fn rect(max: u16) -> impl Strategy<Value = Rect> {
    (0..max + 4, 0..max + 4, 0..max + 4, 0..max + 4).prop_map(|(x, y, w, h)| Rect::new(x, y, w, h))
}

fn op() -> impl Strategy<Value = Op> {
    let order = prop_oneof![
        Just(PixelOrder::Rgba),
        Just(PixelOrder::Bgra),
        Just(PixelOrder::Rgbx),
        Just(PixelOrder::Bgrx)
    ];
    prop_oneof![
        4 => (rect(24), any::<[u8; 4]>()).prop_map(|(r, c)| Op::Fill(r, c)),
        4 => (rect(24), any::<u8>(), order).prop_map(|(r, s, o)| Op::Blit(r, s, o)),
        3 => (rect(24), 0..28u16, 0..28u16).prop_map(|(r, x, y)| Op::Copy(r, x, y)),
        1 => (0..28u16, 0..28u16).prop_map(|(w, h)| Op::Resize(w, h)),
        3 => Just(Op::Take),
    ]
}

proptest! {
    /// Coalescing never loses pixels: replaying every MFR1 message on a mirror reproduces the
    /// framebuffer exactly, whatever the mix of in- and out-of-bounds operations.
    #[test]
    fn mirror_from_mfr1_matches_framebuffer(ops in proptest::collection::vec(op(), 1..60)) {
        let mut fb = Framebuffer::new(20, 16).expect("new");
        let mut mirror = Vec::new();
        let mut seq = 0u32;
        let mut flush = |fb: &mut Framebuffer, mirror: &mut Vec<u8>| {
            seq += 1;
            let update = fb.take_update();
            let set: Vec<Rect> = update.rects.clone();
            for (i, a) in set.iter().enumerate() {
                prop_assert!(a.fits(fb.width(), fb.height()));
                for b in &set[i + 1..] {
                    prop_assert!(!a.overlaps(*b), "dirty rects are disjoint");
                }
            }
            prop_assert!(set.len() <= crate::frame::COALESCE_MAX_RECTS);
            let msg = encode_update(seq, fb, &update);
            let frame = decode_mfr1(&msg).expect("own output decodes");
            frame.apply(mirror);
            Ok(())
        };
        for op in ops {
            let (w, h) = (fb.width(), fb.height());
            let res = match op {
                Op::Fill(r, c) => fb.fill(r, c),
                Op::Blit(r, seed, order) => {
                    let stride = usize::from(r.w) * 4 + 3;
                    let len = stride * usize::from(r.h);
                    let src: Vec<u8> = (0..len).map(|i| (i % 251).to_le_bytes()[0].wrapping_mul(seed)).collect();
                    fb.blit(r, &src, stride, order)
                }
                Op::Copy(r, x, y) => fb.copy(r, x, y),
                Op::Resize(nw, nh) => fb.resize(nw, nh),
                Op::Take => { flush(&mut fb, &mut mirror)?; Ok(()) }
            };
            if res.is_err() {
                prop_assert_eq!((fb.width(), fb.height()), (w, h), "a failed op changes nothing");
            }
        }
        flush(&mut fb, &mut mirror)?;
        prop_assert_eq!(&mirror[..], fb.pixels());
    }
}
