use super::*;

#[test]
fn rects_are_clipped() {
    let r = |left, top, right, bottom| InclusiveRectangle { left, top, right, bottom };
    assert_eq!(to_rect(&r(0, 0, 9, 9), 100, 100), Some(Rect::new(0, 0, 10, 10)));
    assert_eq!(to_rect(&r(90, 90, 200, 200), 100, 100), Some(Rect::new(90, 90, 10, 10)));
    assert_eq!(to_rect(&r(100, 0, 120, 10), 100, 100), None);
    assert_eq!(to_rect(&r(5, 5, 4, 4), 100, 100), None);
}

#[test]
fn blit_copies_the_damaged_region() {
    let sink = FrameSink::new();
    sink.resize(64, 64).expect("resize");
    let image = DecodedImage::new(PixelFormat::RgbA32, 64, 64);
    blit(&sink, &image, &InclusiveRectangle { left: 10, top: 10, right: 19, bottom: 19 });
    blit(&sink, &image, &InclusiveRectangle { left: 60, top: 60, right: 1000, bottom: 1000 });
    let (w, h, px) = sink.snapshot();
    assert_eq!((w, h, px.len()), (64, 64, 64 * 64 * 4));
}

#[test]
fn cursor_sprites_are_bounded() {
    use ironrdp_graphics::pointer::DecodedPointer;
    let p = |w: u16, h: u16, len: usize| DecodedPointer {
        width: w,
        height: h,
        hotspot_x: 100,
        hotspot_y: 1,
        bitmap_data: vec![0; len],
    };
    assert!(matches!(cursor(&p(32, 32, 32 * 32 * 4)), Cursor::Sprite { hot_x: 31, .. }));
    assert_eq!(cursor(&p(32, 32, 10)), Cursor::Default);
    assert_eq!(cursor(&p(MAX_CURSOR + 1, 1, usize::from(MAX_CURSOR + 1) * 4)), Cursor::Default);
    assert_eq!(cursor(&p(0, 0, 0)), Cursor::Default);
}
