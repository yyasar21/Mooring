//! Frame pump: ordering, credits, coalescing, cadence, and the ignored `frame_bench`.

use std::collections::VecDeque;
use std::time::{Duration, Instant};

use mooring_core::frame::{decode_mfr1, Mfr1Record, PixelOrder, Rect};
use tokio::sync::mpsc;

use super::*;

fn pump(sink: &FrameSink, interval: Duration) -> (FrameFlow, mpsc::UnboundedReceiver<Vec<u8>>) {
    let (tx, rx) = mpsc::unbounded_channel();
    let flow = FrameFlow::default();
    let out: FrameOut = Arc::new(move |m| tx.send(m).is_ok());
    tokio::spawn(FramePump::new(sink.clone(), flow.clone(), out, interval).run());
    (flow, rx)
}

async fn recv(rx: &mut mpsc::UnboundedReceiver<Vec<u8>>) -> mooring_core::frame::Mfr1Frame {
    let msg = tokio::time::timeout(Duration::from_secs(5), rx.recv())
        .await
        .expect("frame within 5 s")
        .expect("pump alive");
    decode_mfr1(&msg).expect("valid MFR1")
}

async fn nothing(rx: &mut mpsc::UnboundedReceiver<Vec<u8>>) {
    let r = tokio::time::timeout(Duration::from_millis(120), rx.recv()).await;
    assert!(r.is_err(), "no message expected");
}

fn px(sink: &FrameSink, x: u16, v: u8) {
    sink.blit(Rect::new(x, 0, 1, 1), &[v, v, v, 255], 4, PixelOrder::Rgba).expect("blit");
}

#[tokio::test]
async fn sequence_is_ordered_and_two_messages_stay_in_flight() {
    let sink = FrameSink::new();
    sink.resize(8, 2).expect("resize");
    let (flow, mut rx) = pump(&sink, Duration::from_millis(1));
    let first = recv(&mut rx).await;
    assert_eq!(first.seq, 1);
    assert!(first.is_full() && first.is_resized());
    px(&sink, 1, 10);
    assert_eq!(recv(&mut rx).await.seq, 2);
    assert_eq!(flow.in_flight(), 2);
    px(&sink, 2, 20);
    nothing(&mut rx).await;
    assert!(!flow.ack(9), "forged seq creates no credit");
    assert!(!flow.ack(0));
    nothing(&mut rx).await;
    assert!(flow.ack(1), "oldest acked");
    let third = recv(&mut rx).await;
    assert_eq!(third.seq, 3);
    assert!(!flow.ack(1), "stale ack");
    assert!(flow.ack(3), "cumulative ack releases 2 and 3");
    assert_eq!(flow.in_flight(), 0);
}

#[tokio::test]
async fn a_slow_ui_gets_one_coalesced_newer_frame() {
    let sink = FrameSink::new();
    sink.resize(8, 1).expect("resize");
    let (flow, mut rx) = pump(&sink, Duration::from_millis(1));
    let mut mirror = Vec::new();
    recv(&mut rx).await.apply(&mut mirror);
    px(&sink, 0, 1);
    recv(&mut rx).await.apply(&mut mirror);
    // Both credits used: the next changes merge in the framebuffer.
    for v in 2..=9 {
        px(&sink, 3, v);
        px(&sink, 5, v);
    }
    nothing(&mut rx).await;
    flow.ack(2);
    let f = recv(&mut rx).await;
    assert_eq!(f.seq, 3);
    f.apply(&mut mirror);
    assert_eq!(&mirror[12..16], &[9, 9, 9, 255], "newest value, not a backlog");
    assert_eq!(&mirror[20..24], &[9, 9, 9, 255]);
    assert!(f.records.iter().all(|r| matches!(r, Mfr1Record::Rgba { .. })));
    assert_eq!(mirror, sink.snapshot().2, "mirror equals the framebuffer");
    nothing(&mut rx).await;
}

#[tokio::test]
async fn messages_respect_the_tick() {
    let sink = FrameSink::new();
    sink.resize(4, 1).expect("resize");
    let interval = Duration::from_millis(60);
    let (flow, mut rx) = pump(&sink, interval);
    let start = Instant::now();
    recv(&mut rx).await;
    for i in 0..3u8 {
        flow.ack(u32::from(i) + 1);
        px(&sink, 0, i);
        recv(&mut rx).await;
    }
    assert!(start.elapsed() >= interval * 3, "{:?}", start.elapsed());
}

#[tokio::test]
async fn pump_stops_when_the_ui_is_gone() {
    let sink = FrameSink::new();
    sink.resize(2, 1).expect("resize");
    let flow = FrameFlow::default();
    let out: FrameOut = Arc::new(|_| false);
    let task = tokio::spawn(FramePump::new(sink, flow, out, Duration::from_millis(1)).run());
    tokio::time::timeout(Duration::from_secs(5), task).await.expect("ends").expect("join");
}

#[test]
fn header_info_reads_records_and_full_flag() {
    let sink = FrameSink::new();
    sink.resize(3, 3).expect("resize");
    let msg = sink.take_frame(1).expect("frame");
    assert_eq!(header_info(&msg), (1, true));
    assert_eq!(header_info(&[0; 3]), (0, false), "short input never panics");
}

/// Synthetic 1080p sink, 25 % of the area dirty every 16 ms (a 60 Hz source); the consumer
/// decodes, applies to a mirror (what the UI texture does) and acks. Prints delivered fps
/// and p95 change→applied latency. Run with
/// `cargo test -p mooring-app --release -- --ignored frame_bench --nocapture`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "benchmark"]
#[allow(clippy::print_stdout, clippy::cast_precision_loss)] // the bench reports to stdout
async fn frame_bench() {
    const W: u16 = 1920;
    const H: u16 = 1080;
    let run_for = Duration::from_secs(5);
    let sink = FrameSink::new();
    sink.resize(W, H).expect("resize");
    let (tx, mut rx) = mpsc::unbounded_channel::<Vec<u8>>();
    let flow = FrameFlow::default();
    let out: FrameOut = Arc::new(move |m| tx.send(m).is_ok());
    let pump = FramePump::new(sink.clone(), flow.clone(), out, DEFAULT_INTERVAL);
    let stats = Arc::clone(&pump.stats);
    tokio::spawn(pump.run());
    let stamps = Arc::new(Mutex::new(VecDeque::<(u32, Instant)>::new()));
    let producer = {
        let (sink, stamps) = (sink.clone(), Arc::clone(&stamps));
        tokio::spawn(async move {
            let (rw, rh) = (W / 2, H / 2); // 25 % of the area
            let mut src = vec![0u8; usize::from(rw) * usize::from(rh) * 4];
            let start = Instant::now();
            let mut generation = 0u32;
            while start.elapsed() < run_for {
                generation += 1;
                src[..4].copy_from_slice(&generation.to_le_bytes());
                let (x, y) = if generation.is_multiple_of(2) { (0, 0) } else { (rw, rh) };
                stamps.lock().expect("s").push_back((generation, Instant::now()));
                sink.blit(Rect::new(x, y, rw, rh), &src, usize::from(rw) * 4, PixelOrder::Rgbx)
                    .expect("blit");
                tokio::time::sleep(Duration::from_millis(16)).await;
            }
        })
    };
    let mut mirror = Vec::new();
    let mut latencies = Vec::new();
    let start = Instant::now();
    let mut frames = 0u32;
    while start.elapsed() < run_for {
        let Ok(Some(msg)) = tokio::time::timeout(Duration::from_millis(500), rx.recv()).await
        else {
            continue;
        };
        let f = decode_mfr1(&msg).expect("valid");
        f.apply(&mut mirror);
        let newest = f.records.iter().filter_map(|r| match r {
            Mfr1Record::Rgba { data, .. } if data.len() >= 4 => {
                Some(u32::from_le_bytes([data[0], data[1], data[2], 255]) & 0x00ff_ffff)
            }
            _ => None,
        });
        let applied = Instant::now();
        if let Some(generation) = newest.max() {
            let mut s = stamps.lock().expect("s");
            while let Some((g, t)) = s.front().copied() {
                if g > generation {
                    break;
                }
                s.pop_front();
                if g == generation {
                    latencies.push(applied.duration_since(t));
                }
            }
        }
        frames += 1;
        flow.ack(f.seq);
    }
    producer.await.expect("producer");
    latencies.sort();
    let p95 = latencies
        .get(latencies.len().saturating_mul(95) / 100)
        .copied()
        .unwrap_or_default();
    let fps = f64::from(frames) / start.elapsed().as_secs_f64();
    let s = *stats.lock().expect("stats");
    println!(
        "frame_bench 1080p 25%: {fps:.1} fps, p95 {:.1} ms, {} frames, {} full, {:.1} MB, throttled {}",
        p95.as_secs_f64() * 1000.0,
        s.frames,
        s.full_frames,
        s.bytes as f64 / 1e6,
        s.throttled
    );
    assert!(fps >= 25.0, "pump delivered {fps:.1} fps");
}
