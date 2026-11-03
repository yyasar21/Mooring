//! KDF calibration properties (ADR-0006) through the public `calibrate_with` with a mock
//! timer, plus the header-side KDF bounds that protect unlock from hostile parameters.

use std::time::Duration;

use mooring_vault::{
    calibrate_with, HostLimits, KdfParams, Vault, VaultError, CALIBRATION_CANDIDATES_MIB,
    CALIBRATION_T,
};
use proptest::prelude::*;
use secrecy::SecretString;

const MIB: u32 = 1024;

/// Linear cost model: `nanos_per_kib * m * t / p`.
fn linear(nanos_per_kib: u64) -> impl FnMut(KdfParams) -> Duration {
    move |k| {
        Duration::from_nanos(
            nanos_per_kib.saturating_mul(u64::from(k.m_kib) * u64::from(k.t)) / u64::from(k.p),
        )
    }
}

fn is_candidate(m_kib: u32) -> bool {
    CALIBRATION_CANDIDATES_MIB.iter().any(|c| c * MIB == m_kib)
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    /// Invariants that must hold for any host, cap, target and (monotone) timer.
    #[test]
    fn calibrated_params_respect_every_bound(
        target_ms in 1u64..10_000,
        max_mib in 1u32..4096,
        ram_mib in proptest::option::of(1u64..131_072),
        lanes in 0u32..128,
        nanos_per_kib in 1u64..100_000,
    ) {
        let host = HostLimits { ram_kib: ram_mib.map(|r| r * 1024), lanes };
        let k = calibrate_with(Duration::from_millis(target_ms), max_mib * MIB, host, linear(nanos_per_kib));

        prop_assert!(k.validate().is_ok(), "{k:?} fails validate");
        prop_assert!(k.m_kib >= KdfParams::FLOOR.m_kib);
        prop_assert!((1..=4).contains(&k.p));
        prop_assert_eq!(k.t, CALIBRATION_T);
        prop_assert_eq!(k.p, lanes.clamp(1, 4));

        // Caps: caller max and a quarter of RAM, unless both are below the floor.
        let cap = u64::from(max_mib * MIB).min(ram_mib.map_or(u64::MAX, |r| r * 1024 / 4));
        prop_assert!(u64::from(k.m_kib) <= cap.max(u64::from(KdfParams::FLOOR.m_kib)), "{k:?} > cap {cap}");
        prop_assert!(k.m_kib <= 1024 * MIB, "never above the largest candidate");

        // Either a listed candidate or (when none fits under the cap) the cap itself.
        if !is_candidate(k.m_kib) {
            prop_assert!(u64::from(k.m_kib) == cap.max(u64::from(KdfParams::FLOOR.m_kib)));
            prop_assert!(cap < 64 * 1024);
        }
    }

    /// A larger time budget never yields a weaker memory cost.
    #[test]
    fn monotonic_in_target(
        a in 1u64..5_000, b in 1u64..5_000,
        nanos_per_kib in 1u64..20_000,
        ram_mib in 256u64..65_536,
    ) {
        let (lo, hi) = (a.min(b), a.max(b));
        let host = HostLimits { ram_kib: Some(ram_mib * 1024), lanes: 4 };
        let k_lo = calibrate_with(Duration::from_millis(lo), u32::MAX, host, linear(nanos_per_kib));
        let k_hi = calibrate_with(Duration::from_millis(hi), u32::MAX, host, linear(nanos_per_kib));
        prop_assert!(k_hi.m_kib >= k_lo.m_kib, "{lo} ms -> {k_lo:?}, {hi} ms -> {k_hi:?}");
    }

    /// More RAM or a higher cap never yields a weaker memory cost.
    #[test]
    fn monotonic_in_ram_and_cap(
        r1 in 64u64..65_536, r2 in 64u64..65_536,
        c1 in 8u32..2048, c2 in 8u32..2048,
        nanos_per_kib in 1u64..5_000,
    ) {
        let t = Duration::from_millis(500);
        let host = |r: u64| HostLimits { ram_kib: Some(r * 1024), lanes: 2 };
        let (rl, rh) = (r1.min(r2), r1.max(r2));
        let (cl, ch) = (c1.min(c2), c1.max(c2));
        let a = calibrate_with(t, cl * MIB, host(rl), linear(nanos_per_kib));
        let b = calibrate_with(t, ch * MIB, host(rh), linear(nanos_per_kib));
        prop_assert!(b.m_kib >= a.m_kib, "{a:?} vs {b:?}");
    }

    /// With a timer that is slower than the linear estimate above some size, the chosen
    /// candidate still meets the target when any candidate can.
    #[test]
    fn verification_guards_against_nonlinear_hosts(
        thrash_mib in prop::sample::select(vec![64u32, 128, 256, 512, 1024]),
        factor in 2u32..50,
    ) {
        let target = Duration::from_millis(500);
        let mut base = linear(500);
        let timer = |p: KdfParams| {
            let d = base(p);
            if p.m_kib >= thrash_mib * MIB { d * factor } else { d }
        };
        let k = calibrate_with(target, u32::MAX, HostLimits { ram_kib: None, lanes: 4 }, timer);
        let mut check = linear(500);
        let took = if k.m_kib >= thrash_mib * MIB { check(k) * factor } else { check(k) };
        prop_assert!(took <= target || k.m_kib == 64 * MIB, "{k:?} took {took:?}");
    }
}

#[test]
fn failing_derivation_is_treated_as_slow_not_chosen_large() {
    // Duration::MAX from the probe (a failed derivation) must not overflow or pick 1 GiB.
    let k = calibrate_with(
        Duration::from_millis(500),
        u32::MAX,
        HostLimits { ram_kib: Some(64 * 1024 * 1024), lanes: 4 },
        |_| Duration::MAX,
    );
    assert_eq!(k.m_kib, 64 * MIB);
    assert!(k.validate().is_ok());
}

fn header_with(params: KdfParams) -> Vec<u8> {
    let v = Vault::create(&SecretString::from("calibration pw!".to_owned()), KdfParams::TEST)
        .expect("create");
    let mut h = v.header().clone();
    h.kdf_params = params;
    h.to_bytes().expect("bytes")
}

#[test]
fn header_below_floor_is_refused_at_parse() {
    for p in [
        KdfParams { m_kib: KdfParams::FLOOR.m_kib - 1, ..KdfParams::TEST },
        KdfParams { t: 0, ..KdfParams::TEST },
        KdfParams { p: 0, ..KdfParams::TEST },
    ] {
        assert!(
            matches!(Vault::from_header_bytes(&header_with(p)), Err(VaultError::KdfParams(_))),
            "{p:?}"
        );
    }
}

/// Regression for A1-QA-1 / review B2: ADR-0006 "Security consequences" says a hostile header
/// cannot cause OOM. A tampered `vault.header.json` (or an imported export, which re-runs the
/// same check) with absurd KDF costs must be refused at parse time, above
/// `KdfParams::CEILING` (m <= 4 GiB, t <= 16, p <= 16), before any key derivation.
/// This test does NOT call unlock; it only checks that parsing rejects the header.
#[test]
fn header_with_absurd_kdf_cost_is_refused_at_parse() {
    for p in [
        KdfParams { m_kib: u32::MAX, t: 1, p: 1 },
        KdfParams { m_kib: KdfParams::TEST.m_kib, t: u32::MAX, p: 1 },
        KdfParams { m_kib: KdfParams::TEST.m_kib, t: 1, p: 0x00FF_FFFF },
    ] {
        assert!(Vault::from_header_bytes(&header_with(p)).is_err(), "{p:?} was accepted");
    }
}
