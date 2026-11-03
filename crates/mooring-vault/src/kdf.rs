//! Argon2id parameters, derivation and host calibration (ADR-0002, ADR-0006).

use std::time::{Duration, Instant};

use argon2::{Algorithm, Argon2, Params, Version};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::error::VaultError;

/// Length of the derived key encryption key.
pub const KEY_LEN: usize = 32;
/// Salt length in bytes.
pub const SALT_LEN: usize = 16;

/// Memory-cost candidates for calibration, in MiB (ADR-0006).
pub const CALIBRATION_CANDIDATES_MIB: [u32; 5] = [64, 128, 256, 512, 1024];
/// Time cost used by calibrated parameters.
pub const CALIBRATION_T: u32 = 3;
/// Default calibration target: one derivation in about half a second.
pub const CALIBRATION_TARGET: Duration = Duration::from_millis(500);

/// Argon2id cost parameters, stored in the vault header.
///
/// Defaults follow the OWASP 2024 "first choice" shape scaled up for a desktop app:
/// 256 MiB memory, 3 passes, 4 lanes. [`KdfParams::calibrate`] fits the cost to the host.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct KdfParams {
    /// Memory cost in KiB.
    pub m_kib: u32,
    /// Time cost (passes).
    pub t: u32,
    /// Parallelism (lanes).
    pub p: u32,
}

impl KdfParams {
    /// Production defaults.
    pub const DEFAULT: Self = Self { m_kib: 256 * 1024, t: 3, p: 4 };

    /// Cheap parameters for unit tests only. Never written by the application.
    pub const TEST: Self = Self { m_kib: 8 * 1024, t: 1, p: 1 };

    /// Lower bounds the vault refuses to go below when *reading* a header, so a downgraded
    /// header cannot make brute force cheap.
    pub const FLOOR: Self = Self { m_kib: 8 * 1024, t: 1, p: 1 };

    /// Upper bounds the vault refuses to go above when *reading* a header (4 GiB, 16 passes,
    /// 16 lanes: 4x the largest calibration candidate), so a hostile header or import cannot
    /// make unlock allocate terabytes or spin forever (A1 review B2).
    pub const CEILING: Self = Self { m_kib: 4 * 1024 * 1024, t: 16, p: 16 };

    /// Check against the floor, the ceiling and Argon2's own limits.
    pub fn validate(self) -> Result<(), VaultError> {
        if self.m_kib < Self::FLOOR.m_kib || self.t < Self::FLOOR.t || self.p < Self::FLOOR.p {
            return Err(VaultError::KdfParams("below the minimum floor".into()));
        }
        let c = Self::CEILING;
        if self.m_kib > c.m_kib || self.t > c.t || self.p > c.p {
            return Err(VaultError::KdfParams("above the maximum ceiling".into()));
        }
        Params::new(self.m_kib, self.t, self.p, Some(KEY_LEN))
            .map(|_| ())
            .map_err(|e| VaultError::KdfParams(e.to_string()))
    }

    /// Measure Argon2id on this host and pick the largest memory cost from
    /// [`CALIBRATION_CANDIDATES_MIB`] that is `<= max_m_kib`, `<= 1/4` of physical RAM and
    /// whose single derivation finishes within `target`; `t = 3`,
    /// `p = min(4, available cores)`.
    ///
    /// Never below [`KdfParams::FLOOR`]. When even the smallest eligible candidate is slower
    /// than `target` it is used anyway: a slow unlock beats a weak vault. Runs real Argon2
    /// derivations (up to the chosen memory cost) — call it at creation / password change only.
    pub fn calibrate(target: Duration, max_m_kib: u32) -> KdfParams {
        let host = HostLimits { ram_kib: physical_ram_kib(), lanes: default_lanes() };
        calibrate_with(target, max_m_kib, host, measure_derivation)
    }
}

impl Default for KdfParams {
    fn default() -> Self {
        Self::DEFAULT
    }
}

/// What calibration needs to know about the host. Separate so tests can fake it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HostLimits {
    /// Physical RAM in KiB, if the OS reports it.
    pub ram_kib: Option<u64>,
    /// Argon2 lanes to use; clamped to `1..=4`.
    pub lanes: u32,
}

/// Calibration with an injectable timer. `measure` runs (or simulates) one derivation with the
/// given parameters and returns its wall time.
///
/// Algorithm (ADR-0006): one probe at the floor memory cost with the final `t`/`p`, scaled
/// linearly in memory to estimate every candidate; the largest candidate whose estimate fits is
/// verified by one real run, stepping down while verification is slower than `target`.
pub fn calibrate_with(
    target: Duration,
    max_m_kib: u32,
    host: HostLimits,
    mut measure: impl FnMut(KdfParams) -> Duration,
) -> KdfParams {
    let lanes = host.lanes.clamp(1, 4);
    let shape = |m_kib: u32| KdfParams { m_kib, t: CALIBRATION_T, p: lanes };

    // Hard ceiling: caller's cap and a quarter of RAM, never below the floor.
    let ram_cap = host.ram_kib.map_or(u64::from(u32::MAX), |r| r / 4);
    let ceiling = u32::try_from(u64::from(max_m_kib).min(ram_cap))
        .unwrap_or(u32::MAX)
        .max(KdfParams::FLOOR.m_kib);

    let eligible: Vec<u32> =
        CALIBRATION_CANDIDATES_MIB.iter().map(|mib| mib * 1024).filter(|m| *m <= ceiling).collect();
    let Some(&smallest) = eligible.first() else {
        tracing::warn!(m_kib = ceiling, "kdf calibration: no candidate fits, using ceiling");
        return shape(ceiling);
    };

    let probe = shape(KdfParams::FLOOR.m_kib);
    let per_kib_nanos = measure(probe).as_nanos() / u128::from(probe.m_kib);
    let estimate = |m: u32| {
        Duration::from_nanos(
            u64::try_from(per_kib_nanos.saturating_mul(u128::from(m))).unwrap_or(u64::MAX),
        )
    };

    let start = eligible.iter().rposition(|m| estimate(*m) <= target).unwrap_or(0);
    for &m in eligible[..=start].iter().rev() {
        let params = shape(m);
        let took = measure(params);
        if took <= target || m == smallest {
            tracing::info!(
                m_kib = m,
                t = params.t,
                p = params.p,
                ms = u64::try_from(took.as_millis()).unwrap_or(u64::MAX),
                "kdf calibrated"
            );
            return params;
        }
    }
    shape(smallest)
}

/// One real Argon2id derivation, timed. A failure counts as "infinitely slow".
fn measure_derivation(params: KdfParams) -> Duration {
    let start = Instant::now();
    match derive_kek(b"mooring-calibration", &[0u8; SALT_LEN], params) {
        Ok(_) => start.elapsed(),
        Err(_) => Duration::MAX,
    }
}

/// Physical RAM in KiB as reported by the OS (queried once per process).
fn physical_ram_kib() -> Option<u64> {
    static RAM: std::sync::OnceLock<Option<u64>> = std::sync::OnceLock::new();
    *RAM.get_or_init(query_physical_ram_kib)
}

fn query_physical_ram_kib() -> Option<u64> {
    use sysinfo::{MemoryRefreshKind, RefreshKind, System};
    let sys = System::new_with_specifics(
        RefreshKind::nothing().with_memory(MemoryRefreshKind::nothing().with_ram()),
    )
    .ok()?;
    match sys.total_memory() / 1024 {
        0 => None,
        kib => Some(kib),
    }
}

/// `min(4, available cores)`, at least 1.
fn default_lanes() -> u32 {
    std::thread::available_parallelism()
        .map_or(1, |n| u32::try_from(n.get()).unwrap_or(4))
        .clamp(1, 4)
}

/// Derive the key encryption key from the password.
pub(crate) fn derive_kek(
    password: &[u8],
    salt: &[u8; SALT_LEN],
    params: KdfParams,
) -> Result<Zeroizing<[u8; KEY_LEN]>, VaultError> {
    derive_kek_with_ram(password, salt, params, physical_ram_kib())
}

/// [`derive_kek`] with an injectable RAM size. Refuses, before allocating, a memory cost above
/// half of physical RAM (when known): a header calibrated on a big machine fails cleanly on a
/// small one instead of swapping it to death (A1 review B2).
pub(crate) fn derive_kek_with_ram(
    password: &[u8],
    salt: &[u8; SALT_LEN],
    params: KdfParams,
    ram_kib: Option<u64>,
) -> Result<Zeroizing<[u8; KEY_LEN]>, VaultError> {
    params.validate()?;
    if ram_kib.is_some_and(|ram| u64::from(params.m_kib) > ram / 2) {
        return Err(VaultError::KdfParams("needs more memory than this host has".into()));
    }
    let p = Params::new(params.m_kib, params.t, params.p, Some(KEY_LEN))
        .map_err(|e| VaultError::KdfParams(e.to_string()))?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, p);
    let mut out = Zeroizing::new([0u8; KEY_LEN]);
    argon
        .hash_password_into(password, salt, out.as_mut())
        .map_err(|e| VaultError::KdfParams(e.to_string()))?;
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    const MIB: u32 = 1024;

    /// Linear fake: `nanos_per_kib * m * t / p`.
    fn linear(nanos_per_kib: u64) -> impl FnMut(KdfParams) -> Duration {
        move |k: KdfParams| {
            Duration::from_nanos(
                nanos_per_kib * u64::from(k.m_kib) * u64::from(k.t) / u64::from(k.p),
            )
        }
    }

    fn host(ram_mib: u64, lanes: u32) -> HostLimits {
        HostLimits { ram_kib: Some(ram_mib * 1024), lanes }
    }

    fn ms(n: u64) -> Duration {
        Duration::from_millis(n)
    }

    #[test]
    fn floor_is_enforced() {
        assert!(KdfParams { m_kib: 1024, t: 1, p: 1 }.validate().is_err());
        assert!(KdfParams::TEST.validate().is_ok());
        assert!(KdfParams::DEFAULT.validate().is_ok());
    }

    /// Review L3: `argon2/zeroize` wipes the password-derived initial and final block hashes.
    /// `Block: Zeroize` only exists with that feature, so this does not compile without it.
    #[test]
    fn argon2_zeroize_feature_is_enabled() {
        fn is_zeroize<T: zeroize::Zeroize>() {}
        is_zeroize::<argon2::Block>();
    }

    #[test]
    fn ceiling_is_enforced() {
        assert!(KdfParams::CEILING.validate().is_ok());
        let c = KdfParams::CEILING;
        for bad in [
            KdfParams { m_kib: u32::MAX, ..KdfParams::TEST },
            KdfParams { m_kib: c.m_kib + 1, ..KdfParams::TEST },
            KdfParams { t: 17, ..KdfParams::TEST },
            KdfParams { p: 17, ..KdfParams::TEST },
            KdfParams { m_kib: u32::MAX, t: u32::MAX, p: 0x00FF_FFFF },
        ] {
            assert_eq!(
                bad.validate(),
                Err(VaultError::KdfParams("above the maximum ceiling".into())),
                "{bad:?}"
            );
        }
    }

    #[test]
    fn derive_refuses_more_than_half_of_ram() {
        let too_big = VaultError::KdfParams("needs more memory than this host has".into());
        let salt = [1; SALT_LEN];
        // TEST needs 8 MiB: refused with 8 MiB of RAM (half = 4), fine with 16 MiB or unknown.
        let r = derive_kek_with_ram(b"pw", &salt, KdfParams::TEST, Some(8 * 1024));
        assert_eq!(r.err(), Some(too_big));
        assert!(derive_kek_with_ram(b"pw", &salt, KdfParams::TEST, Some(16 * 1024)).is_ok());
        assert!(derive_kek_with_ram(b"pw", &salt, KdfParams::TEST, None).is_ok());
    }

    #[test]
    fn same_inputs_same_key_different_salt_different_key() {
        let a = derive_kek(b"pw", &[1; SALT_LEN], KdfParams::TEST).expect("kdf");
        let b = derive_kek(b"pw", &[1; SALT_LEN], KdfParams::TEST).expect("kdf");
        let c = derive_kek(b"pw", &[2; SALT_LEN], KdfParams::TEST).expect("kdf");
        assert_eq!(*a, *b);
        assert_ne!(*a, *c);
    }

    #[test]
    fn calibrate_picks_largest_candidate_within_target() {
        // 1 µs/KiB, t=3, p=4: 256 MiB = 196 ms, 512 MiB = 393 ms, 1 GiB = 786 ms.
        let k = calibrate_with(ms(500), u32::MAX, host(64 * 1024, 4), linear(1000));
        assert_eq!(k, KdfParams { m_kib: 512 * MIB, t: CALIBRATION_T, p: 4 });
    }

    #[test]
    fn calibrate_is_monotonic_in_target() {
        let mut last = 0;
        for t in [10, 50, 100, 200, 400, 800, 1600, 5000] {
            let k = calibrate_with(ms(t), u32::MAX, host(64 * 1024, 4), linear(1000));
            assert!(k.m_kib >= last, "target {t} ms went down to {}", k.m_kib);
            assert!(k.validate().is_ok());
            last = k.m_kib;
        }
        assert_eq!(last, 1024 * MIB);
    }

    #[test]
    fn calibrate_output_always_validates() {
        for cap in [0, 1024, 64 * MIB, 300 * MIB, u32::MAX] {
            for ram in [16, 1024, 64 * 1024, 1024 * 1024] {
                for lanes in [0, 1, 4, 64] {
                    let k = calibrate_with(ms(5000), cap, host(ram, lanes), linear(1));
                    assert!(k.validate().is_ok(), "cap {cap} ram {ram} lanes {lanes}: {k:?}");
                }
            }
        }
    }

    #[test]
    fn calibrate_respects_max_and_ram_cap() {
        let k = calibrate_with(ms(5000), 128 * MIB, host(64 * 1024, 4), linear(1));
        assert_eq!(k.m_kib, 128 * MIB);
        // 1 GiB RAM -> a quarter is 256 MiB
        let k = calibrate_with(ms(5000), u32::MAX, host(1024, 4), linear(1));
        assert_eq!(k.m_kib, 256 * MIB);
        // unknown RAM: only the caller cap applies
        let unknown = HostLimits { ram_kib: None, lanes: 2 };
        let k = calibrate_with(ms(5000), u32::MAX, unknown, linear(1));
        assert_eq!(k, KdfParams { m_kib: 1024 * MIB, t: CALIBRATION_T, p: 2 });
    }

    #[test]
    fn calibrate_never_goes_below_floor() {
        // Very slow host: the smallest candidate is still used.
        let k = calibrate_with(ms(1), u32::MAX, host(64 * 1024, 1), linear(1_000_000));
        assert_eq!(k, KdfParams { m_kib: 64 * MIB, t: CALIBRATION_T, p: 1 });
        // Tiny cap or tiny RAM: no candidate fits, the floor wins.
        let k = calibrate_with(ms(1000), 1024, host(64 * 1024, 4), linear(1));
        assert_eq!(k.m_kib, KdfParams::FLOOR.m_kib);
        assert!(k.validate().is_ok());
        let k = calibrate_with(ms(1000), u32::MAX, host(16, 4), linear(1));
        assert_eq!(k.m_kib, KdfParams::FLOOR.m_kib);
    }

    #[test]
    fn calibrate_lanes_are_clamped() {
        let k = calibrate_with(ms(1000), u32::MAX, host(64 * 1024, 64), linear(1));
        assert_eq!(k.p, 4);
        let k = calibrate_with(ms(1000), u32::MAX, host(64 * 1024, 0), linear(1));
        assert_eq!(k.p, 1);
    }

    #[test]
    fn calibrate_steps_down_when_verification_is_slower_than_estimate() {
        // The probe is linear, but anything >= 512 MiB thrashes (10x slower).
        let mut calls = Vec::new();
        let mut fake = linear(1000);
        let k = calibrate_with(ms(500), u32::MAX, host(64 * 1024, 4), |p: KdfParams| {
            calls.push(p.m_kib);
            let base = fake(p);
            if p.m_kib >= 512 * MIB {
                base * 10
            } else {
                base
            }
        });
        assert_eq!(k.m_kib, 256 * MIB);
        assert_eq!(calls, vec![KdfParams::FLOOR.m_kib, 512 * MIB, 256 * MIB]);
    }

    #[test]
    fn default_lanes_is_in_range() {
        assert!((1..=4).contains(&default_lanes()));
    }

    #[test]
    #[ignore = "real Argon2 runs with up to 1 GiB; run with --ignored --release"]
    fn calibrate_real_host_smoke() {
        let k = KdfParams::calibrate(CALIBRATION_TARGET, 1024 * MIB);
        assert!(k.validate().is_ok());
        assert_eq!(k.t, CALIBRATION_T);
        assert!(k.m_kib >= KdfParams::FLOOR.m_kib);
    }
}
