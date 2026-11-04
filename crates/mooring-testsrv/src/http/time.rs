//! UTC date formatting for the mocks (SigV4 `x-amz-date`, RFC 3339, HTTP dates) without a
//! date crate. Civil-date conversion after H. Hinnant's `days_from_civil` algorithms.

use std::time::{SystemTime, UNIX_EPOCH};

pub fn now_unix() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX))
}

/// Days since 1970-01-01 of a proleptic Gregorian date.
pub fn days_from_civil(y: i64, m: u32, d: u32) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let mp = i64::from((m + 9) % 12);
    let doy = (153 * mp + 2) / 5 + i64::from(d) - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

/// `(year, month, day)` of a day count since 1970-01-01.
pub fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = u32::try_from(doy - (153 * mp + 2) / 5 + 1).unwrap_or(1);
    let m = u32::try_from(if mp < 10 { mp + 3 } else { mp - 9 }).unwrap_or(1);
    let y = yoe + era * 400 + i64::from(m <= 2);
    (y, m, d)
}

fn split(t: i64) -> (i64, u32, u32, i64, i64, i64) {
    let (y, m, d) = civil_from_days(t.div_euclid(86_400));
    let s = t.rem_euclid(86_400);
    (y, m, d, s / 3600, (s / 60) % 60, s % 60)
}

/// `20261104T120000Z`.
pub fn amz_date(t: i64) -> String {
    let (y, m, d, hh, mm, ss) = split(t);
    format!("{y:04}{m:02}{d:02}T{hh:02}{mm:02}{ss:02}Z")
}

/// Parses `YYYYMMDDTHHMMSSZ`.
pub fn parse_amz_date(s: &str) -> Option<i64> {
    let b = s.as_bytes();
    if b.len() != 16 || b[8] != b'T' || b[15] != b'Z' {
        return None;
    }
    let n = |r: std::ops::Range<usize>| s.get(r)?.parse::<u32>().ok();
    let (y, m, d) = (n(0..4)?, n(4..6)?, n(6..8)?);
    let (hh, mm, ss) = (n(9..11)?, n(11..13)?, n(13..15)?);
    if !(1..=12).contains(&m) || !(1..=31).contains(&d) || hh > 23 || mm > 59 || ss > 60 {
        return None;
    }
    let days = days_from_civil(i64::from(y), m, d);
    Some(days * 86_400 + i64::from(hh) * 3600 + i64::from(mm) * 60 + i64::from(ss))
}

/// `2026-11-04T12:00:00Z`.
pub fn rfc3339(t: i64) -> String {
    let (y, m, d, hh, mm, ss) = split(t);
    format!("{y:04}-{m:02}-{d:02}T{hh:02}:{mm:02}:{ss:02}Z")
}

/// `2026-11-04T12:00:00.000Z` (S3 `LastModified`).
pub fn rfc3339_millis(t: i64) -> String {
    let (y, m, d, hh, mm, ss) = split(t);
    format!("{y:04}-{m:02}-{d:02}T{hh:02}:{mm:02}:{ss:02}.000Z")
}

/// `Wed, 04 Nov 2026 12:00:00 GMT` (RFC 9110 IMF-fixdate).
pub fn http_date(t: i64) -> String {
    const WD: [&str; 7] = ["Thu", "Fri", "Sat", "Sun", "Mon", "Tue", "Wed"];
    const MO: [&str; 12] =
        ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];
    let (y, m, d, hh, mm, ss) = split(t);
    let wd = WD[usize::try_from(t.div_euclid(86_400).rem_euclid(7)).unwrap_or(0)];
    let mo = MO[usize::try_from(m.saturating_sub(1)).unwrap_or(0)];
    format!("{wd}, {d:02} {mo} {y:04} {hh:02}:{mm:02}:{ss:02} GMT")
}

#[cfg(test)]
mod tests {
    use super::{amz_date, http_date, parse_amz_date, rfc3339};

    #[test]
    fn formats_round_trip() {
        // 2013-05-24T00:00:00Z, the AWS SigV4 example date.
        let t = 1_369_353_600;
        assert_eq!(amz_date(t), "20130524T000000Z");
        assert_eq!(parse_amz_date("20130524T000000Z"), Some(t));
        assert_eq!(rfc3339(0), "1970-01-01T00:00:00Z");
        assert_eq!(http_date(1_793_793_600), "Wed, 04 Nov 2026 12:00:00 GMT");
        assert_eq!(parse_amz_date("2013-05-24"), None);
        for t in [0, 951_782_400, 1_709_164_800, 4_102_444_800] {
            assert_eq!(parse_amz_date(&amz_date(t)), Some(t));
        }
    }
}
