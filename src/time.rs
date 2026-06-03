//! Notes `TIMEDATE` (8-byte timestamp) parsing.
//!
//! TIMEDATE is the universal timestamp format used everywhere in NSF
//! databases (note creation/modification times, the DBID, replica IDs,
//! TYPE_TIME items, etc). It is two little-endian u32 "Innards":
//!
//! ```text
//! Innards[0] = number of 1/100ths of a second since midnight UTC
//! Innards[1] = high byte: timezone/DST flags
//!              low 24 bits: astronomical Julian Day Number (proleptic
//!              Julian calendar; epoch = Jan 1, 4713 BC at noon UTC)
//! ```
//!
//! Worked example from the canonical Lotus C API doc:
//!
//! ```text
//! 2:49:04 P.M. Eastern Standard Time, December 10, 1996
//! Innards[0] = 0x006CDCC0  (= 19:49:04 GMT in 1/100s since midnight)
//! Innards[1] = 0x852563FC  (= DST observed, +5 east, JDN 2,450,428)
//! ```
//!
//! High-byte layout of Innards[1]:
//!
//! ```text
//! bit 31: DST observed flag
//! bit 30: 1 = east of GMT, 0 = west of GMT
//! bits 29-28: quarter-hours offset (0-3)
//! bits 27-24: whole-hours offset (0-15)
//! ```
//!
//! Notes UNID + Database ID + Replica ID all reuse the same 8-byte
//! TIMEDATE layout for their identifiers (the value is treated as an
//! opaque identifier rather than a clock reading, but the format is
//! identical and the bytes parse cleanly into a date).

use crate::error::NsfError;

/// 8 raw bytes of a Notes TIMEDATE, exactly as they appear on disk. The
/// two u32 "Innards" are stored little-endian.
///
/// Kept as opaque bytes rather than decoded fields so the value can serve
/// double duty as an identifier (DBID, UNID-fragment, ReplicaID) and as
/// a clock reading without re-parsing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct Timedate {
    /// Innards[0]. 1/100ths of a second since midnight UTC for clock
    /// uses; arbitrary bytes for identifier uses.
    pub innards0: u32,
    /// Innards[1]. High byte = timezone/DST flags; low 24 bits =
    /// Julian Day Number for clock uses.
    pub innards1: u32,
}

impl Timedate {
    /// Parse from an 8-byte slice. Returns an error if the slice is
    /// shorter than 8 bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, NsfError> {
        if bytes.len() < 8 {
            return Err(NsfError::TooShort {
                actual: bytes.len(),
                required: 8,
            });
        }
        let innards0 = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
        let innards1 = u32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);
        Ok(Self { innards0, innards1 })
    }

    /// Treat the TIMEDATE as a clock reading and decode it. Returns
    /// `None` when the JDN is implausible (zero or far-future) which
    /// usually means the TIMEDATE is actually being used as an opaque
    /// identifier (DBID, ReplicaID).
    pub fn as_clock(&self) -> Option<DecodedTimedate> {
        let raw_julian = self.innards1 & 0x00FF_FFFF;
        // JDN range sanity: Notes 1.0 shipped in 1989 (JDN ~2,447,500).
        // Treat anything before the 1900s or after 2200 as identifier
        // bytes, not a real date.
        if !(2_400_000..=2_550_000).contains(&raw_julian) {
            return None;
        }
        let centiseconds = self.innards0;
        if centiseconds >= 8_640_000 {
            // > 24 hours of centiseconds, garbage.
            return None;
        }
        let dst = (self.innards1 & 0x8000_0000) != 0;
        let east = (self.innards1 & 0x4000_0000) != 0;
        let quarter_hours = ((self.innards1 >> 28) & 0x3) as i32;
        let hours = ((self.innards1 >> 24) & 0xF) as i32;
        let offset_minutes_abs = hours * 60 + quarter_hours * 15;
        let tz_offset_minutes = if east { offset_minutes_abs } else { -offset_minutes_abs };

        // JDN 2440588 = 1970-01-01.
        let days_since_unix_epoch = (raw_julian as i64) - 2_440_588;
        let seconds_into_day = (centiseconds / 100) as i64;
        let unix_seconds_utc = days_since_unix_epoch * 86_400 + seconds_into_day;
        let centi_remainder = (centiseconds % 100) as u32;

        Some(DecodedTimedate {
            unix_seconds_utc,
            centiseconds: centi_remainder,
            tz_offset_minutes,
            dst,
            julian_day_number: raw_julian,
        })
    }

    /// Render as an opaque 16-hex-character identifier. Used to display
    /// DBIDs and ReplicaIDs in the operator UI.
    ///
    /// Order is the on-disk byte order (Innards[0] little-endian bytes
    /// first, then Innards[1] little-endian bytes). This matches what
    /// the Notes client shows in File / Database / Properties.
    pub fn as_hex_id(&self) -> String {
        let b0 = self.innards0.to_le_bytes();
        let b1 = self.innards1.to_le_bytes();
        format!(
            "{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}",
            b0[0], b0[1], b0[2], b0[3], b1[0], b1[1], b1[2], b1[3]
        )
    }
}

/// Decoded clock representation of a TIMEDATE. Returned by
/// [`Timedate::as_clock`]. The TIMEDATE bytes themselves are preserved
/// on the parent [`Timedate`] in case downstream code needs the raw
/// identifier-style view.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DecodedTimedate {
    /// Unix seconds (UTC) corresponding to the date+time portion.
    /// Centiseconds-precision remainder is in `centiseconds`.
    pub unix_seconds_utc: i64,
    /// 0-99 centiseconds (1/100ths of a second) on top of
    /// `unix_seconds_utc`.
    pub centiseconds: u32,
    /// Originating timezone offset from UTC, in minutes. Positive =
    /// east of GMT, negative = west. Preserve this for chain-of-custody:
    /// "this email was sent from CET" is forensically distinct from
    /// "this email was sent at 14:49 UTC".
    pub tz_offset_minutes: i32,
    /// DST-observed flag from the original TIMEDATE. Notes stores DST
    /// status as a flag bit, not as a derived value; preserve it.
    pub dst: bool,
    /// Astronomical Julian Day Number (proleptic Julian calendar). JDN
    /// 2,440,588 == 1970-01-01.
    pub julian_day_number: u32,
}

impl DecodedTimedate {
    /// ISO-8601 representation in the originating timezone, e.g.
    /// `1996-12-10T14:49:04.00-05:00`. Centiseconds-precision.
    pub fn to_iso_8601(&self) -> String {
        // Adjust UTC seconds into the local timezone for display.
        let local_seconds = self.unix_seconds_utc + (self.tz_offset_minutes as i64) * 60;
        let (year, month, day) = civil_from_unix_day(local_seconds.div_euclid(86_400));
        let day_seconds = local_seconds.rem_euclid(86_400) as u32;
        let hour = day_seconds / 3600;
        let minute = (day_seconds % 3600) / 60;
        let second = day_seconds % 60;
        let tz_sign = if self.tz_offset_minutes >= 0 { '+' } else { '-' };
        let tz_abs = self.tz_offset_minutes.unsigned_abs();
        let tz_h = tz_abs / 60;
        let tz_m = tz_abs % 60;
        format!(
            "{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}.{:02}{tz_sign}{tz_h:02}:{tz_m:02}",
            self.centiseconds
        )
    }
}

/// Convert a count of days since 1970-01-01 to (year, month, day) using
/// the proleptic Gregorian calendar. Howard Hinnant's algorithm. Kept
/// inline to avoid pulling chrono into this dependency-free crate.
fn civil_from_unix_day(z: i64) -> (i32, u32, u32) {
    let z = z + 719_468; // shift epoch so March is the first month
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u32;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = (yoe as i32) + (era as i32) * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    (y, m, d)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Canonical Lotus C API example: Dec 10 1996 14:49:04 EST (-5).
    /// Innards[0] = 0x006CDCC0, Innards[1] = 0x852563FC.
    /// We just need byte-for-byte parsing and round-trip; the date math
    /// is verified by the round-trip check on a few well-known epochs.
    #[test]
    fn parses_canonical_lotus_example_bytes() {
        let bytes = [0xC0, 0xDC, 0x6C, 0x00, 0xFC, 0x63, 0x25, 0x85];
        let td = Timedate::from_bytes(&bytes).unwrap();
        assert_eq!(td.innards0, 0x006C_DCC0);
        assert_eq!(td.innards1, 0x8525_63FC);
        let clock = td.as_clock().unwrap();
        assert!(clock.dst, "DST flag should be set");
        assert!(!matches!(clock.tz_offset_minutes, 0), "offset is non-zero");
        // EST is -5 -> -300 minutes from GMT.
        assert_eq!(clock.tz_offset_minutes, -300);
        assert_eq!(clock.julian_day_number, 2_450_428);
    }

    #[test]
    fn round_trips_unix_epoch_day() {
        // JDN 2440588 = 1970-01-01 by definition.
        let mut innards1 = 2_440_588u32;
        innards1 |= 0x4000_0000; // east of GMT (offset zero either way)
        let td = Timedate {
            innards0: 0,
            innards1,
        };
        let clock = td.as_clock().unwrap();
        assert_eq!(clock.unix_seconds_utc, 0);
        let iso = clock.to_iso_8601();
        assert!(iso.starts_with("1970-01-01"), "got {iso}");
    }

    #[test]
    fn renders_iso_8601() {
        let bytes = [0xC0, 0xDC, 0x6C, 0x00, 0xFC, 0x63, 0x25, 0x85];
        let td = Timedate::from_bytes(&bytes).unwrap();
        let clock = td.as_clock().unwrap();
        let iso = clock.to_iso_8601();
        // 1996-12-10 14:49:04.00 in EST (offset -05:00).
        assert!(iso.starts_with("1996-12-10T14:49:04"), "got {iso}");
        assert!(iso.ends_with("-05:00"), "got {iso}");
    }

    #[test]
    fn rejects_short_buffer() {
        let bytes = [0x00; 4];
        let err = Timedate::from_bytes(&bytes).unwrap_err();
        assert!(matches!(err, NsfError::TooShort { .. }));
    }

    #[test]
    fn identifier_uses_render_as_hex() {
        let td = Timedate {
            innards0: 0xDEAD_BEEF,
            innards1: 0xCAFE_BABE,
        };
        // LE byte order: 0xEF 0xBE 0xAD 0xDE | 0xBE 0xBA 0xFE 0xCA.
        assert_eq!(td.as_hex_id(), "EFBEADDEBEBAFECA");
    }

    #[test]
    fn implausible_jdn_returns_none_for_clock() {
        let td = Timedate {
            innards0: 0,
            innards1: 0, // JDN = 0 (way before Notes existed)
        };
        assert!(td.as_clock().is_none());
        // But hex_id still works because identifier-uses do not care.
        assert_eq!(td.as_hex_id(), "0000000000000000");
    }
}
