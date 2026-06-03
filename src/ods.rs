//! On-Disk Structure (ODS) version mapping.
//!
//! The ODS version is a u32 at offset 0 of DBINFO that pins the
//! database file format generation. Notes / Domino is broadly
//! backwards-compatible: a parser targeting ODS 51 reads ODS 43
//! without modification; ODS 53 adds 8-byte file positions for some
//! structures but otherwise rhymes with ODS 51.
//!
//! Mapping per Daniel Nashed's blog (corroborated against HCL release
//! notes):
//!
//! ```text
//! ODS 16   Notes 1.x - 2.x
//! ODS 17   Notes 3.x
//! ODS 20   Notes 4.x
//! ODS 41   Notes 5.x
//! ODS 43   Notes 6.x, 7.x
//! ODS 48   Notes 8.0
//! ODS 51   Notes 8.5, 9.0
//! ODS 52   Notes 9.0.1
//! ODS 53   Notes 10, 11, 12, 14 (HCL Notes)
//! ```

use std::fmt;

/// Decoded ODS version with the human-readable Notes/Domino release.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ods {
    /// Raw ODS version number as read from DBINFO offset 0.
    pub raw: u32,
}

impl Ods {
    /// Wrap a raw ODS u32.
    pub const fn new(raw: u32) -> Self {
        Self { raw }
    }

    /// Best-known Notes / Domino client family this ODS corresponds to.
    /// Returns a static string for known values, or "unknown ODS" for
    /// anything not in the published mapping.
    pub fn client_family(&self) -> &'static str {
        match self.raw {
            16 => "Notes 1.x - 2.x",
            17 => "Notes 3.x",
            20 => "Notes 4.x",
            41 => "Notes 5.x",
            43 => "Notes 6.x, 7.x",
            48 => "Notes 8.0",
            51 => "Notes 8.5, 9.0",
            52 => "Notes 9.0.1",
            53 => "Notes 10, 11, 12, 14 (HCL)",
            _ => "unknown ODS",
        }
    }

    /// True if this is an ODS version Sherlock supports for note
    /// enumeration. ODS < 20 is pre-Notes-4 and uses 4-byte RRV entries
    /// instead of the 8-byte format Sherlock reads; safe to refuse.
    pub fn is_supported_for_enumeration(&self) -> bool {
        self.raw >= 20 && self.raw <= 53
    }

    /// True for the modern 64-bit-positions HCL ODS 53. Some structures
    /// (BBlock file positions in particular) widen from 4 to 8 bytes at
    /// this ODS.
    pub fn is_modern_64bit_positions(&self) -> bool {
        self.raw >= 53
    }
}

impl fmt::Display for Ods {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ODS {} ({})", self.raw, self.client_family())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn maps_modern_hcl_ods_53() {
        let ods = Ods::new(53);
        assert!(ods.client_family().contains("HCL"));
        assert!(ods.is_supported_for_enumeration());
        assert!(ods.is_modern_64bit_positions());
    }

    #[test]
    fn maps_classic_ods_43_notes_6_7() {
        let ods = Ods::new(43);
        assert!(ods.client_family().contains("6.x"));
        assert!(ods.is_supported_for_enumeration());
        assert!(!ods.is_modern_64bit_positions());
    }

    #[test]
    fn refuses_pre_notes_4_ods() {
        for v in [16, 17, 18, 19] {
            assert!(!Ods::new(v).is_supported_for_enumeration());
        }
    }

    #[test]
    fn unknown_ods_falls_back_cleanly() {
        let ods = Ods::new(999);
        assert_eq!(ods.client_family(), "unknown ODS");
        assert!(!ods.is_supported_for_enumeration());
    }

    #[test]
    fn display_includes_raw_and_family() {
        let s = format!("{}", Ods::new(51));
        assert!(s.contains("51"));
        assert!(s.contains("8.5"));
    }
}
