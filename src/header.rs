//! Database header (DBINFO) parsing.
//!
//! Layout per the authoritative `nsfdb_database_header.h` from libyal/
//! libnsfdb (LGPL-3.0-or-later; not vendored, fields re-declared here
//! by name). All offsets are relative to the start of DBINFO, which
//! itself starts at file offset 6 (immediately after the 6-byte file
//! header).
//!
//! ```text
//! offset  width  field
//!     0      4   format_version (ODS)
//!     4      8   database_identifier (TIMEDATE)
//!    12      2   application_version
//!    14      4   non_data_rrv_bucket_position
//!    18      4   available_non_data_rrv_identifier
//!    22      2   number_of_available_non_data_rrvs
//!    24      4   activity_log_offset
//!    28      8   bucket_modification_time (TIMEDATE)
//!    36      2   database_class
//!    38      2   database_flags
//!    40      4   bucket_descriptor_block_size
//!    44      4   bucket_descriptor_block_position (BDB)
//!    48      2   bdt_size
//!    50      4   bdt_position
//!    54      2   bdt_bitmaps
//!    56      4   data_rrv_bucket_position
//!    60      4   first_data_rrv_identifier
//!    64      4   available_data_rrv_identifier
//!    68      2   number_of_available_data_rrvs
//!    70      2   rrv_bucket_size
//!    72      2   summary_bucket_size
//!    74      2   bitmap_size
//!    76      2   allocation_granularity
//!    78      4   extention_granularity
//!    82      4   file_size (in 256-byte units)
//!    86..       (additional fields not yet consumed by this crate)
//! ```
//!
//! All multi-byte integers are little-endian.
//!
//! Empirical notes from the 17-sample corpus:
//!
//! - `bucket_descriptor_block_position` can legitimately be zero on
//!   fresh templates that have not yet been instantiated. The
//!   `data_rrv_bucket_position` is the more reliable "where data
//!   actually lives" pointer; use it to seed RRV walking.
//! - Database flag bit 0x0040 is NOT the encryption flag despite
//!   operator-forum lore. Every file in the corpus (templates and
//!   real .nsfs alike) has that bit set, and none are encrypted. The
//!   authoritative bit position for "Local Database Encryption" lives
//!   in HCL's `dbopts.h` which is not yet imported. Encryption
//!   detection is deferred to a later slice; the constant in
//!   `flags::DBFLAG_LOCAL_PROTECTED` is left as a known-uncertain
//!   placeholder with `is_database_encrypted` returning a documented
//!   "unknown" via `Option<bool>`.

use crate::detect::{identify_file_strict, FileKind};
use crate::error::NsfError;
use crate::ods::Ods;
use crate::time::Timedate;

const DBINFO_START: usize = 6;
const DBINFO_CORE_MIN: usize = 128;

/// Flag bits in DBINFO's `database_flags` u16 at offset 38. Bit
/// interpretation here is what we have verified against the 17-sample
/// corpus; entries marked `tentative` are still uncertain and not yet
/// used to drive any feature.
pub mod flags {
    /// Database is a template (.ntf semantics) rather than a regular
    /// database (.nsf). Verified empirically against the 8-template +
    /// 5-locale-template + 4-real-nsf corpus: set on every .ntf in the
    /// corpus, clear on every .nsf.
    pub const DBFLAG_TEMPLATE: u16 = 0x0010;
}

/// Parsed database header. Self-contained snapshot of DBINFO - the
/// reader does not retain a reference into the file bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DbHeader {
    /// db_header_size from the outermost 6-byte file header.
    pub db_header_size: u32,
    /// ODS version (DBINFO offset 0).
    pub ods: Ods,
    /// Database identifier (DBINFO offset 4). 8-byte TIMEDATE used as
    /// an opaque identifier.
    pub database_id: Timedate,
    /// Application-defined version (DBINFO offset 12). Free-form u16
    /// for the form designer's use.
    pub app_version: u16,
    /// File offset of the bucket holding non-data RRVs (DBINFO offset
    /// 14). Design notes, ACL notes, replication info, etc.
    pub non_data_rrv_bucket_position: u32,
    /// (next) available non-data RRV identifier (DBINFO offset 18).
    pub available_non_data_rrv_identifier: u32,
    /// Number of available non-data RRVs (DBINFO offset 22).
    pub number_of_available_non_data_rrvs: u16,
    /// Activity log offset (DBINFO offset 24).
    pub activity_log_offset: u32,
    /// Most recent bucket modification time (DBINFO offset 28).
    pub bucket_modification: Timedate,
    /// Database class (DBINFO offset 36). 2-byte identifier of what
    /// kind of database this is (mailbox / template / design / etc).
    pub database_class: u16,
    /// Database flags word (DBINFO offset 38). Use [`flags`]
    /// constants to interpret; only [`flags::DBFLAG_TEMPLATE`] is
    /// verified.
    pub database_flags: u16,
    /// Bucket Descriptor Block size (DBINFO offset 40).
    pub bucket_descriptor_block_size: u32,
    /// Bucket Descriptor Block position (DBINFO offset 44). Can be
    /// zero on freshly-instantiated templates; use
    /// [`Self::data_rrv_bucket_position`] for "where notes live"
    /// rather than this.
    pub bucket_descriptor_block_position: u32,
    /// Bucket Descriptor Table size (DBINFO offset 48).
    pub bdt_size: u16,
    /// Bucket Descriptor Table position (DBINFO offset 50).
    pub bdt_position: u32,
    /// Bucket Descriptor Table bitmaps (DBINFO offset 54).
    pub bdt_bitmaps: u16,
    /// File offset of the bucket holding data RRVs (DBINFO offset 56).
    /// THIS is the entry point for note enumeration. Non-zero on any
    /// database that contains notes.
    pub data_rrv_bucket_position: u32,
    /// First data RRV identifier (DBINFO offset 60).
    pub first_data_rrv_identifier: u32,
    /// (next) available data RRV identifier (DBINFO offset 64).
    pub available_data_rrv_identifier: u32,
    /// Number of available data RRVs (DBINFO offset 68).
    pub number_of_available_data_rrvs: u16,
    /// Size of each RRV bucket in bytes (DBINFO offset 70).
    pub rrv_bucket_size: u16,
    /// Size of each summary bucket in bytes (DBINFO offset 72).
    pub summary_bucket_size: u16,
    /// Bitmap allocation map size (DBINFO offset 74).
    pub bitmap_size: u16,
    /// Allocation granularity (DBINFO offset 76).
    pub allocation_granularity: u16,
    /// Extention granularity (DBINFO offset 78). (Spelling matches the
    /// libnsfdb header which inherited the typo from the Notes C API.)
    pub extention_granularity: u32,
    /// File size in 256-byte units (DBINFO offset 82). Multiply by 256
    /// to get the bytes the database knows about; may diverge from the
    /// OS-reported file size if the file was truncated since the
    /// header was last rewritten.
    pub file_size_pages: u32,
}

impl DbHeader {
    /// Parse the file header + DBINFO core from a byte slice containing
    /// at least the first 6 + 128 = 134 bytes of the file.
    pub fn parse(bytes: &[u8]) -> Result<Self, NsfError> {
        let file_kind = identify_file_strict(bytes)?;
        let db_header_size = match file_kind {
            FileKind::Nsf { db_header_size } => db_header_size,
            FileKind::NotNsf { reason } => {
                let _ = reason;
                return Err(NsfError::BadFileSignature { observed: [0, 0] });
            }
        };

        let required = DBINFO_START + DBINFO_CORE_MIN;
        if bytes.len() < required {
            return Err(NsfError::TooShort {
                actual: bytes.len(),
                required,
            });
        }

        let d = &bytes[DBINFO_START..DBINFO_START + DBINFO_CORE_MIN];

        // Helper closures: little-endian readers at the given DBINFO
        // offset. Keeps the field-extraction lines visually aligned with
        // the struct definition above and lets the optimizer fold the
        // bounds checks (we asserted DBINFO_CORE_MIN above).
        let u16_at = |o: usize| u16::from_le_bytes([d[o], d[o + 1]]);
        let u32_at = |o: usize| u32::from_le_bytes([d[o], d[o + 1], d[o + 2], d[o + 3]]);

        let ods_raw = u32_at(0);
        let database_id = Timedate::from_bytes(&d[4..12])?;
        let app_version = u16_at(12);
        let non_data_rrv_bucket_position = u32_at(14);
        let available_non_data_rrv_identifier = u32_at(18);
        let number_of_available_non_data_rrvs = u16_at(22);
        let activity_log_offset = u32_at(24);
        let bucket_modification = Timedate::from_bytes(&d[28..36])?;
        let database_class = u16_at(36);
        let database_flags = u16_at(38);
        let bucket_descriptor_block_size = u32_at(40);
        let bucket_descriptor_block_position = u32_at(44);
        let bdt_size = u16_at(48);
        let bdt_position = u32_at(50);
        let bdt_bitmaps = u16_at(54);
        let data_rrv_bucket_position = u32_at(56);
        let first_data_rrv_identifier = u32_at(60);
        let available_data_rrv_identifier = u32_at(64);
        let number_of_available_data_rrvs = u16_at(68);
        let rrv_bucket_size = u16_at(70);
        let summary_bucket_size = u16_at(72);
        let bitmap_size = u16_at(74);
        let allocation_granularity = u16_at(76);
        let extention_granularity = u32_at(78);
        let file_size_pages = u32_at(82);

        Ok(Self {
            db_header_size,
            ods: Ods::new(ods_raw),
            database_id,
            app_version,
            non_data_rrv_bucket_position,
            available_non_data_rrv_identifier,
            number_of_available_non_data_rrvs,
            activity_log_offset,
            bucket_modification,
            database_class,
            database_flags,
            bucket_descriptor_block_size,
            bucket_descriptor_block_position,
            bdt_size,
            bdt_position,
            bdt_bitmaps,
            data_rrv_bucket_position,
            first_data_rrv_identifier,
            available_data_rrv_identifier,
            number_of_available_data_rrvs,
            rrv_bucket_size,
            summary_bucket_size,
            bitmap_size,
            allocation_granularity,
            extention_granularity,
            file_size_pages,
        })
    }

    /// True if the database is flagged as a template (.ntf semantics).
    /// Verified empirically against the corpus: set on every .ntf,
    /// clear on every .nsf.
    pub fn is_template(&self) -> bool {
        self.database_flags & flags::DBFLAG_TEMPLATE != 0
    }

    /// Encryption detection: NOT IMPLEMENTED in v0.1.
    ///
    /// The libnsfdb spec leaves the encryption-flag bit position as
    /// TODO. The widely-cited 0x0040 value does NOT match the corpus
    /// (every sample has that bit set; none are encrypted). The
    /// authoritative bit lives in HCL's `dbopts.h` which we have not
    /// yet imported.
    ///
    /// Returns `None` until detection is reliable. The viewer surfaces
    /// this as "encryption detection deferred" rather than reporting
    /// false negatives.
    pub fn is_database_encrypted(&self) -> Option<bool> {
        None
    }

    /// Convenience: file-size estimate from the header's
    /// 256-byte-increment field. Multiply by 256.
    pub fn file_size_from_header_bytes(&self) -> u64 {
        (self.file_size_pages as u64) * 256
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a minimal-but-valid header for unit tests. Values are
    /// chosen to be unambiguous (no zeros that overlap with field
    /// defaults).
    fn synthetic_header(ods: u32, flags: u16) -> Vec<u8> {
        let mut buf = vec![0u8; 256];
        // File header: LSIG + db_header_size = 1024.
        buf[0] = 0x1A;
        buf[1] = 0x00;
        buf[2..6].copy_from_slice(&1024u32.to_le_bytes());
        // DBINFO @ file offset 6.
        // ODS at DBINFO offset 0 (file 6).
        buf[6..10].copy_from_slice(&ods.to_le_bytes());
        // database_flags at DBINFO offset 38 (file 44).
        buf[44..46].copy_from_slice(&flags.to_le_bytes());
        // bucket_descriptor_block_position at DBINFO offset 44 (file 50).
        buf[50..54].copy_from_slice(&0x0000_4000u32.to_le_bytes());
        // data_rrv_bucket_position at DBINFO offset 56 (file 62).
        buf[62..66].copy_from_slice(&0x0000_2af0u32.to_le_bytes());
        // file_size at DBINFO offset 82 (file 88).
        buf[88..92].copy_from_slice(&5000u32.to_le_bytes());
        buf
    }

    #[test]
    fn parses_synthetic_ods_53_unencrypted() {
        let buf = synthetic_header(53, 0);
        let h = DbHeader::parse(&buf).unwrap();
        assert_eq!(h.db_header_size, 1024);
        assert_eq!(h.ods.raw, 53);
        assert!(!h.is_template());
        assert!(h.is_database_encrypted().is_none(), "encryption detection deferred");
        assert_eq!(h.bucket_descriptor_block_position, 0x0000_4000);
        assert_eq!(h.data_rrv_bucket_position, 0x0000_2af0);
        assert_eq!(h.file_size_pages, 5000);
        assert_eq!(h.file_size_from_header_bytes(), 5000 * 256);
    }

    #[test]
    fn flags_template_decodes_correctly() {
        let buf = synthetic_header(53, flags::DBFLAG_TEMPLATE);
        let h = DbHeader::parse(&buf).unwrap();
        assert!(h.is_template());
    }

    #[test]
    fn rejects_bad_magic() {
        let mut buf = synthetic_header(53, 0);
        buf[0] = 0xDE;
        buf[1] = 0xAD;
        let err = DbHeader::parse(&buf).unwrap_err();
        assert!(matches!(err, NsfError::BadFileSignature { .. }));
    }

    #[test]
    fn rejects_too_short_for_dbinfo() {
        let buf: Vec<u8> = vec![0x1A, 0x00, 0x00, 0x04, 0x00, 0x00];
        let err = DbHeader::parse(&buf).unwrap_err();
        assert!(matches!(err, NsfError::TooShort { .. }));
    }

    #[test]
    fn ods_supported_check_works_via_header() {
        let buf_modern = synthetic_header(53, 0);
        let h_modern = DbHeader::parse(&buf_modern).unwrap();
        assert!(h_modern.ods.is_supported_for_enumeration());

        let buf_legacy = synthetic_header(17, 0);
        let h_legacy = DbHeader::parse(&buf_legacy).unwrap();
        assert!(!h_legacy.ods.is_supported_for_enumeration());
    }

    #[test]
    fn parses_canonical_comparedbs_ntf_header_bytes() {
        // First 96 bytes of comparedbs.ntf from the corpus. Pinned here
        // so any future regression in field-offset arithmetic is
        // immediately visible. Generated by xxd of the real file.
        #[rustfmt::skip]
        let bytes: &[u8] = &[
            0x1a, 0x00, 0x00, 0x04, 0x00, 0x00, 0x34, 0x00,
            0x00, 0x00, 0xa9, 0xf4, 0x61, 0x00, 0x0c, 0x88,
            0x25, 0x85, 0x00, 0x00, 0xe0, 0x03, 0x00, 0x00,
            0xf6, 0x03, 0x00, 0x00, 0x40, 0x01, 0x00, 0x00,
            0x00, 0x00, 0x3f, 0x08, 0x62, 0x00, 0x0c, 0x88,
            0x25, 0x00, 0x04, 0xff, 0x50, 0x42, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0xf0, 0x2a,
            0x00, 0x00, 0xf6, 0x08, 0x00, 0x00, 0x5a, 0x09,
            0x00, 0x00, 0xe3, 0x01, 0x00, 0x10, 0x00, 0x20,
            0x00, 0x10, 0x00, 0x01, 0x00, 0x00, 0x01, 0x00,
            0x00, 0x30, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        // Pad to the DBINFO_CORE_MIN size with zeros (rest is unused).
        let mut buf = bytes.to_vec();
        buf.resize(256, 0);
        let h = DbHeader::parse(&buf).unwrap();
        // ODS 52 = Notes 9.0.1.
        assert_eq!(h.ods.raw, 52);
        // Template flag set (.ntf).
        assert!(h.is_template(), "comparedbs.ntf flags = 0x{:04X}", h.database_flags);
        // BDB is genuinely zero on this template; data RRV is at 0x2af0.
        assert_eq!(h.bucket_descriptor_block_position, 0);
        assert_eq!(h.data_rrv_bucket_position, 0x2af0);
        // File size 0x3000 pages = 0x300000 = 3 MB (matches actual 3.1 MB).
        assert_eq!(h.file_size_pages, 0x3000);
        // RRV bucket size = 0x1000 = 4 KB pages, the modern Domino default.
        assert_eq!(h.rrv_bucket_size, 0x1000);
    }
}
