//! Superblock parsing.
//!
//! The superblock is the second-tier metadata structure in an NSF database.
//! [`crate::info2::Information2`] holds the file positions of **four**
//! superblock copies: Domino writes all four on every commit so a crash
//! leaves at least one valid. The freshest by `modification_time` is the
//! authoritative copy; the other three are write-ahead-log redundancy.
//!
//! The freshest superblock is the entry point for Bucket Descriptor Table
//! (BDT) walking - it carries the page-count fields plus the data RRV
//! bucket position used for modern-ODS note enumeration. The `bdt_position`
//! field in DBINFO is always zero on modern ODS; only the superblock
//! resolves bucket_index -> file_offset.
//!
//! Header layout (100 bytes, LE throughout) per
//! `libnsfdb/nsfdb_superblock.h::nsfdb_superblock_header`:
//!
//! ```text
//! offset  width  field
//!     0      2   signature (0x0E 0x00)
//!     2      8   modification_time (TIMEDATE)
//!    10      4   uncompressed_size
//!    14      4   number_of_summary_buckets
//!    18      4   number_of_non_summary_buckets
//!    22      4   number_of_bitmaps
//!    26      4   rrv_bucket_size
//!    30      4   data_rrv_bucket_position (256-byte units)
//!    34      4   rrv_identifier_low
//!    38      4   rrv_identifier_high
//!    42      4   bitmap_size
//!    46      4   data_note_identifier_table_size
//!    50      4   modified_note_log_size
//!    54      4   folder_directory_object_size
//!    58      2   flags
//!    60      4   write_count
//!    64      4   size
//!    68      2   compression_type
//!    70      4   number_of_summary_bucket_descriptor_pages
//!    74      4   number_of_non_summary_bucket_descriptor_pages
//!    78      4   number_of_soft_deleted_note_entries
//!    82      2   shared_template_information_size
//!    84      2   unknown1
//!    86      2   number_of_form_names
//!    88      4   form_bitmap_size
//!    92      8   unknown2
//! ```
//!
//! Footer layout (12 bytes) per
//! `libnsfdb/nsfdb_superblock.h::nsfdb_superblock_footer`:
//!
//! ```text
//! offset  width  field
//!     0      8   modification_time (TIMEDATE)
//!     4      4   checksum (XOR-32 of superblock body)
//! ```
//!
//! Note: the NSF_HANDOFF.md document lists the header as 110 bytes; the
//! authoritative `nsfdb_superblock.h` struct sums to **100 bytes** for
//! the header plus 12 for the footer. This module trusts the struct.

use crate::error::NsfError;
use crate::time::Timedate;

/// Magic two bytes at offset 0 of every superblock header.
pub const SUPERBLOCK_SIGNATURE: [u8; 2] = [0x0E, 0x00];
/// On-disk size of the superblock header in bytes.
pub const SUPERBLOCK_HEADER_BYTES: usize = 100;
/// On-disk size of the superblock footer in bytes.
pub const SUPERBLOCK_FOOTER_BYTES: usize = 12;

/// Parsed superblock header. Field naming mirrors the libnsfdb struct.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Superblock {
    /// Most recent modification time. Used to select the freshest of the
    /// four superblock copies via [`select_freshest`].
    pub modification_time: Timedate,
    /// Uncompressed size of the superblock body (when compressed).
    pub uncompressed_size: u32,
    /// Total summary buckets allocated in the database.
    pub number_of_summary_buckets: u32,
    /// Total non-summary buckets allocated in the database.
    pub number_of_non_summary_buckets: u32,
    /// Total bitmaps allocated in the database.
    pub number_of_bitmaps: u32,
    /// Size in bytes of each RRV bucket. Should match DBINFO's
    /// `rrv_bucket_size`; cross-validate at the database layer.
    pub rrv_bucket_size: u32,
    /// Data RRV bucket position in 256-byte units. Multiply by 256 for
    /// the byte offset. Should match DBINFO's `data_rrv_bucket_position`
    /// for non-fresh templates.
    pub data_rrv_bucket_position: u32,
    /// Lower 32 bits of the next-available RRV identifier counter.
    pub rrv_identifier_low: u32,
    /// Upper 32 bits of the next-available RRV identifier counter.
    pub rrv_identifier_high: u32,
    /// Allocation-bitmap size in bytes.
    pub bitmap_size: u32,
    /// Data Note Identifier Table size in bytes.
    pub data_note_identifier_table_size: u32,
    /// Modified-note-log size in bytes.
    pub modified_note_log_size: u32,
    /// Folder Directory Object (FDO) size in bytes.
    pub folder_directory_object_size: u32,
    /// Flags word.
    pub flags: u16,
    /// Write-count counter. Increments on each superblock commit.
    pub write_count: u32,
    /// Total size in bytes of this superblock (header + body + footer).
    pub size: u32,
    /// Compression type of the superblock body. Typically zero
    /// (uncompressed) on modern Domino.
    pub compression_type: u16,
    /// Number of summary-bucket-descriptor pages reachable via this
    /// superblock. Used by Slice 2.6 Phase B for BDT walking.
    pub number_of_summary_bucket_descriptor_pages: u32,
    /// Number of non-summary-bucket-descriptor pages reachable via this
    /// superblock.
    pub number_of_non_summary_bucket_descriptor_pages: u32,
    /// Number of soft-deleted note entries (notes moved to $Trash with
    /// retention period still active).
    pub number_of_soft_deleted_note_entries: u32,
    /// Shared-template-information block size in bytes.
    pub shared_template_information_size: u16,
    /// Number of form names cached at the superblock level.
    pub number_of_form_names: u16,
    /// Form-bitmap size in bytes.
    pub form_bitmap_size: u32,
}

impl Superblock {
    /// Parse a superblock header from the first
    /// [`SUPERBLOCK_HEADER_BYTES`] of a buffer positioned at the
    /// superblock's file offset.
    pub fn parse(bytes: &[u8]) -> Result<Self, NsfError> {
        if bytes.len() < SUPERBLOCK_HEADER_BYTES {
            return Err(NsfError::TooShort {
                actual: bytes.len(),
                required: SUPERBLOCK_HEADER_BYTES,
            });
        }
        if bytes[0] != SUPERBLOCK_SIGNATURE[0] || bytes[1] != SUPERBLOCK_SIGNATURE[1] {
            return Err(NsfError::BadSubrecordSignature {
                kind: "superblock",
                expected: SUPERBLOCK_SIGNATURE,
                observed: [bytes[0], bytes[1]],
            });
        }

        let u16_at = |o: usize| u16::from_le_bytes([bytes[o], bytes[o + 1]]);
        let u32_at = |o: usize| {
            u32::from_le_bytes([bytes[o], bytes[o + 1], bytes[o + 2], bytes[o + 3]])
        };

        Ok(Self {
            modification_time: Timedate::from_bytes(&bytes[2..10])?,
            uncompressed_size: u32_at(10),
            number_of_summary_buckets: u32_at(14),
            number_of_non_summary_buckets: u32_at(18),
            number_of_bitmaps: u32_at(22),
            rrv_bucket_size: u32_at(26),
            data_rrv_bucket_position: u32_at(30),
            rrv_identifier_low: u32_at(34),
            rrv_identifier_high: u32_at(38),
            bitmap_size: u32_at(42),
            data_note_identifier_table_size: u32_at(46),
            modified_note_log_size: u32_at(50),
            folder_directory_object_size: u32_at(54),
            flags: u16_at(58),
            write_count: u32_at(60),
            size: u32_at(64),
            compression_type: u16_at(68),
            number_of_summary_bucket_descriptor_pages: u32_at(70),
            number_of_non_summary_bucket_descriptor_pages: u32_at(74),
            number_of_soft_deleted_note_entries: u32_at(78),
            shared_template_information_size: u16_at(82),
            number_of_form_names: u16_at(86),
            form_bitmap_size: u32_at(88),
        })
    }

    /// Comparable absolute UTC timestamp from this superblock's
    /// `modification_time`. Returned as `(julian_day, centiseconds)`
    /// which compares lexicographically and treats different timezones
    /// uniformly (Innards[0] is always centiseconds since midnight UTC
    /// per the format spec).
    pub fn modification_sort_key(&self) -> (u32, u32) {
        let julian = self.modification_time.innards1 & 0x00FF_FFFF;
        (julian, self.modification_time.innards0)
    }
}

/// Pick the freshest superblock from a slice of parsed superblocks. Each
/// element is paired with its slot index 0..=3 so the caller can report
/// which copy was selected. Returns `None` if the input is empty.
///
/// Comparison uses `(julian_day, centiseconds_since_midnight_utc)` from
/// the superblock's `modification_time` - both UTC, both monotonic across
/// commits.
pub fn select_freshest(superblocks: &[(usize, Superblock)]) -> Option<(usize, Superblock)> {
    superblocks
        .iter()
        .copied()
        .max_by_key(|(_, sb)| sb.modification_sort_key())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a synthetic superblock header. `julian` sets the JDN portion
    /// of `modification_time`; `centi` sets centiseconds; the rest of the
    /// fields are arbitrary fixed values for round-trip testing.
    fn synthetic(julian: u32, centi: u32) -> Vec<u8> {
        let mut buf = vec![0u8; SUPERBLOCK_HEADER_BYTES];
        buf[0..2].copy_from_slice(&SUPERBLOCK_SIGNATURE);
        // Innards[0] = centiseconds (offset 2..6).
        buf[2..6].copy_from_slice(&centi.to_le_bytes());
        // Innards[1] low 24 bits = JDN (offset 6..10).
        buf[6..10].copy_from_slice(&julian.to_le_bytes());
        // rrv_bucket_size at offset 26, set to 0x1000.
        buf[26..30].copy_from_slice(&0x1000u32.to_le_bytes());
        // data_rrv_bucket_position at offset 30, set to 0x2af0.
        buf[30..34].copy_from_slice(&0x2af0u32.to_le_bytes());
        // size at offset 64, set to 4096.
        buf[64..68].copy_from_slice(&4096u32.to_le_bytes());
        // number_of_summary_bucket_descriptor_pages at offset 70.
        buf[70..74].copy_from_slice(&3u32.to_le_bytes());
        // number_of_non_summary_bucket_descriptor_pages at offset 74.
        buf[74..78].copy_from_slice(&5u32.to_le_bytes());
        buf
    }

    #[test]
    fn parses_synthetic_superblock() {
        let buf = synthetic(2_450_428, 0x006C_DCC0);
        let sb = Superblock::parse(&buf).unwrap();
        assert_eq!(sb.rrv_bucket_size, 0x1000);
        assert_eq!(sb.data_rrv_bucket_position, 0x2af0);
        assert_eq!(sb.size, 4096);
        assert_eq!(sb.number_of_summary_bucket_descriptor_pages, 3);
        assert_eq!(sb.number_of_non_summary_bucket_descriptor_pages, 5);
        assert_eq!(sb.modification_sort_key(), (2_450_428, 0x006C_DCC0));
    }

    #[test]
    fn rejects_bad_signature() {
        let mut buf = synthetic(2_450_428, 0);
        buf[0] = 0xFF;
        let err = Superblock::parse(&buf).unwrap_err();
        assert!(matches!(
            err,
            NsfError::BadSubrecordSignature {
                kind: "superblock",
                ..
            }
        ));
        // Error message must identify which signature failed - not
        // confused with the file-header "1A 00" signature.
        let msg = err.to_string();
        assert!(msg.contains("superblock"), "got: {msg}");
        assert!(msg.contains("0E 00"), "got: {msg}");
    }

    #[test]
    fn rejects_short_buffer() {
        let buf = vec![0u8; SUPERBLOCK_HEADER_BYTES - 1];
        let err = Superblock::parse(&buf).unwrap_err();
        assert!(matches!(err, NsfError::TooShort { .. }));
    }

    #[test]
    fn select_freshest_picks_highest_julian_day() {
        let sb_old = Superblock::parse(&synthetic(2_450_000, 0)).unwrap();
        let sb_new = Superblock::parse(&synthetic(2_500_000, 0)).unwrap();
        let sb_mid = Superblock::parse(&synthetic(2_460_000, 0)).unwrap();
        let result = select_freshest(&[(0, sb_old), (1, sb_new), (2, sb_mid)]);
        assert_eq!(result.unwrap().0, 1);
        assert_eq!(result.unwrap().1.modification_sort_key().0, 2_500_000);
    }

    #[test]
    fn select_freshest_breaks_ties_by_centiseconds() {
        let sb_morning = Superblock::parse(&synthetic(2_500_000, 1_000_000)).unwrap();
        let sb_evening = Superblock::parse(&synthetic(2_500_000, 8_000_000)).unwrap();
        let sb_noon = Superblock::parse(&synthetic(2_500_000, 4_320_000)).unwrap();
        let result = select_freshest(&[(0, sb_morning), (1, sb_evening), (2, sb_noon)]);
        assert_eq!(result.unwrap().0, 1);
    }

    #[test]
    fn select_freshest_empty_returns_none() {
        let v: Vec<(usize, Superblock)> = vec![];
        assert!(select_freshest(&v).is_none());
    }

    #[test]
    fn select_freshest_single_returns_that_one() {
        let sb = Superblock::parse(&synthetic(2_450_428, 0)).unwrap();
        let result = select_freshest(&[(2, sb)]);
        assert_eq!(result.unwrap().0, 2);
    }
}
