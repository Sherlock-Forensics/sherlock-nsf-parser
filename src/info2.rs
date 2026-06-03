//! Database information extension block 2 (`nsfdb_database_information2_t`).
//!
//! Lives at file offset **520** in every modern-ODS NSF. Layout of the
//! preceding regions (per `libnsfdb_io_handle_read_database_header`):
//!
//! ```text
//! offset  width  region
//!     0      6   file_header (LSIG + db_header_size)
//!     6    174   nsfdb_database_information_t (DBINFO core - 174 bytes
//!                on disk; the first 128 bytes are the "info buffer"
//!                that [`crate::header::DbHeader`] mirrors)
//!   180     20   nsfdb_database_replication_information_t
//!                (replication_identifier + flags + cutoff interval/time)
//!   200    320   nsfdb_database_header_t (a 320-byte composite:
//!                128 bytes mirror of info-buffer + 128 bytes
//!                special_note_identifiers + 64 bytes unknown1 padding)
//!   520    124   THIS BLOCK (nsfdb_database_information2_t)
//!   644     44   nsfdb_database_information3_t (all unknown)
//!   688    336   nsfdb_database_information4_t (mostly unknown)
//!  1024    ...   payload (RRV buckets, summary buckets, superblocks, ...)
//! ```
//!
//! The `database_header_size` field at file offset 2 always reads 1024 in
//! the modern ODS - libnsfdb asserts this. The total fixed-header region
//! is 1024 bytes; payload starts at offset 1024.
//!
//! This block is the entry point for the **superblock + BDT walk**. It
//! holds:
//!
//! - 4 superblock (position, size) pairs. Domino writes superblocks
//!   round-robin across the 4 slots; an instantiated database typically
//!   has 3 populated and 1 empty (the next slot to be written). The
//!   freshest by `modification_time` is authoritative; the others are
//!   write-ahead-log redundancy. See [`crate::superblock`].
//! - 2 bucket-descriptor-block (BDB1, BDB2) position/size pairs.
//! - Bucket-granularity + fill-factor + size-bound knobs (largely
//!   diagnostic; not load-bearing for parsing but exposed for the viewer's
//!   diagnostic card).
//!
//! All position fields are in 256-byte units (multiply by 256 to get the
//! byte offset). Per `libnsfdb_io_handle.c` line ~2318:
//! `*superblock_offset <<= 8;`.
//!
//! Layout per `libnsfdb/nsfdb_database_header.h::nsfdb_database_information2_t`:
//!
//! ```text
//! offset  width  field
//!     0      8   last_fixup_time (TIMEDATE)
//!     8      4   database_quota_limit
//!    12      4   database_quota_warn_threshold
//!    16      8   unknown_time1 (TIMEDATE)
//!    24      8   unknown_time2 (TIMEDATE)
//!    32      8   object_store_replica_identifier (TIMEDATE-shaped opaque)
//!    40      4   superblock1_position (256-byte units)
//!    44      4   superblock1_size
//!    48      4   superblock2_position
//!    52      4   superblock2_size
//!    56      4   superblock3_position
//!    60      4   superblock3_size
//!    64      4   superblock4_position
//!    68      4   superblock4_size
//!    72      4   maximum_extension_granularity
//!    76      2   summary_bucket_granularity
//!    78      2   non_summary_bucket_granularity
//!    80      4   minimum_summary_bucket_size
//!    84      4   minimum_non_summary_bucket_size
//!    88      4   maximum_summary_bucket_size
//!    92      4   maximum_non_summary_bucket_size
//!    96      2   non_summary_append_size
//!    98      2   non_summary_append_factor
//!   100      2   summary_bucket_fill_factor
//!   102      2   non_summary_bucket_fill_factor
//!   104      4   bucket_descriptor_block1_size
//!   108      4   bucket_descriptor_block1_position (256-byte units)
//!   112      4   bucket_descriptor_block2_size
//!   116      4   bucket_descriptor_block2_position (256-byte units)
//!   120      4   unknown2
//! ```

use crate::error::NsfError;
use crate::time::Timedate;

/// File offset where `Information2` begins. Computed as 6 (file_header)
/// + 174 (nsfdb_database_information_t) + 20 (replication_information)
/// + 320 (nsfdb_database_header_t) = 520.
///
/// Verified empirically against the 4-file real-nsf corpus
/// (XPagesExt.nsf, ToDo.nsf, fakenames.nsf, fakenames-views.nsf) -
/// every file produces sane in-bounds superblock + BDB positions at this
/// offset, whereas the naive "after the 320-byte database_header at
/// offset 6" offset of 326 lands on uninitialized padding bytes.
pub const INFO2_FILE_OFFSET: usize = 520;
/// On-disk size of the `Information2` block in bytes.
pub const INFO2_BYTES: usize = 124;

/// One of the four superblock copies.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SuperblockSlot {
    /// Position in 256-byte units. Multiply by 256 to get the byte offset.
    pub position_pages: u32,
    /// Size in bytes of the superblock body at that position.
    pub size_bytes: u32,
}

impl SuperblockSlot {
    /// True when this slot is not usable as a superblock pointer.
    ///
    /// Either field being zero disqualifies the slot: position=0 points
    /// at the file header (`1A 00` LSIG, not a superblock), and size=0
    /// means there is nothing to read. Empirically (comparedbs.ntf and
    /// other fresh / never-instantiated HCL templates) Domino writes
    /// `position=0` with a nonzero size on uninitialized slots, so the
    /// stricter both-must-be-nonzero rule is required to filter them out.
    pub fn is_empty(&self) -> bool {
        self.position_pages == 0 || self.size_bytes == 0
    }

    /// Byte offset of this superblock body. Returns `None` for an empty
    /// slot so consumers do not chase zero offsets.
    pub fn byte_offset(&self) -> Option<u64> {
        if self.is_empty() {
            None
        } else {
            Some(u64::from(self.position_pages) * 256)
        }
    }
}

/// One of the two bucket-descriptor-block copies.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BdbSlot {
    /// Size in bytes of the BDB at this slot.
    pub size_bytes: u32,
    /// Position in 256-byte units.
    pub position_pages: u32,
}

impl BdbSlot {
    /// True when this slot is not usable as a BDB pointer. Same
    /// either-zero semantics as [`SuperblockSlot::is_empty`].
    pub fn is_empty(&self) -> bool {
        self.position_pages == 0 || self.size_bytes == 0
    }

    /// Byte offset of this BDB.
    pub fn byte_offset(&self) -> Option<u64> {
        if self.is_empty() {
            None
        } else {
            Some(u64::from(self.position_pages) * 256)
        }
    }
}

/// Parsed `nsfdb_database_information2_t`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Information2 {
    /// Most recent fix-up (compact/recovery) timestamp.
    pub last_fixup_time: Timedate,
    /// Per-database quota limit. Operator-defined; zero means unlimited.
    pub database_quota_limit: u32,
    /// Per-database quota warn threshold.
    pub database_quota_warn_threshold: u32,
    /// First of two undocumented TIMEDATEs in this block.
    pub unknown_time1: Timedate,
    /// Second of two undocumented TIMEDATEs in this block.
    pub unknown_time2: Timedate,
    /// Object store replica identifier (TIMEDATE-shaped opaque).
    pub object_store_replica_identifier: Timedate,
    /// Four superblock copies. Pick the freshest via the
    /// [`crate::superblock`] helpers.
    pub superblocks: [SuperblockSlot; 4],
    /// Maximum allowed extension granularity for file growth.
    pub maximum_extension_granularity: u32,
    /// Allocation granularity for summary buckets.
    pub summary_bucket_granularity: u16,
    /// Allocation granularity for non-summary buckets.
    pub non_summary_bucket_granularity: u16,
    /// Lower bound on summary-bucket size.
    pub minimum_summary_bucket_size: u32,
    /// Lower bound on non-summary-bucket size.
    pub minimum_non_summary_bucket_size: u32,
    /// Upper bound on summary-bucket size.
    pub maximum_summary_bucket_size: u32,
    /// Upper bound on non-summary-bucket size.
    pub maximum_non_summary_bucket_size: u32,
    /// Size in bytes that non-summary appends grow by.
    pub non_summary_append_size: u16,
    /// Append factor (growth multiplier for non-summary regions).
    pub non_summary_append_factor: u16,
    /// Fill factor target for summary buckets.
    pub summary_bucket_fill_factor: u16,
    /// Fill factor target for non-summary buckets.
    pub non_summary_bucket_fill_factor: u16,
    /// Two BDB copies (primary + write-ahead redundancy).
    pub bdbs: [BdbSlot; 2],
}

impl Information2 {
    /// Parse `Information2` from the 124 bytes starting at
    /// [`INFO2_FILE_OFFSET`] within a full-file buffer. The caller is
    /// responsible for slicing the right window; this method only checks
    /// the slice length.
    pub fn parse(bytes: &[u8]) -> Result<Self, NsfError> {
        if bytes.len() < INFO2_BYTES {
            return Err(NsfError::TooShort {
                actual: bytes.len(),
                required: INFO2_BYTES,
            });
        }

        let u16_at = |o: usize| u16::from_le_bytes([bytes[o], bytes[o + 1]]);
        let u32_at = |o: usize| {
            u32::from_le_bytes([bytes[o], bytes[o + 1], bytes[o + 2], bytes[o + 3]])
        };

        let last_fixup_time = Timedate::from_bytes(&bytes[0..8])?;
        let database_quota_limit = u32_at(8);
        let database_quota_warn_threshold = u32_at(12);
        let unknown_time1 = Timedate::from_bytes(&bytes[16..24])?;
        let unknown_time2 = Timedate::from_bytes(&bytes[24..32])?;
        let object_store_replica_identifier = Timedate::from_bytes(&bytes[32..40])?;

        let superblocks = [
            SuperblockSlot {
                position_pages: u32_at(40),
                size_bytes: u32_at(44),
            },
            SuperblockSlot {
                position_pages: u32_at(48),
                size_bytes: u32_at(52),
            },
            SuperblockSlot {
                position_pages: u32_at(56),
                size_bytes: u32_at(60),
            },
            SuperblockSlot {
                position_pages: u32_at(64),
                size_bytes: u32_at(68),
            },
        ];

        let maximum_extension_granularity = u32_at(72);
        let summary_bucket_granularity = u16_at(76);
        let non_summary_bucket_granularity = u16_at(78);
        let minimum_summary_bucket_size = u32_at(80);
        let minimum_non_summary_bucket_size = u32_at(84);
        let maximum_summary_bucket_size = u32_at(88);
        let maximum_non_summary_bucket_size = u32_at(92);
        let non_summary_append_size = u16_at(96);
        let non_summary_append_factor = u16_at(98);
        let summary_bucket_fill_factor = u16_at(100);
        let non_summary_bucket_fill_factor = u16_at(102);

        let bdbs = [
            BdbSlot {
                size_bytes: u32_at(104),
                position_pages: u32_at(108),
            },
            BdbSlot {
                size_bytes: u32_at(112),
                position_pages: u32_at(116),
            },
        ];

        Ok(Self {
            last_fixup_time,
            database_quota_limit,
            database_quota_warn_threshold,
            unknown_time1,
            unknown_time2,
            object_store_replica_identifier,
            superblocks,
            maximum_extension_granularity,
            summary_bucket_granularity,
            non_summary_bucket_granularity,
            minimum_summary_bucket_size,
            minimum_non_summary_bucket_size,
            maximum_summary_bucket_size,
            maximum_non_summary_bucket_size,
            non_summary_append_size,
            non_summary_append_factor,
            summary_bucket_fill_factor,
            non_summary_bucket_fill_factor,
            bdbs,
        })
    }

    /// Slot indices 0..=3 of populated superblocks (any with non-zero
    /// position or size).
    pub fn populated_superblock_indices(&self) -> Vec<usize> {
        self.superblocks
            .iter()
            .enumerate()
            .filter_map(|(i, s)| if s.is_empty() { None } else { Some(i) })
            .collect()
    }

    /// Slot indices 0..=1 of populated BDBs.
    pub fn populated_bdb_indices(&self) -> Vec<usize> {
        self.bdbs
            .iter()
            .enumerate()
            .filter_map(|(i, s)| if s.is_empty() { None } else { Some(i) })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a synthetic 124-byte Information2 with one populated
    /// superblock (slot 0) and one populated BDB (slot 0). Useful for
    /// round-trip unit tests; integration tests against the corpus
    /// validate real-file parsing.
    fn synthetic(superblock0_pages: u32, superblock0_size: u32, bdb0_pages: u32) -> Vec<u8> {
        let mut buf = vec![0u8; INFO2_BYTES];
        // Superblock 1 (slot 0): position + size.
        buf[40..44].copy_from_slice(&superblock0_pages.to_le_bytes());
        buf[44..48].copy_from_slice(&superblock0_size.to_le_bytes());
        // BDB 1 (slot 0): size + position. NOTE field order is (size,
        // position) per the struct, not (position, size).
        buf[104..108].copy_from_slice(&512u32.to_le_bytes());
        buf[108..112].copy_from_slice(&bdb0_pages.to_le_bytes());
        // Plausible granularity values.
        buf[76..78].copy_from_slice(&8u16.to_le_bytes());
        buf[78..80].copy_from_slice(&8u16.to_le_bytes());
        buf
    }

    #[test]
    fn parses_synthetic_with_one_populated_superblock_and_bdb() {
        let buf = synthetic(0x100, 1024, 0x200);
        let info = Information2::parse(&buf).unwrap();

        assert_eq!(info.superblocks[0].position_pages, 0x100);
        assert_eq!(info.superblocks[0].size_bytes, 1024);
        assert_eq!(info.superblocks[0].byte_offset(), Some(0x100 * 256));

        assert!(info.superblocks[1].is_empty());
        assert!(info.superblocks[2].is_empty());
        assert!(info.superblocks[3].is_empty());

        assert_eq!(info.bdbs[0].position_pages, 0x200);
        assert_eq!(info.bdbs[0].size_bytes, 512);
        assert_eq!(info.bdbs[0].byte_offset(), Some(0x200 * 256));
        assert!(info.bdbs[1].is_empty());

        assert_eq!(info.populated_superblock_indices(), vec![0]);
        assert_eq!(info.populated_bdb_indices(), vec![0]);
    }

    #[test]
    fn rejects_short_buffer() {
        let buf = vec![0u8; INFO2_BYTES - 1];
        let err = Information2::parse(&buf).unwrap_err();
        assert!(matches!(err, NsfError::TooShort { .. }));
    }

    #[test]
    fn all_empty_returns_no_populated_slots() {
        let buf = vec![0u8; INFO2_BYTES];
        let info = Information2::parse(&buf).unwrap();
        assert!(info.populated_superblock_indices().is_empty());
        assert!(info.populated_bdb_indices().is_empty());
    }

    #[test]
    fn superblock_byte_offset_scales_by_256() {
        let slot = SuperblockSlot {
            position_pages: 0x2AF0,
            size_bytes: 256,
        };
        assert_eq!(slot.byte_offset(), Some(0x2AF0 * 256));
    }

    #[test]
    fn empty_superblock_returns_none_offset() {
        let slot = SuperblockSlot {
            position_pages: 0,
            size_bytes: 0,
        };
        assert_eq!(slot.byte_offset(), None);
    }

    #[test]
    fn four_distinct_superblocks_all_parsed() {
        let mut buf = vec![0u8; INFO2_BYTES];
        for i in 0..4 {
            let offset = 40 + i * 8;
            let pos = (0x100 * (i as u32 + 1)).to_le_bytes();
            let size = (1024u32).to_le_bytes();
            buf[offset..offset + 4].copy_from_slice(&pos);
            buf[offset + 4..offset + 8].copy_from_slice(&size);
        }
        let info = Information2::parse(&buf).unwrap();
        for i in 0..4 {
            assert_eq!(info.superblocks[i].position_pages, 0x100 * (i as u32 + 1));
            assert_eq!(info.superblocks[i].size_bytes, 1024);
        }
        assert_eq!(info.populated_superblock_indices(), vec![0, 1, 2, 3]);
    }
}
