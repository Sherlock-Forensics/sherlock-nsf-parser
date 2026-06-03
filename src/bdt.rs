//! Bucket Descriptor Table (BDT) - the `bucket_index -> file_offset` map.
//!
//! # Where the map actually lives (correction to the original Phase B plan)
//!
//! The NSF_HANDOFF.md Phase B plan (Section 13.4) said the
//! `bucket_index -> file_offset` map is built by walking the **Bucket
//! Descriptor Block (BDB)** referenced from
//! [`crate::info2::Information2`]. Reading the authoritative libnsfdb
//! source (`libnsfdb_io_handle.c`) shows that is **wrong**:
//!
//! - The BDB (`libnsfdb_io_handle_read_bucket_descriptor_block`) holds
//!   *RRV* bucket descriptors (8 bytes each: file_offset + initial RRV
//!   identifier) plus the Unique Name Key table. Those locate the RRV
//!   buckets themselves and name note items - not the summary/non-summary
//!   data buckets.
//! - The actual `bucket_index -> file_offset` map is the array of
//!   `nsfdb_summary_bucket_descriptor` / `nsfdb_non_summary_bucket_descriptor`
//!   entries that lives **inside the superblock body**
//!   (`libnsfdb_io_handle_read_superblock`, the
//!   `number_of_summary_bucket_descriptor_pages` walk).
//!
//! # The compression prerequisite (the real Phase B blocker)
//!
//! The superblock *body* is stored **compressed**. libnsfdb requires
//! `compression_type == 1` and always runs the body through
//! `libnsfdb_compression_cx_decompress` before the descriptor array can be
//! read (`libnsfdb_io_handle.c` ~line 3022 + 3070). Domino "CX"
//! decompression is not yet implemented in this crate, and its reference
//! source was not part of the libnsfdb files pulled into the spike. Until
//! that decompressor lands, [`crate::Database::resolve_bucket_slot`]
//! returns [`NsfError::CompressionUnsupported`] rather than guess at the
//! algorithm - a wrong decompressor would silently corrupt evidence.
//!
//! This module parses the descriptor arrays from an **already-decompressed**
//! superblock body. It is the certain, mechanical half of the resolution
//! path: correct against the libnsfdb layout and unit-tested with synthetic
//! bodies, and ready to be fed real bytes the moment CX decompression
//! exists.
//!
//! # Decompressed body layout (per `libnsfdb_io_handle_read_superblock`)
//!
//! When `number_of_summary_bucket_descriptor_pages > 0`, the body begins
//! with a single summary page (libnsfdb rejects page counts > 1):
//!
//! ```text
//! offset  width                       region
//!     0      4                         unknown1
//!     4     10                         summary_bucket_page_descriptor
//!    14     10                         summary_bucket_group_descriptor
//!    24    200                         unknown2
//!   224     14 * number_of_summary_buckets   summary_bucket_descriptor[]
//!   ...    (pad to 7982 - 14*N)        unknown3
//!         total page = 8206 bytes
//! ```
//!
//! Each `summary_bucket_descriptor` is `file_position[4] +
//! modification_time[8] + largest_free[1] + second_largest_free[1]` = 14
//! bytes. `file_position` is in 256-byte units (`<<= 8` for the byte
//! offset).
//!
//! The non-summary page (if present) follows immediately:
//!
//! ```text
//! offset  width                       region
//!     0      4                         unknown1
//!     4      2                         non_summary_bucket_page_descriptor
//!     6      2                         non_summary_bucket_group_descriptor
//!     8     62                         unknown2
//!    70      6 * number_of_non_summary_buckets   non_summary_bucket_descriptor[]
//!   ...    (pad to 8128 - 6*N)         unknown3
//!         total page = 8198 bytes
//! ```
//!
//! Each `non_summary_bucket_descriptor` is `file_position[4] +
//! largest_free[1] + second_largest_free[1]` = 6 bytes.
//!
//! # bucket_index base
//!
//! RRV bucket-slot entries skip `bucket_index == 0` as an empty sentinel
//! (see [`crate::rrv`]), which means the on-disk `bucket_index` is
//! **1-based**: descriptor-array element `i` is addressed as
//! `bucket_index == i + 1`. This mirrors the 1-based slot indexing
//! confirmed in `libnsfdb_bucket_get_slot`. The 1-based mapping is an
//! inference from the sentinel + the slot-index precedent; it is the one
//! part of this module that cannot be validated against the corpus until
//! CX decompression lets a real bucket-slot entry resolve end to end.
//! Flagged here so it is re-confirmed at that point, not silently trusted.

use crate::error::NsfError;
use crate::superblock::Superblock;

/// On-disk size of one `nsfdb_summary_bucket_descriptor`.
pub const SUMMARY_DESCRIPTOR_BYTES: usize = 14;
/// On-disk size of one `nsfdb_non_summary_bucket_descriptor`.
pub const NON_SUMMARY_DESCRIPTOR_BYTES: usize = 6;

/// Prefix before the summary descriptor array within the body.
const SUMMARY_PAGE_PREFIX: usize = 224;
/// Total bytes a single summary descriptor page occupies.
const SUMMARY_PAGE_BYTES: usize = 8206;
/// Prefix before the non-summary descriptor array within the body. The
/// non-summary page is terminal (no structure follows it in the body we
/// parse), so its total size - 8198 bytes, documented in the module
/// header - is not needed to advance a cursor.
const NON_SUMMARY_PAGE_PREFIX: usize = 70;

/// Parsed bucket-descriptor table: two `bucket_index -> file byte offset`
/// maps, one for summary buckets and one for non-summary buckets. Both are
/// 0-based vectors; the on-disk 1-based `bucket_index` is converted by the
/// accessor methods.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BucketDescriptorTable {
    /// Byte offsets of summary buckets, 0-based.
    pub summary: Vec<u64>,
    /// Byte offsets of non-summary buckets, 0-based.
    pub non_summary: Vec<u64>,
}

impl BucketDescriptorTable {
    /// Parse the descriptor arrays from a decompressed superblock body.
    ///
    /// `body` must be the superblock body *after* CX decompression (the
    /// bytes that follow the 100-byte header, as libnsfdb addresses them).
    /// The counts come from the already-parsed [`Superblock`] header.
    pub fn parse(body: &[u8], sb: &Superblock) -> Result<Self, NsfError> {
        let u32_at = |buf: &[u8], o: usize| -> Option<u32> {
            buf.get(o..o + 4)
                .map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
        };

        let mut cursor = 0usize;
        let mut summary = Vec::new();
        if sb.number_of_summary_bucket_descriptor_pages > 0 {
            let array_start = cursor + SUMMARY_PAGE_PREFIX;
            let count = sb.number_of_summary_buckets as usize;
            summary.reserve(count);
            for i in 0..count {
                let off = array_start + i * SUMMARY_DESCRIPTOR_BYTES;
                let fp = u32_at(body, off).ok_or(NsfError::TooShort {
                    actual: body.len(),
                    required: off + 4,
                })?;
                summary.push(u64::from(fp) << 8);
            }
            cursor += SUMMARY_PAGE_BYTES;
        }

        let mut non_summary = Vec::new();
        if sb.number_of_non_summary_bucket_descriptor_pages > 0 {
            let array_start = cursor + NON_SUMMARY_PAGE_PREFIX;
            let count = sb.number_of_non_summary_buckets as usize;
            non_summary.reserve(count);
            for i in 0..count {
                let off = array_start + i * NON_SUMMARY_DESCRIPTOR_BYTES;
                let fp = u32_at(body, off).ok_or(NsfError::TooShort {
                    actual: body.len(),
                    required: off + 4,
                })?;
                non_summary.push(u64::from(fp) << 8);
            }
        }

        Ok(Self {
            summary,
            non_summary,
        })
    }

    /// Byte offset of a summary bucket given its on-disk 1-based
    /// `bucket_index`. Summary buckets hold note summary-item data, which
    /// is where note enumeration via the RRV lands.
    pub fn summary_bucket_offset(&self, bucket_index: u32) -> Result<u64, NsfError> {
        Self::lookup(&self.summary, bucket_index)
    }

    /// Byte offset of a non-summary bucket given its on-disk 1-based
    /// `bucket_index`.
    pub fn non_summary_bucket_offset(&self, bucket_index: u32) -> Result<u64, NsfError> {
        Self::lookup(&self.non_summary, bucket_index)
    }

    fn lookup(map: &[u64], bucket_index: u32) -> Result<u64, NsfError> {
        if bucket_index == 0 {
            return Err(NsfError::BucketIndexOutOfRange {
                requested: 0,
                available: map.len(),
            });
        }
        let ordinal = (bucket_index - 1) as usize;
        map.get(ordinal)
            .copied()
            .ok_or(NsfError::BucketIndexOutOfRange {
                requested: bucket_index,
                available: map.len(),
            })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::superblock::{Superblock, SUPERBLOCK_HEADER_BYTES, SUPERBLOCK_SIGNATURE};

    /// Build a superblock header with the given page counts + bucket
    /// counts so [`BucketDescriptorTable::parse`] can be exercised.
    fn superblock_with_counts(
        summary_pages: u32,
        summary_buckets: u32,
        non_summary_pages: u32,
        non_summary_buckets: u32,
    ) -> Superblock {
        let mut buf = vec![0u8; SUPERBLOCK_HEADER_BYTES];
        buf[0..2].copy_from_slice(&SUPERBLOCK_SIGNATURE);
        buf[14..18].copy_from_slice(&summary_buckets.to_le_bytes());
        buf[18..22].copy_from_slice(&non_summary_buckets.to_le_bytes());
        buf[70..74].copy_from_slice(&summary_pages.to_le_bytes());
        buf[74..78].copy_from_slice(&non_summary_pages.to_le_bytes());
        Superblock::parse(&buf).unwrap()
    }

    /// Build a synthetic decompressed body with summary (and optionally
    /// non-summary) descriptor pages whose file positions encode the
    /// descriptor index for easy assertions.
    fn synthetic_body(summary_buckets: u32, non_summary_buckets: u32) -> Vec<u8> {
        let mut body = Vec::new();
        // Summary page.
        if summary_buckets > 0 {
            let mut page = vec![0u8; SUMMARY_PAGE_BYTES];
            for i in 0..summary_buckets as usize {
                let off = SUMMARY_PAGE_PREFIX + i * SUMMARY_DESCRIPTOR_BYTES;
                // file_position = 0x100 + i so byte offset = (0x100+i) << 8.
                let fp = 0x100u32 + i as u32;
                page[off..off + 4].copy_from_slice(&fp.to_le_bytes());
            }
            body.extend_from_slice(&page);
        }
        // Non-summary page. Sized to cover its prefix + descriptors; it is
        // the terminal page so its full padded size is not required here.
        if non_summary_buckets > 0 {
            let mut page = vec![
                0u8;
                NON_SUMMARY_PAGE_PREFIX
                    + non_summary_buckets as usize * NON_SUMMARY_DESCRIPTOR_BYTES
            ];
            for i in 0..non_summary_buckets as usize {
                let off = NON_SUMMARY_PAGE_PREFIX + i * NON_SUMMARY_DESCRIPTOR_BYTES;
                let fp = 0x900u32 + i as u32;
                page[off..off + 4].copy_from_slice(&fp.to_le_bytes());
            }
            body.extend_from_slice(&page);
        }
        body
    }

    #[test]
    fn parses_summary_descriptor_array() {
        let sb = superblock_with_counts(1, 3, 0, 0);
        let body = synthetic_body(3, 0);
        let bdt = BucketDescriptorTable::parse(&body, &sb).unwrap();
        assert_eq!(bdt.summary.len(), 3);
        assert_eq!(bdt.summary[0], 0x100u64 << 8);
        assert_eq!(bdt.summary[1], 0x101u64 << 8);
        assert_eq!(bdt.summary[2], 0x102u64 << 8);
        assert!(bdt.non_summary.is_empty());
    }

    #[test]
    fn parses_both_pages_with_correct_offsets() {
        let sb = superblock_with_counts(1, 2, 1, 2);
        let body = synthetic_body(2, 2);
        let bdt = BucketDescriptorTable::parse(&body, &sb).unwrap();
        assert_eq!(bdt.summary.len(), 2);
        assert_eq!(bdt.non_summary.len(), 2);
        // Non-summary page sits after the summary page; its descriptors
        // must still decode to the 0x900-based positions, proving the
        // cursor advanced by exactly one summary page.
        assert_eq!(bdt.non_summary[0], 0x900u64 << 8);
        assert_eq!(bdt.non_summary[1], 0x901u64 << 8);
    }

    #[test]
    fn summary_offset_is_one_based() {
        let sb = superblock_with_counts(1, 3, 0, 0);
        let body = synthetic_body(3, 0);
        let bdt = BucketDescriptorTable::parse(&body, &sb).unwrap();
        // bucket_index 1 -> element 0.
        assert_eq!(bdt.summary_bucket_offset(1).unwrap(), 0x100u64 << 8);
        assert_eq!(bdt.summary_bucket_offset(3).unwrap(), 0x102u64 << 8);
    }

    #[test]
    fn bucket_index_zero_is_rejected() {
        let sb = superblock_with_counts(1, 1, 0, 0);
        let body = synthetic_body(1, 0);
        let bdt = BucketDescriptorTable::parse(&body, &sb).unwrap();
        assert!(matches!(
            bdt.summary_bucket_offset(0),
            Err(NsfError::BucketIndexOutOfRange { requested: 0, .. })
        ));
    }

    #[test]
    fn bucket_index_past_end_is_rejected() {
        let sb = superblock_with_counts(1, 2, 0, 0);
        let body = synthetic_body(2, 0);
        let bdt = BucketDescriptorTable::parse(&body, &sb).unwrap();
        assert!(matches!(
            bdt.summary_bucket_offset(3),
            Err(NsfError::BucketIndexOutOfRange {
                requested: 3,
                available: 2
            })
        ));
    }

    #[test]
    fn no_descriptor_pages_yields_empty_maps() {
        // A database with zero descriptor pages (e.g. a fresh shell)
        // must produce empty maps, not a panic or an error.
        let sb = superblock_with_counts(0, 0, 0, 0);
        let bdt = BucketDescriptorTable::parse(&[], &sb).unwrap();
        assert!(bdt.summary.is_empty());
        assert!(bdt.non_summary.is_empty());
    }

    #[test]
    fn non_summary_only_starts_at_body_offset_zero() {
        // When there is no summary page, the non-summary page is the
        // first thing in the body (cursor must NOT skip a summary page
        // that isn't there). Mirrors libnsfdb: the summary block is only
        // advanced past when number_of_summary_bucket_descriptor_pages > 0.
        let sb = superblock_with_counts(0, 0, 1, 2);
        let body = synthetic_body(0, 2);
        let bdt = BucketDescriptorTable::parse(&body, &sb).unwrap();
        assert!(bdt.summary.is_empty());
        assert_eq!(bdt.non_summary.len(), 2);
        assert_eq!(bdt.non_summary[0], 0x900u64 << 8);
        assert_eq!(bdt.non_summary[1], 0x901u64 << 8);
    }

    #[test]
    fn truncated_body_errors_not_panics() {
        let sb = superblock_with_counts(1, 3, 0, 0);
        // Body too short to hold all three descriptors.
        let body = vec![0u8; SUMMARY_PAGE_PREFIX + SUMMARY_DESCRIPTOR_BYTES];
        assert!(matches!(
            BucketDescriptorTable::parse(&body, &sb),
            Err(NsfError::TooShort { .. })
        ));
    }
}
