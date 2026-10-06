//! Record Relocation Vector (RRV) bucket parsing.
//!
//! An RRV bucket is a special bucket type that maps NoteIDs to physical
//! locations - either a file offset (for legacy / overflow records) or
//! a (bucket_index, slot_index, nonsum) triple (for records stored
//! inside another bucket). The DBINFO carries `data_rrv_bucket_position`
//! (file offset in 256-byte units) as the entry point for note
//! enumeration.
//!
//! RRV bucket layout per `libnsfdb/nsfdb_rrv_bucket.h`:
//!
//! ```text
//! offset  width  field
//!     0      1   signature (0x06)
//!     1      1   header_size (0x20 = 32)
//!     2      4   unknown1
//!     6      4   initial_rrv_identifier
//!    10      6   unknown2
//!    16      2   unknown_size
//!    18      4   checksum
//!    22     10   unknown3
//! ```
//!
//! Header is exactly 32 bytes. After the header, RRV entries follow as
//! a sequence of 8-byte records. Each entry has the layout:
//!
//! ```text
//!     0      4   rrv_entry        (u32 LE; high bit selects variant)
//!     4      4   rrv_entry_bsid   (u32 LE; only used in bucket-slot variant)
//! ```
//!
//! Modern ODS bit layout (reverse-engineered from
//! `libnsfdb_rrv_bucket.c::libnsfdb_rrv_bucket_read`):
//!
//! - If `rrv_entry & 0x80000000 == 0` -> file-position variant.
//!   `rrv_entry` is the file position in 256-byte units (multiply by
//!   256 to get byte offset). Sentinels 0 and 0x7FFFFFFF mark empty
//!   slots.
//! - If `rrv_entry & 0x80000000 != 0` -> bucket-slot variant.
//!   - `bucket_index` = `rrv_entry & 0x00FFFFFF`
//!   - `nonsum_high`  = `(rrv_entry >> 7) & 0x00E00000`
//!   - `slot_index`   = `rrv_entry_bsid & 0x000007FF`
//!   - `nonsum_low`   = `rrv_entry_bsid >> 11`
//!   - `nonsum`       = `nonsum_high | nonsum_low`
//!   - Sentinels: `bucket_index == 0` or `bucket_index == 0x00FFFFFF`
//!     mark empty slots.
//!
//! The rrv_identifier counter increments by 4 per entry, starting at
//! `initial_rrv_identifier`. The identifier IS the NoteID (with the
//! low 2 bits acting as flag bits per the spec; we expose the raw
//! identifier and let callers mask).

use crate::error::NsfError;

/// Expected signature byte at offset 0 of every RRV bucket.
pub const RRV_BUCKET_SIGNATURE: u8 = 0x06;
/// Fixed RRV bucket header size on disk (matches header_size byte value
/// `0x20` and the libnsfdb compile-time assertion).
pub const RRV_BUCKET_HEADER_BYTES: usize = 32;
/// Bytes consumed per RRV entry (two u32s).
pub const RRV_ENTRY_BYTES: usize = 8;

/// Empty-slot sentinel for the file-position variant.
const FILE_POSITION_EMPTY_ALT: u32 = 0x7FFF_FFFF;
/// Empty-slot sentinel for the bucket-slot variant.
const BUCKET_INDEX_EMPTY_ALT: u32 = 0x00FF_FFFF;

/// Parsed RRV bucket header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RrvBucketHeader {
    /// Header size byte (always 0x20 for modern format).
    pub header_size: u8,
    /// Starting RRV identifier. Each entry's identifier is computed as
    /// `initial_rrv_identifier + (entry_index * 4)`.
    pub initial_rrv_identifier: u32,
    /// Stored XOR-32 checksum.
    pub checksum: u32,
}

impl RrvBucketHeader {
    /// Parse from the first 32 bytes of an RRV bucket. Errors on bad
    /// signature, bad header size, or short input.
    pub fn parse(bytes: &[u8]) -> Result<Self, NsfError> {
        if bytes.len() < RRV_BUCKET_HEADER_BYTES {
            return Err(NsfError::TooShort {
                actual: bytes.len(),
                required: RRV_BUCKET_HEADER_BYTES,
            });
        }
        if bytes[0] != RRV_BUCKET_SIGNATURE {
            return Err(NsfError::BadFileSignature {
                observed: [bytes[0], 0],
            });
        }
        if bytes[1] != 0x20 {
            return Err(NsfError::BadHeaderSize {
                size: bytes[1] as u32,
            });
        }
        let initial_rrv_identifier =
            u32::from_le_bytes([bytes[6], bytes[7], bytes[8], bytes[9]]);
        let checksum = u32::from_le_bytes([bytes[18], bytes[19], bytes[20], bytes[21]]);
        Ok(Self {
            header_size: bytes[1],
            initial_rrv_identifier,
            checksum,
        })
    }
}

/// Resolved location of an RRV entry. Empty slots are skipped during
/// iteration so consumers never see them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RrvLocation {
    /// Record is stored inline in another bucket at the named slot.
    BucketSlot {
        /// Index of the bucket holding the record (resolved via the
        /// Bucket Descriptor Table).
        bucket_index: u32,
        /// Slot index inside that bucket.
        slot_index: u16,
        /// Non-summary identifier; references additional data outside
        /// the bucket for records that exceed the bucket-slot capacity.
        nonsum: u32,
    },
    /// Record is stored at a direct file position. The offset is in
    /// 256-byte units; multiply by 256 to get the byte offset.
    FilePosition {
        /// Position in 256-byte units (multiply by 256 for byte offset).
        file_position_pages: u32,
    },
}

impl RrvLocation {
    /// Byte offset into the file for the file-position variant; None
    /// for bucket-slot.
    pub fn file_byte_offset(&self) -> Option<u64> {
        match self {
            Self::FilePosition {
                file_position_pages,
            } => Some(u64::from(*file_position_pages) * 256),
            _ => None,
        }
    }
}

/// One parsed RRV entry: the RRV identifier (effectively the NoteID
/// without flag bits) plus the resolved location.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RrvEntry {
    /// RRV identifier. Derived from
    /// `initial_rrv_identifier + (entry_index * 4)` during iteration;
    /// the low 2 bits act as flag bits per the spec.
    pub rrv_identifier: u32,
    /// Where the record lives.
    pub location: RrvLocation,
}

/// Iterate non-empty RRV entries from a buffer that holds the bucket
/// header + the full sequence of entries (i.e. the entire RRV bucket).
///
/// Empty slots are skipped silently. Trailing bytes shorter than 8 are
/// ignored. The iterator owns the (parsed) header and a slice cursor
/// over the entry region.
pub struct RrvIter<'a> {
    /// Current rrv_identifier value. Advances by 4 every entry.
    next_rrv_identifier: u32,
    /// Remaining entry bytes.
    remaining: &'a [u8],
}

impl<'a> RrvIter<'a> {
    /// Build an iterator from a full RRV-bucket buffer (header + entries).
    pub fn new(bucket: &'a [u8]) -> Result<(RrvBucketHeader, Self), NsfError> {
        let header = RrvBucketHeader::parse(bucket)?;
        let entry_data = &bucket[RRV_BUCKET_HEADER_BYTES..];
        Ok((
            header,
            Self {
                next_rrv_identifier: header.initial_rrv_identifier,
                remaining: entry_data,
            },
        ))
    }
}

impl<'a> Iterator for RrvIter<'a> {
    type Item = RrvEntry;

    fn next(&mut self) -> Option<Self::Item> {
        while self.remaining.len() >= RRV_ENTRY_BYTES {
            let rrv_entry = u32::from_le_bytes([
                self.remaining[0],
                self.remaining[1],
                self.remaining[2],
                self.remaining[3],
            ]);
            let rrv_entry_bsid = u32::from_le_bytes([
                self.remaining[4],
                self.remaining[5],
                self.remaining[6],
                self.remaining[7],
            ]);
            self.remaining = &self.remaining[RRV_ENTRY_BYTES..];
            let identifier = self.next_rrv_identifier;
            self.next_rrv_identifier = self.next_rrv_identifier.wrapping_add(4);

            // Bit 31 selects variant.
            if (rrv_entry & 0x8000_0000) == 0 {
                // File-position variant. Skip empty markers.
                if rrv_entry == 0 || rrv_entry == FILE_POSITION_EMPTY_ALT {
                    continue;
                }
                return Some(RrvEntry {
                    rrv_identifier: identifier,
                    location: RrvLocation::FilePosition {
                        file_position_pages: rrv_entry,
                    },
                });
            } else {
                // Bucket-slot variant.
                let bucket_index = rrv_entry & 0x00FF_FFFF;
                if bucket_index == 0 || bucket_index == BUCKET_INDEX_EMPTY_ALT {
                    continue;
                }
                let nonsum_high = (rrv_entry >> 7) & 0x00E0_0000;
                let slot_index = (rrv_entry_bsid & 0x0000_07FF) as u16;
                let nonsum_low = rrv_entry_bsid >> 11;
                let nonsum = nonsum_high | nonsum_low;
                return Some(RrvEntry {
                    rrv_identifier: identifier,
                    location: RrvLocation::BucketSlot {
                        bucket_index,
                        slot_index,
                        nonsum,
                    },
                });
            }
        }
        None
    }
}

/// Header size of a pre-Notes 5 (ODS 20) RRV bucket. The header-size byte
/// at offset 1 carries this value, as the modern format's carries 0x20.
pub const LEGACY_RRV_HEADER_BYTES: usize = 10;
/// Bytes per entry in a pre-Notes 5 RRV bucket.
pub const LEGACY_RRV_ENTRY_BYTES: usize = 4;

/// A pre-Notes 5 (ODS 20) RRV bucket.
///
/// Decoded from a real Notes 4 mail file, not from a published spec:
///
/// ```text
/// offset  width  field
///     0      1   signature (0x06, as in the modern format)
///     1      1   header_size (0x0A)
///     2      4   previous bucket's file position, in bytes
///     6      4   initial_rrv_identifier
///    10    4*n   entries: the note record's file position, in bytes
/// ```
///
/// Why each field is read this way, from that file:
///
/// - the data bucket DBINFO names had an initial identifier of 163,862 and
///   300 used entries, and DBINFO's next-available data identifier was
///   165,062 - exactly `163,862 + 300 * 4`;
/// - an 8,192-byte bucket holds 2,045 entries, and DBINFO's first data
///   identifier, 8,442, is exactly 19 buckets of `2,045 * 4` below 163,862;
///   so DBINFO names the newest bucket and the header pointer leads back
///   through the older ones;
/// - every used entry lies inside the file on a 64-byte boundary, which is
///   the database's allocation granularity;
/// - empty entries are `0xFFFFFFFF`, and runs of them sit between used
///   entries in the non-data bucket, as deleted notes would leave.
#[derive(Debug, Clone, Copy)]
pub struct LegacyRrvBucket<'a> {
    /// File position (bytes) of the previous bucket in the chain; 0 at the
    /// oldest.
    pub previous_bucket_position: u32,
    /// Identifier of the first entry. Each entry's identifier is
    /// `initial_rrv_identifier + index * 4`.
    pub initial_rrv_identifier: u32,
    entries: &'a [u8],
}

impl<'a> LegacyRrvBucket<'a> {
    /// Parse a whole bucket. Errors on a bad signature or a header size
    /// other than [`LEGACY_RRV_HEADER_BYTES`].
    pub fn parse(bucket: &'a [u8]) -> Result<Self, NsfError> {
        if bucket.len() < LEGACY_RRV_HEADER_BYTES {
            return Err(NsfError::TooShort {
                actual: bucket.len(),
                required: LEGACY_RRV_HEADER_BYTES,
            });
        }
        if bucket[0] != RRV_BUCKET_SIGNATURE {
            return Err(NsfError::BadFileSignature {
                observed: [bucket[0], 0],
            });
        }
        if bucket[1] as usize != LEGACY_RRV_HEADER_BYTES {
            return Err(NsfError::BadHeaderSize {
                size: bucket[1] as u32,
            });
        }
        let u32_at = |o: usize| {
            u32::from_le_bytes([bucket[o], bucket[o + 1], bucket[o + 2], bucket[o + 3]])
        };
        Ok(Self {
            previous_bucket_position: u32_at(2),
            initial_rrv_identifier: u32_at(6),
            entries: &bucket[LEGACY_RRV_HEADER_BYTES..],
        })
    }

    /// Used entries as `(rrv_identifier, byte_offset)`. Empty entries
    /// (`0xFFFFFFFF`, and 0, which cannot be a note's position because the
    /// file header lives there) are skipped.
    pub fn entries(&self) -> impl Iterator<Item = (u32, u64)> + 'a {
        let initial = self.initial_rrv_identifier;
        self.entries
            .chunks_exact(LEGACY_RRV_ENTRY_BYTES)
            .enumerate()
            .filter_map(move |(i, e)| {
                let pos = u32::from_le_bytes([e[0], e[1], e[2], e[3]]);
                if pos == 0 || pos == u32::MAX {
                    return None;
                }
                let id = initial.wrapping_add((i as u32).wrapping_mul(4));
                Some((id, u64::from(pos)))
            })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn legacy_bucket_reads_ids_and_byte_offsets_and_skips_empties() {
        let mut b = vec![0xFFu8; LEGACY_RRV_HEADER_BYTES + 4 * LEGACY_RRV_ENTRY_BYTES];
        b[0] = RRV_BUCKET_SIGNATURE;
        b[1] = 0x0A;
        b[2..6].copy_from_slice(&0x09CF_A000u32.to_le_bytes());
        b[6..10].copy_from_slice(&163_862u32.to_le_bytes());
        b[10..14].copy_from_slice(&0x0BEB_5E40u32.to_le_bytes());
        // entry 1 left empty (0xFFFFFFFF)
        b[18..22].copy_from_slice(&0u32.to_le_bytes());
        b[22..26].copy_from_slice(&0x004B_A800u32.to_le_bytes());
        let bucket = LegacyRrvBucket::parse(&b).unwrap();
        assert_eq!(bucket.previous_bucket_position, 0x09CF_A000);
        let got: Vec<_> = bucket.entries().collect();
        assert_eq!(got, vec![(163_862, 0x0BEB_5E40), (163_874, 0x004B_A800)]);
    }

    /// The two layouts share a signature byte, so the header size is what
    /// keeps either parser from reading the other's bucket.
    #[test]
    fn legacy_and_modern_buckets_refuse_each_other() {
        let mut legacy = vec![0u8; 64];
        legacy[0] = RRV_BUCKET_SIGNATURE;
        legacy[1] = 0x0A;
        assert!(RrvBucketHeader::parse(&legacy).is_err());
        let mut modern = vec![0u8; 64];
        modern[0] = RRV_BUCKET_SIGNATURE;
        modern[1] = 0x20;
        assert!(LegacyRrvBucket::parse(&modern).is_err());
    }

    fn synthetic_bucket_with_entries(entries: &[(u32, u32)]) -> Vec<u8> {
        let mut buf = vec![0u8; RRV_BUCKET_HEADER_BYTES + entries.len() * RRV_ENTRY_BYTES];
        buf[0] = RRV_BUCKET_SIGNATURE;
        buf[1] = 0x20;
        // initial_rrv_identifier = 100 (arbitrary)
        buf[6..10].copy_from_slice(&100u32.to_le_bytes());
        for (i, (a, b)) in entries.iter().enumerate() {
            let off = RRV_BUCKET_HEADER_BYTES + i * RRV_ENTRY_BYTES;
            buf[off..off + 4].copy_from_slice(&a.to_le_bytes());
            buf[off + 4..off + 8].copy_from_slice(&b.to_le_bytes());
        }
        buf
    }

    #[test]
    fn parses_header_signature() {
        let buf = synthetic_bucket_with_entries(&[]);
        let h = RrvBucketHeader::parse(&buf).unwrap();
        assert_eq!(h.header_size, 0x20);
        assert_eq!(h.initial_rrv_identifier, 100);
    }

    #[test]
    fn skips_zero_and_alternate_empty_markers_in_file_position_variant() {
        let buf = synthetic_bucket_with_entries(&[
            (0, 0),
            (FILE_POSITION_EMPTY_ALT, 0),
            (0x0000_2AF0, 0),
        ]);
        let (_, iter) = RrvIter::new(&buf).unwrap();
        let entries: Vec<_> = iter.collect();
        // Only the third entry should survive; identifier = 100 + 8 = 108.
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].rrv_identifier, 108);
        assert!(matches!(
            entries[0].location,
            RrvLocation::FilePosition {
                file_position_pages: 0x0000_2AF0
            }
        ));
        assert_eq!(
            entries[0].location.file_byte_offset(),
            Some(0x0000_2AF0 * 256)
        );
    }

    #[test]
    fn parses_bucket_slot_variant_bit_layout() {
        // Construct a bucket-slot entry: bucket_index=0x123456,
        // slot_index=0x1AB (0..2047), nonsum=0x00C00042 (must fit
        // 0x00FFFFFF after recombination).
        let bucket_index: u32 = 0x0012_3456;
        let slot_index: u32 = 0x01AB;
        // Reconstruct rrv_entry: high bit + (nonsum_high << 7) +
        // bucket_index. We'll only set bucket_index here and verify
        // the round-trip; nonsum_high = 0 keeps the test focused.
        let rrv_entry: u32 = 0x8000_0000 | bucket_index;
        // rrv_entry_bsid: slot_index in low 11 bits, nonsum_low in
        // the remaining bits.
        let nonsum_low: u32 = 0x0001_2345; // arbitrary
        let rrv_entry_bsid: u32 = (nonsum_low << 11) | slot_index;
        let buf = synthetic_bucket_with_entries(&[(rrv_entry, rrv_entry_bsid)]);
        let (_, iter) = RrvIter::new(&buf).unwrap();
        let entries: Vec<_> = iter.collect();
        assert_eq!(entries.len(), 1);
        match entries[0].location {
            RrvLocation::BucketSlot {
                bucket_index: b,
                slot_index: s,
                nonsum,
            } => {
                assert_eq!(b, bucket_index);
                assert_eq!(s, slot_index as u16);
                // nonsum_high is 0 in this test, so nonsum == nonsum_low.
                assert_eq!(nonsum, nonsum_low);
            }
            other => panic!("expected BucketSlot, got {other:?}"),
        }
    }

    #[test]
    fn rejects_bad_rrv_signature() {
        let mut buf = synthetic_bucket_with_entries(&[]);
        buf[0] = 0x55;
        assert!(RrvBucketHeader::parse(&buf).is_err());
    }

    #[test]
    fn rejects_bad_rrv_header_size() {
        let mut buf = synthetic_bucket_with_entries(&[]);
        buf[1] = 0x30;
        assert!(RrvBucketHeader::parse(&buf).is_err());
    }
}
