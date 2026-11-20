//! Generic bucket (and bucket-shaped page) parsing.
//!
//! A bucket is the unit of allocation inside an NSF file. The DBINFO
//! header reports the size of summary buckets and RRV buckets
//! separately. Every bucket starts with a `nsfdb_bucket_header`
//! (signature 0x02, 66 bytes including footer-pointer fields) and
//! optionally ends with a `nsfdb_bucket_footer`. Note records and
//! summary item data live inside buckets, indexed by slot.
//!
//! Layout per `libnsfdb/nsfdb_bucket.h`:
//!
//! ```text
//! offset  width  field
//!     0      1   signature (0x02)
//!     1      1   header_size
//!     2      4   unknown1
//!     6      4   size
//!    10      8   modification_time (TIMEDATE)
//!    18     20   unknown2
//!    38      2   unknown3
//!    40      4   checksum
//!    44      4   number_of_slots
//!    48      2   unknown4
//!    50      4   footer_size
//!    54     12   unknown5
//! ```

use crate::error::NsfError;
use crate::time::Timedate;

/// Expected signature byte at offset 0 of every bucket.
pub const BUCKET_SIGNATURE: u8 = 0x02;
/// Minimum bytes a bucket header consumes on disk.
pub const BUCKET_HEADER_BYTES: usize = 66;

/// Parsed bucket header. Field naming matches the libnsfdb struct.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BucketHeader {
    /// Header size as declared on disk (typically 0x42 = 66 for modern
    /// ODS). Surfaced for diagnostics; consumers should use
    /// [`BUCKET_HEADER_BYTES`] when offsetting into bucket data.
    pub header_size: u8,
    /// Total bucket size in bytes (including header + slots + footer).
    pub size: u32,
    /// Most recent modification time.
    pub modification_time: Timedate,
    /// XOR-32 checksum of the header.
    pub checksum: u32,
    /// Number of slots in this bucket. Each slot holds one allocated
    /// record (a note record in a non-summary bucket; summary-item
    /// data in a summary bucket).
    pub number_of_slots: u32,
    /// Footer size in bytes.
    pub footer_size: u32,
}

impl BucketHeader {
    /// Parse a bucket header from the first 66 bytes of bucket data.
    /// Errors on signature mismatch or short input.
    pub fn parse(bytes: &[u8]) -> Result<Self, NsfError> {
        if bytes.len() < BUCKET_HEADER_BYTES {
            return Err(NsfError::TooShort {
                actual: bytes.len(),
                required: BUCKET_HEADER_BYTES,
            });
        }
        if bytes[0] != BUCKET_SIGNATURE {
            return Err(NsfError::BadFileSignature {
                observed: [bytes[0], 0],
            });
        }
        let header_size = bytes[1];
        let size = u32::from_le_bytes([bytes[6], bytes[7], bytes[8], bytes[9]]);
        let modification_time = Timedate::from_bytes(&bytes[10..18])?;
        let checksum = u32::from_le_bytes([bytes[40], bytes[41], bytes[42], bytes[43]]);
        let number_of_slots =
            u32::from_le_bytes([bytes[44], bytes[45], bytes[46], bytes[47]]);
        let footer_size =
            u32::from_le_bytes([bytes[50], bytes[51], bytes[52], bytes[53]]);
        Ok(Self {
            header_size,
            size,
            modification_time,
            checksum,
            number_of_slots,
            footer_size,
        })
    }
}

/// Size of the on-disk sector the per-sector stamp is laid out on.
pub const STAMP_SECTOR_BYTES: usize = 512;
/// Offset inside each sector of the byte whose low nibble carries the stamp.
pub const STAMP_OFFSET_IN_SECTOR: usize = 66;
/// Largest declared bucket size [`restore_sector_stamps`] will copy. The
/// size comes from the file, so a crafted header must not be able to ask
/// for an arbitrary allocation; real summary buckets seen are 32 KiB.
pub const MAX_STAMPED_BUCKET_BYTES: usize = 1 << 20;

/// Undo the per-sector stamp of a bucket, returning a patched copy.
///
/// Observed on an ODS 52 database (local patch, not from libnsfdb): in each
/// 512-byte sector of a summary bucket, the low nibble of the byte at sector
/// offset 66 is overwritten with one stamp value shared by the whole bucket.
/// The displaced nibbles are kept in the bucket footer, one per sector, in
/// reverse sector order, low nibble of each footer byte first: the original
/// of sector `k` (of `n`) is nibble `n - 1 - k` of the footer. Read raw, a
/// stamped byte turns `-` into `)` in a value, or flips the summary flag of
/// an item descriptor and shifts every later value of that note.
///
/// `bytes` starts at the bucket and may run past it. Returns `None`, leaving
/// the bucket to be read as it is, unless all of this holds:
///
/// - the header parses, the declared size is at most
///   [`MAX_STAMPED_BUCKET_BYTES`], and the whole bucket is present;
/// - the size is a whole number of sectors and the footer holds exactly one
///   nibble per sector (`footer_size * 2 == size / 512`);
/// - every sector's byte at offset 66 carries the same low nibble (the
///   stamp), which a bucket without stamps does not do by accident unless
///   it is empty;
/// - restoring changes at least one byte.
pub fn restore_sector_stamps(bytes: &[u8]) -> Option<Vec<u8>> {
    let header = BucketHeader::parse(bytes).ok()?;
    let size = header.size as usize;
    // The size is whatever the file says. Refuse to copy more than a
    // bucket can plausibly be before looking at anything else.
    if size > MAX_STAMPED_BUCKET_BYTES {
        return None;
    }
    let bucket = bytes.get(..size)?;
    if size == 0 || size % STAMP_SECTOR_BYTES != 0 {
        return None;
    }
    let sectors = size / STAMP_SECTOR_BYTES;
    let footer_size = header.footer_size as usize;
    if footer_size.checked_mul(2)? != sectors {
        return None;
    }
    let footer = &bucket[size - footer_size..];
    let stamp = bucket[STAMP_OFFSET_IN_SECTOR] & 0x0F;
    let at = |k: usize| k * STAMP_SECTOR_BYTES + STAMP_OFFSET_IN_SECTOR;
    if (0..sectors).any(|k| bucket[at(k)] & 0x0F != stamp) {
        return None;
    }
    let mut out = bucket.to_vec();
    let mut changed = false;
    for k in 0..sectors {
        let i = sectors - 1 - k;
        let original = (footer[i / 2] >> (4 * (i % 2))) & 0x0F;
        let p = at(k);
        let restored = (bucket[p] & 0xF0) | original;
        changed |= restored != bucket[p];
        out[p] = restored;
    }
    changed.then_some(out)
}

/// One entry of a bucket's slot-index table: where a slot's bytes live
/// inside the bucket and how many bytes they span.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BucketSlot {
    /// Byte offset of the slot's data, measured from the start of the
    /// bucket (i.e. into the same buffer the bucket header was parsed
    /// from). Per `libnsfdb_bucket_read_slots` the slot data is addressed
    /// as `bucket_data[offset]`, not relative to the end of the header.
    pub offset: u16,
    /// Size in bytes of the slot's data.
    pub size: u16,
}

/// A borrowed view over a single bucket: the parsed header plus the
/// backing bytes, with slot-table resolution.
///
/// Bucket layout, reverse-engineered from `libnsfdb_bucket.c`:
///
/// ```text
/// +------------------+ offset 0
/// | header (66 B)    |
/// +------------------+
/// | slot data ...    |  slot bytes live here, addressed by absolute
/// |                  |  offset from the bucket start
/// +------------------+
/// | slot-index table |  number_of_slots entries, 4 bytes each,
/// |                  |  stored BACK-TO-FRONT: slot 0 occupies the last
/// |                  |  4 bytes before the footer. Each entry is
/// |                  |  [u16 offset][u16 size] (offset at the lower
/// |                  |  address, size at the higher).
/// +------------------+ size - footer_size
/// | footer           |
/// +------------------+ size
/// ```
///
/// Slot indices on disk are **1-based** (`libnsfdb_bucket_get_slot`
/// rejects index 0 and looks up `slot_index - 1`); RRV bucket-slot
/// entries carry the 1-based value, so [`Bucket::slot`] takes it as-is.
#[derive(Debug)]
pub struct Bucket<'a> {
    header: BucketHeader,
    /// Bytes from the bucket start, bounded to the bucket's declared
    /// `size` (or the available tail, whichever is shorter).
    bytes: &'a [u8],
}

impl<'a> Bucket<'a> {
    /// Parse a bucket from a buffer positioned at the bucket's file
    /// offset. The buffer may extend past the bucket (e.g. it is the
    /// remainder of the whole file); this constructor clamps the view to
    /// the bucket's declared `size` so slot resolution cannot read into a
    /// neighbouring structure.
    pub fn parse(bytes: &'a [u8]) -> Result<Self, NsfError> {
        let header = BucketHeader::parse(bytes)?;
        let declared = header.size as usize;
        // Clamp to declared size when the buffer is longer; tolerate a
        // buffer shorter than declared (truncated tail) by keeping what
        // we have - slot accessors bounds-check individually.
        let end = declared.min(bytes.len());
        Ok(Self {
            header,
            bytes: &bytes[..end],
        })
    }

    /// The parsed bucket header.
    pub fn header(&self) -> &BucketHeader {
        &self.header
    }

    /// Number of slots the bucket declares.
    pub fn slot_count(&self) -> u32 {
        self.header.number_of_slots
    }

    /// Resolve the slot-index entry for a 1-based `slot_index`.
    ///
    /// Returns [`NsfError::SlotIndexOutOfRange`] if the index is zero or
    /// beyond the declared slot count, or [`NsfError::TooShort`] if the
    /// bucket buffer does not actually contain the slot-index table the
    /// header advertises (truncated / corrupt bucket).
    pub fn slot_entry(&self, slot_index: u16) -> Result<BucketSlot, NsfError> {
        let count = self.header.number_of_slots;
        if slot_index == 0 || u32::from(slot_index) > count {
            return Err(NsfError::SlotIndexOutOfRange {
                requested: slot_index,
                available: count,
            });
        }
        // The slot-index table sits immediately below the footer and
        // grows downward: slot 0 is the last 4 bytes before the footer.
        let table_end = (self.bytes.len()).saturating_sub(self.header.footer_size as usize);
        // Entry for the (1-based) slot: 0-based ordinal is slot_index - 1.
        let ordinal = (slot_index - 1) as usize;
        // Lower bound of this entry within the table.
        let entry_base = match table_end.checked_sub(4 * (ordinal + 1)) {
            Some(b) => b,
            None => {
                return Err(NsfError::TooShort {
                    actual: self.bytes.len(),
                    required: 4 * (ordinal + 1),
                })
            }
        };
        let entry = self.bytes.get(entry_base..entry_base + 4).ok_or(NsfError::TooShort {
            actual: self.bytes.len(),
            required: entry_base + 4,
        })?;
        let offset = u16::from_le_bytes([entry[0], entry[1]]);
        let size = u16::from_le_bytes([entry[2], entry[3]]);
        Ok(BucketSlot { offset, size })
    }

    /// Return the raw bytes of the slot at the 1-based `slot_index`.
    ///
    /// Bounds-checks the slot's `(offset, size)` against the bucket so a
    /// corrupt slot-index table cannot read out of bounds; returns
    /// [`NsfError::TooShort`] in that case.
    pub fn slot(&self, slot_index: u16) -> Result<&'a [u8], NsfError> {
        let BucketSlot { offset, size } = self.slot_entry(slot_index)?;
        let start = offset as usize;
        let end = start + size as usize;
        self.bytes.get(start..end).ok_or(NsfError::TooShort {
            actual: self.bytes.len(),
            required: end,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn synthetic_bucket() -> Vec<u8> {
        let mut buf = vec![0u8; 128];
        buf[0] = BUCKET_SIGNATURE;
        buf[1] = 0x42;
        buf[6..10].copy_from_slice(&4096u32.to_le_bytes());
        // Modification timedate: leave zero; valid as opaque.
        buf[44..48].copy_from_slice(&100u32.to_le_bytes());
        buf[50..54].copy_from_slice(&12u32.to_le_bytes());
        buf
    }

    #[test]
    fn parses_synthetic_bucket() {
        let buf = synthetic_bucket();
        let h = BucketHeader::parse(&buf).unwrap();
        assert_eq!(h.header_size, 0x42);
        assert_eq!(h.size, 4096);
        assert_eq!(h.number_of_slots, 100);
        assert_eq!(h.footer_size, 12);
    }

    #[test]
    fn rejects_bad_signature() {
        let mut buf = synthetic_bucket();
        buf[0] = 0xFF;
        assert!(BucketHeader::parse(&buf).is_err());
    }

    /// Build a synthetic bucket with two slots so the back-to-front
    /// slot-index table can be exercised end to end.
    ///
    /// Layout (size = 100, footer = 12):
    /// - header  : [0, 66)
    /// - slot 0  : [66, 70)  = 4 bytes of 0xAA
    /// - slot 1  : [70, 73)  = 3 bytes of 0xBB
    /// - table   : [80, 88)  slot 1 entry then slot 0 entry (downward)
    /// - footer  : [88, 100)
    fn synthetic_bucket_with_slots() -> Vec<u8> {
        let mut buf = vec![0u8; 100];
        buf[0] = BUCKET_SIGNATURE;
        buf[1] = 0x42;
        buf[6..10].copy_from_slice(&100u32.to_le_bytes()); // size
        buf[44..48].copy_from_slice(&2u32.to_le_bytes()); // number_of_slots
        buf[50..54].copy_from_slice(&12u32.to_le_bytes()); // footer_size
        // slot data
        buf[66..70].copy_from_slice(&[0xAA; 4]);
        buf[70..73].copy_from_slice(&[0xBB; 3]);
        // slot-index table, back-to-front. table_end = 100 - 12 = 88.
        // slot 0 entry at [84, 88): offset=66, size=4
        buf[84..86].copy_from_slice(&66u16.to_le_bytes());
        buf[86..88].copy_from_slice(&4u16.to_le_bytes());
        // slot 1 entry at [80, 84): offset=70, size=3
        buf[80..82].copy_from_slice(&70u16.to_le_bytes());
        buf[82..84].copy_from_slice(&3u16.to_le_bytes());
        buf
    }

    #[test]
    fn bucket_resolves_one_based_slots() {
        let buf = synthetic_bucket_with_slots();
        let bucket = Bucket::parse(&buf).unwrap();
        assert_eq!(bucket.slot_count(), 2);
        // 1-based: slot 1 is the first slot.
        assert_eq!(bucket.slot(1).unwrap(), &[0xAA; 4]);
        assert_eq!(bucket.slot(2).unwrap(), &[0xBB; 3]);
    }

    #[test]
    fn bucket_rejects_slot_index_zero() {
        let buf = synthetic_bucket_with_slots();
        let bucket = Bucket::parse(&buf).unwrap();
        let err = bucket.slot(0).unwrap_err();
        assert!(matches!(
            err,
            NsfError::SlotIndexOutOfRange {
                requested: 0,
                available: 2
            }
        ));
    }

    #[test]
    fn bucket_rejects_slot_index_past_end() {
        let buf = synthetic_bucket_with_slots();
        let bucket = Bucket::parse(&buf).unwrap();
        let err = bucket.slot(3).unwrap_err();
        assert!(matches!(
            err,
            NsfError::SlotIndexOutOfRange {
                requested: 3,
                available: 2
            }
        ));
    }

    #[test]
    fn bucket_clamps_view_to_declared_size() {
        let mut buf = synthetic_bucket_with_slots();
        // Append trailing bytes from a "neighbouring" structure; the
        // bucket view must not read into them.
        buf.extend_from_slice(&[0x99; 64]);
        let bucket = Bucket::parse(&buf).unwrap();
        // Still resolves correctly against the clamped 100-byte view.
        assert_eq!(bucket.slot(2).unwrap(), &[0xBB; 3]);
    }

    #[test]
    fn bucket_slot_with_corrupt_offset_errors_not_panics() {
        let mut buf = synthetic_bucket_with_slots();
        // Point slot 1's offset past the end of the bucket.
        buf[84..86].copy_from_slice(&250u16.to_le_bytes());
        let bucket = Bucket::parse(&buf).unwrap();
        assert!(matches!(bucket.slot(1), Err(NsfError::TooShort { .. })));
    }

    #[test]
    fn bucket_slot_with_corrupt_size_overflow_errors_not_panics() {
        let mut buf = synthetic_bucket_with_slots();
        // Slot 1 offset stays valid (66) but size runs past the bucket
        // end. offset + size must be bounds-checked, not just offset.
        buf[86..88].copy_from_slice(&250u16.to_le_bytes());
        let bucket = Bucket::parse(&buf).unwrap();
        assert!(matches!(bucket.slot(1), Err(NsfError::TooShort { .. })));
    }

    /// A 2048-byte bucket (4 sectors, 2-byte footer) holding one slot whose
    /// text crosses the stamped byte of sector 1, stamped with nibble 9.
    fn stamped_bucket() -> (Vec<u8>, Vec<u8>) {
        let size = 2048usize;
        let mut clean = vec![0u8; size];
        clean[0] = BUCKET_SIGNATURE;
        clean[1] = 0x42;
        clean[6..10].copy_from_slice(&(size as u32).to_le_bytes());
        clean[44..48].copy_from_slice(&1u32.to_le_bytes());
        clean[50..54].copy_from_slice(&2u32.to_le_bytes());
        // "AB00123-45" placed so that '-' sits at sector 1, offset 66.
        let text = b"AB00123-45";
        let start = 512 + 66 - 7;
        clean[start..start + text.len()].copy_from_slice(text);
        clean[1024 + 66] = 0x6C; // 'l' in sector 2
        clean[1536 + 66] = 0x8E; // sector 3
        // slot 1 entry sits just below the footer.
        let table = size - 2 - 4;
        clean[table..table + 2].copy_from_slice(&(start as u16).to_le_bytes());
        clean[table + 2..table + 4].copy_from_slice(&(text.len() as u16).to_le_bytes());

        let mut stamped = clean.clone();
        let mut footer = [0u8; 2];
        for k in 0..4usize {
            let p = k * 512 + 66;
            let i = 3 - k;
            footer[i / 2] |= (clean[p] & 0x0F) << (4 * (i % 2));
            stamped[p] = (clean[p] & 0xF0) | 0x09;
        }
        stamped[size - 2..].copy_from_slice(&footer);
        clean[size - 2..].copy_from_slice(&footer);
        (stamped, clean)
    }

    #[test]
    fn a_stamped_bucket_is_restored_from_its_footer() {
        let (stamped, clean) = stamped_bucket();
        // Read raw, the slot shows the stamp.
        let raw = Bucket::parse(&stamped).unwrap();
        assert_eq!(raw.slot(1).unwrap(), b"AB00123)45");
        // Trailing bytes of a neighbour must not matter.
        let mut with_tail = stamped.clone();
        with_tail.extend_from_slice(&[0x77; 100]);
        let fixed = restore_sector_stamps(&with_tail).expect("layout matches");
        assert_eq!(fixed, clean);
        assert_eq!(Bucket::parse(&fixed).unwrap().slot(1).unwrap(), b"AB00123-45");
    }

    /// A stamped bucket of `sectors` sectors, every sector's stamped byte
    /// originally 0x41, with a footer that restores it.
    fn stamped_bucket_of(sectors: usize) -> Vec<u8> {
        let size = sectors * STAMP_SECTOR_BYTES;
        let footer = sectors / 2;
        let mut b = vec![0u8; size];
        b[0] = BUCKET_SIGNATURE;
        b[1] = 0x42;
        b[6..10].copy_from_slice(&(size as u32).to_le_bytes());
        b[50..54].copy_from_slice(&(footer as u32).to_le_bytes());
        for f in &mut b[size - footer..] {
            *f = 0x11;
        }
        // Stamps last: in a bucket this large the footer spans whole
        // sectors, whose stamped bytes are stamped like any other.
        for k in 0..sectors {
            b[k * STAMP_SECTOR_BYTES + STAMP_OFFSET_IN_SECTOR] = 0x49;
        }
        b
    }

    #[test]
    fn an_oversized_declared_bucket_is_left_alone() {
        // At the cap the layout is restored...
        let at_cap = stamped_bucket_of(MAX_STAMPED_BUCKET_BYTES / STAMP_SECTOR_BYTES);
        let fixed = restore_sector_stamps(&at_cap).expect("bucket at the cap");
        assert_eq!(fixed[STAMP_OFFSET_IN_SECTOR], 0x41);
        // ...and one that declares more is not copied, though every other
        // condition holds and all of its bytes are present.
        let over = stamped_bucket_of(MAX_STAMPED_BUCKET_BYTES / STAMP_SECTOR_BYTES + 2);
        assert!(restore_sector_stamps(&over).is_none());
        // A header that declares far more than the file holds is refused
        // on its size alone.
        let mut huge = stamped_bucket_of(4);
        huge[6..10].copy_from_slice(&u32::MAX.to_le_bytes());
        assert!(restore_sector_stamps(&huge).is_none());
    }

    #[test]
    fn a_bucket_that_does_not_match_the_stamp_layout_is_left_alone() {
        let (stamped, _) = stamped_bucket();
        // Footer does not hold one nibble per sector.
        let mut other_footer = stamped.clone();
        other_footer[50..54].copy_from_slice(&12u32.to_le_bytes());
        assert!(restore_sector_stamps(&other_footer).is_none());
        // Sectors disagree on the stamp nibble.
        let mut mixed = stamped.clone();
        mixed[1024 + 66] ^= 0x01;
        assert!(restore_sector_stamps(&mixed).is_none());
        // Bucket not wholly present.
        assert!(restore_sector_stamps(&stamped[..2000]).is_none());
        // The classic 12-byte-footer bucket of the other tests.
        assert!(restore_sector_stamps(&synthetic_bucket_with_slots()).is_none());
    }

    #[test]
    fn zero_slot_bucket_reports_no_slots() {
        let mut buf = synthetic_bucket_with_slots();
        // Force the declared slot count to zero.
        buf[44..48].copy_from_slice(&0u32.to_le_bytes());
        let bucket = Bucket::parse(&buf).unwrap();
        assert_eq!(bucket.slot_count(), 0);
        assert!(matches!(
            bucket.slot(1),
            Err(NsfError::SlotIndexOutOfRange {
                requested: 1,
                available: 0
            })
        ));
    }
}
