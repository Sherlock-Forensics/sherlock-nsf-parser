//! Bucket Descriptor Block (BDB) - the master index of every RRV bucket.
//!
//! A single RRV bucket maps only a small contiguous slice of NoteIDs. To
//! enumerate every note in a database you must walk *all* RRV buckets, and
//! the list of those buckets lives in the BDB. `Information2` carries two
//! BDB (position, size) slots (a primary copy plus write-ahead-log
//! redundancy); the freshest by `write_count` is authoritative.
//!
//! On-disk layout per `nsfdb_bucket_descriptor_block.h` +
//! `libnsfdb_io_handle_read_bucket_descriptor_block`:
//!
//! ```text
//! header (66 bytes)
//!   0   2   signature (0x01 0x00)
//!   2   2   version   (0x02 0x00)
//!   4   2   compression_type (must be 1 = CX)
//!   6   4   uncompressed_size
//!  10   4   write_count
//!  14   4   size (total BDB size incl. header + body + footer)
//!  18   8   modification_time
//!  26   4   number_of_unique_name_keys
//!  30   4   unknown1
//!  34   4   unique_name_key_text_size
//!  38   4   number_of_rrv_bucket_descriptors
//!  42   4   number_of_unk_hash_table_entries
//!  46   8   unknown2
//!  54   4   checksum
//!  58   8   unknown3
//! body (CX-compressed; first 4 bytes of the compressed region are a
//!       prefix the decompressor skips, exactly like the superblock body)
//!   decompressed: number_of_rrv_bucket_descriptors * 8 bytes, then the
//!   Unique Name Key table (not parsed here).
//! footer (12 bytes): modification_time[8] + checksum[4]
//! ```
//!
//! Each RRV bucket descriptor is 8 bytes: `file_offset[4]` (in 256-byte
//! units after clearing the type flag) + `initial_rrv_identifier[4]`. The
//! low bit of `file_offset` is the bucket-type flag: set => non-data,
//! clear => data. The flag is cleared and the value shifted left 8 to get
//! the byte offset.

use crate::cx;
use crate::error::NsfError;

/// BDB header size on disk.
const BDB_HEADER_BYTES: usize = 66;
/// BDB footer size on disk.
const BDB_FOOTER_BYTES: usize = 12;
/// On-disk size of one RRV bucket descriptor in the decompressed body.
const RRV_DESCRIPTOR_BYTES: usize = 8;
/// On-disk size of one Unique Name Key table entry in the decompressed
/// body: `[text_offset: u32][name_length: u16][unused: u32]`.
const UNK_ENTRY_BYTES: usize = 10;
/// Bytes of preamble before the UNK name-text payload begins.
const UNK_TEXT_PREAMBLE: usize = 4;

/// RRV bucket kind. Data buckets hold document/data NoteIDs; non-data
/// buckets hold design and special-note NoteIDs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RrvBucketKind {
    /// Data RRV bucket (`type 'd'` in the reference).
    Data,
    /// Non-data RRV bucket (`type 'n'`).
    NonData,
}

/// One entry in the BDB: where an RRV bucket lives plus the RRV-identifier
/// counter it starts from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RrvBucketDescriptor {
    /// Whether this RRV bucket holds data or non-data NoteIDs.
    pub kind: RrvBucketKind,
    /// Byte offset of the RRV bucket within the file.
    pub file_offset: u64,
    /// The RRV identifier the bucket's first entry corresponds to. (The
    /// RRV bucket header carries its own `initial_rrv_identifier` too; this
    /// is the BDB's record of it.)
    pub initial_rrv_identifier: u32,
}

/// Parsed Bucket Descriptor Block: the list of every RRV bucket plus the
/// Unique Name Key table (field-name strings).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BucketDescriptorBlock {
    /// Write-count from the header. Higher = fresher (used to pick between
    /// the primary and WAL-redundant copies).
    pub write_count: u32,
    /// Every RRV bucket descriptor, in file order.
    pub rrv_buckets: Vec<RrvBucketDescriptor>,
    /// Unique Name Key strings, indexed by `name_id` (a note item's
    /// `name_id` indexes this vector to recover the field name, e.g.
    /// `FirstName`, `$UpdatedBy`). Empty when the UNK text region was not
    /// present / decodable.
    pub unk_names: Vec<String>,
    /// Item type byte per `name_id` (UNK entry offset 6). Parallel to
    /// `unk_names`.
    pub unk_types: Vec<u8>,
    /// Item class byte per `name_id` (UNK entry offset 7): 0x03 NUMBER,
    /// 0x04 TIME, 0x05 TEXT, 0x06 FORMULA, 0x00 NOCOMPUTE. Parallel to
    /// `unk_names`.
    pub unk_classes: Vec<u8>,
}

impl BucketDescriptorBlock {
    /// Resolve a note item's `name_id` to its field-name string.
    pub fn name(&self, name_id: u16) -> Option<&str> {
        self.unk_names.get(name_id as usize).map(|s| s.as_str())
    }

    /// Authoritative data kind of the field with this `name_id`, from the
    /// UNK table's class/type bytes. Returns [`FieldKind::Unknown`] when the
    /// id is out of range.
    pub fn field_kind(&self, name_id: u16) -> crate::item::FieldKind {
        let i = name_id as usize;
        let class = self.unk_classes.get(i).copied().unwrap_or(0xFF);
        let ty = self.unk_types.get(i).copied().unwrap_or(0xFF);
        if class == 0xFF {
            crate::item::FieldKind::Unknown
        } else {
            crate::item::field_kind(class, ty)
        }
    }
}

impl BucketDescriptorBlock {
    /// Parse the BDB located at `offset` (byte offset into the full file
    /// buffer). `available_size` is the slot's declared size from
    /// `Information2`; the header's own `size` field must not exceed it.
    pub fn parse(file: &[u8], offset: u64, available_size: u32) -> Result<Self, NsfError> {
        let start = offset as usize;
        let header = file
            .get(start..start + BDB_HEADER_BYTES)
            .ok_or(NsfError::TooShort {
                actual: file.len(),
                required: start + BDB_HEADER_BYTES,
            })?;

        if header[0] != 0x01 || header[1] != 0x00 {
            return Err(NsfError::BadSubrecordSignature {
                kind: "bucket descriptor block",
                expected: [0x01, 0x00],
                observed: [header[0], header[1]],
            });
        }

        let u16_at = |o: usize| u16::from_le_bytes([header[o], header[o + 1]]);
        let u32_at = |o: usize| {
            u32::from_le_bytes([header[o], header[o + 1], header[o + 2], header[o + 3]])
        };

        let compression_type = u16_at(4);
        let uncompressed_size = u32_at(6) as usize;
        let write_count = u32_at(10);
        let stored_size = u32_at(14) as usize;
        let number_of_unique_name_keys = u32_at(26) as usize;
        let unique_name_key_text_size = u32_at(34) as usize;
        let number_of_rrv_bucket_descriptors = u32_at(38) as usize;

        if stored_size > available_size as usize {
            return Err(NsfError::TooShort {
                actual: available_size as usize,
                required: stored_size,
            });
        }
        if compression_type != 1 {
            return Err(NsfError::CompressionUnsupported {
                structure: "bucket descriptor block",
                compression_type,
            });
        }
        if stored_size < BDB_HEADER_BYTES + BDB_FOOTER_BYTES + 4 {
            return Err(NsfError::DecompressionFailed {
                detail: "bucket descriptor block size too small to hold a compressed body",
            });
        }

        let body_len = stored_size - BDB_HEADER_BYTES - BDB_FOOTER_BYTES;
        let comp_start = start + BDB_HEADER_BYTES;
        let comp = file
            .get(comp_start..comp_start + body_len)
            .ok_or(NsfError::TooShort {
                actual: file.len(),
                required: comp_start + body_len,
            })?;
        // The body is a chain of length-prefixed CX segments: RRV
        // descriptors + UNK table (segment 0), the UNK name text
        // (segment 1), then the UNK hash table (segment 2).
        let body = cx::decompress_chained(comp, uncompressed_size)?;

        let need = number_of_rrv_bucket_descriptors * RRV_DESCRIPTOR_BYTES;
        if body.len() < need {
            return Err(NsfError::TooShort {
                actual: body.len(),
                required: need,
            });
        }

        let mut rrv_buckets = Vec::with_capacity(number_of_rrv_bucket_descriptors);
        for i in 0..number_of_rrv_bucket_descriptors {
            let base = i * RRV_DESCRIPTOR_BYTES;
            let raw = u32::from_le_bytes([
                body[base],
                body[base + 1],
                body[base + 2],
                body[base + 3],
            ]);
            let initial_rrv_identifier = u32::from_le_bytes([
                body[base + 4],
                body[base + 5],
                body[base + 6],
                body[base + 7],
            ]);
            let kind = if raw & 1 != 0 {
                RrvBucketKind::NonData
            } else {
                RrvBucketKind::Data
            };
            let file_offset = u64::from(raw & 0xFFFF_FFFE) << 8;
            rrv_buckets.push(RrvBucketDescriptor {
                kind,
                file_offset,
                initial_rrv_identifier,
            });
        }

        // Unique Name Key table: `name_id` -> field-name string. It follows
        // the RRV descriptors in the decompressed body; each 10-byte entry
        // indexes into the name-text payload that follows the table (past a
        // 4-byte preamble). Out-of-bounds entries degrade to empty strings
        // rather than failing the whole parse.
        let unk_table_start = number_of_rrv_bucket_descriptors * RRV_DESCRIPTOR_BYTES;
        let text_start = unk_table_start + number_of_unique_name_keys * UNK_ENTRY_BYTES;
        let text_payload_start = text_start + UNK_TEXT_PREAMBLE;
        let text_end = (text_start + unique_name_key_text_size).min(body.len());
        let mut unk_names = Vec::with_capacity(number_of_unique_name_keys);
        let mut unk_types = Vec::with_capacity(number_of_unique_name_keys);
        let mut unk_classes = Vec::with_capacity(number_of_unique_name_keys);
        let text = body.get(text_payload_start..text_end).unwrap_or(&[]);
        for i in 0..number_of_unique_name_keys {
            let e = unk_table_start + i * UNK_ENTRY_BYTES;
            // Entry: [text_offset:u32][name_len:u16][item_type:1][item_class:1][unknown:2]
            let (name, ty, class) = body
                .get(e..e + UNK_ENTRY_BYTES)
                .map(|d| {
                    let off = u32::from_le_bytes([d[0], d[1], d[2], d[3]]) as usize;
                    let len = u16::from_le_bytes([d[4], d[5]]) as usize;
                    let name = text
                        .get(off..off + len)
                        .map(|s| String::from_utf8_lossy(s).into_owned())
                        .unwrap_or_default();
                    (name, d[6], d[7])
                })
                .unwrap_or_default();
            unk_names.push(name);
            unk_types.push(ty);
            unk_classes.push(class);
        }

        Ok(Self {
            write_count,
            rrv_buckets,
            unk_names,
            unk_types,
            unk_classes,
        })
    }

    /// Parse a pre-Notes 5 (ODS 20) BDB: uncompressed, at DBINFO's BDB
    /// position read as bytes.
    ///
    /// Decoded from a real Notes 4 mail file, where every boundary below
    /// is fixed by the header's own counts and the last name ends exactly at
    /// the header's used-size word:
    ///
    /// ```text
    /// header (32 bytes)
    ///   0   2   signature (0x01 0x00)
    ///   2   2   0x8000 in the one file seen; not checked
    ///   6   2   number of summary-bucket descriptors (12 bytes each)
    ///   8   2   number of Unique Name Keys (8 bytes each)
    ///  10   2   number of RRV bucket descriptors (8 bytes each)
    ///  12   2   bytes used: the end of the name text
    /// 32  RRV bucket descriptors: position (bytes; bit 0 set = non-data),
    ///     initial_rrv_identifier
    ///     summary-bucket descriptors: position, TIMEDATE
    ///     UNK entries: text_offset u16, length u16, type u8, class u8, u16
    ///     name text, packed, offsets relative to its start
    /// ```
    ///
    /// The sample's names chained perfectly - each of 1,677 offsets is the
    /// previous offset plus its length - and resolved the mail fields to
    /// their expected names (SendTo, Subject, From, Body, PostedDate). The
    /// parse refuses anything whose counts do not land the text end on the
    /// used-size word, so a different layout yields no names rather than
    /// wrong ones.
    pub fn parse_legacy(file: &[u8], offset: u64, available_size: u32) -> Result<Self, NsfError> {
        const HEADER: usize = 32;
        const SUMMARY_DESCRIPTOR: usize = 12;
        const UNK_ENTRY: usize = 8;
        let start = offset as usize;
        let block = file
            .get(start..start.saturating_add(available_size as usize))
            .filter(|b| b.len() >= HEADER)
            .ok_or(NsfError::TooShort {
                actual: file.len(),
                required: start.saturating_add(available_size as usize),
            })?;
        if block[0] != 0x01 || block[1] != 0x00 {
            return Err(NsfError::BadSubrecordSignature {
                kind: "bucket descriptor block",
                expected: [0x01, 0x00],
                observed: [block[0], block[1]],
            });
        }
        let u16_at = |o: usize| u16::from_le_bytes([block[o], block[o + 1]]) as usize;
        let u32_at = |o: usize| u32::from_le_bytes([block[o], block[o + 1], block[o + 2], block[o + 3]]);
        let n_summary = u16_at(6);
        let n_unk = u16_at(8);
        let n_rrv = u16_at(10);
        let used = u16_at(12);
        let unk_start = HEADER + n_rrv * RRV_DESCRIPTOR_BYTES + n_summary * SUMMARY_DESCRIPTOR;
        let text_start = unk_start + n_unk * UNK_ENTRY;
        let inconsistent = NsfError::DecompressionFailed {
            detail: "legacy bucket descriptor block counts do not account for its size",
        };
        if used > block.len() || text_start > used {
            return Err(inconsistent);
        }
        if n_unk > 0 {
            let last = unk_start + (n_unk - 1) * UNK_ENTRY;
            if text_start + u16_at(last) + u16_at(last + 2) != used {
                return Err(inconsistent);
            }
        }

        let rrv_buckets = (0..n_rrv)
            .map(|i| {
                let o = HEADER + i * RRV_DESCRIPTOR_BYTES;
                let raw = u32_at(o);
                RrvBucketDescriptor {
                    kind: if raw & 1 != 0 { RrvBucketKind::NonData } else { RrvBucketKind::Data },
                    file_offset: u64::from(raw & 0xFFFF_FFFE),
                    initial_rrv_identifier: u32_at(o + 4),
                }
            })
            .collect();

        let text = &block[text_start..used];
        let mut unk_names = Vec::with_capacity(n_unk);
        let mut unk_types = Vec::with_capacity(n_unk);
        let mut unk_classes = Vec::with_capacity(n_unk);
        for i in 0..n_unk {
            let e = unk_start + i * UNK_ENTRY;
            let (off, len) = (u16_at(e), u16_at(e + 2));
            unk_names.push(
                text.get(off..off + len)
                    .map(|s| String::from_utf8_lossy(s).into_owned())
                    .unwrap_or_default(),
            );
            unk_types.push(block[e + 4]);
            unk_classes.push(block[e + 5]);
        }
        Ok(Self {
            write_count: 0,
            rrv_buckets,
            unk_names,
            unk_types,
            unk_classes,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A legacy BDB laid out like the Notes 4 sample: two RRV descriptors,
    /// one summary descriptor, three names.
    fn legacy_bdb() -> Vec<u8> {
        let names: [(&str, u8, u8); 3] = [("SendTo", 0, 5), ("Subject", 0, 5), ("PostedDate", 0, 4)];
        let mut b = vec![0u8; 32];
        b[0] = 0x01;
        b[2..4].copy_from_slice(&0x8000u16.to_le_bytes());
        b[6..8].copy_from_slice(&1u16.to_le_bytes());
        b[8..10].copy_from_slice(&3u16.to_le_bytes());
        b[10..12].copy_from_slice(&2u16.to_le_bytes());
        for (pos, id) in [(0xC001u32, 262u32), (0x0049_AC00, 8442)] {
            b.extend_from_slice(&pos.to_le_bytes());
            b.extend_from_slice(&id.to_le_bytes());
        }
        b.extend_from_slice(&[0u8; 12]);
        let mut off = 0u16;
        for (n, ty, cl) in names {
            b.extend_from_slice(&off.to_le_bytes());
            b.extend_from_slice(&(n.len() as u16).to_le_bytes());
            b.extend_from_slice(&[ty, cl, 0x6E, 0x56]);
            off += n.len() as u16;
        }
        for (n, _, _) in names {
            b.extend_from_slice(n.as_bytes());
        }
        let used = b.len() as u16;
        b[12..14].copy_from_slice(&used.to_le_bytes());
        b.resize(256, 0);
        b
    }

    #[test]
    fn a_legacy_bdb_yields_names_kinds_and_byte_offsets() {
        let b = legacy_bdb();
        let bdb = BucketDescriptorBlock::parse_legacy(&b, 0, 256).unwrap();
        assert_eq!(bdb.unk_names, vec!["SendTo", "Subject", "PostedDate"]);
        assert_eq!(bdb.field_kind(1), crate::item::FieldKind::Text);
        assert_eq!(bdb.field_kind(2), crate::item::FieldKind::Time);
        assert_eq!(bdb.rrv_buckets[0].kind, RrvBucketKind::NonData);
        assert_eq!(bdb.rrv_buckets[0].file_offset, 0xC000);
        assert_eq!(bdb.rrv_buckets[1].file_offset, 0x0049_AC00);
        assert_eq!(bdb.rrv_buckets[1].initial_rrv_identifier, 8442);
    }

    /// Counts that do not land the text on the used-size word mean the
    /// layout is not the one decoded; no names beats wrong names.
    #[test]
    fn a_legacy_bdb_whose_counts_do_not_close_is_refused() {
        let mut b = legacy_bdb();
        b[8..10].copy_from_slice(&2u16.to_le_bytes());
        assert!(BucketDescriptorBlock::parse_legacy(&b, 0, 256).is_err());
    }

    #[test]
    fn rejects_bad_signature() {
        let mut buf = vec![0u8; 128];
        buf[0] = 0xFF;
        let err = BucketDescriptorBlock::parse(&buf, 0, 128).unwrap_err();
        assert!(matches!(
            err,
            NsfError::BadSubrecordSignature {
                kind: "bucket descriptor block",
                ..
            }
        ));
    }

    #[test]
    fn rejects_unsupported_compression() {
        let mut buf = vec![0u8; 128];
        buf[0] = 0x01;
        buf[1] = 0x00;
        // compression_type = 0 (uncompressed) is unsupported.
        buf[4] = 0x00;
        buf[14..18].copy_from_slice(&100u32.to_le_bytes()); // stored_size
        let err = BucketDescriptorBlock::parse(&buf, 0, 128).unwrap_err();
        assert!(matches!(
            err,
            NsfError::CompressionUnsupported {
                structure: "bucket descriptor block",
                ..
            }
        ));
    }

    #[test]
    fn rejects_stored_size_over_available() {
        let mut buf = vec![0u8; 128];
        buf[0] = 0x01;
        buf[1] = 0x00;
        buf[4] = 0x01; // compression_type = CX
        buf[14..18].copy_from_slice(&4096u32.to_le_bytes()); // stored_size > available
        let err = BucketDescriptorBlock::parse(&buf, 0, 128).unwrap_err();
        assert!(matches!(err, NsfError::TooShort { .. }));
    }
}
