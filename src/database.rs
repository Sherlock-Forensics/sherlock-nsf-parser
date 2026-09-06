//! High-level `Database::open` API.
//!
//! Pulls the file header + DBINFO together, then exposes the entry
//! points for note enumeration. The actual RRV walk requires having
//! the file mmapped or fully buffered; this layer keeps the byte
//! window borrowed so consumers control I/O strategy.

use crate::bdb::BucketDescriptorBlock;
use crate::bucket::Bucket;
use crate::cx;
use crate::error::NsfError;
use crate::header::DbHeader;
use crate::info2::{Information2, INFO2_BYTES, INFO2_FILE_OFFSET};
use crate::note::NoteHeader;
use crate::rrv::{RrvBucketHeader, RrvEntry, RrvIter, RrvLocation};
use crate::superblock::{select_freshest, Superblock, SUPERBLOCK_HEADER_BYTES};

/// Body offset where the resident summary-descriptor page begins inside a
/// single-page database (the libnsfdb-documented prefix `4 + 10 + 10 +
/// 200`). For a multi-page database the resident page sits after the page
/// index: `SUMMARY_RESIDENT_PREFIX + (pages - 1) * SUMMARY_DESCRIPTOR_BYTES`.
const SUMMARY_RESIDENT_PREFIX: usize = 224;
/// On-disk size of one summary bucket descriptor (`file_position[4] +
/// modification_time[8] + 2 free-byte fields`).
const SUMMARY_DESCRIPTOR_BYTES: usize = 14;
/// Header size that precedes the descriptor array inside an *out-of-body*
/// summary descriptor page (the pages pointed to by the body page index).
/// Empirically derived (validated to 99.3% against the fakenames identity
/// oracle); see the `nsf_b2_addressing_cracked` engineering note. Distinct
/// from the in-body resident page, which uses [`SUMMARY_RESIDENT_PREFIX`].
const OUT_OF_BODY_PAGE_HEADER: usize = 250;
/// Number of bucket descriptors per out-of-body summary page. Empirically
/// derived (the resident page base lands at `(pages-1)*PER_OUT_OF_BODY_PAGE
/// + 1`, exactly matching the observed bucket_index range). The resident
/// page's count comes from `Superblock::number_of_summary_buckets` instead.
const PER_OUT_OF_BODY_PAGE: usize = 567;

fn read_u32_le(buf: &[u8], offset: usize) -> Option<u32> {
    buf.get(offset..offset + 4)
        .map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
}

/// Top-level handle to a buffered NSF file.
///
/// Holds a borrowed slice of the full file bytes. Cheap to construct -
/// no copies are made. The parser walks the file lazily; consumers pay
/// for what they enumerate.
#[derive(Debug)]
pub struct Database<'a> {
    bytes: &'a [u8],
    header: DbHeader,
}

impl<'a> Database<'a> {
    /// Open an NSF from a full-file byte buffer. Validates the file
    /// header and DBINFO; lazy on everything else.
    pub fn open(bytes: &'a [u8]) -> Result<Self, NsfError> {
        let header = DbHeader::parse(bytes)?;
        Ok(Self { bytes, header })
    }

    /// Parsed database header.
    pub fn header(&self) -> &DbHeader {
        &self.header
    }

    /// True when the database carries a populated data RRV bucket. A
    /// fresh / never-instantiated template will return false here -
    /// it has design notes via the non-data RRV but no data notes.
    pub fn has_data_rrv(&self) -> bool {
        self.header.data_rrv_bucket_position != 0
    }

    /// Parse + iterate the data RRV bucket if present. Returns the
    /// bucket header for diagnostics plus an iterator over the
    /// non-empty RRV entries.
    ///
    /// The data RRV bucket's file position is reported in 256-byte
    /// units in DBINFO; this method converts to a byte offset and
    /// reads `rrv_bucket_size` bytes from that point.
    pub fn data_rrv_iter(&self) -> Result<Option<(RrvBucketHeader, RrvIter<'a>)>, NsfError> {
        if !self.has_data_rrv() {
            return Ok(None);
        }
        let byte_offset = u64::from(self.header.data_rrv_bucket_position) * 256;
        let bucket_size = self.header.rrv_bucket_size as u64;
        let end = byte_offset.saturating_add(bucket_size);
        if end > self.bytes.len() as u64 {
            return Err(NsfError::TooShort {
                actual: self.bytes.len(),
                required: end as usize,
            });
        }
        let bucket = &self.bytes[byte_offset as usize..end as usize];
        let (header, iter) = RrvIter::new(bucket)?;
        Ok(Some((header, iter)))
    }

    /// Convenience: count non-empty entries in the data RRV. Walks the
    /// bucket but does not retain the per-entry state.
    pub fn data_note_count(&self) -> Result<u64, NsfError> {
        let Some((_, iter)) = self.data_rrv_iter()? else {
            return Ok(0);
        };
        Ok(iter.count() as u64)
    }

    /// True when the database carries a populated non-data RRV bucket.
    /// Design notes (forms, views) and, in databases like `fakenames.nsf`,
    /// the bulk of document notes are reached through the non-data RRV
    /// rather than the data RRV.
    pub fn has_non_data_rrv(&self) -> bool {
        self.header.non_data_rrv_bucket_position != 0
    }

    /// Parse + iterate the non-data RRV bucket if present. Mirrors
    /// [`Self::data_rrv_iter`] but reads from
    /// `non_data_rrv_bucket_position`. Most bucket-slot RRV entries (the
    /// ones [`Self::resolve_bucket_slot`] resolves) live here.
    pub fn non_data_rrv_iter(&self) -> Result<Option<(RrvBucketHeader, RrvIter<'a>)>, NsfError> {
        if !self.has_non_data_rrv() {
            return Ok(None);
        }
        let byte_offset = u64::from(self.header.non_data_rrv_bucket_position) * 256;
        let bucket_size = self.header.rrv_bucket_size as u64;
        let end = byte_offset.saturating_add(bucket_size);
        if end > self.bytes.len() as u64 {
            return Err(NsfError::TooShort {
                actual: self.bytes.len(),
                required: end as usize,
            });
        }
        let bucket = &self.bytes[byte_offset as usize..end as usize];
        let (header, iter) = RrvIter::new(bucket)?;
        Ok(Some((header, iter)))
    }

    /// Collect at most `limit` RRV entries from the data RRV for
    /// preview / list rendering. Useful for "show the first 200 notes
    /// in the viewer" without walking 40,000 entries up front.
    pub fn data_rrv_take(&self, limit: usize) -> Result<Vec<RrvEntry>, NsfError> {
        let Some((_, iter)) = self.data_rrv_iter()? else {
            return Ok(Vec::new());
        };
        Ok(iter.take(limit).collect())
    }

    /// Parse the database information extension block 2 (file offset 520,
    /// 124 bytes). Carries the 4 superblock positions + 2 BDB positions
    /// plus bucket-size knobs.
    pub fn information2(&self) -> Result<Information2, NsfError> {
        let end = INFO2_FILE_OFFSET + INFO2_BYTES;
        if self.bytes.len() < end {
            return Err(NsfError::TooShort {
                actual: self.bytes.len(),
                required: end,
            });
        }
        Information2::parse(&self.bytes[INFO2_FILE_OFFSET..end])
    }

    /// Parse every populated superblock copy (skipping uninitialized
    /// slots). Each entry is `(slot_index, Superblock)` so callers can
    /// report which copy was loaded. Domino allocates 4 slots and rotates
    /// commits across them; instantiated databases typically have 3
    /// populated and 1 empty, with the freshest by `modification_time`
    /// authoritative (use [`Self::freshest_superblock`]).
    ///
    /// Forensic-tool-grade resilience: slots are skipped silently when
    /// any of these conditions hold, rather than crashing the load:
    ///
    /// - Slot is empty (position or size zero).
    /// - Slot's declared byte offset extends past the file end.
    /// - Slot's body does not start with the superblock signature
    ///   `0E 00`. This catches fresh-template uninitialized regions
    ///   that Domino allocates with `allocation_granularity` but never
    ///   commits to (empirically these are filled with `AA AA AA AA`,
    ///   e.g. SB3 of `comparedbs.ntf`).
    ///
    /// Other parse failures (e.g. unexpected short read mid-header) are
    /// not expected in practice with a fully-buffered NSF and would
    /// surface as errors. The 3-redundant-copy WAL guarantees that
    /// silently dropping an unreadable slot leaves at least one valid
    /// copy.
    pub fn superblocks(&self) -> Result<Vec<(usize, Superblock)>, NsfError> {
        let info = self.information2()?;
        let mut out = Vec::with_capacity(4);
        for (i, slot) in info.superblocks.iter().enumerate() {
            let Some(byte_offset) = slot.byte_offset() else {
                continue;
            };
            let start = byte_offset as usize;
            let end = start.saturating_add(SUPERBLOCK_HEADER_BYTES);
            if end > self.bytes.len() {
                continue;
            }
            match Superblock::parse(&self.bytes[start..end]) {
                Ok(sb) => out.push((i, sb)),
                Err(NsfError::BadSubrecordSignature { .. }) => {
                    // Uninitialized / 0xAA-filled region. Skip silently.
                }
                Err(other) => return Err(other),
            }
        }
        Ok(out)
    }

    /// Convenience: parse all populated superblocks and return the
    /// freshest one by `modification_time`. The other three copies are
    /// write-ahead-log redundancy and should be ignored once this one
    /// is loaded. Returns `None` if no superblock slots are populated
    /// (extremely rare; would indicate a partially-initialized NSF).
    pub fn freshest_superblock(&self) -> Result<Option<(usize, Superblock)>, NsfError> {
        let all = self.superblocks()?;
        Ok(select_freshest(&all))
    }

    /// Decompress the freshest superblock's body (the CX-compressed region
    /// that carries the bucket-descriptor array). Returns `None` when the
    /// database has no superblock.
    ///
    /// Body layout from the superblock byte offset, per the reference:
    /// `[0,100)` header, then the compressed region of length
    /// `size - 112` (100-byte header + 12-byte footer removed), of which
    /// the first 4 bytes are a prefix the decompressor skips. The
    /// decompressed length is the header's `uncompressed_size` field.
    pub fn decompressed_superblock_body(&self) -> Result<Option<Vec<u8>>, NsfError> {
        let Some((slot, sb)) = self.freshest_superblock()? else {
            return Ok(None);
        };
        let info = self.information2()?;
        let Some(sb_offset) = info.superblocks.get(slot).and_then(|s| s.byte_offset()) else {
            return Ok(None);
        };
        let size = sb.size as usize;
        // Need at least header (100) + footer (12) + the 4-byte prefix.
        if size < SUPERBLOCK_HEADER_BYTES + 12 + 4 {
            return Err(NsfError::DecompressionFailed {
                detail: "superblock size too small to hold a compressed body",
            });
        }
        let region_start = sb_offset as usize + SUPERBLOCK_HEADER_BYTES;
        let region_len = size - SUPERBLOCK_HEADER_BYTES - 12;
        // The body is a chain of length-prefixed CX segments (the leading 4
        // bytes are the first segment's compressed length). Single-segment
        // bodies - the common superblock case - decode identically.
        let region_end = region_start + region_len;
        let region = self.bytes.get(region_start..region_end).ok_or(NsfError::TooShort {
            actual: self.bytes.len(),
            required: region_end,
        })?;
        let body = cx::decompress_chained(region, sb.uncompressed_size as usize)?;
        Ok(Some(body))
    }

    /// Build the global summary-bucket descriptor map: a 0-based vector of
    /// file byte offsets where `offsets[bucket_index - 1]` is the byte
    /// offset of the summary bucket an RRV bucket-slot entry's
    /// `bucket_index` refers to (`bucket_index` is 1-based on disk).
    ///
    /// # Multi-page geometry
    ///
    /// On modern ODS the summary bucket descriptors are spread across
    /// `number_of_summary_bucket_descriptor_pages` pages. The decompressed
    /// superblock body begins with a page index of `(pages - 1)` stride-14
    /// records (the page's `file_position` is the first 4 bytes of each
    /// record); those point to the out-of-body pages. The final (resident)
    /// page's descriptor array is inline in the body at
    /// `SUMMARY_RESIDENT_PREFIX + (pages - 1) * SUMMARY_DESCRIPTOR_BYTES`.
    /// Single-page databases (`pages <= 1`) have only the resident page at
    /// the libnsfdb-documented offset 224.
    ///
    /// libnsfdb itself only handles a single descriptor page (it errors on
    /// `> 1`), so the multi-page geometry here was reverse-engineered and
    /// validated against the `rrv_identifier` identity oracle (see
    /// [`Self::enumerate_notes`]). The out-of-body page header size
    /// ([`OUT_OF_BODY_PAGE_HEADER`]) and per-page descriptor count
    /// ([`PER_OUT_OF_BODY_PAGE`]) are empirical constants; mis-fits surface
    /// as identity-gate failures in [`Self::enumerate_notes`] rather than as
    /// silently wrong records.
    pub fn summary_bucket_offsets(&self) -> Result<Vec<u64>, NsfError> {
        Ok(self
            .summary_bucket_raw_fps()?
            .into_iter()
            .map(|fp| u64::from(fp) << 8)
            .collect())
    }

    /// The raw 4-byte `file_position` value of each summary bucket
    /// descriptor, 0-based by `bucket_index`. The byte offset is
    /// `fp << 8` (see [`Self::summary_bucket_offsets`]); the raw form is
    /// retained because the rare group-marker slots carry flag bits inside
    /// the `file_position` field that [`Self::enumerate_notes`] corrects.
    fn summary_bucket_raw_fps(&self) -> Result<Vec<u32>, NsfError> {
        let Some((_, sb)) = self.freshest_superblock()? else {
            return Ok(Vec::new());
        };
        let Some(body) = self.decompressed_superblock_body()? else {
            return Ok(Vec::new());
        };
        let pages = sb.number_of_summary_bucket_descriptor_pages as usize;
        let n_page_ptrs = pages.saturating_sub(1);
        let resident_count = sb.number_of_summary_buckets as usize;

        let mut fps = Vec::new();

        // Out-of-body pages, in page-index order.
        for j in 0..n_page_ptrs {
            let page_fp = read_u32_le(&body, j * SUMMARY_DESCRIPTOR_BYTES).unwrap_or(0);
            let page_off = u64::from(page_fp) << 8;
            for k in 0..PER_OUT_OF_BODY_PAGE {
                let o = page_off as usize
                    + OUT_OF_BODY_PAGE_HEADER
                    + k * SUMMARY_DESCRIPTOR_BYTES;
                fps.push(read_u32_le(self.bytes, o).unwrap_or(0));
            }
        }

        // Resident page, inline in the decompressed body.
        let resident_prefix = SUMMARY_RESIDENT_PREFIX + n_page_ptrs * SUMMARY_DESCRIPTOR_BYTES;
        for k in 0..resident_count {
            let o = resident_prefix + k * SUMMARY_DESCRIPTOR_BYTES;
            fps.push(read_u32_le(&body, o).unwrap_or(0));
        }

        Ok(fps)
    }

    /// Resolve a single RRV bucket-slot pair to the raw bytes of the slot's
    /// record, using the summary-bucket descriptor map.
    ///
    /// This is the physical resolution step: it does not identity-check the
    /// result. For verified note enumeration (where each resolved record is
    /// confirmed to carry the requested `rrv_identifier`), use
    /// [`Self::enumerate_notes`]. Rebuilds the descriptor map on each call;
    /// callers resolving many entries should prefer `enumerate_notes`, which
    /// builds the map once.
    pub fn resolve_bucket_slot(
        &self,
        bucket_index: u32,
        slot_index: u16,
    ) -> Result<&'a [u8], NsfError> {
        let offsets = self.summary_bucket_offsets()?;
        Self::resolve_in(self.bytes, &offsets, bucket_index, slot_index)
    }

    /// Resolve `bucket_index`/`slot_index` against a prebuilt descriptor map.
    fn resolve_in(
        bytes: &'a [u8],
        offsets: &[u64],
        bucket_index: u32,
        slot_index: u16,
    ) -> Result<&'a [u8], NsfError> {
        let ordinal = (bucket_index as usize)
            .checked_sub(1)
            .ok_or(NsfError::BucketIndexOutOfRange {
                requested: bucket_index,
                available: offsets.len(),
            })?;
        let off = *offsets
            .get(ordinal)
            .ok_or(NsfError::BucketIndexOutOfRange {
                requested: bucket_index,
                available: offsets.len(),
            })?;
        let start = off as usize;
        let bucket_bytes = bytes.get(start..).ok_or(NsfError::TooShort {
            actual: bytes.len(),
            required: start,
        })?;
        let bucket = Bucket::parse(bucket_bytes)?;
        bucket.slot(slot_index)
    }

    /// Parse the freshest Bucket Descriptor Block (BDB) - the master index
    /// of every RRV bucket in the database. Returns `None` when no BDB slot
    /// is populated (a fresh / never-instantiated shell). Of the two BDB
    /// copies in [`Information2`] (primary + write-ahead-log redundancy) the
    /// one with the higher `write_count` is authoritative.
    pub fn bucket_descriptor_block(&self) -> Result<Option<BucketDescriptorBlock>, NsfError> {
        let info = self.information2()?;
        let mut best: Option<BucketDescriptorBlock> = None;
        for slot in &info.bdbs {
            let Some(off) = slot.byte_offset() else {
                continue;
            };
            match BucketDescriptorBlock::parse(self.bytes, off, slot.size_bytes) {
                Ok(bdb) => {
                    if best.as_ref().map_or(true, |b| bdb.write_count > b.write_count) {
                        best = Some(bdb);
                    }
                }
                // A malformed / superseded BDB copy is skipped; the other
                // copy is the WAL redundancy that covers it.
                Err(_) => continue,
            }
        }
        Ok(best)
    }

    /// Enumerate every note in the database by walking the BDB -> all RRV
    /// buckets -> each RRV entry, resolving each to a note record.
    ///
    /// Every resolution is **identity-gated**: a note is only accepted if
    /// the resolved record's `rrv_identifier` (note header offset 6) equals
    /// the RRV entry's identifier. This is the chain-of-custody guarantee -
    /// a record is never returned unless it provably is the note the RRV
    /// entry points to. Entries that no candidate resolves under the gate
    /// are counted in `unresolved` rather than returned as possibly-wrong
    /// evidence.
    ///
    /// # Group-marker recovery
    ///
    /// A small set of summary-descriptor slots (the page's group-boundary
    /// slots) carry group-marker flag bits inside the `file_position` field:
    /// the low nibble, or bits 16-19 (in which case the true high nibble
    /// matches the locally-sequential neighbours). For each bucket-slot
    /// entry the resolver tries the raw descriptor first, then these
    /// marker-corrected candidates, accepting the first that passes the
    /// identity gate. Because acceptance requires an exact 32-bit
    /// `rrv_identifier` match, a wrong candidate cannot be accepted - the
    /// recovery is heuristic in *what it tries* but never in *what it
    /// returns*.
    pub fn enumerate_notes(&self) -> Result<NoteEnumeration, NsfError> {
        let mut out = NoteEnumeration::default();

        // RRV bucket size: superblock copy preferred, DBINFO as the fallback.
        //
        // The freshest superblock's `rrv_bucket_size` is 0 in a real slice of
        // databases (ToDo.nsf, notebook12_EN.ntf and teamrm12_EN.ntf in the
        // corpus) even though DBINFO names a valid 4096 and the RRV buckets
        // are plainly present - 63, 157 and 495 non-data RRV entries
        // respectively. Trusting the superblock copy alone returned zero
        // notes for every such database, which the viewer then presented as
        // an unreadable file.
        //
        // A missing superblock is likewise no longer fatal. The bucket
        // offsets come from the BDB and the two DBINFO pointers below, never
        // from the superblock, so its size field is the only thing wanted
        // here and DBINFO carries that too.
        let sb_size = self
            .freshest_superblock()?
            .map(|(_, sb)| sb.rrv_bucket_size as usize)
            .unwrap_or(0);
        let rrv_bucket_size = if sb_size != 0 {
            sb_size
        } else {
            self.header.rrv_bucket_size as usize
        };
        if rrv_bucket_size == 0 {
            return Ok(out);
        }
        let raw_fps = self.summary_bucket_raw_fps()?;

        // Collect every RRV bucket to walk: those listed in the BDB plus
        // the data and non-data RRV buckets named directly in DBINFO.
        // Deduped by byte offset - on modern ODS the DBINFO buckets are
        // usually also in the BDB; on older / simpler databases they may
        // not be, so both sources are needed for complete enumeration.
        let mut rrv_offsets: std::collections::BTreeSet<u64> = std::collections::BTreeSet::new();
        if let Some(bdb) = self.bucket_descriptor_block()? {
            rrv_offsets.extend(bdb.rrv_buckets.iter().map(|d| d.file_offset));
        }
        if self.header.data_rrv_bucket_position != 0 {
            rrv_offsets.insert(u64::from(self.header.data_rrv_bucket_position) * 256);
        }
        if self.header.non_data_rrv_bucket_position != 0 {
            rrv_offsets.insert(u64::from(self.header.non_data_rrv_bucket_position) * 256);
        }

        for &bucket_off in &rrv_offsets {
            let start = bucket_off as usize;
            let Some(slice) = self.bytes.get(start..start.saturating_add(rrv_bucket_size))
            else {
                continue;
            };
            let Ok((_, iter)) = RrvIter::new(slice) else {
                continue;
            };
            for entry in iter {
                let resolved = match entry.location {
                    RrvLocation::FilePosition {
                        file_position_pages,
                    } => {
                        out.file_position_total += 1;
                        let off = u64::from(file_position_pages) << 8;
                        self.bytes
                            .get(off as usize..)
                            .and_then(|buf| self.note_if_matches(entry.rrv_identifier, off, buf))
                    }
                    RrvLocation::BucketSlot {
                        bucket_index,
                        slot_index,
                        ..
                    } => {
                        out.bucket_slot_total += 1;
                        self.resolve_validated(&raw_fps, bucket_index, slot_index, entry.rrv_identifier)
                    }
                };
                match resolved {
                    Some(note) => out.notes.push(note),
                    None => out.unresolved += 1,
                }
            }
        }
        Ok(out)
    }

    /// Parse `buf` as a note header and return a [`ResolvedNote`] only if it
    /// carries `expected_identifier` (the identity gate).
    fn note_if_matches(
        &self,
        expected_identifier: u32,
        file_offset: u64,
        buf: &[u8],
    ) -> Option<ResolvedNote> {
        match NoteHeader::parse(buf) {
            Ok(header) if header.rrv_identifier == expected_identifier => Some(ResolvedNote {
                rrv_identifier: expected_identifier,
                file_offset,
                header,
            }),
            _ => None,
        }
    }

    /// Resolve a bucket-slot entry to an identity-verified note, trying the
    /// raw descriptor first then group-marker-corrected candidates. Returns
    /// `None` only if no candidate yields a note carrying `expected_id`.
    fn resolve_validated(
        &self,
        raw_fps: &[u32],
        bucket_index: u32,
        slot_index: u16,
        expected_id: u32,
    ) -> Option<ResolvedNote> {
        let ord = (bucket_index as usize).checked_sub(1)?;
        let primary = *raw_fps.get(ord)?;
        // High nibble (bits 16-19) of neighbouring descriptors, used to
        // repair a bits-16-19 group marker (buckets are locally sequential).
        let prev_hi = ord
            .checked_sub(1)
            .and_then(|i| raw_fps.get(i))
            .map(|f| f & 0x000F_0000)
            .unwrap_or(0);
        let next_hi = raw_fps.get(ord + 1).map(|f| f & 0x000F_0000).unwrap_or(0);

        let candidates = [
            primary,
            primary & 0xFFFF_FFF0,                    // low-nibble group marker
            (primary & 0xFFF0_FFFF) | prev_hi,        // bits-16-19 marker, prev high nibble
            (primary & 0xFFF0_FFFF) | next_hi,        // bits-16-19 marker, next high nibble
        ];

        for &fp in &candidates {
            let bucket_off = u64::from(fp) << 8;
            let Some(buf) = self.bytes.get(bucket_off as usize..) else {
                continue;
            };
            let Ok(bucket) = Bucket::parse(buf) else {
                continue;
            };
            let Ok(slot) = bucket.slot(slot_index) else {
                continue;
            };
            let slot_off = bucket_off + (slot.as_ptr() as usize - buf.as_ptr() as usize) as u64;
            if let Some(note) = self.note_if_matches(expected_id, slot_off, slot) {
                return Some(note);
            }
        }
        None
    }

    /// Return a note's non-summary data object - the separately-stored
    /// large payload that holds rich-text ($Body / mail bodies), file
    /// attachments (OBJECT items), and other items too big for the inline
    /// summary. `None` when the note has no non-summary data.
    ///
    /// Location: `non_summary_data_identifier << 8` is the byte offset of
    /// the object, which opens with a header - signature `0x0010`, then a
    /// `u32` size and the owning note's `u32` rrv_identifier (both validated
    /// here) - followed by the payload (a CD-record stream for rich text, or
    /// object segments for attachments). The returned slice is the whole
    /// object including that header; record-level decoding (CD records,
    /// attachment extraction) is a later slice.
    pub fn non_summary_data(&self, note: &ResolvedNote) -> Option<&'a [u8]> {
        let id = note.header.non_summary_data_identifier;
        let size = note.header.non_summary_data_size as usize;
        if id == 0 || size < 10 {
            return None;
        }
        let off = (u64::from(id) << 8) as usize;
        let obj = self.bytes.get(off..off.checked_add(size)?)?;
        // Validate the object header against the note's own metadata so a
        // wrong / stale identifier never returns unrelated bytes.
        let hdr_size = u32::from_le_bytes([obj[2], obj[3], obj[4], obj[5]]) as usize;
        let hdr_rrv = u32::from_le_bytes([obj[6], obj[7], obj[8], obj[9]]);
        if obj[0] != 0x10 || obj[1] != 0x00 || hdr_size != size || hdr_rrv != note.rrv_identifier {
            return None;
        }
        Some(obj)
    }

    /// Decode a note's rich-text body and attachments from its non-summary
    /// data (CD-record stream). Returns `None` when the note has no
    /// non-summary data or it decodes to nothing. See [`crate::cd`].
    pub fn note_content(&self, note: &ResolvedNote) -> Option<crate::cd::NoteContent> {
        let obj = self.non_summary_data(note)?;
        let content = crate::cd::parse(obj);
        if content.is_empty() {
            None
        } else {
            Some(content)
        }
    }

    /// Parse the items (fields) of a resolved note: each item's name id,
    /// type/flags, and raw value bytes. See [`crate::item`] for the layout
    /// and what is / isn't decoded (field-name resolution is a later slice).
    ///
    /// The record window is bounded to the note's declared `size` so item
    /// values cannot read into a neighbouring record.
    pub fn note_items(&self, note: &ResolvedNote) -> Vec<crate::item::NoteItem<'a>> {
        let start = note.file_offset as usize;
        let end = start
            .saturating_add(note.header.size as usize)
            .min(self.bytes.len());
        let Some(record) = self.bytes.get(start..end) else {
            return Vec::new();
        };
        crate::item::parse_items(record, note.header.number_of_note_items)
    }
}

/// One note resolved (and identity-verified) by [`Database::enumerate_notes`].
#[derive(Debug, Clone)]
pub struct ResolvedNote {
    /// The RRV identifier the note was reached through (== the note
    /// header's `rrv_identifier`; the identity gate guarantees equality).
    pub rrv_identifier: u32,
    /// Byte offset of the note record within the file.
    pub file_offset: u64,
    /// The parsed note header.
    pub header: NoteHeader,
}

/// Result of a full-database note enumeration via [`Database::enumerate_notes`].
#[derive(Debug, Clone, Default)]
pub struct NoteEnumeration {
    /// Every identity-verified note, in RRV-walk order.
    pub notes: Vec<ResolvedNote>,
    /// RRV entries that could not be resolved to a note carrying the
    /// expected identifier (failed the identity gate). Reported rather than
    /// returned as possibly-wrong records.
    pub unresolved: u64,
    /// Total bucket-slot RRV entries seen.
    pub bucket_slot_total: u64,
    /// Total file-position RRV entries seen.
    pub file_position_total: u64,
}
