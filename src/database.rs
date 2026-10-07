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
use crate::rrv::{LegacyRrvBucket, RrvBucketHeader, RrvEntry, RrvIter, RrvLocation};
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
    /// The data RRV bucket's file position is converted to a byte offset
    /// with [`DbHeader::position_bytes`], and `rrv_bucket_size` bytes are
    /// read from that point. Modern-layout buckets only: a pre-Notes 5
    /// bucket fails the header check here; see [`crate::LegacyRrvBucket`].
    pub fn data_rrv_iter(&self) -> Result<Option<(RrvBucketHeader, RrvIter<'a>)>, NsfError> {
        if !self.has_data_rrv() {
            return Ok(None);
        }
        let byte_offset = self.header.position_bytes(self.header.data_rrv_bucket_position);
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
        let byte_offset = self.header.position_bytes(self.header.non_data_rrv_bucket_position);
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
        if self.header.uses_byte_positions() {
            // One uncompressed copy, named directly by DBINFO. A layout that
            // does not close is no BDB rather than an error: the notes are
            // still readable without field names.
            let pos = self.header.bucket_descriptor_block_position;
            if pos == 0 {
                return Ok(None);
            }
            return Ok(BucketDescriptorBlock::parse_legacy(
                self.bytes,
                self.header.position_bytes(pos),
                self.header.bucket_descriptor_block_size,
            )
            .ok());
        }
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
        if self.header.uses_byte_positions() {
            return Ok(self.enumerate_legacy());
        }
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
                let (resolved, location) = match entry.location {
                    RrvLocation::FilePosition {
                        file_position_pages,
                    } => {
                        out.file_position_total += 1;
                        let off = u64::from(file_position_pages) << 8;
                        let r = match self.bytes.get(off as usize..) {
                            Some(buf) => self.note_at(entry.rrv_identifier, off, buf),
                            None => Err(WithheldReason::Unresolvable),
                        };
                        (r, WithheldLocation::FilePosition { file_position_pages })
                    }
                    RrvLocation::BucketSlot {
                        bucket_index,
                        slot_index,
                        ..
                    } => {
                        out.bucket_slot_total += 1;
                        let r = self.resolve_validated(
                            &raw_fps,
                            bucket_index,
                            slot_index,
                            entry.rrv_identifier,
                        );
                        (r, WithheldLocation::BucketSlot { bucket_index, slot_index })
                    }
                };
                out.record(entry.rrv_identifier, location, resolved);
            }
        }
        Ok(out)
    }

    /// Enumeration for a pre-Notes 5 (ODS 20) database.
    ///
    /// There is no BDB, superblock or summary-bucket step to take: each RRV
    /// entry is the byte offset of a note record, and the buckets form two
    /// chains (data and non-data) that start at the DBINFO pointers and run
    /// back through each header's previous-bucket field. See
    /// [`LegacyRrvBucket`] for how that layout was established.
    ///
    /// The identity gate is the modern one, unchanged: a record is a note
    /// only if it parses as a note header carrying the identifier its entry
    /// claims. On the first ODS 20 mail file 10,231 notes passed it with the
    /// modern note header unchanged; the other 3,436 entries pointed at
    /// 0x0007 records, which are not notes.
    fn enumerate_legacy(&self) -> NoteEnumeration {
        let mut out = NoteEnumeration::default();
        let bucket_size = self.header.rrv_bucket_size as usize;
        if bucket_size < crate::rrv::LEGACY_RRV_HEADER_BYTES {
            return out;
        }
        let mut seen = std::collections::BTreeSet::new();
        // The chains from DBINFO, plus every bucket the BDB lists, so a
        // break in a chain cannot hide the buckets beyond it. Each is walked
        // once whichever route reaches it first.
        let mut starts = vec![
            self.header.data_rrv_bucket_position,
            self.header.non_data_rrv_bucket_position,
        ];
        if let Ok(Some(bdb)) = self.bucket_descriptor_block() {
            starts.extend(
                bdb.rrv_buckets
                    .iter()
                    .filter_map(|d| u32::try_from(d.file_offset).ok()),
            );
        }
        for start in starts {
            let mut pos = start;
            // Every bucket is visited once: a chain that loops, or two chains
            // that share a tail, cannot walk forever or count twice.
            while pos != 0 && seen.insert(pos) {
                let start = pos as usize;
                let Some(slice) = self.bytes.get(start..start.saturating_add(bucket_size)) else {
                    break;
                };
                let Ok(bucket) = LegacyRrvBucket::parse(slice) else {
                    break;
                };
                for (id, off) in bucket.entries() {
                    out.file_position_total += 1;
                    let r = match self.bytes.get(off as usize..) {
                        Some(buf) => self.note_at(id, off, buf),
                        None => Err(WithheldReason::Unresolvable),
                    };
                    out.record(id, WithheldLocation::FileOffset { byte_offset: off }, r);
                }
                pos = bucket.previous_bucket_position;
            }
        }
        out
    }

    /// Parse `buf` as a note header and apply the identity gate, reporting
    /// which way it failed so the caller can classify a withheld entry.
    fn note_at(
        &self,
        expected_identifier: u32,
        file_offset: u64,
        buf: &[u8],
    ) -> Result<ResolvedNote, WithheldReason> {
        let parsed = if self.header.uses_byte_positions() {
            NoteHeader::parse_legacy(buf)
        } else {
            NoteHeader::parse(buf)
        };
        match parsed {
            Ok(header) if header.rrv_identifier == expected_identifier => Ok(ResolvedNote {
                rrv_identifier: expected_identifier,
                file_offset,
                header,
            }),
            // Parsed as a note, but a different one. The characteristic
            // shape of a stale RRV entry whose slot has been reused.
            Ok(header) => Err(WithheldReason::IdentityMismatch {
                found_identifier: header.rrv_identifier,
                found_note_class: header.note_class,
            }),
            Err(_) => Err(WithheldReason::NotANoteRecord {
                found_signature: u16::from_le_bytes([
                    buf.first().copied().unwrap_or(0),
                    buf.get(1).copied().unwrap_or(0),
                ]),
            }),
        }
    }

    /// Resolve a bucket-slot entry to an identity-verified note, trying the
    /// raw descriptor first then group-marker-corrected candidates. Errors
    /// only if no candidate yields a note carrying `expected_id`; the error
    /// reports the most informative failure any candidate produced.
    fn resolve_validated(
        &self,
        raw_fps: &[u32],
        bucket_index: u32,
        slot_index: u16,
        expected_id: u32,
    ) -> Result<ResolvedNote, WithheldReason> {
        let Some(ord) = (bucket_index as usize).checked_sub(1) else {
            return Err(WithheldReason::Unresolvable);
        };
        let Some(&primary) = raw_fps.get(ord) else {
            return Err(WithheldReason::Unresolvable);
        };
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

        // Best failure seen across the candidates. An IdentityMismatch says
        // the slot was located and holds a real but different note, which is
        // far more informative than "could not locate", so it outranks the
        // other reasons when several candidates fail differently.
        let mut best_err = WithheldReason::Unresolvable;
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
            match self.note_at(expected_id, slot_off, slot) {
                Ok(note) => return Ok(note),
                Err(e) => {
                    if e.rank() > best_err.rank() {
                        best_err = e;
                    }
                }
            }
        }
        Err(best_err)
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
    ///
    /// On a pre-Notes 5 database it is something else: the identifier is a
    /// byte offset to the non-summary items' bare values, back to back in
    /// descriptor order, with no header. Established on a Notes 4 mail file,
    /// where the three sampled pointers opened on a "Received: from" header
    /// and on rich-text values (type word 0x0001, then CD records), and the
    /// size matched what the viewer showed for those notes. The slice is
    /// returned only when the non-summary items' declared sizes add up to
    /// exactly that size, so a misread pointer yields nothing.
    pub fn non_summary_data(&self, note: &ResolvedNote) -> Option<&'a [u8]> {
        if self.header.uses_byte_positions() {
            return self.legacy_non_summary(note);
        }
        self.object_bytes(
            note.header.non_summary_data_identifier,
            note.header.non_summary_data_size,
            note.rrv_identifier,
        )
    }

    /// The same lookup from raw header values, for a record that is not a
    /// `ResolvedNote` - a carved candidate, for instance.
    ///
    /// The identity check is the point and is not optional: the object
    /// header must carry the same RRV the caller expects, so a stale or
    /// wrong identifier returns `None` rather than unrelated bytes. A carved
    /// candidate is unverified as a note, but the object it points at either
    /// matches its identifier or is not returned.
    pub fn object_bytes(&self, identifier: u32, size: u32, expect_rrv: u32) -> Option<&'a [u8]> {
        let size = size as usize;
        if identifier == 0 || size < 10 {
            return None;
        }
        let off = (u64::from(identifier) << 8) as usize;
        let obj = self.bytes.get(off..off.checked_add(size)?)?;
        let hdr_size = u32::from_le_bytes([obj[2], obj[3], obj[4], obj[5]]) as usize;
        let hdr_rrv = u32::from_le_bytes([obj[6], obj[7], obj[8], obj[9]]);
        if obj[0] != 0x10 || obj[1] != 0x00 || hdr_size != size || hdr_rrv != expect_rrv {
            return None;
        }
        Some(obj)
    }

    /// The note's record bytes, bounded to its declared size.
    fn record(&self, note: &ResolvedNote) -> Option<&'a [u8]> {
        let start = note.file_offset as usize;
        let end = start
            .saturating_add(note.header.size as usize)
            .min(self.bytes.len());
        self.bytes.get(start..end)
    }

    /// Pre-Notes 5 non-summary data: see [`Self::non_summary_data`].
    fn legacy_non_summary(&self, note: &ResolvedNote) -> Option<&'a [u8]> {
        let size = note.header.non_summary_data_size as usize;
        if note.header.non_summary_data_identifier == 0 || size == 0 {
            return None;
        }
        let declared = crate::item::non_summary_total(
            self.record(note)?,
            note.header.number_of_note_items,
            crate::note::LEGACY_NOTE_HEADER_BYTES,
        )?;
        if declared != size {
            return None;
        }
        let off = note.header.non_summary_data_identifier as usize;
        self.bytes.get(off..off.checked_add(size)?)
    }

    /// Decode a note's rich-text body and attachments from its non-summary
    /// data (CD-record stream). Returns `None` when the note has no
    /// non-summary data or it decodes to nothing. See [`crate::cd`].
    ///
    /// On a pre-Notes 5 database the rich-text items' values are decoded
    /// directly, since there is no object wrapping them.
    pub fn note_content(&self, note: &ResolvedNote) -> Option<crate::cd::NoteContent> {
        let content = if self.header.uses_byte_positions() {
            let values: Vec<&[u8]> = self
                .note_items_walk(note)
                .items
                .iter()
                .filter(|it| it.type_flags & crate::item::ITEM_SUMMARY == 0)
                .filter(|it| it.value.get(..2) == Some(&[0x01, 0x00][..]))
                .map(|it| it.value)
                .collect();
            crate::cd::parse_items(&values)
        } else {
            crate::cd::parse(self.non_summary_data(note)?)
        };
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
    /// Walk a note's items WITH the accounting: how many the header
    /// declared, how many were recovered, and where the walk stopped.
    ///
    /// Measured on fakenames.nsf, four notes declare between 45 and 139
    /// items and yield none, because the first item's declared value size
    /// runs past the end of the record - a large note keeps its values
    /// somewhere this build does not follow. Returning a bare empty vector
    /// for those, as `note_items` must for compatibility, tells a caller
    /// "this note has no fields" when the truth is "this note's fields were
    /// not reachable".
    /// Collect the non-note records an enumeration withheld.
    ///
    /// The viewer shows these because "the RRV table points at 75 records
    /// this build cannot read" is evidence an examiner may want to look at
    /// themselves, and counting them without offering them is the coverage
    /// gap this project keeps finding.
    pub fn non_note_records(&self, en: &NoteEnumeration) -> Vec<NonNoteRecord> {
        self.non_note_records_with_skipped(en).0
    }

    /// The same, plus how many non-note targets could NOT be offered because
    /// they live in a bucket slot rather than at a file position.
    ///
    /// Locating a bucket slot needs the bucket walk, which this method does
    /// not do. Returning the count separately means a caller can say "3 more
    /// exist and are not listed here" instead of silently showing a shorter
    /// list than the enumeration counted.
    pub fn non_note_records_with_skipped(
        &self,
        en: &NoteEnumeration,
    ) -> (Vec<NonNoteRecord>, usize) {
        let skipped = en
            .withheld
            .iter()
            .filter(|wh| {
                matches!(wh.reason, WithheldReason::NotANoteRecord { .. })
                    && matches!(wh.location, WithheldLocation::BucketSlot { .. })
            })
            .count();
        let recs = en
            .withheld
            .iter()
            .filter_map(|wh| {
                let WithheldReason::NotANoteRecord { found_signature } = wh.reason else {
                    return None;
                };
                // A bucket slot needs the bucket walk to locate; not offered
                // rather than guessed at.
                let off = wh.location.byte_offset()?;
                let declared_len = self
                    .bytes
                    .get(off as usize + 2..off as usize + 6)
                    .map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
                    .filter(|len| {
                        *len > 0 && (off as usize).saturating_add(*len as usize) <= self.bytes.len()
                    });
                Some(NonNoteRecord {
                    rrv_identifier: wh.rrv_identifier,
                    file_offset: off,
                    signature: found_signature,
                    declared_len,
                })
            })
            .collect();
        (recs, skipped)
    }

    pub fn note_items_walk(&self, note: &ResolvedNote) -> crate::item::ItemWalk<'a> {
        let Some(record) = self.record(note) else {
            return crate::item::ItemWalk {
                items: Vec::new(),
                claimed: note.header.number_of_note_items,
                stop: crate::item::ItemWalkStop::TableDoesNotFit {
                    needed: 0,
                    record_len: 0,
                },
                unreached_name_ids: Vec::new(),
                unreached: Vec::new(),
            };
        };
        if self.header.uses_byte_positions() {
            // 84-byte header, and the non-summary values are bare bytes this
            // walk can hand out directly (checked to add up first).
            return crate::item::walk_items_at(
                record,
                note.header.number_of_note_items,
                crate::note::LEGACY_NOTE_HEADER_BYTES,
                self.legacy_non_summary(note),
            );
        }
        crate::item::walk_items(record, note.header.number_of_note_items)
    }

    pub fn note_items(&self, note: &ResolvedNote) -> Vec<crate::item::NoteItem<'a>> {
        self.note_items_walk(note).items
    }
}

/// A record the RRV table points at that is not a note.
///
/// Measured on fakenames.nsf: 75 of these, every one carrying signature
/// 0x001B, between 1KB and 7KB, and DENSE with data - one is 3997 non-zero
/// bytes out of 4115. They are live records holding real content that this
/// build cannot interpret, which is a different thing from empty space and
/// a different thing again from a note it failed to read.
///
/// The bytes are offered as they are. Nothing here claims to know their
/// internal structure.
#[derive(Debug, Clone)]
pub struct NonNoteRecord {
    /// The identifier the RRV entry claimed.
    pub rrv_identifier: u32,
    /// Byte offset of the record in the file.
    pub file_offset: u64,
    /// The 16-bit signature found there.
    pub signature: u16,
    /// Length declared by the record's own u32 at offset 2, when that value
    /// is plausible (non-zero and inside the file). `None` means the length
    /// could not be established, and the caller must not invent one.
    pub declared_len: Option<u32>,
}

impl NonNoteRecord {
    /// The record's bytes, when a plausible length was declared.
    pub fn bytes<'a>(&self, file: &'a [u8]) -> Option<&'a [u8]> {
        let len = self.declared_len? as usize;
        let start = self.file_offset as usize;
        file.get(start..start.checked_add(len)?)
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

/// Upper bound on per-entry withheld detail retained by an enumeration. The
/// `unresolved` count stays exact past this point; only the detail stops.
pub const MAX_WITHHELD_DETAIL: usize = 10_000;

/// Why an RRV entry did not yield an identity-verified note.
///
/// An examiner asked "did your tool miss anything?" needs a better answer
/// than a bare count. These distinguish an entry that is *expected* to fail
/// (a stale pointer into a reused slot - ordinary database churn) from one
/// that indicates the resolver could not follow the layout.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WithheldReason {
    /// The target parsed as a valid note record, but one carrying a
    /// different `rrv_identifier`. The signature of a stale or superseded
    /// RRV entry whose slot has since been reused by another note. Benign:
    /// ordinary database churn, and the identity gate is doing its job.
    IdentityMismatch {
        /// The `rrv_identifier` actually found at the target.
        found_identifier: u32,
        /// The note class actually found at the target.
        found_note_class: u16,
    },
    /// The target was located but did not parse as a note record.
    ///
    /// Measured over the corpus (506 such entries) this splits two ways, and
    /// `found_signature` is what separates them:
    ///
    /// - **484 file-position entries**, carrying signature `0x001B` (428) or
    ///   `0x0007` (56) - never the note signature. Every file-position RRV
    ///   entry in the corpus lands here, and their identifiers are the
    ///   reserved low RRVs (`0x106` is also the `initial_rrv_identifier` in
    ///   the RRV bucket headers). These address database-internal
    ///   allocations that were never notes, so withholding them is correct.
    ///
    /// - **22 bucket-slot entries**, carrying the note signature `0x0004`
    ///   but failing header parse anyway - a truncated slot or an
    ///   unparseable TIMEDATE. These are real note records the parser cannot
    ///   yet read, and are tracked as a parser gap rather than accepted as
    ///   normal.
    ///
    /// So a `found_signature` of `0x0004` here means evidence was missed; any
    /// other value means the entry was never a note to begin with.
    NotANoteRecord {
        /// The 16-bit signature actually found at the target, so a report
        /// can name the allocation class instead of only saying "not a note".
        found_signature: u16,
    },
    /// The target could not be located: descriptor index out of range, the
    /// bucket did not parse, or the slot index exceeded the bucket. This is
    /// the reason that indicates a resolver gap rather than data churn.
    Unresolvable,
}

impl WithheldReason {
    /// Ordering used to pick the most informative failure across the
    /// candidate descriptors tried for one bucket-slot entry.
    fn rank(&self) -> u8 {
        match self {
            WithheldReason::Unresolvable => 0,
            WithheldReason::NotANoteRecord { .. } => 1,
            WithheldReason::IdentityMismatch { .. } => 2,
        }
    }
}

/// Where a withheld entry pointed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WithheldLocation {
    /// A direct file position, in 256-byte pages.
    FilePosition {
        /// Page number the entry named.
        file_position_pages: u32,
    },
    /// A summary-bucket slot.
    BucketSlot {
        /// 1-based bucket index.
        bucket_index: u32,
        /// Slot within the bucket.
        slot_index: u16,
    },
    /// A direct file position in bytes, from a pre-Notes 5 RRV bucket.
    FileOffset {
        /// Byte offset the entry named.
        byte_offset: u64,
    },
}

impl WithheldLocation {
    /// Byte offset of the target, for the two direct-position variants.
    pub fn byte_offset(&self) -> Option<u64> {
        match *self {
            Self::FilePosition { file_position_pages } => Some(u64::from(file_position_pages) << 8),
            Self::FileOffset { byte_offset } => Some(byte_offset),
            Self::BucketSlot { .. } => None,
        }
    }
}

/// One RRV entry that failed the identity gate, with the reason it failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WithheldEntry {
    /// The identifier the RRV entry claimed.
    pub rrv_identifier: u32,
    /// Where the entry pointed.
    pub location: WithheldLocation,
    /// Why no note was returned for it.
    pub reason: WithheldReason,
}

/// Result of a full-database note enumeration via [`Database::enumerate_notes`].
#[derive(Debug, Clone, Default)]
pub struct NoteEnumeration {
    /// Every identity-verified note, in RRV-walk order.
    pub notes: Vec<ResolvedNote>,
    /// RRV entries that could not be resolved to a note carrying the
    /// expected identifier (failed the identity gate). Reported rather than
    /// returned as possibly-wrong records. Always exact.
    pub unresolved: u64,
    /// Per-entry detail for the withheld entries, capped at
    /// [`MAX_WITHHELD_DETAIL`]. Lets a report say *why* entries were
    /// withheld rather than only how many.
    pub withheld: Vec<WithheldEntry>,
    /// True when more entries were withheld than `withheld` retains.
    pub withheld_truncated: bool,
    /// Total bucket-slot RRV entries seen.
    pub bucket_slot_total: u64,
    /// Total file-position RRV entries seen.
    pub file_position_total: u64,
}

impl NoteEnumeration {
    /// Keep a resolved note, or count and (within the cap) describe why an
    /// entry was withheld.
    fn record(
        &mut self,
        rrv_identifier: u32,
        location: WithheldLocation,
        resolved: Result<ResolvedNote, WithheldReason>,
    ) {
        match resolved {
            Ok(note) => self.notes.push(note),
            Err(reason) => {
                self.unresolved += 1;
                // Detail is capped so a corrupt database cannot make
                // enumeration allocate without bound. The count above stays
                // exact regardless.
                if self.withheld.len() < MAX_WITHHELD_DETAIL {
                    self.withheld.push(WithheldEntry {
                        rrv_identifier,
                        location,
                        reason,
                    });
                } else {
                    self.withheld_truncated = true;
                }
            }
        }
    }

    /// Count of withheld entries (among those with retained detail) that
    /// carry `reason`'s discriminant.
    pub fn withheld_count(&self, matches: impl Fn(&WithheldReason) -> bool) -> usize {
        self.withheld.iter().filter(|w| matches(&w.reason)).count()
    }

    /// Number of withheld entries that indicate evidence the parser could
    /// not read, as opposed to entries that were never notes.
    ///
    /// Counts [`WithheldReason::Unresolvable`] (the target could not be
    /// located) and any [`WithheldReason::NotANoteRecord`] whose target
    /// nonetheless carries the note signature (a note record that failed to
    /// parse). An [`WithheldReason::IdentityMismatch`] is ordinary slot
    /// reuse and a non-note signature was never a note, so neither counts.
    ///
    /// The same holds on a pre-Notes 5 database: its notes carry the same
    /// 0x0004 signature (10,231 resolved that way on the first ODS 20 mail
    /// file), so a target without it is not a note there either.
    pub fn missed_evidence_count(&self) -> usize {
        self.withheld
            .iter()
            .filter(|w| match w.reason {
                WithheldReason::Unresolvable => true,
                WithheldReason::NotANoteRecord { found_signature } => {
                    found_signature == u16::from_le_bytes(crate::note::NOTE_SIGNATURE)
                }
                WithheldReason::IdentityMismatch { .. } => false,
            })
            .count()
    }

    /// True when no withheld entry indicates missed evidence and the detail
    /// is complete enough to say so.
    pub fn all_gaps_explained(&self) -> bool {
        !self.withheld_truncated && self.missed_evidence_count() == 0
    }
}

#[cfg(test)]
mod non_note_tests {
    use super::*;

    fn corpus() -> Option<std::path::PathBuf> {
        let p = std::path::PathBuf::from(CORPUS_ROOT)
            .join("real-nsf")
            .join("fakenames.nsf");
        p.is_file().then_some(p)
    }

    const CORPUS_ROOT: &str = r"C:\SherlockForensics\.scratch\nsf-samples";

    /// The records are real: dense with data rather than free space, and
    /// every withheld non-note entry is offered rather than counted.
    #[test]
    fn corpus_non_note_records_are_live_records_with_content() {
        let Some(path) = corpus() else {
            eprintln!("corpus not present; skipping");
            return;
        };
        let bytes = std::fs::read(&path).expect("read");
        let db = Database::open(&bytes).expect("open");
        let en = db.enumerate_notes().expect("enumerate");
        let recs = db.non_note_records(&en);
        let withheld_non_note = en
            .withheld
            .iter()
            .filter(|w| matches!(w.reason, WithheldReason::NotANoteRecord { .. }))
            .count();
        assert_eq!(recs.len(), withheld_non_note, "every non-note entry is offered");
        assert!(!recs.is_empty(), "the corpus should hold some");

        let mut with_bytes = 0usize;
        let mut dense = 0usize;
        for r in &recs {
            assert_eq!(r.signature, 0x001B, "one class in this database");
            if let Some(b) = r.bytes(&bytes) {
                with_bytes += 1;
                // Free space would be zeros; these are not.
                if b.iter().filter(|x| **x != 0).count() * 4 > b.len() {
                    dense += 1;
                }
            }
        }
        eprintln!(
            "non-note records: {} total, {with_bytes} with a plausible length, {dense} dense",
            recs.len()
        );
        assert!(dense > 0, "these records hold content, which is why they are offered");
    }

    #[test]
    fn a_record_with_no_plausible_length_offers_no_bytes() {
        // Inventing a length would hand the operator a slice of whatever
        // followed it, labelled as a record.
        let r = NonNoteRecord {
            rrv_identifier: 1,
            file_offset: 0,
            signature: 0x001B,
            declared_len: None,
        };
        assert!(r.bytes(&[0u8; 64]).is_none());
    }

    #[test]
    fn corpus_counts_non_note_targets_by_location_kind() {
        let Some(path) = corpus() else {
            eprintln!("corpus not present; skipping");
            return;
        };
        let bytes = std::fs::read(&path).expect("read");
        let db = Database::open(&bytes).expect("open");
        let en = db.enumerate_notes().expect("enumerate");
        let (mut file_pos, mut bucket) = (0usize, 0usize);
        for wh in &en.withheld {
            if !matches!(wh.reason, WithheldReason::NotANoteRecord { .. }) {
                continue;
            }
            match wh.location {
                WithheldLocation::FilePosition { .. } | WithheldLocation::FileOffset { .. } => {
                    file_pos += 1
                }
                WithheldLocation::BucketSlot { .. } => bucket += 1,
            }
        }
        eprintln!("non-note targets: {file_pos} at a file position, {bucket} in a bucket slot");
    }

    #[test]
    fn a_length_past_the_end_of_the_file_is_refused() {
        let r = NonNoteRecord {
            rrv_identifier: 1,
            file_offset: 32,
            signature: 0x001B,
            declared_len: Some(1000),
        };
        assert!(r.bytes(&[0u8; 64]).is_none());
    }
}

#[cfg(test)]
mod legacy_tests {
    use super::*;

    const BUCKET: usize = 0x100;

    /// A synthetic ODS 20 file shaped like the first real one: DBINFO
    /// positions in bytes, a data chain of two buckets (newest first, linked
    /// back through the header), and one non-data bucket.
    fn ods20() -> Vec<u8> {
        let mut b = vec![0u8; 0x4000];
        b[0] = 0x1A;
        b[2..6].copy_from_slice(&768u32.to_le_bytes());
        let d = 6;
        b[d..d + 4].copy_from_slice(&20u32.to_le_bytes());
        b[d + 14..d + 18].copy_from_slice(&0x1300u32.to_le_bytes()); // non-data RRV
        b[d + 38..d + 40].copy_from_slice(&0x0250u16.to_le_bytes()); // flags, template bit set
        b[d + 56..d + 60].copy_from_slice(&0x1100u32.to_le_bytes()); // data RRV (newest)
        b[d + 70..d + 72].copy_from_slice(&(BUCKET as u16).to_le_bytes());
        b[d + 82..d + 86].copy_from_slice(&0x4000u32.to_le_bytes()); // file size, bytes

        let bucket = |b: &mut Vec<u8>, at: usize, prev: u32, initial: u32, entries: &[u32]| {
            b[at..at + BUCKET].fill(0xFF);
            b[at] = 0x06;
            b[at + 1] = 0x0A;
            b[at + 2..at + 6].copy_from_slice(&prev.to_le_bytes());
            b[at + 6..at + 10].copy_from_slice(&initial.to_le_bytes());
            for (i, e) in entries.iter().enumerate() {
                let o = at + 10 + i * 4;
                b[o..o + 4].copy_from_slice(&e.to_le_bytes());
            }
        };
        let note = |b: &mut Vec<u8>, at: usize, id: u32| {
            b[at] = 0x04;
            b[at + 2..at + 6].copy_from_slice(&100u32.to_le_bytes());
            b[at + 6..at + 10].copy_from_slice(&id.to_le_bytes());
            b[at + 40..at + 42].copy_from_slice(&1u16.to_le_bytes());
        };
        // Older data bucket, ids 10.. ; newest, ids 1002..
        bucket(&mut b, 0x1000, 0, 10, &[0x2040, u32::MAX, 0x2100]);
        bucket(&mut b, 0x1100, 0x1000, 1002, &[0x2200]);
        bucket(&mut b, 0x1300, 0, 30, &[0x2300]);
        note(&mut b, 0x2040, 10);
        note(&mut b, 0x2100, 18);
        note(&mut b, 0x2200, 1002);
        // 0x2300 is left as something that is not a modern note record.
        b[0x2300] = 0x07;
        b
    }

    #[test]
    fn an_ods20_header_counts_bytes_and_is_not_a_template() {
        let b = ods20();
        let db = Database::open(&b).unwrap();
        let h = db.header();
        assert!(h.uses_byte_positions());
        assert_eq!(h.file_size_from_header_bytes(), 0x4000);
        assert!(!h.is_template(), "the 0x0010 bit is unverified before ODS 43");
    }

    #[test]
    fn the_legacy_walk_follows_both_chains_through_the_identity_gate() {
        let b = ods20();
        let en = Database::open(&b).unwrap().enumerate_notes().unwrap();
        let mut ids: Vec<u32> = en.notes.iter().map(|n| n.rrv_identifier).collect();
        ids.sort();
        assert_eq!(ids, vec![10, 18, 1002], "both data buckets, empties skipped");
        assert_eq!(en.file_position_total, 4);
        assert_eq!(en.unresolved, 1);
        let w = en.withheld[0];
        assert_eq!(w.rrv_identifier, 30);
        assert_eq!(w.location, WithheldLocation::FileOffset { byte_offset: 0x2300 });
    }

    /// ODS 20 notes carry the modern 0x0004 signature, so a target without
    /// it is classified as on any other database: not a note. A real note
    /// under another identifier is stale reuse, as anywhere else.
    #[test]
    fn legacy_targets_are_classified_by_signature_like_any_other() {
        let mut b = ods20();
        let en = Database::open(&b).unwrap().enumerate_notes().unwrap();
        assert_eq!(en.missed_evidence_count(), 0, "0x0007 is not a note");
        b[0x2300] = 0x04;
        b[0x2302..0x2306].copy_from_slice(&100u32.to_le_bytes());
        b[0x2306..0x230A].copy_from_slice(&999u32.to_le_bytes());
        let en = Database::open(&b).unwrap().enumerate_notes().unwrap();
        assert_eq!(en.unresolved, 1);
        assert!(matches!(en.withheld[0].reason, WithheldReason::IdentityMismatch { .. }));
    }

    /// A chain whose previous pointer loops back must end, not spin.
    #[test]
    fn a_looping_chain_is_walked_once() {
        let mut b = ods20();
        b[0x1000 + 2..0x1000 + 6].copy_from_slice(&0x1100u32.to_le_bytes());
        let en = Database::open(&b).unwrap().enumerate_notes().unwrap();
        assert_eq!(en.notes.len(), 3);
    }

    /// A Notes 4 mail note as the sampled ones are laid out: an 84-byte
    /// header, the Body (non-summary) declared before the Subject, the
    /// Subject's value in the record, and the Body's value bare at the
    /// non-summary pointer.
    fn with_mail_note(nonsum_size: u32) -> Vec<u8> {
        let mut b = ods20();
        let body: &[u8] = &[
            0x01, 0x00, // TYPE_COMPOSITE
            0x85, 0xFF, 0x0E, 0x00, 0, 0, 0, 0, b'H', b'e', b'l', b'l', b'o', b'!',
        ];
        let at = 0x2200;
        b[at..at + 0x100].fill(0);
        b[at] = 0x04;
        b[at + 6..at + 10].copy_from_slice(&1002u32.to_le_bytes());
        b[at + 40..at + 42].copy_from_slice(&1u16.to_le_bytes());
        b[at + 50..at + 52].copy_from_slice(&2u16.to_le_bytes());
        b[at + 56..at + 60].copy_from_slice(&0x3000u32.to_le_bytes());
        b[at + 60..at + 64].copy_from_slice(&nonsum_size.to_le_bytes());
        let d = at + 84;
        for (i, (id, flags, size)) in [(0x7Eu16, 0x0002u16, body.len() as u16), (0x68, 0x0004, 5)]
            .iter()
            .enumerate()
        {
            let o = d + i * 8;
            b[o..o + 2].copy_from_slice(&id.to_le_bytes());
            b[o + 2..o + 4].copy_from_slice(&flags.to_le_bytes());
            b[o + 4..o + 6].copy_from_slice(&size.to_le_bytes());
        }
        b[d + 16..d + 21].copy_from_slice(b"Hi Ed");
        let size = (84 + 16 + 5) as u32;
        b[at + 2..at + 6].copy_from_slice(&size.to_le_bytes());
        b[0x3000..0x3000 + body.len()].copy_from_slice(body);
        b
    }

    #[test]
    fn a_legacy_note_reads_its_fields_and_its_body() {
        let b = with_mail_note(16);
        let db = Database::open(&b).unwrap();
        let en = db.enumerate_notes().unwrap();
        let n = en.notes.iter().find(|n| n.rrv_identifier == 1002).unwrap();
        let w = db.note_items_walk(n);
        let subject = w.items.iter().find(|i| i.name_id == 0x68).unwrap();
        assert_eq!(subject.as_text(), "Hi Ed");
        assert!(w.items.iter().any(|i| i.name_id == 0x7E), "the body item gets its value");
        assert_eq!(db.note_content(n).unwrap().body_text, "Hello!");
    }

    /// The pointer is only trusted when the non-summary sizes add up to
    /// the header's size. Off by one, and the body is not read at all.
    #[test]
    fn a_legacy_body_whose_sizes_do_not_add_up_is_not_read() {
        let b = with_mail_note(17);
        let db = Database::open(&b).unwrap();
        let en = db.enumerate_notes().unwrap();
        let n = en.notes.iter().find(|n| n.rrv_identifier == 1002).unwrap();
        assert!(db.note_content(n).is_none());
        let w = db.note_items_walk(n);
        assert!(w.unreached.iter().any(|u| u.name_id == 0x7E));
        assert_eq!(w.items.iter().find(|i| i.name_id == 0x68).unwrap().as_text(), "Hi Ed");
    }
}
