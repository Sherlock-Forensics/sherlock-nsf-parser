//! Domino "CX" decompression - used for the superblock body.
//!
//! # Clean-room notice
//!
//! This is a from-scratch reimplementation written from an *understanding*
//! of the algorithm, not a translation of any source. libnsfdb (LGPLv3)
//! was consulted at development time as an algorithmic reference only. No
//! LGPL code is incorporated into this Apache-2.0 crate. The abstraction
//! here (an explicit
//! LSB-first [`BitReader`] with `read_bit` / `read_bits` / `read_run`
//! primitives) is deliberately structured in Rust idioms rather than
//! mirroring the reference's manual 16-bit-window bit juggling.
//!
//! # The format
//!
//! Despite the "CX" / "Huffman" naming in some references, the scheme is a
//! bit-oriented LZ77 variant. Bits are consumed LSB-first within each byte.
//! The first 3 bits of byte 0 are a mode header (must be > 3; lower values
//! are unsupported), so decoding starts at bit index 3 of byte 0.
//!
//! Each token begins with one tag bit:
//!
//! - tag `0`  -> a literal: the next 8 bits (LSB-first) are an output byte.
//! - tag `1`  -> a back-reference (length, offset):
//!   - a second tag bit: `0` means an explicit length follows (run-coded,
//!     see [`BitReader::read_run`]); `1` means the minimum length.
//!   - length = decoded-run (or 0 when omitted) + 2.
//!   - length >= 0x102 is the end-of-stream marker.
//!   - when length > 2, a third tag bit: `0` means the high bits of the
//!     offset follow (same run coding), shifted left by 8; `1` means no
//!     high bits.
//!   - the low 8 bits of the offset always follow.
//!   - copy `length` bytes from `output[len - offset]`, byte by byte so
//!     overlapping runs replicate correctly.
//!
//! The run coding for lengths/offsets: a unary prefix of `w-1` zero bits
//! terminated by a one bit selects a field width `w` (1..=9, the 9 cap
//! matching the reference's 8-data-bit + implicit-terminator behaviour),
//! then `w` value bits follow. The decoded magnitude is
//! `(1 << w) - 1 + value`.

use crate::error::NsfError;

/// Mode-header bits (low 3 bits of byte 0) at or below this are an
/// unsupported CX variant.
const MIN_SUPPORTED_MODE: u8 = 3;
/// Decoder starts at this bit index within byte 0 (past the mode header).
const START_BIT_INDEX: u8 = 3;
/// Length value (after the +2 bias) that marks end of stream.
const END_OF_STREAM_LENGTH: u32 = 0x0102;
/// Minimum back-reference length (the +2 bias).
const MIN_MATCH_LENGTH: u32 = 2;
/// Cap on the run-code field width, matching the reference's implicit
/// terminator after 8 data bits.
const MAX_RUN_WIDTH: u32 = 9;

/// High bit of a chained segment's length word: the segment is stored
/// uncompressed. See [`decompress_chained`].
const STORED_SEGMENT_FLAG: u32 = 0x8000_0000;

/// LSB-first bit reader over a borrowed byte slice.
struct BitReader<'a> {
    data: &'a [u8],
    /// Current byte index.
    pos: usize,
    /// Current bit within the byte, 0..=7, LSB-first.
    bit: u8,
}

impl<'a> BitReader<'a> {
    fn new(data: &'a [u8], start_bit: u8) -> Self {
        Self {
            data,
            pos: 0,
            bit: start_bit,
        }
    }

    /// True once every bit of the input has been consumed. Used at token
    /// boundaries to detect a clean end of stream (vs a mid-token cutoff,
    /// which surfaces as an error from the read primitives).
    fn exhausted(&self) -> bool {
        self.pos >= self.data.len()
    }

    /// Read a single bit (LSB-first). Errors if the stream is exhausted.
    fn read_bit(&mut self) -> Result<u8, NsfError> {
        let byte = *self.data.get(self.pos).ok_or(NsfError::DecompressionFailed {
            detail: "compressed stream truncated mid-token",
        })?;
        let value = (byte >> self.bit) & 0x01;
        self.bit += 1;
        if self.bit >= 8 {
            self.bit = 0;
            self.pos += 1;
        }
        Ok(value)
    }

    /// Read `n` bits LSB-first into the low bits of a `u32` (first bit read
    /// becomes bit 0). `n` is at most 16 in this format.
    fn read_bits(&mut self, n: u32) -> Result<u32, NsfError> {
        let mut value = 0u32;
        for i in 0..n {
            value |= u32::from(self.read_bit()?) << i;
        }
        Ok(value)
    }

    /// Decode one run-coded magnitude (length or offset-high).
    ///
    /// Width `w` is `1 + (count of leading zero bits up to a cap of 8)`,
    /// terminated by a one bit (or forced at the cap). Then `w` value bits
    /// are read. Result is `(1 << w) - 1 + value`.
    fn read_run(&mut self) -> Result<u32, NsfError> {
        let mut zeros = 0u32;
        while zeros < (MAX_RUN_WIDTH - 1) && self.read_bit()? == 0 {
            zeros += 1;
        }
        // At the cap the reference treats the next bit as an implicit
        // terminator regardless of its value; consume it to stay aligned.
        if zeros == MAX_RUN_WIDTH - 1 {
            let _ = self.read_bit()?;
        }
        let w = zeros + 1;
        let value = self.read_bits(w)?;
        Ok(((1u32 << w) - 1) + value)
    }
}

/// Decompress a Domino CX stream.
///
/// `expected_size` is the declared uncompressed length (from the structure
/// header carrying this body). It bounds the output so a malformed stream
/// cannot drive unbounded growth - a forensic-resilience requirement.
///
/// Returns [`NsfError::CompressionUnsupported`] for an unsupported mode
/// header and [`NsfError::DecompressionFailed`] for a truncated stream,
/// an out-of-bounds back-reference, or output overflowing `expected_size`.
pub fn decompress(compressed: &[u8], expected_size: usize) -> Result<Vec<u8>, NsfError> {
    decompress_bounded(compressed, expected_size, false)
}

/// [`decompress`], except that with `stop_at_size` output reaching
/// `expected_size` ends the stream instead of failing it.
fn decompress_bounded(
    compressed: &[u8],
    expected_size: usize,
    stop_at_size: bool,
) -> Result<Vec<u8>, NsfError> {
    let first = *compressed.first().ok_or(NsfError::DecompressionFailed {
        detail: "empty compressed stream",
    })?;
    if (first & 0x07) <= MIN_SUPPORTED_MODE {
        return Err(NsfError::CompressionUnsupported {
            structure: "CX stream",
            compression_type: u16::from(first & 0x07),
        });
    }

    let mut out: Vec<u8> = Vec::with_capacity(expected_size);
    let mut reader = BitReader::new(compressed, START_BIT_INDEX);

    while !reader.exhausted() {
        // Output at the declared size ends the stream before the next token
        // is read, so a token past that size can neither fail nor add.
        if stop_at_size && out.len() >= expected_size {
            break;
        }
        let tag = reader.read_bit()?;
        if tag == 0 {
            // Literal byte.
            let byte = reader.read_bits(8)? as u8;
            if out.len() >= expected_size {
                return Err(NsfError::DecompressionFailed {
                    detail: "output exceeded declared uncompressed size",
                });
            }
            out.push(byte);
            continue;
        }

        // Back-reference. Second tag bit selects explicit vs minimum length.
        let mut length = if reader.read_bit()? == 0 {
            reader.read_run()?
        } else {
            0
        };
        length += MIN_MATCH_LENGTH;

        if length >= END_OF_STREAM_LENGTH {
            break;
        }

        // Offset: optional high bits (only when length > minimum), then a
        // mandatory low byte.
        let mut offset = 0u32;
        if length > MIN_MATCH_LENGTH {
            if reader.read_bit()? == 0 {
                offset = reader.read_run()? << 8;
            }
        }
        offset |= reader.read_bits(8)?;

        let offset = offset as usize;
        let length = length as usize;
        if offset == 0 || offset > out.len() {
            return Err(NsfError::DecompressionFailed {
                detail: "back-reference offset points before start of output",
            });
        }
        let length = if out.len() + length > expected_size {
            if !stop_at_size {
                return Err(NsfError::DecompressionFailed {
                    detail: "back-reference would exceed declared uncompressed size",
                });
            }
            expected_size - out.len()
        } else {
            length
        };
        // Byte-by-byte copy so overlapping runs (offset < length) replicate.
        for _ in 0..length {
            let src = out.len() - offset;
            out.push(out[src]);
        }
    }

    Ok(out)
}

/// Decompress a **chain** of length-prefixed CX segments.
///
/// Large compressed bodies (the Bucket Descriptor Block, and superblock
/// bodies above one segment's worth) are stored as a sequence of
/// independent CX streams, each preceded by its own little-endian `u32`
/// compressed length:
///
/// ```text
/// [seg_len_0: u32][CX stream 0][seg_len_1: u32][CX stream 1] ...
/// ```
///
/// Each segment is a self-contained CX stream (its own 3-bit mode header)
/// terminated by the end-of-stream marker. The decompressed outputs are
/// concatenated. Decoding stops once `expected_size` bytes are produced or
/// the body is exhausted - so a single-segment body (the common superblock
/// case) round-trips identically to feeding [`decompress`] the lone stream.
///
/// A length word with its high bit set ([`STORED_SEGMENT_FLAG`]) marks a
/// segment stored as is, without compression; its bytes are copied. A
/// Bucket Descriptor Block of a 1 GB database had one such segment of 16
/// bytes among 23 compressed ones. Read as a length, the flag made the
/// segment 2 GB long, and the database had no field names or notes. A
/// stored segment that is empty or longer than the declared size leaves is
/// refused.
///
/// The last segment - one with nothing or a zero length word after it -
/// may decode to a few bytes more than the declared size leaves for it;
/// those bytes are dropped. Any earlier segment that does so still fails
/// the body. Both superblock copies of a
/// 9 GB log database decoded 8 bytes past their declared size, in the
/// final tokens of the last segment, while the descriptor array the
/// superblock is read for ends 100 KB earlier. Failing the whole body
/// there left the database unreadable. Output that reaches the declared
/// size ends the chain, so only bytes past that size are ever dropped;
/// [`decompress`] on a single stream still refuses them.
///
/// libnsfdb does not implement this chaining (its BDB reader leaves the
/// length prefix as a `TODO` and only ever decodes the first segment); it
/// was reverse-engineered against the Unique Name Key text region, whose
/// recovered strings (`FirstName`, `$UpdatedBy`, ...) validate the model.
pub fn decompress_chained(body: &[u8], expected_size: usize) -> Result<Vec<u8>, NsfError> {
    let mut out: Vec<u8> = Vec::with_capacity(expected_size);
    let mut cursor = 0usize;
    while out.len() < expected_size {
        let Some(len_bytes) = body.get(cursor..cursor + 4) else {
            break;
        };
        let word = u32::from_le_bytes([len_bytes[0], len_bytes[1], len_bytes[2], len_bytes[3]]);
        let stored = word & STORED_SEGMENT_FLAG != 0;
        let seg_len = (word & !STORED_SEGMENT_FLAG) as usize;
        let remaining = expected_size - out.len();
        if stored && (seg_len == 0 || seg_len > remaining) {
            // A stored segment holds output bytes one for one, so it can be
            // neither empty nor longer than what the declared size leaves.
            return Err(NsfError::DecompressionFailed {
                detail: "stored CX segment does not fit the declared size",
            });
        }
        if seg_len == 0 {
            break;
        }
        let seg_start = cursor + 4;
        let seg_end = seg_start
            .checked_add(seg_len)
            .ok_or(NsfError::DecompressionFailed {
                detail: "CX segment length overflow",
            })?;
        let seg = body.get(seg_start..seg_end).ok_or(NsfError::TooShort {
            actual: body.len(),
            required: seg_end,
        })?;
        // Only the last segment - nothing or a zero word after it - may run
        // past the declared size; an earlier one doing so means the size or
        // the segmentation was misread.
        let last = body
            .get(seg_end..seg_end + 4)
            .map_or(true, |w| w == [0, 0, 0, 0]);
        let part = if stored {
            seg.to_vec()
        } else {
            decompress_bounded(seg, remaining, last)?
        };
        if part.is_empty() {
            break;
        }
        out.extend_from_slice(&part);
        cursor = seg_end;
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Pack `(value, width)` fields LSB-first after the mode bits.
    fn stream(fields: &[(u32, u8)]) -> Vec<u8> {
        let mut out = vec![0b100u8];
        let mut bit = START_BIT_INDEX as usize;
        for &(value, width) in fields {
            for i in 0..width {
                if bit / 8 == out.len() {
                    out.push(0);
                }
                if value >> i & 1 == 1 {
                    out[bit / 8] |= 1 << (bit % 8);
                }
                bit += 1;
            }
        }
        out
    }

    /// "ABC" as literals, then a minimum-length back-reference 3 back:
    /// "ABCAB", exactly 40 bits.
    fn abcab() -> Vec<u8> {
        let lit = |c: u8| [(0, 1), (u32::from(c), 8)];
        let mut f: Vec<(u32, u8)> = Vec::new();
        for c in *b"ABC" {
            f.extend(lit(c));
        }
        f.extend([(1, 1), (1, 1), (3, 8)]);
        stream(&f)
    }

    #[test]
    fn a_stream_past_its_declared_size_fails_alone_but_ends_a_chain() {
        let s = abcab();
        assert_eq!(decompress(&s, 5).unwrap(), b"ABCAB");
        assert!(matches!(decompress(&s, 4), Err(NsfError::DecompressionFailed { .. })));
        let mut chain = (s.len() as u32).to_le_bytes().to_vec();
        chain.extend(&s);
        assert_eq!(decompress_chained(&chain, 4).unwrap(), b"ABCA");
        assert_eq!(decompress_chained(&chain, 2).unwrap(), b"AB");
    }

    #[test]
    fn a_segment_flagged_as_stored_is_copied_as_is() {
        let s = abcab();
        let mut chain = (s.len() as u32).to_le_bytes().to_vec();
        chain.extend(&s);
        chain.extend((3u32 | STORED_SEGMENT_FLAG).to_le_bytes());
        chain.extend(b"xyz");
        chain.extend((s.len() as u32).to_le_bytes());
        chain.extend(&s);
        assert_eq!(decompress_chained(&chain, 13).unwrap(), b"ABCABxyzABCAB");
        // A stored segment longer than the declared size leaves is refused.
        assert!(decompress_chained(&chain, 6).is_err());
        // So is a flagged segment of length 0.
        let mut empty = (s.len() as u32).to_le_bytes().to_vec();
        empty.extend(&s);
        empty.extend(STORED_SEGMENT_FLAG.to_le_bytes());
        assert!(decompress_chained(&empty, 13).is_err());
    }

    #[test]
    fn only_the_last_segment_may_run_past_the_declared_size() {
        let s = abcab();
        let mut chain = Vec::new();
        for _ in 0..2 {
            chain.extend((s.len() as u32).to_le_bytes());
            chain.extend(&s);
        }
        // The second segment overruns: its tail is dropped.
        assert_eq!(decompress_chained(&chain, 8).unwrap(), b"ABCABABC");
        // The first segment overruns while another follows: an error.
        assert!(decompress_chained(&chain, 4).is_err());
    }

    #[test]
    fn a_token_cut_off_past_the_declared_size_does_not_fail_the_chain() {
        // "ABCAB", then a back-reference tag whose offset bits are missing.
        let mut s = abcab();
        s.push(0b0000_0011);
        let mut chain = (s.len() as u32).to_le_bytes().to_vec();
        chain.extend(&s);
        assert_eq!(decompress_chained(&chain, 5).unwrap(), b"ABCAB");
        assert!(decompress(&s, 5).is_err());
    }

    #[test]
    fn rejects_empty_stream() {
        assert!(matches!(
            decompress(&[], 16),
            Err(NsfError::DecompressionFailed { .. })
        ));
    }

    #[test]
    fn rejects_unsupported_mode_header() {
        // Low 3 bits == 2 (<= 3) is an unsupported mode.
        assert!(matches!(
            decompress(&[0b0000_0010, 0, 0], 16),
            Err(NsfError::CompressionUnsupported { .. })
        ));
    }

    /// A back-reference whose offset points before the output start must
    /// error, not panic or read out of bounds. Mode bits = 7 (supported);
    /// first token is a back-reference (tag bit 1) while output is empty.
    #[test]
    fn rejects_backreference_before_output_start() {
        // byte 0: low 3 bits = 0b111 (mode ok). Bit index 3 = first tag.
        // Set bit 3 = 1 (back-ref), bit 4 = 1 (minimum length) -> length 2,
        // then it needs a low offset byte; offset will be nonzero but
        // output is empty so it must error on the offset bound.
        let stream = [0b0001_1111u8, 0xFF, 0xFF, 0xFF];
        assert!(matches!(
            decompress(&stream, 64),
            Err(NsfError::DecompressionFailed { .. })
        ));
    }

    #[test]
    fn bitreader_reads_lsb_first() {
        // bits of 0b1011_0100 starting at index 0: 0,0,1,0,1,1,0,1
        let data = [0b1011_0100u8];
        let mut r = BitReader::new(&data, 0);
        assert_eq!(r.read_bit().unwrap(), 0);
        assert_eq!(r.read_bit().unwrap(), 0);
        assert_eq!(r.read_bit().unwrap(), 1);
        assert_eq!(r.read_bits(5).unwrap(), 0b1011_0); // remaining 5 bits, LSB-first
    }

    #[test]
    fn bitreader_exhaustion_is_detected() {
        let data = [0xFFu8];
        let mut r = BitReader::new(&data, 0);
        for _ in 0..8 {
            r.read_bit().unwrap();
        }
        assert!(r.exhausted());
        assert!(matches!(
            r.read_bit(),
            Err(NsfError::DecompressionFailed { .. })
        ));
    }
}
