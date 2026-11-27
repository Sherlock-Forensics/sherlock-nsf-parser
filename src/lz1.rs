//! Notes attachment LZ1 decompression (`COMPRESS_LZ1`, compression type 2
//! in a `$FILE` item), the default for attachments since Notes 6 when the
//! database property "Use LZ1 compression for attachments" is on.
//!
//! No description of the format was found, published or in other readers.
//! It was worked out from one database (ODS 52) that holds the same PDF
//! twice, once stored and once LZ1-compressed, and then checked on eleven
//! more compressed attachments that carry their own integrity checks: every
//! PDF opened, and every zip (xlsx, docx) and PNG passed its CRCs.
//!
//! # Chunks
//!
//! The payload is a sequence of chunks, each at most 16384 bytes once
//! decoded, each with a 10-byte header:
//!
//! ```text
//! u32  stored length of the chunk body
//! u32  decoded length of the chunk
//! u16  flags: 0x0001 body is compressed
//!             0x0002 body is the bytes themselves (stored == decoded)
//!             0x0004 last chunk
//! ```
//!
//! A chunk that would not shrink is stored as it is, so a file that is
//! already compressed is mostly 0x0002 chunks. Seen: 1, 2, 5 and 6.
//!
//! # A compressed body
//!
//! A bit stream, most significant bit first, of tokens. Each chunk starts
//! with an empty history: a copy never reaches into the previous chunk.
//!
//! ```text
//! 0 bbbbbbbb                    literal byte
//! 1 <distance> <length>         copy <length> bytes from <distance> + 1 back
//!
//! distance:  0  + 7 bits        0 ..= 127
//!            10 + 10 bits       128 ..= 1151
//!            11 + 10 bits v     1152 + v, for v < 768
//!            1111 + 12 bits w   1920 + w, for w < 4095
//!            1111 + 12 ones     end of the chunk's tokens
//!
//! length:    0  + 3 bits        2 ..= 9
//!            10 + 6 bits        10 ..= 73
//!            11 + 10 bits       74 ..= 1097
//! ```
//!
//! (The third and fourth distance forms are one 10-bit field whose top two
//! bits being set announces two more bits of prefix.) A copy may overlap
//! its own output, which is how a run is written: a literal, then a copy
//! from distance 0.
//!
//! Decoding is accepted only when the chunks produce exactly the size the
//! `$FILE` item declares and every chunk produces exactly what its header
//! says. The object's SHA-1, where it records one, covers the stored
//! payload, not the decoded file, and is checked by the caller.

/// Size of the header in front of every chunk.
const CHUNK_HEADER_BYTES: usize = 10;

const FLAG_COMPRESSED: u16 = 0x0001;
const FLAG_STORED: u16 = 0x0002;
const FLAG_LAST: u16 = 0x0004;

/// Why an LZ1 payload did not decode to the declared file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Lz1Error {
    /// The payload ended inside a chunk header or body, or the chunks ended
    /// before the declared size was reached.
    Truncated {
        /// Bytes produced before the input ended.
        produced: usize,
    },
    /// A chunk's flags name neither a compressed nor a stored body.
    UnknownChunk {
        /// The flags word found.
        flags: u16,
    },
    /// A stored chunk whose two lengths differ, or a chunk that declares
    /// more than is left of the file.
    BadChunkSize,
    /// A copy reaches back past the start of its chunk.
    BadDistance,
    /// A compressed chunk's tokens ended, or ran past, somewhere other than
    /// its declared decoded length.
    ChunkSizeMismatch,
    /// Chunks remain after the declared size was reached.
    TrailingData,
}

/// Bits of a chunk body, most significant first.
struct Bits<'a> {
    data: &'a [u8],
    pos: usize,
}

impl Bits<'_> {
    fn take(&mut self, n: u32) -> Option<u32> {
        let mut v = 0u32;
        for _ in 0..n {
            let byte = *self.data.get(self.pos / 8)?;
            v = (v << 1) | u32::from((byte >> (7 - (self.pos % 8))) & 1);
            self.pos += 1;
        }
        Some(v)
    }

    /// A copy token's distance field; `None` when the bits run out.
    fn distance(&mut self) -> Option<Distance> {
        Some(Distance::Back(if self.take(1)? == 0 {
            self.take(7)? as usize
        } else if self.take(1)? == 0 {
            128 + self.take(10)? as usize
        } else {
            let v = self.take(10)? as usize;
            if v < 768 {
                1152 + v
            } else {
                let w = ((v & 0xFF) << 4) | self.take(4)? as usize;
                if w == 0xFFF {
                    return Some(Distance::End);
                }
                1920 + w
            }
        }))
    }

    /// A copy token's length field; `None` when the bits run out.
    fn length(&mut self) -> Option<usize> {
        Some(if self.take(1)? == 0 {
            2 + self.take(3)? as usize
        } else if self.take(1)? == 0 {
            10 + self.take(6)? as usize
        } else {
            74 + self.take(10)? as usize
        })
    }
}

/// What a distance field says.
enum Distance {
    /// Copy from this many bytes, plus one, behind the output.
    Back(usize),
    /// No copy: the chunk's tokens end here.
    End,
}

/// Decode one compressed chunk body onto `out`, producing exactly `decoded`
/// bytes.
fn inflate_chunk(body: &[u8], decoded: usize, out: &mut Vec<u8>) -> Result<(), Lz1Error> {
    let start = out.len();
    let end = start + decoded;
    let mut bits = Bits { data: body, pos: 0 };
    let short = |out: &Vec<u8>| Lz1Error::Truncated { produced: out.len() };
    while out.len() < end {
        let Some(flag) = bits.take(1) else {
            return Err(short(out));
        };
        if flag == 0 {
            let Some(b) = bits.take(8) else {
                return Err(short(out));
            };
            out.push(b as u8);
            continue;
        }
        let Some(distance) = bits.distance() else {
            return Err(short(out));
        };
        let Distance::Back(distance) = distance else {
            // End marker before the declared length.
            return Err(Lz1Error::ChunkSizeMismatch);
        };
        let Some(length) = bits.length() else {
            return Err(short(out));
        };
        if distance >= out.len() - start {
            return Err(Lz1Error::BadDistance);
        }
        if out.len() + length > end {
            return Err(Lz1Error::ChunkSizeMismatch);
        }
        let from = out.len() - distance - 1;
        for i in 0..length {
            let b = out[from + i];
            out.push(b);
        }
    }
    Ok(())
}

/// Decompress `payload` (the object payload) to exactly `expected` bytes.
///
/// Nothing is allocated on the strength of `expected` alone: the output
/// grows as chunks decode and never past `expected`.
pub fn decompress(payload: &[u8], expected: usize) -> Result<Vec<u8>, Lz1Error> {
    let mut out = Vec::new();
    let mut pos = 0usize;
    let mut last = false;
    while out.len() < expected {
        if last {
            return Err(Lz1Error::Truncated { produced: out.len() });
        }
        let truncated = Lz1Error::Truncated { produced: out.len() };
        let header = payload.get(pos..pos + CHUNK_HEADER_BYTES).ok_or(truncated)?;
        let stored = u32::from_le_bytes([header[0], header[1], header[2], header[3]]) as usize;
        let decoded = u32::from_le_bytes([header[4], header[5], header[6], header[7]]) as usize;
        let flags = u16::from_le_bytes([header[8], header[9]]);
        let body_at = pos + CHUNK_HEADER_BYTES;
        let body = body_at
            .checked_add(stored)
            .and_then(|end| payload.get(body_at..end))
            .ok_or(truncated)?;
        if decoded == 0 || decoded > expected - out.len() {
            return Err(Lz1Error::BadChunkSize);
        }
        if flags & FLAG_COMPRESSED != 0 {
            inflate_chunk(body, decoded, &mut out)?;
        } else if flags & FLAG_STORED != 0 {
            if stored != decoded {
                return Err(Lz1Error::BadChunkSize);
            }
            out.extend_from_slice(body);
        } else {
            return Err(Lz1Error::UnknownChunk { flags });
        }
        last = flags & FLAG_LAST != 0;
        pos = body_at + stored;
    }
    if !last && pos < payload.len() {
        return Err(Lz1Error::TrailingData);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Test-side encoder for the token stream: enough to write each form.
    #[derive(Default)]
    struct Writer {
        bits: Vec<bool>,
    }

    impl Writer {
        fn put(&mut self, value: usize, n: u32) {
            for i in (0..n).rev() {
                self.bits.push((value >> i) & 1 == 1);
            }
        }
        fn literal(&mut self, b: u8) {
            self.put(0, 1);
            self.put(b as usize, 8);
        }
        fn text(&mut self, s: &[u8]) {
            for &b in s {
                self.literal(b);
            }
        }
        fn copy(&mut self, distance: usize, length: usize) {
            self.put(1, 1);
            match distance {
                0..=127 => {
                    self.put(0, 1);
                    self.put(distance, 7);
                }
                128..=1151 => {
                    self.put(0b10, 2);
                    self.put(distance - 128, 10);
                }
                1152..=1919 => {
                    self.put(0b11, 2);
                    self.put(distance - 1152, 10);
                }
                _ => {
                    self.put(0b1111, 4);
                    self.put(distance - 1920, 12);
                }
            }
            match length {
                2..=9 => {
                    self.put(0, 1);
                    self.put(length - 2, 3);
                }
                10..=73 => {
                    self.put(0b10, 2);
                    self.put(length - 10, 6);
                }
                _ => {
                    self.put(0b11, 2);
                    self.put(length - 74, 10);
                }
            }
        }
        fn end(&mut self) {
            self.put(0x1FFFF, 17);
        }
        fn bytes(&self) -> Vec<u8> {
            self.bits
                .chunks(8)
                .map(|c| c.iter().enumerate().fold(0u8, |a, (i, &b)| a | (u8::from(b) << (7 - i))))
                .collect()
        }
    }

    fn chunk(body: &[u8], decoded: usize, flags: u16) -> Vec<u8> {
        let mut c = (body.len() as u32).to_le_bytes().to_vec();
        c.extend_from_slice(&(decoded as u32).to_le_bytes());
        c.extend_from_slice(&flags.to_le_bytes());
        c.extend_from_slice(body);
        c
    }

    #[test]
    fn literals_and_a_short_copy() {
        // "abcabcabc": three literals, then six bytes from three back.
        let mut w = Writer::default();
        w.text(b"abc");
        w.copy(2, 6);
        w.end();
        let payload = chunk(&w.bytes(), 9, 5);
        assert_eq!(decompress(&payload, 9).unwrap(), b"abcabcabc");
    }

    #[test]
    fn a_run_is_a_copy_from_distance_zero() {
        let mut w = Writer::default();
        w.literal(b' ');
        w.copy(0, 99);
        w.literal(b'\n');
        w.end();
        let payload = chunk(&w.bytes(), 101, 5);
        let mut want = vec![b' '; 100];
        want.push(b'\n');
        assert_eq!(decompress(&payload, 101).unwrap(), want);
    }

    /// One copy through each distance form and each length form, reaching
    /// back to a marker placed that far behind.
    #[test]
    fn every_distance_and_length_form_decodes() {
        // 6100 distinct-ish bytes so a wrong distance shows.
        let base: Vec<u8> = (0..6100u32).map(|i| (i * 7 + i / 251) as u8).collect();
        for (distance, length) in [
            (0usize, 2usize),
            (127, 9),
            (128, 10),
            (1151, 73),
            (1152, 74),
            (1919, 300),
            (1920, 1097),
            (6014, 5),
        ] {
            let mut w = Writer::default();
            w.text(&base);
            w.copy(distance, length);
            w.end();
            let mut want = base.clone();
            let from = base.len() - distance - 1;
            for i in 0..length {
                let b = want[from + i];
                want.push(b);
            }
            let payload = chunk(&w.bytes(), want.len(), 5);
            assert_eq!(decompress(&payload, want.len()).unwrap(), want, "distance {distance} length {length}");
        }
    }

    #[test]
    fn stored_and_compressed_chunks_follow_each_other() {
        let mut w = Writer::default();
        w.text(b"xy");
        w.copy(1, 4);
        w.end();
        let mut payload = chunk(b"raw bytes ", 10, 2);
        payload.extend(chunk(&w.bytes(), 6, 1));
        payload.extend(chunk(b"!", 1, 6));
        assert_eq!(decompress(&payload, 17).unwrap(), b"raw bytes xyxyxy!");
    }

    /// The history is the chunk's own output: a copy in a second chunk
    /// cannot reach the first.
    #[test]
    fn a_copy_does_not_reach_into_the_previous_chunk() {
        let mut w = Writer::default();
        w.literal(b'a');
        w.copy(3, 2);
        w.end();
        let mut payload = chunk(b"abcdefgh", 8, 2);
        payload.extend(chunk(&w.bytes(), 3, 5));
        assert_eq!(decompress(&payload, 11), Err(Lz1Error::BadDistance));
    }

    #[test]
    fn a_decode_that_does_not_fit_the_declared_sizes_is_refused() {
        let mut w = Writer::default();
        w.text(b"abc");
        w.copy(2, 6);
        w.end();
        let body = w.bytes();
        // The file is declared one byte longer than the chunks give.
        assert_eq!(decompress(&chunk(&body, 9, 5), 10), Err(Lz1Error::Truncated { produced: 9 }));
        // The chunk declares more than its tokens give: the end marker
        // arrives first.
        assert_eq!(decompress(&chunk(&body, 10, 5), 10), Err(Lz1Error::ChunkSizeMismatch));
        // The chunk declares less: the copy would run past it.
        assert_eq!(decompress(&chunk(&body, 8, 5), 8), Err(Lz1Error::ChunkSizeMismatch));
        // The chunk declares more than is left of the file.
        assert_eq!(decompress(&chunk(&body, 9, 5), 8), Err(Lz1Error::BadChunkSize));
        // A stored chunk whose lengths differ.
        assert_eq!(decompress(&chunk(b"abcd", 5, 6), 5), Err(Lz1Error::BadChunkSize));
        // Flags that name no body form.
        assert_eq!(decompress(&chunk(b"abcd", 4, 4), 4), Err(Lz1Error::UnknownChunk { flags: 4 }));
        // More chunks after the declared size was reached.
        let mut two = chunk(b"abcd", 4, 2);
        two.extend(chunk(b"efgh", 4, 6));
        assert_eq!(decompress(&two, 4), Err(Lz1Error::TrailingData));
    }

    #[test]
    fn a_payload_cut_short_is_refused_wherever_it_is_cut() {
        let mut w = Writer::default();
        w.text(b"abcdefgh");
        w.copy(7, 40);
        w.end();
        let body = w.bytes();
        let payload = chunk(&body, 48, 5);
        assert!(decompress(&payload, 48).is_ok());
        for cut in 0..payload.len() {
            assert!(
                matches!(decompress(&payload[..cut], 48), Err(Lz1Error::Truncated { .. })),
                "cut at {cut}"
            );
        }
        // A whole chunk whose tokens stop early: the bits run out.
        assert_eq!(decompress(&chunk(&body[..5], 48, 5), 48), Err(Lz1Error::Truncated { produced: 4 }));
    }

    /// A header may claim any size; nothing is reserved for it up front.
    #[test]
    fn a_huge_declared_size_costs_nothing_until_bytes_decode() {
        let payload = chunk(b"abcd", 4, 6);
        assert_eq!(decompress(&payload, usize::MAX), Err(Lz1Error::Truncated { produced: 4 }));
    }
}
