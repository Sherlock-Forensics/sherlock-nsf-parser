//! Notes attachment Huffman decompression (`COMPRESS_HUFF`, compression
//! type 1 in a `$FILE` item), used for file attachments from Notes 4 on.
//!
//! Lotus never documented the scheme. The layout below follows the MIT-licensed
//! nsf2pst project's `huff.c` (github.com/rshi0212/nsf2pst), which was the
//! reference for this implementation, and it was checked against a real
//! Notes 4 attachment object: its payload opens with a u32 checksum, a table
//! size of 272 (a multiple of four, under 1024) and a table of signed words
//! whose first entries are small negative node links and whose later ones
//! include byte values.
//!
//! ```text
//! u32   checksum: sum of every decompressed byte, mod 2^32
//! then one or more blocks:
//!   u16           table size in bytes (a multiple of 4, 4..=1024)
//!   i16 x size/2  the tree: node n's children are entries 2n (bit 1) and
//!                 2n+1 (bit 0); a negative entry -m continues at node m,
//!                 0..=255 is an output byte, 256 ends the block
//!   bits          MSB-first; the next block starts at the following byte
//! ```
//!
//! Decoding is only accepted when it produces exactly the size the `$FILE`
//! item declares and the checksum matches. Either check alone could pass
//! on a wrong decode; both together will not, so a file this returns is the
//! file that was attached.

/// Why a Huffman payload did not decode to the declared file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HuffError {
    /// Shorter than the 4-byte checksum.
    Truncated,
    /// A block's table size or a tree entry is out of range.
    BadTable,
    /// The bits ran out before the declared size was reached.
    Short {
        /// Bytes produced before the input ended.
        produced: usize,
    },
    /// Decoded to the declared size but the checksum disagrees.
    Checksum {
        /// Checksum stored in the object.
        stored: u32,
        /// Checksum of what was decoded.
        computed: u32,
    },
}

/// Decompress `raw` (the object payload) to exactly `expected` bytes.
pub fn decompress(raw: &[u8], expected: usize) -> Result<Vec<u8>, HuffError> {
    let stored = u32::from_le_bytes(raw.get(..4).ok_or(HuffError::Truncated)?.try_into().unwrap());
    let mut out = Vec::with_capacity(expected);
    let mut pos = 4usize;
    while out.len() < expected {
        let size = u16::from_le_bytes([
            *raw.get(pos).ok_or(HuffError::Short { produced: out.len() })?,
            *raw.get(pos + 1).ok_or(HuffError::Short { produced: out.len() })?,
        ]) as usize;
        if size < 4 || size > 1024 || size % 4 != 0 {
            return Err(HuffError::BadTable);
        }
        let table: Vec<i32> = raw
            .get(pos + 2..pos + 2 + size)
            .ok_or(HuffError::BadTable)?
            .chunks_exact(2)
            .map(|w| i16::from_le_bytes([w[0], w[1]]) as i32)
            .collect();
        let mut bit = (pos + 2 + size) * 8;
        let total = raw.len() * 8;
        let mut node = 0usize;
        let mut ended = false;
        while bit < total {
            let b = (raw[bit / 8] >> (7 - (bit % 8))) & 1;
            bit += 1;
            let v = *table.get(2 * node + usize::from(b == 0)).ok_or(HuffError::BadTable)?;
            match v {
                v if v < 0 => node = (-v) as usize,
                256 => {
                    ended = true;
                    break;
                }
                v if v > 256 => return Err(HuffError::BadTable),
                v => {
                    out.push(v as u8);
                    node = 0;
                    if out.len() == expected {
                        break;
                    }
                }
            }
        }
        if out.len() == expected {
            break;
        }
        if !ended {
            return Err(HuffError::Short { produced: out.len() });
        }
        pos = bit.div_ceil(8);
    }
    let computed = out.iter().fold(0u32, |s, &b| s.wrapping_add(u32::from(b)));
    if computed != stored {
        return Err(HuffError::Checksum { stored, computed });
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Encode with a fixed two-symbol-plus-end tree:
    ///   node 0: bit 1 -> 'A', bit 0 -> node 1
    ///   node 1: bit 1 -> 'B', bit 0 -> end of block
    fn encode(text: &[u8]) -> Vec<u8> {
        let table: [i16; 4] = [b'A' as i16, -1, b'B' as i16, 256];
        let mut bits = Vec::new();
        for &c in text {
            match c {
                b'A' => bits.push(1),
                b'B' => bits.extend([0, 1]),
                _ => unreachable!(),
            }
        }
        bits.extend([0, 0]);
        let mut raw = text.iter().fold(0u32, |s, &b| s + b as u32).to_le_bytes().to_vec();
        raw.extend_from_slice(&8u16.to_le_bytes());
        for t in table {
            raw.extend_from_slice(&t.to_le_bytes());
        }
        for chunk in bits.chunks(8) {
            let mut byte = 0u8;
            for (i, b) in chunk.iter().enumerate() {
                byte |= (*b as u8) << (7 - i);
            }
            raw.push(byte);
        }
        raw
    }

    #[test]
    fn decodes_to_the_declared_size_with_a_matching_checksum() {
        let raw = encode(b"ABBAAB");
        assert_eq!(decompress(&raw, 6).unwrap(), b"ABBAAB");
    }

    #[test]
    fn a_wrong_checksum_is_refused() {
        let mut raw = encode(b"ABBA");
        raw[0] ^= 1;
        assert!(matches!(decompress(&raw, 4), Err(HuffError::Checksum { .. })));
    }

    #[test]
    fn a_declared_size_the_bits_cannot_reach_is_refused() {
        let raw = encode(b"AB");
        assert!(matches!(decompress(&raw, 5), Err(HuffError::Short { .. })));
    }

    #[test]
    fn a_malformed_table_is_refused() {
        let mut raw = encode(b"AB");
        raw[4] = 6; // table size not a multiple of 4
        assert_eq!(decompress(&raw, 2), Err(HuffError::BadTable));
        assert_eq!(decompress(&[1, 2], 2), Err(HuffError::Truncated));
    }
}
