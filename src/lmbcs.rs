//! LMBCS (Lotus Multi-Byte Character Set) to Unicode.
//!
//! Notes stores text - item values and the text of rich-text runs alike - in
//! LMBCS, optimization group 1. A byte from 0x20 to 0x7F is ASCII. A byte
//! below 0x20 is a *group byte* announcing how to read what follows, except
//! NUL, tab, line feed, carriage return and 0x19, which stand for
//! themselves. A byte of 0x80 or above with no group byte before it belongs
//! to group 1.
//!
//! ```text
//! 0x01        group 1  Latin-1        next byte in code page 850
//! 0x02        group 2  Greek          next byte in code page 851
//! 0x03        group 3  Hebrew         next byte in Windows-1255
//! 0x04        group 4  Arabic         next byte in Windows-1256
//! 0x05        group 5  Cyrillic       next byte in Windows-1251
//! 0x06        group 6  Latin-2        next byte in code page 852
//! 0x08        group 8  Turkish        next byte in Windows-1254
//! 0x0B        group 11 Thai           next byte in Windows-874
//! 0x0F        control                 next byte minus 0x20 is a C0 control,
//!                                     or a C1 control as it stands
//! 0x10..0x13  Far East groups         next TWO bytes in a double-byte code
//!                                     page (932, 949, 950, 936)
//! 0x14        Unicode                 next two bytes are UTF-16BE
//! ```
//!
//! When the byte after a single-byte group byte is below 0x80 it is not
//! looked up in the group's code page but, together with the group byte, in
//! a table of exceptions: `01 29` is an en dash, `01 26` and `01 38` the
//! double quotation marks, `01 07` a bullet, `02 73` a less-than-or-equal
//! sign. Only groups 1, 2 and 6 have exceptions.
//!
//! This follows the ICU LMBCS converter (`ucnv_lmb.cpp`) and its mapping
//! data; the tables are in [`crate::lmbcs_tables`]. What is not decoded:
//! the four Far East groups, whose double-byte tables are too large to
//! carry here. Their characters are consumed at their width and yield
//! U+FFFD each, so the text around them stays aligned and the loss is
//! visible rather than silent. The same goes for a byte a code page does
//! not define and for a group byte that names no group.
//!
//! A NUL inside text is how Notes separates lines; it is passed through as
//! U+0000 for the caller to treat as it needs.
//!
//! Checked on a real database, in text whose wording was known: `06 E7` is
//! `š`, `06 9F` is `č`, a bare `81` is `ü`, `03 80` after an amount is the
//! euro sign, `02 E6` before `m` is `μ`, and `01 29` between two phrases is
//! a dash.

use crate::lmbcs_tables as t;

const REPLACEMENT: char = '\u{FFFD}';

/// The character a table gives at `index`.
fn at(table: &[u16; 128], index: u8) -> char {
    char::from_u32(u32::from(table[usize::from(index & 0x7F)])).unwrap_or(REPLACEMENT)
}

/// The code page of a single-byte group, for bytes 0x80 and above.
fn code_page(group: u8) -> Option<&'static [u16; 128]> {
    Some(match group {
        0x01 => &t::CP850,
        0x02 => &t::CP851,
        0x03 => &t::CP1255,
        0x04 => &t::CP1256,
        0x05 => &t::CP1251,
        0x06 => &t::CP852,
        0x08 => &t::CP1254,
        0x0B => &t::CP874,
        _ => return None,
    })
}

/// The exception table of a group, for a following byte below 0x80.
fn exceptions(group: u8) -> Option<&'static [u16; 128]> {
    Some(match group {
        0x01 => &t::EXCEPT_1,
        0x02 => &t::EXCEPT_2,
        0x06 => &t::EXCEPT_6,
        _ => return None,
    })
}

/// Decode LMBCS bytes to a `String`.
///
/// Never fails: a sequence cut short at the end of the input, a character
/// of a group this module has no table for, and a byte that names no group
/// each yield one U+FFFD. A NUL comes through as U+0000.
pub fn decode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        let b = bytes[i];
        match b {
            0x00 | 0x09 | 0x0A | 0x0D | 0x19 | 0x20..=0x7F => {
                out.push(b as char);
                i += 1;
            }
            0x80..=0xFF => {
                out.push(at(&t::CP850, b));
                i += 1;
            }
            // Control group: the control character, offset so that no byte
            // below 0x20 appears except as the first byte of a character.
            0x0F => {
                let Some(&next) = bytes.get(i + 1) else {
                    out.push(REPLACEMENT);
                    break;
                };
                out.push(match next {
                    0x20..=0x3F => char::from(next - 0x20),
                    0x80..=0x9F => char::from(next),
                    _ => REPLACEMENT,
                });
                i += 2;
            }
            // Unicode group: UTF-16BE, with 0xF6 standing in for a high
            // byte so that a code unit ending in 00 holds no NUL.
            0x14 => {
                let Some(pair) = bytes.get(i + 1..i + 3) else {
                    out.push(REPLACEMENT);
                    break;
                };
                let unit = if pair[0] == 0xF6 {
                    u16::from(pair[1]) << 8
                } else {
                    u16::from_be_bytes([pair[0], pair[1]])
                };
                out.push(char::from_u32(u32::from(unit)).unwrap_or(REPLACEMENT));
                i += 3;
            }
            // Far East groups: two bytes follow, or, when the group byte is
            // doubled, one. No tables here.
            0x10..=0x13 => {
                let Some(pair) = bytes.get(i + 1..i + 3) else {
                    out.push(REPLACEMENT);
                    break;
                };
                out.push(if pair[0] == b && pair[1] < 0x80 {
                    pair[1] as char
                } else {
                    REPLACEMENT
                });
                i += 3;
            }
            // Single-byte groups, and group bytes that name nothing.
            _ => {
                let Some(page) = code_page(b) else {
                    out.push(REPLACEMENT);
                    i += 1;
                    continue;
                };
                let Some(&next) = bytes.get(i + 1) else {
                    out.push(REPLACEMENT);
                    break;
                };
                out.push(if next >= 0x80 {
                    at(page, next)
                } else {
                    exceptions(b).map_or(REPLACEMENT, |e| at(e, next))
                });
                i += 2;
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ascii_passes_through_with_tabs_and_line_breaks() {
        assert_eq!(decode(b"Offer 12\tok\r\n"), "Offer 12\tok\r\n");
    }

    #[test]
    fn a_bare_high_byte_is_code_page_850() {
        // u-umlaut, e-acute, sharp s.
        assert_eq!(decode(&[b'M', 0x81, b'l', 0x82, 0xE1]), "M\u{fc}l\u{e9}\u{df}");
    }

    #[test]
    fn group_six_is_code_page_852() {
        // s-caron, c-caron, z-caron, S-caron.
        assert_eq!(
            decode(&[0x06, 0xE7, 0x06, 0x9F, 0x06, 0xA7, 0x06, 0xE6]),
            "\u{161}\u{10d}\u{17e}\u{160}"
        );
    }

    #[test]
    fn each_single_byte_group_uses_its_own_code_page() {
        assert_eq!(decode(&[0x01, 0x84]), "\u{e4}"); // a-umlaut
        assert_eq!(decode(&[0x02, 0xE6]), "\u{3bc}"); // mu
        assert_eq!(decode(&[0x03, 0x80]), "\u{20ac}"); // euro sign
        assert_eq!(decode(&[0x04, 0xC7]), "\u{627}"); // alef
        assert_eq!(decode(&[0x05, 0xC6]), "\u{416}"); // zhe
        assert_eq!(decode(&[0x08, 0xFD]), "\u{131}"); // dotless i
        assert_eq!(decode(&[0x0B, 0xA1]), "\u{e01}"); // ko kai
    }

    /// A group byte followed by a byte below 0x80 is an exception, not the
    /// ASCII character that byte would be on its own.
    #[test]
    fn a_low_byte_after_a_group_byte_is_an_exception() {
        assert_eq!(decode(b"a \x01\x29 b"), "a \u{2013} b"); // en dash
        assert_eq!(decode(b"\x01\x26x\x01\x38"), "\u{201c}x\u{201d}"); // quotes
        assert_eq!(decode(b"\x01\x07"), "\u{2022}"); // bullet
        assert_eq!(decode(b"\x01\x1A"), "\u{2192}"); // right arrow
        assert_eq!(decode(b"\x02\x73"), "\u{2264}"); // less-than or equal
        assert_eq!(decode(b"\x06\x2E"), "\u{100}"); // A-macron
        // A group with no exceptions, and a hole in a group that has them.
        assert_eq!(decode(b"\x05\x41"), "\u{fffd}");
        assert_eq!(decode(b"\x01\x2D"), "\u{fffd}");
    }

    #[test]
    fn the_unicode_group_is_utf16_big_endian() {
        assert_eq!(decode(&[b'a', 0x14, 0x20, 0xAC, b'b']), "a\u{20ac}b");
        // 0xF6 stands in for the high byte of a unit whose low byte is 00.
        assert_eq!(decode(&[0x14, 0xF6, 0x21]), "\u{2100}");
        // A lone surrogate is not a character.
        assert_eq!(decode(&[0x14, 0xD8, 0x00]), "\u{fffd}");
    }

    #[test]
    fn the_control_group_gives_the_control_character() {
        assert_eq!(decode(&[0x0F, 0x21]), "\u{1}");
        assert_eq!(decode(&[0x0F, 0x85]), "\u{85}");
    }

    #[test]
    fn far_east_characters_keep_the_text_around_them_aligned() {
        assert_eq!(decode(&[b'x', 0x10, 0x88, 0x9F, b'y', 0x11, 0xA9, 0xFC, b'z']), "x\u{fffd}y\u{fffd}z");
        // A doubled group byte announces a single byte.
        assert_eq!(decode(&[0x10, 0x10, b'A', b'z']), "Az");
    }

    #[test]
    fn a_byte_that_names_no_group_is_one_replacement() {
        assert_eq!(decode(&[b'a', 0x07, b'b', 0x1F, b'c']), "a\u{fffd}b\u{fffd}c");
    }

    #[test]
    fn a_sequence_cut_short_is_one_replacement() {
        assert_eq!(decode(&[b'a', 0x06]), "a\u{fffd}");
        assert_eq!(decode(&[b'a', 0x14, 0x20]), "a\u{fffd}");
        assert_eq!(decode(&[b'a', 0x10, 0x88]), "a\u{fffd}");
        assert_eq!(decode(&[b'a', 0x0F]), "a\u{fffd}");
    }

    #[test]
    fn a_nul_is_passed_through() {
        assert_eq!(decode(b"one\0two"), "one\0two");
    }

    /// The standard tables agree with what the standard says at points
    /// that are easy to get wrong, and every table is free of surrogates.
    #[test]
    fn the_tables_hold_characters() {
        assert_eq!(at(&t::CP850, 0xD5), '\u{131}');
        assert_eq!(at(&t::CP852, 0xD0), '\u{111}');
        assert_eq!(at(&t::CP851, 0x91), REPLACEMENT);
        for table in [
            &t::CP850, &t::CP851, &t::CP852, &t::CP1251, &t::CP1254, &t::CP1255, &t::CP1256,
            &t::CP874, &t::EXCEPT_1, &t::EXCEPT_2, &t::EXCEPT_6,
        ] {
            assert!(table.iter().all(|&u| char::from_u32(u32::from(u)).is_some()));
        }
    }
}
