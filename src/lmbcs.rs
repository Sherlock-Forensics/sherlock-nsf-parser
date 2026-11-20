//! LMBCS (Lotus Multi-Byte Character Set) to Unicode.
//!
//! Notes stores text - item values and the text of rich-text runs alike - in
//! LMBCS, optimization group 1. A byte below 0x80 is ASCII, except that a
//! byte below 0x20 may be a *group byte* announcing how to read what
//! follows; a byte of 0x80 or above with no group byte before it belongs to
//! group 1.
//!
//! ```text
//! 0x01        group 1  Latin-1        next byte in code page 850
//! 0x02        group 2  Greek          next byte in code page 1253
//! 0x03        group 3  Hebrew         next byte in code page 1255
//! 0x04        group 4  Arabic         next byte in code page 1256
//! 0x05        group 5  Cyrillic       next byte in code page 1251
//! 0x06        group 6  Latin-2        next byte in code page 852
//! 0x08        group 8  Turkish        next byte in code page 1254
//! 0x0B        group 11 Thai           next byte in code page 874
//! 0x0F        control                 low five bits of the next byte are a C0 control
//! 0x10..0x13  Far East groups         next TWO bytes in a DBCS code page
//! 0x14        Unicode                 next two bytes are UTF-16BE
//! ```
//!
//! Groups 1, 5 and 6 are decoded through their tables. The other
//! single-byte groups and the Far East groups are consumed at their right
//! width and yield U+FFFD each, so text around them stays aligned and the
//! loss is visible rather than silent. A NUL inside text is how Notes
//! separates lines; it is passed through as U+0000 for the caller to treat
//! as it needs.
//!
//! The group layout follows the ICU converter documentation for LMBCS. The
//! two tables that matter for Central European data were checked on a real
//! database: `06 E7` reads as `š` and `06 9F` as `č` in names whose spelling
//! was known.

/// Code page 850, bytes 0x80..=0xFF.
const CP850: &str = "\u{00c7}\u{00fc}\u{00e9}\u{00e2}\u{00e4}\u{00e0}\u{00e5}\u{00e7}\u{00ea}\u{00eb}\u{00e8}\u{00ef}\u{00ee}\u{00ec}\u{00c4}\u{00c5}\u{00c9}\u{00e6}\u{00c6}\u{00f4}\u{00f6}\u{00f2}\u{00fb}\u{00f9}\u{00ff}\u{00d6}\u{00dc}\u{00f8}\u{00a3}\u{00d8}\u{00d7}\u{0192}\u{00e1}\u{00ed}\u{00f3}\u{00fa}\u{00f1}\u{00d1}\u{00aa}\u{00ba}\u{00bf}\u{00ae}\u{00ac}\u{00bd}\u{00bc}\u{00a1}\u{00ab}\u{00bb}\u{2591}\u{2592}\u{2593}\u{2502}\u{2524}\u{00c1}\u{00c2}\u{00c0}\u{00a9}\u{2563}\u{2551}\u{2557}\u{255d}\u{00a2}\u{00a5}\u{2510}\u{2514}\u{2534}\u{252c}\u{251c}\u{2500}\u{253c}\u{00e3}\u{00c3}\u{255a}\u{2554}\u{2569}\u{2566}\u{2560}\u{2550}\u{256c}\u{00a4}\u{00f0}\u{00d0}\u{00ca}\u{00cb}\u{00c8}\u{0131}\u{00cd}\u{00ce}\u{00cf}\u{2518}\u{250c}\u{2588}\u{2584}\u{00a6}\u{00cc}\u{2580}\u{00d3}\u{00df}\u{00d4}\u{00d2}\u{00f5}\u{00d5}\u{00b5}\u{00fe}\u{00de}\u{00da}\u{00db}\u{00d9}\u{00fd}\u{00dd}\u{00af}\u{00b4}\u{00ad}\u{00b1}\u{2017}\u{00be}\u{00b6}\u{00a7}\u{00f7}\u{00b8}\u{00b0}\u{00a8}\u{00b7}\u{00b9}\u{00b3}\u{00b2}\u{25a0}\u{00a0}";

/// Code page 852, bytes 0x80..=0xFF.
const CP852: &str = "\u{00c7}\u{00fc}\u{00e9}\u{00e2}\u{00e4}\u{016f}\u{0107}\u{00e7}\u{0142}\u{00eb}\u{0150}\u{0151}\u{00ee}\u{0179}\u{00c4}\u{0106}\u{00c9}\u{0139}\u{013a}\u{00f4}\u{00f6}\u{013d}\u{013e}\u{015a}\u{015b}\u{00d6}\u{00dc}\u{0164}\u{0165}\u{0141}\u{00d7}\u{010d}\u{00e1}\u{00ed}\u{00f3}\u{00fa}\u{0104}\u{0105}\u{017d}\u{017e}\u{0118}\u{0119}\u{00ac}\u{017a}\u{010c}\u{015f}\u{00ab}\u{00bb}\u{2591}\u{2592}\u{2593}\u{2502}\u{2524}\u{00c1}\u{00c2}\u{011a}\u{015e}\u{2563}\u{2551}\u{2557}\u{255d}\u{017b}\u{017c}\u{2510}\u{2514}\u{2534}\u{252c}\u{251c}\u{2500}\u{253c}\u{0102}\u{0103}\u{255a}\u{2554}\u{2569}\u{2566}\u{2560}\u{2550}\u{256c}\u{00a4}\u{0111}\u{0110}\u{010e}\u{00cb}\u{010f}\u{0147}\u{00cd}\u{00ce}\u{011b}\u{2518}\u{250c}\u{2588}\u{2584}\u{0162}\u{016e}\u{2580}\u{00d3}\u{00df}\u{00d4}\u{0143}\u{0144}\u{0148}\u{0160}\u{0161}\u{0154}\u{00da}\u{0155}\u{0170}\u{00fd}\u{00dd}\u{0163}\u{00b4}\u{00ad}\u{02dd}\u{02db}\u{02c7}\u{02d8}\u{00a7}\u{00f7}\u{00b8}\u{00b0}\u{00a8}\u{02d9}\u{0171}\u{0158}\u{0159}\u{25a0}\u{00a0}";

/// Code page 1251, bytes 0x80..=0xFF.
const CP1251: &str = "\u{0402}\u{0403}\u{201a}\u{0453}\u{201e}\u{2026}\u{2020}\u{2021}\u{20ac}\u{2030}\u{0409}\u{2039}\u{040a}\u{040c}\u{040b}\u{040f}\u{0452}\u{2018}\u{2019}\u{201c}\u{201d}\u{2022}\u{2013}\u{2014}\u{fffd}\u{2122}\u{0459}\u{203a}\u{045a}\u{045c}\u{045b}\u{045f}\u{00a0}\u{040e}\u{045e}\u{0408}\u{00a4}\u{0490}\u{00a6}\u{00a7}\u{0401}\u{00a9}\u{0404}\u{00ab}\u{00ac}\u{00ad}\u{00ae}\u{0407}\u{00b0}\u{00b1}\u{0406}\u{0456}\u{0491}\u{00b5}\u{00b6}\u{00b7}\u{0451}\u{2116}\u{0454}\u{00bb}\u{0458}\u{0405}\u{0455}\u{0457}\u{0410}\u{0411}\u{0412}\u{0413}\u{0414}\u{0415}\u{0416}\u{0417}\u{0418}\u{0419}\u{041a}\u{041b}\u{041c}\u{041d}\u{041e}\u{041f}\u{0420}\u{0421}\u{0422}\u{0423}\u{0424}\u{0425}\u{0426}\u{0427}\u{0428}\u{0429}\u{042a}\u{042b}\u{042c}\u{042d}\u{042e}\u{042f}\u{0430}\u{0431}\u{0432}\u{0433}\u{0434}\u{0435}\u{0436}\u{0437}\u{0438}\u{0439}\u{043a}\u{043b}\u{043c}\u{043d}\u{043e}\u{043f}\u{0440}\u{0441}\u{0442}\u{0443}\u{0444}\u{0445}\u{0446}\u{0447}\u{0448}\u{0449}\u{044a}\u{044b}\u{044c}\u{044d}\u{044e}\u{044f}";

const REPLACEMENT: char = '\u{FFFD}';

/// The character a single-byte group gives for `b`.
fn in_table(table: &str, b: u8) -> char {
    if b < 0x80 {
        return b as char;
    }
    table.chars().nth((b - 0x80) as usize).unwrap_or(REPLACEMENT)
}

/// Decode LMBCS bytes to a `String`.
///
/// Never fails: a sequence cut short at the end of the input, or a group
/// this module has no table for, yields U+FFFD. A NUL comes through as
/// U+0000.
pub fn decode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        let b = bytes[i];
        match b {
            // Single-byte groups: one byte follows.
            0x01..=0x06 | 0x08 | 0x0B | 0x0F => {
                let Some(&next) = bytes.get(i + 1) else {
                    out.push(REPLACEMENT);
                    break;
                };
                out.push(match b {
                    0x01 => in_table(CP850, next),
                    0x05 => in_table(CP1251, next),
                    0x06 => in_table(CP852, next),
                    0x0F => char::from(next & 0x1F),
                    _ if next < 0x80 => next as char,
                    _ => REPLACEMENT,
                });
                i += 2;
            }
            // Far East groups and Unicode: two bytes follow.
            0x10..=0x14 => {
                let Some(pair) = bytes.get(i + 1..i + 3) else {
                    out.push(REPLACEMENT);
                    break;
                };
                out.push(if b == 0x14 {
                    char::from_u32(u32::from(u16::from_be_bytes([pair[0], pair[1]])))
                        .unwrap_or(REPLACEMENT)
                } else {
                    REPLACEMENT
                });
                i += 3;
            }
            0x80..=0xFF => {
                out.push(in_table(CP850, b));
                i += 1;
            }
            _ => {
                out.push(b as char);
                i += 1;
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
        // s-caron, c-caron, z-caron.
        assert_eq!(decode(&[0x06, 0xE7, 0x06, 0x9F, 0x06, 0xA7]), "\u{161}\u{10d}\u{17e}");
    }

    #[test]
    fn group_one_and_five_use_their_tables() {
        assert_eq!(decode(&[0x01, 0x84]), "\u{e4}");
        assert_eq!(decode(&[0x05, 0xC6]), "\u{416}");
    }

    #[test]
    fn group_twenty_is_utf16_big_endian() {
        assert_eq!(decode(&[b'a', 0x14, 0x20, 0xAC, b'b']), "a\u{20ac}b");
    }

    #[test]
    fn unknown_groups_keep_the_text_around_them_aligned() {
        // A Greek byte and a Far East pair, each one replacement character.
        assert_eq!(decode(&[b'x', 0x02, 0xE1, b'y', 0x10, 0x88, 0x9F, b'z']), "x\u{fffd}y\u{fffd}z");
    }

    #[test]
    fn a_sequence_cut_short_is_one_replacement() {
        assert_eq!(decode(&[b'a', 0x06]), "a\u{fffd}");
        assert_eq!(decode(&[b'a', 0x14, 0x20]), "a\u{fffd}");
    }

    #[test]
    fn a_nul_is_passed_through() {
        assert_eq!(decode(b"one\0two"), "one\0two");
    }

    #[test]
    fn the_tables_are_complete() {
        for t in [CP850, CP852, CP1251] {
            assert_eq!(t.chars().count(), 128);
        }
    }
}
