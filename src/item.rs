//! Note item parsing - the fields inside a note record.
//!
//! A note record is: the 100-byte note header, then `number_of_note_items`
//! fixed 8-byte item descriptors, then the item values packed back to back
//! in descriptor order. Reverse-engineered from the fakenames Person docs
//! (validated against known field values - street addresses, e-mail
//! addresses, names).
//!
//! Item descriptor (8 bytes):
//!
//! ```text
//! offset  width  field
//!     0      2   name_id     (Unique Name Key id - the field name lives in
//!                             the BDB UNK table, deduplicated across notes)
//!     2      2   type_flags  (item data-type + summary/flag bits)
//!     4      2   value_size  (byte length of this item's value)
//!     6      2   reserved
//! ```
//!
//! Each item's value is `value_size` bytes, taken sequentially from the
//! value region that begins right after the descriptor table at
//! `NOTE_HEADER_BYTES + number_of_note_items * ITEM_DESCRIPTOR_BYTES`.
//!
//! # What is and isn't decoded here
//!
//! This exposes each item's `name_id`, `type_flags`, and **raw value
//! bytes**, plus a best-effort text rendering. Field *names* require the
//! BDB Unique Name Key text table (not yet decoded - it is stored in a
//! region of the BDB body that resists the documented single-stream CX
//! decode). Typed decoding of numbers / times / rich-text (CD records) is
//! left to later slices; the raw bytes are preserved so nothing is lost.

use crate::note::NOTE_HEADER_BYTES;
use crate::time::Timedate;

/// On-disk size of one item descriptor.
pub const ITEM_DESCRIPTOR_BYTES: usize = 8;

/// Authoritative item data kind, derived from the field's `(item_class,
/// item_type)` bytes in the BDB Unique Name Key table (the on-disk note
/// item carries no inline type word). Resolve via
/// [`crate::BucketDescriptorBlock::field_kind`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FieldKind {
    /// CLASS_TEXT / TYPE_TEXT.
    Text,
    /// CLASS_TEXT / TYPE_TEXT_LIST (multi-value text).
    TextList,
    /// CLASS_TEXT / TYPE_RFC822_TEXT (internet headers).
    Rfc822Text,
    /// CLASS_NUMBER / TYPE_NUMBER (IEEE-754 double).
    Number,
    /// CLASS_NUMBER / TYPE_NUMBER_RANGE.
    NumberRange,
    /// CLASS_TIME / TYPE_TIME (TIMEDATE).
    Time,
    /// CLASS_TIME / TYPE_TIME_RANGE.
    TimeRange,
    /// CLASS_FORMULA.
    Formula,
    /// NOCOMPUTE / TYPE_COMPOSITE (CD-record rich text, e.g. `$Body`).
    RichText,
    /// NOCOMPUTE / TYPE_OBJECT (file attachment / object).
    Object,
    /// NOCOMPUTE / TYPE_HTML.
    Html,
    /// NOCOMPUTE / TYPE_MIME_PART.
    MimePart,
    /// Unrecognized class/type pairing.
    Unknown,
}

impl FieldKind {
    /// Short human label.
    pub fn label(self) -> &'static str {
        match self {
            FieldKind::Text => "Text",
            FieldKind::TextList => "Text list",
            FieldKind::Rfc822Text => "RFC822 text",
            FieldKind::Number => "Number",
            FieldKind::NumberRange => "Number range",
            FieldKind::Time => "Time",
            FieldKind::TimeRange => "Time range",
            FieldKind::Formula => "Formula",
            FieldKind::RichText => "Rich text",
            FieldKind::Object => "Attachment / object",
            FieldKind::Html => "HTML",
            FieldKind::MimePart => "MIME part",
            FieldKind::Unknown => "Unknown",
        }
    }
}

/// Map a `(item_class, item_type)` pair to a [`FieldKind`]. Class/type are
/// the bytes at UNK-entry offsets 7 and 6 respectively.
pub fn field_kind(item_class: u8, item_type: u8) -> FieldKind {
    match item_class {
        0x05 => match item_type {
            0x01 => FieldKind::TextList,
            0x02 => FieldKind::Rfc822Text,
            _ => FieldKind::Text,
        },
        0x03 => match item_type {
            0x01 => FieldKind::NumberRange,
            _ => FieldKind::Number,
        },
        0x04 => match item_type {
            0x01 => FieldKind::TimeRange,
            _ => FieldKind::Time,
        },
        0x06 => FieldKind::Formula,
        0x00 => match item_type {
            0x01 => FieldKind::RichText,
            0x03 => FieldKind::Object,
            0x15 => FieldKind::Html,
            0x18 => FieldKind::MimePart,
            _ => FieldKind::Unknown,
        },
        _ => FieldKind::Unknown,
    }
}

/// One parsed note item: its name id, type/flags, and raw value bytes.
#[derive(Debug, Clone, Copy)]
pub struct NoteItem<'a> {
    /// Unique Name Key id of the field name. The name string itself lives
    /// in the BDB UNK table (name resolution is a later slice); the id is
    /// stable within a database so callers can group / correlate fields.
    pub name_id: u16,
    /// Item type + flag bits (the low byte distinguishes the value type
    /// family; high bits carry summary / sign flags).
    pub type_flags: u16,
    /// Raw value bytes, exactly `value_size` long.
    pub value: &'a [u8],
}

impl<'a> NoteItem<'a> {
    /// Decode a TYPE_TEXT_LIST value into its individual entries.
    ///
    /// On-disk layout, validated against the corpus: a `u16` entry count,
    /// then one `u16` byte-length per entry, then every entry's text
    /// concatenated with no separator between them. A `$UpdatedBy` value of
    /// 66 bytes decodes as count 2, lengths 33 and 27, giving
    /// `["CN=Karsten Lehmann/O=Haus Weilgut", "CN=Karsten Lehmann/O=Mindoo"]`.
    ///
    /// Returns `None` unless the header and lengths account for the value
    /// byte-for-byte. That exact-fit requirement is the validation: entries
    /// run together with no delimiter, so a wrong count or length would
    /// silently split names mid-word rather than fail, and a recipient list
    /// chopped into fragments is worse than one left undecoded.
    ///
    /// [`Self::as_text`] flattens the same bytes into a single string with
    /// the binary prefix rendered as `.`, which is why it cannot be used to
    /// recover a recipient list.
    pub fn as_text_list(&self) -> Option<Vec<String>> {
        let v = self.value;
        if v.len() < 4 {
            return None;
        }
        let count = u16::from_le_bytes([v[0], v[1]]) as usize;
        if count == 0 {
            return None;
        }
        let header = 2usize.checked_add(count.checked_mul(2)?)?;
        if header > v.len() {
            return None;
        }
        let mut lens = Vec::with_capacity(count);
        let mut sum = 0usize;
        for k in 0..count {
            let o = 2 + k * 2;
            let l = u16::from_le_bytes([v[o], v[o + 1]]) as usize;
            sum = sum.checked_add(l)?;
            lens.push(l);
        }
        if header.checked_add(sum)? != v.len() {
            return None;
        }
        let mut out = Vec::with_capacity(count);
        let mut off = header;
        for l in lens {
            let end = off + l;
            out.push(String::from_utf8_lossy(&v[off..end]).into_owned());
            off = end;
        }
        Some(out)
    }

    /// Best-effort text rendering of the value: runs of printable ASCII are
    /// kept, other bytes become `.`. Lotus text items (the common case for
    /// names, addresses, e-mail) render cleanly; binary values (numbers,
    /// timedates, rich text) render as dotted placeholders. Lossless access
    /// to the original bytes is via [`Self::value`].
    pub fn as_text(&self) -> String {
        self.value
            .iter()
            .map(|&b| if (0x20..0x7f).contains(&b) { b as char } else { '.' })
            .collect()
    }

    /// True if the value is entirely printable ASCII (a clean text field).
    pub fn is_printable_text(&self) -> bool {
        !self.value.is_empty()
            && self
                .value
                .iter()
                .all(|&b| (0x20..0x7f).contains(&b) || b == b'\t')
    }

    /// Best-effort human rendering of the value by shape (the on-disk note
    /// summary does not carry a per-item type tag, so this infers it):
    ///
    /// - printable bytes -> text;
    /// - 8 bytes that validate as a TIMEDATE (sane Julian-day range) -> ISO
    ///   date; otherwise an IEEE-754 double (the Notes NUMBER type) when it
    ///   is a sane magnitude;
    /// - 1/2/4 bytes -> unsigned integer;
    /// - anything else -> a hex byte summary.
    ///
    /// This is a display aid, not an authoritative type decode (proper
    /// per-field typing from the form design is a later slice). The raw
    /// bytes remain available via [`Self::value`].
    pub fn display_value(&self) -> String {
        if self.value.is_empty() {
            return String::new();
        }
        if self.is_printable_text() {
            return self.as_text();
        }
        match self.value.len() {
            8 => {
                if let Ok(td) = Timedate::from_bytes(self.value) {
                    if let Some(clock) = td.as_clock() {
                        return clock.to_iso_8601();
                    }
                }
                let bytes: [u8; 8] = self.value.try_into().expect("len checked");
                let f = f64::from_le_bytes(bytes);
                if f == 0.0 || (f.is_finite() && f.abs() >= 1e-4 && f.abs() < 1e15) {
                    if f.fract() == 0.0 {
                        return format!("{}", f as i64);
                    }
                    return format!("{f}");
                }
                hex_summary(self.value)
            }
            4 => format!(
                "{}",
                u32::from_le_bytes(self.value.try_into().expect("len checked"))
            ),
            2 => {
                let v = u16::from_le_bytes([self.value[0], self.value[1]]);
                // An empty field stores only its 2-byte Notes data-type word
                // (TYPE_TEXT 0x0500, TYPE_NUMBER 0x0300, TYPE_TIME 0x0400,
                // ...). Treat those as empty rather than a bogus integer.
                if is_type_word(v) {
                    String::new()
                } else {
                    format!("{v}")
                }
            }
            1 => format!("{}", self.value[0]),
            _ => hex_summary(self.value),
        }
    }
}

/// True if `v` is a Notes item data-type constant (the value an empty
/// field stores in place of data): NUMBER 0x0300, NUMBER_RANGE 0x0301,
/// TIME 0x0400, TIME_RANGE 0x0401, TEXT 0x0500, TEXT_LIST 0x0501,
/// FORMULA 0x0600/0x0601, USERID 0x0700.
fn is_type_word(v: u16) -> bool {
    matches!(
        v,
        0x0300 | 0x0301 | 0x0400 | 0x0401 | 0x0500 | 0x0501 | 0x0600 | 0x0601 | 0x0700
    )
}

impl NoteItem<'_> {
    /// Render the value using the authoritative [`FieldKind`] (from the BDB
    /// UNK table) rather than guessing by shape. Rich-text and attachment
    /// values live in the note's non-summary data; here they render as a
    /// kind marker (use `Database::non_summary_data` for the content).
    pub fn render(&self, kind: FieldKind) -> String {
        if self.value.is_empty() {
            return String::new();
        }
        // An empty field stores only its 2-byte type word.
        if self.value.len() == 2 && is_type_word(u16::from_le_bytes([self.value[0], self.value[1]])) {
            return String::new();
        }
        match kind {
            // A TEXT_LIST decodes to its entries when the on-disk lengths fit
            // exactly; joining with "; " keeps a multi-recipient field
            // readable instead of running the names together. Falls through
            // to the flat rendering when the value is not a well-formed list.
            FieldKind::TextList if self.as_text_list().is_some() => {
                self.as_text_list().unwrap_or_default().join("; ")
            }
            FieldKind::Text
            | FieldKind::TextList
            | FieldKind::Rfc822Text
            | FieldKind::Formula
            | FieldKind::Html
            | FieldKind::MimePart => {
                if self.is_printable_text() {
                    self.as_text()
                } else {
                    hex_summary(self.value)
                }
            }
            FieldKind::Number | FieldKind::NumberRange => {
                if self.value.len() >= 8 {
                    let b: [u8; 8] = self.value[..8].try_into().expect("len checked");
                    let f = f64::from_le_bytes(b);
                    if f.is_finite() && f.fract() == 0.0 && f.abs() < 1e15 {
                        format!("{}", f as i64)
                    } else if f.is_finite() {
                        format!("{f}")
                    } else {
                        hex_summary(self.value)
                    }
                } else {
                    self.display_value()
                }
            }
            FieldKind::Time | FieldKind::TimeRange => {
                if self.value.len() >= 8 {
                    if let Ok(td) = Timedate::from_bytes(&self.value[..8]) {
                        if let Some(c) = td.as_clock() {
                            return c.to_iso_8601();
                        }
                    }
                    hex_summary(self.value)
                } else {
                    self.display_value()
                }
            }
            FieldKind::RichText => "(rich text)".to_string(),
            FieldKind::Object => "(attachment / object)".to_string(),
            FieldKind::Unknown => self.display_value(),
        }
    }
}

/// Compact hex rendering of up to the first 16 bytes.
fn hex_summary(b: &[u8]) -> String {
    let mut s = String::new();
    for (i, x) in b.iter().take(16).enumerate() {
        if i > 0 {
            s.push(' ');
        }
        s.push_str(&format!("{x:02x}"));
    }
    if b.len() > 16 {
        s.push_str(" ...");
    }
    s
}

/// Parse the items of a note from its full record bytes (starting at the
/// note header). `number_of_note_items` comes from the note header. Items
/// whose value would run past the record are dropped (truncated record);
/// the walk stops there rather than emitting out-of-bounds slices.
pub fn parse_items(record: &[u8], number_of_note_items: u16) -> Vec<NoteItem<'_>> {
    let count = number_of_note_items as usize;
    let table_end = NOTE_HEADER_BYTES + count * ITEM_DESCRIPTOR_BYTES;
    if record.len() < table_end {
        return Vec::new();
    }
    let mut items = Vec::with_capacity(count);
    let mut cursor = table_end;
    for i in 0..count {
        let d = NOTE_HEADER_BYTES + i * ITEM_DESCRIPTOR_BYTES;
        let name_id = u16::from_le_bytes([record[d], record[d + 1]]);
        let type_flags = u16::from_le_bytes([record[d + 2], record[d + 3]]);
        let value_size = u16::from_le_bytes([record[d + 4], record[d + 5]]) as usize;
        let Some(value) = record.get(cursor..cursor + value_size) else {
            break;
        };
        cursor += value_size;
        items.push(NoteItem {
            name_id,
            type_flags,
            value,
        });
    }
    items
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a synthetic note record: 100-byte header + N 8-byte descriptors
    /// + packed values.
    fn synthetic(items: &[(u16, u16, &[u8])]) -> Vec<u8> {
        let mut buf = vec![0u8; NOTE_HEADER_BYTES];
        // descriptors
        for (name_id, type_flags, value) in items {
            buf.extend_from_slice(&name_id.to_le_bytes());
            buf.extend_from_slice(&type_flags.to_le_bytes());
            buf.extend_from_slice(&(value.len() as u16).to_le_bytes());
            buf.extend_from_slice(&0u16.to_le_bytes());
        }
        // values
        for (_, _, value) in items {
            buf.extend_from_slice(value);
        }
        buf
    }

    #[test]
    fn parses_packed_text_values() {
        let rec = synthetic(&[
            (0x09A1, 0x000C, b"613 Goolagong Pde."),
            (0x07E5, 0x020C, b"a@b.org"),
            (0x0036, 0x0004, b""), // empty value
        ]);
        let items = parse_items(&rec, 3);
        assert_eq!(items.len(), 3);
        assert_eq!(items[0].name_id, 0x09A1);
        assert_eq!(items[0].as_text(), "613 Goolagong Pde.");
        assert!(items[0].is_printable_text());
        assert_eq!(items[1].as_text(), "a@b.org");
        assert!(items[2].value.is_empty());
    }

    #[test]
    fn truncated_record_stops_cleanly() {
        let mut rec = synthetic(&[(0x0001, 0x000C, b"hello world")]);
        rec.truncate(rec.len() - 4); // chop the value
        let items = parse_items(&rec, 1);
        // Value would overrun -> dropped, no panic.
        assert!(items.is_empty());
    }

    #[test]
    fn zero_items_yields_empty() {
        let rec = vec![0u8; NOTE_HEADER_BYTES];
        assert!(parse_items(&rec, 0).is_empty());
    }

    #[test]
    fn display_value_renders_by_shape() {
        let rec = synthetic(&[
            (1, 0x0C, b"hello"),                 // text
            (2, 0x04, &0x0500u16.to_le_bytes()), // bare TEXT type word -> empty
            (3, 0x04, &42u16.to_le_bytes()),     // real 2-byte integer
            (4, 0x04, &[0x99; 6]),               // 6 bytes -> hex summary
        ]);
        let items = parse_items(&rec, 4);
        assert_eq!(items[0].display_value(), "hello");
        assert_eq!(items[1].display_value(), ""); // type-word placeholder
        assert_eq!(items[2].display_value(), "42");
        assert_eq!(items[3].display_value(), "99 99 99 99 99 99");
    }
}

#[cfg(test)]
mod text_list_tests {
    use super::*;

    fn item(value: &[u8]) -> NoteItem<'_> {
        NoteItem { name_id: 0, type_flags: 0, value }
    }

    /// Build a well-formed TEXT_LIST value from entries.
    fn encode(entries: &[&str]) -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(&(entries.len() as u16).to_le_bytes());
        for e in entries {
            v.extend_from_slice(&(e.len() as u16).to_le_bytes());
        }
        for e in entries {
            v.extend_from_slice(e.as_bytes());
        }
        v
    }

    #[test]
    fn decodes_the_corpus_shape() {
        // Byte-for-byte the $UpdatedBy value observed in fakenames.nsf:
        // count 2, lengths 33 and 27.
        let v = encode(&[
            "CN=Karsten Lehmann/O=Haus Weilgut",
            "CN=Karsten Lehmann/O=Mindoo",
        ]);
        assert_eq!(v.len(), 66, "corpus value was 66 bytes");
        assert_eq!(v[0..2], [0x02, 0x00]);
        assert_eq!(v[2..4], [0x21, 0x00]);
        assert_eq!(v[4..6], [0x1B, 0x00]);
        let got = item(&v).as_text_list().expect("must decode");
        assert_eq!(
            got,
            vec![
                "CN=Karsten Lehmann/O=Haus Weilgut".to_string(),
                "CN=Karsten Lehmann/O=Mindoo".to_string()
            ]
        );
    }

    #[test]
    fn single_entry_list_decodes() {
        let v = encode(&["CN=Alice/O=Acme"]);
        assert_eq!(item(&v).as_text_list().unwrap(), vec!["CN=Alice/O=Acme"]);
    }

    #[test]
    fn rejects_anything_that_does_not_fit_exactly() {
        // Entries run together with no delimiter, so a length that is wrong
        // by one would split a name mid-word and still look plausible. Only
        // an exact fit is accepted.
        let mut v = encode(&["alice", "bob"]);
        v.push(b'X'); // one trailing byte the lengths do not account for
        assert!(item(&v).as_text_list().is_none());

        let mut short = encode(&["alice", "bob"]);
        short.pop();
        assert!(item(&short).as_text_list().is_none());
    }

    #[test]
    fn rejects_degenerate_headers() {
        assert!(item(&[]).as_text_list().is_none());
        assert!(item(&[0x01, 0x00]).as_text_list().is_none());
        // Count of zero is not a list.
        assert!(item(&[0x00, 0x00, 0x00, 0x00]).as_text_list().is_none());
        // A count large enough to overflow the header arithmetic must not panic.
        assert!(item(&[0xFF, 0xFF, 0x00, 0x00]).as_text_list().is_none());
    }

    #[test]
    fn render_joins_list_entries_readably() {
        let v = encode(&["CN=Alice/O=Acme", "CN=Bob/O=Acme"]);
        assert_eq!(
            item(&v).render(FieldKind::TextList),
            "CN=Alice/O=Acme; CN=Bob/O=Acme"
        );
    }

    #[test]
    fn render_falls_back_when_the_value_is_not_a_well_formed_list() {
        // Plain text mistyped as a list must still render as text rather
        // than vanish.
        let v = b"plain text value";
        let out = item(v).render(FieldKind::TextList);
        assert_eq!(out, "plain text value");
    }
}
