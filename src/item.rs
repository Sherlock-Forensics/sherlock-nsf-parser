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
    walk_items(record, number_of_note_items).items
}

/// Why an item walk stopped short of the header's declared count.
///
/// A note that declares 139 items and yields none is not a note with no
/// fields, and returning a bare empty vector for it makes the tool answer
/// "there is nothing here" to a question it never managed to ask.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ItemWalkStop {
    /// Every declared item was read.
    Complete,
    /// The descriptor table itself does not fit inside the record.
    TableDoesNotFit { needed: usize, record_len: usize },
    /// An item's declared value size runs past the end of the record, so the
    /// values are not all stored inside it. Measured across the corpus, 1412
    /// of 42854 notes stop this way and 19584 declared items are never
    /// reached. Where those values live is not yet known, and guessing would
    /// be worse than saying so.
    ValueOverrunsRecord {
        index: usize,
        declared_size: usize,
        remaining: usize,
    },
}

/// An item walk, with the accounting that says whether to trust it.
#[derive(Debug, Clone)]
pub struct ItemWalk<'a> {
    pub items: Vec<NoteItem<'a>>,
    /// What the note header said to expect.
    pub claimed: u16,
    pub stop: ItemWalkStop,
    /// Name ids of the declared items the walk did not reach, read from the
    /// descriptor table (which is intact - it is the VALUES that are not in
    /// the record). Naming them turns "some fields are missing" into "these
    /// fields are missing", which is the difference between an alarm and a
    /// finding.
    pub unreached_name_ids: Vec<u16>,
    /// The same items, each with its field flags and what they say about why
    /// it was not reached. `unreached_name_ids` stays as the bare list for
    /// callers that only want to name them.
    pub unreached: Vec<UnreachedItem>,
}

impl ItemWalk<'_> {
    /// True when fewer items were recovered than the header declared.
    pub fn incomplete(&self) -> bool {
        self.items.len() < self.claimed as usize
    }

    /// Items the header declared that the walk never reached.
    pub fn unreached(&self) -> usize {
        (self.claimed as usize).saturating_sub(self.items.len())
    }
}

/// Walk a note's items and report what happened, not only what worked.
pub fn walk_items(record: &[u8], number_of_note_items: u16) -> ItemWalk<'_> {
    let count = number_of_note_items as usize;
    let table_end = NOTE_HEADER_BYTES + count * ITEM_DESCRIPTOR_BYTES;
    if record.len() < table_end {
        return ItemWalk {
            items: Vec::new(),
            claimed: number_of_note_items,
            stop: ItemWalkStop::TableDoesNotFit {
                needed: table_end,
                record_len: record.len(),
            },
            unreached_name_ids: Vec::new(),
            unreached: Vec::new(),
        };
    }
    let mut items = Vec::with_capacity(count);
    let mut cursor = table_end;
    let mut stop = ItemWalkStop::Complete;
    for i in 0..count {
        let d = NOTE_HEADER_BYTES + i * ITEM_DESCRIPTOR_BYTES;
        let name_id = u16::from_le_bytes([record[d], record[d + 1]]);
        let type_flags = u16::from_le_bytes([record[d + 2], record[d + 3]]);
        let value_size = u16::from_le_bytes([record[d + 4], record[d + 5]]) as usize;
        let Some(value) = record.get(cursor..cursor + value_size) else {
            stop = ItemWalkStop::ValueOverrunsRecord {
                index: i,
                declared_size: value_size,
                remaining: record.len().saturating_sub(cursor),
            };
            break;
        };
        cursor += value_size;
        items.push(NoteItem {
            name_id,
            type_flags,
            value,
        });
    }
    let mut unreached_name_ids = Vec::new();
    let mut unreached = Vec::new();
    for i in items.len()..count {
        let d = NOTE_HEADER_BYTES + i * ITEM_DESCRIPTOR_BYTES;
        let (Some(a), Some(b)) = (record.get(d), record.get(d + 1)) else {
            break;
        };
        let name_id = u16::from_le_bytes([*a, *b]);
        // The descriptor table is fixed-width, so an item's flags are still
        // readable even where the walk could not reach its value.
        let flags = match (record.get(d + 2), record.get(d + 3)) {
            (Some(x), Some(y)) => u16::from_le_bytes([*x, *y]),
            _ => 0,
        };
        unreached_name_ids.push(name_id);
        unreached.push(UnreachedItem {
            name_id,
            flags,
            reason: UnreachedReason::classify(flags),
        });
    }
    ItemWalk {
        items,
        claimed: number_of_note_items,
        stop,
        unreached_name_ids,
        unreached,
    }
}

/// Field flag: the value is stored in the note data rather than in the
/// non-summary data. Its absence means the value was never in this record to
/// be found.
pub const ITEM_SUMMARY: u16 = 0x0004;

/// Field flag: name the item in the item table, but store no value for it.
pub const ITEM_PLACEHOLDER: u16 = 0x0100;

/// Why a declared item was not recovered from the record.
///
/// This distinction exists because the previous answer - a single count of
/// "fields that went unread" - alarmed examiners about the ordinary case.
/// Measured across the corpus, roughly three quarters of unreached items are
/// items that by definition have no value in the record: a placeholder stores
/// nothing, and a non-summary item's value lives in the non-summary object.
/// Reporting those as potentially-missed evidence overstates the problem and
/// buries the quarter that is real.
///
/// Flag meanings are from the libyal NSF format documentation. This build
/// reads the flags; it does not yet follow a non-summary item to its value,
/// which is why [`UnreachedReason::ValueInNonSummary`] says where the value is
/// rather than claiming to have read it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnreachedReason {
    /// `ITEM_PLACEHOLDER` set. No value was ever stored. Expected, not a gap.
    NoValueStored,
    /// `ITEM_SUMMARY` clear: the value lives in the non-summary object rather
    /// than in this record. Expected to be absent here.
    ValueInNonSummary,
    /// A summary item that should have been in the record and was not. The
    /// only one of the three that means recoverable data went unrecovered.
    Unexplained,
}

impl UnreachedReason {
    pub fn classify(flags: u16) -> Self {
        if flags & ITEM_PLACEHOLDER != 0 {
            UnreachedReason::NoValueStored
        } else if flags & ITEM_SUMMARY == 0 {
            UnreachedReason::ValueInNonSummary
        } else {
            UnreachedReason::Unexplained
        }
    }

    /// True when the item's absence from the record is expected rather than a
    /// shortfall in what this build recovered.
    pub fn is_expected(self) -> bool {
        !matches!(self, UnreachedReason::Unexplained)
    }

    pub fn label(self) -> &'static str {
        match self {
            UnreachedReason::NoValueStored => "no value stored",
            UnreachedReason::ValueInNonSummary => "value is in the non-summary object",
            UnreachedReason::Unexplained => "unexplained",
        }
    }
}

/// One declared item the walk did not reach, and why.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UnreachedItem {
    pub name_id: u16,
    /// Raw field flags from the descriptor, kept so a reader is never left
    /// taking this build's classification on trust.
    pub flags: u16,
    pub reason: UnreachedReason,
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

    #[test]
    fn a_walk_that_reaches_every_item_says_so() {
        let rec = synthetic(&[(1, 0x000D, b"abc"), (2, 0x000D, b"de")]);
        let w = walk_items(&rec, 2);
        assert_eq!(w.items.len(), 2);
        assert_eq!(w.claimed, 2);
        assert_eq!(w.stop, ItemWalkStop::Complete);
        assert!(!w.incomplete());
        assert_eq!(w.unreached(), 0);
    }

    #[test]
    fn a_value_running_past_the_record_is_reported_not_swallowed() {
        // The measured corpus case: a note declares items whose values are
        // not inside the record, and the walk returned an empty vector that
        // a caller could only read as "this note has no fields".
        let mut rec = synthetic(&[(1, 0x000D, b"abcdef")]);
        rec.truncate(NOTE_HEADER_BYTES + ITEM_DESCRIPTOR_BYTES + 2);
        let w = walk_items(&rec, 1);
        assert!(w.items.is_empty());
        assert!(w.incomplete());
        assert_eq!(w.unreached(), 1);
        match w.stop {
            ItemWalkStop::ValueOverrunsRecord { index, declared_size, remaining } => {
                assert_eq!(index, 0);
                assert_eq!(declared_size, 6);
                assert_eq!(remaining, 2);
            }
            other => panic!("expected an overrun, got {other:?}"),
        }
    }

    #[test]
    fn a_table_that_does_not_fit_is_its_own_answer() {
        let rec = vec![0u8; NOTE_HEADER_BYTES + 4];
        let w = walk_items(&rec, 10);
        assert!(w.items.is_empty());
        assert!(w.incomplete());
        assert!(matches!(w.stop, ItemWalkStop::TableDoesNotFit { .. }));
    }

    #[test]
    fn a_partial_walk_keeps_what_it_reached() {
        // Two of three fields is worth more than none, as long as the count
        // says two of three.
        let mut rec = synthetic(&[
            (1, 0x000D, b"aa"),
            (2, 0x000D, b"bb"),
            (3, 0x000D, b"cccccccccc"),
        ]);
        rec.truncate(NOTE_HEADER_BYTES + 3 * ITEM_DESCRIPTOR_BYTES + 4);
        let w = walk_items(&rec, 3);
        assert_eq!(w.items.len(), 2);
        assert_eq!(w.claimed, 3);
        assert_eq!(w.unreached(), 1);
    }
}

/// # Where the overflow values are NOT
///
/// When an item walk stops, the values it could not read are somewhere.
/// These diagnostics (all ignored by default; run with
/// `cargo test -- --ignored --nocapture`) record what has been RULED OUT,
/// so the next attempt does not repeat it:
///
/// - `diagnose_overflow_is_the_non_summary_object`: the first unreached
///   item's declared size equals the non-summary object's payload for only
///   42 of 617 incomplete notes. Not a general rule.
/// - `diagnose_declared_vs_record_size`: with a 100-byte header the declared
///   totals exceed the record by 2-25x; with a 64-byte header they are
///   nonsense (~68KB). The descriptor table really does start at 100, and
///   the record really is too small for what it declares.
/// - `diagnose_values_span_record_then_object`: the record tail plus the
///   object payload SIZES the gap almost exactly - 595 of 617 notes come out
///   8 to 11 bytes over. Arithmetically compelling.
/// - `diagnose_which_overflow_layout_decodes`: and it is still wrong.
///   Walking the unreached descriptors against that concatenation, and
///   against the object at offsets 0 and 68, decodes ZERO TEXT_LIST values.
///   A TEXT_LIST is a strict oracle: its internal lengths must account for
///   the value byte for byte, so a correct offset would decode and a wrong
///   one cannot. The size arithmetic matching was a coincidence.
///
/// A second attempt then looked at the object store rather than the
/// non-summary object:
///
/// - `diagnose_withheld_signatures`: every non-note RRV target in
///   fakenames.nsf carries ONE signature, 0x001B - 75 of them. So there is a
///   single object class, and it is a candidate home for the missing values.
/// - `diagnose_object_records`: those records are `1B 00` then a u32 length
///   then a short header, and their lengths run from ~1KB to ~7KB.
/// - `diagnose_object_length_matches_unreached_sum`: but there are only 75
///   of them against 617 incomplete notes, and matching lengths to unreached
///   sums gives no consistent offset (best diffs scatter across -32..+55
///   with no mode). They cannot account for the gap.
///
/// The values' location remains unknown. Nothing here guesses at it, and
/// black-box probing has now been tried twice; the next attempt should come
/// from a format reference or from a database where the same note can be
/// compared against a known-good export.
#[cfg(test)]
mod overflow_diagnostics {
    use super::*;
    /// Which concatenation recovers real values? A TEXT_LIST value only
    /// decodes when its internal lengths account for the bytes exactly, so
    /// $UpdatedBy is an oracle: if the offset is wrong, it will not decode.
    #[test]
    #[ignore = "diagnostic"]
    fn diagnose_which_overflow_layout_decodes() {
        let path = std::path::PathBuf::from(r"C:\SherlockForensics")
            .join(".scratch")
            .join("nsf-samples")
            .join("real-nsf")
            .join("fakenames.nsf");
        if !path.is_file() {
            return;
        }
        let bytes = std::fs::read(&path).expect("read");
        let db = crate::Database::open(&bytes).expect("open");
        let en = db.enumerate_notes().expect("enumerate");
        let bdb = db.bucket_descriptor_block().expect("bdb").expect("bdb");
        // Try several starts for the object's value region.
        let mut wins: std::collections::BTreeMap<String, usize> = Default::default();
        for n in &en.notes {
            let w = db.note_items_walk(n);
            if !w.incomplete() {
                continue;
            }
            let Some(obj) = db.non_summary_data(n) else { continue };
            let start = n.file_offset as usize;
            let end = (start + n.header.size as usize).min(bytes.len());
            let rec = &bytes[start..end];
            let count = n.header.number_of_note_items as usize;
            let table_end = NOTE_HEADER_BYTES + count * ITEM_DESCRIPTOR_BYTES;
            let mut consumed = table_end;
            for k in 0..w.items.len() {
                let d = NOTE_HEADER_BYTES + k * ITEM_DESCRIPTOR_BYTES;
                consumed += u16::from_le_bytes([rec[d + 4], rec[d + 5]]) as usize;
            }
            for (label, buf) in [
                ("tail+obj68", {
                    let mut v = rec[consumed.min(rec.len())..].to_vec();
                    v.extend_from_slice(obj.get(68..).unwrap_or(&[]));
                    v
                }),
                ("obj68", obj.get(68..).unwrap_or(&[]).to_vec()),
                ("obj0", obj.to_vec()),
            ] {
                // Walk the unreached descriptors against this buffer and see
                // whether any TEXT_LIST field decodes exactly.
                let mut off = 0usize;
                let mut decoded = 0usize;
                for k in w.items.len()..count {
                    let d = NOTE_HEADER_BYTES + k * ITEM_DESCRIPTOR_BYTES;
                    if d + 8 > rec.len() {
                        break;
                    }
                    let id = u16::from_le_bytes([rec[d], rec[d + 1]]);
                    let sz = u16::from_le_bytes([rec[d + 4], rec[d + 5]]) as usize;
                    let Some(val) = buf.get(off..off + sz) else { break };
                    off += sz;
                    if bdb.field_kind(id) == FieldKind::TextList {
                        let it = NoteItem { name_id: id, type_flags: 0, value: val };
                        if it.as_text_list().is_some() {
                            decoded += 1;
                        }
                    }
                }
                if decoded > 0 {
                    *wins.entry(label.to_string()).or_default() += decoded;
                }
            }
        }
        eprintln!("TEXT_LIST decodes by layout: {wins:?}");
    }

    /// Precise test: are the values packed across the record AND then the
    /// non-summary payload, contiguously?
    #[test]
    #[ignore = "diagnostic"]
    fn diagnose_values_span_record_then_object() {
        let path = std::path::PathBuf::from(r"C:\SherlockForensics")
            .join(".scratch")
            .join("nsf-samples")
            .join("real-nsf")
            .join("fakenames.nsf");
        if !path.is_file() {
            return;
        }
        let bytes = std::fs::read(&path).expect("read");
        let db = crate::Database::open(&bytes).expect("open");
        let en = db.enumerate_notes().expect("enumerate");
        let (mut exact, mut over, mut under) = (0usize, 0usize, 0usize);
        let mut excess: std::collections::BTreeMap<usize, usize> = Default::default();
        let mut shown = 0;
        for n in &en.notes {
            let w = db.note_items_walk(n);
            if !w.incomplete() {
                continue;
            }
            let start = n.file_offset as usize;
            let end = (start + n.header.size as usize).min(bytes.len());
            let rec = &bytes[start..end];
            let count = n.header.number_of_note_items as usize;
            let table_end = NOTE_HEADER_BYTES + count * ITEM_DESCRIPTOR_BYTES;
            let mut consumed = table_end;
            let mut declared_total = 0usize;
            for k in 0..count {
                let d = NOTE_HEADER_BYTES + k * ITEM_DESCRIPTOR_BYTES;
                if d + 8 > rec.len() {
                    break;
                }
                let sz = u16::from_le_bytes([rec[d + 4], rec[d + 5]]) as usize;
                declared_total += sz;
                if k < w.items.len() {
                    consumed += sz;
                }
            }
            let leftover = rec.len().saturating_sub(consumed);
            let ns_payload = (n.header.non_summary_data_size as usize).saturating_sub(68);
            let available = leftover + ns_payload;
            let needed = declared_total
                - (consumed - table_end); // what the recovered items already took
            match available.cmp(&needed) {
                std::cmp::Ordering::Equal => exact += 1,
                std::cmp::Ordering::Greater => {
                    over += 1;
                    *excess.entry(available - needed).or_default() += 1;
                }
                std::cmp::Ordering::Less => {
                    under += 1;
                    if shown < 5 {
                        shown += 1;
                        eprintln!(
                            "   note 0x{:08X} needed {needed} available {available} (leftover {leftover} + ns {ns_payload})",
                            n.rrv_identifier
                        );
                    }
                }
            }
        }
        eprintln!("SPAN TEST: {exact} exact, {over} more available than needed, {under} short");
        let mut v: Vec<_> = excess.into_iter().collect();
        v.sort_by(|a, b| b.1.cmp(&a.1));
        eprintln!("   excess bytes, most common:");
        for (e, n) in v.iter().take(10) {
            eprintln!("      {e:>8} bytes  {n} notes");
        }
    }

    /// Does the sum of the UNREACHED declared sizes match the non-summary
    /// object's payload? If the overflow values live there, it should.
    #[test]
    #[ignore = "diagnostic"]
    fn diagnose_unreached_sum_vs_non_summary() {
        let path = std::path::PathBuf::from(r"C:\SherlockForensics")
            .join(".scratch")
            .join("nsf-samples")
            .join("real-nsf")
            .join("fakenames.nsf");
        if !path.is_file() {
            return;
        }
        let bytes = std::fs::read(&path).expect("read");
        let db = crate::Database::open(&bytes).expect("open");
        let en = db.enumerate_notes().expect("enumerate");
        let mut hist: std::collections::BTreeMap<i64, usize> = Default::default();
        let mut shown = 0;
        for n in &en.notes {
            let w = db.note_items_walk(n);
            if !w.incomplete() {
                continue;
            }
            let start = n.file_offset as usize;
            let end = (start + n.header.size as usize).min(bytes.len());
            let rec = &bytes[start..end];
            let count = n.header.number_of_note_items as usize;
            let mut unreached_sum = 0usize;
            for k in w.items.len()..count {
                let d = NOTE_HEADER_BYTES + k * ITEM_DESCRIPTOR_BYTES;
                if d + 8 > rec.len() {
                    break;
                }
                unreached_sum += u16::from_le_bytes([rec[d + 4], rec[d + 5]]) as usize;
            }
            let ns_payload = (n.header.non_summary_data_size as usize).saturating_sub(68);
            let diff = ns_payload as i64 - unreached_sum as i64;
            *hist.entry(diff).or_default() += 1;
            if diff != 0 && shown < 5 {
                shown += 1;
                eprintln!(
                    "   note 0x{:08X} unreached_sum {unreached_sum} ns_payload {ns_payload} diff {diff}",
                    n.rrv_identifier
                );
            }
        }
        let mut v: Vec<_> = hist.into_iter().collect();
        v.sort_by(|a, b| b.1.cmp(&a.1));
        eprintln!("UNREACHED SUM vs NS PAYLOAD, most common diffs:");
        for (d, n) in v.into_iter().take(8) {
            eprintln!("   diff {d:>8}  {n} notes");
        }
    }

    /// How far off is the record from holding everything it declares?
    #[test]
    #[ignore = "diagnostic"]
    fn diagnose_declared_vs_record_size() {
        let path = std::path::PathBuf::from(r"C:\SherlockForensics")
            .join(".scratch")
            .join("nsf-samples")
            .join("real-nsf")
            .join("fakenames.nsf");
        if !path.is_file() {
            return;
        }
        let bytes = std::fs::read(&path).expect("read");
        let db = crate::Database::open(&bytes).expect("open");
        let en = db.enumerate_notes().expect("enumerate");
        let mut shown = 0;
        let (mut fits_at_64, mut fits_at_100, mut neither) = (0, 0, 0);
        for n in &en.notes {
            let w = db.note_items_walk(n);
            if !w.incomplete() {
                continue;
            }
            let start = n.file_offset as usize;
            let end = (start + n.header.size as usize).min(bytes.len());
            let rec = &bytes[start..end];
            let count = n.header.number_of_note_items as usize;
            let mut fit = |base: usize| -> Option<usize> {
                let table_end = base + count * ITEM_DESCRIPTOR_BYTES;
                if rec.len() < table_end {
                    return None;
                }
                let mut sum = table_end;
                for k in 0..count {
                    let d = base + k * ITEM_DESCRIPTOR_BYTES;
                    sum += u16::from_le_bytes([rec[d + 4], rec[d + 5]]) as usize;
                }
                Some(sum)
            };
            let at100 = fit(100);
            let at64 = fit(64);
            match (at64, at100) {
                (Some(a), _) if a == rec.len() => fits_at_64 += 1,
                (_, Some(b)) if b == rec.len() => fits_at_100 += 1,
                _ => {
                    neither += 1;
                    if shown < 6 {
                        shown += 1;
                        eprintln!(
                            "   note 0x{:08X} rec {} items {} needs@100 {:?} needs@64 {:?}",
                            n.rrv_identifier,
                            rec.len(),
                            count,
                            at100,
                            at64
                        );
                    }
                }
            }
        }
        eprintln!("SIZE FIT: {fits_at_64} fit with a 64-byte header, {fits_at_100} with 100, {neither} neither");
    }

    /// What is actually INSIDE the 0x001B object records? If they hold file
    /// data, the name-only attachments have their bytes here.
    #[test]
    #[ignore = "diagnostic"]
    fn diagnose_object_payloads() {
        let path = std::path::PathBuf::from(r"C:\SherlockForensics")
            .join(".scratch")
            .join("nsf-samples")
            .join("real-nsf")
            .join("fakenames.nsf");
        if !path.is_file() {
            return;
        }
        let bytes = std::fs::read(&path).expect("read");
        let db = crate::Database::open(&bytes).expect("open");
        let en = db.enumerate_notes().expect("enumerate");
        let mut shown = 0;
        for wh in &en.withheld {
            if !matches!(
                wh.reason,
                crate::WithheldReason::NotANoteRecord { found_signature: 0x001B }
            ) {
                continue;
            }
            let crate::WithheldLocation::FilePosition { file_position_pages } = wh.location else {
                continue;
            };
            if shown >= 8 {
                break;
            }
            shown += 1;
            let off = (file_position_pages as usize) * 256;
            let len = bytes
                .get(off + 2..off + 6)
                .map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]) as usize)
                .unwrap_or(0);
            let body = bytes.get(off..off + len.min(64 * 1024)).unwrap_or(&[]);
            let nonzero = body.iter().filter(|b| **b != 0).count();
            let first_nz = body.iter().skip(6).position(|b| *b != 0);
            eprintln!(
                "   rrv 0x{:08X} len {len:6} nonzero {nonzero}/{} first_nz_after_hdr {:?}",
                wh.rrv_identifier,
                body.len(),
                first_nz
            );
            for base in [0usize] {
                let w = bytes.get(off + base..off + base + 24).unwrap_or(&[]);
                let printable: String = w
                    .iter()
                    .map(|b| if b.is_ascii_graphic() { *b as char } else { '.' })
                    .collect();
                let hex: Vec<String> = w.iter().take(8).map(|b| format!("{b:02X}")).collect();
                eprintln!(
                    "   rrv 0x{:08X} len {len:6} base {base:2}: {} | {printable}",
                    wh.rrv_identifier,
                    hex.join(" ")
                );
            }
        }
    }

    /// Does an object record's length match a note's unreached value sum?
    #[test]
    #[ignore = "diagnostic"]
    fn diagnose_object_length_matches_unreached_sum() {
        let path = std::path::PathBuf::from(r"C:\SherlockForensics")
            .join(".scratch")
            .join("nsf-samples")
            .join("real-nsf")
            .join("fakenames.nsf");
        if !path.is_file() {
            return;
        }
        let bytes = std::fs::read(&path).expect("read");
        let db = crate::Database::open(&bytes).expect("open");
        let en = db.enumerate_notes().expect("enumerate");
        // Every object record: (rrv, file offset, declared length).
        let mut objects: Vec<(u32, usize, usize)> = Vec::new();
        for wh in &en.withheld {
            if !matches!(
                wh.reason,
                crate::WithheldReason::NotANoteRecord { found_signature: 0x001B }
            ) {
                continue;
            }
            if let crate::WithheldLocation::FilePosition { file_position_pages } = wh.location {
                let off = (file_position_pages as usize) * 256;
                if let Some(b) = bytes.get(off + 2..off + 6) {
                    let len = u32::from_le_bytes([b[0], b[1], b[2], b[3]]) as usize;
                    objects.push((wh.rrv_identifier, off, len));
                }
            }
        }
        eprintln!("objects: {}", objects.len());
        let mut matched = 0usize;
        let mut offsets: std::collections::BTreeMap<i64, usize> = Default::default();
        let mut incomplete = 0usize;
        for n in &en.notes {
            let w = db.note_items_walk(n);
            if !w.incomplete() {
                continue;
            }
            incomplete += 1;
            let start = n.file_offset as usize;
            let end = (start + n.header.size as usize).min(bytes.len());
            let rec = &bytes[start..end];
            let count = n.header.number_of_note_items as usize;
            let mut unreached_sum = 0usize;
            for k in w.items.len()..count {
                let d = NOTE_HEADER_BYTES + k * ITEM_DESCRIPTOR_BYTES;
                if d + 8 > rec.len() {
                    break;
                }
                unreached_sum += u16::from_le_bytes([rec[d + 4], rec[d + 5]]) as usize;
            }
            // Any object within 64 bytes of that size?
            if let Some((_, _, len)) = objects
                .iter()
                .min_by_key(|(_, _, len)| (*len as i64 - unreached_sum as i64).abs())
            {
                let diff = *len as i64 - unreached_sum as i64;
                if diff.abs() <= 64 {
                    matched += 1;
                    *offsets.entry(diff).or_default() += 1;
                }
            }
        }
        eprintln!("{incomplete} incomplete notes, {matched} have an object within 64 bytes of their unreached sum");
        let mut v: Vec<_> = offsets.into_iter().collect();
        v.sort_by(|a, b| b.1.cmp(&a.1));
        for (d, n) in v.into_iter().take(8) {
            eprintln!("   diff {d:>6}  {n}");
        }
    }

    /// Dump the 0x001B records: what do they hold, and how big are they?
    #[test]
    #[ignore = "diagnostic"]
    fn diagnose_object_records() {
        let path = std::path::PathBuf::from(r"C:\SherlockForensics")
            .join(".scratch")
            .join("nsf-samples")
            .join("real-nsf")
            .join("fakenames.nsf");
        if !path.is_file() {
            return;
        }
        let bytes = std::fs::read(&path).expect("read");
        let db = crate::Database::open(&bytes).expect("open");
        let en = db.enumerate_notes().expect("enumerate");
        let mut shown = 0;
        for wh in &en.withheld {
            let crate::WithheldReason::NotANoteRecord { found_signature } = &wh.reason else {
                continue;
            };
            if *found_signature != 0x001B || shown >= 6 {
                continue;
            }
            let crate::WithheldLocation::FilePosition { file_position_pages } = wh.location else {
                eprintln!("   rrv 0x{:08X} lives in a bucket slot", wh.rrv_identifier);
                shown += 1;
                continue;
            };
            let off = (file_position_pages as usize) * 256;
            let head: Vec<String> = bytes
                .get(off..off + 48)
                .unwrap_or(&[])
                .iter()
                .map(|b| format!("{b:02X}"))
                .collect();
            // A record's length usually follows its 2-byte signature.
            let len16 = bytes
                .get(off + 2..off + 4)
                .map(|b| u16::from_le_bytes([b[0], b[1]]))
                .unwrap_or(0);
            let len32 = bytes
                .get(off + 2..off + 6)
                .map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
                .unwrap_or(0);
            eprintln!(
                "   rrv 0x{:08X} at 0x{off:X} len16 {len16} len32 {len32}: {}",
                wh.rrv_identifier,
                head.join(" ")
            );
            shown += 1;
        }
    }

    /// What ARE the withheld non-note records? If some of them are the
    /// object store, the missing item values may be inside them.
    #[test]
    #[ignore = "diagnostic"]
    fn diagnose_withheld_signatures() {
        let path = std::path::PathBuf::from(r"C:\SherlockForensics")
            .join(".scratch")
            .join("nsf-samples")
            .join("real-nsf")
            .join("fakenames.nsf");
        if !path.is_file() {
            return;
        }
        let bytes = std::fs::read(&path).expect("read");
        let db = crate::Database::open(&bytes).expect("open");
        let en = db.enumerate_notes().expect("enumerate");
        let mut sigs: std::collections::BTreeMap<u16, usize> = Default::default();
        let mut reasons: std::collections::BTreeMap<&str, usize> = Default::default();
        for wh in &en.withheld {
            match &wh.reason {
                crate::WithheldReason::NotANoteRecord { found_signature } => {
                    *reasons.entry("NotANoteRecord").or_default() += 1;
                    *sigs.entry(*found_signature).or_default() += 1;
                }
                crate::WithheldReason::IdentityMismatch { .. } => {
                    *reasons.entry("IdentityMismatch").or_default() += 1;
                }
                crate::WithheldReason::Unresolvable => {
                    *reasons.entry("Unresolvable").or_default() += 1;
                }
            }
        }
        eprintln!("WITHHELD: {} entries {reasons:?}", en.withheld.len());
        let mut v: Vec<_> = sigs.into_iter().collect();
        v.sort_by(|a, b| b.1.cmp(&a.1));
        for (sig, n) in v.into_iter().take(10) {
            eprintln!("   signature 0x{sig:04X}  {n}");
        }
    }

    /// Test one hypothesis: when the walk stops, is the first unreached
    /// item's declared value size exactly the non-summary object's payload
    /// (its size minus the 68-byte object header)?
    #[test]
    #[ignore = "diagnostic"]
    fn diagnose_overflow_is_the_non_summary_object() {
        let path = std::path::PathBuf::from(r"C:\SherlockForensics")
            .join(".scratch")
            .join("nsf-samples")
            .join("real-nsf")
            .join("fakenames.nsf");
        if !path.is_file() {
            return;
        }
        let bytes = std::fs::read(&path).expect("read");
        let db = crate::Database::open(&bytes).expect("open");
        let en = db.enumerate_notes().expect("enumerate");
        let (mut tested, mut exact, mut nonsummary_zero, mut other) = (0, 0, 0, 0);
        let mut examples = 0;
        for n in &en.notes {
            let w = db.note_items_walk(n);
            if !w.incomplete() {
                continue;
            }
            let start = n.file_offset as usize;
            let end = (start + n.header.size as usize).min(bytes.len());
            let rec = &bytes[start..end];
            let idx = w.items.len();
            let d = NOTE_HEADER_BYTES + idx * ITEM_DESCRIPTOR_BYTES;
            if d + 8 > rec.len() {
                continue;
            }
            let declared = u16::from_le_bytes([rec[d + 4], rec[d + 5]]) as usize;
            let ns = n.header.non_summary_data_size as usize;
            tested += 1;
            if ns == 0 {
                nonsummary_zero += 1;
            } else if declared + 68 == ns {
                exact += 1;
            } else {
                other += 1;
                if examples < 6 {
                    examples += 1;
                    eprintln!(
                        "   note 0x{:08X} declared {declared} nonsummary {ns} diff {}",
                        n.rrv_identifier,
                        ns as i64 - declared as i64
                    );
                }
            }
        }
        eprintln!(
            "OVERFLOW HYPOTHESIS: {tested} incomplete notes; {exact} match declared+68==nonsummary; {nonsummary_zero} have no non-summary object; {other} neither"
        );
    }

    /// What KIND of field is going unread? If they are the rich-text and
    /// attachment fields, their values legitimately live in the note's
    /// non-summary object, which this tool already reads separately - and
    /// the coverage warning would be alarming about something covered.
    #[test]
    #[ignore = "diagnostic"]
    fn diagnose_unreached_field_kinds() {
        let path = std::path::PathBuf::from(r"C:\SherlockForensics")
            .join(".scratch")
            .join("nsf-samples")
            .join("real-nsf")
            .join("fakenames.nsf");
        if !path.is_file() {
            return;
        }
        let bytes = std::fs::read(&path).expect("read");
        let db = crate::Database::open(&bytes).expect("open");
        let en = db.enumerate_notes().expect("enumerate");
        let bdb = db.bucket_descriptor_block().expect("bdb").expect("bdb");
        let mut by_kind: std::collections::BTreeMap<String, usize> = Default::default();
        let mut by_name: std::collections::BTreeMap<String, usize> = Default::default();
        for n in &en.notes {
            let w = db.note_items_walk(n);
            for id in &w.unreached_name_ids {
                let kind = bdb.field_kind(*id);
                *by_kind.entry(format!("{:?}", kind)).or_default() += 1;
                let name = bdb
                    .unk_names
                    .get(*id as usize)
                    .cloned()
                    .unwrap_or_else(|| format!("0x{id:04X}"));
                *by_name.entry(name).or_default() += 1;
            }
        }
        eprintln!("UNREACHED BY KIND:");
        for (k, n) in &by_kind {
            eprintln!("   {k:<16} {n}");
        }
        eprintln!("UNREACHED BY NAME (top):");
        let mut v: Vec<_> = by_name.into_iter().collect();
        v.sort_by(|a, b| b.1.cmp(&a.1));
        for (name, n) in v.into_iter().take(12) {
            eprintln!("   {name:<28} {n}");
        }
    }

    /// Compare the item table of a note that walks cleanly with one that
    /// stops immediately, to see what actually differs.
    #[test]
    #[ignore = "diagnostic"]
    fn diagnose_incomplete_item_tables() {
        let path = std::path::PathBuf::from(r"C:\SherlockForensics")
            .join(".scratch")
            .join("nsf-samples")
            .join("real-nsf")
            .join("fakenames.nsf");
        if !path.is_file() {
            return;
        }
        let bytes = std::fs::read(&path).expect("read");
        let db = crate::Database::open(&bytes).expect("open");
        let en = db.enumerate_notes().expect("enumerate");
        let mut good = 0usize;
        let mut bad = 0usize;
        for n in &en.notes {
            let w = db.note_items_walk(n);
            let show = if w.incomplete() && bad < 2 {
                bad += 1;
                true
            } else if !w.incomplete() && w.claimed > 5 && good < 2 {
                good += 1;
                true
            } else {
                false
            };
            if !show {
                continue;
            }
            let start = n.file_offset as usize;
            let end = (start + n.header.size as usize).min(bytes.len());
            let rec = &bytes[start..end];
            eprintln!(
                "{} note 0x{:08X} class 0x{:04X} size {} claimed {} recovered {} nonsummary {}",
                if w.incomplete() { "BAD " } else { "GOOD" },
                n.rrv_identifier,
                n.header.note_class,
                n.header.size,
                w.claimed,
                w.items.len(),
                n.header.non_summary_data_size
            );
            for k in 0..6usize {
                let d = NOTE_HEADER_BYTES + k * ITEM_DESCRIPTOR_BYTES;
                if d + 8 > rec.len() {
                    break;
                }
                eprintln!(
                    "     desc[{k}] name 0x{:04X} type 0x{:04X} size {:6} tail 0x{:04X}",
                    u16::from_le_bytes([rec[d], rec[d + 1]]),
                    u16::from_le_bytes([rec[d + 2], rec[d + 3]]),
                    u16::from_le_bytes([rec[d + 4], rec[d + 5]]),
                    u16::from_le_bytes([rec[d + 6], rec[d + 7]]),
                );
            }
        }
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

#[cfg(test)]
mod unreached_classification_tests {
    use super::*;

    #[test]
    fn a_placeholder_stores_no_value_and_that_is_expected() {
        let r = UnreachedReason::classify(ITEM_PLACEHOLDER);
        assert_eq!(r, UnreachedReason::NoValueStored);
        assert!(r.is_expected(), "a placeholder is not a coverage gap");
    }

    #[test]
    fn a_non_summary_item_keeps_its_value_elsewhere_and_that_is_expected() {
        let r = UnreachedReason::classify(0x0009);
        assert_eq!(r, UnreachedReason::ValueInNonSummary);
        assert!(r.is_expected());
    }

    /// The only case that means recoverable data went unrecovered. If this
    /// ever starts reading as expected, the tool stops reporting a real gap.
    #[test]
    fn a_summary_item_that_is_missing_is_unexplained_and_is_not_expected() {
        let r = UnreachedReason::classify(ITEM_SUMMARY);
        assert_eq!(r, UnreachedReason::Unexplained);
        assert!(!r.is_expected(), "this one must keep its warning");
    }

    /// Placeholder wins over the summary bit: an item that stores nothing has
    /// no value wherever its other flags point.
    #[test]
    fn placeholder_takes_precedence_over_the_summary_bit() {
        assert_eq!(
            UnreachedReason::classify(ITEM_PLACEHOLDER | ITEM_SUMMARY),
            UnreachedReason::NoValueStored
        );
    }
}

#[cfg(test)]
mod unreached_corpus_tests {
    use super::*;

    /// The measurement behind the correction, pinned so it cannot drift back.
    ///
    /// Before this classification the tool reported every unreached item as a
    /// field that went unread, implying evidence might have been missed. Most
    /// of them are items that by definition have no value in the record. The
    /// assertion is deliberately a proportion rather than exact counts: the
    /// claim being defended is "the majority are expected", not a number that
    /// would have to be re-baselined whenever the corpus changes.
    #[test]
    fn most_unreached_items_are_expected_absences_not_coverage_gaps() {
        let path = std::path::PathBuf::from(r"C:\SherlockForensics")
            .join(".scratch")
            .join("nsf-samples")
            .join("real-nsf")
            .join("fakenames.nsf");
        if !path.is_file() {
            eprintln!("corpus not present; skipping");
            return;
        }
        let bytes = std::fs::read(&path).expect("read");
        let db = crate::Database::open(&bytes).expect("open");
        let en = db.enumerate_notes().expect("enumerate");

        let (mut expected, mut unexplained) = (0usize, 0usize);
        for n in &en.notes {
            for u in db.note_items_walk(n).unreached {
                if u.reason.is_expected() {
                    expected += 1;
                } else {
                    unexplained += 1;
                }
            }
        }
        let total = expected + unexplained;
        assert!(total > 1_000, "corpus should have plenty to classify: {total}");
        assert!(
            expected > unexplained,
            "the majority must be expected absences: {expected} expected vs {unexplained} unexplained"
        );
        // And the real gap must not be classified out of existence - the
        // point of the correction is to make it visible, not to hide it.
        assert!(
            unexplained > 0,
            "a genuine unexplained remainder still exists and must keep its warning"
        );
        eprintln!("unreached: {expected} expected, {unexplained} unexplained, {total} total");
    }
}
