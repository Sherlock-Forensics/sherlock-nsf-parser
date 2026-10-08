//! Note item parsing - the fields inside a note record.
//!
//! A note record is: the 100-byte note header, then `number_of_note_items`
//! fixed 8-byte item descriptors, then the values of the SUMMARY items
//! (`ITEM_SUMMARY` set) packed back to back in descriptor order. A
//! non-summary item's value lives in the non-summary object and takes no
//! space here. Reverse-engineered from the fakenames Person docs
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
//! Each summary item's value is `value_size` bytes, taken sequentially from
//! the value region that begins right after the descriptor table at
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

/// Item data kind, derived from the field's `(item_class, item_type)` bytes
/// in the BDB Unique Name Key table. Resolve via
/// [`crate::BucketDescriptorBlock::field_kind`]. That is the field's kind as
/// the database first met it; a value that carries its own type word says
/// what it actually is, and [`NoteItem::effective_kind`] lets that win.
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
    /// NOCOMPUTE / TYPE_NOTEREF_LIST: a count, then 16-byte UNIDs ($REF,
    /// $Orig).
    NoteRefList,
    /// NOCOMPUTE / TYPE_NOTELINK_LIST: a count, then 40-byte doc links
    /// ($Links).
    NoteLinkList,
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
            FieldKind::NoteRefList => "Note reference list",
            FieldKind::NoteLinkList => "Doc link list",
            FieldKind::Unknown => "Unknown",
        }
    }

    /// The kind a Notes data-type word names, for the words seen on disk.
    fn from_type_word(w: u16) -> Option<Self> {
        Some(match w {
            0x0001 => FieldKind::RichText,
            0x0003 => FieldKind::Object,
            0x0004 => FieldKind::NoteRefList,
            0x0007 => FieldKind::NoteLinkList,
            0x0300 => FieldKind::Number,
            0x0301 => FieldKind::NumberRange,
            0x0400 => FieldKind::Time,
            0x0401 => FieldKind::TimeRange,
            0x0500 => FieldKind::Text,
            0x0501 => FieldKind::TextList,
            0x0600 | 0x0601 => FieldKind::Formula,
            _ => return None,
        })
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
            0x04 => FieldKind::NoteRefList,
            0x07 => FieldKind::NoteLinkList,
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
    /// The value's own data-type word, when it carries one.
    ///
    /// Item flag bit [`ITEM_NO_TYPE_WORD`] decides it. Clear, and the value
    /// opens with its 2-byte Notes type (TYPE_TEXT_LIST 0x0501, TYPE_TIME_RANGE
    /// 0x0401, ...); set, and the value is bare data of the field's kind.
    /// Measured over the corpus: 92.5% of 204,401 bit-clear values open with
    /// a known type word, against 1.3% of 969,400 bit-set ones, which is
    /// coincidence. A Notes 4 customer's recipient fields were the visible
    /// case: SendTo flagged 0x0045 opened `01 05` and rendered as bytes,
    /// SendTo flagged 0x004D in another note was plain text and rendered
    /// fine.
    pub fn type_word(&self) -> Option<u16> {
        if self.type_flags & ITEM_NO_TYPE_WORD != 0 {
            return None;
        }
        let w = u16::from_le_bytes([*self.value.first()?, *self.value.get(1)?]);
        FieldKind::from_type_word(w).map(|_| w)
    }

    /// The value with its type word, if any, removed: the data itself.
    pub fn data(&self) -> &'a [u8] {
        if self.type_word().is_some() {
            &self.value[2..]
        } else {
            self.value
        }
    }

    /// The kind to decode this value as: its own type word when it has one,
    /// otherwise the field's kind from the name table.
    pub fn effective_kind(&self, field: FieldKind) -> FieldKind {
        self.type_word()
            .and_then(FieldKind::from_type_word)
            .unwrap_or(field)
    }

    /// The same item viewed as its data alone, so every decoder below reads
    /// the same bytes whether or not the value carried a type word.
    fn bare(&self) -> NoteItem<'a> {
        NoteItem {
            name_id: self.name_id,
            type_flags: self.type_flags | ITEM_NO_TYPE_WORD,
            value: self.data(),
        }
    }

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
        let v = self.data();
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
    ///
    /// Tabs and line breaks are kept: a stored header block such as
    /// `$AdditionalHeaders` is many lines, and dotting its CR/LF out both
    /// hid it as "binary" and ran its headers together.
    pub fn as_text(&self) -> String {
        self.data()
            .iter()
            .map(|&b| match b {
                0x20..=0x7E | b'\t' | b'\r' | b'\n' => b as char,
                _ => '.',
            })
            .collect()
    }

    /// True if the value is entirely printable ASCII, tabs and line breaks
    /// (a clean text field).
    pub fn is_printable_text(&self) -> bool {
        let v = self.data();
        !v.is_empty()
            && v.iter()
                .all(|&b| (0x20..0x7f).contains(&b) || matches!(b, b'\t' | b'\r' | b'\n'))
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
        if self.type_word().is_some() {
            return self.bare().display_value();
        }
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
        // A value that names its own type is decoded as that type, from the
        // bytes after the word.
        if self.type_word().is_some() {
            return self.bare().render(self.effective_kind(kind));
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
                } else if let Some(t) = self.as_multiline_text() {
                    t
                } else {
                    hex_summary(self.value)
                }
            }
            FieldKind::NumberRange if self.as_range(fmt_number).is_some() => {
                self.as_range(fmt_number).unwrap_or_default()
            }
            FieldKind::TimeRange if self.as_range(fmt_time).is_some() => {
                self.as_range(fmt_time).unwrap_or_default()
            }
            FieldKind::NoteRefList => self
                .as_note_refs()
                .map(|r| r.join("; "))
                .unwrap_or_else(|| hex_summary(self.value)),
            FieldKind::NoteLinkList => self
                .as_note_links()
                .map(|r| r.join("; "))
                .unwrap_or_else(|| hex_summary(self.value)),
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

    /// Decode a Notes RANGE value (TIME_RANGE, NUMBER_RANGE): a `u16` count
    /// of single entries and a `u16` count of pairs, then the singles, then
    /// the pairs, each entry 8 bytes. Pairs render as `a - b`; everything is
    /// joined with `; `. `None` unless the counts account for the value
    /// exactly, as with [`Self::as_text_list`].
    ///
    /// The customer's RouteTimes values are the shape: `00 00 02 00` (no
    /// singles, two pairs) then four TIMEDATEs, 36 bytes.
    pub fn as_range(&self, entry: fn(&[u8]) -> String) -> Option<String> {
        let v = self.data();
        let singles = u16::from_le_bytes([*v.first()?, *v.get(1)?]) as usize;
        let pairs = u16::from_le_bytes([*v.get(2)?, *v.get(3)?]) as usize;
        if singles + pairs == 0 || 4 + singles * 8 + pairs * 16 != v.len() {
            return None;
        }
        let mut out: Vec<String> = Vec::with_capacity(singles + pairs);
        let body = &v[4..];
        for k in 0..singles {
            out.push(entry(&body[k * 8..k * 8 + 8]));
        }
        let pair_base = singles * 8;
        for k in 0..pairs {
            let o = pair_base + k * 16;
            out.push(format!("{} - {}", entry(&body[o..o + 8]), entry(&body[o + 8..o + 16])));
        }
        Some(out.join("; "))
    }

    /// Text whose line breaks are stored as NUL bytes, the way a Notes text
    /// item separates lines. A customer's `$AdditionalHeaders` - a stored
    /// header block - still rendered as hex after CR/LF was allowed, and NUL
    /// line separators are the remaining non-printable byte a header block
    /// would hold. A value qualifies when at least 90% of it is printable or
    /// a line break, it holds a line of text, and it does not open with a
    /// NUL; any other control byte (an LMBCS character-set prefix, say)
    /// renders as `.` rather than sending the whole value to hex. Binary
    /// values sit nowhere near 90% printable.
    pub fn as_multiline_text(&self) -> Option<String> {
        let v = self.data();
        let printable = v.iter().filter(|&&b| (0x20..0x7f).contains(&b)).count();
        let texty = v
            .iter()
            .filter(|&&b| (0x20..0x7f).contains(&b) || matches!(b, 0 | b'\t' | b'\r' | b'\n'))
            .count();
        if printable < 8 || texty * 10 < v.len() * 9 || v.first() == Some(&0) {
            return None;
        }
        let text: String = v
            .iter()
            .map(|&b| match b {
                0 => '\n',
                0x20..=0x7E | b'\t' | b'\r' | b'\n' => b as char,
                _ => '.',
            })
            .collect();
        Some(text.trim_end_matches('\n').to_string())
    }

    /// Decode a TYPE_NOTELINK_LIST value (`$Links`): a `u16` count, then
    /// 40-byte doc links - replica ID (8 bytes), view UNID (16), note UNID
    /// (16) - rendered in the byte order the viewer prints UNIDs. `None`
    /// unless the count accounts for the value exactly. A customer's
    /// `$Links` was count 4 and 162 bytes, which is 2 + 4 * 40.
    pub fn as_note_links(&self) -> Option<Vec<String>> {
        let v = self.data();
        let count = u16::from_le_bytes([*v.first()?, *v.get(1)?]) as usize;
        if count == 0 || 2 + count * 40 != v.len() {
            return None;
        }
        let hex = |b: &[u8]| b.iter().map(|x| format!("{x:02X}")).collect::<String>();
        Some(
            v[2..]
                .chunks_exact(40)
                .map(|l| format!("replica {} view {} note {}", hex(&l[..8]), hex(&l[8..24]), hex(&l[24..])))
                .collect(),
        )
    }

    /// Decode a `$FILE` item's value: the descriptor of a file attachment,
    /// whose bytes live in a separate object (see
    /// [`crate::Database::file_attachment`]).
    ///
    /// Layout per the MIT-licensed nsf2pst reader, the same for Notes 4 and
    /// later: object type u16 (0 = file), object RRV u32, name length u16,
    /// host u16, compression u16 (0 none, 1 Huffman, 2 LZ1), attributes
    /// u16, flags u16, file size u32, created and modified TIMEDATEs, then
    /// the name at byte 36. `None` unless the name fits inside the value.
    pub fn as_file_object(&self) -> Option<FileObject> {
        let v = self.data();
        let u16_at = |o: usize| Some(u16::from_le_bytes([*v.get(o)?, *v.get(o + 1)?]));
        let u32_at = |o: usize| Some(u32::from_le_bytes(v.get(o..o + 4)?.try_into().ok()?));
        if u16_at(0)? != 0 {
            return None;
        }
        let name_len = u16_at(6)? as usize;
        let name = v.get(36..36 + name_len)?;
        Some(FileObject {
            object_rrv: u32_at(2)?,
            compression: u16_at(10)?,
            size: u32_at(16)?,
            created: Timedate::from_bytes(v.get(20..28)?).ok(),
            modified: Timedate::from_bytes(v.get(28..36)?).ok(),
            name: String::from_utf8_lossy(name).into_owned(),
            encrypted: self.type_flags & ITEM_SEAL != 0,
        })
    }

    /// Decode a TYPE_NOTEREF_LIST value: a `u16` count, then that many
    /// 16-byte UNIDs, rendered in the same byte order the viewer prints a
    /// note's own UNID. `None` unless the count accounts for the value
    /// exactly. A customer's $Orig was `01 00` and then exactly the UNID the
    /// viewer showed for that note.
    pub fn as_note_refs(&self) -> Option<Vec<String>> {
        let v = self.data();
        let count = u16::from_le_bytes([*v.first()?, *v.get(1)?]) as usize;
        if count == 0 || 2 + count * 16 != v.len() {
            return None;
        }
        Some(
            v[2..]
                .chunks_exact(16)
                .map(|u| u.iter().map(|b| format!("{b:02X}")).collect())
                .collect(),
        )
    }
}

/// A `$FILE` item: one file attachment's descriptor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileObject {
    /// RRV identifier of the object holding the file's bytes.
    pub object_rrv: u32,
    /// 0 none, 1 Huffman, 2 LZ1.
    pub compression: u16,
    /// The file's size once decompressed.
    pub size: u32,
    /// File creation time as recorded at attach time.
    pub created: Option<Timedate>,
    /// File modification time as recorded at attach time.
    pub modified: Option<Timedate>,
    /// File name as attached.
    pub name: String,
    /// The item is sealed ([`ITEM_SEAL`]): the object holds the file
    /// encrypted to the recipients' Notes IDs, and the descriptor alone is
    /// readable.
    pub encrypted: bool,
}

/// One TIMEDATE as ISO 8601, or its hex when it is not a clock value (an
/// all-zero entry, for instance, which some list items carry as a slot).
fn fmt_time(b: &[u8]) -> String {
    // An all-zero entry is an unset slot - most $Revisions values open with
    // one - and is said to be empty rather than printed as eight zero bytes
    // that read like a decoding failure.
    if b.iter().all(|&x| x == 0) {
        return "(empty)".to_string();
    }
    Timedate::from_bytes(b)
        .ok()
        .and_then(|t| t.as_clock())
        .map(|c| c.to_iso_8601())
        .unwrap_or_else(|| hex_summary(b))
}

/// One IEEE-754 double, as an integer when it is one.
fn fmt_number(b: &[u8]) -> String {
    let f = f64::from_le_bytes(b.try_into().unwrap_or([0; 8]));
    if f.is_finite() && f.fract() == 0.0 && f.abs() < 1e15 {
        format!("{}", f as i64)
    } else {
        format!("{f}")
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
    /// A summary item's declared value size runs past the end of the record.
    /// Since the walk stopped charging non-summary items against the record
    /// (0.1.18), 210 of 51,913 corpus notes stop this way, down from 10,421,
    /// and 696 summary items go unreached, down from 38,385. Where those
    /// last values live is not known, and guessing would be worse than
    /// saying so.
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
    walk_items_at(record, number_of_note_items, NOTE_HEADER_BYTES, None)
}

/// Sum of the declared sizes of the non-summary items, read from the
/// descriptor table at `header_len`. `None` when the table does not fit.
pub fn non_summary_total(record: &[u8], number_of_note_items: u16, header_len: usize) -> Option<usize> {
    let count = number_of_note_items as usize;
    record.get(..header_len + count * ITEM_DESCRIPTOR_BYTES)?;
    Some(
        (0..count)
            .map(|i| header_len + i * ITEM_DESCRIPTOR_BYTES)
            .filter(|&d| u16::from_le_bytes([record[d + 2], record[d + 3]]) & ITEM_SUMMARY == 0)
            .map(|d| u16::from_le_bytes([record[d + 4], record[d + 5]]) as usize)
            .sum(),
    )
}

/// The general walk: an item table starting at `header_len`, and optionally
/// the note's non-summary data as bare item values.
///
/// `non_summary`, when given, must hold exactly the non-summary items'
/// values in descriptor order - the caller checks that the sizes add up
/// (see [`non_summary_total`]) - and those items then get their values from
/// it instead of being reported as stored elsewhere. That is the pre-Notes 5
/// layout; a modern non-summary object has a header and is not passed here.
pub fn walk_items_at<'a>(
    record: &'a [u8],
    number_of_note_items: u16,
    header_len: usize,
    non_summary: Option<&'a [u8]>,
) -> ItemWalk<'a> {
    let count = number_of_note_items as usize;
    let table_end = header_len + count * ITEM_DESCRIPTOR_BYTES;
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
    let mut unreached_name_ids = Vec::new();
    let mut unreached = Vec::new();
    let mut cursor = table_end;
    let mut ns_cursor = 0usize;
    let mut stop = ItemWalkStop::Complete;
    for i in 0..count {
        let d = header_len + i * ITEM_DESCRIPTOR_BYTES;
        let name_id = u16::from_le_bytes([record[d], record[d + 1]]);
        let type_flags = u16::from_le_bytes([record[d + 2], record[d + 3]]);
        let value_size = u16::from_le_bytes([record[d + 4], record[d + 5]]) as usize;
        // Only summary items keep their value in the record. A non-summary
        // item's value lives in the non-summary object, so it takes no space
        // here, and charging its size against the record shifts every later
        // value onto the wrong bytes. Measured on the corpus: of 15,642
        // summary TEXT_LIST values that follow a non-summary item, 345 decode
        // exactly when every item is charged and 14,263 when only summary
        // items are. A TEXT_LIST only decodes when its internal lengths
        // account for the bytes exactly, so that is not a judgement call.
        let in_record = type_flags & ITEM_SUMMARY != 0;
        let value = if !in_record {
            let v = non_summary.and_then(|ns| ns.get(ns_cursor..ns_cursor + value_size));
            if v.is_some() {
                ns_cursor += value_size;
            }
            v
        } else if stop != ItemWalkStop::Complete {
            None
        } else if let Some(v) = record.get(cursor..cursor + value_size) {
            cursor += value_size;
            Some(v)
        } else {
            stop = ItemWalkStop::ValueOverrunsRecord {
                index: i,
                declared_size: value_size,
                remaining: record.len().saturating_sub(cursor),
            };
            None
        };
        match value {
            Some(value) => items.push(NoteItem {
                name_id,
                type_flags,
                value,
            }),
            None => {
                unreached_name_ids.push(name_id);
                unreached.push(UnreachedItem {
                    name_id,
                    flags: type_flags,
                    reason: UnreachedReason::classify(type_flags),
                });
            }
        }
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

/// Field flag: the value is sealed (encrypted). On a `$FILE` the
/// descriptor stays in the clear and the object it names is encrypted.
pub const ITEM_SEAL: u16 = 0x0002;

/// Field flag: the value is bare data of the field's kind. When clear, the
/// value opens with its own 2-byte data-type word. See
/// [`NoteItem::type_word`] for the measurement this rests on.
pub const ITEM_NO_TYPE_WORD: u16 = 0x0008;

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

    /// The shape that misread a fifth of the corpus and nearly every Notes 4
    /// mail note: a body item (non-summary, its value elsewhere) declared
    /// before the summary fields. Its size must not be charged against the
    /// record, or every later field reads the wrong bytes.
    #[test]
    fn a_non_summary_item_takes_no_space_in_the_record() {
        let mut rec = vec![0u8; NOTE_HEADER_BYTES];
        for (id, flags, size) in [(0x7Eu16, 0x0002u16, 7219u16), (0x67, 0x0004, 5), (0x6B, 0x0004, 3)] {
            rec.extend_from_slice(&id.to_le_bytes());
            rec.extend_from_slice(&flags.to_le_bytes());
            rec.extend_from_slice(&size.to_le_bytes());
            rec.extend_from_slice(&0u16.to_le_bytes());
        }
        rec.extend_from_slice(b"Hello");
        rec.extend_from_slice(b"Ed!");
        let w = walk_items(&rec, 3);
        assert_eq!(w.stop, ItemWalkStop::Complete);
        let got: Vec<_> = w.items.iter().map(|i| (i.name_id, i.as_text())).collect();
        assert_eq!(got, vec![(0x67, "Hello".to_string()), (0x6B, "Ed!".to_string())]);
        assert_eq!(w.unreached.len(), 1);
        assert_eq!(w.unreached[0].name_id, 0x7E);
        assert_eq!(w.unreached[0].reason, UnreachedReason::ValueInNonSummary);
    }
}

/// Values shaped like the ones a Notes 4 customer sent from their own
/// mailbox (same flags, same layouts; names replaced).
#[cfg(test)]
mod typed_value_tests {
    use super::*;

    fn item(flags: u16, value: &[u8]) -> NoteItem<'_> {
        NoteItem { name_id: 0x67, type_flags: flags, value }
    }

    fn text_list(type_word: bool, names: &[&str]) -> Vec<u8> {
        let mut v = Vec::new();
        if type_word {
            v.extend_from_slice(&0x0501u16.to_le_bytes());
        }
        v.extend_from_slice(&(names.len() as u16).to_le_bytes());
        for n in names {
            v.extend_from_slice(&(n.len() as u16).to_le_bytes());
        }
        for n in names {
            v.extend_from_slice(n.as_bytes());
        }
        v
    }

    fn file_value(name: &str) -> Vec<u8> {
        let mut v = vec![0u8; 36];
        v[2..6].copy_from_slice(&52654u32.to_le_bytes());
        v[6..8].copy_from_slice(&(name.len() as u16).to_le_bytes());
        v[10..12].copy_from_slice(&1u16.to_le_bytes());
        v[16..20].copy_from_slice(&5131u32.to_le_bytes());
        v.extend_from_slice(name.as_bytes());
        v
    }

    /// A sealed `$FILE` keeps its descriptor readable; only the object is
    /// encrypted. The flag is what lets a failure say so.
    #[test]
    fn a_sealed_file_item_is_marked_encrypted() {
        let v = file_value("Budget.xls");
        let plain = item(ITEM_NO_TYPE_WORD, &v).as_file_object().expect("descriptor");
        assert!(!plain.encrypted);
        assert_eq!((plain.object_rrv, plain.size, plain.name.as_str()), (52654, 5131, "Budget.xls"));
        let sealed = item(ITEM_NO_TYPE_WORD | ITEM_SEAL, &v).as_file_object().expect("descriptor");
        assert!(sealed.encrypted);
        assert_eq!(sealed.name, "Budget.xls");
    }

    /// SendTo flagged 0x0045 opens with TYPE_TEXT_LIST although the field
    /// table calls SendTo Text. The value's own word has to win, or a
    /// multi-recipient field renders as bytes.
    #[test]
    fn a_value_that_names_its_type_is_decoded_as_that_type() {
        let v = text_list(true, &["CN=Ann Example/O=ACME@ACME", "CN=Bob Sample/O=ACME@ACME"]);
        let it = item(0x0045, &v);
        assert_eq!(it.type_word(), Some(0x0501));
        assert_eq!(it.effective_kind(FieldKind::Text), FieldKind::TextList);
        assert_eq!(
            it.render(FieldKind::Text),
            "CN=Ann Example/O=ACME@ACME; CN=Bob Sample/O=ACME@ACME"
        );
        assert_eq!(it.as_text_list().unwrap().len(), 2);
    }

    /// The same field flagged 0x004D is bare text, and a value that happens
    /// to start like a type word must not be cut when the flag says there is
    /// none.
    #[test]
    fn bit_0x0008_means_bare_data() {
        let it = item(0x004D, b"ALL_STAFF");
        assert_eq!(it.type_word(), None);
        assert_eq!(it.render(FieldKind::Text), "ALL_STAFF");
        let lookalike = [0x01, 0x05, b'x', b'y'];
        assert_eq!(item(0x000C, &lookalike).data(), &lookalike[..]);
        let plain = text_list(false, &["one", "two"]);
        assert_eq!(item(0x000C, &plain).render(FieldKind::TextList), "one; two");
    }

    #[test]
    fn time_ranges_decode_singles_and_pairs() {
        let t1 = [0x30, 0xF8, 0x7C, 0x00, 0x2B, 0x6D, 0x25, 0x4A];
        let t2 = [0xE0, 0x16, 0x81, 0x00, 0x2B, 0x6D, 0x25, 0x4A];
        // TimeRange, flagged 0x0004: type word, no singles, one pair.
        let mut v = 0x0401u16.to_le_bytes().to_vec();
        v.extend_from_slice(&[0, 0, 1, 0]);
        v.extend_from_slice(&t1);
        v.extend_from_slice(&t2);
        let r = item(0x0004, &v).render(FieldKind::Time);
        assert!(r.starts_with("2003-") && r.contains(" - 2003-"), "{r}");
        // RouteTimes, flagged 0x0008: bare, two pairs.
        let mut v = vec![0, 0, 2, 0];
        for t in [t1, t2, t1, t2] {
            v.extend_from_slice(&t);
        }
        let r = item(0x0008, &v).render(FieldKind::TimeRange);
        assert_eq!(r.matches(" - ").count(), 2, "{r}");
        assert_eq!(r.matches("; ").count(), 1, "{r}");
        // Counts that do not fit fall back rather than misread.
        assert!(item(0x0008, &v[..30]).as_range(fmt_time).is_none());
    }

    #[test]
    fn a_note_reference_list_is_its_unids() {
        let mut v = vec![1, 0];
        v.extend_from_slice(&[0x80, 0x37, 0x2C, 0x0A, 0x9F, 0x01, 0x25, 0xE7]);
        v.extend_from_slice(&[0x58, 0x10, 0x0E, 0x00, 0x26, 0x6D, 0x25, 0x4A]);
        assert_eq!(field_kind(0x00, 0x04), FieldKind::NoteRefList);
        assert_eq!(
            item(0x000C, &v).render(FieldKind::NoteRefList),
            "80372C0A9F0125E758100E00266D254A"
        );
    }

    /// A stored header block is text with line breaks, and must render as
    /// text rather than as "binary".
    #[test]
    fn multi_line_text_stays_text() {
        let v = b"Received: from a.example ([192.0.2.1])\r\n by b.example; Tue, 3 Jun 2003\r\nX-Mailer: test\r\n";
        let it = item(0x0008, v);
        assert!(it.is_printable_text());
        let r = it.render(FieldKind::Text);
        assert!(r.contains("Received: from a.example") && r.contains("\r\nX-Mailer: test"), "{r}");
    }

    /// Notes separates the lines of a text item with NUL. A header block
    /// stored that way is text, one header per line.
    #[test]
    fn nul_separated_lines_are_text() {
        let v = b"Received: from a.example by b.example\0X-Mailer: test\0";
        let r = item(0x0008, v).render(FieldKind::Text);
        assert_eq!(r, "Received: from a.example by b.example\nX-Mailer: test");
        // Binary with a few zeros is not mistaken for it.
        assert!(item(0x0008, &[0, 1, 2, 0, 9]).as_multiline_text().is_none());
    }

    #[test]
    fn a_doc_link_list_is_its_links() {
        let mut v = vec![1, 0];
        v.extend_from_slice(&[0x11; 8]);
        v.extend_from_slice(&[0x22; 16]);
        v.extend_from_slice(&[0x33; 16]);
        assert_eq!(field_kind(0x00, 0x07), FieldKind::NoteLinkList);
        let r = item(0x0008, &v).render(FieldKind::NoteLinkList);
        assert_eq!(
            r,
            format!("replica {} view {} note {}", "11".repeat(8), "22".repeat(16), "33".repeat(16))
        );
        assert!(item(0x0008, &v[..41]).as_note_links().is_none());
    }

    /// Most $Revisions values hold one all-zero entry. It is an empty slot,
    /// and says so rather than printing as bytes.
    #[test]
    fn an_all_zero_date_is_empty() {
        let v = [1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        assert_eq!(item(0x000C, &v).render(FieldKind::TimeRange), "(empty)");
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
/// Resolved (0.1.18): every attempt above assumed the walk charged ALL
/// items against the record. Only summary items are stored there; charging
/// a non-summary item's size shifted every later value and produced the
/// overrun these diagnostics were chasing. The TEXT_LIST oracle settles it:
/// 14,263 of 15,642 summary lists after a non-summary item decode under the
/// summary-only walk, 345 under the old one. The diagnostics below still
/// use the old arithmetic and are kept as the record of what was tried.
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

    /// Bare values, flagged as such (summary, no type word), the way the
    /// corpus values these tests mirror are stored.
    fn item(value: &[u8]) -> NoteItem<'_> {
        NoteItem { name_id: 0, type_flags: ITEM_SUMMARY | ITEM_NO_TYPE_WORD, value }
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
