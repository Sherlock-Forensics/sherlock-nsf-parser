//! Note record parsing.
//!
//! A note is the unit of user-visible data inside an NSF database -
//! emails, calendar entries, contacts, design notes, the ACL, etc. all
//! live as notes distinguished by `note_class`.
//!
//! Note header layout per `libnsfdb/nsfdb_note.h` (100 bytes):
//!
//! ```text
//! offset  width  field
//!     0      2   signature (0x0004)
//!     2      4   size
//!     6      4   rrv_identifier
//!    10      8   file_identifier (TIMEDATE-shaped opaque)
//!    18      8   note_identifier (TIMEDATE-shaped opaque - half of UNID)
//!    26      4   sequence_number
//!    30      8   sequence_time (TIMEDATE)
//!    38      2   status_flags
//!    40      2   note_class
//!    42      8   modification_time (TIMEDATE)
//!    50      2   number_of_note_items
//!    52      2   unknown1
//!    54      2   number_of_responses
//!    56      4   non_summary_data_identifier
//!    60      4   non_summary_data_size
//!    64      8   access_time (TIMEDATE)
//!    72      8   creation_time (TIMEDATE)
//!    80      4   parent_note_identifier
//!    84      2   unknown3
//!    86      4   folder_reference_count
//!    90      4   unknown4
//!    94      4   folder_note_identifier
//!    98      2   unknown5
//! ```
//!
//! Note class catalogue (bit flags; a note can carry multiple class
//! bits but in practice each note is one class):
//!
//! ```text
//! NOTE_CLASS_DOCUMENT    0x0001  // user-visible documents (mail, etc)
//! NOTE_CLASS_INFO        0x0002  // database info note
//! NOTE_CLASS_FORM        0x0004  // form design
//! NOTE_CLASS_VIEW        0x0008  // view design
//! NOTE_CLASS_ICON        0x0010  // database icon
//! NOTE_CLASS_DESIGN      0x0020  // design collection
//! NOTE_CLASS_ACL         0x0040  // access control list
//! NOTE_CLASS_HELP_INDEX  0x0080
//! NOTE_CLASS_HELP        0x0100
//! NOTE_CLASS_FILTER      0x0200  // agent / mail rule
//! NOTE_CLASS_FIELD       0x0400  // shared field
//! NOTE_CLASS_REPLFORMULA 0x0800
//! NOTE_CLASS_PRIVATE     0x1000
//! ```

use crate::error::NsfError;
use crate::time::Timedate;

/// Magic two bytes at offset 0 of every note header.
pub const NOTE_SIGNATURE: [u8; 2] = [0x04, 0x00];
/// Note header size in bytes.
pub const NOTE_HEADER_BYTES: usize = 100;

/// Note class flag values. A note's `note_class` is typically one of
/// these; multi-bit values are uncommon in practice.
#[allow(missing_docs)]
pub mod class {
    pub const DOCUMENT: u16 = 0x0001;
    pub const INFO: u16 = 0x0002;
    pub const FORM: u16 = 0x0004;
    pub const VIEW: u16 = 0x0008;
    pub const ICON: u16 = 0x0010;
    pub const DESIGN: u16 = 0x0020;
    pub const ACL: u16 = 0x0040;
    pub const HELP_INDEX: u16 = 0x0080;
    pub const HELP: u16 = 0x0100;
    pub const FILTER: u16 = 0x0200;
    pub const FIELD: u16 = 0x0400;
    pub const REPLFORMULA: u16 = 0x0800;
    pub const PRIVATE: u16 = 0x1000;
}

/// Parsed note header. Self-contained snapshot - the reader does not
/// retain a reference into bucket bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NoteHeader {
    /// Total note size in bytes (header + item descriptors + item data).
    pub size: u32,
    /// RRV identifier the note was reached through. Local to one NSF.
    pub rrv_identifier: u32,
    /// File identifier portion of the UNID (8 bytes).
    pub file_identifier: Timedate,
    /// Note identifier portion of the UNID (8 bytes). Together with
    /// `file_identifier` this forms the 16-byte Universal Note ID
    /// (UNID) which is globally unique across replicas.
    pub note_identifier: Timedate,
    /// Replication-sequence number. Increments on every modification.
    pub sequence_number: u32,
    /// Replication-sequence time.
    pub sequence_time: Timedate,
    /// Status flags word.
    pub status_flags: u16,
    /// Note class (DOCUMENT / FORM / VIEW / ACL / etc). See [`class`]
    /// constants.
    pub note_class: u16,
    /// Most recent modification time. Operator-facing "when was this
    /// note last touched".
    pub modification_time: Timedate,
    /// Number of items (fields) attached to this note. Each item has
    /// its own descriptor block immediately after the note header.
    pub number_of_note_items: u16,
    /// Number of response notes (replies to this note as a parent in
    /// a discussion-style database).
    pub number_of_responses: u16,
    /// Identifier into the non-summary data area for items too large
    /// to fit in summary slots (rich-text bodies, attachments).
    pub non_summary_data_identifier: u32,
    /// Size in bytes of the non-summary data area associated with this
    /// note.
    pub non_summary_data_size: u32,
    /// Most recent access time.
    pub access_time: Timedate,
    /// File-creation time (first-write timestamp).
    pub creation_time: Timedate,
    /// NoteID of the parent (for response notes).
    pub parent_note_identifier: u32,
    /// Number of folders that reference this note.
    pub folder_reference_count: u32,
    /// NoteID of an associated folder (if any).
    pub folder_note_identifier: u32,
}

impl NoteHeader {
    /// Parse a note header from at least the first 100 bytes of a note
    /// record. Errors on signature mismatch or short input.
    pub fn parse(bytes: &[u8]) -> Result<Self, NsfError> {
        if bytes.len() < NOTE_HEADER_BYTES {
            return Err(NsfError::TooShort {
                actual: bytes.len(),
                required: NOTE_HEADER_BYTES,
            });
        }
        if bytes[0] != NOTE_SIGNATURE[0] || bytes[1] != NOTE_SIGNATURE[1] {
            return Err(NsfError::BadFileSignature {
                observed: [bytes[0], bytes[1]],
            });
        }
        let u16_at = |o: usize| u16::from_le_bytes([bytes[o], bytes[o + 1]]);
        let u32_at = |o: usize| {
            u32::from_le_bytes([bytes[o], bytes[o + 1], bytes[o + 2], bytes[o + 3]])
        };
        Ok(Self {
            size: u32_at(2),
            rrv_identifier: u32_at(6),
            file_identifier: Timedate::from_bytes(&bytes[10..18])?,
            note_identifier: Timedate::from_bytes(&bytes[18..26])?,
            sequence_number: u32_at(26),
            sequence_time: Timedate::from_bytes(&bytes[30..38])?,
            status_flags: u16_at(38),
            note_class: u16_at(40),
            modification_time: Timedate::from_bytes(&bytes[42..50])?,
            number_of_note_items: u16_at(50),
            number_of_responses: u16_at(54),
            non_summary_data_identifier: u32_at(56),
            non_summary_data_size: u32_at(60),
            access_time: Timedate::from_bytes(&bytes[64..72])?,
            creation_time: Timedate::from_bytes(&bytes[72..80])?,
            parent_note_identifier: u32_at(80),
            folder_reference_count: u32_at(86),
            folder_note_identifier: u32_at(94),
        })
    }

    /// True if any DOCUMENT bit is set in the note class. User-visible
    /// emails, calendar entries, contacts, and custom-form documents
    /// all carry this bit.
    pub fn is_document(&self) -> bool {
        self.note_class & class::DOCUMENT != 0
    }

    /// True if the note carries any design-related class bit (FORM,
    /// VIEW, ICON, DESIGN, HELP, FILTER, FIELD, REPLFORMULA, PRIVATE).
    pub fn is_design(&self) -> bool {
        const DESIGN_MASK: u16 = class::FORM
            | class::VIEW
            | class::ICON
            | class::DESIGN
            | class::HELP
            | class::HELP_INDEX
            | class::FILTER
            | class::FIELD
            | class::REPLFORMULA
            | class::PRIVATE;
        self.note_class & DESIGN_MASK != 0
    }

    /// 16-byte UNID (Universal Note Identifier) as a hex string. This
    /// is the globally-unique identifier that survives replication and
    /// compaction. Two replicas of the same logical note carry the
    /// same UNID.
    pub fn unid_hex(&self) -> String {
        format!(
            "{}{}",
            self.file_identifier.as_hex_id(),
            self.note_identifier.as_hex_id()
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn synthetic_note(note_class: u16, item_count: u16) -> Vec<u8> {
        let mut buf = vec![0u8; NOTE_HEADER_BYTES + 32];
        buf[0..2].copy_from_slice(&NOTE_SIGNATURE);
        buf[2..6].copy_from_slice(&512u32.to_le_bytes());
        buf[6..10].copy_from_slice(&12345u32.to_le_bytes());
        buf[40..42].copy_from_slice(&note_class.to_le_bytes());
        buf[50..52].copy_from_slice(&item_count.to_le_bytes());
        buf
    }

    #[test]
    fn parses_document_note() {
        let buf = synthetic_note(class::DOCUMENT, 17);
        let n = NoteHeader::parse(&buf).unwrap();
        assert!(n.is_document());
        assert!(!n.is_design());
        assert_eq!(n.number_of_note_items, 17);
        assert_eq!(n.rrv_identifier, 12345);
        assert_eq!(n.size, 512);
    }

    #[test]
    fn parses_form_note_as_design() {
        let buf = synthetic_note(class::FORM, 8);
        let n = NoteHeader::parse(&buf).unwrap();
        assert!(!n.is_document());
        assert!(n.is_design());
    }

    #[test]
    fn parses_acl_note_neither_document_nor_design() {
        let buf = synthetic_note(class::ACL, 3);
        let n = NoteHeader::parse(&buf).unwrap();
        assert!(!n.is_document());
        assert!(!n.is_design());
    }

    #[test]
    fn rejects_bad_signature() {
        let mut buf = synthetic_note(class::DOCUMENT, 1);
        buf[0] = 0xFF;
        assert!(NoteHeader::parse(&buf).is_err());
    }

    #[test]
    fn unid_hex_is_32_chars() {
        let buf = synthetic_note(class::DOCUMENT, 1);
        let n = NoteHeader::parse(&buf).unwrap();
        assert_eq!(n.unid_hex().len(), 32);
    }
}
