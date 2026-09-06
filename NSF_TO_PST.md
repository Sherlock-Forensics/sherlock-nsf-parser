# NSF -> PST conversion adapter (design)

How an NSF folder/note walk from `sherlock-nsf-parser` maps onto the
from-scratch Unicode PST writer in `outlook-pst::writer`, the packaging step
that lets one crate call the other, and a minimal conversion-loop sketch.

This is a design document. It describes the adapter; it does not change either
the reader (`sherlock-nsf-parser`) or the writer (`outlook-pst`). Both crates
build and test green as-is.


## 1. The two halves

### Reader: `sherlock-nsf-parser` (this crate)

Read-only, pure-Rust, Apache-2.0, zero non-std runtime deps. Relevant surface:

- `Database::open(&[u8]) -> Result<Database, NsfError>` - borrows a buffered
  NSF image (operator opens the source file read-only and reads it into a
  buffer; the parser never writes).
- `Database::enumerate_notes() -> NoteEnumeration` - every identity-verified
  note in RRV-walk order (`NoteEnumeration::notes: Vec<ResolvedNote>`).
- `ResolvedNote { rrv_identifier, file_offset, header: NoteHeader }`.
  `header.note_class` + `header.is_document()` classify a note (mail bodies are
  `class::DOCUMENT == 0x0001`; forms / views / ACL / icon are design notes to
  skip).
- `Database::note_items(&ResolvedNote) -> Vec<NoteItem>` - the note's summary
  fields, each `{ name_id: u16, type_flags, value: &[u8] }` with
  `value()` / `as_text()` / `display_value()` / `render(FieldKind)`.
- `Database::note_content(&ResolvedNote) -> Option<NoteContent>` - the
  non-summary body: `NoteContent { body_text: String, attachments:
  Vec<cd::Attachment { name, data, kind }> }` (rich text + reconstructed
  file/image attachments).

### Writer: `outlook-pst::writer` (lives under `pst-viewer/vendor/outlook-pst`)

From-scratch Unicode PST writer. Produces an Outlook-mountable, scanpst-clean
PST with the full ~47-node store scaffold plus operator-supplied messages.
Public content API, all re-exported from `outlook_pst::writer`:

```rust
pub const TOP_FOLDER_HANDLE: FolderId; // folder 0x8022, usable without add_folder

pub struct PstWriter { /* private */ }
impl PstWriter {
    pub fn new_unicode() -> Self;
    pub fn add_folder(&mut self, &FolderDescription) -> io::Result<FolderId>; // v1: Err(Unsupported)
    pub fn add_message(&mut self, FolderId, &MessageFields) -> io::Result<u32>; // returns message NID
    pub fn finish_to_path(self, path) -> io::Result<()>; // CONSUMES self; O_EXCL, refuses existing path
}

pub struct MessageFields { message_class, subject, sender_name, sender_email,
    display_to, display_cc, body_text, body_html: Option<String>,
    transport_headers: Option<String>, delivery_time, creation_time,
    last_modification_time, message_flags, importance,
    recipients: Vec<Recipient>, attachments: Vec<Attachment> }
pub struct Recipient { display_name, email_address, recipient_type } // 1=To 2=Cc 3=Bcc
pub struct Attachment { filename, data } // data <= ~8112 bytes (single block) in v1
pub struct FolderDescription { display_name, parent: Option<FolderId> }
pub struct FolderId(/* private */);
```

All times are Windows FILETIME (100ns ticks since 1601); pass `0` when unknown
and the writer substitutes a fixed sentinel. Strings are plain Rust `str`; the
writer encodes UTF-16LE. The writer only ever creates a NEW file.


## 2. Field mapping (NSF note -> `MessageFields`)

A mail document in an NSF is a `NOTE_CLASS_DOCUMENT` note whose form is `Memo`
(or `Reply`, `NonDelivery Report`, etc.). Its mail fields are summary items
(`note_items`) plus the rich-text `$Body` in non-summary data (`note_content`).

| NSF source | `MessageFields` target | MAPI prop |
|---|---|---|
| item `Subject` | `subject` | 0x0037 |
| item `From` / `Principal` (display) | `sender_name` | 0x0C1A / 0x0042 |
| item `From` / `INetFrom` (address) | `sender_email` | 0x0C1F / 0x0065 |
| item `SendTo` (joined) | `display_to` | 0x0E04 |
| item `CopyTo` (joined) | `display_cc` | 0x0E03 |
| each `SendTo` entry | `recipients` (type 1 = To) | recipient TC subnode |
| each `CopyTo` entry | `recipients` (type 2 = Cc) | recipient TC subnode |
| `$Body` -> `NoteContent::body_text` | `body_text` | 0x1000 |
| MIME part / HTML item, if present | `body_html: Some(..)` | 0x1013 |
| `$MIMETrack` / RFC822 header item | `transport_headers: Some(..)` | 0x007D |
| item `PostedDate` / `DeliveredDate` (TIMEDATE) | `delivery_time` | 0x0E06 |
| note header create/mod time | `creation_time` / `last_modification_time` | 0x3007 / 0x3008 |
| `NoteContent::attachments[]` | `attachments` (split if > 1 block) | 0x3701 etc. |
| fixed | `message_class = "IPM.Note"` | 0x001A |

TIMEDATE -> FILETIME: `Timedate::as_clock()` yields a wall-clock the adapter
converts to FILETIME ticks; pass `0` when a date item is absent.


## 3. Folder mapping

`sherlock-nsf-parser` enumerates notes as a flat identity-verified set; it does
not model the Notes view/folder hierarchy as a tree today (folders are `$FolderRef`
/ view design notes, not yet walked into a parent/child structure).

The writer is also flat in v1: `add_folder` returns `Err(Unsupported)` and the
only valid target is `TOP_FOLDER_HANDLE`. So the v1 adapter is **flat -> flat**:
every converted mail document goes into `TOP_FOLDER_HANDLE` ("Top of Outlook
data file"). This is correct and lossless for content; folder structure is a
later slice that lands on BOTH sides at once (NSF folder-tree walk + writer
multi-folder `add_folder`). The mapping table and loop below do not change when
that lands - only the `FolderId` passed to `add_message` does.


## 4. Packaging decision

**Decision: a NEW adapter crate that depends on BOTH `sherlock-nsf-parser` and
`outlook-pst`. Do NOT add `outlook-pst` as a dependency of
`sherlock-nsf-parser`.** No code change is applied to either crate; the writer
API is already `pub` and reachable (`outlook_pst::writer::{PstWriter,
MessageFields, Recipient, Attachment, FolderId, FolderDescription,
TOP_FOLDER_HANDLE}`), so it is consumable as-is.

Why not add the writer to this crate:

1. **License.** `sherlock-nsf-parser` is Apache-2.0 and published to crates.io;
   `outlook-pst` is an MIT vendored fork (Microsoft) that is NOT published -
   `pst-viewer` consumes it only via `[patch.crates-io] outlook-pst = { path =
   "vendor/outlook-pst" }`. A path/git dep to an unpublished fork makes this
   crate unpublishable and entangles the two licenses.
2. **Dependency policy.** This crate's `Cargo.toml` states an explicit "zero
   non-std runtime deps so downstream binaries don't inherit a heavy dep tree
   just to read NSFs" rule. The writer pulls `byteorder` / `thiserror` /
   `tracing`. Reading an NSF must not require the PST writer.
3. **Lane.** The reader is the read-only building block; conversion (read one
   format, write another) is an application concern, not a parser concern.

Why not add the reader to `outlook-pst`: it is a vendored upstream fork kept
minimal (VENDOR-CHANGES.md documents the single deviation); piling a Notes
reader into it would diverge it hard from upstream for no benefit.

### The adapter crate

Create `sherlock-nsf-to-pst` (proprietary, alongside `sherlock-nsf-viewer`)
with both crates as dependencies. Because `outlook-pst` is only published as a
vendored fork, the adapter's manifest mirrors `pst-viewer`'s patch:

```toml
[package]
name = "sherlock-nsf-to-pst"
edition = "2021"

[dependencies]
sherlock-nsf-parser = { path = "../sherlock-nsf-parser" }
outlook-pst = "1"

# Same redirect pst-viewer uses: resolve outlook-pst to the vendored fork that
# carries the writer. (When the writer is promoted to sherlock-shared-crates -
# see below - this patch goes away and the dep points there directly.)
[patch.crates-io]
outlook-pst = { path = "../pst-viewer/vendor/outlook-pst" }
```

Forensic invariants this crate enforces: source NSF opened read-only; output
PST is a brand-new file (`finish_to_path` is `O_EXCL`, refuses an existing
path); the writer never mutates anything.

### Optional future hardening (do later, not now)

If a second consumer beyond `pst-viewer` and this adapter ever needs the writer,
promote the vendored `outlook-pst` into `sherlock-shared-crates` as a workspace
member and drop the per-consumer `[patch]`. That is a mechanical move, but it is
**not** required for the adapter to work and is out of scope here - the `[patch]`
mirror above is sufficient and is the same pattern already in production for
`pst-viewer`. Documented so the decision is explicit, not applied, to avoid
touching the shared-crates workspace.


## 5. Conversion-loop sketch

```rust
use sherlock_nsf_parser::{Database, note::class};
use outlook_pst::writer::{
    Attachment, MessageFields, PstWriter, Recipient, TOP_FOLDER_HANDLE,
};

/// Convert every mail document in `nsf_bytes` into a new PST at `out_path`.
/// `nsf_bytes` is the source NSF read into memory (opened read-only upstream).
pub fn nsf_to_pst(nsf_bytes: &[u8], out_path: &std::path::Path) -> std::io::Result<u64> {
    let db = Database::open(nsf_bytes)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string()))?;

    let mut writer = PstWriter::new_unicode();
    let mut written = 0u64;

    let enumeration = db
        .enumerate_notes()
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string()))?;

    for note in &enumeration.notes {
        // Only user-visible documents; skip forms / views / ACL / icon / etc.
        if !note.header.is_document() {
            continue;
        }

        // Summary fields, keyed by name_id today (name resolution is a parser
        // gap - see "Open items"). Helper resolves the few mail field ids.
        let items = db.note_items(note);
        let fields = MailFields::from_items(&items); // adapter-local extractor

        // Rich-text body + attachments from non-summary data.
        let content = db.note_content(note).unwrap_or_default();

        let mut msg = MessageFields {
            subject: fields.subject,
            sender_name: fields.from_name,
            sender_email: fields.from_email,
            display_to: fields.send_to.join("; "),
            display_cc: fields.copy_to.join("; "),
            body_text: content.body_text,
            delivery_time: fields.posted_filetime, // 0 if unknown
            ..MessageFields::default()              // message_class defaults to IPM.Note
        };

        for addr in &fields.send_to {
            msg.recipients.push(Recipient {
                display_name: addr.clone(),
                email_address: addr.clone(),
                recipient_type: 1, // To
            });
        }
        for addr in &fields.copy_to {
            msg.recipients.push(Recipient {
                display_name: addr.clone(),
                email_address: addr.clone(),
                recipient_type: 2, // Cc
            });
        }

        // v1 writer caps an attachment at one block (~8112 bytes). Larger
        // attachments are deferred (XBLOCK data trees) - skip with a logged
        // note rather than fail the whole conversion. (A later writer slice
        // lifts this; the adapter loop is unchanged when it does.)
        for att in content.attachments {
            if att.data.len() <= 8112 && !att.data.is_empty() {
                msg.attachments.push(Attachment { filename: att.name, data: att.data });
            }
        }

        writer.add_message(TOP_FOLDER_HANDLE, &msg)?; // flat: all mail under Top folder
        written += 1;
    }

    writer.finish_to_path(out_path)?; // O_EXCL: refuses to overwrite
    Ok(written)
}
```

`MailFields::from_items` is adapter-local glue: it scans `note_items` for the
mail field name_ids and pulls each `as_text()` / decodes each TIMEDATE. Until
the parser resolves field NAMES (below) it keys on the database's stable
name_ids (resolved once per database by matching known field strings, or via a
small per-form name_id map).


## 6. Open items (gate the adapter, not the writer)

1. **Field-name resolution (parser gap, blocks a clean adapter).**
   `NoteItem` exposes `name_id: u16` but the parser does NOT yet resolve the
   name STRING (the BDB Unique Name Key text table is not decoded - see
   `item.rs` doc comment). The adapter cannot say "give me the `Subject` item"
   by name yet. Bridge options, cheapest first: (a) resolve name_ids by matching
   known mail field byte-patterns within a database the first time they are
   seen; (b) finish the UNK-table decode in `sherlock-nsf-parser` (the proper
   fix - turns `name_id` into a real field name and benefits every consumer).
   Recommend (b) as a `sherlock-nsf-parser` slice before the adapter ships.

2. **Recipient address vs display name.** NSF `SendTo` is often canonical Notes
   names (`CN=Jane Doe/O=Acme`), not SMTP. The adapter should prefer an
   `INetSendTo` / RFC822 address item for `email_address` and fall back to the
   Notes name for `display_name`. Without an SMTP address Outlook still shows
   the recipient, but reply-to is degraded.

3. **Large attachments.** Writer v1 is single-block per attachment (~8112
   bytes). The sketch skips larger ones; lifting this is a writer slice
   (XBLOCK data trees) tracked on the writer side, independent of this adapter.

4. **Folder hierarchy.** Flat in v1 (section 3). Lands as a paired slice on both
   crates; the loop's `add_message` target is the only line that changes.

5. **HTML / MIME body.** `NoteContent` decodes the CD `$Body` to plain text
   today. When a note carries a MIME part or HTML item, populate `body_html`
   and `transport_headers`; otherwise `body_text` alone is a faithful render.
