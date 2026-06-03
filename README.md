# sherlock-nsf-parser

[![Crates.io](https://img.shields.io/crates/v/sherlock-nsf-parser.svg)](https://crates.io/crates/sherlock-nsf-parser)
[![Docs.rs](https://docs.rs/sherlock-nsf-parser/badge.svg)](https://docs.rs/sherlock-nsf-parser)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE-APACHE)

A pure-Rust, read-only parser for IBM / HCL **Lotus Notes Storage Facility (NSF)** databases.

No FFI. No Notes client. No Domino server. No C library to link. Point it at a `.nsf` /
`.ntf` file and read what is inside, from any platform Rust compiles for.

This is, to our knowledge, the first open-source pure-Rust NSF reader. It is the parsing
engine behind the [Sherlock NSF Viewer](#the-sherlock-nsf-viewer) forensic GUI.

## Why this exists

Organizations spent two decades putting mail, contacts, calendars, and application data into
Lotus Notes. That data is still sitting in `.nsf` files long after the Notes client was
uninstalled, the Domino server was decommissioned, and the people who ran it moved on.

Reading those files traditionally meant standing up a Notes/Domino environment or buying a
five-figure forensic suite. The format is also almost entirely undocumented in public, which
is why open tooling has historically depended on the proprietary Notes C API.

This crate reads the on-disk structures directly, with a hard correctness guarantee (see
[Forensic posture](#forensic-posture)) and zero runtime dependencies.

## Status

Active development, pre-1.0. The public API may change between `0.x` releases as format
coverage grows.

### What works today

- **File identification** - distinguishes NSF / NTF / NSG / mail.box and related shapes.
- **Database header / DBINFO** - ODS version, database id (DBID), encryption and template
  flags, bucket / RRV positions and sizes, Bucket Descriptor Block position.
- **Superblock** parsing with freshest-of-copies selection (multi-page summary bucket
  descriptor map).
- **Bucket Descriptor Block (BDB)** - the master index of every RRV bucket, plus the Unique
  Name Key table that gives fields their real names and types.
- **RRV bucket / entry decoding** and bucket-slot resolution.
- **Identity-gated full-database note enumeration** - walks every note in the database and
  verifies each resolved record against its own NoteID before trusting it.
- **Per-note items** with real field names and authoritative typing (TEXT, TEXT_LIST, TIME,
  NUMBER, FORMULA, COMPOSITE, OBJECT, and more).
- **Rich-text bodies** - walks the Composite Data (CD) record stream and reconstructs the
  message body text.
- **Attachment extraction** - pulls embedded images and files out of the non-summary object
  stream, byte-for-byte.
- **TIMEDATE** timestamp decoding (clock view + identifier view) and ODS version mapping.

### Not yet

- Decrypting database/item-level encrypted NSFs (encryption is detected and flagged, not
  decrypted; requires `.id` file parsing + RSA private key unwrap).
- Form-based semantic dispatch (Memo / Person / Appointment field schemas).
- Full file-attachment segment coverage for every CD file-segment variant.
- Writing or replicating NSFs. This crate is read-only, forever.

## Forensic posture

This crate is built for evidence work, and two properties are non-negotiable:

- **Read-only.** The parser never writes to, mmaps for write, or otherwise mutates the source
  file. It takes an immutable `&[u8]`. The file on disk is exactly what it was.
- **Identity-gated resolution.** NSF addresses notes through layers of indirection (RRV
  buckets, bucket slots, file positions). A resolution step is only trusted when the record it
  lands on reports the same NoteID (`rrv_identifier`) that was used to look it up. Records that
  do not match are reported as *unresolved* rather than silently returned. The parser would
  rather tell you it could not resolve a note than hand you the wrong one.

`enumerate_notes()` returns both the identity-verified notes and the count of entries it could
not resolve, so you always know the coverage of any extraction.

It is also `#![forbid(unsafe_code)]`: deterministic parsing, no global state, no panics on
malformed input.

## Usage

```toml
[dependencies]
sherlock-nsf-parser = "0.1"
```

```rust
use sherlock_nsf_parser::Database;

let bytes = std::fs::read("mail.nsf")?;
let db = Database::open(&bytes)?;

// Walk every note, identity-verified.
let result = db.enumerate_notes()?;
println!(
    "{} notes identity-verified, {} unresolved",
    result.notes.len(),
    result.unresolved,
);

// Field names and types live in the Bucket Descriptor Block.
let bdb = db.bucket_descriptor_block()?;

for note in &result.notes {
    println!(
        "note 0x{:08X}  class 0x{:04X}",
        note.rrv_identifier, note.header.note_class,
    );

    // Typed, named fields.
    for item in db.note_items(note) {
        if let Some(bdb) = bdb.as_ref() {
            let name = bdb.name(item.name_id).unwrap_or("(unknown)");
            let kind = bdb.field_kind(item.name_id);
            println!("    {name}: {}", item.render(kind));
        }
    }

    // Rich-text body + attachments, decoded from the CD record stream.
    if let Some(content) = db.note_content(note) {
        if !content.body_text.trim().is_empty() {
            println!("    body: {}", content.body_text.trim());
        }
        for att in &content.attachments {
            println!("    attachment: {} ({} bytes)", att.name, att.data.len());
        }
    }
}
# Ok::<(), sherlock_nsf_parser::NsfError>(())
```

Just want to know what a file is?

```rust
use sherlock_nsf_parser::{identify_file, FileKind};

let bytes = std::fs::read("mail.nsf")?;
match identify_file(&bytes) {
    FileKind::Nsf { db_header_size, .. } => {
        println!("Valid NSF; DB header is {db_header_size} bytes");
    }
    FileKind::NotNsf { reason } => {
        eprintln!("Not an NSF: {reason}");
    }
}
# Ok::<(), std::io::Error>(())
```

### Proven against real data

The enumeration and resolution paths are validated against the canonical 142 MB Mindoo
`fakenames.nsf` Domino directory, where the parser identity-verifies over 42,000 documents and
correctly reconstructs rich-text bodies and attachments (including a multi-megabyte JPEG rebuilt
from its CD image segments). The corpus suite also covers HCL Domino 6.x-9.0.1 templates and
OpenNTF XPages demo databases.

## The Sherlock NSF Viewer

This crate is the open-source engine. If you want a polished desktop application on top of it
(browse, filter, keyboard navigation, attachment save, structured export, signed chain-of-custody
reports), that is the **Sherlock NSF Viewer**, a commercial forensic tool from
[Sherlock Forensics](https://www.sherlockforensics.com). Free to view and browse; Pro unlocks
export and reporting.

## License

Licensed under the Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or
<http://www.apache.org/licenses/LICENSE-2.0>).

## Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in
the work by you, as defined in the Apache-2.0 license, shall be licensed as above, without any
additional terms or conditions. Test fixtures from previously-unsupported NSF variants are
especially welcome.

## Format reference

This crate cross-references Joachim Metz's libnsfdb notes
(<https://github.com/libyal/libnsfdb>) and the public HCL Domino C API documentation, but the
note-addressing, item-typing, and CD-record work here was reverse-engineered directly from
observed file structures.

## Disclaimer

Not affiliated with, endorsed by, or sponsored by IBM or HCL. "Lotus Notes", "Domino", and
related marks belong to their respective owners. This is a clean-room reader developed from
publicly observable file structures for interoperability and digital-forensics purposes.
