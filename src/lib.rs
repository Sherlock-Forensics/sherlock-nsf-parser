//! Read-only parser for IBM / HCL Lotus Notes Storage Facility (NSF)
//! databases. Pure Rust, no FFI, no Notes client required.
//!
//! Current capability surface:
//!
//! - File-shape identification ([`detect`])
//! - Database header parsing ([`header::DbHeader`]) - ODS version,
//!   database id, template flag, BDB position (the encryption flag is
//!   NOT among these - see below)
//! - Database information extension block 2 parsing
//!   ([`info2::Information2`]) - 4 superblock positions + 2 BDB positions
//!   + bucket-size knobs
//! - Superblock header parsing ([`superblock::Superblock`]) plus
//!   freshest-of-4-copies selection ([`superblock::select_freshest`])
//! - Bucket header parsing ([`bucket::BucketHeader`]) + RRV bucket header
//!   + per-entry decoder ([`rrv::RrvIter`])
//! - Note record header parsing ([`note::NoteHeader`]) with class
//!   catalogue + UNID composition
//! - High-level [`database::Database`] handle with data-RRV walking
//! - Bucket Descriptor Block parsing ([`bdb::BucketDescriptorBlock`]) - the
//!   master index of every RRV bucket
//! - Multi-page summary bucket-descriptor map + bucket-slot resolution
//!   ([`database::Database::resolve_bucket_slot`]) and identity-gated
//!   full-database note enumeration
//!   ([`database::Database::enumerate_notes`]) (Slice 2.6 Phase B.2)
//! - Per-note item parsing with real field names + authoritative typing
//!   ([`item::NoteItem`], [`item::FieldKind`]) sourced from the BDB Unique
//!   Name Key table
//! - CD-record stream walking for rich-text bodies + OBJECT-item attachment
//!   extraction ([`cd::NoteContent`], [`database::Database::note_content`])
//! - TIMEDATE timestamp parsing ([`time::Timedate`])
//! - ODS version mapping ([`ods::Ods`])
//!
//! Coming in subsequent slices:
//!
//! - Form-based dispatch (Memo / Person / Appointment / ...)
//! - Encryption DETECTION, which is not implemented at all today. This
//!   line previously read "detected + flagged today", which was wrong:
//!   `DbHeader::is_database_encrypted` returns `None` unconditionally
//!   because the authoritative flag bit is not known. A consumer must
//!   treat the absence of an encryption finding as "not checked",
//!   never as "not encrypted".
//! - Item-level decryption, which additionally requires a Notes ID file
//!   and its password; without the key it is not a parsing problem.
//!
//! See the project README for current capability status and the
//! companion `priorart_nsf_format.md` for the design rationale and
//! format reference.
//!
//! # Versioning
//!
//! This crate is pre-1.0 and under active development. Public API may
//! break between 0.x releases as format coverage grows.

#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![warn(rust_2018_idioms)]

pub mod bdb;
pub mod bdt;
pub mod bucket;
pub mod cd;
pub mod cx;
pub mod database;
pub mod detect;
pub mod error;
pub mod header;
pub mod info2;
pub mod item;
pub mod note;
pub mod ods;
pub mod rrv;
pub mod superblock;
pub mod time;

pub use bdb::{BucketDescriptorBlock, RrvBucketDescriptor, RrvBucketKind};
pub use cd::{Attachment, AttachmentKind, BodyRun, NoteContent, RunStyle};
pub use item::{ItemWalk, ItemWalkStop};
pub use bdt::BucketDescriptorTable;
pub use bucket::{Bucket, BucketHeader, BucketSlot};
pub use database::{
    Database, NoteEnumeration, ResolvedNote, WithheldEntry, WithheldLocation, WithheldReason,
    MAX_WITHHELD_DETAIL,
};
pub use detect::{identify_file, FileKind};
pub use error::NsfError;
pub use header::DbHeader;
pub use info2::{BdbSlot, Information2, SuperblockSlot};
pub use item::{field_kind, parse_items, FieldKind, NoteItem};
pub use note::NoteHeader;
pub use ods::Ods;
pub use rrv::{RrvBucketHeader, RrvEntry, RrvIter, RrvLocation};
pub use superblock::{select_freshest, Superblock};
pub use time::{DecodedTimedate, Timedate};
