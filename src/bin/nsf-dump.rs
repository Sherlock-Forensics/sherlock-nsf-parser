//! `nsf-dump` - command-line smoke tool for the Sherlock NSF parser.
//!
//! Opens an NSF/NTF file, enumerates every note (identity-gated), and
//! prints a forensic summary: ODS version, RRV entry counts, verified note
//! count, note-class histogram, sample documents with provenance (UNID +
//! timestamps), and the readable field values of the first document.
//!
//! Usage:
//!   nsf-dump <path-to.nsf>
//!   nsf-dump <path-to.nsf> --fields <rrv_hex>   show all fields of one note
//!   nsf-dump <path-to.nsf> --all-fields         show fields of every document

use std::collections::BTreeMap;

use sherlock_nsf_parser::note::class;
use sherlock_nsf_parser::{Database, ResolvedNote, Timedate};

fn class_name(c: u16) -> &'static str {
    match c {
        class::DOCUMENT => "DOCUMENT",
        class::INFO => "INFO",
        class::FORM => "FORM",
        class::VIEW => "VIEW",
        class::ICON => "ICON",
        class::DESIGN => "DESIGN",
        class::ACL => "ACL",
        class::HELP_INDEX => "HELP_INDEX",
        class::HELP => "HELP",
        class::FILTER => "FILTER",
        class::FIELD => "FIELD",
        class::REPLFORMULA => "REPLFORMULA",
        class::PRIVATE => "PRIVATE",
        _ => "(other/special)",
    }
}

fn ts(t: &Timedate) -> String {
    t.as_clock()
        .map(|c| c.to_iso_8601())
        .unwrap_or_else(|| t.as_hex_id())
}

fn print_fields(db: &Database<'_>, names: Option<&sherlock_nsf_parser::BucketDescriptorBlock>, n: &ResolvedNote) {
    println!(
        "\nfields of note rrv=0x{:08X} ({}) - {} items:",
        n.rrv_identifier,
        class_name(n.header.note_class),
        n.header.number_of_note_items
    );
    if n.header.non_summary_data_size > 0 {
        let resolved = db.non_summary_data(n).map(|o| o.len()).unwrap_or(0);
        println!(
            "  [non-summary object: {} bytes declared, {resolved} resolved at 0x{:X} - rich text / attachment]",
            n.header.non_summary_data_size,
            (n.header.non_summary_data_identifier as u64) << 8,
        );
    }
    for it in db.note_items(n) {
        // Resolve the field name via the BDB Unique Name Key table; fall
        // back to the numeric id when the name is unknown.
        let label = names
            .and_then(|b| b.name(it.name_id))
            .filter(|s| !s.is_empty())
            .map(|s| s.to_string())
            .unwrap_or_else(|| format!("0x{:04X}", it.name_id));
        // Render by the field's authoritative type from the UNK table.
        let kind = names
            .map(|b| b.field_kind(it.name_id))
            .unwrap_or(sherlock_nsf_parser::FieldKind::Unknown);
        let value = it.render(kind);
        if !value.is_empty() {
            println!("  {label} = {value}");
        }
    }
    // Rich-text body + attachments from the non-summary CD stream.
    if let Some(c) = db.note_content(n) {
        if !c.body_text.trim().is_empty() {
            let preview: String = c.body_text.trim().chars().take(200).collect();
            println!("  [body] {preview}{}", if c.body_text.trim().chars().count() > 200 { " ..." } else { "" });
        }
        for a in &c.attachments {
            println!("  [attachment] {} ({} bytes, {:?})", a.name, a.data.len(), a.kind);
        }
    }
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let path = match args.get(1).filter(|a| !a.starts_with("--")).cloned() {
        Some(p) => p,
        None => {
            eprintln!("usage: nsf-dump <path-to.nsf> [--all-fields | --fields <rrv_hex>]");
            std::process::exit(2);
        }
    };

    let bytes = match std::fs::read(&path) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("error: cannot read {path}: {e}");
            eprintln!("usage: nsf-dump <path-to.nsf> [--all-fields | --fields <rrv_hex>]");
            std::process::exit(1);
        }
    };
    let db = match Database::open(&bytes) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("error: not a parseable NSF ({path}): {e}");
            std::process::exit(1);
        }
    };

    let e = match db.enumerate_notes() {
        Ok(e) => e,
        Err(err) => {
            eprintln!("error: enumeration failed: {err}");
            std::process::exit(1);
        }
    };
    let total_entries = e.bucket_slot_total + e.file_position_total;
    // Field-name table (Unique Name Key) for labelling item fields.
    let names = db.bucket_descriptor_block().ok().flatten();

    println!("=== {path} ===");
    println!("ODS {}", db.header().ods);
    println!(
        "RRV entries: {total_entries} ({} bucket-slot, {} file-position)",
        e.bucket_slot_total, e.file_position_total
    );
    println!(
        "identity-verified notes: {}  ({:.2}% of entries)",
        e.notes.len(),
        100.0 * e.notes.len() as f64 / total_entries.max(1) as f64
    );
    println!(
        "flagged unresolved (stale / non-note targets): {} ({:.2}%)",
        e.unresolved,
        100.0 * e.unresolved as f64 / total_entries.max(1) as f64
    );

    let mut hist: BTreeMap<u16, u64> = BTreeMap::new();
    let mut documents = 0u64;
    for n in &e.notes {
        *hist.entry(n.header.note_class).or_default() += 1;
        if n.header.is_document() {
            documents += 1;
        }
    }
    println!("\ndocument-class notes: {documents}");
    println!("note-class histogram:");
    for (cls, count) in &hist {
        println!("  0x{cls:04X} {:<16} {count}", class_name(*cls));
    }

    // --fields <rrv_hex>: dump one note's fields and exit.
    if let Some(pos) = args.iter().position(|a| a == "--fields") {
        if let Some(hex) = args.get(pos + 1) {
            let want = u32::from_str_radix(hex.trim_start_matches("0x"), 16).unwrap_or(0);
            match e.notes.iter().find(|n| n.rrv_identifier == want) {
                Some(n) => print_fields(&db, names.as_ref(), n),
                None => eprintln!("no note with rrv 0x{want:08X}"),
            }
        }
        return;
    }

    // --all-fields: dump every document's fields.
    if args.iter().any(|a| a == "--all-fields") {
        for n in e.notes.iter().filter(|n| n.header.is_document()) {
            print_fields(&db, names.as_ref(), n);
        }
        return;
    }

    // Default: sample documents + the first document's fields.
    println!("\nsample documents:");
    for n in e.notes.iter().filter(|n| n.header.is_document()).take(8) {
        println!(
            "  rrv=0x{:08X}  UNID={}  created={}  modified={}  items={}",
            n.rrv_identifier,
            n.header.unid_hex(),
            ts(&n.header.creation_time),
            ts(&n.header.modification_time),
            n.header.number_of_note_items,
        );
    }
    if let Some(n) = e.notes.iter().find(|n| n.header.is_document()) {
        print_fields(&db, names.as_ref(), n);
    }
}
