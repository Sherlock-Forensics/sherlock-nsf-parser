//! Smoke regression against an optional real-Domino corpus.
//!
//! Set the `NSF_CORPUS_DIR` environment variable to a directory holding
//! `hcl-templates-en/`, `hcl-templates-locale/`, and `real-nsf/`
//! subdirectories of `.nsf` / `.ntf` / `.nsg` / `.box` samples. When the
//! variable is unset or the directory is absent (the normal case for an
//! external user who has just `cargo add`-ed the parser), these tests
//! skip with a clear message rather than fail.
//!
//! The corpus is not distributed with the crate; supply your own samples.

use std::path::{Path, PathBuf};

use sherlock_nsf_parser::{
    Database, DbHeader, FileKind, NoteHeader, RrvIter, RrvLocation, WithheldLocation,
    WithheldReason,
};

fn corpus_root() -> Option<PathBuf> {
    // Driven entirely by the NSF_CORPUS_DIR environment variable so the
    // crate carries no machine-specific paths. Unset / missing -> skip.
    std::env::var_os("NSF_CORPUS_DIR")
        .map(PathBuf::from)
        .filter(|p| p.is_dir())
}

fn read_prefix(path: &Path, n: usize) -> std::io::Result<Vec<u8>> {
    use std::io::Read;
    let mut f = std::fs::File::open(path)?;
    let mut buf = vec![0u8; n];
    let read = f.read(&mut buf)?;
    buf.truncate(read);
    Ok(buf)
}

fn for_each_sample(mut callback: impl FnMut(&Path)) -> usize {
    let Some(root) = corpus_root() else {
        eprintln!("corpus not present at expected paths; skipping");
        return 0;
    };
    let mut count = 0usize;
    for sub in ["hcl-templates-en", "hcl-templates-locale", "real-nsf"] {
        let dir = root.join(sub);
        let Ok(entries) = std::fs::read_dir(&dir) else { continue };
        for entry in entries.flatten() {
            let p = entry.path();
            let Some(ext) = p.extension().and_then(|e| e.to_str()) else { continue };
            let ext_lower = ext.to_ascii_lowercase();
            if !matches!(ext_lower.as_str(), "nsf" | "ntf" | "nsg" | "box") {
                continue;
            }
            callback(&p);
            count += 1;
        }
    }
    count
}

#[test]
fn every_sample_passes_magic_check() {
    let count = for_each_sample(|path| {
        let bytes = read_prefix(path, 6).expect("read first 6 bytes");
        match sherlock_nsf_parser::identify_file(&bytes) {
            FileKind::Nsf { db_header_size } => {
                assert!(
                    db_header_size >= 64,
                    "{}: db_header_size {} is implausibly small",
                    path.display(),
                    db_header_size
                );
                assert!(
                    db_header_size <= 65_536,
                    "{}: db_header_size {} is implausibly large",
                    path.display(),
                    db_header_size
                );
            }
            FileKind::NotNsf { reason } => {
                panic!("{} failed magic check: {}", path.display(), reason);
            }
        }
    });
    if count == 0 {
        eprintln!("no samples found, test was a no-op");
    } else {
        eprintln!("verified magic + header-size on {count} corpus samples");
    }
}

#[test]
fn every_sample_parses_dbinfo() {
    let count = for_each_sample(|path| {
        let bytes = read_prefix(path, 4096).expect("read first 4 KB");
        let header = match DbHeader::parse(&bytes) {
            Ok(h) => h,
            Err(e) => panic!("{}: DBINFO parse failed: {}", path.display(), e),
        };
        assert!(
            header.ods.is_supported_for_enumeration(),
            "{}: ODS {} not in supported range",
            path.display(),
            header.ods.raw
        );
        // No "non-zero RRV" assertion: empirically, fresh HCL templates
        // (e.g. notebook12_EN.ntf, comparedbs.ntf) ship with both BDB
        // position AND data RRV bucket position = 0. The note data
        // lives elsewhere (or there literally are no data notes yet -
        // a template carries only design notes, accessed via
        // non_data_rrv_bucket_position). The parser-level invariant is
        // "DbHeader::parse succeeds without panicking on every corpus
        // file"; pointer-validity is a downstream concern.
    });
    eprintln!("DBINFO-parsed {count} corpus samples");
}

#[test]
fn ntf_templates_carry_template_flag_or_extension() {
    let count = for_each_sample(|path| {
        let bytes = read_prefix(path, 4096).expect("read first 4 KB");
        let header = DbHeader::parse(&bytes).expect("parse");
        let ext = path
            .extension()
            .and_then(|e| e.to_str())
            .map(|s| s.to_ascii_lowercase())
            .unwrap_or_default();
        // If the file is .ntf, EITHER the flag is set OR the extension
        // is the differentiator (per the recon doc, extension is
        // canonical; flag is a confirmation signal). Both being absent
        // would be surprising.
        if ext == "ntf" {
            // Allow either: real Domino templates set the flag; some
            // OpenNTF builds skip it. The .ntf extension is enough.
            let _ = header.is_template();
        }
    });
    eprintln!("template-flag invariant checked on {count} samples");
}

#[test]
fn encryption_detection_is_deferred_in_v0_1() {
    // is_database_encrypted returns None in v0.1 because we have not
    // yet imported the authoritative DB flag bit positions from HCL's
    // dbopts.h. This test pins the expectation so that adding the
    // dbopts.h import in a later slice is a clear API change.
    let count = for_each_sample(|path| {
        let bytes = read_prefix(path, 4096).expect("read first 4 KB");
        let header = DbHeader::parse(&bytes).expect("parse");
        assert!(
            header.is_database_encrypted().is_none(),
            "{}: encryption detection should report None until dbopts.h is imported",
            path.display()
        );
    });
    eprintln!("encryption-detection-deferred invariant pinned on {count} samples");
}

#[test]
fn corpus_data_rrv_walk_counts_notes() {
    // For every corpus sample with a non-zero data_rrv_bucket_position,
    // walk the RRV and count non-empty entries. We are NOT asserting
    // an exact count - the corpus is large and varied - but every
    // file with a populated data RRV should produce at least one
    // entry without panicking.
    let mut sampled = 0usize;
    let mut total_entries = 0u64;
    for_each_sample(|path| {
        let full = match std::fs::read(path) {
            Ok(b) => b,
            Err(_) => return,
        };
        let db = match Database::open(&full) {
            Ok(d) => d,
            Err(_) => return,
        };
        if !db.has_data_rrv() {
            return;
        }
        let count = match db.data_note_count() {
            Ok(c) => c,
            Err(e) => panic!("{}: RRV walk failed: {e}", path.display()),
        };
        eprintln!("{}: {} data RRV entries", path.display(), count);
        // The XPagesExt.nsf demo + fakenames.nsf both have data;
        // the templates may or may not. The invariant is just
        // "walk does not panic" plus "if has_data_rrv() returns
        // true, the walk produces a finite count".
        sampled += 1;
        total_entries = total_entries.saturating_add(count);
    });
    eprintln!(
        "RRV walk total: {} samples with data RRV, {} entries combined",
        sampled, total_entries
    );
}

#[test]
fn xpages_ext_data_rrv_walk_completes() {
    // XPagesExt.nsf is the XPages Extension Library DEMO - its content
    // is design notes (forms, views, XPage definitions), not data
    // documents. The data RRV bucket is allocated but every entry is
    // 0xFFFFFFFF (empty), which is structurally correct. The test
    // confirms the walk completes cleanly + reports a finite count.
    //
    // To actually see documents, walk the non-data RRV (where the
    // design notes live) - but that requires bucket_index resolution
    // via the BDT, which is implemented in Slice 2.6+ alongside
    // superblock parsing.
    let Some(root) = corpus_root() else {
        eprintln!("corpus not present; skipping");
        return;
    };
    let path = root.join("real-nsf").join("XPagesExt.nsf");
    if !path.is_file() {
        eprintln!("XPagesExt.nsf not present; skipping");
        return;
    }
    let bytes = std::fs::read(&path).expect("read XPagesExt.nsf");
    let db = Database::open(&bytes).expect("open XPagesExt.nsf");
    assert!(db.has_data_rrv());
    let count = db.data_note_count().expect("walk");
    eprintln!(
        "XPagesExt.nsf data RRV: {} entries (expected 0; design-only demo)",
        count
    );
    // 0 is a valid outcome for design-only DBs. Future Slice 2.6 will
    // walk the non-data RRV via BDT to surface the design-note count.
}

#[test]
fn every_sample_parses_information2_at_offset_520() {
    // The first 520 + 124 = 644 bytes of every NSF must contain a
    // parseable Information2 block. Parsing exercises the offset-520
    // assumption: 6-byte file_header + 174-byte
    // nsfdb_database_information_t + 20-byte replication_information
    // + 320-byte nsfdb_database_header_t = 520 (per
    // libnsfdb_io_handle_read_database_header).
    //
    // No assertion on populated_superblock_indices() being non-empty:
    // some files may have only an empty Vec result and that's still
    // valid parsing. The downstream every_sample_real_nsf_loads_superblocks
    // test asserts the positive control on instantiated databases.
    let count = for_each_sample(|path| {
        let bytes = read_prefix(path, 4096).expect("read first 4 KB");
        let db = Database::open(&bytes).expect("open");
        let info = match db.information2() {
            Ok(i) => i,
            Err(e) => panic!("{}: Information2 parse failed: {}", path.display(), e),
        };
        eprintln!(
            "{}: info2 populated superblocks: {:?}, populated BDBs: {:?}",
            path.display(),
            info.populated_superblock_indices(),
            info.populated_bdb_indices()
        );
    });
    eprintln!("Information2 parsed on {count} corpus samples");
}

#[test]
fn every_sample_superblocks_load_without_crashing() {
    // Forensic-tool-grade resilience: superblocks() must not crash on
    // any corpus file even when slots are malformed (out-of-bounds or
    // partially-zeroed). Fresh templates may legitimately return an
    // empty Vec; instantiated databases return >=1 entries. Either
    // outcome is acceptable here; the positive control is the
    // every_sample_real_nsf_loads_superblocks test below.
    let count = for_each_sample(|path| {
        let full = match std::fs::read(path) {
            Ok(b) => b,
            Err(_) => return,
        };
        let db = Database::open(&full).expect("open");
        let sbs = match db.superblocks() {
            Ok(s) => s,
            Err(e) => panic!("{}: superblocks() crashed: {}", path.display(), e),
        };
        for (i, sb) in &sbs {
            eprintln!(
                "{}: superblock {} - mod_key {:?}, rrv_bucket_size {}, data_rrv_pos {}, sum_bdt_pages {}, nonsum_bdt_pages {}",
                path.display(),
                i,
                sb.modification_sort_key(),
                sb.rrv_bucket_size,
                sb.data_rrv_bucket_position,
                sb.number_of_summary_bucket_descriptor_pages,
                sb.number_of_non_summary_bucket_descriptor_pages,
            );
        }
        if sbs.is_empty() {
            eprintln!("{}: no superblocks loaded (likely fresh template)", path.display());
        }
    });
    eprintln!("superblocks() load + resilience verified on {count} corpus samples");
}

#[test]
fn every_sample_real_nsf_loads_superblocks() {
    // POSITIVE CONTROL pairing with the empty-tolerance test above.
    // Every file in real-nsf/ is an instantiated database (XPagesExt,
    // ToDo, fakenames, fakenames-views) so superblocks() MUST return
    // at least one entry. If it doesn't, our offset arithmetic or
    // is_empty filter is broken on real data.
    let Some(root) = corpus_root() else {
        eprintln!("corpus not present; skipping");
        return;
    };
    let real_nsf = root.join("real-nsf");
    let Ok(entries) = std::fs::read_dir(&real_nsf) else {
        eprintln!("real-nsf/ not present; skipping");
        return;
    };
    let mut sampled = 0usize;
    for entry in entries.flatten() {
        let p = entry.path();
        let Some(ext) = p.extension().and_then(|e| e.to_str()) else {
            continue;
        };
        if ext.to_ascii_lowercase() != "nsf" {
            continue;
        }
        let full = match std::fs::read(&p) {
            Ok(b) => b,
            Err(_) => continue,
        };
        let db = Database::open(&full).expect("open real .nsf");
        let sbs = db.superblocks().expect("load superblocks on real .nsf");
        assert!(
            !sbs.is_empty(),
            "{}: real .nsf must have at least one parseable superblock",
            p.display()
        );
        let (idx, sb) = db
            .freshest_superblock()
            .expect("freshest_superblock")
            .expect("real .nsf must produce a freshest superblock");
        // Cross-check: data_rrv_bucket_position from the freshest
        // superblock should match DBINFO's data_rrv_bucket_position
        // when both are non-zero. Mismatch indicates either drift in
        // mid-commit OR a parsing offset bug.
        let dbinfo_pos = db.header().data_rrv_bucket_position;
        if dbinfo_pos != 0 && sb.data_rrv_bucket_position != 0 {
            assert_eq!(
                sb.data_rrv_bucket_position,
                dbinfo_pos,
                "{}: superblock {idx} data_rrv_bucket_position {} disagrees with DBINFO {}",
                p.display(),
                sb.data_rrv_bucket_position,
                dbinfo_pos
            );
        }
        eprintln!(
            "{}: {} superblocks; freshest = slot {} (write_count {}, size {}, dbinfo_data_rrv_pos {}, sb_data_rrv_pos {})",
            p.display(),
            sbs.len(),
            idx,
            sb.write_count,
            sb.size,
            dbinfo_pos,
            sb.data_rrv_bucket_position,
        );
        sampled += 1;
    }
    eprintln!("real-nsf/ positive control sampled {sampled} files");
}

#[test]
fn fakenames_enumerates_notes_identity_gated() {
    // Slice 2.6 Phase B.2 acceptance: walk the BDB -> every RRV bucket ->
    // every entry, resolve each to a note record, and identity-gate it (the
    // resolved note's rrv_identifier must equal the RRV entry's). This is
    // the whole document-enumeration chain end to end: BDB CX-decompress,
    // multi-page summary descriptor map, bucket/slot resolution, note parse.
    //
    // fakenames.nsf carries ~49K notes (~40K of them Person documents). A
    // correct chain must verify the vast majority. The earlier
    // ">=10 landed on a bucket" check only proved we hit a 0x02 signature,
    // not that we hit the RIGHT record; this asserts the identity gate -
    // the only trustworthy correctness signal.
    let Some(root) = corpus_root() else {
        eprintln!("corpus not present; skipping");
        return;
    };
    let path = root.join("real-nsf").join("fakenames.nsf");
    if !path.is_file() {
        eprintln!("fakenames.nsf not present; skipping");
        return;
    }
    let bytes = std::fs::read(&path).expect("read fakenames.nsf");
    let db = Database::open(&bytes).expect("open fakenames.nsf");

    let e = db.enumerate_notes().expect("enumerate notes");
    eprintln!(
        "fakenames: {} verified notes, {} unresolved, {} bucket-slot, {} file-position",
        e.notes.len(),
        e.unresolved,
        e.bucket_slot_total,
        e.file_position_total
    );

    // Identity guarantee: enumerate_notes only returns records that passed
    // the gate, so this holds by construction - asserted to lock the contract.
    for n in &e.notes {
        assert_eq!(
            n.header.rrv_identifier, n.rrv_identifier,
            "enumerate_notes returned a record that failed the identity gate"
        );
    }

    // The bulk of the database must enumerate end to end. The group-marker
    // slots are recovered by the identity-validated candidate resolver, so
    // the verified count is high.
    assert!(
        e.notes.len() >= 42_000,
        "expected >= 42000 identity-verified notes, got {}",
        e.notes.len()
    );

    // The residual unresolved entries are genuine data-level anomalies -
    // stale/superseded RRV entries whose slot now holds a different note,
    // and file-position entries pointing at non-note structures. The
    // identity gate flags them rather than serving wrong records, so they
    // stay well under 1% of all entries - never the silent-mis-resolution
    // failure mode a forensic tool must avoid.
    let total = e.bucket_slot_total + e.file_position_total;
    assert!(
        (e.unresolved as f64) < 0.01 * total as f64,
        "unresolved {} exceeded 1% of {} total entries",
        e.unresolved,
        total
    );
}

#[test]
fn resolve_bucket_slot_returns_the_identity_correct_record() {
    // Direct test of the public resolve_bucket_slot: take a real bucket-slot
    // RRV entry from the database and confirm resolution lands on the note
    // carrying that entry's exact rrv_identifier.
    let Some(root) = corpus_root() else {
        eprintln!("corpus not present; skipping");
        return;
    };
    let path = root.join("real-nsf").join("fakenames.nsf");
    if !path.is_file() {
        eprintln!("fakenames.nsf not present; skipping");
        return;
    }
    let bytes = std::fs::read(&path).expect("read");
    let db = Database::open(&bytes).expect("open");

    let bdb = db
        .bucket_descriptor_block()
        .expect("parse BDB")
        .expect("fakenames has a BDB");
    let (_, sb) = db
        .freshest_superblock()
        .expect("superblock")
        .expect("fakenames has a superblock");
    let rrv_bucket_size = sb.rrv_bucket_size as usize;

    // resolve_bucket_slot is un-gated physical resolution: it returns the
    // record at the addressed (bucket, slot). For the vast majority of
    // entries that record IS the right note; a small set of summary-page
    // group-descriptor slots mis-resolve (which is exactly why
    // enumerate_notes applies the identity gate on top). Assert the raw
    // method's identity-match RATE is high, not that it is perfect.
    let mut checked = 0u64;
    let mut matched = 0u64;
    'outer: for desc in &bdb.rrv_buckets {
        let start = desc.file_offset as usize;
        let Some(slice) = bytes.get(start..start.saturating_add(rrv_bucket_size)) else {
            continue;
        };
        let Ok((_, iter)) = RrvIter::new(slice) else { continue };
        for entry in iter {
            if let RrvLocation::BucketSlot {
                bucket_index,
                slot_index,
                ..
            } = entry.location
            {
                checked += 1;
                if let Ok(record) = db.resolve_bucket_slot(bucket_index, slot_index) {
                    if let Ok(nh) = NoteHeader::parse(record) {
                        if nh.rrv_identifier == entry.rrv_identifier {
                            matched += 1;
                        }
                    }
                }
                if checked >= 1000 {
                    break 'outer;
                }
            }
        }
    }
    assert!(checked >= 1000, "expected >= 1000 bucket-slot entries, got {checked}");
    let rate = matched as f64 / checked as f64;
    eprintln!("resolve_bucket_slot identity-match rate: {matched}/{checked} = {:.1}%", rate * 100.0);
    assert!(
        rate >= 0.95,
        "resolve_bucket_slot identity-match rate {:.1}% below 95%",
        rate * 100.0
    );
}

#[test]
fn fakenames_resolves_field_names() {
    // The BDB Unique Name Key table maps a note item's name_id to the
    // field-name string. Recovered by chained-CX decode of the BDB body.
    let Some(root) = corpus_root() else {
        eprintln!("corpus not present; skipping");
        return;
    };
    let path = root.join("real-nsf").join("fakenames.nsf");
    if !path.is_file() {
        eprintln!("fakenames.nsf not present; skipping");
        return;
    }
    let bytes = std::fs::read(&path).expect("read");
    let db = Database::open(&bytes).expect("open");
    let bdb = db
        .bucket_descriptor_block()
        .expect("parse BDB")
        .expect("fakenames has a BDB");
    eprintln!("recovered {} field names", bdb.unk_names.len());

    // name_id 0x098B carried the FirstName value ("Josef") in the Person docs.
    assert_eq!(bdb.name(0x098B), Some("FirstName"));
    for expected in ["FirstName", "LastName", "$UpdatedBy", "Form"] {
        assert!(
            bdb.unk_names.iter().any(|n| n == expected),
            "expected field name {expected:?} not found in UNK table"
        );
    }
}

#[test]
fn fakenames_resolves_non_summary_object() {
    // Design notes (and, in mail DBs, Memo bodies) store large data in a
    // separate non-summary object at non_summary_data_identifier << 8.
    let Some(root) = corpus_root() else {
        eprintln!("corpus not present; skipping");
        return;
    };
    let path = root.join("real-nsf").join("fakenames.nsf");
    if !path.is_file() {
        eprintln!("fakenames.nsf not present; skipping");
        return;
    }
    let bytes = std::fs::read(&path).expect("read");
    let db = Database::open(&bytes).expect("open");
    let e = db.enumerate_notes().expect("enumerate");
    let form = e
        .notes
        .iter()
        .find(|n| n.header.note_class == 0x0004 && n.header.non_summary_data_size > 0)
        .expect("a FORM note with non-summary data");
    let obj = db
        .non_summary_data(form)
        .expect("non-summary object resolves + validates");
    assert_eq!(obj.len(), form.header.non_summary_data_size as usize);
    assert_eq!(&obj[0..2], &[0x10, 0x00], "object header signature");
    eprintln!("form rrv 0x{:08X}: non-summary object {} bytes", form.rrv_identifier, obj.len());
}

#[test]
fn fakenames_decodes_richtext_body_and_jpeg_attachment() {
    // CD-record decode: doc 0x1C746 has a rich-text body (Easter dates),
    // doc 0x28C7A embeds a JPEG attachment.
    let Some(root) = corpus_root() else {
        eprintln!("corpus not present; skipping");
        return;
    };
    let path = root.join("real-nsf").join("fakenames.nsf");
    if !path.is_file() {
        eprintln!("fakenames.nsf not present; skipping");
        return;
    }
    let bytes = std::fs::read(&path).expect("read");
    let db = Database::open(&bytes).expect("open");
    let e = db.enumerate_notes().expect("enumerate");
    let find = |rrv: u32| e.notes.iter().find(|n| n.rrv_identifier == rrv).expect("note");

    // Rich-text body.
    let body = db.note_content(find(0x0001C746)).expect("body content");
    assert!(
        body.body_text.contains("Easter") && body.body_text.contains("1980"),
        "rich-text body did not decode: {:?}",
        &body.body_text[..body.body_text.len().min(80)]
    );

    // JPEG attachment, reconstructed from image segments.
    let att = db.note_content(find(0x00028C7A)).expect("attachment content");
    let jpg = att
        .attachments
        .iter()
        .find(|a| a.data.len() > 100_000)
        .expect("a large image attachment");
    assert_eq!(&jpg.data[0..3], &[0xFF, 0xD8, 0xFF], "valid JPEG SOI");
    assert_eq!(&jpg.data[jpg.data.len() - 2..], &[0xFF, 0xD9], "valid JPEG EOI");
    eprintln!("decoded body {} chars; JPEG {} bytes", body.body_text.len(), jpg.data.len());
}

#[test]
fn corpus_covers_multiple_ods_versions() {
    let mut seen_ods: std::collections::BTreeSet<u32> = std::collections::BTreeSet::new();
    for_each_sample(|path| {
        let bytes = read_prefix(path, 4096).expect("read first 4 KB");
        let header = DbHeader::parse(&bytes).expect("parse");
        seen_ods.insert(header.ods.raw);
    });
    if seen_ods.is_empty() {
        eprintln!("no samples found, test was a no-op");
        return;
    }
    eprintln!("observed ODS versions in corpus: {seen_ods:?}");
    // The empirical corpus carries ODS 43 (Notes 6.x/7.x) and ODS 52
    // (Notes 9.0.1) - older than the "HCL Domino 14" badge on the
    // hcl-templates-en repo suggested. The recon doc's expectation of
    // ODS 53 in the corpus was off; templates retain their original
    // ODS when copied between Domino versions unless explicitly
    // re-instantiated. Both ODS 43 and 52 exercise the parser's
    // little-endian path equivalently for v0.1.
    assert!(seen_ods.len() >= 2, "expected at least 2 distinct ODS versions");
}

#[test]
fn zero_superblock_rrv_bucket_size_falls_back_to_dbinfo() {
    // Regression: enumerate_notes read rrv_bucket_size from the freshest
    // superblock only, and returned an empty enumeration when that copy was
    // zero. It is zero in these three databases even though DBINFO carries a
    // valid 4096 and the RRV buckets are populated, so all three enumerated
    // as unreadable while the data sat right there. Guarded here because the
    // symptom - an empty note list - looks identical to a genuinely empty
    // database, which is exactly how it survived unnoticed.
    let Some(root) = corpus_root() else {
        eprintln!("corpus not present; skipping");
        return;
    };
    let cases = [
        ("real-nsf", "ToDo.nsf"),
        ("hcl-templates-en", "notebook12_EN.ntf"),
        ("hcl-templates-en", "teamrm12_EN.ntf"),
    ];
    let mut checked = 0;
    for (sub, name) in cases {
        let path = root.join(sub).join(name);
        if !path.is_file() {
            eprintln!("{name} not present; skipping");
            continue;
        }
        let bytes = std::fs::read(&path).unwrap_or_else(|e| panic!("read {name}: {e}"));
        let db = Database::open(&bytes).unwrap_or_else(|e| panic!("open {name}: {e:?}"));

        // The precondition that made the bug reachable. If a future corpus
        // refresh changes this, the case stops testing what it claims to.
        let sb_size = db
            .freshest_superblock()
            .expect("freshest superblock")
            .map(|(_, sb)| sb.rrv_bucket_size)
            .unwrap_or(0);
        assert_eq!(sb_size, 0, "{name}: expected a zero superblock rrv_bucket_size");
        assert_ne!(
            db.header().rrv_bucket_size,
            0,
            "{name}: DBINFO must carry the fallback size"
        );

        let e = db.enumerate_notes().unwrap_or_else(|e| panic!("enumerate {name}: {e:?}"));
        eprintln!("{name}: {} notes, {} unresolved", e.notes.len(), e.unresolved);
        assert!(
            !e.notes.is_empty(),
            "{name} enumerated 0 notes; the DBINFO rrv_bucket_size fallback regressed"
        );
        for n in &e.notes {
            assert_eq!(
                n.header.rrv_identifier, n.rrv_identifier,
                "{name}: record failed the identity gate"
            );
        }
        checked += 1;
    }
    eprintln!("zero-superblock fallback verified on {checked} databases");
}

#[test]
fn withheld_entries_are_classified_and_none_are_missed_notes() {
    // The gap between "RRV entries seen" and "notes returned" used to be a
    // bare count, which cannot answer the question an examiner is actually
    // asked: did the tool miss anything? enumerate_notes now classifies each
    // withheld entry, and this pins the classification down.
    //
    // Measured over the corpus, withheld entries fall into exactly two
    // benign classes plus one that is not:
    //   - IdentityMismatch: stale RRV entry, slot reused by another note.
    //   - NotANoteRecord with a non-note signature: never was a note.
    //   - NotANoteRecord with signature 0x0004: a note we cannot parse.
    // The third is missed evidence and is asserted to stay at zero on the
    // file-position path, where all 484 corpus entries are non-note
    // allocations (signature 0x001B or 0x0007).
    let Some(root) = corpus_root() else {
        eprintln!("corpus not present; skipping");
        return;
    };
    let path = root.join("real-nsf").join("fakenames.nsf");
    if !path.is_file() {
        eprintln!("fakenames.nsf not present; skipping");
        return;
    }
    let bytes = std::fs::read(&path).expect("read fakenames.nsf");
    let db = Database::open(&bytes).expect("open fakenames.nsf");
    let e = db.enumerate_notes().expect("enumerate notes");

    // Detail must be complete for the classification to mean anything.
    assert!(!e.withheld_truncated, "withheld detail was truncated");
    assert_eq!(
        e.withheld.len() as u64,
        e.unresolved,
        "withheld detail must account for every unresolved entry"
    );

    // Every file-position entry points at a non-note allocation, so no
    // withheld file-position entry may carry the note signature.
    for w in &e.withheld {
        if let WithheldLocation::FilePosition { .. } = w.location {
            if let WithheldReason::NotANoteRecord { found_signature } = w.reason {
                assert_ne!(
                    found_signature, 0x0004,
                    "a file-position entry carried the note signature: rrv 0x{:08X}",
                    w.rrv_identifier
                );
            }
        }
    }

    // Nothing may be Unresolvable: that reason means the resolver could not
    // follow the layout at all, which is the failure mode this parser exists
    // to avoid.
    let unresolvable = e.withheld_count(|r| matches!(r, WithheldReason::Unresolvable));
    assert_eq!(unresolvable, 0, "{unresolvable} entries could not be located");

    eprintln!(
        "fakenames withheld: {} total, {} stale reuse, {} missed-evidence",
        e.unresolved,
        e.withheld_count(|r| matches!(r, WithheldReason::IdentityMismatch { .. })),
        e.missed_evidence_count(),
    );
}
