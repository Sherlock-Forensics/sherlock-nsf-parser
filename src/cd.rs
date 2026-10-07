//! Composite Data (CD) record parsing - Lotus Notes rich text + attachments.
//!
//! A note's non-summary data object (see [`crate::Database::non_summary_data`])
//! is a CD-record stream that begins after the object's fixed 68-byte header.
//! CD records carry the rich-text `$Body` (CDTEXT records) and embedded
//! file/image attachments (CDFILEHEADER/CDFILESEGMENT, CDIMAGEHEADER/
//! CDIMAGESEGMENT).
//!
//! CD records are NOT part of libnsfdb (which is container-level only); this
//! was reverse-engineered against fakenames.nsf and cross-checked with the HCL
//! Notes C API "Composite Data" reference. Validated end to end: a rich-text
//! body decodes to its prose, and a 1.4 MB JPEG reconstructs from 137 image
//! segments to a byte-valid `FF D8 ... FF D9` file.
//!
//! ## Record framing
//!
//! The byte immediately after the 1-byte signature selects the length class:
//!
//! ```text
//! 0xFF -> WSIG: [sig:u8][0xFF][len:u16]   (4-byte header)
//! 0x00 -> LSIG: [sig:u8][0x00][len:u32]   (6-byte header)
//! else -> BSIG: [sig:u8][len:u8]          (2-byte header)
//! ```
//!
//! `len` is the total record size including the header. Records are padded to
//! an even (WORD) boundary: advance by `len + (len & 1)`.

/// CD-record stream offset within a non-summary object (past its 68-byte
/// header).
pub const CD_STREAM_START: usize = 0x44;

// Signature low-byte constants.
const SIG_TEXT: u8 = 0x85;
/// CDPARAGRAPH. Its presence IS the paragraph break; the payload carries
/// nothing a renderer needs, which is why the flattened text has newlines
/// and why a structured body has to see the record at all.
const SIG_PARAGRAPH: u8 = 0x6D;
const SIG_IMAGEHEADER: u8 = 0x7D;
const SIG_IMAGESEGMENT: u8 = 0x7C;
const SIG_FILEHEADER: u8 = 0xA9;
const SIG_FILESEGMENT: u8 = 0xAA;

/// One CD record: its signature byte and the bytes after the framing header.
#[derive(Debug, Clone, Copy)]
pub struct CdRecord<'a> {
    /// Signature low byte (the `SIG_CD_*` type).
    pub sig: u8,
    /// Record payload (between the framing header and the record end).
    pub body: &'a [u8],
}

/// Walk the CD-record stream of a non-summary object (records start at
/// [`CD_STREAM_START`]). Stops cleanly at a malformed / trailing-filler region.
pub fn walk(obj: &[u8]) -> Vec<CdRecord<'_>> {
    walk_from(obj, CD_STREAM_START)
}

fn walk_from(obj: &[u8], start: usize) -> Vec<CdRecord<'_>> {
    let mut i = start;
    let mut out = Vec::new();
    while i + 2 <= obj.len() {
        let sig = obj[i];
        let (hdr, total) = match obj[i + 1] {
            0xFF => {
                if i + 4 > obj.len() {
                    break;
                }
                (4usize, u16::from_le_bytes([obj[i + 2], obj[i + 3]]) as usize)
            }
            0x00 => {
                if i + 6 > obj.len() {
                    break;
                }
                (
                    6usize,
                    u32::from_le_bytes([obj[i + 2], obj[i + 3], obj[i + 4], obj[i + 5]]) as usize,
                )
            }
            b1 => (2usize, b1 as usize),
        };
        if total < hdr || i + total > obj.len() {
            break;
        }
        out.push(CdRecord {
            sig,
            body: &obj[i + hdr..i + total],
        });
        i += total + (total & 1); // even-boundary padding
    }
    out
}

/// What kind of object an [`Attachment`] reconstructs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AttachmentKind {
    /// Embedded image (CDIMAGEHEADER/CDIMAGESEGMENT).
    Image,
    /// File attachment (CDFILEHEADER/CDFILESEGMENT).
    File,
}

/// A reconstructed attachment: suggested name + raw bytes.
#[derive(Debug, Clone)]
pub struct Attachment {
    /// File name (from CDFILEHEADER) or a synthesized `image_N.ext`.
    pub name: String,
    /// Reassembled bytes.
    ///
    /// Empty when the CD stream names a file but carries none of it. That
    /// is not a decoding failure: measured on fakenames.nsf, those notes'
    /// CDFILESEGMENT records have zero-length bodies, so the bytes are not
    /// in the rich-text stream at all - Notes keeps the attachment in a
    /// separate file object, which this build does not yet resolve. A
    /// consumer must report such an attachment as PRESENT WITH NO CONTENT
    /// RECOVERED, never as an empty file.
    pub data: Vec<u8>,
    /// Image vs file.
    pub kind: AttachmentKind,
}

/// Character emphasis carried in a CDTEXT run's FONTID attributes.
///
/// Read from the 4-byte FONTID prefix the plain-text rendering skips. Only
/// the attributes that survive into any sane rendering are exposed: colour,
/// face and point size deliberately are not, because reproducing a font
/// stack is presentation rather than evidence.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct RunStyle {
    pub bold: bool,
    pub italic: bool,
    pub underline: bool,
    pub strikethrough: bool,
}

impl RunStyle {
    /// Decode FONTIDFIELDS.Attrib.
    pub fn from_attrib(attrib: u8) -> Self {
        Self {
            bold: attrib & 0x01 != 0,
            italic: attrib & 0x02 != 0,
            underline: attrib & 0x04 != 0,
            strikethrough: attrib & 0x08 != 0,
        }
    }

    pub fn is_plain(&self) -> bool {
        *self == Self::default()
    }
}

/// One run of body text with the emphasis it was written with.
#[derive(Debug, Clone, Default)]
pub struct BodyRun {
    pub text: String,
    pub style: RunStyle,
    /// True when a paragraph boundary was recorded before this run.
    pub paragraph_break_before: bool,
}

/// Decoded rich-text + attachments of a note's non-summary object.
#[derive(Debug, Clone, Default)]
pub struct NoteContent {
    /// Plain-text rendering of the CDTEXT runs (the rich-text body).
    pub body_text: String,
    /// The same body as styled runs, in document order.
    ///
    /// `body_text` stays the flattened rendering every existing caller
    /// expects; this is the structure it was flattened from, so a consumer
    /// that can show emphasis does not have to re-walk the stream.
    pub runs: Vec<BodyRun>,
    /// Embedded images and file attachments.
    pub attachments: Vec<Attachment>,
}

impl NoteContent {
    /// True when there is neither body text nor any attachment.
    pub fn is_empty(&self) -> bool {
        self.body_text.trim().is_empty() && self.attachments.is_empty()
    }
}

/// Extension implied by the CDIMAGEHEADER image-type code.
///
/// Only a fallback: the code is not reliable. Across the corpus 81 images
/// carrying type 2 (JPEG) are PNG data, so this is consulted only when the
/// reassembled bytes match no known signature.
fn image_ext_from_type(image_type: u16) -> &'static str {
    match image_type {
        1 => "gif",
        2 => "jpg",
        3 => "bmp",
        4 => "png",
        _ => "img",
    }
}

/// Extension implied by the reassembled bytes themselves.
///
/// Preferred over the declared type code because the bytes are what the
/// operator will export and open. Naming PNG data `image_3.jpg` mislabels an
/// artifact that a downstream tool then refuses to open, and in an
/// evidentiary export a wrong extension is a wrong claim about the file.
fn image_ext_from_magic(data: &[u8]) -> Option<&'static str> {
    // Byte values rather than escaped literals: these signatures are binary,
    // and an escape that survives one editing pass wrong becomes a signature
    // that silently never matches.
    const PNG: &[u8] = &[0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A];
    const JPG: &[u8] = &[0xFF, 0xD8, 0xFF];
    const GIF87: &[u8] = b"GIF87a";
    const GIF89: &[u8] = b"GIF89a";
    const BMP: &[u8] = b"BM";
    const TIF_LE: &[u8] = &[0x49, 0x49, 0x2A, 0x00];
    const TIF_BE: &[u8] = &[0x4D, 0x4D, 0x00, 0x2A];
    const RIFF: &[u8] = b"RIFF";
    const SIGS: &[(&[u8], &str)] = &[
        (PNG, "png"),
        (JPG, "jpg"),
        (GIF87, "gif"),
        (GIF89, "gif"),
        (BMP, "bmp"),
        (TIF_LE, "tif"),
        (TIF_BE, "tif"),
        (RIFF, "webp"),
    ];
    for (sig, ext) in SIGS {
        if data.starts_with(sig) {
            // RIFF is a container; only call it webp when it says so.
            if *ext == "webp" && !(data.len() >= 12 && &data[8..12] == b"WEBP") {
                continue;
            }
            return Some(ext);
        }
    }
    None
}

/// Extension for a reconstructed image: content first, declared type as the
/// fallback.
fn image_ext(image_type: u16, data: &[u8]) -> &'static str {
    image_ext_from_magic(data).unwrap_or_else(|| image_ext_from_type(image_type))
}

/// First >= 3-char printable run in a CDFILEHEADER body (the file name).
fn file_name(body: &[u8]) -> Option<String> {
    let mut i = 0;
    while i < body.len() {
        if body[i].is_ascii_graphic() || body[i] == b' ' {
            let s = i;
            while i < body.len() && (body[i].is_ascii_graphic() || body[i] == b' ') {
                i += 1;
            }
            if i - s >= 3 {
                return Some(String::from_utf8_lossy(&body[s..i]).into_owned());
            }
        } else {
            i += 1;
        }
    }
    None
}

/// Parse a non-summary object into its rich-text body + attachments.
pub fn parse(obj: &[u8]) -> NoteContent {
    parse_records(walk(obj))
}

/// Parse the values of rich-text (TYPE_COMPOSITE) items directly, for a
/// database whose non-summary data is the bare item values with no object
/// header around them (pre-Notes 5). Each value opens with its 2-byte type
/// word, then CD records; each is walked on its own so one item's padding
/// cannot shift the next item's records.
pub fn parse_items(values: &[&[u8]]) -> NoteContent {
    let mut recs = Vec::new();
    for v in values {
        if let Some(stream) = v.get(2..) {
            recs.extend(walk_from(stream, 0));
        }
    }
    parse_records(recs)
}

fn parse_records(recs: Vec<CdRecord<'_>>) -> NoteContent {
    let mut content = NoteContent::default();

    // Body text: concatenate CDTEXT runs (4-byte FONTID prefix, then LMBCS;
    // we emit printable ASCII and treat NUL as a run separator). The FONTID
    // prefix the flattened text skips carries the emphasis, so the same pass
    // records the runs it was flattened from.
    let mut pending_break = false;
    for r in recs.iter().filter(|r| r.sig == SIG_TEXT || r.sig == SIG_PARAGRAPH) {
        if r.sig == SIG_PARAGRAPH {
            pending_break = true;
            continue;
        }
        // FONTIDFIELDS: Face, Attrib, Color, PointSize.
        let style = RunStyle::from_attrib(r.body.get(1).copied().unwrap_or(0));
        let text = r.body.get(4..).unwrap_or(&[]);
        let mut run = String::new();
        for &b in text {
            match b {
                0x09 | 0x0A | 0x0D | 0x20..=0x7E => run.push(b as char),
                _ => {}
            }
        }
        content.body_text.push_str(&run);
        content.body_text.push('\n');
        if !run.is_empty() {
            content.runs.push(BodyRun {
                text: run,
                style,
                paragraph_break_before: pending_break,
            });
            pending_break = false;
        }
    }
    while content.body_text.ends_with('\n') {
        content.body_text.pop();
    }

    // Attachments: a single pass that groups segments under the most recent
    // image/file header.
    let mut cur_image: Option<(u16, Vec<u8>)> = None;
    let mut cur_file: Option<(String, Vec<u8>)> = None;
    let mut img_n = 0usize;
    let finish_image = |content: &mut NoteContent, img: Option<(u16, Vec<u8>)>, n: &mut usize| {
        if let Some((ty, data)) = img {
            if !data.is_empty() {
                *n += 1;
                content.attachments.push(Attachment {
                    name: format!("image_{n}.{}", image_ext(ty, &data)),
                    data,
                    kind: AttachmentKind::Image,
                });
            }
        }
    };
    let finish_file = |content: &mut NoteContent, file: Option<(String, Vec<u8>)>| {
        if let Some((name, data)) = file {
            content.attachments.push(Attachment {
                name,
                data,
                kind: AttachmentKind::File,
            });
        }
    };

    for r in &recs {
        match r.sig {
            SIG_IMAGEHEADER => {
                finish_image(&mut content, cur_image.take(), &mut img_n);
                finish_file(&mut content, cur_file.take());
                let ty = if r.body.len() >= 2 {
                    u16::from_le_bytes([r.body[0], r.body[1]])
                } else {
                    0
                };
                cur_image = Some((ty, Vec::new()));
            }
            SIG_IMAGESEGMENT => {
                if let Some((_, data)) = cur_image.as_mut() {
                    if r.body.len() >= 4 {
                        let data_size = u16::from_le_bytes([r.body[0], r.body[1]]) as usize;
                        let seg = r.body.get(4..4 + data_size).unwrap_or(&r.body[4..]);
                        data.extend_from_slice(seg);
                    }
                }
            }
            SIG_FILEHEADER => {
                finish_image(&mut content, cur_image.take(), &mut img_n);
                finish_file(&mut content, cur_file.take());
                let name = file_name(r.body).unwrap_or_else(|| "attachment.bin".to_string());
                cur_file = Some((name, Vec::new()));
            }
            SIG_FILESEGMENT => {
                if let Some((_, data)) = cur_file.as_mut() {
                    data.extend_from_slice(r.body);
                }
            }
            _ => {}
        }
    }
    finish_image(&mut content, cur_image.take(), &mut img_n);
    finish_file(&mut content, cur_file.take());

    content
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn walk_empty_object_is_safe() {
        assert!(walk(&[]).is_empty());
        assert!(walk(&[0u8; 10]).is_empty());
    }

    #[test]
    fn parse_empty_is_empty() {
        assert!(parse(&[0u8; 0x44]).is_empty());
    }
}

#[cfg(test)]
mod image_ext_tests {
    use super::*;

    const PNG_BYTES: [u8; 8] = [0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A];
    const JPG_BYTES: [u8; 3] = [0xFF, 0xD8, 0xFF];

    #[test]
    fn content_overrides_a_wrong_declared_type() {
        // The case that motivated this: across the corpus 81 images declare
        // CDIMAGEHEADER type 2 (JPEG) and hold PNG data. Naming those
        // image_N.jpg mislabels every one of them on export.
        assert_eq!(image_ext(2, &PNG_BYTES), "png");
        assert_eq!(image_ext(1, &PNG_BYTES), "png");
    }

    #[test]
    fn declared_type_is_used_when_the_bytes_say_nothing() {
        assert_eq!(image_ext(1, b"not a known signature"), "gif");
        assert_eq!(image_ext(2, b"not a known signature"), "jpg");
        assert_eq!(image_ext(3, b"not a known signature"), "bmp");
        assert_eq!(image_ext(4, b"not a known signature"), "png");
        assert_eq!(image_ext(99, b"not a known signature"), "img");
    }

    #[test]
    fn empty_data_falls_back_to_the_declared_type() {
        assert_eq!(image_ext(2, &[]), "jpg");
    }

    #[test]
    fn recognises_the_common_signatures() {
        assert_eq!(image_ext_from_magic(&JPG_BYTES), Some("jpg"));
        assert_eq!(image_ext_from_magic(b"GIF89a...."), Some("gif"));
        assert_eq!(image_ext_from_magic(b"GIF87a...."), Some("gif"));
        assert_eq!(image_ext_from_magic(b"BM.."), Some("bmp"));
        assert_eq!(image_ext_from_magic(&[0x49, 0x49, 0x2A, 0x00]), Some("tif"));
        assert_eq!(image_ext_from_magic(b"no"), None);
    }

    #[test]
    fn riff_is_only_webp_when_it_says_webp() {
        // A RIFF container can be WAV or AVI; claiming webp on the container
        // magic alone would rename audio to an image extension.
        assert_eq!(image_ext_from_magic(b"RIFF____WEBPmore"), Some("webp"));
        assert_eq!(image_ext_from_magic(b"RIFF____WAVEfmt "), None);
    }
}

#[cfg(test)]
mod run_tests {
    use super::*;

    #[test]
    fn font_attributes_decode_to_the_emphasis_they_mean() {
        assert!(RunStyle::from_attrib(0x00).is_plain());
        assert!(RunStyle::from_attrib(0x01).bold);
        assert!(RunStyle::from_attrib(0x02).italic);
        assert!(RunStyle::from_attrib(0x04).underline);
        assert!(RunStyle::from_attrib(0x08).strikethrough);
        let both = RunStyle::from_attrib(0x03);
        assert!(both.bold && both.italic && !both.underline);
    }

    /// Measure what the corpus actually carries, rather than assuming rich
    /// text is rich. The number decides whether rendering emphasis is worth
    /// anything on real evidence.
    #[test]
    #[ignore = "diagnostic: prints the CD signature histogram"]
    fn corpus_signature_histogram() {
        let root = std::env::var_os("NSF_CORPUS_DIR")
            .map(std::path::PathBuf::from)
            .unwrap_or_else(|| {
                std::path::PathBuf::from(r"C:\SherlockForensics")
                    .join(".scratch")
                    .join("nsf-samples")
            });
        let path = root.join("real-nsf").join("fakenames.nsf");
        if !path.is_file() {
            return;
        }
        let bytes = std::fs::read(&path).expect("read");
        let db = crate::Database::open(&bytes).expect("open");
        let en = db.enumerate_notes().expect("enumerate");
        let mut hist: std::collections::BTreeMap<u8, usize> = Default::default();
        for n in en.notes.iter().take(4000) {
            let Some(obj) = db.non_summary_data(n) else { continue };
            for r in walk(&obj) {
                *hist.entry(r.sig).or_default() += 1;
            }
        }
        for (sig, n) in &hist {
            eprintln!("  sig 0x{sig:02X}  {n}");
        }
    }

    /// Pin the measured shape of a name-only attachment, so the doc claim
    /// above cannot drift back to "an encoding we cannot decode".
    #[test]
    fn a_file_segment_with_no_body_yields_a_named_attachment_with_no_bytes() {
        // A CD stream with a file header and an EMPTY segment, which is what
        // fakenames.nsf actually carries for six attachments.
        let mut obj = vec![0u8; CD_STREAM_START];
        // CDFILEHEADER, BSIG framing: [sig][len][body...]
        let name = b"report.bin";
        let mut header_body = vec![0u8; 8];
        header_body.extend_from_slice(name);
        obj.push(SIG_FILEHEADER);
        obj.push((2 + header_body.len()) as u8);
        obj.extend_from_slice(&header_body);
        // CDFILESEGMENT with a zero-length body.
        obj.push(SIG_FILESEGMENT);
        obj.push(2);

        let content = parse(&obj);
        assert_eq!(content.attachments.len(), 1);
        let a = &content.attachments[0];
        assert_eq!(a.name, "report.bin");
        assert!(a.data.is_empty(), "there were no bytes to recover");
        assert_eq!(a.kind, AttachmentKind::File);
    }

    #[test]
    fn a_file_segment_with_a_body_recovers_its_bytes() {
        let mut obj = vec![0u8; CD_STREAM_START];
        let mut header_body = vec![0u8; 8];
        header_body.extend_from_slice(b"note.txt");
        obj.push(SIG_FILEHEADER);
        obj.push((2 + header_body.len()) as u8);
        obj.extend_from_slice(&header_body);
        let payload = b"hello world";
        obj.push(SIG_FILESEGMENT);
        obj.push((2 + payload.len()) as u8);
        obj.extend_from_slice(payload);

        let content = parse(&obj);
        assert_eq!(content.attachments.len(), 1);
        assert_eq!(content.attachments[0].data, payload.to_vec());
    }

    #[test]
    #[ignore = "diagnostic: why does the attachment note report zero items?"]
    fn diagnose_zero_item_note() {
        let root = std::env::var_os("NSF_CORPUS_DIR")
            .map(std::path::PathBuf::from)
            .unwrap_or_else(|| {
                std::path::PathBuf::from(r"C:\SherlockForensics")
                    .join(".scratch")
                    .join("nsf-samples")
            });
        let path = root.join("real-nsf").join("fakenames.nsf");
        if !path.is_file() {
            return;
        }
        let bytes = std::fs::read(&path).expect("read");
        let db = crate::Database::open(&bytes).expect("open");
        let en = db.enumerate_notes().expect("enumerate");
        for n in en.notes.iter().filter(|n| db.note_items(n).is_empty()) {
            eprintln!(
                "note 0x{:08X} class 0x{:04X} size {} items_field {} nonsummary {} at 0x{:X}",
                n.rrv_identifier,
                n.header.note_class,
                n.header.size,
                n.header.number_of_note_items,
                n.header.non_summary_data_size,
                n.file_offset
            );
            let start = n.file_offset as usize;
            let end = (start + n.header.size as usize).min(bytes.len());
            let rec = &bytes[start..end];
            let head: Vec<String> = rec.iter().take(140).map(|b| format!("{b:02X}")).collect();
            eprintln!("   first bytes: {}", head.join(" "));
        }
    }

    #[test]
    fn corpus_bodies_decompose_into_runs() {
        let root = std::env::var_os("NSF_CORPUS_DIR")
            .map(std::path::PathBuf::from)
            .unwrap_or_else(|| {
                std::path::PathBuf::from(r"C:\SherlockForensics")
                    .join(".scratch")
                    .join("nsf-samples")
            });
        let path = root.join("real-nsf").join("fakenames.nsf");
        if !path.is_file() {
            eprintln!("corpus not present; skipping");
            return;
        }
        let bytes = std::fs::read(&path).expect("read");
        let db = crate::Database::open(&bytes).expect("open");
        let en = db.enumerate_notes().expect("enumerate");
        let mut notes_with_body = 0usize;
        let mut runs = 0usize;
        let mut styled = 0usize;
        let mut breaks = 0usize;
        for n in en.notes.iter().take(4000) {
            let Some(c) = db.note_content(n) else { continue };
            if c.runs.is_empty() {
                continue;
            }
            notes_with_body += 1;
            runs += c.runs.len();
            styled += c.runs.iter().filter(|r| !r.style.is_plain()).count();
            breaks += c.runs.iter().filter(|r| r.paragraph_break_before).count();
            // The flattened text must still contain every run's text, or the
            // two renderings disagree about what the body says.
            for r in &c.runs {
                assert!(
                    c.body_text.contains(r.text.trim_end_matches('\n')) || r.text.trim().is_empty(),
                    "run text missing from the flattened body"
                );
            }
        }
        eprintln!(
            "corpus bodies: {notes_with_body} notes, {runs} runs, {styled} styled, {breaks} paragraph breaks"
        );
        assert!(notes_with_body > 0, "the corpus should hold rich-text bodies");
    }
}
