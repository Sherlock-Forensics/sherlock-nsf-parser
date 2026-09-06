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
    let mut i = CD_STREAM_START;
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
    /// Reassembled bytes. May be empty for file variants whose segment
    /// encoding is not yet decoded (the name is still recovered).
    pub data: Vec<u8>,
    /// Image vs file.
    pub kind: AttachmentKind,
}

/// Decoded rich-text + attachments of a note's non-summary object.
#[derive(Debug, Clone, Default)]
pub struct NoteContent {
    /// Plain-text rendering of the CDTEXT runs (the rich-text body).
    pub body_text: String,
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
    let recs = walk(obj);
    let mut content = NoteContent::default();

    // Body text: concatenate CDTEXT runs (4-byte font/style prefix, then LMBCS;
    // we emit printable ASCII and treat NUL as a run separator).
    for r in recs.iter().filter(|r| r.sig == SIG_TEXT) {
        let text = r.body.get(4..).unwrap_or(&[]);
        for &b in text {
            match b {
                0x09 | 0x0A | 0x0D | 0x20..=0x7E => content.body_text.push(b as char),
                _ => {}
            }
        }
        content.body_text.push('\n');
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
