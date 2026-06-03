//! File-identification: tell an NSF from a non-NSF without committing to
//! parsing the rest of the database.
//!
//! The NSF file header is 6 bytes at offset 0:
//!
//! ```text
//! offset  width  field
//! 0       2      LSIG signature, fixed `1A 00` (LE u16 = 0x001A)
//! 2       4      DB header size in bytes (LE u32), typically 256-4096
//! ```
//!
//! There is no ASCII magic; the format was never designed with a
//! human-readable identifier. NSF, NTF (template), NSG (web), and `.box`
//! files (e.g. `mail.box` on a Domino server) all share this header --
//! the file extension is the differentiator, not a magic byte. This
//! module reports the structural family ("file looks like an NSF") and
//! leaves extension classification to the caller.

use crate::error::NsfError;

/// LSIG signature byte 0 - always `0x1A` for valid NSFs.
pub const NSF_LSIG_BYTE_0: u8 = 0x1A;
/// LSIG signature byte 1 - always `0x00` for valid NSFs.
pub const NSF_LSIG_BYTE_1: u8 = 0x00;
/// Lower bound for a plausible DB-header-size field. Real Notes builds
/// have never been observed to use smaller. Documented as 256 bytes
/// minimum in the libnsfdb spec.
pub const MIN_PLAUSIBLE_DB_HEADER_SIZE: u32 = 64;
/// Upper bound for a plausible DB-header-size field. Real Notes builds
/// have never been observed to exceed ~4 KB; we accept up to 64 KB as a
/// safety margin while still rejecting obvious-garbage values.
pub const MAX_PLAUSIBLE_DB_HEADER_SIZE: u32 = 65_536;

/// Result of file-shape identification.
///
/// `Nsf` is returned only when the file-header signature matches AND the
/// declared DB-header-size is plausible. `NotNsf` carries a short reason
/// suitable for surfacing in an operator-facing modal.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FileKind {
    /// File looks like a valid NSF / NTF / NSG. Returned fields are read
    /// from the 6-byte file header; the rest of the file has not yet
    /// been parsed.
    Nsf {
        /// Database-header size in bytes as declared by the file header.
        /// This is the size of the DBINFO region that immediately
        /// follows the 6-byte file header.
        db_header_size: u32,
    },
    /// File is not an NSF (or is too short / structurally bogus to be
    /// one). `reason` is a single-sentence English description suitable
    /// for surfacing in a UI.
    NotNsf {
        /// Plain-language reason the file was rejected.
        reason: String,
    },
}

impl FileKind {
    /// True if the kind is [`FileKind::Nsf`].
    pub fn is_nsf(&self) -> bool {
        matches!(self, Self::Nsf { .. })
    }
}

/// Identify a file from its leading bytes.
///
/// Pass at least the first 6 bytes; passing more is fine and costs
/// nothing (extra bytes are ignored at this stage).
///
/// Returns [`FileKind::NotNsf`] -- not an error -- when the file is
/// recognizably not an NSF; an operator-facing tool wants to surface a
/// reason, not bail. The hard-error path on [`NsfError`] is reserved for
/// callers who specifically want the structured variant; most consumers
/// should prefer this function.
pub fn identify_file(bytes: &[u8]) -> FileKind {
    match identify_file_strict(bytes) {
        Ok(kind) => kind,
        Err(e) => FileKind::NotNsf {
            reason: e.to_string(),
        },
    }
}

/// Strict variant of [`identify_file`] that returns the structured error
/// instead of folding it into a `NotNsf { reason }`. Useful for callers
/// that want to programmatically distinguish "too short" from "wrong
/// signature" from "implausible header size".
pub fn identify_file_strict(bytes: &[u8]) -> Result<FileKind, NsfError> {
    if bytes.len() < 6 {
        return Err(NsfError::TooShort {
            actual: bytes.len(),
            required: 6,
        });
    }
    if bytes[0] != NSF_LSIG_BYTE_0 || bytes[1] != NSF_LSIG_BYTE_1 {
        return Err(NsfError::BadFileSignature {
            observed: [bytes[0], bytes[1]],
        });
    }
    let db_header_size = u32::from_le_bytes([bytes[2], bytes[3], bytes[4], bytes[5]]);
    if db_header_size < MIN_PLAUSIBLE_DB_HEADER_SIZE
        || db_header_size > MAX_PLAUSIBLE_DB_HEADER_SIZE
    {
        return Err(NsfError::BadHeaderSize {
            size: db_header_size,
        });
    }
    Ok(FileKind::Nsf { db_header_size })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Minimal valid-looking file header: LSIG `1A 00`, DB header size = 256.
    fn ok_header() -> Vec<u8> {
        let mut v = vec![0u8; 16];
        v[0] = 0x1A;
        v[1] = 0x00;
        // db_header_size = 256 (LE)
        v[2] = 0x00;
        v[3] = 0x01;
        v[4] = 0x00;
        v[5] = 0x00;
        v
    }

    #[test]
    fn identifies_valid_nsf_header() {
        let h = ok_header();
        let kind = identify_file(&h);
        assert!(kind.is_nsf());
        match kind {
            FileKind::Nsf { db_header_size } => assert_eq!(db_header_size, 256),
            _ => unreachable!(),
        }
    }

    #[test]
    fn rejects_too_short_file() {
        let kind = identify_file(&[0x1A, 0x00, 0x00]);
        assert!(!kind.is_nsf());
        match kind {
            FileKind::NotNsf { reason } => assert!(reason.contains("too short")),
            _ => unreachable!(),
        }
    }

    #[test]
    fn rejects_bad_signature() {
        let mut h = ok_header();
        h[0] = 0x21; // !BDN magic - common confusion with PST
        h[1] = 0x42;
        let kind = identify_file(&h);
        assert!(!kind.is_nsf());
        match kind {
            FileKind::NotNsf { reason } => {
                assert!(reason.contains("21 42"));
                assert!(reason.contains("1A 00"));
            }
            _ => unreachable!(),
        }
    }

    #[test]
    fn rejects_zero_header_size() {
        let mut h = ok_header();
        h[2] = 0x00;
        h[3] = 0x00;
        h[4] = 0x00;
        h[5] = 0x00;
        let kind = identify_file(&h);
        assert!(!kind.is_nsf());
        match kind {
            FileKind::NotNsf { reason } => assert!(reason.contains("implausible")),
            _ => unreachable!(),
        }
    }

    #[test]
    fn rejects_impossibly_large_header_size() {
        let mut h = ok_header();
        // 4 GB header? definitely not.
        h[2] = 0xFF;
        h[3] = 0xFF;
        h[4] = 0xFF;
        h[5] = 0xFF;
        let kind = identify_file(&h);
        assert!(!kind.is_nsf());
    }

    #[test]
    fn strict_variant_returns_structured_error() {
        let mut h = ok_header();
        h[0] = 0xDE;
        h[1] = 0xAD;
        let err = identify_file_strict(&h).unwrap_err();
        assert!(matches!(
            err,
            NsfError::BadFileSignature { observed: [0xDE, 0xAD] }
        ));
    }

    #[test]
    fn accepts_extra_bytes_after_header() {
        let mut h = ok_header();
        h.extend_from_slice(&[0xAA; 100_000]);
        let kind = identify_file(&h);
        assert!(kind.is_nsf());
    }
}
