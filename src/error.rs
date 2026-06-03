//! Error taxonomy for the parser.
//!
//! Variants are stable across 0.x; new variants will be added rather than
//! existing ones renamed.

use std::fmt;

/// Top-level parser error.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NsfError {
    /// File is shorter than the minimum size required to even hold a
    /// valid NSF file header (6 bytes).
    TooShort {
        /// Bytes actually available.
        actual: usize,
        /// Bytes required for the operation that failed.
        required: usize,
    },
    /// The 2-byte file-header signature did not match the NSF LSIG marker
    /// (`0x1A 0x00`). Likely not an NSF file at all.
    BadFileSignature {
        /// The two bytes that were read at file offset 0.
        observed: [u8; 2],
    },
    /// The database-header-size field in the file header is implausible
    /// (zero, larger than any documented NSF, or larger than the file
    /// itself).
    BadHeaderSize {
        /// The size value read from the file header.
        size: u32,
    },
    /// A subrecord (superblock, bucket descriptor block, ...) signature
    /// check failed. Distinct from [`Self::BadFileSignature`] so the
    /// error message can identify which structure failed validation.
    BadSubrecordSignature {
        /// Short human-readable name of the structure whose signature
        /// failed (e.g. "superblock", "BDB header").
        kind: &'static str,
        /// Expected signature bytes (typically 2 bytes).
        expected: [u8; 2],
        /// Observed bytes at the signature position.
        observed: [u8; 2],
    },
    /// A structure required for the requested operation is stored
    /// compressed and the parser does not yet implement the compression
    /// scheme. The canonical case: on modern ODS the superblock body
    /// (which carries the bucket-descriptor array that maps a
    /// `bucket_index` to a file offset) is stored with Domino "CX"
    /// compression. Resolving an [`crate::RrvLocation::BucketSlot`] entry
    /// to bytes requires decompressing that body first. Until the CX
    /// decompressor lands, bucket-slot resolution returns this error
    /// rather than guessing - in a forensic context a wrong decompressor
    /// silently corrupts evidence, which is worse than an explicit
    /// not-yet-supported signal.
    CompressionUnsupported {
        /// Structure whose body is compressed (e.g. "superblock body").
        structure: &'static str,
        /// The compression-type value read from the structure header.
        compression_type: u16,
    },
    /// A `bucket_index` from an RRV entry is past the end of the parsed
    /// bucket-descriptor array. Indicates either corruption or a stale
    /// (non-freshest) superblock being consulted.
    BucketIndexOutOfRange {
        /// The bucket index requested.
        requested: u32,
        /// The number of bucket descriptors actually present.
        available: usize,
    },
    /// A `slot_index` from an RRV entry is outside the bucket's slot
    /// table. Slot indices are 1-based on disk; zero is never valid.
    SlotIndexOutOfRange {
        /// The slot index requested (1-based as stored on disk).
        requested: u16,
        /// The number of slots the bucket actually declares.
        available: u32,
    },
    /// Decompression of a compressed structure failed: the compressed
    /// stream was truncated, a back-reference pointed before the start of
    /// the output, or the declared output size was exceeded. Distinct from
    /// [`Self::CompressionUnsupported`] (which means "scheme not
    /// implemented"); this means "scheme implemented, but this input did
    /// not decode cleanly".
    DecompressionFailed {
        /// Short description of which invariant the stream violated.
        detail: &'static str,
    },
}

impl fmt::Display for NsfError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooShort { actual, required } => write!(
                f,
                "file too short: {actual} bytes available, {required} required"
            ),
            Self::BadFileSignature { observed } => write!(
                f,
                "not an NSF file: expected file-header signature 1A 00, got {:02X} {:02X}",
                observed[0], observed[1]
            ),
            Self::BadHeaderSize { size } => write!(
                f,
                "implausible database-header size in file header: {size}"
            ),
            Self::BadSubrecordSignature {
                kind,
                expected,
                observed,
            } => write!(
                f,
                "bad {kind} signature: expected {:02X} {:02X}, got {:02X} {:02X}",
                expected[0], expected[1], observed[0], observed[1]
            ),
            Self::CompressionUnsupported {
                structure,
                compression_type,
            } => write!(
                f,
                "{structure} is compressed (compression type {compression_type}); \
                 decompression not yet implemented"
            ),
            Self::BucketIndexOutOfRange {
                requested,
                available,
            } => write!(
                f,
                "bucket index {requested} out of range: {available} bucket descriptors present"
            ),
            Self::SlotIndexOutOfRange {
                requested,
                available,
            } => write!(
                f,
                "slot index {requested} out of range: bucket declares {available} slots"
            ),
            Self::DecompressionFailed { detail } => {
                write!(f, "decompression failed: {detail}")
            }
        }
    }
}

impl std::error::Error for NsfError {}
