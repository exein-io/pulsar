//! Checked access to one record read from the ring.
//!
//! Layouts come from the generated [`crate::abi`] types and every read is a
//! bounds-checked copy, so a short or malformed record is an error, never a
//! panic or an out-of-bounds read.

use std::{
    borrow::Cow,
    mem::{align_of, size_of},
};

use thiserror::Error;
use zerocopy::FromBytes;

use crate::{
    ProducerId,
    abi::{
        PULSAR_F_UNATTRIBUTED, PULSAR_FIELD_MISSING, PULSAR_FIELD_PRESENT, PULSAR_FIELD_TRUNCATED,
        pulsar_buffer_index, pulsar_record_header, pulsar_subject, pulsar_tail,
    },
};

/// Bytes before the body of every record.
pub const HEADER_SIZE: usize = size_of::<pulsar_record_header>();

/// Offset of the `pulsar_tail` after a body of type `B`, as C lays out
/// `struct { struct pulsar_record_header header; B body; struct pulsar_tail tail; }`.
pub const fn tail_offset<B>() -> usize {
    (HEADER_SIZE + size_of::<B>()).next_multiple_of(align_of::<pulsar_tail>())
}

#[derive(Debug, Error)]
pub enum DecodeError {
    #[error("record of {len} bytes, at least {needed} expected")]
    Short { len: usize, needed: usize },
    #[error("header gives {header} bytes, the ring delivered {ring}")]
    SizeMismatch { header: u32, ring: usize },
    #[error("tail announces {announced} bytes, the record has {present}")]
    TailMismatch { announced: u32, present: usize },
    #[error("field at {start}+{len} is outside the {tail} tail bytes")]
    FieldOutOfBounds { start: u16, len: u16, tail: usize },
    #[error("unknown field status {0}")]
    FieldStatus(u32),
    #[error("producer {producer} has no kind {kind}")]
    UnknownKind { producer: ProducerId, kind: u32 },
}

/// A record whose size matches its header.
#[derive(Clone, Copy)]
pub struct RecordView<'a> {
    header: pulsar_record_header,
    bytes: &'a [u8],
}

impl<'a> RecordView<'a> {
    pub fn parse(bytes: &'a [u8]) -> Result<Self, DecodeError> {
        let (header, _) =
            pulsar_record_header::read_from_prefix(bytes).map_err(|_| DecodeError::Short {
                len: bytes.len(),
                needed: HEADER_SIZE,
            })?;
        if header.size as usize != bytes.len() {
            return Err(DecodeError::SizeMismatch {
                header: header.size,
                ring: bytes.len(),
            });
        }
        Ok(Self { header, bytes })
    }

    pub fn header(&self) -> &pulsar_record_header {
        &self.header
    }

    pub fn producer(&self) -> ProducerId {
        ProducerId(self.header.producer.into())
    }

    pub fn kind(&self) -> u32 {
        self.header.kind.into()
    }

    /// The process the record is about, unless the probe couldn't tell.
    pub fn subject(&self) -> Option<&pulsar_subject> {
        (self.header.flags & PULSAR_F_UNATTRIBUTED == 0).then_some(&self.header.subject)
    }

    /// The body of the record.
    pub fn body<B: FromBytes>(&self) -> Result<B, DecodeError> {
        B::read_from_prefix(&self.bytes[HEADER_SIZE..])
            .map(|(body, _)| body)
            .map_err(|_| DecodeError::Short {
                len: self.bytes.len(),
                needed: HEADER_SIZE + size_of::<B>(),
            })
    }

    /// The body and the tail of a variable-size record.
    pub fn body_and_tail<B: FromBytes>(&self) -> Result<(B, Tail<'a>), DecodeError> {
        let body = self.body::<B>()?;
        let offset = tail_offset::<B>();
        let data_start = offset + size_of::<pulsar_tail>();
        let short = DecodeError::Short {
            len: self.bytes.len(),
            needed: data_start,
        };
        let (tail, data) = self
            .bytes
            .get(offset..)
            .and_then(|bytes| pulsar_tail::read_from_prefix(bytes).ok())
            .ok_or(short)?;
        if tail.len as usize != data.len() {
            return Err(DecodeError::TailMismatch {
                announced: tail.len,
                present: data.len(),
            });
        }
        Ok((body, Tail { data }))
    }
}

/// The bytes after the body of a variable-size record.
#[derive(Clone, Copy)]
pub struct Tail<'a> {
    data: &'a [u8],
}

impl<'a> Tail<'a> {
    /// The field `index` points to, or `None` when the probe couldn't read it.
    pub fn field(&self, index: &pulsar_buffer_index) -> Result<Option<Field<'a>>, DecodeError> {
        let truncated = match u32::from(index.status) {
            PULSAR_FIELD_MISSING => return Ok(None),
            PULSAR_FIELD_PRESENT => false,
            PULSAR_FIELD_TRUNCATED => true,
            status => return Err(DecodeError::FieldStatus(status)),
        };
        let start = usize::from(index.start);
        let bytes = self.data.get(start..start + usize::from(index.len)).ok_or(
            DecodeError::FieldOutOfBounds {
                start: index.start,
                len: index.len,
                tail: self.data.len(),
            },
        )?;
        Ok(Some(Field { bytes, truncated }))
    }
}

/// A variable-size field. When `truncated`, `bytes` is only its beginning.
#[derive(Clone, Copy, Debug)]
pub struct Field<'a> {
    pub bytes: &'a [u8],
    pub truncated: bool,
}

impl<'a> Field<'a> {
    pub fn to_string_lossy(&self) -> Cow<'a, str> {
        String::from_utf8_lossy(self.bytes)
    }

    /// The NUL-separated strings of the field, like `argv`.
    pub fn split_nul(&self) -> impl Iterator<Item = Cow<'a, str>> {
        let bytes = self.bytes.strip_suffix(&[0]).unwrap_or(self.bytes);
        bytes
            .split(|byte| *byte == 0)
            .filter(move |_| !bytes.is_empty())
            .map(String::from_utf8_lossy)
    }
}
