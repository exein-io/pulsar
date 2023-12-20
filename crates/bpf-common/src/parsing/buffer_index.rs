//! `BufferIndex` points to a sub-slice of a buffer. It allows to refer to dynamically
//! sized arguments. It can be considered as a pointer, which allows to extract actual
//! data only when paired with the pointed at Bytes.

use bytes::Bytes;
use std::str::{from_utf8, Utf8Error};
use thiserror::Error;

#[derive(Debug)]
pub struct BufferIndex<T: ?Sized> {
    /// Start index of the slice
    start: u16,
    /// Length of the pointed-at slice
    len: u16,
    /// BufferIndex is marked with a generic argument, which  annotates what the pointed at
    /// buffer should be. Utility methods are added in `impl BufferIndex<T>` for making it
    /// easier to work with those resources.
    _data: std::marker::PhantomData<T>,
}

impl<T: ?Sized> BufferIndex<T> {
    /// Return length of the pointed at slice
    pub fn len(&self) -> usize {
        self.len as usize
    }

    /// Return if the slice is empty
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Given a buffer, try to extract the pointed at slice of bytes.
    /// Returns `Err(IndexError::IndexOutsideBuffer)` when buffer is too short.
    pub fn bytes<'a>(&self, buffer: &'a Bytes) -> Result<&'a [u8], IndexError> {
        let start = self.start as usize;
        let end = (self.start + self.len) as usize;
        if start <= end && end <= buffer.len() {
            Ok(&buffer[start..end])
        } else {
            Err(IndexError::IndexOutsideBuffer {
                start,
                end,
                len: buffer.len(),
            })
        }
    }
}

impl BufferIndex<str> {
    /// Try to parse the buffer pointed at as an utf8 string.
    /// Returns `Err(IndexError::NotAString)` when invalid utf8 characters are encountered.
    pub fn string(&self, buffer: &Bytes) -> Result<String, IndexError> {
        let bytes = self.bytes(buffer)?;
        let str = from_utf8(bytes).map_err(|err| IndexError::NotAString {
            error: err,
            bytes: bytes.to_vec(),
        })?;
        Ok(str.to_string())
    }
}

#[derive(Error, Debug, PartialEq, Eq)]
pub enum IndexError {
    #[error("Index [{start}-{end}] is out of event buffer (len {len})")]
    IndexOutsideBuffer {
        start: usize,
        end: usize,
        len: usize,
    },
    #[error("Index is not pointing to a valid string. {bytes:?} {error:?}")]
    NotAString {
        #[source]
        error: Utf8Error,
        bytes: Vec<u8>,
    },
}

#[cfg(feature = "test-suite")]
mod test_utils {
    use super::*;
    use crate::test_runner::ComparableField;

    // Allow comparing BufferIndex<[str]> to String
    impl ComparableField<String> for BufferIndex<str> {
        fn equals(&self, t: &String, buffer: &Bytes) -> bool {
            self.string(buffer).as_ref() == Ok(t)
        }
        fn repr(&self, buffer: &Bytes) -> String {
            format!("{:?}", self.string(buffer))
        }
    }

    // Allow comparing BufferIndex<[u8]> to Vec<u8>
    impl ComparableField<Vec<u8>> for BufferIndex<[u8]> {
        fn equals(&self, t: &Vec<u8>, buffer: &Bytes) -> bool {
            self.bytes(buffer) == Ok(t)
        }
        fn repr(&self, buffer: &Bytes) -> String {
            format!("{:?}", self.bytes(buffer))
        }
    }
}
