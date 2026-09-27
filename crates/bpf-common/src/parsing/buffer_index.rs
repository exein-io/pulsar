//! `BufferIndex` points to a sub-slice of a buffer. It allows to refer to dynamically
//! sized arguments. It can be considered as a pointer, which allows to extract actual
//! data only when paired with the pointed at Bytes.

use bytes::Bytes;
use std::str::{Utf8Error, from_utf8};
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

#[cfg(feature = "test-utils")]
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

// Unit tests
#[cfg(test)]
mod tests {
    use std::marker::PhantomData;

    use bytes::Bytes;

    use super::*;

    // Allows to construct a `BufferIndex` directly. Done here
    // so that private field are accesed without hacks.
    fn index<T: ?Sized>(start: u16, len: u16) -> BufferIndex<T> {
        BufferIndex {
            start,
            len,
            _data: PhantomData,
        }
    }

    #[test]
    fn in_bounds_slice_is_extraced() {
        let buffer = Bytes::from_static(b"hello random string");
        let index: BufferIndex<[u8]> = index(0, 5);
        assert_eq!(index.bytes(&buffer).unwrap(), b"hello");
    }

    #[test]
    fn zero_length_slice_at_end_of_buffer_is_ok() {
        let buffer = Bytes::from_static(b"hello");
        let index: BufferIndex<[u8]> = index(5, 0);
        assert!(index.bytes(&buffer).unwrap().is_empty());
    }

    #[test]
    fn length_past_buffer_end_is_rejected() {
        let buffer = Bytes::from_static(b"hello");
        let index: BufferIndex<[u8]> = index(0, 15);
        assert_eq!(
            index.bytes(&buffer).unwrap_err(),
            IndexError::IndexOutsideBuffer {
                start: 0,
                end: 15,
                len: 5
            }
        )
    }

    #[test]
    fn start_past_buffer_end_is_rejected() {
        let buffer = Bytes::from_static(b"hello");
        let index: BufferIndex<[u8]> = index(15, 1);
        assert_eq!(
            index.bytes(&buffer).unwrap_err(),
            IndexError::IndexOutsideBuffer {
                start: 15,
                end: 16,
                len: 5
            }
        )
    }

    #[test]
    fn valid_utf8_is_parsed_as_string() {
        let text = "h\u{e9}ello"; // "héllo", é is a "weird" (still valid utf8) char
        let buffer = Bytes::from_static(text.as_bytes());
        let index: BufferIndex<str> = index(0, text.len() as u16);
        assert_eq!(index.string(&buffer).unwrap(), text);
    }

    #[test]
    fn invalid_utf8_returns_not_a_string_error() {
        let buffer = Bytes::from_static(&[0xff, 0xfe, 0xfd]); // rubbish data
        let index: BufferIndex<str> = index(0, 3);
        assert!(matches!(
            index.string(&buffer).unwrap_err(),
            IndexError::NotAString { .. }
        ));
    }

    // TODO: This is behaviour that happens in debug mode, maybe it will need to be removed
    // once release mode is established, as of now the test case is left commented.
    // In release mode it will not panic but wrap around integer range (u8).
    /*
    #[test]
    #[should_panic(expected = "attempt to add with overflow")]
    fn start_plus_len_overflow_panics_instead_of_returning_an_error() {
        let buffer = Bytes::from_static(b"hello");
        let index: BufferIndex<[u8]> = index(60_000, 10_000);
        let _ = index.bytes(&buffer);
    }*/
}
