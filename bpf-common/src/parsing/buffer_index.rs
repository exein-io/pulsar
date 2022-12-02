use bytes::Bytes;
use std::str::{from_utf8, Utf8Error};
use thiserror::Error;

#[derive(Error, Debug, PartialEq)]
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

#[derive(Debug)]
pub struct BufferIndex<T: ?Sized> {
    start: u16,
    len: u16,
    _data: std::marker::PhantomData<T>,
}

impl<T: ?Sized> BufferIndex<T> {
    pub fn len(&self) -> usize {
        self.len as usize
    }

    pub fn bytes<'a>(&self, buffer: &'a Bytes) -> Result<&'a [u8], IndexError> {
        let start = self.start as usize;
        let end = (self.start + self.len) as usize;
        if end <= buffer.len() {
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
    pub fn string(&self, buffer: &Bytes) -> Result<String, IndexError> {
        let bytes = self.bytes(buffer)?;
        let str = from_utf8(bytes).map_err(|err| IndexError::NotAString {
            error: err,
            bytes: bytes.to_vec(),
        })?;
        Ok(str.to_string())
    }
}

#[cfg(feature = "test-utils")]
mod test_utils {

    use super::*;
    use crate::test_runner::ComparableField;

    impl ComparableField<String> for BufferIndex<str> {
        fn equals(&self, t: &String, buffer: &Bytes) -> bool {
            self.bytes(buffer)
                .map(|item| from_utf8(item) == Ok(t))
                .unwrap_or(false)
        }

        fn repr(&self, buffer: &Bytes) -> String {
            let bytes = match self.bytes(buffer) {
                Ok(bytes) => bytes,
                Err(err) => {
                    return format!("{}", err);
                }
            };
            match from_utf8(bytes) {
                Ok(str) => str.to_string(),
                Err(_) => format!("{:?}", bytes),
            }
        }
    }

    #[cfg(feature = "test-utils")]
    impl ComparableField<Vec<u8>> for BufferIndex<[u8]> {
        fn equals(&self, t: &Vec<u8>, buffer: &Bytes) -> bool {
            self.bytes(buffer) == Ok(t)
        }

        fn repr(&self, buffer: &Bytes) -> String {
            format!("{:?}", self.bytes(buffer))
        }
    }
}
