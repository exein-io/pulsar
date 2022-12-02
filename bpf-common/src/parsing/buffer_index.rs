use core::fmt;

use bytes::Bytes;

use crate::test_runner::ComparableField;

#[derive(Debug)]
pub struct BufferIndex<T: ?Sized> {
    start: u16,
    len: u16,
    _data: std::marker::PhantomData<T>,
}

impl<T: ?Sized> fmt::Display for BufferIndex<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[index {} bytes at {}]", self.len, self.start)
    }
}

impl<T: ?Sized> BufferIndex<T> {
    pub fn len(&self) -> usize {
        self.len as usize
    }

    pub fn bytes<'a>(&self, buffer: &'a Bytes) -> &'a [u8] {
        let start = self.start as usize;
        let end = (self.start + self.len) as usize;
        if end <= buffer.len() {
            &buffer[start..end]
        } else {
            log::error!(
                "Index points to wrong buffer location: {} buffer len: {:}",
                self,
                buffer.len()
            );
            &[]
        }
    }
}

impl BufferIndex<str> {
    fn as_str<'a>(&self, buffer: &'a Bytes) -> Option<&'a str> {
        std::str::from_utf8(self.bytes(&buffer)).ok()
    }
}

impl ComparableField<String> for BufferIndex<str> {
    fn equals(&self, t: &String, buffer: &Bytes) -> bool {
        self.as_str(buffer).map(|item| item == t).unwrap_or(false)
    }

    fn repr(&self, buffer: &Bytes) -> String {
        self.as_str(buffer)
            .map(|item| item.to_string())
            .unwrap_or_else(|| format!("{:?}", &buffer[..]))
    }
}

impl ComparableField<Vec<u8>> for BufferIndex<[u8]> {
    fn equals(&self, t: &Vec<u8>, buffer: &Bytes) -> bool {
        self.bytes(buffer) == t
    }

    fn repr(&self, buffer: &Bytes) -> String {
        format!("{:?}", self.bytes(buffer))
    }
}
