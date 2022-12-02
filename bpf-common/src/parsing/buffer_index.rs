use core::fmt;

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
    fn bytes<'a>(&self, buffer: &'a bytes::BytesMut) -> &'a [u8] {
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

impl ComparableField<String> for BufferIndex<str> {
    fn equals(&self, t: &String, buffer: &bytes::BytesMut) -> bool {
        if let Ok(item) = std::str::from_utf8(self.bytes(&buffer)) {
            item == t
        } else {
            false
        }
    }

    fn repr(&self, buffer: &bytes::BytesMut) -> String {
        match std::str::from_utf8(self.bytes(&buffer)) {
            Ok(item) => format!("{}", item),
            Err(_) => format!("{:?}", &buffer[..]),
        }
    }
}
