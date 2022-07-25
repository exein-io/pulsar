//! DataArray is a simple data structure which can be shared with eBPF C code.
//! It's composed of an array (of a certain max length) and a length indicating
//! how many bytes of the array are filled.
//!
//! This struct:
//! - simplifies equality checks, while ignoring garbage data
//! - allows conversion to and from &[u8]

use std::fmt;

#[derive(Clone, Eq)]
#[repr(C)]
pub struct DataArray<const T: usize> {
    copied_data_len: u32,
    data: [u8; T],
}

impl<const T: usize> DataArray<T> {
    pub fn len(&self) -> usize {
        self.copied_data_len as usize
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl<const T: usize> AsRef<[u8]> for DataArray<T> {
    fn as_ref(&self) -> &[u8] {
        &self.data[0..self.len()]
    }
}

impl<const T: usize> PartialEq for DataArray<T> {
    fn eq(&self, other: &Self) -> bool {
        let len = self.copied_data_len as usize;
        self.copied_data_len == other.copied_data_len && self.data[..len] == other.data[..len]
    }
}

impl<const T: usize> fmt::Debug for DataArray<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DataArray")
            .field("copied_data_len", &self.copied_data_len)
            .finish()
    }
}

impl<const T: usize> From<&[u8]> for DataArray<T> {
    fn from(src: &[u8]) -> Self {
        let mut data = [0; T];
        data[..src.len()].clone_from_slice(src);
        Self {
            copied_data_len: src.len() as u32,
            data,
        }
    }
}
