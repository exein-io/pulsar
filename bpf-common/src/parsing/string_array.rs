//! StringArray is a zero terminated string which can be shared with eBPF C code.
//! It's stored in an array of a certain max length.
//!
//! This struct:
//! - simplifies equality checks, while ignoring garbage data
//! - allows conversion from &str
//! - allows conversion to String using String::from_utf8_lossy
use core::fmt;

#[derive(Clone, Eq)]
#[repr(C)]
pub struct StringArray<const N: usize> {
    data: [u8; N],
}

#[allow(clippy::len_without_is_empty)]
impl<const N: usize> StringArray<N> {
    // if no 0 is contained in the string, it's all garbage
    pub fn len(&self) -> Option<usize> {
        self.data.iter().position(|c| *c == 0)
    }
}

impl<const N: usize> PartialEq for StringArray<N> {
    fn eq(&self, other: &Self) -> bool {
        match self.len() {
            Some(len) => self.data[..len + 1] == other.data[..len + 1],
            None => false,
        }
    }
}

impl<const N: usize> From<&str> for StringArray<N> {
    fn from(slice: &str) -> Self {
        let mut data = [0; N];
        let len = slice.len();
        data[..len].copy_from_slice(slice.as_bytes());
        data[len] = 0;
        Self { data }
    }
}

impl<const N: usize> fmt::Display for StringArray<N> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.data.iter().position(|&r| r == 0) {
            Some(zero_pos) => write!(f, "{}", String::from_utf8_lossy(&self.data[..zero_pos])),
            None => Ok(()),
        }
    }
}

impl<const N: usize> fmt::Debug for StringArray<N> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("StringArray")
            .field("data", &self.to_string())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_equality() {
        let a: StringArray<100> = "hello".into();
        let b: StringArray<100> = "hello".into();
        let c: StringArray<100> = "hellow".into();
        assert_eq!(a, b);
        assert_ne!(a, c);
        assert_ne!(c, a);
    }
}
