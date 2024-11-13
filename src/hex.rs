use std::fmt::Write;

/// Encoding values as hex string.
///
/// # Example
///
/// ```
/// use hex::Hex;
///
/// println!("{}", Hex("Hello world!"));
/// # assert_eq!(Hex("Hello world!").to_string(), "48656c6c6f20776f726c6421".to_string());
/// ```
#[derive(Debug)]
pub struct Hex<T>(pub T);

impl<T: AsRef<[u8]>> std::fmt::Display for Hex<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let iterator = BytesToHexChars::new(self.0.as_ref(), HEX_CHARS_LOWER);
        for ch in iterator {
            f.write_char(ch)?;
        }
        Ok(())
    }
}

const HEX_CHARS_LOWER: &[u8; 16] = b"0123456789abcdef";
// const HEX_CHARS_UPPER: &[u8; 16] = b"0123456789ABCDEF";

struct BytesToHexChars<'a> {
    inner: ::core::slice::Iter<'a, u8>,
    table: &'static [u8; 16],
    next: Option<char>,
}

impl<'a> BytesToHexChars<'a> {
    fn new(inner: &'a [u8], table: &'static [u8; 16]) -> BytesToHexChars<'a> {
        BytesToHexChars {
            inner: inner.iter(),
            table,
            next: None,
        }
    }
}

impl<'a> Iterator for BytesToHexChars<'a> {
    type Item = char;

    fn next(&mut self) -> Option<Self::Item> {
        match self.next.take() {
            Some(current) => Some(current),
            None => self.inner.next().map(|byte| {
                let current = self.table[(byte >> 4) as usize] as char;
                self.next = Some(self.table[(byte & 0x0F) as usize] as char);
                current
            }),
        }
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let length = self.len();
        (length, Some(length))
    }
}

impl<'a> std::iter::ExactSizeIterator for BytesToHexChars<'a> {
    fn len(&self) -> usize {
        let mut length = self.inner.len() * 2;
        if self.next.is_some() {
            length += 1;
        }
        length
    }
}
