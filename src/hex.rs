//! Libsodium hexadecimal encoding/decoding helper functions
#[cfg(not(feature = "std"))]
use prelude::*;

/// Encodes byte sequence into a hexadecimal string.
///
/// # Panics
///
/// Panics if `2 * bin.len() + 1` overflows.
pub fn encode<T: AsRef<[u8]>>(bin: T) -> String {
    hex::encode(bin)
}

/// Parses a hexadecimal string into a byte sequence.
///
/// Fails if `hex.len()` is not even or
/// if `hex` contains characters not in [0-9a-fA-F].
pub fn decode<T: AsRef<[u8]>>(hex: T) -> Result<Vec<u8>, ()> {
    hex::decode(hex).map_err(|_| ())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encode() {
        assert_eq!("".to_string(), encode(b""));
        assert_eq!("666f6f626172".to_string(), encode(b"foobar"));
    }

    #[test]
    fn test_decode() {
        assert_eq!(Ok(b"".to_vec()), decode(""));
        assert_eq!(Ok(b"foobar".to_vec()), decode("666F6F626172"));
        assert_eq!(Err(()), decode("abc"));
        assert_eq!(Err(()), decode("abxy"));
    }
}
