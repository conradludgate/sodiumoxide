//! Libsodium Base64 encoding/decoding helper functions

use base64::Engine;
#[cfg(not(feature = "std"))]
use prelude::*;

/// Supported variants of Base64 encoding/decoding
#[derive(Debug, PartialEq, Copy, Clone)]
pub enum Variant {
    /// Base64 as defined in RFC 4648 §4
    Original,
    /// Base64 as defined in RFC 4648 §4 but without padding
    OriginalNoPadding,
    /// Base64 as defined in RFC 4648 §5
    UrlSafe,
    /// Base64 as defined in RFC 4648 §5 but without padding
    UrlSafeNoPadding,
}

/// Encodes a byte sequence as a Base64 string using the given variant.
pub fn encode<T: AsRef<[u8]>>(bin: T, variant: Variant) -> String {
    let engine = match variant {
        Variant::Original => base64::engine::general_purpose::STANDARD,
        Variant::OriginalNoPadding => base64::engine::general_purpose::STANDARD_NO_PAD,
        Variant::UrlSafe => base64::engine::general_purpose::URL_SAFE,
        Variant::UrlSafeNoPadding => base64::engine::general_purpose::URL_SAFE_NO_PAD,
    };
    engine.encode(bin)
}

/// Decodes a Base64 string into a byte sequence using the given variant.
///
/// Fails if the decoded length overflows
/// or if `b64` contains invalid characters.
pub fn decode<T: AsRef<[u8]>>(b64: T, variant: Variant) -> Result<Vec<u8>, ()> {
    let engine = match variant {
        Variant::Original => base64::engine::general_purpose::STANDARD,
        Variant::OriginalNoPadding => base64::engine::general_purpose::STANDARD_NO_PAD,
        Variant::UrlSafe => base64::engine::general_purpose::URL_SAFE,
        Variant::UrlSafeNoPadding => base64::engine::general_purpose::URL_SAFE_NO_PAD,
    };
    engine.decode(b64).map_err(|_| ())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encode() {
        assert_eq!("".to_string(), encode(b"", Variant::Original));
        assert_eq!("Zg==".to_string(), encode(b"f", Variant::Original));
        assert_eq!("Zm8=".to_string(), encode(b"fo", Variant::Original));
        assert_eq!("Zm9v".to_string(), encode(b"foo", Variant::Original));
        assert_eq!("Zm9vYg==".to_string(), encode(b"foob", Variant::Original));
        assert_eq!("Zm9vYmE=".to_string(), encode(b"fooba", Variant::Original));
        assert_eq!("Zm9vYmFy".to_string(), encode(b"foobar", Variant::Original));
    }

    #[test]
    fn test_decode() {
        assert_eq!(Ok(b"".to_vec()), decode("", Variant::Original));
        assert_eq!(Ok(b"f".to_vec()), decode("Zg==", Variant::Original));
        assert_eq!(Ok(b"fo".to_vec()), decode("Zm8=", Variant::Original));
        assert_eq!(Ok(b"foo".to_vec()), decode("Zm9v", Variant::Original));
        assert_eq!(Ok(b"foob".to_vec()), decode("Zm9vYg==", Variant::Original));
        assert_eq!(Ok(b"fooba".to_vec()), decode("Zm9vYmE=", Variant::Original));
        assert_eq!(
            Ok(b"foobar".to_vec()),
            decode("Zm9vYmFy", Variant::Original)
        );
    }
}
