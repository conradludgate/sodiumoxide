//! Libsodium Base64 encoding/decoding helper functions

use base64ct::Encoding;
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
    match variant {
        Variant::Original => base64ct::Base64::encode_string(bin.as_ref()),
        Variant::OriginalNoPadding => base64ct::Base64Unpadded::encode_string(bin.as_ref()),
        Variant::UrlSafe => base64ct::Base64Url::encode_string(bin.as_ref()),
        Variant::UrlSafeNoPadding => base64ct::Base64UrlUnpadded::encode_string(bin.as_ref()),
    }
}

/// Decodes a Base64 string into a byte sequence using the given variant.
///
/// Fails if the decoded length overflows
/// or if `b64` contains invalid characters.
pub fn decode<T: AsRef<[u8]>>(b64: T, variant: Variant) -> Result<Vec<u8>, ()> {
    let mut vec = vec![0; decoded_len(b64.as_ref().len())];
    let d = match variant {
        Variant::Original => base64ct::Base64::decode(b64.as_ref(), &mut vec),
        Variant::OriginalNoPadding => base64ct::Base64Unpadded::decode(b64.as_ref(), &mut vec),
        Variant::UrlSafe => base64ct::Base64Url::decode(b64.as_ref(), &mut vec),
        Variant::UrlSafeNoPadding => base64ct::Base64UrlUnpadded::decode(b64.as_ref(), &mut vec),
    }
    .map_err(|_| ())?
    .len();
    vec.truncate(d);
    Ok(vec)
}

fn decoded_len(input_len: usize) -> usize {
    // overflow-proof computation of `(3*n)/4`
    let k = input_len / 4;
    let l = input_len - 4 * k;
    3 * k + (3 * l) / 4
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
