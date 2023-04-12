//! Cryptographic padding routines
//!
//! Most modern cryptographic constructions disclose message lengths. The ciphertext for a given
//! message will always have the same length, or add a constant number of bytes to it. For most
//! applications, this is not an issue. But in some specific situations, such as interactive remote
//! shells, hiding the length may be desirable. Padding can be used for that purpose.
//!
//! Algorithm These functions use the ISO/IEC 7816-4 padding algorithm. It supports arbitrary block
//! sizes, ensures that the padding data are checked for computing the unpadded length, and is more
//! resistant to some classes of attacks than other standard padding algorithms.
//!
//! Notes Padding should be applied prior to encryption, and removed after decryption. Usage of
//! padding in order to hide the length of a password is not recommended. A client willing to send a
//! password to a server should hash it instead (even with a single iteration of the hash function).
//! This ensures that the length of the transmitted data is constant, and that the server doesn't
//! effortlessly get a copy of the password. Applications may eventually leak the unpadded length
//! via side channels, but the sodium_pad() and sodium_unpad() functions themselves try to minimize
//! side channels for a given length & <block size mask> value.

/// The `pad()` function adds padding data to a buffer buf whose original size is `unpadded_buflen`
/// in order to extend its total length to a multiple of blocksize.
///
/// The function returns `Err(())` if the padded buffer length would exceed `max_buflen`, or if the
/// block size is 0. It returns a result containing the new padded length upon success.
pub fn pad(buf: &mut [u8], unpadded_buflen: usize, blocksize: usize) -> Result<usize, ()> {
    if blocksize == 0 {
        return Err(());
    }
    let extra = blocksize - unpadded_buflen % blocksize;
    let padded_buflen = unpadded_buflen + extra;
    if padded_buflen > buf.len() {
        return Err(());
    }
    let (_, remainder) = buf.split_at_mut(unpadded_buflen);
    let (pad, remainder) = remainder.split_first_mut().ok_or(())?;
    *pad = 0x80;
    remainder.fill(0);
    Ok(padded_buflen)
}

/// The `unpad()` function computes the original, unpadded length of a message previously padded
/// using [`pad()`]. The original length is returned upon success.
pub fn unpad(buf: &[u8], padded_buflen: usize, blocksize: usize) -> Result<usize, ()> {
    if padded_buflen > buf.len() || blocksize == 0 || padded_buflen % blocksize > 0 {
        return Err(());
    }
    if padded_buflen == 0 {
        return Err(());
    }
    let last_block = &buf[padded_buflen - blocksize..padded_buflen];
    let padding = last_block.iter().rev().position(|x| *x == 128).ok_or(())? + 1;
    Ok(padded_buflen - padding)
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    pub fn test_on_block_boundary() {
        const BUF_LEN: usize = 32;
        let mut buf = vec![0u8; BUF_LEN];
        assert_eq!(Ok(BUF_LEN), pad(&mut buf, 16, 16));
    }

    #[test]
    pub fn test_pad_and_unpad_with_good_length() {
        let mut buf = vec![0u8; 64];
        for i in 0u8..33 {
            buf[i as usize] = i;
        }

        assert_eq!(Ok(64), pad(&mut buf, 33, 32));
        assert_eq!(Ok(33), unpad(&buf, 64, 32));

        for i in 0u8..33 {
            assert_eq!(i, buf[i as usize]);
        }

        assert_eq!(0x80u8, buf[33]);

        for _i in 33..64 {
            assert_eq!(0u8, buf[0]);
        }
    }

    #[test]
    pub fn test_on_bad_length() {
        const BUF_LEN: usize = 32;
        let mut buf = vec![0u8; BUF_LEN];
        assert_eq!(Err(()), pad(&mut buf, BUF_LEN, BUF_LEN));
        assert_eq!(Err(()), unpad(&buf, BUF_LEN, BUF_LEN));
    }
}
