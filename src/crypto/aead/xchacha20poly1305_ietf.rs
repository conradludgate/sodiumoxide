//! The XChaCha20-Poly1305 construction can safely encrypt a practically
//! unlimited number of messages with the same key, without any practical limit
//! to the size of the message (up to ~ 2^64 bytes).
//!
//! As an alternative to counters, its large nonce size (192-bit) allows random
//! nonces to be safely used
//!
//! For this reason, and if interoperability with other libraries is not a
//! concern, this is the recommended AEAD construction.

use crate::crypto::nonce::gen_random_nonce;
use chacha20poly1305::{
    aead::{Aead, AeadInPlace, KeyInit, Payload},
    XChaCha20Poly1305,
};

use crate::randombytes::randombytes_into;

/// Number of bytes in a `Key`.
pub const KEYBYTES: usize = 32;

/// Number of bytes in a `Nonce`.
pub const NONCEBYTES: usize = 24;

/// Number of bytes in an authentication `Tag`.
pub const TAGBYTES: usize = 16;

new_type! {
    /// `Key` for symmetric authenticated encryption with additional data.
    ///
    /// When a `Key` goes out of scope its contents will
    /// be zeroed out
    secret Key(KEYBYTES);
}

new_type! {
    /// `Nonce` for symmetric authenticated encryption with additional data.
    nonce Nonce(NONCEBYTES);
}

new_type! {
    /// Authentication `Tag` for symmetric authenticated encryption with additional data in
    /// detached mode.
    public Tag(TAGBYTES);
}

/// `gen_key()` randomly generates a secret key
///
/// THREAD SAFETY: `gen_key()` is thread-safe provided that you have
/// called `sodiumoxide::init()` once before using any other function
/// from sodiumoxide.
pub fn gen_key() -> Key {
    let mut k = Key([0u8; KEYBYTES]);
    randombytes_into(&mut k.0);
    k
}

/// `seal()` encrypts and authenticates a message `m` together with optional plaintext data `ad`
/// using a secret key `k` and a nonce `n`. It returns a ciphertext `c`.
pub fn seal(m: &[u8], ad: Option<&[u8]>, n: &Nonce, k: &Key) -> Vec<u8> {
    let cipher = XChaCha20Poly1305::new_from_slice(&k.0).unwrap();

    cipher
        .encrypt(
            chacha20poly1305::XNonce::from_slice(&n.0),
            Payload {
                msg: m,
                aad: ad.unwrap_or_default(),
            },
        )
        .unwrap()
}

/// `seal_detached()` encrypts and authenticates a message `m` together with optional plaintext data
/// `ad` using a secret key `k` and a nonce `n`.
/// `m` is encrypted in place, so after this function returns it will contain the ciphertext.
/// The detached authentication tag is returned by value.
pub fn seal_detached(m: &mut [u8], ad: Option<&[u8]>, n: &Nonce, k: &Key) -> Tag {
    let cipher = XChaCha20Poly1305::new_from_slice(&k.0).unwrap();

    Tag(cipher
        .encrypt_in_place_detached(
            chacha20poly1305::XNonce::from_slice(&n.0),
            ad.unwrap_or_default(),
            m,
        )
        .unwrap()
        .as_slice()
        .try_into()
        .unwrap())
}

/// `open()` verifies and decrypts a ciphertext `c` together with optional plaintext data `ad`
/// using a secret key `k` and a nonce `n`.
/// It returns a plaintext `Ok(m)`.
/// If the ciphertext fails verification, `open()` returns `Err(())`.
pub fn open(c: &[u8], ad: Option<&[u8]>, n: &Nonce, k: &Key) -> Result<Vec<u8>, ()> {
    let cipher = XChaCha20Poly1305::new_from_slice(&k.0).unwrap();

    cipher
        .decrypt(
            chacha20poly1305::XNonce::from_slice(&n.0),
            Payload {
                msg: c,
                aad: ad.unwrap_or_default(),
            },
        )
        .map_err(|_| ())
}
/// `open_detached()` verifies and decrypts a ciphertext `c` toghether with optional plaintext data
/// `ad` and and authentication tag `tag`, using a secret key `k` and a nonce `n`.
/// `c` is decrypted in place, so if this function is successful it will contain the plaintext.
/// If the ciphertext fails verification, `open_detached()` returns `Err(())`,
/// and the ciphertext is not modified.
pub fn open_detached(
    c: &mut [u8],
    ad: Option<&[u8]>,
    t: &Tag,
    n: &Nonce,
    k: &Key,
) -> Result<(), ()> {
    let cipher = XChaCha20Poly1305::new_from_slice(&k.0).unwrap();

    cipher
        .decrypt_in_place_detached(
            chacha20poly1305::XNonce::from_slice(&n.0),
            ad.unwrap_or_default(),
            c,
            chacha20poly1305::Tag::from_slice(&t.0),
        )
        .map_err(|_| ())
}

#[cfg(test)]
mod test_m {
    use super::*;
    use crate::crypto::nonce::gen_random_nonce;

    #[test]
    fn test_seal_open() {
        use crate::randombytes::randombytes;
        for i in 0..256usize {
            let k = gen_key();
            let n = gen_random_nonce();
            let ad = randombytes(i);
            let m = randombytes(i);
            let c = seal(&m, Some(&ad), &n, &k);
            let m2 = open(&c, Some(&ad), &n, &k).unwrap();
            assert_eq!(m, m2);
        }
    }

    #[test]
    fn test_seal_open_tamper() {
        use crate::randombytes::randombytes;
        for i in 0..32usize {
            let k = gen_key();
            let n = gen_random_nonce();
            let mut ad = randombytes(i);
            let m = randombytes(i);
            let mut c = seal(&m, Some(&ad), &n, &k);
            for j in 0..c.len() {
                c[j] ^= 0x20;
                let m2 = open(&c, Some(&ad), &n, &k);
                c[j] ^= 0x20;
                assert!(m2.is_err());
            }
            for j in 0..ad.len() {
                ad[j] ^= 0x20;
                let m2 = open(&c, Some(&ad), &n, &k);
                ad[j] ^= 0x20;
                assert!(m2.is_err());
            }
        }
    }

    #[test]
    fn test_seal_open_detached() {
        use crate::randombytes::randombytes;
        for i in 0..256usize {
            let k = gen_key();
            let n = gen_random_nonce();
            let ad = randombytes(i);
            let mut m = randombytes(i);
            let m2 = m.clone();
            let t = seal_detached(&mut m, Some(&ad), &n, &k);
            open_detached(&mut m, Some(&ad), &t, &n, &k).unwrap();
            assert_eq!(m, m2);
        }
    }

    #[test]
    fn test_seal_open_detached_tamper() {
        use crate::randombytes::randombytes;
        for i in 0..32usize {
            let k = gen_key();
            let n = gen_random_nonce();
            let mut ad = randombytes(i);
            let mut m = randombytes(i);
            let mut t = seal_detached(&mut m, Some(&ad), &n, &k);
            for j in 0..m.len() {
                m[j] ^= 0x20;
                let r = open_detached(&mut m, Some(&ad), &t, &n, &k);
                m[j] ^= 0x20;
                assert!(r.is_err());
            }
            for j in 0..ad.len() {
                ad[j] ^= 0x20;
                let r = open_detached(&mut m, Some(&ad), &t, &n, &k);
                ad[j] ^= 0x20;
                assert!(r.is_err());
            }
            for j in 0..t.0.len() {
                t.0[j] ^= 0x20;
                let r = open_detached(&mut m, Some(&ad), &t, &n, &k);
                t.0[j] ^= 0x20;
                assert!(r.is_err());
            }
        }
    }

    #[test]
    fn test_seal_open_detached_same() {
        use crate::randombytes::randombytes;
        for i in 0..256usize {
            let k = gen_key();
            let n = gen_random_nonce();
            let ad = randombytes(i);
            let mut m = randombytes(i);

            let c = seal(&m, Some(&ad), &n, &k);
            let t = seal_detached(&mut m, Some(&ad), &n, &k);

            assert_eq!(&c[0..c.len() - TAGBYTES], &m[..]);
            assert_eq!(&c[c.len() - TAGBYTES..], &t.0[..]);

            let m2 = open(&c, Some(&ad), &n, &k).unwrap();
            open_detached(&mut m, Some(&ad), &t, &n, &k).unwrap();

            assert_eq!(m2, m);
        }
    }
}

/// `gen_nonce` randomly generates a nonce
///
/// THREAD SAFETY: `gen_nonce()` is thread-safe provided that you have
/// called `sodiumoxide::init()` once before using any other function
/// from sodiumoxide.
pub fn gen_nonce() -> Nonce {
    gen_random_nonce()
}

#[cfg(test)]
mod test {
    use super::*;
    #[test]
    fn test_vector_1() {
        let m = &[
            0x4c, 0x61, 0x64, 0x69, 0x65, 0x73, 0x20, 0x61, 0x6e, 0x64, 0x20, 0x47, 0x65, 0x6e,
            0x74, 0x6c, 0x65, 0x6d, 0x65, 0x6e, 0x20, 0x6f, 0x66, 0x20, 0x74, 0x68, 0x65, 0x20,
            0x63, 0x6c, 0x61, 0x73, 0x73, 0x20, 0x6f, 0x66, 0x20, 0x27, 0x39, 0x39, 0x3a, 0x20,
            0x49, 0x66, 0x20, 0x49, 0x20, 0x63, 0x6f, 0x75, 0x6c, 0x64, 0x20, 0x6f, 0x66, 0x66,
            0x65, 0x72, 0x20, 0x79, 0x6f, 0x75, 0x20, 0x6f, 0x6e, 0x6c, 0x79, 0x20, 0x6f, 0x6e,
            0x65, 0x20, 0x74, 0x69, 0x70, 0x20, 0x66, 0x6f, 0x72, 0x20, 0x74, 0x68, 0x65, 0x20,
            0x66, 0x75, 0x74, 0x75, 0x72, 0x65, 0x2c, 0x20, 0x73, 0x75, 0x6e, 0x73, 0x63, 0x72,
            0x65, 0x65, 0x6e, 0x20, 0x77, 0x6f, 0x75, 0x6c, 0x64, 0x20, 0x62, 0x65, 0x20, 0x69,
            0x74, 0x2e,
        ];
        let ad = &[
            0x50, 0x51, 0x52, 0x53, 0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7,
        ];
        let k = Key([
            0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d,
            0x8e, 0x8f, 0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98, 0x99, 0x9a, 0x9b,
            0x9c, 0x9d, 0x9e, 0x9f,
        ]);
        let n = Nonce([
            0xf2, 0x8a, 0x50, 0xa7, 0x8a, 0x7e, 0x23, 0xc9, 0xcb, 0xa6, 0x78, 0x34, 0x66, 0xf8,
            0x03, 0x59, 0x0f, 0x04, 0xe9, 0x22, 0x31, 0xa3, 0x2d, 0x5d,
        ]);
        let c_expected = &[
            0x20, 0xf1, 0xae, 0x75, 0xe1, 0xe5, 0xe0, 0x00, 0x40, 0x29, 0x4f, 0x0f, 0xb1, 0x0e,
            0xbb, 0x08, 0x10, 0xc5, 0x93, 0xc7, 0xdb, 0xa4, 0xec, 0x10, 0x4c, 0x1e, 0x5e, 0xf9,
            0x50, 0x7f, 0xae, 0xef, 0x58, 0xfc, 0x28, 0x98, 0xbb, 0xd0, 0xe4, 0x7b, 0x2f, 0x53,
            0x31, 0xfb, 0xc3, 0x67, 0xd3, 0xc2, 0x78, 0x4e, 0x36, 0x48, 0xce, 0x1e, 0xaa, 0x77,
            0x87, 0xad, 0x18, 0x6d, 0xb2, 0x68, 0x5e, 0xe8, 0x9a, 0xe4, 0xd3, 0x44, 0x1f, 0x6e,
            0xa0, 0xb2, 0x22, 0x4c, 0xd5, 0xa1, 0x34, 0x16, 0x1b, 0x55, 0x4d, 0x8b, 0x48, 0x35,
            0x0b, 0x4a, 0xd4, 0x01, 0x15, 0xdb, 0x81, 0xea, 0x82, 0x09, 0x68, 0xe9, 0x43, 0x89,
            0x2f, 0x2b, 0x80, 0x51, 0xcb, 0x5f, 0x7a, 0x86, 0x66, 0xe7, 0xe7, 0xef, 0x7f, 0x84,
            0xc0, 0xa2, 0xf8, 0x0a, 0x12, 0xd0, 0x66, 0x80, 0xc8, 0xee, 0xbb, 0xd9, 0x30, 0x04,
            0x10, 0x9d, 0xe8, 0x42,
        ];
        let c = seal(m, Some(ad), &n, &k);
        assert_eq!(&c[..], &c_expected[..]);
    }

    #[test]
    fn test_nonce_length() {
        assert_eq!(192 / 8, gen_nonce().as_ref().len());
    }
}
