//! The original ChaCha20-Poly1305 construction can safely encrypt a pratically
//! unlimited number of messages with the same key, without any practical limit
//! to the size of a message (up to ~ 2^64 bytes).

// this module sucks - https://datatracker.ietf.org/doc/html/draft-agl-tls-chacha20poly1305-04

use chacha20poly1305::{
    aead::{Aead, AeadCore, AeadInPlace, KeyInit, Payload},
    ChaCha20Poly1305,
};

use crate::randombytes::randombytes_into;
use std::ptr;

/// Number of bytes in a `Key`.
pub const KEYBYTES: usize = 32;

/// Number of bytes in a `Nonce`.
pub const NONCEBYTES: usize = 8;

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
    let cipher = ChaCha20Poly1305::new_from_slice(&k.0).unwrap();
    
    let aad_len = ad.map_or(0, <[u8]>::len);
    let mut padded = vec![10; aad_len + 1];
    padded[..aad_len].copy_from_slice(ad.unwrap_or_default());

    let mut nonce = chacha20poly1305::Nonce::default();
    nonce[4..].copy_from_slice(&n.0);

    cipher
        .encrypt(
            &nonce,
            Payload {
                msg: m,
                aad: &padded,
            },
        )
        .unwrap()
}

/// `seal_detached()` encrypts and authenticates a message `m` together with optional plaintext data
/// `ad` using a secret key `k` and a nonce `n`.
/// `m` is encrypted in place, so after this function returns it will contain the ciphertext.
/// The detached authentication tag is returned by value.
pub fn seal_detached(m: &mut [u8], ad: Option<&[u8]>, n: &Nonce, k: &Key) -> Tag {
    let cipher = ChaCha20Poly1305::new_from_slice(&k.0).unwrap();

    let aad_len = ad.map_or(0, <[u8]>::len);
    let mut padded = vec![10; aad_len + 1];
    padded[..aad_len].copy_from_slice(ad.unwrap_or_default());

    let mut nonce = chacha20poly1305::Nonce::default();
    nonce[4..].copy_from_slice(&n.0);

    Tag(cipher
        .encrypt_in_place_detached(
            &nonce,
            &padded,
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
    let cipher = ChaCha20Poly1305::new_from_slice(&k.0).unwrap();

    let aad_len = ad.map_or(0, <[u8]>::len);
    let mut padded = vec![10; aad_len + 1];
    padded[..aad_len].copy_from_slice(ad.unwrap_or_default());

    let mut nonce = chacha20poly1305::Nonce::default();
    nonce[4..].copy_from_slice(&n.0);

    cipher
        .decrypt(
            &nonce,
            Payload {
                msg: c,
                aad: &padded,
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
    let cipher = ChaCha20Poly1305::new_from_slice(&k.0).unwrap();

    let aad_len = ad.map_or(0, <[u8]>::len);
    let mut padded = vec![10; aad_len + 1];
    padded[..aad_len].copy_from_slice(ad.unwrap_or_default());

    let mut nonce = chacha20poly1305::Nonce::default();
    nonce[4..].copy_from_slice(&n.0);

    cipher
        .decrypt_in_place_detached(
            &nonce,
            &padded,
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

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_vector_1() {
        dbg!(hex::decode("87e229d4500845a079c00a00000000000000e3e446f7ede9a19b62a40a00000000000000"));

        // Test vector from https://tools.ietf.org/html/draft-agl-tls-chacha20poly1305-04#section-7
        let m = &[0x86, 0xd0, 0x99, 0x74, 0x84, 0x0b, 0xde, 0xd2, 0xa5, 0xca, 10];
        let k = Key([
            0x42, 0x90, 0xbc, 0xb1, 0x54, 0x17, 0x35, 0x31, 0xf3, 0x14, 0xaf, 0x57, 0xf3, 0xbe,
            0x3b, 0x50, 0x06, 0xda, 0x37, 0x1e, 0xce, 0x27, 0x2a, 0xfa, 0x1b, 0x5d, 0xbd, 0xd1,
            0x10, 0x0a, 0x10, 0x07,
        ]);
        let n = Nonce([0xcd, 0x7c, 0xf6, 0x7b, 0xe3, 0x9c, 0x79, 0x4a]);
        let ad = &[0x87, 0xe2, 0x29, 0xd4, 0x50, 0x08, 0x45, 0xa0, 0x79, 0xc0];

        let c_expected = &[
            0xe3, 0xe4, 0x46, 0xf7, 0xed, 0xe9, 0xa1, 0x9b, 0x62, 0xa4, 0x67, 0x7d, 0xab, 0xf4,
            0xe3, 0xd2, 0x4b, 0x87, 0x6b, 0xb2, 0x84, 0x75, 0x38, 0x96, 0xe1, 0xd6,
        ];

        let c = seal(m, Some(ad), &n, &k);
        assert_eq!(&c[..], c_expected);
    }
}
