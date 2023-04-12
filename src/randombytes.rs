//! Cryptographic random number generation.

use chacha20::cipher::{KeyIvInit, StreamCipher};
use chacha20::{ChaCha20, Key, Nonce};

#[cfg(not(feature = "std"))]
use prelude::*;
use rand::{distributions::Uniform, prelude::Distribution, thread_rng, RngCore};

/// The number of seed bytes to use for the deterministic RNG functions
/// [`randombytes_buf_deterministic()`] and
/// [`randombytes_buf_deterministic_into()`]
pub const SEEDBYTES: usize = 0x20;

/// `randombytes()` randomly generates size bytes of data.
///
/// THREAD SAFETY: `randombytes()` is thread-safe provided that you have
/// called `sodiumoxide::init()` once before using any other function
/// from sodiumoxide.
pub fn randombytes(size: usize) -> Vec<u8> {
    let mut buf = vec![0u8; size];
    thread_rng().fill_bytes(&mut buf);
    buf
}

/// `randombytes_into()` fills a buffer `buf` with random data.
///
/// THREAD SAFETY: `randombytes_into()` is thread-safe provided that you have
/// called `sodiumoxide::init()` once before using any other function
/// from sodiumoxide.
pub fn randombytes_into(buf: &mut [u8]) {
    thread_rng().fill_bytes(buf)
}

/// `randombytes_uniform()` returns an unpredictable value between 0 and
/// `upper_bound` (excluded). It guarantees a uniform distribution of the
/// possible output values even when `upper_bound` is not a power of 2. Note
/// that an `upper_bound` < 2 leaves only a  single element to be chosen, namely
/// 0.
///
/// THREAD SAFETY: `randombytes()` is thread-safe provided that you have
/// called `sodiumoxide::init()` once before using any other function
/// from sodiumoxide.
pub fn randombytes_uniform(upper_bound: u32) -> u32 {
    if upper_bound == 0 {
        return 0;
    }
    Uniform::from(0..upper_bound).sample(&mut thread_rng())
}

new_type! {
    /// `Seed` bytes for the deterministic random functions
    secret Seed(SEEDBYTES);
}

/// WARNING: you should only use this function for testing purposes or a *known good* use case
/// in which it is acceptable to rely on the secrecy of the seed passed to
/// `randombytes_buf_deterministic`. The function is (as its name suggests) entirely deterministic
/// given knowledge of the seed. It does not incorporate entropy of any form and should almost
/// never be used for cryptographic purposes. If you need to generate a deterministic stream of
/// cryptographic quality pseudo random data you're better suited using a stream cipher directly
/// e.g. one of the stream ciphers exposed in [`sodiumoxide::crypto::stream`](::crypto::stream) or
/// the higher level [`secretstream`](::crypto::secretstream) API.
///
/// The `randombytes_buf_deterministic` function stores size bytes into buf indistinguishable from
/// random bytes without knowing seed. For a given seed, this function will always output the same
/// sequence; size can be up to 2^38 (256 GB).
///
/// Seed is [`SEEDBYTES`] bytes long.
///
/// This function is mainly useful for writing tests, and was introduced in libsodium 1.0.12. Under
/// the hood, it uses the ChaCha20 stream cipher. Up to 256 GB can be produced with a single seed.
pub fn randombytes_buf_deterministic(size: usize, seed: &Seed) -> Vec<u8> {
    let mut buf = vec![0u8; size];
    randombytes_buf_deterministic_into(buf.as_mut_slice(), seed);
    buf
}

/// WARNING: using this function in a cryptographic setting is dangerous. Read the full
/// documentation of [`randombytes_buf_deterministic()`] before proceeding.
///
/// A counterpart to [`randombytes_buf_deterministic()`] that
/// fills `buf` with `buf.len()` bytes instead of returning a value.
pub fn randombytes_buf_deterministic_into(buf: &mut [u8], seed: &Seed) {
    const NONCE: [u8; 12] = *b"LibsodiumDRG";
    let mut chacha20 = ChaCha20::new(&Key::from(seed.0), &Nonce::from(NONCE));
    chacha20.apply_keystream(buf);
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_randombytes_uniform_0() {
        assert_eq!(randombytes_uniform(0), 0);
    }

    #[test]
    fn test_randombytes_uniform_1() {
        assert_eq!(randombytes_uniform(1), 0);
    }

    #[test]
    fn test_randombytes_uniform_7() {
        assert!(randombytes_uniform(7) < 7);
    }

    #[test]
    fn test_randombytes_buf_deterministic() {
        let seed = Seed([0u8; SEEDBYTES]);
        let res_1 = randombytes_buf_deterministic(10, &seed);
        let res_2 = randombytes_buf_deterministic(10, &seed);
        assert_eq!(res_1, res_2);
    }

    #[test]
    fn test_randombytes_buf_deterministic_into() {
        let seed = Seed([0u8; SEEDBYTES]);
        let mut buf_1 = vec![0u8; 10];
        let mut buf_2 = vec![0u8; 10];
        randombytes_buf_deterministic_into(buf_1.as_mut_slice(), &seed);
        randombytes_buf_deterministic_into(buf_2.as_mut_slice(), &seed);
        assert_eq!(buf_1, buf_2);
    }

    #[test]
    fn test_randombytes_buf_deterministic_unique_given_seed() {
        let seed_1 = Seed([
            0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23,
            24, 25, 26, 27, 28, 29, 30, 31,
        ]);
        let seed_2 = Seed([
            32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 53,
            54, 55, 56, 57, 58, 59, 60, 61, 62, 63,
        ]);

        let res_1 = randombytes_buf_deterministic(1 << 10, &seed_1);
        let res_2 = randombytes_buf_deterministic(1 << 10, &seed_2);
        assert_ne!(res_1, res_2);
    }
}
