//! `HMAC-SHA-512-256`, i.e., the first 256 bits of
//! `HMAC-SHA-512`.  `HMAC-SHA-512-256` is conjectured to meet the standard notion
//! of unforgeability.

// this module is wrong...

use hmac::{Hmac, Mac};
use sha2::Sha512;
use subtle::ConstantTimeEq;

/// Number of bytes in a `Key`.
pub const KEYBYTES: usize = 32;

/// Number of bytes in a `Tag`.
pub const TAGBYTES: usize = 32;

new_type! {
    /// Authentication `Key`
    ///
    /// When a `Key` goes out of scope its contents
    /// will be zeroed out
    secret Key(KEYBYTES);
}

new_type! {
    /// Authentication `Tag`
    ///
    /// The tag implements the traits `PartialEq` and `Eq` using constant-time
    /// comparison functions. See `sodiumoxide::utils::memcmp`
    public Tag(TAGBYTES);
}

/// `gen_key()` randomly generates a key for authentication
///
/// THREAD SAFETY: `gen_key()` is thread-safe provided that you have
/// called `sodiumoxide::init()` once before using any other function
/// from sodiumoxide.
pub fn gen_key() -> Key {
    let mut k = [0; KEYBYTES];
    randombytes_into(&mut k);
    Key(k)
}

/// `authenticate()` authenticates a message `m` using a secret key `k`.
/// The function returns an authenticator tag.
pub fn authenticate(m: &[u8], k: &Key) -> Tag {
    let mut state = State::init(&k.0);
    state.update(m);
    state.finalize()
}

/// `verify()` returns `true` if `tag` is a correct authenticator of message `m`
/// under a secret key `k`. Otherwise it returns false.
pub fn verify(tag: &Tag, m: &[u8], k: &Key) -> bool {
    let mut state = State::init(&k.0);
    state.update(m);
    state.finalize().0.as_slice().ct_eq(tag.0.as_slice()).into()
}

#[cfg(test)]
mod test_m {
    use crate::randombytes::randombytes;

    use super::*;

    #[test]
    fn test_auth_verify() {
        for i in 0..256usize {
            let k = gen_key();
            let m = randombytes(i);
            let tag = authenticate(&m, &k);
            assert!(verify(&tag, &m, &k));
        }
    }

    #[test]
    fn test_auth_verify_tamper() {
        for i in 0..32usize {
            let k = gen_key();
            let mut m = randombytes(i);
            let Tag(mut tagbuf) = authenticate(&m, &k);
            for j in 0..m.len() {
                m[j] ^= 0x20;
                assert!(!verify(&Tag(tagbuf), &m, &k));
                m[j] ^= 0x20;
            }
            for j in 0..tagbuf.len() {
                tagbuf[j] ^= 0x20;
                assert!(!verify(&Tag(tagbuf), &m, &k));
                tagbuf[j] ^= 0x20;
            }
        }
    }

    #[cfg(feature = "serde")]
    #[test]
    fn test_serialisation() {
        use crate::randombytes::randombytes;
        use crate::test_utils::round_trip;
        for i in 0..256usize {
            let k = gen_key();
            let m = randombytes(i);
            let tag = authenticate(&m, &k);
            round_trip(k);
            round_trip(tag);
        }
    }
}

#[cfg(feature = "benchmarks")]
#[cfg(test)]
mod bench_m {
    extern crate test;
    use super::*;
    use randombytes::randombytes;

    const BENCH_SIZES: [usize; 14] = [0, 1, 2, 4, 8, 16, 32, 64, 128, 256, 512, 1024, 2048, 4096];

    #[bench]
    fn bench_auth(b: &mut test::Bencher) {
        let k = gen_key();
        let ms: Vec<Vec<u8>> = BENCH_SIZES.iter().map(|s| randombytes(*s)).collect();
        b.iter(|| {
            for m in ms.iter() {
                authenticate(&m, &k);
            }
        });
    }

    #[bench]
    fn bench_verify(b: &mut test::Bencher) {
        let k = gen_key();
        let ms: Vec<Vec<u8>> = BENCH_SIZES.iter().map(|s| randombytes(*s)).collect();
        let tags: Vec<Tag> = ms.iter().map(|m| authenticate(&m, &k)).collect();
        b.iter(|| {
            for (m, t) in ms.iter().zip(tags.iter()) {
                verify(t, &m, &k);
            }
        });
    }
}

use crate::randombytes::randombytes_into;

/// Authentication `State`
///
/// State for multi-part (streaming) authenticator tag (HMAC) computation.
///
/// When a `State` goes out of scope its contents will be zeroed out.
///
/// NOTE: the streaming interface takes variable length keys, as opposed to the
/// simple interface which takes a fixed length key. The streaming interface also does not
/// define its own `Key` type, instead using slices for its `init()` method.
/// The caller of the functions is responsible for zeroing out the key after it's been used
/// (in contrast to the simple interface which defines a `Drop` implementation for `Key`).
///
/// NOTE: these functions are specific to `libsodium` and do not exist in `NaCl`.

#[must_use]
pub struct State(Hmac<Sha512>);

impl State {
    /// `init()` initializes an authentication structure using a secret key 'k'.
    pub fn init(k: &[u8]) -> State {
        State(Hmac::new_from_slice(k).unwrap())
    }

    /// `update()` can be called more than once in order to compute the authenticator
    /// from sequential chunks of the message.
    pub fn update(&mut self, in_: &[u8]) {
        self.0.update(in_);
    }

    /// `finalize()` finalizes the authenticator computation and returns a `Tag`. `finalize`
    /// consumes the `State` so that it cannot be accidentally reused.
    pub fn finalize(self) -> Tag {
        let tag = self.0.finalize();
        Tag(tag.into_bytes()[..TAGBYTES].try_into().unwrap())
    }
}

#[cfg(test)]
mod test_s {
    use crate::randombytes::randombytes;

    use super::*;

    #[test]
    fn test_auth_eq_auth_state() {
        for i in 0..256usize {
            let k = gen_key();
            let m = randombytes(i);
            let tag = authenticate(&m, &k);
            let mut state = State::init(k.as_ref());
            state.update(&m);
            let tag2 = state.finalize();
            assert_eq!(tag, tag2);
        }
    }

    #[test]
    fn test_auth_eq_auth_state_chunked() {
        for i in 0..256usize {
            let k = gen_key();
            let m = randombytes(i);
            let tag = authenticate(&m, &k);
            let mut state = State::init(k.as_ref());
            for c in m.chunks(1) {
                state.update(c);
            }
            let tag2 = state.finalize();
            assert_eq!(tag, tag2);
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_vector_1() {
        // corresponding to tests/auth.c from NaCl
        // "Test Case 2" from RFC 4231
        let key = Key([
            0x4a, 0x65, 0x66, 0x65, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
        ]);
        let c = [
            0x77, 0x68, 0x61, 0x74, 0x20, 0x64, 0x6f, 0x20, 0x79, 0x61, 0x20, 0x77, 0x61, 0x6e,
            0x74, 0x20, 0x66, 0x6f, 0x72, 0x20, 0x6e, 0x6f, 0x74, 0x68, 0x69, 0x6e, 0x67, 0x3f,
        ];

        let a_expected = [
            0x16, 0x4b, 0x7a, 0x7b, 0xfc, 0xf8, 0x19, 0xe2, 0xe3, 0x95, 0xfb, 0xe7, 0x3b, 0x56,
            0xe0, 0xa3, 0x87, 0xbd, 0x64, 0x22, 0x2e, 0x83, 0x1f, 0xd6, 0x10, 0x27, 0x0c, 0xd7,
            0xea, 0x25, 0x05, 0x54,
        ];

        let Tag(a) = authenticate(&c, &key);

        assert_eq!(a, a_expected);
    }

    #[test]
    fn test_vector_state_1() {
        // corresponding to tests/auth.c from NaCl
        // "Test Case 2" from RFC 4231
        let key = [
            74, 101, 102, 101, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0,
        ];
        let c = [
            0x77, 0x68, 0x61, 0x74, 0x20, 0x64, 0x6f, 0x20, 0x79, 0x61, 0x20, 0x77, 0x61, 0x6e,
            0x74, 0x20, 0x66, 0x6f, 0x72, 0x20, 0x6e, 0x6f, 0x74, 0x68, 0x69, 0x6e, 0x67, 0x3f,
        ];

        let a_expected = [
            0x16, 0x4b, 0x7a, 0x7b, 0xfc, 0xf8, 0x19, 0xe2, 0xe3, 0x95, 0xfb, 0xe7, 0x3b, 0x56,
            0xe0, 0xa3, 0x87, 0xbd, 0x64, 0x22, 0x2e, 0x83, 0x1f, 0xd6, 0x10, 0x27, 0x0c, 0xd7,
            0xea, 0x25, 0x05, 0x54,
        ];

        let mut state = State::init(&key);
        state.update(&c);
        let Tag(a) = state.finalize();
        assert_eq!(a, a_expected);
    }
}
