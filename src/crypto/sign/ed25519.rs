//! `ed25519`, a signature scheme specified in
//! [Ed25519](http://ed25519.cr.yp.to/). This function is conjectured to meet the
//! standard notion of unforgeability for a public-key signature scheme under
//! chosen-message attacks.

pub use ed25519::{
    signature::{Signer, Verifier},
    Error, Signature,
};

use ed25519_dalek::{SigningKey, VerifyingKey};
#[cfg(not(feature = "std"))]
use prelude::*;
use rand::thread_rng;

/// Number of bytes in a `Seed`.
// pub const SEEDBYTES: usize = ffi::crypto_sign_ed25519_SEEDBYTES as usize;

/// Number of bytes in a `SecretKey`.
pub const SECRETKEYBYTES: usize = ed25519_dalek::SECRET_KEY_LENGTH;

/// Number of bytes in a `PublicKey`.
pub const PUBLICKEYBYTES: usize = ed25519_dalek::PUBLIC_KEY_LENGTH;

/// Number of bytes in a `Signature`.
pub const SIGNATUREBYTES: usize = ed25519::Signature::BYTE_SIZE;

// new_type! {
//     /// `Seed` that can be used for keypair generation
//     ///
//     /// The `Seed` is used by `keypair_from_seed()` to generate
//     /// a secret and public signature key.
//     ///
//     /// When a `Seed` goes out of scope its contents
//     /// will be zeroed out
//     secret Seed(SEEDBYTES);
// }

new_type! {
    /// `SecretKey` for signatures
    ///
    /// When a `SecretKey` goes out of scope its contents
    /// will be zeroed out
    secret SecretKey(SECRETKEYBYTES);
}

impl SecretKey {
    /// `public_key()` computes the corresponding public key for a given secret key
    pub fn public_key(&self) -> PublicKey {
        let sk = SigningKey::from_bytes(&self.0);
        let pk = VerifyingKey::from(&sk);
        PublicKey(pk.to_bytes())
    }
}

impl Signer<Signature> for SecretKey {
    fn try_sign(&self, msg: &[u8]) -> Result<Signature, Error> {
        Ok(SigningKey::from_bytes(&self.0).sign(msg))
    }
}
impl ed25519_1::signature::Signer<ed25519_1::Signature> for SecretKey {
    fn try_sign(&self, msg: &[u8]) -> Result<ed25519_1::Signature, ed25519_1::Error> {
        todo!()
    }
}

new_type! {
    /// `PublicKey` for signatures
    public PublicKey(PUBLICKEYBYTES);
}

impl Verifier<Signature> for PublicKey {
    fn verify(&self, msg: &[u8], sig: &Signature) -> Result<(), Error> {
        VerifyingKey::from_bytes(&self.0)
            .unwrap()
            .verify(msg, &Signature::from_bytes(&sig.to_bytes()))
    }
}
impl ed25519_1::signature::Verifier<ed25519_1::Signature> for PublicKey {
    fn verify(&self, msg: &[u8], sig: &ed25519_1::Signature) -> Result<(), ed25519_1::Error> {
        VerifyingKey::from_bytes(&self.0)
            .unwrap()
            .verify(msg, &Signature::from_bytes(&sig.to_bytes()))
            .map_err(|_| ed25519_1::Error::new())
    }
}

/// `gen_keypair()` randomly generates a secret key and a corresponding public
/// key.
///
/// THREAD SAFETY: `gen_keypair()` is thread-safe provided that you have
/// called `sodiumoxide::init()` once before using any other function
/// from sodiumoxide.
pub fn gen_keypair() -> (PublicKey, SecretKey) {
    let sk = SigningKey::generate(&mut thread_rng());
    let pk = VerifyingKey::from(&sk);
    (PublicKey(pk.to_bytes()), SecretKey(sk.to_bytes()))
}

// /// `keypair_from_seed()` computes a secret key and a corresponding public key
// /// from a `Seed`.
// pub fn keypair_from_seed(seed: &Seed) -> (PublicKey, SecretKey) {
//     let mut pk = PublicKey([0u8; PUBLICKEYBYTES]);
//     let mut sk = SecretKey([0u8; SECRETKEYBYTES]);
//     unsafe {
//         ffi::crypto_sign_ed25519_seed_keypair(
//             pk.0.as_mut_ptr(),
//             sk.0.as_mut_ptr(),
//             seed.0.as_ptr(),
//         );
//     }
//     (pk, sk)
// }

/// `sign()` signs a message `m` using the signer's secret key `sk`.
/// `sign()` returns the resulting signed message `sm`.
pub fn sign(m: &[u8], sk: &SecretKey) -> Vec<u8> {
    let mut data = m.to_vec();
    data.extend_from_slice(&SigningKey::from_bytes(&sk.0).sign(m).to_bytes());
    data
}

/// `verify()` verifies the signature in `sm` using the signer's public key `pk`.
/// `verify()` returns the message `Ok(m)`.
/// If the signature fails verification, `verify()` returns `Err(())`.
pub fn verify(sm: &[u8], pk: &PublicKey) -> Result<Vec<u8>, ()> {
    if SIGNATUREBYTES > sm.len() {
        return Err(());
    }
    let (m, s) = sm.split_at(sm.len() - SIGNATUREBYTES);
    VerifyingKey::from_bytes(&pk.0)
        .unwrap()
        .verify(m, &Signature::from_slice(s).unwrap())
        .map_err(|_| ())?;
    Ok(m.to_vec())
}

/// `sign_detached()` signs a message `m` using the signer's secret key `sk`.
/// `sign_detached()` returns the resulting signature `sig`.
pub fn sign_detached(m: &[u8], sk: &SecretKey) -> ed25519_1::Signature {
    ed25519_1::Signature::from_bytes(&SigningKey::from_bytes(&sk.0).sign(m).to_bytes()).unwrap()
}

/// `verify_detached()` verifies the signature in `sig` against the message `m`
/// and the signer's public key `pk`.
/// `verify_detached()` returns true if the signature is valid, false otherwise.
pub fn verify_detached(sig: &ed25519_1::Signature, m: &[u8], pk: &PublicKey) -> bool {
    VerifyingKey::from_bytes(&pk.0)
        .unwrap()
        .verify(m, &Signature::from_bytes(&sig.to_bytes()))
        .is_ok()
}

// /// State for multi-part (streaming) computation of signature.
// #[derive(Copy, Clone)]
// pub struct State(ffi::crypto_sign_ed25519ph_state);

// impl State {
//     /// `init()` initialize a streaming signing state.
//     pub fn init() -> State {
//         let mut s = mem::MaybeUninit::uninit();
//         let state = unsafe {
//             ffi::crypto_sign_ed25519ph_init(s.as_mut_ptr());
//             s.assume_init() // s is definitely initialized
//         };
//         State(state)
//     }

//     /// `update()` can be called more than once in order to compute the digest
//     /// from sequential chunks of the message.
//     pub fn update(&mut self, m: &[u8]) {
//         unsafe {
//             ffi::crypto_sign_ed25519ph_update(&mut self.0, m.as_ptr(), m.len() as c_ulonglong);
//         }
//     }

//     /// `finalize()` finalizes the hashing computation and returns a `Signature`.
//     // Moves self becuase libsodium says the state should not be used
//     // anymore after final().
//     pub fn finalize(mut self, &SecretKey(ref sk): &SecretKey) -> Signature {
//         let mut sig = [0u8; SIGNATUREBYTES];
//         let mut siglen: c_ulonglong = 0;
//         unsafe {
//             ffi::crypto_sign_ed25519ph_final_create(
//                 &mut self.0,
//                 sig.as_mut_ptr(),
//                 &mut siglen,
//                 sk.as_ptr(),
//             );
//         }
//         assert_eq!(siglen, SIGNATUREBYTES as c_ulonglong);
//         Signature::new(sig)
//     }

//     /// `verify` verifies the signature in `sm` using the signer's public key `pk`.
//     pub fn verify(&mut self, sig: &Signature, &PublicKey(ref pk): &PublicKey) -> bool {
//         let mut sig = sig.to_bytes();
//         let ret = unsafe {
//             ffi::crypto_sign_ed25519ph_final_verify(&mut self.0, sig.as_mut_ptr(), pk.as_ptr())
//         };
//         ret == 0
//     }
// }

// impl fmt::Debug for State {
//     fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
//         write!(f, "ed25519 state")
//     }
// }

// // Impl Default becuase `State` does have a sensible default: State::init()
// impl Default for State {
//     fn default() -> State {
//         State::init()
//     }
// }

// use crate::crypto::box_;

// /// Converts a ed25519 [PublicKey]  into a curve25519 [box_::PublicKey]
// pub fn to_curve25519_pk(ed25519_pk: &PublicKey) -> Result<box_::PublicKey, ()> {
//     let mut x25519_pk = box_::PublicKey([0u8; box_::PUBLICKEYBYTES]);

//     let ret = unsafe {
//         ffi::crypto_sign_ed25519_pk_to_curve25519(x25519_pk.0.as_mut_ptr(), ed25519_pk.0.as_ptr())
//     };

//     if ret == 0 {
//         Ok(x25519_pk)
//     } else {
//         Err(())
//     }
// }

// /// Converts an ed25519 [SecretKey] into a curve25519 [box_::SecretKey]
// pub fn to_curve25519_sk(ed25519_sk: &SecretKey) -> Result<box_::SecretKey, ()> {
//     let mut x25519_sk = box_::SecretKey([0u8; box_::SECRETKEYBYTES]);

//     let ret = unsafe {
//         ffi::crypto_sign_ed25519_sk_to_curve25519(x25519_sk.0.as_mut_ptr(), ed25519_sk.0.as_ptr())
//     };

//     if ret == 0 {
//         Ok(x25519_sk)
//     } else {
//         Err(())
//     }
// }

#[cfg(test)]
mod test {
    use crate::randombytes::{randombytes, randombytes_into};

    use super::*;
    use ed25519_1::Signature;
    use hex;

    #[test]
    fn test_sk_to_pk() {
        let (pk, sk) = gen_keypair();
        assert_eq!(sk.public_key(), pk);
    }

    #[test]
    fn test_sign_verify() {
        for i in 0..256usize {
            let (pk, sk) = gen_keypair();
            let m = randombytes(i);
            let sm = sign(&m, &sk);
            let m2 = verify(&sm, &pk);
            assert!(Ok(m) == m2);
        }
    }

    #[test]
    fn test_sign_verify_tamper() {
        for i in 0..32usize {
            let (pk, sk) = gen_keypair();
            let m = randombytes(i);
            let mut sm = sign(&m, &sk);
            for j in 0..sm.len() {
                sm[j] ^= 0x20;
                assert!(Err(()) == verify(&sm, &pk));
                sm[j] ^= 0x20;
            }
        }
    }

    #[test]
    fn test_sign_verify_detached() {
        for i in 0..256usize {
            let (pk, sk) = gen_keypair();
            let m = randombytes(i);
            let sig = sign_detached(&m, &sk);
            assert!(verify_detached(&sig, &m, &pk));
        }
    }

    #[test]
    fn test_sign_verify_detached_tamper() {
        for i in 0..32usize {
            let (pk, sk) = gen_keypair();
            let m = randombytes(i);
            let mut sig = sign_detached(&m, &sk).to_bytes();
            for j in 0..SIGNATUREBYTES-1 {
                sig[j] ^= 0x20;
                assert!(!verify_detached(&Signature::new(sig), &m, &pk));
                sig[j] ^= 0x20;
            }
        }
    }

    // #[test]
    // fn test_sign_verify_seed() {
    //     for i in 0..256usize {
    //         let mut seedbuf = [0; 32];
    //         randombytes_into(&mut seedbuf);
    //         let seed = Seed(seedbuf);
    //         let (pk, sk) = keypair_from_seed(&seed);
    //         let m = randombytes(i);
    //         let sm = sign(&m, &sk);
    //         let m2 = verify(&sm, &pk);
    //         assert!(Ok(m) == m2);
    //     }
    // }

    // #[test]
    // fn test_sign_verify_tamper_seed() {
    //     for i in 0..32usize {
    //         let mut seedbuf = [0; 32];
    //         randombytes_into(&mut seedbuf);
    //         let seed = Seed(seedbuf);
    //         let (pk, sk) = keypair_from_seed(&seed);
    //         let m = randombytes(i);
    //         let mut sm = sign(&m, &sk);
    //         for j in 0..sm.len() {
    //             sm[j] ^= 0x20;
    //             assert!(Err(()) == verify(&sm, &pk));
    //             sm[j] ^= 0x20;
    //         }
    //     }
    // }

    // #[test]
    // fn test_vectors() {
    //     // test vectors from the Python implementation
    //     // from the [Ed25519 Homepage](http://ed25519.cr.yp.to/software.html)
    //     use std::fs::File;
    //     use std::io::{BufRead, BufReader};

    //     let r = BufReader::new(File::open("testvectors/ed25519.input").unwrap());
    //     for mline in r.lines() {
    //         let line = mline.unwrap();
    //         let mut x = line.split(':');
    //         let x0 = x.next().unwrap();
    //         let x1 = x.next().unwrap();
    //         let x2 = x.next().unwrap();
    //         let x3 = x.next().unwrap();
    //         let seed_bytes = hex::decode(&x0[..64]).unwrap();
    //         let mut seed = Seed([0u8; SEEDBYTES]);
    //         seed.0.copy_from_slice(&seed_bytes);
    //         let (pk, sk) = keypair_from_seed(&seed);
    //         let m = hex::decode(x2).unwrap();
    //         let sm = sign(&m, &sk);
    //         verify(&sm, &pk).unwrap();
    //         assert!(x1 == hex::encode(pk));
    //         assert!(x3 == hex::encode(sm));
    //     }
    // }

    // #[test]
    // fn test_vectors_detached() {
    //     // test vectors from the Python implementation
    //     // from the [Ed25519 Homepage](http://ed25519.cr.yp.to/software.html)
    //     use std::fs::File;
    //     use std::io::{BufRead, BufReader};

    //     let r = BufReader::new(File::open("testvectors/ed25519.input").unwrap());
    //     for mline in r.lines() {
    //         let line = mline.unwrap();
    //         let mut x = line.split(':');
    //         let x0 = x.next().unwrap();
    //         let x1 = x.next().unwrap();
    //         let x2 = x.next().unwrap();
    //         let x3 = x.next().unwrap();
    //         let seed_bytes = hex::decode(&x0[..64]).unwrap();
    //         assert!(seed_bytes.len() == SEEDBYTES);
    //         let mut seed = Seed([0u8; SEEDBYTES]);
    //         for (s, b) in seed.0.iter_mut().zip(seed_bytes.iter()) {
    //             *s = *b
    //         }
    //         let (pk, sk) = keypair_from_seed(&seed);
    //         let m = hex::decode(x2).unwrap();
    //         let sig = sign_detached(&m, &sk);
    //         assert!(verify_detached(&sig, &m, &pk));
    //         assert!(x1 == hex::encode(pk));
    //         let sm = hex::encode(sig) + x2; // x2 is m hex encoded
    //         assert!(x3 == sm);
    //     }
    // }

    // #[test]
    // fn test_streaming_sign() {
    //     for i in 0..256usize {
    //         let (pk, sk) = gen_keypair();
    //         let m = randombytes(i);
    //         let mut creation_state = State::init();
    //         creation_state.update(&m);
    //         let sig = creation_state.finalize(&sk);
    //         let mut validator_state = State::init();
    //         validator_state.update(&m);
    //         assert!(validator_state.verify(&sig, &pk));
    //     }
    // }

    // #[test]
    // fn test_streaming_empty_sign() {
    //     let (pk, sk) = gen_keypair();
    //     let creation_state = State::init();
    //     let sig = creation_state.finalize(&sk);
    //     let mut validator_state = State::init();
    //     assert!(validator_state.verify(&sig, &pk));
    // }

    // #[test]
    // fn test_streaming_vectors() {
    //     // test vectors from the Python implementation
    //     // from the [Ed25519 Homepage](http://ed25519.cr.yp.to/software.html)
    //     use std::fs::File;
    //     use std::io::{BufRead, BufReader};

    //     let r = BufReader::new(File::open("testvectors/ed25519.input").unwrap());
    //     for mline in r.lines() {
    //         let line = mline.unwrap();
    //         let mut x = line.split(':');
    //         let x0 = x.next().unwrap();
    //         let x1 = x.next().unwrap();
    //         let x2 = x.next().unwrap();
    //         let seed_bytes = hex::decode(&x0[..64]).unwrap();
    //         assert!(seed_bytes.len() == SEEDBYTES);
    //         let mut seed = Seed([0u8; SEEDBYTES]);
    //         for (s, b) in seed.0.iter_mut().zip(seed_bytes.iter()) {
    //             *s = *b
    //         }
    //         let (pk, sk) = keypair_from_seed(&seed);

    //         let m = hex::decode(x2).unwrap();

    //         let mut creation_state = State::init();
    //         creation_state.update(&m);
    //         let sig = creation_state.finalize(&sk);

    //         let mut validator_state = State::init();
    //         validator_state.update(&m);

    //         assert!(validator_state.verify(&sig, &pk));

    //         assert_eq!(x1, hex::encode(pk));
    //     }
    // }

    // #[test]
    // fn test_streaming_copy() {
    //     let i = 256;
    //     let (pk, sk) = gen_keypair();
    //     let m = randombytes(i);
    //     let mut creation_state = State::init();
    //     creation_state.update(&m);

    //     let creation_state_copy = creation_state;
    //     let sig = creation_state_copy.finalize(&sk);
    //     let mut validator_state = State::init();
    //     validator_state.update(&m);
    //     assert!(validator_state.verify(&sig, &pk));
    // }

    // #[test]
    // fn test_streaming_default() {
    //     let i = 256;
    //     let (pk, sk) = gen_keypair();
    //     let m = randombytes(i);
    //     let mut creation_state = State::default();
    //     creation_state.update(&m);

    //     let sig = creation_state.finalize(&sk);
    //     let mut validator_state = State::init();
    //     validator_state.update(&m);
    //     assert!(validator_state.verify(&sig, &pk));
    // }

    // #[test]
    // fn test_streaming_format() {
    //     let creation_state = State::init();
    //     let creation_state_fmt = format!("{:?}", creation_state);
    //     assert_eq!(creation_state_fmt, "ed25519 state");
    // }

    // #[test]
    // fn test_chunks_sign() {
    //     let (pk, sk) = gen_keypair();
    //     let mut creation_state = State::init();
    //     let mut validator_state = State::init();
    //     for i in 0..64usize {
    //         let chunk = randombytes(i);
    //         creation_state.update(&chunk);
    //         validator_state.update(&chunk);
    //     }
    //     let sig = creation_state.finalize(&sk);
    //     assert!(validator_state.verify(&sig, &pk));
    // }

    // #[test]
    // fn test_convert_keys() {
    //     let (pk, sk) = gen_keypair();

    //     let _pk2 = to_curve25519_pk(&pk).unwrap();
    //     let _sk2 = to_curve25519_sk(&sk).unwrap();
    // }
}

#[cfg(feature = "benchmarks")]
#[cfg(test)]
mod bench {
    extern crate test;
    use super::*;
    use randombytes::randombytes;

    const BENCH_SIZES: [usize; 14] = [0, 1, 2, 4, 8, 16, 32, 64, 128, 256, 512, 1024, 2048, 4096];

    #[bench]
    fn bench_sign(b: &mut test::Bencher) {
        let (_, sk) = gen_keypair();
        let ms: Vec<Vec<u8>> = BENCH_SIZES.iter().map(|s| randombytes(*s)).collect();
        b.iter(|| {
            for m in ms.iter() {
                sign(m, &sk);
            }
        });
    }

    #[bench]
    fn bench_verify(b: &mut test::Bencher) {
        let (pk, sk) = gen_keypair();
        let sms: Vec<Vec<u8>> = BENCH_SIZES
            .iter()
            .map(|s| {
                let m = randombytes(*s);
                sign(&m, &sk)
            })
            .collect();
        b.iter(|| {
            for sm in sms.iter() {
                verify(sm, &pk);
            }
        });
    }
}
