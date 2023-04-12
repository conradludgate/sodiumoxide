//! A particular combination of `Curve25519`, `Blake2B`, `XSalsa20` and `Poly1305`.

use aes_gcm::{aead::Aead, AeadInPlace};
use crypto_box::SalsaBox;
#[cfg(not(feature = "std"))]
use prelude::*;
use rand::thread_rng;

use super::super::box_::curve25519xsalsa20poly1305 as box_;

/// Number of additional bytes in a ciphertext compared to the corresponding
/// plaintext.
pub const SEALBYTES: usize = crypto_box::KEY_SIZE + 16;

fn get_seal_nonce(
    ephemeral_pk: &crypto_box::PublicKey,
    recipient_pk: &crypto_box::PublicKey,
) -> crypto_box::Nonce {
    use blake2::{Blake2b, Digest};
    let mut hasher = Blake2b::<typenum::U24>::new();
    hasher.update(ephemeral_pk.as_bytes());
    hasher.update(recipient_pk.as_bytes());
    hasher.finalize()
}

/// The `seal()` function encrypts a message `m` for a recipient whose public key
/// is `pk`. It returns the ciphertext whose length is `SEALBYTES + m.len()`.
///
/// The function creates a new key pair for each message, and attaches the public
/// key to the ciphertext. The secret key is overwritten and is not accessible
/// after this function returns.
pub fn seal(m: &[u8], pk: &box_::PublicKey) -> Vec<u8> {
    let tx_sk = crypto_box::SecretKey::generate(&mut thread_rng());
    let rx_pk = crypto_box::PublicKey::from(pk.0);
    let tx_pk = tx_sk.public_key();

    let mut buf = Vec::with_capacity(crypto_box::KEY_SIZE + m.len() + 16);
    buf.extend_from_slice(tx_pk.as_bytes());
    buf.extend_from_slice(&[0; 16]);
    buf.extend_from_slice(m);

    let nonce = get_seal_nonce(&tx_pk, &rx_pk);
    let salsabox = SalsaBox::new(&rx_pk, &tx_sk);

    let tag = salsabox
        .encrypt_in_place_detached(&nonce, &[], &mut buf[crypto_box::KEY_SIZE + 16..])
        .unwrap();
    buf[crypto_box::KEY_SIZE..crypto_box::KEY_SIZE + 16].copy_from_slice(tag.as_slice());
    buf
}

/// The `open()` function decrypts the ciphertext `c` using the key pair `(pk, sk)`
/// and returns the decrypted message.
///
/// Key pairs are compatible with other
/// `crypto::box_::curve25519xsalsa20poly1305` operations and can be created
/// using `crypto::box::gen_keypair()`.
///
/// This function doesn't require passing the public key of the sender, as the
/// ciphertext already includes this information.
///
/// If decryption fails it returns `Err(())`.
pub fn open(c: &[u8], pk: &box_::PublicKey, sk: &box_::SecretKey) -> Result<Vec<u8>, ()> {
    if c.len() < SEALBYTES {
        return Err(());
    }
    let rx_sk = crypto_box::SecretKey::from(sk.0);
    let rx_pk = crypto_box::PublicKey::from(pk.0);
    let (tx_pk, ciphertext) = c.split_at(crypto_box::KEY_SIZE);
    let tx_pk: [u8; crypto_box::KEY_SIZE] = tx_pk.try_into().unwrap();
    let tx_pk = crypto_box::PublicKey::from(tx_pk);

    let nonce = get_seal_nonce(&tx_pk, &rx_pk);
    let salsabox = SalsaBox::new(&tx_pk, &rx_sk);

    salsabox.decrypt(&nonce, ciphertext).map_err(|_| ())
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::randombytes::randombytes;

    #[test]
    fn test_seal_open() {
        for i in 0..256usize {
            let (pk, sk) = box_::gen_keypair();
            let m = randombytes(i);
            let c = seal(&m, &pk);
            let opened = open(&c, &pk, &sk).unwrap();
            assert_eq!(m, opened);
        }
    }

    #[test]
    fn test_seal_open_tamper() {
        for i in 0..32usize {
            let (pk, sk) = box_::gen_keypair();
            let m = randombytes(i);
            let mut c = seal(&m, &pk);
            for j in 0..c.len() {
                c[j] ^= 0x20;
                assert!(Err(()) == open(&c, &pk, &sk));
                c[j] ^= 0x20;
            }
        }
    }
}
