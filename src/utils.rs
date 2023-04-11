//! Libsodium utility functions

use subtle::ConstantTimeEq;
use zeroize::Zeroize;

/// `memzero()` tries to effectively zero out the data in `x` even if
/// optimizations are being applied to the code.
pub fn memzero(x: &mut [u8]) {
    x.zeroize()
}

/// `memcmp()` returns true if `x[0]`, `x[1]`, ..., `x[len-1]` are the
/// same as `y[0]`, `y[1]`, ..., `y[len-1]`. Otherwise it returns `false`.
///
/// This function is safe to use for secrets `x[0]`, `x[1]`, ..., `x[len-1]`,
/// `y[0]`, `y[1]`, ..., `y[len-1]`. The time taken by `memcmp` is independent
/// of the contents of `x[0]`, `x[1]`, ..., `x[len-1]`, `y[0]`, `y[1]`, ..., `y[len-1]`.
/// In contrast, the standard C comparison function `memcmp(x,y,len)` takes time
/// that depends on the longest matching prefix of `x` and `y`, often allowing easy
/// timing attacks.
pub fn memcmp(x: &[u8], y: &[u8]) -> bool {
    x.ct_eq(y).into()
}

/// `mlock()` locks memory given region which can help avoiding swapping the
/// sensitive memory region to disk.
///
/// Operating system might limit the amount of memory a process can `mlock()`.
/// This function can fail if `mlock()` fails to lock the memory.
pub fn mlock(x: &mut [u8]) -> Result<(), ()> {
    // https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtuallock on windows
    unsafe { nix::sys::mman::mlock(x as *const [u8] as *const _, x.len()).map_err(|_| ()) }
}

/// `munlock()` unlocks memory region.
///
/// `munlock()` overwrites the region with zeros before unlocking it, so it
/// doesn't have to be done before calling this function.
pub fn munlock(x: &mut [u8]) -> Result<(), ()> {
    x.fill(0);
    unsafe { nix::sys::mman::munlock(x as *const [u8] as *const _, x.len()).map_err(|_| ()) }
}

/// `increment_le()` treats `x` as an unsigned little-endian number and increments it in
/// constant time.
///
/// WARNING: this method does not check for arithmetic overflow. When used for incrementing
/// nonces it is the caller's responsibility to ensure that any given nonce value
/// is used only once.
/// If the caller does not do that the cryptographic primitives in sodiumoxide
/// will not uphold any security guarantees (i.e. they may break)
pub fn increment_le(x: &mut [u8]) {
    for c in x {
        let (d, carry) = c.overflowing_add(1);
        *c = d;
        if !carry {
            return;
        }
    }
}

/// `add_le()` treats `x` and `y` as unsigned little-endian numbers and adds `y` to `x`
/// modulo 2^(8*len) in constant time.
///
/// `add_le()` will return Err<()> if the length of `x` is not equal to the length of `y`.
///
/// WARNING: When used for incrementing nonces it is the caller's responsibility to ensure
/// that any given nonce value is used only once.
/// If the caller does not do that the cryptographic primitives in sodiumoxide
/// will not uphold any security guarantees (i.e. they may break)
pub fn add_le(x: &mut [u8], y: &[u8]) -> Result<(), ()> {
    if x.len() == y.len() {
        let mut carry = 0;
        for (x, y) in std::iter::zip(x, y) {
            let (z, c1) = x.overflowing_add(*y);
            let (w, c2) = z.overflowing_add(carry);
            *x = w;
            carry = (c1 | c2) as u8;
        }
        Ok(())
    } else {
        Err(())
    }
}

#[cfg(test)]
mod test {
    use rand::{thread_rng, RngCore};

    use super::*;

    #[test]
    fn test_memcmp() {
        // use randombytes::randombytes;

        for i in 0..256 {
            let mut x = vec![0; i];
            thread_rng().fill_bytes(&mut x);
            assert!(memcmp(&x, &x));
            let mut y = x.clone();
            assert!(memcmp(&x, &y));
            y.push(0);
            assert!(!memcmp(&x, &y));
            assert!(!memcmp(&y, &x));

            let mut y = vec![0; i];
            thread_rng().fill_bytes(&mut y);
            if x == y {
                assert!(memcmp(&x, &y))
            } else {
                assert!(!memcmp(&x, &y))
            }
        }
    }

    #[test]
    fn test_increment_le_zero() {
        for i in 1..256 {
            let mut x = vec![0u8; i];
            increment_le(&mut x);
            assert!(!x.iter().all(|x| *x == 0));
            let mut y = vec![0u8; i];
            y[0] += 1;
            assert_eq!(x, y);
        }
    }

    #[test]
    fn test_increment_le_vectors() {
        let mut x = [255, 2, 3, 4, 5];
        let y = [0, 3, 3, 4, 5];
        increment_le(&mut x);
        assert!(!x.iter().all(|x| *x == 0));
        assert_eq!(x, y);
        let mut x = [255, 255, 3, 4, 5];
        let y = [0, 0, 4, 4, 5];
        increment_le(&mut x);
        assert!(!x.iter().all(|x| *x == 0));
        assert_eq!(x, y);
        let mut x = [255, 255, 255, 4, 5];
        let y = [0, 0, 0, 5, 5];
        increment_le(&mut x);
        assert!(!x.iter().all(|x| *x == 0));
        assert_eq!(x, y);
        let mut x = [255, 255, 255, 255, 5];
        let y = [0, 0, 0, 0, 6];
        increment_le(&mut x);
        assert!(!x.iter().all(|x| *x == 0));
        assert_eq!(x, y);
        let mut x = [255, 255, 255, 255, 255];
        let y = [0, 0, 0, 0, 0];
        increment_le(&mut x);
        assert!(x.iter().all(|x| *x == 0));
        assert_eq!(x, y);
    }

    #[test]
    fn test_increment_le_overflow() {
        for i in 1..256 {
            let mut x = vec![255u8; i];
            increment_le(&mut x);
            assert!(x.iter().all(|xi| *xi == 0));
        }
    }

    #[test]
    fn test_add_le_zero() {
        for i in 1..256 {
            let mut x = vec![0u8; i];
            let mut y = vec![0u8; i];
            y[0] = 42;
            assert!(add_le(&mut x, &y).is_ok());
            assert!(!x.iter().all(|x| *x == 0));
            assert_eq!(x, y);
        }
    }

    #[test]
    fn test_add_le_vectors() {
        let mut x = [255, 2, 3, 4, 5];
        let y = [42, 0, 0, 0, 0];
        let z = [41, 3, 3, 4, 5];
        assert!(add_le(&mut x, &y).is_ok());
        assert!(!x.iter().all(|x| *x == 0));
        assert_eq!(x, z);
        let mut x = [255, 255, 3, 4, 5];
        let z = [41, 0, 4, 4, 5];
        assert!(add_le(&mut x, &y).is_ok());
        assert!(!x.iter().all(|x| *x == 0));
        assert_eq!(x, z);
        let mut x = [255, 255, 255, 4, 5];
        let z = [41, 0, 0, 5, 5];
        assert!(add_le(&mut x, &y).is_ok());
        assert!(!x.iter().all(|x| *x == 0));
        assert_eq!(x, z);
        let mut x = [255, 255, 255, 255, 5];
        let z = [41, 0, 0, 0, 6];
        assert!(add_le(&mut x, &y).is_ok());
        assert!(!x.iter().all(|x| *x == 0));
        assert_eq!(x, z);
        let mut x = [255, 255, 255, 255, 255];
        let z = [41, 0, 0, 0, 0];
        assert!(add_le(&mut x, &y).is_ok());
        assert!(!x.iter().all(|x| *x == 0));
        assert_eq!(x, z);
    }

    #[test]
    fn test_add_le_overflow() {
        for i in 1..256 {
            let mut x = vec![255u8; i];
            let mut y = vec![0u8; i];
            y[0] = 42;
            assert!(add_le(&mut x, &y).is_ok());
            assert!(!x.iter().all(|x| *x == 0));
            y[0] -= 1;
            assert_eq!(x, y);
        }
    }

    #[test]
    fn test_add_le_different_lengths() {
        for i in 1..256 {
            let mut x = vec![1u8; i];
            let y = vec![42u8; i + 1];
            let z = vec![42u8; i - 1];
            assert!(add_le(&mut x, &y).is_err());
            assert_eq!(x, vec![1u8; i]);
            assert!(add_le(&mut x, &z).is_err());
            assert_eq!(x, vec![1u8; i]);
        }
    }

    #[test]
    fn test_mlock_munlock() {
        #[cfg(not(feature = "std"))]
        use prelude::*;
        let t = b"hello world";
        let mut x = Vec::new();
        x.extend_from_slice(t);
        assert!(mlock(&mut x).is_ok());
        assert_eq!(&x, t);
        assert!(munlock(&mut x).is_ok());
        assert_ne!(&x, t);
    }
}
