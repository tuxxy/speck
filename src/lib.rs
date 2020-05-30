#![no_std]
#![forbid(unsafe_code)]

pub mod cipher_modes;

use crate::cipher_modes::ECB;

/// This library implements NSA's lightweight block cipher Speck.
/// The formal specification of Speck can be found: https://eprint.iacr.org/2013/404.pdf
///
/// The Speck parameters are found in Table 4.1 in the above paper.

/// Speck parameters (for 128-bit security)
/// ALPHA and BETA are the parameters to the rotations
/// ROUNDS is the number of times to apply the round function
const ALPHA: u32 = 8;
const BETA: u32 = 3;
const ROUNDS: usize = 32;

/// Performs the Speck round function once.
/// (S^{-\alpha}x + y) \oplus k, S^{\beta}y \oplus (S^{-\alpha}x + y) \oplus k
///
/// Notice that (S^{-\alpha}x + y) \oplus k component gets used twice, thus
/// we can simplify the round function to 2 rotations, 1 addition, and 2 XORs.
#[inline(always)]
fn round(x: &mut u64, y: &mut u64, k: &u64) {
    *x = x.rotate_right(ALPHA).wrapping_add(*y) ^ k;
    *y = y.rotate_left(BETA) ^ *x;
}

/// Performs the Speck inverse round function once.
/// The inverse round function is necessary for decryption.
/// (S^{\alpha}((x \oplus k) - S^{-\beta}(x \oplus y)), S^{-\beta}(x \oplus y))
///
/// Notice that that S^{-\beta}(x \oplus y) component gets used twice, thus
/// we can simplify the round function to 2 rotations, 1 subtraction, and 2 XORs.
#[inline(always)]
fn inv_round(x: &mut u64, y: &mut u64, k: &u64) {
    *y = (*y ^ *x).rotate_right(BETA);
    *x = (*x ^ *k).wrapping_sub(*y).rotate_left(ALPHA);
}

/// Computes the Speck key schedule via the round function.
#[inline(always)]
fn key_schedule(k1: &mut u64, k2: &mut u64) -> [u64; ROUNDS] {
    let mut schedule = [0u64; ROUNDS];
    for i in 0..ROUNDS as u64 {
        schedule[i as usize] = *k2;
        round(k1, k2, &i)
    }
    schedule
}

/// Implements Speck encryption/decryption.
/// This tuple-struct takes a key schedule as input.
///
/// TODO: Build an API around generating the key schedule
pub struct Speck([u64; ROUNDS]);

impl Speck {
    pub fn new(key: &u128) -> Self {
        let mut k1 = (key >> 64) as u64;
        let mut k2 = *key as u64;

        Speck(key_schedule(&mut k1, &mut k2))
    }

    /// Performs a raw encryption using Speck.
    /// This is not exposed via the Speck type because the raw
    /// encryption function is generally unsafe to use.
    ///
    /// TODO: Implement ciphermodes, potentially expose this as ECB.
    pub(crate) fn encrypt(&self, plaintext: &u128) -> u128 {
        // Split the u128 block into u64 chunks
        let mut chunk_1 = (plaintext >> 64) as u64;
        let mut chunk_2 = *plaintext as u64;

        // Perform the Speck round with each of its round keys
        for round_key in &self.0 {
            round(&mut chunk_1, &mut chunk_2, round_key);
        }

        // The chunks are mutated in place, so we just put them back together
        chunk_2 as u128 | (chunk_1 as u128) << 64
    }

    /// Performs a raw decryption using Speck.
    ///
    /// TODO: Implement ciphermodes, potentially expose this as ECB.
    pub(crate) fn decrypt(&self, ciphertext: &u128) -> u128 {
        // Split the u128 block into u64 chunks
        let mut chunk_1 = (ciphertext >> 64) as u64;
        let mut chunk_2 = *ciphertext as u64;

        // Perform the Speck round with each of its round keys
        for round_key in self.0.iter().rev() {
            inv_round(&mut chunk_1, &mut chunk_2, round_key);
        }

        // The chunks are mutated in place, so we just put them back together
        chunk_2 as u128 | (chunk_1 as u128) << 64
    }
}

impl ECB for Speck {
    fn encrypt(&self, plaintext: &u128) -> u128 {
        self.encrypt(plaintext)
    }

    fn decrypt(&self, ciphertext: &u128) -> u128 {
        self.decrypt(ciphertext)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_speck128_128_encryption_and_decryption() {
        // Speck128/128 test vectors (see Appendix C in the paper)
        let key: u128 = 0x0f0e0d0c0b0a09080706050403020100;
        let plaintext: u128 = 0x6c617669757165207469206564616d20;
        let ciphertext: u128 = 0xa65d9851797832657860fedf5c570d18;

        let speck = Speck::new(&key);
        assert_eq!(speck.encrypt(&plaintext), ciphertext);
        assert_eq!(speck.decrypt(&ciphertext), plaintext);
    }

    #[test]
    fn test_speck_ecb_mode() {
        let key: u128 = 0x0f0e0d0c0b0a09080706050403020100;
        let plaintext: u128 = 0x6c617669757165207469206564616d20;
        let ciphertext: u128 = 0xa65d9851797832657860fedf5c570d18;

        let speck = Speck::new(&key);
        assert_eq!(<Speck as ECB>::encrypt(&speck, &plaintext), ciphertext);
        assert_eq!(<Speck as ECB>::decrypt(&speck, &ciphertext), plaintext);
    }
}
