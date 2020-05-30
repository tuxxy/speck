#![no_std]
#![forbid(unsafe_code)]

/// This library implements NSA's lightweight block cipher SPECK.
/// The formal specification of SPECK can be found: https://eprint.iacr.org/2013/404.pdf
///
/// The SPECK parameters are found in Table 4.1 in the above paper.

/// SPECK parameters (for 128-bit security)
/// ALPHA and BETA are the parameters to the rotations
/// ROUNDS is the number of times to apply the round function
const ALPHA: u32 = 8;
const BETA: u32 = 3;
const ROUNDS: usize = 32;

/// Performs the SPECK round function once.
/// (S^{-\alpha}x + y) \oplus k, S^{\beta}y \oplus (S^{-\alpha}x + y) \oplus k
///
/// Notice that (S^{-\alpha}x + y) \oplus k component gets used twice, thus
/// we can simplify the round function to 2 rotations, 1 addition, and 2 XORs.
#[inline(always)]
fn round(x: &mut u64, y: &mut u64, k: &u64) {
    *x = x.rotate_right(ALPHA).wrapping_add(*y) ^ k;
    *y = y.rotate_left(BETA) ^ *x;
}

/// Performs the SPECK inverse round function once.
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

/// Computes the SPECK key schedule via the round function.
#[inline(always)]
fn key_schedule(k1: &mut u64, k2: &mut u64) -> [u64; ROUNDS] {
    let mut schedule = [0u64; ROUNDS];
    for i in 0..ROUNDS as u64 {
        schedule[i as usize] = *k2;
        round(k1, k2, &i)
    }
    schedule
}

#[cfg(test)]
mod tests {}
