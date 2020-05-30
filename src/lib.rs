#![no_std]
#![forbid(unsafe_code)]

/// This library implements NSA's lightweight block cipher SPECK.
/// The formal specification of SPECK can be found: https://eprint.iacr.org/2013/404.pdf
///
/// The SPECK parameters can be found in Table 4.1 in the above paper.

/// SPECK rotation parameters
const ALPHA: u32 = 8;
const BETA: u32 = 3;

/// Performs the SPECK round function once.
/// (S^{-\alpha}x + y) \oplus k, S^{\beta}y \oplus (S^{-\alpha}x + y) \oplus k
///
/// Notice that (S^{-\alpha}x + y) \oplus k component gets used twice, thus
/// we can simplify the round function to 2 rotations, 1 addition, and 2 XORs.
#[inline(always)]
fn round(mut x: u64, mut y: u64, k: &u64) {
    x = x.rotate_right(ALPHA).wrapping_add(y) ^ k;
    y = y.rotate_left(BETA) ^ x;
}

/// Performs the SPECK inverse round function once.
/// The inverse round function is necessary for decryption.
/// (S^{\alpha}((x \oplus k) - S^{-\beta}(x \oplus y)), S^{-\beta}(x \oplus y))
///
/// Notice that that S^{-\beta}(x \oplus y) component gets used twice, thus
/// we can simplify the round function to 2 rotations, 1 subtraction, and 2 XORs.
#[inline(always)]
fn inv_round(mut x: u64, mut y: u64, k: &u64) {
    y = (y ^ x).rotate_right(BETA);
    x = (x ^ k).wrapping_sub(y).rotate_left(ALPHA);
}

#[cfg(test)]
mod tests {
}
