/// A trait for the Electronic Codebook (ECB) ciphermode.
/// WARNING: ECB is generally unsafe to use because it lacks diffusion.
/// See: https://blog.filippo.io/the-ecb-penguin/ for details.
///
/// TODO: Implement other ciphermodes
pub trait ECB {
    fn encrypt(&self, plaintext: &u128) -> u128;
    fn decrypt(&self, ciphertext: &u128) -> u128;
}
