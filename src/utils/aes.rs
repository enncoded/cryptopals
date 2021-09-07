use openssl::symm::*;

pub fn aes_ecb_decrypt(input_bytes: &[u8], key: &[u8]) -> Vec<u8> {
    decrypt(Cipher::aes_128_ecb(), key, None, input_bytes).unwrap()
}
