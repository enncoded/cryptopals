use openssl::symm::*;
use crate::utils::xor::repeating_key_xor;
use itertools::Itertools;
use crate::utils::algos::{pkcs7_pad, pkcs7_unpad};
use rand::Rng;

pub fn gen_bytes(count: usize) -> Vec<u8> {
    (0..count).map(|_| rand::thread_rng().gen::<u8>()).collect_vec()
}

pub fn encrypt_data_random_alg(input_bytes: &[u8]) -> (&str, Vec<u8>) {
    let mut rng = rand::thread_rng();
    let amount_to_pad = rng.gen_range(5..=10);
    let mut padded_input: Vec<u8> = gen_bytes(amount_to_pad);
    padded_input.extend_from_slice(input_bytes);
    padded_input.extend(gen_bytes(amount_to_pad));

    let key = gen_bytes(16);
    if rng.gen_bool(1.0) { // ECB
        ("ecb", aes_128_ecb_encrypt(padded_input.as_slice(), key.as_slice()))
    } else { // CBC
        let iv = gen_bytes(16);
        // println!("key: {:?}, iv: {:?}", key, iv);
        ("cbc", aes_128_cbc_encrypt(padded_input.as_slice(), key.as_slice(), iv.as_slice()))
    }
}

pub fn aes_128_ecb_decrypt(input_bytes: &[u8], key: &[u8]) -> Vec<u8> {
    let input_len = input_bytes.len();
    let mut decrypter = Crypter::new(Cipher::aes_128_ecb(), Mode::Decrypt, key, None).unwrap();
    let mut decrypted = vec![0u8; input_len + key.len()];
    decrypter.update(input_bytes, decrypted.as_mut_slice()).unwrap();

    decrypted[0..input_bytes.len()].to_vec()
}

pub fn aes_128_ecb_encrypt(input_bytes: &[u8], key: &[u8]) -> Vec<u8> {
    let input_bytes = pkcs7_pad(input_bytes.to_vec(), 16);
    let input_len = input_bytes.len();
    let mut encrypter = Crypter::new(Cipher::aes_128_ecb(), Mode::Encrypt, key, None).unwrap();
    let mut encrypted = vec![0u8; input_len + key.len()];
    encrypter.update(input_bytes.as_ref(), encrypted.as_mut_slice()).unwrap();

    encrypted[0..input_bytes.len()].to_vec()
}

pub fn aes_128_cbc_decrypt(input_bytes: &[u8], key: &[u8], iv: &[u8]) -> Vec<u8> {
    let mut previous_block = iv;
    let decrypted = input_bytes.chunks(16).map(|cur_block| {
        let decrypted = aes_128_ecb_decrypt(cur_block, key);

        let xor_block = repeating_key_xor(decrypted.as_slice(), previous_block);
        previous_block = cur_block;
        xor_block
    }).concat();
    pkcs7_unpad(decrypted, 16)
}

pub fn aes_128_cbc_encrypt(input_bytes: &[u8], key: &[u8], iv: &[u8]) -> Vec<u8> {
    let input_bytes = pkcs7_pad(input_bytes.to_vec(), 16);

    let mut previous_block = iv.to_vec();
    input_bytes.chunks(16).map(|cur_block| {
        let xor_block = repeating_key_xor(cur_block, previous_block.as_slice());

        previous_block = aes_128_ecb_encrypt(&xor_block, key);
        previous_block.clone()
    }).concat()
}

pub fn count_duplicate_blocks(input_bytes: &[u8], block_size: usize) -> usize {
    let chunks = input_bytes.chunks(block_size);
    chunks.clone().count() - chunks.unique().count()
}
