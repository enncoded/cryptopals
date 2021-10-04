use core::fmt;
use std::borrow::BorrowMut;
use openssl::symm::*;
use crate::utils::xor::repeating_key_xor;
use itertools::Itertools;
use crate::utils::algos::{pkcs7_pad, pkcs7_unpad};
use rand::Rng;
use std::fmt::{Display, Formatter};
use crate::utils::into_bytes::from_base64;

#[derive(PartialEq, Eq, Debug)]
pub enum CipherMode {
    ECB,
    CBC,
}

impl Display for CipherMode {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match *self {
            CipherMode::ECB => write!(f, "ECB"),
            CipherMode::CBC => write!(f, "CBC"),
        }
    }
}

pub fn gen_bytes(count: usize) -> Vec<u8> {
    (0..count).map(|_| rand::thread_rng().gen::<u8>()).collect_vec()
}

// Randomly does ECB or CBC
pub fn encryption_oracle(input_bytes: &[u8]) -> (CipherMode, Vec<u8>) {
    let mut rng = rand::thread_rng();
    let amount_to_pad = rng.gen_range(5..=10);
    let mut padded_input: Vec<u8> = gen_bytes(amount_to_pad);
    padded_input.extend_from_slice(input_bytes);
    padded_input.extend(gen_bytes(amount_to_pad));

    let key = gen_bytes(16);
    if rng.gen_bool(0.5) { // ECB
        (CipherMode::ECB, aes_128_ecb_encrypt(padded_input.as_slice(), key.as_slice()))
    } else { // CBC
        let iv = gen_bytes(16);
        (CipherMode::CBC, aes_128_cbc_encrypt(padded_input.as_slice(), key.as_slice(), iv.as_slice()))
    }
}

// Same thing as encryption_oracle, but uses a constant key for ECB instead of generating one each time
pub fn encryption_oracle_ecb_const_key(input_bytes: &[u8]) -> Vec<u8> {
    let key = b"asdf;lkjasdf;lkj".to_vec();

    let unknown_text = b"Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK";
    let mut input_bytes = input_bytes.to_vec();
    input_bytes.append(&mut from_base64(unknown_text).to_vec());

    aes_128_ecb_encrypt(input_bytes.as_slice(), key.as_slice())
}

pub fn aes_128_ecb_decrypt(input_bytes: &[u8], key: &[u8]) -> Vec<u8> {
    let mut decrypted = Vec::new();

    for chunk in input_bytes.chunks(16) {
        decrypted.append(aes_128_ecb_decrypt_block(chunk, key).borrow_mut())
    }

    let output = decrypted[0..input_bytes.len()].to_vec();
    pkcs7_unpad(output.as_slice(), 16)
}

fn aes_128_ecb_encrypt_block(input_bytes: &[u8], key: &[u8]) -> Vec<u8> {
    let input_len = input_bytes.len();
    let mut encrypter = Crypter::new(Cipher::aes_128_ecb(), Mode::Encrypt, key, None).unwrap();
    let mut encrypted = vec![0u8; input_len + key.len()];
    encrypter.update(input_bytes.as_ref(), encrypted.as_mut_slice()).unwrap();

    encrypted[0..input_len].to_vec()
}

pub fn aes_128_ecb_encrypt(input_bytes: &[u8], key: &[u8]) -> Vec<u8> {
    let input_bytes = pkcs7_pad(input_bytes, 16); // pad before encryption
    input_bytes.chunks(16).map( |chunk| {
        (aes_128_ecb_encrypt_block(chunk, key))
    }).concat()
}

pub fn aes_128_cbc_decrypt(input_bytes: &[u8], key: &[u8], iv: &[u8]) -> Vec<u8> {
    let mut previous_block = iv;
    let decrypted = input_bytes.chunks(16).map(|cur_block| {
        let decrypted = aes_128_ecb_decrypt_block(cur_block, key);

        let xor_block = repeating_key_xor(decrypted.as_slice(), previous_block);
        previous_block = cur_block;
        xor_block
    }).concat();
    pkcs7_unpad(decrypted.as_slice(), 16)
}

pub fn aes_128_cbc_encrypt(input_bytes: &[u8], key: &[u8], iv: &[u8]) -> Vec<u8> {
    let input_bytes = pkcs7_pad(input_bytes, 16);

    let mut previous_block = iv.to_vec();
    input_bytes.chunks(16).map(|cur_block| {
        let xor_block = repeating_key_xor(cur_block, previous_block.as_slice());
        previous_block = aes_128_ecb_encrypt_block(&xor_block, key);
        previous_block.clone()
    }).concat()
}

pub fn determine_cipher(input_bytes: &[u8]) -> CipherMode {
    if count_duplicate_blocks(input_bytes, 16) > 0 {
        CipherMode::ECB
    } else {
        CipherMode::CBC
    }
}

pub fn count_duplicate_blocks(input_bytes: &[u8], block_size: usize) -> usize {
    let chunks = input_bytes.chunks(block_size);
    chunks.clone().count() - chunks.unique().count()
}

fn aes_128_ecb_decrypt_block(input_block: &[u8], key: &[u8]) -> Vec<u8> {
    let mut decrypter = Crypter::new(Cipher::aes_128_ecb(), Mode::Decrypt, key, None).unwrap();
    let mut decrypted = vec![0u8; input_block.len() + key.len()];
    decrypter.update(input_block, decrypted.as_mut_slice()).unwrap();
    decrypted[0..input_block.len()].to_vec()
}

