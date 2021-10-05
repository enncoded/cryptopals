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

pub fn aes_128_ecb_decrypt(input_bytes: &[u8], key: &[u8]) -> Vec<u8> {
    let mut decrypted = Vec::new();

    for chunk in input_bytes.chunks(16) {
        decrypted.extend(aes_128_ecb_decrypt_block(chunk, key))
    }

    let output = decrypted[0..input_bytes.len()].to_vec();
    pkcs7_unpad(output.as_slice(), 16)
}

pub fn aes_128_ecb_encrypt(input_bytes: &[u8], key: &[u8]) -> Vec<u8> {
    let input_bytes = pkcs7_pad(input_bytes, 16); // pad before encryption
    input_bytes.chunks(16).map(|chunk| {
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

pub fn guess_block_size(cipher: impl Fn(&[u8]) -> Vec<u8>) -> usize {
    let mut block_size = 0;

    let mut prev_output_len = 0;
    for i in 1..1000 {
        let input = "a".repeat(i);
        let output = cipher(input.as_bytes());

        let output_len = output.len();
        if output_len != prev_output_len && prev_output_len != 0 {
            block_size = output_len;
            break;
        }

        prev_output_len = output_len;
    }

    // The size of the increase is the blocksize
    block_size - prev_output_len
}

pub fn decrypt_byte(already_decrypted: &[u8], idx: usize, block_size: usize) -> u8 {
    // For the requested index
    let expected_block_num = idx / block_size;
    let expected_block_begin = expected_block_num * block_size;
    let index_in_expected_block = idx % block_size;

    // Get the short output, where the encryption function will fill bytes from the plaintext
    // such that the byte to find is at the end of a block
    let padding = b"A".repeat(block_size - idx - expected_block_begin + 1);
    let padding_output = chal_12_oracle(padding.as_slice());
    let expected_block = padding_output.iter().skip(expected_block_begin).take(block_size).map(|b| *b).collect_vec();

    // Iterate through every possible byte, appending it to the end of filler and sending
    // that to the encryption function
    let mut deciphered_byte = 0u8;
    for b in 0..=255u8 {
        let bytes_to_fill = block_size - 1;
        let mut guess_block = already_decrypted.iter().rev().take(bytes_to_fill).map(|b| *b).rev().collect_vec();
        let guess_len = guess_block.len();

        if guess_len < bytes_to_fill {
            let bytes_to_fill = bytes_to_fill - guess_len;
            let mut filler = b"A".repeat(bytes_to_fill);
            filler.extend(guess_block);
            guess_block = filler.clone();
        }

        guess_block.push(b);

        let guess_output = chal_12_oracle(guess_block.as_slice());
        let guess_first_block = guess_output.iter().take(block_size).map(|b| *b).collect_vec();
        if guess_first_block.eq(expected_block.as_slice()) {
            deciphered_byte = b;
            break;
        }
    }
    deciphered_byte
}

pub fn count_duplicate_blocks(input_bytes: &[u8], block_size: usize) -> usize {
    let chunks = input_bytes.chunks(block_size);
    chunks.clone().count() - chunks.unique().count()
}

pub fn determine_cipher(input_bytes: &[u8], block_size: usize) -> CipherMode {
    if count_duplicate_blocks(input_bytes, block_size) > 0 {
        CipherMode::ECB
    } else {
        CipherMode::CBC
    }
}

fn aes_128_ecb_decrypt_block(input_bytes: &[u8], key: &[u8]) -> Vec<u8> {
    let input_len = input_bytes.len();
    let mut decrypter = Crypter::new(Cipher::aes_128_ecb(), Mode::Decrypt, key, None).unwrap();
    let mut decrypted = vec![0u8; input_len + key.len()];
    decrypter.update(input_bytes, decrypted.as_mut_slice()).unwrap();
    decrypted[0..input_len].to_vec()
}

fn aes_128_ecb_encrypt_block(input_bytes: &[u8], key: &[u8]) -> Vec<u8> {
    let input_len = input_bytes.len();
    let mut encrypter = Crypter::new(Cipher::aes_128_ecb(), Mode::Encrypt, key, None).unwrap();
    let mut encrypted = vec![0u8; input_len + key.len()];
    encrypter.update(input_bytes.as_ref(), encrypted.as_mut_slice()).unwrap();

    encrypted[0..input_len].to_vec()
}

// Encrypts with ECB using a constant key
pub fn chal_12_oracle(my_str: &[u8]) -> Vec<u8> {
    let unknown_string = from_base64(b"Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK");
    let mut cipher_input = my_str.to_vec();
    cipher_input.extend(unknown_string);

    let key = b"\xb3\x2b\x96\xf2\xaa\xf3\x2e\xf7\x63\x81\xeb\xfb\xbf\xda\x04\x9c".to_vec();
    aes_128_ecb_encrypt(cipher_input.as_slice(), key.as_slice())
}
