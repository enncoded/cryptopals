use crate::utils::algos::{pkcs7_pad, pkcs7_unpad};
use crate::utils::misc::{read_no_newlines, read_lines};
use crate::utils::into_bytes::{from_base64, from_hex};
use crate::utils::aes::*;
use crate::utils::xor::repeating_key_xor;
use itertools::Itertools;

// Implement PKCS#7 padding
#[test]
fn challenge_9() {
    let input = b"abc";
    let block_size = 8 as usize;
    assert_eq!(pkcs7_pad(input, block_size), b"abc\x05\x05\x05\x05\x05".to_vec());

    let input = b"abcdefghi";
    let block_size = 8 as usize;
    assert_eq!(pkcs7_pad(input, block_size), b"abcdefghi\x07\x07\x07\x07\x07\x07\x07".to_vec());

    let input = b"abc";
    let block_size = 2 as usize;
    assert_eq!(pkcs7_pad(input, block_size), b"abc\x01".to_vec());
}

// Implement CBC mode
#[test]
fn challenge_10() {
    let block_size = 16 as usize;
    let input_bytes = from_base64(read_no_newlines("resources/set2_chal10.txt").as_bytes());
    let key = "YELLOW SUBMARINE".as_bytes();

    let iv = b"\x00".repeat(block_size);
    let decrypted = aes_128_cbc_decrypt(&input_bytes, key, &iv);
    let re_encrypted = aes_128_cbc_encrypt(&decrypted, key, &iv);

    // println!("{}", String::from_utf8(decrypted).unwrap());

    assert_eq!(input_bytes, re_encrypted);
}

// An ECB/CBC detection oracle
#[test]
fn challenge_11() {
    for i in 0..=10 {
        let line_bytes = b"A".repeat(50);
        let (method, encrypted) = encryption_oracle(&line_bytes);
        let determined_mode = determine_cipher(&encrypted);
        assert_eq!(method, determined_mode)
    }
}

#[test]
fn challenge_12() {
    let input = b"aaaaaaaaaaaaaaaa";
    let padded = pkcs7_pad(input, 16);
    println!("{}", padded.len());
    // let my_input = "Look to those who walked before to lead those who walk after".as_bytes();
    // println!("asdf {:?}", my_input);
    // let ciphertext = encryption_oracle_ecb_const_key(my_input);
    // let guessed_block_size = determine_block_size(ciphertext);
}
