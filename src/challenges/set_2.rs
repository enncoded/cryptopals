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
    assert_eq!(pkcs7_pad(input.to_vec(), block_size), b"abc\x05\x05\x05\x05\x05".to_vec());

    let input = b"abcdefghi";
    let block_size = 8 as usize;
    assert_eq!(pkcs7_pad(input.to_vec(), block_size), b"abcdefghi\x07\x07\x07\x07\x07\x07\x07".to_vec());

    let input = b"abc";
    let block_size = 2 as usize;
    assert_eq!(pkcs7_pad(input.to_vec(), block_size), b"abc\x01".to_vec());
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

#[test]
fn challenge_11() {
    for i in 0..=10 {
        let line_bytes = b"A".repeat(50);
        let (method, encrypted) = encrypt_data_random_alg(line_bytes.as_slice());
        let duplicates = count_duplicate_blocks(encrypted.as_slice(), 16);
        if duplicates != 0 {
            println!("{} - found {} duplicates for {:?}", method.to_ascii_uppercase(), duplicates, line_bytes);
        }
    }
}
