#![allow(unused_variables)]

use crate::utils::*;
use crate::utils::algos::{calc_char_freq_for_bytes};
use crate::utils::xor::{repeating_key_xor, break_repeating_key_xor};
use crate::utils::misc::{read_no_newlines, read_lines};
use crate::utils::aes::{aes_128_ecb_decrypt, aes_128_ecb_encrypt, count_duplicate_blocks};
use crate::utils::into_bytes::from_hex;
use itertools::Itertools;

// convert hex to base64
#[test]
fn challenge_1() {
    let input = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d";
    let expected = "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t";

    let output = base64::encode(into_bytes::from_hex(input));
    assert_eq!(expected, output);
}

// Fixed (2 equal length buffers) XOR
#[test]
fn challenge_2() {
    let input = into_bytes::from_hex("1c0111001f010100061a024b53535009181c"); // encoded hexadecimal string
    let xor_key = into_bytes::from_hex("686974207468652062756c6c277320657965");
    let expected = "746865206b696420646f6e277420706c6179";

    let xor_output = xor::fixed_xor(input, xor_key);
    let output = from_bytes::into_hex(xor_output);

    assert_eq!(expected, output)
}

// Single-byte XOR cipher
#[test]
fn challenge_3() {
    let input = into_bytes::from_hex("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736");

    let (winning_string, _) = algos::calc_char_freq_for_bytes(input);

    assert_eq!(winning_string, "Cooking MC's like a pound of bacon");
    // println!("{} won. Key used was {}", winning_string, winning_key);
}

// Detect single-character XOR
#[test]
fn challenge_4() {
    let input_lines = misc::read_lines("resources/set1_chal4.txt").expect("Error reading file!");
    for line in input_lines {
        if let Err(e) = line {
            eprintln!("Error while reading line: {}", e);
        } else {
            let bytes = into_bytes::from_hex(line.unwrap().as_str().trim());
            // let (decrypted, _key) = calc_char_freq_for_bytes(bytes);
            let (decrypted, _) = calc_char_freq_for_bytes(bytes);
            if decrypted != String::default() {
                // println!("{} decrypted with key {}", decrypted, key);
            }
        }
    }
}

// Implement repeating-key XOR
#[test]
fn challenge_5() {
    let input = b"Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal";
    let expected = into_bytes::from_hex("0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f");
    let key = b"ICE";

    let output = repeating_key_xor(input, key);

    assert_eq!(output, expected)
}

// Break repeating-key XOR
#[test]
fn challenge_6() {
    // Test hamming distance function
    // assert_eq!(calc_hamming_distance(b"this is a test".to_vec(), b"wokka wokka!!!".to_vec()), 37);
    let input_string = read_no_newlines("resources/set1_chal6.txt");
    let input_bytes: Vec<u8> = into_bytes::from_base64(input_string.as_bytes());

    let key = break_repeating_key_xor(input_bytes.as_slice());
    let decrypted_message = String::from_utf8(repeating_key_xor(input_bytes.as_slice(), key.as_slice())).unwrap();
    // println!("key: {:?},\nmessage: {}", String::from_utf8(key).unwrap(),
    //          String::from_utf8(decrypted_message).unwrap());
    assert!(decrypted_message.starts_with("I'm back and I'm ringin' the bell"));
}

// Decrypt AES in ECB mode
#[test]
fn challenge_7() {
    let input_string = read_no_newlines("resources/set1_chal7.txt");
    let input_bytes = into_bytes::from_base64(input_string.as_bytes());
    let key = b"YELLOW SUBMARINE";

    let result = String::from_utf8(aes_128_ecb_decrypt(input_bytes.as_slice(), key)).unwrap();

    assert!(result.starts_with("I'm back and I'm ringin' the bell"));
    let encrypted = aes_128_ecb_encrypt(input_bytes.as_slice(), key);
    assert_eq!(input_bytes, aes_128_ecb_decrypt(encrypted.as_slice(), key));
}

// Detect AES in ECB mode
#[test]
fn challenge_8() {
    let input_lines = read_lines("resources/set1_chal8.txt").unwrap().map(|line| line.unwrap()).collect_vec();

    let scores = input_lines.iter().enumerate().map(|(line_num, line)| {
        let line_bytes = from_hex(line.as_str());
        let duplicates = count_duplicate_blocks(line_bytes.as_slice(), 16);
        (line_num + 1, line, duplicates)
    });
    let sorted = scores.sorted_by(|a, b| a.2.cmp(&b.2)).collect_vec();
    let winner = sorted.last().unwrap();

    assert_eq!(winner.0, 133);
    // println!("The AES-ECB encrypted string block is on line {}: \n{}\nwith {} duplicates", winner.0, winner.1, winner.2);
}
