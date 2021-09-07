use crate::utils::*;
use crate::utils::algos::{calc_char_freq_for_bytes, calc_hamming_distance};
use crate::utils::xor::repeating_key_xor;
use std::fs::read_to_string;

#[test]
// convert hex to base64
fn challenge_1() {
    let input = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d";
    let expected = "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t";

    let output = base64::encode(into_bytes::from_hex(input));
    assert_eq!(expected, output);
}

#[test]
// Fixed (2 equal length buffers) XOR
fn challenge_2() {
    let input = into_bytes::from_hex("1c0111001f010100061a024b53535009181c"); // encoded hexadecimal string
    let xor_key = into_bytes::from_hex("686974207468652062756c6c277320657965");
    let expected = "746865206b696420646f6e277420706c6179";

    let xor_output = xor::fixed_xor(input, xor_key);
    let output = from_bytes::into_hex(xor_output);

    assert_eq!(expected, output)
}

#[test]
fn challenge_3() {
    let input = into_bytes::from_hex("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736");

    let (winning_string, _) = algos::calc_char_freq_for_bytes(input);

    assert_eq!(winning_string, "Cooking MC's like a pound of bacon");
    // println!("{} won. Key used was {}", winning_string, winning_key);
}

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

#[test]
fn challenge_5() {
    let input = b"Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal";
    let expected = into_bytes::from_hex("0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f");
    let key = b"ICE";

    let output = repeating_key_xor(input, key);

    assert_eq!(output, expected)
}

#[test]
fn challenge_6() {
    // Test hamming distance function
    // assert_eq!(calc_hamming_distance(b"this is a test".to_vec(), b"wokka wokka!!!".to_vec()), 37);

    // Ugly code warning :)
    let input_string: String = read_to_string("resources/set1_chal6.txt").expect("Error reading file")
        .chars().into_iter().filter(|c| *c != '\n').collect();
    let input_bytes: Vec<u8> = into_bytes::from_base64(input_string.as_bytes());

    let smallest_keysize = (2..41).map(|keysize| {
        let keysize_blocks: Vec<Vec<u8>> = input_bytes.chunks_exact(keysize).map(|b| b.to_vec()).collect();

        let mut kb_iter = keysize_blocks.iter();
        let mut distances = Vec::new();
        while kb_iter.len() >= 2 {
            let first_split = kb_iter.next().unwrap();
            let second_split = kb_iter.next().unwrap();

            distances.push(calc_hamming_distance(first_split.clone(), second_split.clone()) as f32 / keysize as f32);
        }
        let avg_distance = distances.iter().sum::<f32>() / distances.len() as f32;
        (keysize, avg_distance)
    }).min_by(|a, b| a.1.partial_cmp(&b.1).unwrap()).unwrap().0;

    let keysize_blocks: Vec<Vec<u8>> = input_bytes.chunks_exact(smallest_keysize).map(|b| b.to_vec()).collect();
    let mut inner_iters: Vec<_> = keysize_blocks.iter().map(|c| c.into_iter()).collect();
    let transposed_blocks: Vec<Vec<u8>> = (0..smallest_keysize).map(|_| {
        inner_iters.iter_mut().map(|ci| *ci.next().unwrap()).collect::<Vec<u8>>()
    }).collect();

    // println!("Smallest keysize: {} - {}, {}", smallest_keysize, keysize_blocks.len(), transposed_blocks.len());

    let key_bytes: Vec<u8> = transposed_blocks.iter().map(|inner_vec| {
        calc_char_freq_for_bytes(inner_vec.clone()).1
    }).collect();

    // println!("key: {}", String::from_utf8(key.to_vec()));
    let decrypted_message = String::from_utf8(repeating_key_xor(input_bytes.as_slice(), key_bytes.as_slice())).unwrap();
    // println!("key: {:?},\nmessage: {}", key_bytes, decrypted_message);
}


