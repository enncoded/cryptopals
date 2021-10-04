use crate::utils::*;
use std::convert::TryFrom;
use std::error::Error;
use std::io::Bytes;
use std::string::ParseError;
use itertools::Itertools;

pub fn char_freq(input: &[u8]) -> f32 {
    let mut score = 0.0;
    for i in input {
        let c = (*i as char).to_ascii_lowercase();
        let char_score = match c {
            'e' => 12.702,
            't' => 9.056,
            'a' => 8.167,
            'o' => 7.507,
            'i' => 6.094,
            'n' => 6.749,
            's' => 6.327,
            'h' => 6.094,
            'r' => 5.987,
            'd' => 4.254,
            'l' => 4.025,
            'c' => 2.782,
            'u' => 2.756,
            'm' => 2.406,
            'w' => 2.36,
            'f' => 2.228,
            'g' => 2.015,
            'y' => 1.974,
            'p' => 1.929,
            'b' => 1.492,
            'v' => 0.978,
            'k' => 0.772,
            'j' => 0.153,
            'x' => 0.15,
            'q' => 0.095,
            'z' => 0.074,
            ' ' => 0.0,
            '.' => 0.0,
            ',' => 0.0,
            ';' => 0.0,
            ':' => 0.0,
            '\'' => 0.0,
            '\n' => 0.0,
            _ => -10.0,
        };
        score += char_score;
    };

    score
}

pub fn calc_char_freq_for_bytes(input: Vec<u8>) -> (String, u8) {
    let mut winning_key: u8 = 0;
    let mut highest = 0.0;
    let mut winning_string = String::new();
    for i in u8::MIN..u8::MAX {
        let xor_output = xor::single_byte_xor(input.as_slice(), i);
        let score = algos::char_freq(xor_output.as_slice());
        if score > highest {
            highest = score;
            winning_string = String::from_utf8(xor_output.clone()).unwrap_or_default();

            winning_key = i;
        }
        //println!("{} - {}", String::from_utf8(xor_output).unwrap(), score);
    }

    (winning_string.clone(), winning_key)
}

// Computes the edit distance between 2 strings
pub fn calc_hamming_distance(first: Vec<u8>, second: Vec<u8>) -> u32 {
    let mut sum = first.iter().zip(second.iter()).map(|(a, b)| {
        (a ^ b).count_ones()
    }).sum();

    sum += u32::try_from(i32::try_from(first.len() - second.len()).unwrap().abs() * 8).unwrap();

    sum
}

fn pkcs7_pad_block(input_block: &[u8], block_size: usize) -> Vec<u8> {
    let mut output = input_block.clone().to_vec();
    let mut pad_length = block_size - input_block.len();
    let pad_byte = pad_length as u8;

    if pad_length == 0 {
        pad_length = block_size;
    }

    for i in 0..pad_length {
        output.push(pad_byte);
    }

    output
}

// Pads a message
pub fn pkcs7_pad(input: &[u8], block_size: usize) -> Vec<u8> {
    let mut output = input.clone().to_vec();
    let input_len = input.len();

    let mut padding_len = block_size - (input_len % block_size);
    if padding_len == 0 {
        padding_len = block_size;
    }

    let padding_byte = padding_len as u8;
    for i in 0..padding_len {
        output.push(padding_byte);
    }

    output
}

pub fn pkcs7_unpad(input: &[u8], block_size: usize) -> Vec<u8> {
    validate_pkcs7_padding(input, block_size);

    let input_len = input.len();
    let pad_len = input[input_len - 1] as usize;
    input[0..(input_len - pad_len)].to_vec()
}


fn validate_pkcs7_padding(input: &[u8], block_size: usize) {
    if input.len() % block_size != 0 {
        panic!("Invalid padding for input: {:?}", input);
    }
}
