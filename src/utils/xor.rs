use std::ops::BitXor;
use crate::utils::algos::{calc_hamming_distance, calc_char_freq_for_bytes};

// Takes bytes
pub fn fixed_xor(first: Vec<u8>, second: Vec<u8>) -> Vec<u8> {
    let mut output = Vec::new();

    for (x, y) in first.iter().zip(second) {
        let xor_val = x.bitxor(y);
        output.push(xor_val);
    }

    output
}

pub fn single_byte_xor(input_str: &[u8], xor_key: u8) -> Vec<u8> {
    input_str.iter().map(|b| b ^ xor_key).collect()
}

pub fn repeating_key_xor(input_str: &[u8], xor_key: &[u8]) -> Vec<u8> {
    let mut output = Vec::new();
    let mut key_iter = xor_key.iter().cycle();
    for input_byte in input_str {
        let key_byte = key_iter.next().unwrap();
        let result = *input_byte ^ *key_byte;
        // println!("{} ^ {} = {}", *input_byte as char, *key_byte as char, result);
        output.push(result);
    }
    output
}

pub fn break_repeating_key_xor(input_bytes: &[u8]) -> Vec<u8>{
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

    key_bytes
}
