use std::ops::BitXor;

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
