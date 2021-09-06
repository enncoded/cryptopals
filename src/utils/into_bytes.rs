// from https://stackoverflow.com/questions/26185485/how-to-convert-hexadecimal-values-to-base64-in-rust
pub fn from_hex(input: &str) -> Vec<u8> {
    let mut bytes = Vec::new();
    for i in 0..(input.len() / 2) {
        let res = u8::from_str_radix(&input[2 * i .. 2 * i + 2], 16);
        match res {
            Ok(v) => bytes.push(v),
            Err(e) => println!("Problem converting `{}` to b64", e)
        }
    }

    bytes
}

pub fn from_base64(input: &[u8]) -> Vec<u8> {
    base64::decode(input).unwrap()
}
