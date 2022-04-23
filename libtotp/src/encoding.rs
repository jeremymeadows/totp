//! Library to manage encoding/decoding base64/base32 data.

const B64_ALPHABET: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
const B32_ALPHABET: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

/// Encodes data into a base64 string.
pub fn b64_encode(bytes: &[u8]) -> String {
    let mut bstr = String::new();
    let mut b64str = String::new();

    for b in bytes {
        bstr.push_str(&format!("{:08b}", b));
    }
    while bstr.len() % 6 != 0 {
        bstr.push('0');
    }

    for c in bstr.chars().collect::<Vec<char>>().chunks(6) {
        b64str.push(
            B64_ALPHABET
                .chars()
                .nth(
                    u8::from_str_radix(&c.iter().collect::<String>(), 2)
                        .unwrap()
                        .into(),
                )
                .unwrap(),
        );
    }
    while b64str.len() % 8 != 0 {
        b64str.push('=');
    }

    b64str
}

/// Decodes data from a base64 string.
pub fn b64_decode(b64str: &str) -> Vec<u8> {
    let mut bstr = String::new();
    let mut bytes = Vec::new();

    for c in b64str.trim_end_matches('=').chars() {
        let n = B64_ALPHABET.find(c).unwrap();
        bstr.push_str(&format!("{:06b}", n & 0x3f));
    }
    while bstr.len() % 8 != 0 {
        bstr.push('0');
    }

    for b in bstr.chars().collect::<Vec<char>>().chunks(8) {
        match u8::from_str_radix(&b.iter().collect::<String>(), 2) {
            Ok(b) if b != 0 => bytes.push(b),
            Ok(_) => (),
            Err(_) => panic!("invalid base64 string"),
        }
    }

    bytes
}

/// Encodes data into a base32 string.
pub fn b32_encode(bytes: &[u8]) -> String {
    let mut bstr = String::new();
    let mut b32str = String::new();

    for b in bytes {
        bstr.push_str(&format!("{:08b}", b));
    }
    while bstr.len() % 5 != 0 {
        bstr.push('0');
    }

    for c in bstr.chars().collect::<Vec<char>>().chunks(5) {
        b32str.push(
            B32_ALPHABET
                .chars()
                .nth(
                    u8::from_str_radix(&c.iter().collect::<String>(), 2)
                        .unwrap()
                        .into(),
                )
                .unwrap(),
        );
    }
    while b32str.len() % 8 != 0 {
        b32str.push('=');
    }

    b32str
}

/// Decodes data from a base32 string.
pub fn b32_decode(b32str: &str) -> Vec<u8> {
    let mut bstr = String::new();
    let mut bytes = Vec::new();

    for c in b32str.trim_end_matches('=').chars() {
        let n = B32_ALPHABET.find(c).unwrap();
        bstr.push_str(&format!("{:05b}", n & 0x1f));
    }
    while bstr.len() % 8 != 0 {
        bstr.push('0');
    }

    for b in bstr.chars().collect::<Vec<char>>().chunks(8) {
        match u8::from_str_radix(&b.iter().collect::<String>(), 2) {
            Ok(b) if b != 0 => bytes.push(b),
            Ok(_) => (),
            Err(_) => panic!("invalid base32 string"),
        }
    }

    bytes
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test() {
        assert_eq!(b32_encode(b"Hello!"), "JBSWY3DPEE======".to_string());
        assert_eq!(b32_decode("JBSWY3DPEE======"), b"Hello!");
    }
}
