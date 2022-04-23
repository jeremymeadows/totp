//! Implementation of the SHA-1 160-bit hash function.
//!
//! Passes the NIST test vectors for the 
//! [hashing algorithm](https://csrc.nist.gov/csrc/media/projects/cryptographic-standards-and-guidelines/documents/examples/sha1.pdf) 
//! and the
//! [HMAC algorithm](https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/HMAC_SHA1.pdf)

/// Number of bytes in each block.
const BLOCK_SIZE: usize = 64;
/// Number of bytes in the final digest.
const OUTPUT_SIZE: usize = 20;

/// A SHA-1 hasher.
pub struct Sha1 {
    data: Vec<u8>,
    h: (u32, u32, u32, u32, u32),
}

/// The completed digest for a given hash.
pub struct Digest {
    h: (u32, u32, u32, u32, u32),
}

impl Sha1 {
    /// Creates a new SHA-1 hasher with no internal data.
    pub fn new() -> Self {
        Self {
            data: Vec::new(),
            h: (0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0),
        }
    }

    /// Gets the digest of the provided byte slice.
    pub fn hash(bytes: &[u8]) -> Digest {
        let mut hasher = Sha1::new();
        hasher.add(bytes);
        hasher.digest()
    }

    /// Gets the HMAC of the provided data, using a key.
    pub fn hmac(key: &[u8], data: &[u8]) -> Digest {
        let mut hasher = Sha1::new();
        hasher.add(data);
        hasher.digest_hmac(key)
    }

    /// Adds data to the hasher.
    pub fn add(&mut self, bytes: &[u8]) {
        self.data.append(&mut Vec::from(bytes));
    }

    /// Pad the data with `0` so that it fits evenly into a multiple of `BLOCK_SIZE` bytes.
    fn pad(&self) -> Vec<u8> {
        let mut data = self.data.clone();
        let mut padding = vec![0x80_u8];
        padding
            .append(&mut ([0x00_u8].repeat(BLOCK_SIZE - 1 - (self.data.len() + 8) % BLOCK_SIZE)));

        data.append(&mut padding);
        data.append(&mut Vec::from((self.data.len() as u64 * 8).to_be_bytes()));
        data
    }

    /// Splits the data up into multiple blocks, each of which are `BLOCK_SIZE` bytes.
    fn blocks(&self) -> Vec<[u8; BLOCK_SIZE]> {
        let mut a = [0; BLOCK_SIZE];
        let mut v = Vec::new();

        for i in self.pad().chunks(BLOCK_SIZE).collect::<Vec<_>>() {
            for j in 0..a.len() {
                a[j] = i[j];
            }
            v.push(a.clone());
        }

        v
    }

    /// Expand a block to 80 bytes.
    fn expand_block(block: &[u8; BLOCK_SIZE]) -> [u32; 80] {
        let mut w = [0; 80];

        for i in 0..16 {
            for j in 0..4 {
                w[i] += (block[i * 4 + j] as u32) << ((3 - j) * 8);
            }
        }
        for i in 16..80 {
            w[i] = (w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]).rotate_left(1)
        }

        w
    }

    /// Computes the digest for the currently loaded data.
    pub fn digest(&mut self) -> Digest {
        for block in self.blocks() {
            let expanded_block = Self::expand_block(&block);
            let (mut a, mut b, mut c, mut d, mut e) = self.h;

            for i in 0..80 {
                let (f, k): (u32, u32) = if i < 20 {
                    ((b & c) | ((!b) & d), 0x5A827999)
                } else if i < 40 {
                    (b ^ c ^ d, 0x6ED9EBA1)
                } else if i < 60 {
                    ((b & c) | (b & d) | (c & d), 0x8F1BBCDC)
                } else {
                    (b ^ c ^ d, 0xCA62C1D6)
                };

                let tmp = a
                    .rotate_left(5)
                    .wrapping_add(f)
                    .wrapping_add(e)
                    .wrapping_add(k)
                    .wrapping_add(expanded_block[i]);
                e = d;
                d = c;
                c = b.rotate_left(30);
                b = a;
                a = tmp as u32;
            }

            self.h = (
                self.h.0.wrapping_add(a),
                self.h.1.wrapping_add(b),
                self.h.2.wrapping_add(c),
                self.h.3.wrapping_add(d),
                self.h.4.wrapping_add(e),
            );
        }

        Digest { h: self.h }
    }

    /// Computes the keyed hash-based message authentication code for the currently loaded data.
    pub fn digest_hmac(&mut self, key: &[u8]) -> Digest {
        let mut key = key.to_vec();

        if key.len() > BLOCK_SIZE {
            key = Self::hash(&key).as_bytes().to_vec();
        }

        while key.len() < BLOCK_SIZE {
            key.push(0);
        }

        let mut i_pad = [0x36_u8; BLOCK_SIZE];
        for i in 0..BLOCK_SIZE {
            i_pad[i] ^= key[i];
        }

        let mut o_pad = [0x5c_u8; BLOCK_SIZE];
        for i in 0..BLOCK_SIZE {
            o_pad[i] ^= key[i];
        }

        let h: [u32; 5] = Self::hash(
            &[
                o_pad.as_slice(),
                Self::hash(&[i_pad.as_slice(), self.data.as_slice()].concat())
                    .as_bytes()
                    .as_slice(),
            ]
            .concat(),
        )
        .as_bytes()
        .chunks(4)
        .map(|e| u32::from_be_bytes(e.try_into().unwrap()))
        .collect::<Vec<u32>>()
        .try_into()
        .unwrap();

        Digest {
            h: (h[0], h[1], h[2], h[3], h[4]),
        }
    }
}

impl Digest {
    /// Gets a hex-string representation of the digest.
    pub fn to_string(&self) -> String {
        format!(
            "{:08x}{:08x}{:08x}{:08x}{:08x}",
            self.h.0, self.h.1, self.h.2, self.h.3, self.h.4
        )
    }

    /// Gets the digest as an array of bytes.
    pub fn as_bytes(&self) -> [u8; OUTPUT_SIZE] {
        [
            self.h.0.to_be_bytes(),
            self.h.1.to_be_bytes(),
            self.h.2.to_be_bytes(),
            self.h.3.to_be_bytes(),
            self.h.4.to_be_bytes(),
        ]
        .iter()
        .flat_map(|e| e.to_owned())
        .collect::<Vec<u8>>()
        .try_into()
        .unwrap()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_1() {
        let hash = Sha1::hash(b"abc");

        assert_eq!(hash.to_string(), "a9993e364706816aba3e25717850c26c9cd0d89d");
        assert_eq!(
            hash.as_bytes(),
            [
                0xa9, 0x99, 0x3e, 0x36, 0x47, 0x06, 0x81, 0x6a, 0xba, 0x3e, 0x25, 0x71, 0x78, 0x50,
                0xc2, 0x6c, 0x9c, 0xd0, 0xd8, 0x9d
            ]
        );
    }

    #[test]
    fn test_2() {
        let hash = Sha1::hash(b"");

        assert_eq!(hash.to_string(), "da39a3ee5e6b4b0d3255bfef95601890afd80709");
        assert_eq!(
            hash.as_bytes(),
            [
                0xda, 0x39, 0xa3, 0xee, 0x5e, 0x6b, 0x4b, 0x0d, 0x32, 0x55, 0xbf, 0xef, 0x95, 0x60,
                0x18, 0x90, 0xaf, 0xd8, 0x07, 0x09
            ]
        );
    }

    #[test]
    fn test_3() {
        let hash = Sha1::hash(b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq");

        assert_eq!(hash.to_string(), "84983e441c3bd26ebaae4aa1f95129e5e54670f1");
        assert_eq!(
            hash.as_bytes(),
            [
                0x84, 0x98, 0x3e, 0x44, 0x1c, 0x3b, 0xd2, 0x6e, 0xba, 0xae, 0x4a, 0xa1, 0xf9, 0x51,
                0x29, 0xe5, 0xe5, 0x46, 0x70, 0xf1,
            ]
        );
    }

    #[test]
    fn test_4() {
        let hash = Sha1::hash(b"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu");

        assert_eq!(hash.to_string(), "a49b2446a02c645bf419f995b67091253a04a259");
        assert_eq!(
            hash.as_bytes(),
            [
                0xa4, 0x9b, 0x24, 0x46, 0xa0, 0x2c, 0x64, 0x5b, 0xf4, 0x19, 0xf9, 0x95, 0xb6, 0x70,
                0x91, 0x25, 0x3a, 0x04, 0xa2, 0x59,
            ]
        );
    }

    #[test]
    fn test_5() {
        let hash = Sha1::hash(&b"a".repeat(1000000));

        assert_eq!(hash.to_string(), "34aa973cd4c4daa4f61eeb2bdbad27316534016f");
        assert_eq!(
            hash.as_bytes(),
            [
                0x34, 0xaa, 0x97, 0x3c, 0xd4, 0xc4, 0xda, 0xa4, 0xf6, 0x1e, 0xeb, 0x2b, 0xdb, 0xad,
                0x27, 0x31, 0x65, 0x34, 0x01, 0x6f,
            ]
        );
    }

    #[test]
    fn test_hmac_1() {
        let text = "Sample message for keylen=blocklen";
        let key = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D,
            0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B,
            0x1C, 0x1D, 0x1E, 0x1F, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29,
            0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
            0x38, 0x39, 0x3A, 0x3B, 0x3C, 0x3D, 0x3E, 0x3F,
        ];
        let mac = [
            0x5F, 0xD5, 0x96, 0xEE, 0x78, 0xD5, 0x55, 0x3C, 0x8F, 0xF4, 0xE7, 0x2D, 0x26, 0x6D,
            0xFD, 0x19, 0x23, 0x66, 0xDA, 0x29,
        ];

        assert_eq!(Sha1::hmac(key.as_slice(), text.as_bytes()).as_bytes(), mac);
    }

    #[test]
    fn test_hmac_2() {
        let text = "Sample message for keylen<blocklen";
        let key = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D,
            0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13,
        ];
        let mac = [
            0x4C, 0x99, 0xFF, 0x0C, 0xB1, 0xB3, 0x1B, 0xD3, 0x3F, 0x84, 0x31, 0xDB, 0xAF, 0x4D,
            0x17, 0xFC, 0xD3, 0x56, 0xA8, 0x07,
        ];

        assert_eq!(Sha1::hmac(key.as_slice(), text.as_bytes()).as_bytes(), mac);
    }

    #[test]
    fn test_hmac_3() {
        let text = "Sample message for keylen=blocklen";
        let key = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D,
            0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B,
            0x1C, 0x1D, 0x1E, 0x1F, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29,
            0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
            0x38, 0x39, 0x3A, 0x3B, 0x3C, 0x3D, 0x3E, 0x3F, 0x40, 0x41, 0x42, 0x43, 0x44, 0x45,
            0x46, 0x47, 0x48, 0x49, 0x4A, 0x4B, 0x4C, 0x4D, 0x4E, 0x4F, 0x50, 0x51, 0x52, 0x53,
            0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5A, 0x5B, 0x5C, 0x5D, 0x5E, 0x5F, 0x60, 0x61,
            0x62, 0x63,
        ];
        let mac = [
            0x2D, 0x51, 0xB2, 0xF7, 0x75, 0x0E, 0x41, 0x05, 0x84, 0x66, 0x2E, 0x38, 0xF1, 0x33,
            0x43, 0x5F, 0x4C, 0x4F, 0xD4, 0x2A,
        ];

        assert_eq!(Sha1::hmac(key.as_slice(), text.as_bytes()).as_bytes(), mac);
    }

    #[test]
    fn test_hmac_4() {
        let text = "Sample message for keylen<blocklen, with truncated tag";
        let key = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D,
            0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B,
            0x1C, 0x1D, 0x1E, 0x1F, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29,
            0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F, 0x30,
        ];
        let mac = [
            0xFE, 0x35, 0x29, 0x56, 0x5C, 0xD8, 0xE2, 0x8C, 0x5F, 0xA7, 0x9E, 0xAC,
        ];

        assert_eq!(
            Sha1::hmac(key.as_slice(), text.as_bytes()).as_bytes()[0..mac.len()],
            mac
        );
    }
}
