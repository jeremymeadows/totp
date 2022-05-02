//! Implementation of the SHA-2 256-bit hash function.
//!
//! Passes the NIST test vectors for the
//! [hashing algorithm](https://csrc.nist.gov/csrc/media/projects/cryptographic-standards-and-guidelines/documents/examples/sha1.pdf)
//! and the
//! [HMAC algorithm](https://csrc.nist.gov/csrc/media/projects/cryptographic-standards-and-guidelines/documents/examples/hmac_sha1.pdf)

/// Number of bytes in each block.
const BLOCK_SIZE: usize = 64;
/// Number of bytes in the final digest.
const OUTPUT_SIZE: usize = 32;

const K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

/// A SHA-2 hasher.
pub struct Sha256 {
    data: Vec<u8>,
    h: [u32; 8],
}

/// The completed digest for a given hash.
pub struct Digest {
    h: [u32; 8],
}

impl Sha256 {
    /// Creates a new SHA-2 hasher with no internal data.
    pub fn new() -> Self {
        Self {
            data: Vec::new(),
            h: [
                0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
                0x5be0cd19,
            ],
        }
    }

    /// Gets the digest of the provided byte slice.
    pub fn hash(bytes: &[u8]) -> Digest {
        let mut hasher = Sha256::new();
        hasher.add(bytes);
        hasher.digest()
    }

    /// Gets the HMAC of the provided data, using a key.
    pub fn hmac(key: &[u8], data: &[u8]) -> Digest {
        let mut hasher = Sha256::new();
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
        padding.append(
            &mut ([0x00_u8]
                .repeat(BLOCK_SIZE - 1 - (self.data.len() + u64::BITS as usize / 8) % BLOCK_SIZE)),
        );

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
    fn expand_block(block: &[u8; BLOCK_SIZE]) -> [u32; 64] {
        let mut w = [0; 64];

        for i in 0..16 {
            for j in 0..4 {
                w[i] += (block[i * 4 + j] as u32) << ((3 - j) * 8);
            }
        }

        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);

            w[i] = w[i - 16]
                .wrapping_add(w[i - 7])
                .wrapping_add(s0)
                .wrapping_add(s1);
        }

        w
    }

    /// Computes the digest for the currently loaded data.
    pub fn digest(&mut self) -> Digest {
        for block in self.blocks() {
            let data = Self::expand_block(&block);
            let (mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h) = (
                self.h[0], self.h[1], self.h[2], self.h[3], self.h[4], self.h[5], self.h[6],
                self.h[7],
            );

            for i in 0..64 {
                let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
                let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
                let ch = (e & f) ^ (!e & g);
                let maj = (a & b) ^ (a & c) ^ (b & c);
                let tmp_1 = h
                    .wrapping_add(s1)
                    .wrapping_add(ch)
                    .wrapping_add(K[i])
                    .wrapping_add(data[i]);
                let tmp_2 = s0.wrapping_add(maj);

                h = g;
                g = f;
                f = e;
                e = d.wrapping_add(tmp_1);
                d = c;
                c = b;
                b = a;
                a = tmp_1.wrapping_add(tmp_2);
            }

            self.h = [
                self.h[0].wrapping_add(a),
                self.h[1].wrapping_add(b),
                self.h[2].wrapping_add(c),
                self.h[3].wrapping_add(d),
                self.h[4].wrapping_add(e),
                self.h[5].wrapping_add(f),
                self.h[6].wrapping_add(g),
                self.h[7].wrapping_add(h),
            ];
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

        let h: [u32; 8] = Self::hash(
            &[
                &o_pad,
                Self::hash(&[&i_pad, self.data.as_slice()].concat())
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
            h: [h[0], h[1], h[2], h[3], h[4], h[5], h[6], h[7]],
        }
    }
}

impl Digest {
    /// Gets a hex-string representation of the digest.
    pub fn to_string(&self) -> String {
        self.h.map(|e| format!("{:08x}", e)).join("")
    }

    /// Gets the digest as an array of bytes.
    pub fn as_bytes(&self) -> [u8; OUTPUT_SIZE] {
        self.h
            .map(|e| e.to_be_bytes())
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
    fn empty_message() {
        let hash = Sha256::hash(b"");

        assert_eq!(
            hash.to_string(),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        );
        assert_eq!(
            hash.as_bytes(),
            [
                0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f,
                0xb9, 0x24, 0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c, 0xa4, 0x95, 0x99, 0x1b,
                0x78, 0x52, 0xb8, 0x55,
            ]
        );
    }

    #[test]
    fn one_block_message() {
        let hash = Sha256::hash(b"abc");

        assert_eq!(
            hash.to_string(),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_eq!(
            hash.as_bytes(),
            [
                0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde, 0x5d, 0xae,
                0x22, 0x23, 0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61,
                0xf2, 0x00, 0x15, 0xad,
            ]
        );
    }

    #[test]
    fn two_block_message() {
        let hash = Sha256::hash(b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq");

        assert_eq!(
            hash.to_string(),
            "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1",
        );
        assert_eq!(
            hash.as_bytes(),
            [
                0x24, 0x8d, 0x6a, 0x61, 0xd2, 0x06, 0x38, 0xb8, 0xe5, 0xc0, 0x26, 0x93, 0x0c, 0x3e,
                0x60, 0x39, 0xa3, 0x3c, 0xe4, 0x59, 0x64, 0xff, 0x21, 0x67, 0xf6, 0xec, 0xed, 0xd4,
                0x19, 0xdb, 0x06, 0xc1,
            ]
        );
    }
}
