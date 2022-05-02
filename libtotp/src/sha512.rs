//! Implementation of the SHA-2 512-bit hash function.
//!
//! Passes the NIST test vectors for the
//! [hashing algorithm](https://csrc.nist.gov/csrc/media/projects/cryptographic-standards-and-guidelines/documents/examples/sha1.pdf)
//! and the
//! [HMAC algorithm](https://csrc.nist.gov/csrc/media/projects/cryptographic-standards-and-guidelines/documents/examples/hmac_sha1.pdf)

/// Number of bytes in each block.
const BLOCK_SIZE: usize = 128;
/// Number of bytes in the final digest.
const OUTPUT_SIZE: usize = 64;

const K: [u64; 80] = [
    0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc,
    0x3956c25bf348b538, 0x59f111f1b605d019, 0x923f82a4af194f9b, 0xab1c5ed5da6d8118,
    0xd807aa98a3030242, 0x12835b0145706fbe, 0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2,
    0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235, 0xc19bf174cf692694,
    0xe49b69c19ef14ad2, 0xefbe4786384f25e3, 0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65,
    0x2de92c6f592b0275, 0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5,
    0x983e5152ee66dfab, 0xa831c66d2db43210, 0xb00327c898fb213f, 0xbf597fc7beef0ee4,
    0xc6e00bf33da88fc2, 0xd5a79147930aa725, 0x06ca6351e003826f, 0x142929670a0e6e70,
    0x27b70a8546d22ffc, 0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed, 0x53380d139d95b3df,
    0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47edaee6, 0x92722c851482353b,
    0xa2bfe8a14cf10364, 0xa81a664bbc423001, 0xc24b8b70d0f89791, 0xc76c51a30654be30,
    0xd192e819d6ef5218, 0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8,
    0x19a4c116b8d2d0c8, 0x1e376c085141ab53, 0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8,
    0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb, 0x5b9cca4f7763e373, 0x682e6ff3d6b2b8a3,
    0x748f82ee5defb2fc, 0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec,
    0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915, 0xc67178f2e372532b,
    0xca273eceea26619c, 0xd186b8c721c0c207, 0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178,
    0x06f067aa72176fba, 0x0a637dc5a2c898a6, 0x113f9804bef90dae, 0x1b710b35131c471b,
    0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc, 0x431d67c49c100d4c,
    0x4cc5d4becb3e42b6, 0x597f299cfc657e2a, 0x5fcb6fab3ad6faec, 0x6c44198c4a475817,
];

/// A SHA-2 hasher.
pub struct Sha512 {
    data: Vec<u8>,
    h: [u64; 8],
}

/// The completed digest for a given hash.
pub struct Digest {
    h: [u64; 8],
}

impl Sha512 {
    /// Creates a new SHA-2 hasher with no internal data.
    pub fn new() -> Self {
        Self {
            data: Vec::new(),
            h: [
                0x6a09e667f3bcc908,
                0xbb67ae8584caa73b,
                0x3c6ef372fe94f82b,
                0xa54ff53a5f1d36f1,
                0x510e527fade682d1,
                0x9b05688c2b3e6c1f,
                0x1f83d9abfb41bd6b,
                0x5be0cd19137e2179,
            ],
        }
    }

    /// Gets the digest of the provided byte slice.
    pub fn hash(bytes: &[u8]) -> Digest {
        let mut hasher = Sha512::new();
        hasher.add(bytes);
        hasher.digest()
    }

    /// Gets the HMAC of the provided data, using a key.
    pub fn hmac(key: &[u8], data: &[u8]) -> Digest {
        let mut hasher = Sha512::new();
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
                .repeat(BLOCK_SIZE - 1 - (self.data.len() + u128::BITS as usize / 8) % BLOCK_SIZE)),
        );

        data.append(&mut padding);
        data.append(&mut Vec::from((self.data.len() as u128 * 8).to_be_bytes()));
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
    fn expand_block(block: &[u8; BLOCK_SIZE]) -> [u64; 80] {
        let mut w = [0; 80];

        for i in 0..16 {
            for j in 0..8 {
                w[i] += (block[i * 8 + j] as u64) << ((7 - j) * 8);
            }
        }

        for i in 16..80 {
            let s0 = w[i - 15].rotate_right(1) ^ w[i - 15].rotate_right(8) ^ (w[i - 15] >> 7);
            let s1 = w[i - 2].rotate_right(19) ^ w[i - 2].rotate_right(61) ^ (w[i - 2] >> 6);

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

            for i in 0..80 {
                let s0 = a.rotate_right(28) ^ a.rotate_right(34) ^ a.rotate_right(39);
                let s1 = e.rotate_right(14) ^ e.rotate_right(18) ^ e.rotate_right(41);
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

        let h: [u64; 8] = Self::hash(
            &[
                &o_pad,
                Self::hash(&[&i_pad, self.data.as_slice()].concat())
                    .as_bytes()
                    .as_slice(),
            ]
            .concat(),
        )
        .as_bytes()
        .chunks(8)
        .map(|e| u64::from_be_bytes(e.try_into().unwrap()))
        .collect::<Vec<u64>>()
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
        self.h.map(|e| format!("{:016x}", e)).join("")
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
        let hash = Sha512::hash(b"");

        assert_eq!(
            hash.to_string(),
            "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e",
        );
        assert_eq!(
            hash.as_bytes(),
            [
                0xcf, 0x83, 0xe1, 0x35, 0x7e, 0xef, 0xb8, 0xbd, 0xf1, 0x54, 0x28, 0x50, 0xd6, 0x6d,
                0x80, 0x07, 0xd6, 0x20, 0xe4, 0x05, 0x0b, 0x57, 0x15, 0xdc, 0x83, 0xf4, 0xa9, 0x21,
                0xd3, 0x6c, 0xe9, 0xce, 0x47, 0xd0, 0xd1, 0x3c, 0x5d, 0x85, 0xf2, 0xb0, 0xff, 0x83,
                0x18, 0xd2, 0x87, 0x7e, 0xec, 0x2f, 0x63, 0xb9, 0x31, 0xbd, 0x47, 0x41, 0x7a, 0x81,
                0xa5, 0x38, 0x32, 0x7a, 0xf9, 0x27, 0xda, 0x3e,
            ]
        );
    }

    #[test]
    fn one_block_message() {
        let hash = Sha512::hash(b"abc");

        assert_eq!(
            hash.to_string(),
            "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f",
        );
        assert_eq!(
            hash.as_bytes(),
            [
                0xdd, 0xaf, 0x35, 0xa1, 0x93, 0x61, 0x7a, 0xba, 0xcc, 0x41, 0x73, 0x49, 0xae, 0x20,
                0x41, 0x31, 0x12, 0xe6, 0xfa, 0x4e, 0x89, 0xa9, 0x7e, 0xa2, 0x0a, 0x9e, 0xee, 0xe6,
                0x4b, 0x55, 0xd3, 0x9a, 0x21, 0x92, 0x99, 0x2a, 0x27, 0x4f, 0xc1, 0xa8, 0x36, 0xba,
                0x3c, 0x23, 0xa3, 0xfe, 0xeb, 0xbd, 0x45, 0x4d, 0x44, 0x23, 0x64, 0x3c, 0xe8, 0x0e,
                0x2a, 0x9a, 0xc9, 0x4f, 0xa5, 0x4c, 0xa4, 0x9f,
            ]
        );
    }

    #[test]
    fn two_block_message() {
        let hash = Sha512::hash(b"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu");

        assert_eq!(
            hash.to_string(),
            "8e959b75dae313da8cf4f72814fc143f8f7779c6eb9f7fa17299aeadb6889018501d289e4900f7e4331b99dec4b5433ac7d329eeb6dd26545e96e55b874be909",
        );
        assert_eq!(
            hash.as_bytes(),
            [
                0x8e, 0x95, 0x9b, 0x75, 0xda, 0xe3, 0x13, 0xda, 0x8c, 0xf4, 0xf7, 0x28, 0x14, 0xfc,
                0x14, 0x3f, 0x8f, 0x77, 0x79, 0xc6, 0xeb, 0x9f, 0x7f, 0xa1, 0x72, 0x99, 0xae, 0xad,
                0xb6, 0x88, 0x90, 0x18, 0x50, 0x1d, 0x28, 0x9e, 0x49, 0x00, 0xf7, 0xe4, 0x33, 0x1b,
                0x99, 0xde, 0xc4, 0xb5, 0x43, 0x3a, 0xc7, 0xd3, 0x29, 0xee, 0xb6, 0xdd, 0x26, 0x54,
                0x5e, 0x96, 0xe5, 0x5b, 0x87, 0x4b, 0xe9, 0x09,
            ]
        );
    }
}
