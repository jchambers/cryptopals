pub struct Sha1 {
    hash: [u32; 5],
    buffer: [u8; 64],
    buffer_write_index: usize,
    message_length_bytes: usize,
}

impl Sha1 {
    const INITIAL_HASH: [u32; 5] = [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0];

    fn new() -> Self {
        Self {
            hash: Sha1::INITIAL_HASH,

            buffer: [0; 64],
            buffer_write_index: 0,
            message_length_bytes: 0,
        }
    }

    pub fn update(&mut self, bytes: &[u8]) {
        let mut read_index = 0;

        while read_index < bytes.len() {
            let bytes_to_read =
                (bytes.len() - read_index).min(self.buffer.len() - self.buffer_write_index);

            self.buffer[self.buffer_write_index..self.buffer_write_index + bytes_to_read]
                .clone_from_slice(&bytes[read_index..read_index + bytes_to_read]);

            read_index += bytes_to_read;
            self.buffer_write_index += bytes_to_read;

            if self.buffer_write_index == self.buffer.len() {
                self.process_buffer();
                self.buffer_write_index = 0;
            }
        }

        self.message_length_bytes += bytes.len();
    }

    fn process_buffer(&mut self) {
        let mut extended = [0; 80];

        self.buffer
            .chunks_exact(4)
            .enumerate()
            .for_each(|(i, word)| {
                extended[i] =
                    u32::from_be_bytes(word.try_into().unwrap());
            });

        for i in 16..extended.len() {
            // w[i] = (w[i-3] xor w[i-8] xor w[i-14] xor w[i-16]) leftrotate 1
            extended[i] =
                (extended[i - 3] ^ extended[i - 8] ^ extended[i - 14] ^ extended[i - 16]).rotate_left(1);
        }

        let [mut a, mut b, mut c, mut d, mut e] = self.hash;

        for i in 0..extended.len() {
            let (f, k) = match i {
                0..=19 => (
                    (b & c) ^ (!b & d),
                    0x5a827999,
                ),

                20..=39 => (
                    b ^ c ^ d,
                    0x6ed9eba1,
                ),

                40..=59 => (
                    (b & c) ^ (b & d) ^ (c & d),
                    0x8f1bbcdc,
                ),

                _ => (
                    b ^ c ^ d,
                    0xca62c1d6,
                ),
            };

            let next_a = (a.rotate_left(5))
                .wrapping_add(f)
                .wrapping_add(e)
                .wrapping_add(k)
                .wrapping_add(extended[i]);

            e = d;
            d = c;
            c = b.rotate_left(30);
            b = a;
            a = next_a;
        }

        self.hash[0] = self.hash[0].wrapping_add(a);
        self.hash[1] = self.hash[1].wrapping_add(b);
        self.hash[2] = self.hash[2].wrapping_add(c);
        self.hash[3] = self.hash[3].wrapping_add(d);
        self.hash[4] = self.hash[4].wrapping_add(e);
    }

    pub fn finish(&mut self) -> Vec<u8> {
        self.update(&[0x80]);
        self.message_length_bytes -= 1;

        // This could be more efficient, but opting for clarity for the moment
        while self.buffer_write_index != 56 {
            self.update(&[0x00]);

            // Hacky!
            self.message_length_bytes -= 1;
        }

        let message_length_bits = self.message_length_bytes as u64 * 8;

        self.buffer[56..].clone_from_slice(&message_length_bits.to_be_bytes());
        self.process_buffer();

        let mut hash = Vec::with_capacity(20);

        for word in self.hash {
            hash.extend_from_slice(&word.to_be_bytes());
        }

        hash
    }
}

#[cfg(test)]
mod test {
    use crate::sha1::Sha1;

    #[test]
    fn test_hash() {
        // Test vectors from https://www.di-mgt.com.au/sha_testvectors.html
        {
            let mut sha1 = Sha1::new();
            sha1.update(&[]);

            assert_eq!(
                hex::decode("da39a3ee5e6b4b0d3255bfef95601890afd80709").unwrap(),
                sha1.finish()
            )
        }

        {
            let mut sha1 = Sha1::new();
            sha1.update(b"abc");

            assert_eq!(
                hex::decode("a9993e364706816aba3e25717850c26c9cd0d89d").unwrap(),
                sha1.finish()
            )
        }

        {
            let mut sha1 = Sha1::new();
            sha1.update(b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq");

            assert_eq!(
                hex::decode("84983e441c3bd26ebaae4aa1f95129e5e54670f1").unwrap(),
                sha1.finish()
            )
        }

        {
            let mut sha1 = Sha1::new();
            sha1.update(b"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu");

            assert_eq!(
                hex::decode("a49b2446a02c645bf419f995b67091253a04a259").unwrap(),
                sha1.finish()
            )
        }

        {
            let mut sha1 = Sha1::new();

            for _ in 0..1_000_000 / 64 {
                sha1.update(&[b'a'; 64]);
            }

            assert_eq!(
                hex::decode("34aa973cd4c4daa4f61eeb2bdbad27316534016f").unwrap(),
                sha1.finish()
            )
        }

        {
            let mut sha1 = Sha1::new();

            for _ in 0..16_777_216 {
                sha1.update(b"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmno");
            }

            assert_eq!(
                hex::decode("7789f0c9ef7bfc40d93311143dfbe69e2017f592").unwrap(),
                sha1.finish()
            )
        }
    }
}
