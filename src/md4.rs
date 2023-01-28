pub struct MD4 {
    hash: [u32; 4],
    buffer: [u8; 64],
    buffer_write_index: usize,
    message_length_bytes: usize,
}

macro_rules! round1 {
    ($a:expr, $b:expr, $c:expr, $d:expr, $k:expr, $s:expr, $X:expr) => {
        $a = $a
            .wrapping_add(($b & $c) | (!$b & $d))
            .wrapping_add($X[$k])
            .rotate_left($s);
    }
}

macro_rules! round2 {
    ($a:expr, $b:expr, $c:expr, $d:expr, $k:expr, $s:expr, $X:expr) => {
        $a = $a
            .wrapping_add(($b & $c) | ($b & $d) | ($c & $d))
            .wrapping_add($X[$k])
            .wrapping_add(0x5a827999)
            .rotate_left($s);
    }
}

macro_rules! round3 {
    ($a:expr, $b:expr, $c:expr, $d:expr, $k:expr, $s:expr, $X:expr) => {
        $a = $a
            .wrapping_add($b ^ $c ^ $d)
            .wrapping_add($X[$k])
            .wrapping_add(0x6ed9eba1)
            .rotate_left($s);
    }
}

impl MD4 {
    pub fn with_initial_state(hash: &[u8], message_length_bytes: usize) -> Self {
        assert_eq!(16, hash.len());

        let hash_words: Vec<u32> = hash.chunks_exact(4)
            .map(|word| u32::from_le_bytes(word.try_into().unwrap()))
            .collect();

        Self {
            hash: hash_words.as_slice().try_into().unwrap(),

            buffer: [0; 64],
            buffer_write_index: 0,
            message_length_bytes,
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
        let words: Vec<u32> = self.buffer
            .chunks_exact(4)
            .map(|chunk| u32::from_le_bytes(chunk.try_into().unwrap()))
            .collect();

        let [mut a, mut b, mut c, mut d] = self.hash;

        round1!(a, b, c, d, 0,  3,  words);
        round1!(d, a, b, c, 1,  7,  words);
        round1!(c, d, a, b, 2,  11, words);
        round1!(b, c, d, a, 3,  19, words);
        round1!(a, b, c, d, 4,  3,  words);
        round1!(d, a, b, c, 5,  7,  words);
        round1!(c, d, a, b, 6,  11, words);
        round1!(b, c, d, a, 7,  19, words);
        round1!(a, b, c, d, 8,  3,  words);
        round1!(d, a, b, c, 9,  7,  words);
        round1!(c, d, a, b, 10, 11, words);
        round1!(b, c, d, a, 11, 19, words);
        round1!(a, b, c, d, 12, 3,  words);
        round1!(d, a, b, c, 13, 7,  words);
        round1!(c, d, a, b, 14, 11, words);
        round1!(b, c, d, a, 15, 19, words);

        round2!(a, b, c, d, 0,  3,  words);
        round2!(d, a, b, c, 4,  5,  words);
        round2!(c, d, a, b, 8,  9,  words);
        round2!(b, c, d, a, 12, 13, words);
        round2!(a, b, c, d, 1,  3,  words);
        round2!(d, a, b, c, 5,  5,  words);
        round2!(c, d, a, b, 9,  9,  words);
        round2!(b, c, d, a, 13, 13, words);
        round2!(a, b, c, d, 2,  3,  words);
        round2!(d, a, b, c, 6,  5,  words);
        round2!(c, d, a, b, 10, 9,  words);
        round2!(b, c, d, a, 14, 13, words);
        round2!(a, b, c, d, 3,  3,  words);
        round2!(d, a, b, c, 7,  5,  words);
        round2!(c, d, a, b, 11, 9,  words);
        round2!(b, c, d, a, 15, 13, words);

        round3!(a, b, c, d, 0,  3,  words);
        round3!(d, a, b, c, 8,  9,  words);
        round3!(c, d, a, b, 4,  11, words);
        round3!(b, c, d, a, 12, 15, words);
        round3!(a, b, c, d, 2,  3,  words);
        round3!(d, a, b, c, 10, 9,  words);
        round3!(c, d, a, b, 6,  11, words);
        round3!(b, c, d, a, 14, 15, words);
        round3!(a, b, c, d, 1,  3,  words);
        round3!(d, a, b, c, 9,  9,  words);
        round3!(c, d, a, b, 5,  11, words);
        round3!(b, c, d, a, 13, 15, words);
        round3!(a, b, c, d, 3,  3,  words);
        round3!(d, a, b, c, 11, 9,  words);
        round3!(c, d, a, b, 7,  11, words);
        round3!(b, c, d, a, 15, 15, words);

        self.hash[0] = self.hash[0].wrapping_add(a);
        self.hash[1] = self.hash[1].wrapping_add(b);
        self.hash[2] = self.hash[2].wrapping_add(c);
        self.hash[3] = self.hash[3].wrapping_add(d);
    }

    pub fn finish(mut self) -> Vec<u8> {
        self.update(&MD4::padding(self.message_length_bytes));

        let mut hash = Vec::with_capacity(20);

        for word in self.hash {
            hash.extend_from_slice(&word.to_le_bytes());
        }

        hash
    }

    pub fn padding(message_length_bytes: usize) -> Vec<u8> {
        let padding_length = (56 - (message_length_bytes + 1) as isize).rem_euclid(64) as usize;

        let mut padding = vec![0; padding_length + 1];
        padding[0] = 0x80;

        let message_length_bits = message_length_bytes as u64 * 8;
        padding.extend_from_slice(&message_length_bits.to_le_bytes());

        padding
    }
}

impl Default for MD4 {
    fn default() -> Self {
        Self {
            hash: [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476],

            buffer: [0; 64],
            buffer_write_index: 0,
            message_length_bytes: 0,
        }
    }
}

#[cfg(test)]
mod test {
    use crate::md4::MD4;

    const TEST_VECTORS: [(&str, &str); 7] = [
            (
                "",
                "31d6cfe0d16ae931b73c59d7e0c089c0"),
            (
                "a",
                "bde52cb31de33e46245e05fbdbd6fb24"),
            (
                "abc",
                "a448017aaf21d8525fc10ae87aa6729d"),
            (
                "message digest",
                "d9130a8164549fe818874806e1c7014b"),
            (
                "abcdefghijklmnopqrstuvwxyz",
                "d79e1c308aa5bbcdeea8ed63df412da9"),
            (
                "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
                "043f8582f241db351ce627e153e7f0e4"
            ),
            (
                "12345678901234567890123456789012345678901234567890123456789012345678901234567890",
                "e33b4ddc9c38f2199c3e7b164fcc0536"
            ),
    ];

    #[test]
    fn test_hash() {
        for (message, digest) in TEST_VECTORS {
            let mut md4 = MD4::default();
            md4.update(message.as_bytes());

            assert_eq!(hex::decode(digest).unwrap(), md4.finish());
        }
    }
}
