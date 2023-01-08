use std::collections::HashSet;
use rand::{Rng, RngCore};

fn main() {
    // Use a cleartext that guarantees we'll have at least two identical blocks even after padding
    const CLEARTEXT: &[u8] = &[0; 48];

    for _ in 0..100 {
        let (ciphertext, actual_block_mode) = EncryptionOracle::encrypt(CLEARTEXT);
        assert_eq!(actual_block_mode, detect_block_mode(&ciphertext));
    }
}

#[derive(Debug, Eq, PartialEq)]
enum BlockMode {
    ECB,
    CBC,
}

fn detect_block_mode(ciphertext: &[u8]) -> BlockMode {
    // A harder twist on this would be to pretend we don't know the block length, buuuut we do.
    const BLOCK_SIZE: usize = 16;

    let mut blocks = HashSet::new();

    let has_duplicate_block = ciphertext.chunks_exact(BLOCK_SIZE)
        .any(|block| !blocks.insert(block));

    if has_duplicate_block {
        BlockMode::ECB
    } else {
        BlockMode::CBC
    }
}

struct EncryptionOracle {
}

impl EncryptionOracle {
    pub fn encrypt(cleartext: &[u8]) -> (Vec<u8>, BlockMode) {
        let block_mode = if rand::thread_rng().gen_bool(0.5) {
            BlockMode::ECB
        } else {
            BlockMode::CBC
        };

        let padded_cleartext = {
            let mut leading_padding = vec![0; 5 + (rand::thread_rng().next_u32() % 5) as usize];
            let mut trailing_padding = vec![0; 5 + (rand::thread_rng().next_u32() % 5) as usize];

            rand::thread_rng().fill_bytes(leading_padding.as_mut_slice());
            rand::thread_rng().fill_bytes(trailing_padding.as_mut_slice());

            let mut padded_cleartext = Vec::with_capacity(leading_padding.len() + cleartext.len() + trailing_padding.len());
            padded_cleartext.append(&mut leading_padding);
            padded_cleartext.extend_from_slice(cleartext);
            padded_cleartext.append(&mut trailing_padding);

            padded_cleartext
        };

        let key = {
            let mut key = [0; 16];
            rand::thread_rng().fill_bytes(&mut key);

            key
        };

        let ciphertext = match block_mode {
            BlockMode::ECB => cryptopals::aes::aes_ecb_encrypt(&padded_cleartext, &key),
            BlockMode::CBC => {
                let iv = {
                    let mut iv = [0; 16];
                    rand::thread_rng().fill_bytes(&mut iv);

                    iv
                };

                cryptopals::aes::aes_cbc_encrypt(&padded_cleartext, &key, &iv)
            }
        };

        (ciphertext, block_mode)
    }
}
