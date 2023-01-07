use std::collections::HashSet;
use aes::Aes128;
use aes::cipher::generic_array::GenericArray;
use aes::cipher::{BlockEncrypt, KeyInit};
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
            BlockMode::ECB => Self::encrypt_ecb(&padded_cleartext, &key),
            BlockMode::CBC => {
                let iv = {
                    let mut iv = [0; 16];
                    rand::thread_rng().fill_bytes(&mut iv);

                    iv
                };

                Self::encrypt_cbc(&padded_cleartext, &key, &iv)
            }
        };

        (ciphertext, block_mode)
    }

    fn encrypt_ecb(cleartext: &[u8], key: &[u8]) -> Vec<u8> {
        let cipher = Aes128::new_from_slice(key).unwrap();
        let mut ciphertext = Vec::with_capacity(cleartext.len());

        cleartext.chunks(16)
            .map(Self::pkcs7_pad::<16>)
            .for_each(|block| {
                let mut block = GenericArray::from(block);
                cipher.encrypt_block(&mut block);

                ciphertext.extend_from_slice(block.as_slice());
            });

        ciphertext
    }

    fn encrypt_cbc(cleartext: &[u8], key: &[u8], iv: &[u8]) -> Vec<u8> {
        let cipher = Aes128::new_from_slice(key).unwrap();
        let mut ciphertext: Vec<u8> = Vec::with_capacity(cleartext.len());

        for block in cleartext.chunks(16) {
            let previous_block = if ciphertext.len() >= 16 {
                &ciphertext[ciphertext.len() - 16..]
            } else {
                iv
            };

            let block: [u8; 16] = Self::pkcs7_pad(block);
            let block: [u8; 16] = block.iter()
                .zip(previous_block.iter())
                .map(|(a, b)| a ^ b)
                .collect::<Vec<u8>>()
                .try_into()
                .unwrap();

            let mut block = GenericArray::from(block);

            cipher.encrypt_block(&mut block);
            ciphertext.extend_from_slice(block.as_slice());
        }

        ciphertext
    }

    fn pkcs7_pad<const N: usize>(bytes: &[u8]) -> [u8; N] {
        assert!(bytes.len() <= N);

        let mut block = [(N - bytes.len()) as u8; N];
        block[..bytes.len()].clone_from_slice(bytes);

        block
    }
}
