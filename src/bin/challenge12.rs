extern crate core;

use aes::Aes128;
use aes::cipher::generic_array::GenericArray;
use aes::cipher::{BlockEncrypt, KeyInit};
use indoc::indoc;
use rand::RngCore;

const ENCODED_TARGET_TEXT: &str = indoc! {"
    Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg
    aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq
    dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg
    YnkK"};

fn main() {
    let key = {
        let mut key = [0; 16];
        rand::thread_rng().fill_bytes(&mut key);

        key
    };

    let block_length = (1usize..=1024usize)
        .find(|block_length| {
            let cleartext = vec![0; block_length * 2];
            let ciphertext = concatenate_and_encrypt(&cleartext, &key);

            ciphertext[0..*block_length] == ciphertext[*block_length..block_length * 2]
        })
        .unwrap();

    assert_eq!(16, block_length);

    // Now we know how long a block is, but how long is the target text?
    let target_text_length = {
        let ciphertext_length_without_prefix = concatenate_and_encrypt(&[], &key).len();
        let mut padding = 0;

        let padding_length = loop {
            padding += 1;

            if concatenate_and_encrypt(&vec![0; padding], &key).len() > ciphertext_length_without_prefix {
                // Adding padding_length bytes is enough to push us over the line into a new block,
                break padding - 1
            }
        };

        ciphertext_length_without_prefix - padding_length
    };

    // We add an extra block_length worth of zeroes here to make the chosen-prefix selection easier
    let mut target_text = vec![0; target_text_length + block_length - 1];

    for i in block_length..target_text.len() {
        let padding_length = block_length - ((i % block_length) + 1);
        let ciphertext = concatenate_and_encrypt(vec![0; padding_length].as_slice(), &key);

        let block = (i / block_length) - 1;
        let block_ciphertext = &ciphertext[block * block_length..(block + 1) * block_length];

        let mut candidate_block = Vec::from(&target_text[i - block_length..i]);

        assert!(candidate_block.len() == block_length);

        for candidate_byte in u8::MIN..=u8::MAX {
            candidate_block[block_length - 1] = candidate_byte;

            let candidate_cipertext = &concatenate_and_encrypt(&candidate_block, &key)[0..block_length];

            if candidate_cipertext == block_ciphertext {
                target_text[i - 1] = candidate_byte;
                break;
            }
        }
    }

    println!("{}", std::str::from_utf8(&target_text[block_length - 1..]).unwrap());
}

fn concatenate_and_encrypt(prefix: &[u8], key: &[u8]) -> Vec<u8> {
    let cleartext = {
        let mut target_text = {
            let mut encoded_target_text = ENCODED_TARGET_TEXT.to_string();
            encoded_target_text.retain(|c| !c.is_whitespace());

            radix64::STD.decode(&encoded_target_text).unwrap()
        };

        let mut cleartext = Vec::with_capacity(prefix.len() + target_text.len());
        cleartext.extend_from_slice(prefix);
        cleartext.append(&mut target_text);

        cleartext
    };

    let cipher = Aes128::new_from_slice(key).unwrap();
    let mut ciphertext = Vec::with_capacity(cleartext.len());

    cleartext.chunks(16)
        .map(pkcs7_pad::<16>)
        .for_each(|block| {
            let mut block = GenericArray::from(block);
            cipher.encrypt_block(&mut block);

            ciphertext.extend_from_slice(block.as_slice());
        });

    ciphertext
}

fn pkcs7_pad<const N: usize>(bytes: &[u8]) -> [u8; N] {
    assert!(bytes.len() <= N);

    let mut block = [(N - bytes.len()) as u8; N];
    block[..bytes.len()].clone_from_slice(bytes);

    block
}
