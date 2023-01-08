extern crate core;

use std::collections::HashSet;
use indoc::indoc;
use lazy_static::lazy_static;
use rand::RngCore;

const ENCODED_TARGET_TEXT: &str = indoc! {"
    Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg
    aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq
    dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg
    YnkK"};

const MAX_PREFIX_LENGTH: usize = 1024;

lazy_static! {
    static ref STATIC_PREFIX: Vec<u8> = {
        let prefix_length = rand::thread_rng().next_u32() as usize % MAX_PREFIX_LENGTH;
        let mut static_prefix = vec![0; prefix_length];

        rand::thread_rng().fill_bytes(static_prefix.as_mut_slice());

        static_prefix
    };
}

fn main() {
    let key = {
        let mut key = [0; 16];
        rand::thread_rng().fill_bytes(&mut key);

        key
    };

    // As before, start by finding the block length, but this time, find the block that gets
    // repeated, too
    let (block_length, repeated_block) = (8usize..=1024usize)
        .filter_map(|block_length| {
            let cleartext = vec![0; block_length * 3];
            let ciphertext = concatenate_and_encrypt(&cleartext, &key);

            let mut blocks = HashSet::new();

            for chunk in ciphertext.chunks_exact(block_length) {
                if !blocks.insert(chunk) {
                    // We've seen this block before
                    return Some((block_length, Vec::from(chunk)));
                }
            }

            None
        })
        .next()
        .unwrap();

    assert_eq!(16, block_length);

    // To find the static prefix length, we add known bytes until our known-repeated block from
    // earlier appears in the ciphertext. The position of the repeated block and the number of bytes
    // we had to add to get there will let us figure out the length of the static prefix.
    let static_prefix_length = {
        let mut chosen_cleartext_length = 0;

        loop {
            chosen_cleartext_length += 1;

            let ciphertext = concatenate_and_encrypt(&vec![0; chosen_cleartext_length], &key);

            if let Some((repeated_block_index, _)) = ciphertext.chunks_exact(block_length)
                .enumerate()
                .find(|(_, block)| {
                    *block == repeated_block.as_slice()
                }) {

                break (block_length * repeated_block_index) - (chosen_cleartext_length - block_length);
            }
        }
    };

    assert_eq!(STATIC_PREFIX.len(), static_prefix_length);

    let static_prefix_padding = block_length - (static_prefix_length % block_length);

    // Now we know how long a block is and how long the static prefix is, but how long is the target
    // text?
    let target_text_length = {
        let ciphertext_length_without_chosen_text =
            concatenate_and_encrypt(&vec![0; static_prefix_padding], &key).len();

        let mut padding = static_prefix_padding;

        let padding_length = loop {
            padding += 1;

            if concatenate_and_encrypt(&vec![0; padding], &key).len() > ciphertext_length_without_chosen_text {
                // Adding padding_length bytes is enough to push us over the line into a new block,
                break padding - static_prefix_padding - 1
            }
        };

        ciphertext_length_without_chosen_text - padding_length - static_prefix_length - static_prefix_padding
    };

    // We add an extra block_length worth of zeroes here to make the chosen-prefix selection easier
    let mut target_text = vec![0; target_text_length + block_length - 1];
    let static_prefix_blocks = (static_prefix_length + static_prefix_padding) / block_length;

    for i in block_length..target_text.len() {
        let padding_length = block_length - ((i % block_length) + 1);
        let ciphertext = concatenate_and_encrypt(vec![0; static_prefix_padding + padding_length].as_slice(), &key);

        let block = static_prefix_blocks + (i / block_length) - 1;
        let block_ciphertext = &ciphertext[block * block_length..(block + 1) * block_length];

        let mut chosen_cleartext = vec![0; static_prefix_padding];
        chosen_cleartext.extend_from_slice(&target_text[i - block_length..i]);

        let chosen_cleartext_end = chosen_cleartext.len() - 1;
        let mut found_byte = false;

        for candidate_byte in u8::MIN..=u8::MAX {
            chosen_cleartext[chosen_cleartext_end] = candidate_byte;

            let candidate_cipertext = &concatenate_and_encrypt(&chosen_cleartext, &key)[static_prefix_blocks * block_length..(static_prefix_blocks + 1) * block_length];

            if candidate_cipertext == block_ciphertext {
                target_text[i - 1] = candidate_byte;
                found_byte = true;
                break;
            }
        }

        assert!(found_byte);
    }

    println!("{}", std::str::from_utf8(&target_text[block_length - 1..]).unwrap());
}

fn concatenate_and_encrypt(chosen_cleartext: &[u8], key: &[u8]) -> Vec<u8> {
    let cleartext = {
        let mut target_text = {
            let mut encoded_target_text = ENCODED_TARGET_TEXT.to_string();
            encoded_target_text.retain(|c| !c.is_whitespace());

            radix64::STD.decode(&encoded_target_text).unwrap()
        };

        let mut cleartext = Vec::with_capacity(STATIC_PREFIX.len() + chosen_cleartext.len() + target_text.len());
        cleartext.extend_from_slice(STATIC_PREFIX.as_slice());
        cleartext.extend_from_slice(chosen_cleartext);
        cleartext.append(&mut target_text);

        cleartext
    };

    cryptopals::aes::aes_ecb_encrypt(&cleartext, key)
}
