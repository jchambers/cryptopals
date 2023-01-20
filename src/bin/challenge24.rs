extern crate core;

use std::time::{SystemTime, UNIX_EPOCH};
use rand::RngCore;
use cryptopals::random::MersenneTwister;

fn main() {
    {
        let plaintext = b"Sixteen bits isn't much";

        let mut padded_plaintext = vec![0u8; (rand::thread_rng().next_u32() % 32) as usize];
        rand::thread_rng().fill_bytes(padded_plaintext.as_mut_slice());
        padded_plaintext.extend_from_slice(plaintext);

        let seed = rand::thread_rng().next_u32() as u16;
        let ciphertext = aes_prng_transform(&padded_plaintext, seed);

        let mut recovered_seed = 0;

        for candidate in u16::MIN..=u16::MAX {
            let decrypted_plaintext = aes_prng_transform(&ciphertext, candidate);

            if decrypted_plaintext.ends_with(plaintext) {
                recovered_seed = candidate;
                break;
            }
        }

        println!("Recovered seed: {:04x}", recovered_seed);
        assert_eq!(seed, recovered_seed);
    }

    {
        let current_time_token = generate_password_reset_token();

        let more_different_token = {
            let mut token_bytes = vec![0; 32];
            rand::thread_rng().fill_bytes(token_bytes.as_mut_slice());

            hex::encode(token_bytes)
        };

        assert!(is_current_time_seed_password_reset_token(&current_time_token));
        assert!(!is_current_time_seed_password_reset_token(&more_different_token));
    }
}

fn aes_prng_transform(text: &[u8], seed: u16) -> Vec<u8> {
    let mut keystream = Vec::with_capacity(text.len());
    let mut mt = MersenneTwister::new(seed as u32);

    while keystream.len() < text.len() {
        keystream.extend_from_slice(&mt.next_u32().to_be_bytes());
    }

    text.iter()
        .zip(keystream.iter())
        .map(|(a, b)| a ^ b)
        .collect()
}

fn generate_password_reset_token() -> String {
    let current_time = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as u32;

    let mut mt = MersenneTwister::new(current_time);
    let mut token_bytes = Vec::with_capacity(32);

    for _ in 0..8 {
        token_bytes.extend_from_slice(&mt.next_u32().to_be_bytes());
    }

    hex::encode(token_bytes)
}

fn is_current_time_seed_password_reset_token(token: &str) -> bool {
    let current_time = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as u32;

    let start_time = current_time - 1_000;
    let token_bytes = hex::decode(token).unwrap();

    for seed in start_time..=current_time {
        let mut token_bytes_from_seed = Vec::with_capacity(32);
        let mut mt = MersenneTwister::new(seed);

        while token_bytes_from_seed.len() < token_bytes.len() {
            token_bytes_from_seed.extend_from_slice(&mt.next_u32().to_be_bytes());
        }

        assert_eq!(token_bytes.len(), token_bytes_from_seed.len());

        if token_bytes_from_seed == token_bytes {
            return true;
        }
    }

    false
}

#[cfg(test)]
mod test {
    use rand::RngCore;
    use crate::aes_prng_transform;

    #[test]
    fn test_aes_prng_transform() {
        let seed = rand::thread_rng().next_u32() as u16;
        let text = b"I'm pretty sure the two halves of this challenge are separate ideas.";

        assert_ne!(text, aes_prng_transform(text, seed).as_slice());
        assert_eq!(text, aes_prng_transform(aes_prng_transform(text, seed).as_slice(), seed).as_slice());
    }
}
