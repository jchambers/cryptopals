use std::error::Error;
use rand::RngCore;

const ENCODED_CLEARTEXT: &str = include_str!("../../data/challenge20.txt");

fn main() -> Result<(), Box<dyn Error>> {
    let key = {
        let mut key = [0; 16];
        rand::thread_rng().fill_bytes(&mut key);

        key
    };

    let ciphertexts: Vec<Vec<u8>> = ENCODED_CLEARTEXT
        .lines()
        .map(|line| {
            radix64::STD
                .decode(line)
                .map(|decoded| cryptopals::aes::aes_ctr_transform(&decoded, &key, 0))
        })
        .collect::<Result<_, _>>()?;

    let shortest_ciphertext_length = ciphertexts.iter()
        .map(|ciphertext| ciphertext.len())
        .min()
        .unwrap();

    let mut keystream = vec![0; shortest_ciphertext_length];

    for i in 0..keystream.len() {
        keystream[i] = (u8::MIN..=u8::MAX)
            .max_by_key(|candidate| {
                let column: String = ciphertexts.iter()
                    .map(|ciphertext| (ciphertext[i] ^ candidate) as char)
                    .collect();

                cryptopals::text::englishiness(&column)
            })
            .unwrap();
    }

    ciphertexts.iter()
        .for_each(|ciphertext| {
            let cleartext: String = ciphertext.iter()
                .zip(keystream.iter())
                .map(|(a, b)| (a ^ b) as char)
                .collect();

            println!("{}", cleartext);
        });

    Ok(())
}