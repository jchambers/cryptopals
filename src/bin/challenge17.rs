use std::error::Error;
use rand::RngCore;

const STRINGS: [&str; 10] = [
    "MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc=",
    "MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic=",
    "MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw==",
    "MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg==",
    "MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl",
    "MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA==",
    "MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw==",
    "MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8=",
    "MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g=",
    "MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93",
];

// I don't THINK this is cheating in the spirit of this challenge, but could be mistaken!
const BLOCK_SIZE: usize = 16;

fn main() -> Result<(), Box<dyn Error>> {
    let padding_oracle = PaddingOracle::new()?;

    let (ciphertext, iv) = padding_oracle.encrypt();
    let decrypted_cleartext = decrypt_ciphertext(&ciphertext, &iv, &padding_oracle);

    assert_eq!(padding_oracle.cleartext, decrypted_cleartext);
    println!("{}", String::from_utf8(decrypted_cleartext)?);

    Ok(())
}

fn decrypt_ciphertext(ciphertext: &[u8], iv: &[u8], padding_oracle: &PaddingOracle) -> Vec<u8> {
    assert_eq!(0, ciphertext.len() % BLOCK_SIZE);

    let cleartext: Vec<u8> = ciphertext.chunks_exact(BLOCK_SIZE)
        .enumerate()
        .flat_map(|(i, block)| {
            let iv = if i == 0 {
                iv
            } else {
                &ciphertext[BLOCK_SIZE * (i - 1)..BLOCK_SIZE * i]
            };

            decrypt_block(block, iv, padding_oracle).into_iter()
        })
        .collect();

    cryptopals::pkcs7::pkcs7_strip(&cleartext)
}

fn decrypt_block(block: &[u8], iv: &[u8], padding_oracle: &PaddingOracle) -> Vec<u8> {
    assert!(block.len() < u8::MAX as usize);
    assert_eq!(block.len(), iv.len());

    let mut iv_error = vec![0; iv.len()];
    let mut cleartext = vec![0u8; block.len()];

    for i in (0..block.len()).rev() {
        let padding = (block.len() - i) as u8;

        // Tinker with our error block so we know that we have valid padding up to the byte
        // we're trying to guess
        for p in i + 1..block.len() {
            // We know the cleartext byte at this position and want to introduce an error such
            // that cleartext ^ error = padding. Solving for `error`:
            //
            //     cleartext ^ error = padding
            //  => cleartext ^ cleartext ^ error = cleartext ^ padding
            //  => error = cleartext ^ padding
            iv_error[p] = cleartext[p] ^ padding;
        }

        // Sweep possible values of i to find something that doesn't have bad padding
        let mut found_cleartext_byte = false;

        for candidate in u8::MIN..u8::MAX {
            iv_error[i] = candidate;

            let iv: Vec<u8> = iv.iter()
                .zip(iv_error.iter())
                .map(|(a, b)| a ^ b)
                .collect();

            if padding_oracle.has_valid_padding(block, &iv) {
                println!("Candidate at position {}: {:x?}", i, candidate);
            }
        }

        for candidate in u8::MIN..u8::MAX {
            iv_error[i] = candidate;

            let iv: Vec<u8> = iv.iter()
                .zip(iv_error.iter())
                .map(|(a, b)| a ^ b)
                .collect();

            if padding_oracle.has_valid_padding(block, &iv) {
                // TERRIBLE TERRIBLE HACK: some blocks may already be padded correctly! The RIGHT
                // thing to do would be to do a depth-first search through the mutation space. The
                // terrible thing I'm doing here instead is just observing that bytes 0-16 are
                // unlikely to appear naturally in text (\r and \n notwithstanding) and using that
                // as a heuristic to avoid going down the wrong path.
                if i == 15 && candidate == 0 {
                    println!("Skipping candidate");
                    continue;
                }

                // We know that cleartext ^ candidate = padding, so then we know that
                // cleartext = padding ^ candidate.
                cleartext[i] = padding ^ candidate;
                found_cleartext_byte = true;

                break;
            }
        }

        if !found_cleartext_byte {
            println!("IV:                  {:02x?}", iv);
            println!("Actual cleartext len: {}", padding_oracle.cleartext.len());
            println!("Actual cleartext:    {:02x?}", padding_oracle.cleartext);
            println!("Decrypted cleartext: {:02x?}", cleartext);
            assert!(found_cleartext_byte);
        }
    }

    println!("Finished block: {:02x?}", cleartext);

    cleartext
}

struct PaddingOracle {
    key: [u8; BLOCK_SIZE],
    cleartext: Vec<u8>,
}

impl PaddingOracle {
    fn new() -> Result<Self, Box<dyn Error>> {
        let key = {
            let mut key = [0; BLOCK_SIZE];
            rand::thread_rng().fill_bytes(&mut key);

            key
        };

        let cleartext = {
            let encoded = STRINGS[rand::thread_rng().next_u32() as usize % STRINGS.len()];
            radix64::STD.decode(&encoded)?
        };

        Ok(Self { key, cleartext })
    }

    fn encrypt(&self) -> (Vec<u8>, [u8; BLOCK_SIZE]) {
        let iv = {
            let mut iv = [0; BLOCK_SIZE];
            rand::thread_rng().fill_bytes(&mut iv);

            iv
        };

        (cryptopals::aes::aes_cbc_encrypt(&self.cleartext, &self.key, &iv), iv)
    }

    fn has_valid_padding(&self, ciphertext: &[u8], iv: &[u8]) -> bool {
        let cleartext = cryptopals::aes::aes_cbc_decrypt(ciphertext, &self.key, iv);
        let last_byte = cleartext[cleartext.len() - 1];

        last_byte > 0 &&
            (last_byte as usize) <= ciphertext.len() &&
            cleartext[cleartext.len() - last_byte as usize..].iter().all(|&b| b == last_byte)
    }
}
