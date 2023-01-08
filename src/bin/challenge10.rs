extern crate core;

use std::{env, fs};
use std::error::Error;
use cryptopals::aes::aes_cbc_decrypt;

const KEY: &[u8] = "YELLOW SUBMARINE".as_bytes();
const IV: [u8; 16] = [0; 16];

fn main() -> Result<(), Box<dyn Error>> {
    let args: Vec<String> = env::args().collect();

    if let Some(path) = args.get(1) {
        let ciphertext = {
            let mut encoded = fs::read_to_string(path)?;
            encoded.retain(|c| !c.is_whitespace());

            radix64::STD.decode(&encoded)?
        };

        let cleartext = String::from_utf8(aes_cbc_decrypt(ciphertext.as_slice(), KEY, &IV))?;

        println!("{}", cleartext);

        Ok(())
    } else {
        Err("Usage: challenge10 PATH_TO_INPUT_FILE".into())
    }
}

