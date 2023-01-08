use std::{env, fs};
use std::error::Error;

const KEY: &[u8] = "YELLOW SUBMARINE".as_bytes();

fn main() -> Result<(), Box<dyn Error>> {
    let args: Vec<String> = env::args().collect();

    if let Some(path) = args.get(1) {
        let ciphertext = {
            let mut encoded = fs::read_to_string(path)?;
            encoded.retain(|c| !c.is_whitespace());

            radix64::STD.decode(&encoded)?
        };

        println!("{}", String::from_utf8(cryptopals::aes::aes_ecb_decrypt(&ciphertext, KEY))?);

        Ok(())
    } else {
        Err("Usage: challenge07 PATH_TO_INPUT_FILE".into())
    }
}
