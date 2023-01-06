use std::{env, fs};
use std::error::Error;
use aes::Aes128;
use aes::cipher::generic_array::GenericArray;
use aes::cipher::{BlockDecrypt, KeyInit};

const KEY: &[u8] = "YELLOW SUBMARINE".as_bytes();

fn main() -> Result<(), Box<dyn Error>> {
    let args: Vec<String> = env::args().collect();

    if let Some(path) = args.get(1) {
        let ciphertext = {
            let mut encoded = fs::read_to_string(path)?;
            encoded.retain(|c| !c.is_whitespace());

            radix64::STD.decode(&encoded)?
        };

        let cipher = Aes128::new_from_slice(KEY).unwrap();

        let cleartext: String = ciphertext.chunks(16)
            .map(|block| {
                let block: [u8; 16] = block.try_into().unwrap();
                let mut block = GenericArray::from(block);
                cipher.decrypt_block(&mut block);

                String::from(std::str::from_utf8(block.as_slice()).unwrap())
            })
            .collect();

        println!("{}", cleartext);

        Ok(())
    } else {
        Err("Usage: challenge07 PATH_TO_INPUT_FILE".into())
    }
}
