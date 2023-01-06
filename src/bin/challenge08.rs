use std::{env, io};
use std::collections::HashSet;
use std::error::Error;
use std::fs::File;
use std::io::BufRead;

fn main() -> Result<(), Box<dyn Error>> {
    let args: Vec<String> = env::args().collect();

    if let Some(path) = args.get(1) {
        let ciphertexts: Vec<Vec<u8>> = io::BufReader::new(File::open(path)?)
            .lines()
            .filter_map(|line| line.ok())
            .filter(|line| !line.is_empty())
            .map(hex::decode)
            .collect::<Result<_, _>>()?;

        ciphertexts
            .iter()
            .enumerate()
            .for_each(|(i, ciphertext)| {
                let blocks: HashSet<&[u8]> = ciphertext.chunks_exact(16)
                    .collect();

                if blocks.len() < ciphertext.len() / 16 {
                    println!("Ciphertext {} has {} repeated blocks", i, (ciphertext.len() / 16) - blocks.len());
                }
            });

        Ok(())
    } else {
        Err("Usage: challenge08 PATH_TO_INPUT_FILE".into())
    }
}
