use std::collections::HashSet;
use std::error::Error;
use std::fs::File;
use std::{env, io};
use std::io::BufRead;

const WORDS_FILE: &str = "/usr/share/dict/words";

fn main() -> Result<(), Box<dyn Error>> {
    let args: Vec<String> = env::args().collect();

    if let Some(path) = args.get(1) {
        let words: HashSet<String> = io::BufReader::new(File::open(WORDS_FILE)?)
            .lines()
            .filter_map(|line| line.ok())
            .collect();

        let ciphertexts: Vec<Vec<u8>> = io::BufReader::new(File::open(path)?)
            .lines()
            .filter_map(|line| line.ok())
            .filter(|line| !line.is_empty())
            .map(|line| hex::decode(line))
            .collect::<Result<_, _>>()?;

        let (ciphertext, key, cleartext) = ciphertexts.iter()
            .map(|ciphertext| {
                let (key, cleartext) = guess_key(ciphertext, &words);
                (ciphertext, key, cleartext)
            })
            .max_by_key(|(_, _, cleartext)| englishiness(cleartext, &words))
            .unwrap();

        println!("decrypt({}, {:#04x}): {}", hex::encode(ciphertext), key, cleartext);

        Ok(())
    } else {
        Err("Usage: challenge04 PATH_TO_INPUT_FILE".into())
    }
}

fn guess_key(ciphertext: &[u8], words: &HashSet<String>) -> (u8, String) {
    (0..=u8::MAX)
        .map(|key| {
            let cleartext: String = ciphertext.iter()
                .filter_map(|b| char::from_u32((b ^ key) as u32))
                .collect();

            (key, cleartext)
        })
        .max_by_key(|(_, cleartext)| englishiness(cleartext, words))
        .unwrap()
}

fn englishiness(string: &str, words: &HashSet<String>) -> usize {
    string.split(' ')
        .filter(|&word| words.contains(word))
        .count()
}
