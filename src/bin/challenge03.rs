use std::collections::HashSet;
use std::error::Error;
use std::fs::File;
use std::io;
use std::io::BufRead;

const WORDS_FILE: &str = "/usr/share/dict/words";
const CIPHERTEXT: &str = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736";

fn main() -> Result<(), Box<dyn Error>> {
    let words: HashSet<String> = io::BufReader::new(File::open(WORDS_FILE)?)
        .lines()
        .filter_map(|line| line.ok())
        .collect();

    let ciphertext = hex::decode(CIPHERTEXT)?;

    let (key, cleartext) = (0..=u8::MAX)
        .map(|key| {
            let cleartext: String = ciphertext.iter()
                .filter_map(|b| char::from_u32((b ^ key) as u32))
                .collect();

            (key, cleartext)
        })
        .max_by_key(|(_, cleartext)| englishiness(&cleartext, &words))
        .unwrap();

    println!("Key = {:#04x}; cleartext = {}", key, cleartext);

    Ok(())
}

fn englishiness(string: &str, words: &HashSet<String>) -> usize {
    string.split(' ')
        .filter(|&word| words.contains(word))
        .count()
}
