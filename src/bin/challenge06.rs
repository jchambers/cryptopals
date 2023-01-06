use std::{env, fs};
use std::error::Error;
use cryptopals::text::englishiness;

fn main() -> Result<(), Box<dyn Error>> {
    let args: Vec<String> = env::args().collect();

    if let Some(path) = args.get(1) {
        let ciphertext = {
            let mut encoded = fs::read_to_string(path)?;
            encoded.retain(|c| !c.is_whitespace());

            radix64::STD.decode(&encoded)?
        };

        let probable_key_lengths = probable_key_lengths(&ciphertext, 2, 40);
        let key = guess_key(&ciphertext, probable_key_lengths[0]);

        let cleartext = String::from_utf8(ciphertext
            .iter()
            .zip(key.iter().cycle())
            .map(|(a, b)| a ^ b)
            .collect())?;

        println!("{}", cleartext);

        Ok(())
    } else {
        Err("Usage: challenge06 PATH_TO_INPUT_FILE".into())
    }
}

fn guess_key(ciphertext: &[u8], key_length: usize) -> Vec<u8> {
    let mut key = vec![0; key_length];

    for i in 0..key_length {
        let bytes_at_block_position: Vec<u8> = ciphertext.iter()
            .skip(i)
            .step_by(key_length)
            .copied()
            .collect();

        let (key_byte_at_position, _) = (u8::MIN..=u8::MAX)
            .map(|key| {
                let cleartext: String = bytes_at_block_position.iter()
                    .filter_map(|b| char::from_u32((b ^ key) as u32))
                    .collect();

                (key, cleartext)
            })
            .max_by_key(|(_, cleartext)| englishiness(cleartext))
            .unwrap();

        key[i] = key_byte_at_position;
    }

    key
}

fn probable_key_lengths(ciphertext: &[u8], min_length: usize, max_length: usize) -> Vec<usize> {
    let mut normalized_distances: Vec<(usize, f64)> = vec![];

    for key_length in min_length..=max_length {
        let chunks: Vec<&[u8]> = ciphertext.chunks_exact(key_length)
            .collect();

        let distance_sum: u32 = chunks.windows(2)
            .map(|window| hamming_distance(window[0], window[1]))
            .sum();

        normalized_distances.push((key_length, distance_sum as f64 / (key_length * (chunks.len() - 1)) as f64));
    }

    normalized_distances.sort_by(|(_, a), (_, b)| a.partial_cmp(b).unwrap());

    normalized_distances.iter()
        .map(|(key_length, _)| *key_length)
        .collect()
}

fn hamming_distance(a: &[u8], b: &[u8]) -> u32 {
    if a.len() != b.len() {
        panic!("Slices must have equal lengths")
    }

    a.iter()
        .zip(b.iter())
        .map(|(a, b)| (a ^ b).count_ones())
        .sum()
}

#[cfg(test)]
mod test {
    use crate::hamming_distance;

    #[test]
    fn test_hamming_distance() {
        assert_eq!(
            37,
            hamming_distance(
                "this is a test".as_bytes(),
                "wokka wokka!!!".as_bytes(),
            )
        )
    }
}
