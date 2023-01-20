use std::error::Error;
use rand::RngCore;

const ENCODED_CLEARTEXT: &str = include_str!("../../data/challenge25.txt");

fn main() -> Result<(), Box<dyn Error>> {
    let original_cleartext = {
        let mut encoded = ENCODED_CLEARTEXT.to_string();
        encoded.retain(|c| !c.is_whitespace());

        radix64::STD.decode(&encoded)?
    };

    let mut encrypted_ciphertext = CtrEncryptedText::new(&original_cleartext);

    let original_ciphertext = encrypted_ciphertext.ciphertext();
    encrypted_ciphertext.edit(0, vec![0; original_ciphertext.len()].as_slice());
    let keystream = encrypted_ciphertext.ciphertext();

    let decrypted_cleartext: Vec<u8> = original_ciphertext.iter()
        .zip(keystream.iter())
        .map(|(a, b)| a ^ b)
        .collect();

    assert_eq!(original_cleartext, decrypted_cleartext);

    Ok(())
}

struct CtrEncryptedText {
    key: [u8; 16],
    nonce: u64,

    ciphertext: Vec<u8>,
}

impl CtrEncryptedText {
    fn new(cleartext: &[u8]) -> Self {
        let key = {
            let mut key = [0; 16];
            rand::thread_rng().fill_bytes(&mut key);

            key
        };

        let nonce = rand::thread_rng().next_u64();
        let ciphertext = cryptopals::aes::aes_ctr_transform(cleartext, &key, nonce);

        Self {
            key,
            nonce,
            ciphertext,
        }
    }

    fn ciphertext(&self) -> Vec<u8> {
        self.ciphertext.clone()
    }

    fn edit(&mut self, offset: usize, text: &[u8]) {
        assert!(offset + text.len() <= self.ciphertext.len());
        let mut cleartext = cryptopals::aes::aes_ctr_transform(&self.ciphertext, &self.key, self.nonce);
        cleartext[offset..offset + text.len()].clone_from_slice(text);

        self.ciphertext = cryptopals::aes::aes_ctr_transform(&cleartext, &self.key, self.nonce);
    }
}
