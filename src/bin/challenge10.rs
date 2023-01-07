extern crate core;

use std::{env, fs};
use std::error::Error;
use aes::Aes128;
use aes::cipher::generic_array::GenericArray;
use aes::cipher::{BlockDecrypt, BlockEncrypt, KeyInit};

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

        let cleartext = String::from_utf8(aes_decrypt_with_cbc(ciphertext.as_slice(), KEY, &IV))?;

        println!("{}", cleartext);

        Ok(())
    } else {
        Err("Usage: challenge10 PATH_TO_INPUT_FILE".into())
    }
}

#[cfg(test)]
fn aes_encrypt_with_cbc(cleartext: &[u8], key: &[u8], iv: &[u8]) -> Vec<u8> {
    let cipher = Aes128::new_from_slice(key).unwrap();
    let mut ciphertext: Vec<u8> = Vec::with_capacity(cleartext.len());

    for block in cleartext.chunks(16) {
        let previous_block = if ciphertext.len() >= 16 {
            &ciphertext[ciphertext.len() - 16..]
        } else {
            iv
        };

        let block: [u8; 16] = pkcs7_pad(block);
        let block: [u8; 16] = block.iter()
            .zip(previous_block.iter())
            .map(|(a, b)| a ^ b)
            .collect::<Vec<u8>>()
            .try_into()
            .unwrap();

        let mut block = GenericArray::from(block);

        cipher.encrypt_block(&mut block);
        ciphertext.extend_from_slice(block.as_slice());
    }

    ciphertext
}

fn aes_decrypt_with_cbc(ciphertext: &[u8], key: &[u8], iv: &[u8]) -> Vec<u8> {
    assert_eq!(0, ciphertext.len() % 16);

    let cipher = Aes128::new_from_slice(key).unwrap();
    let mut cleartext: Vec<u8> = Vec::with_capacity(ciphertext.len());

    for offset in (0..ciphertext.len()).step_by(16) {
        let block: [u8; 16] = ciphertext[offset..offset + 16].try_into().unwrap();
        let mut block = GenericArray::from(block);

        cipher.decrypt_block(&mut block);

        let previous_block = if offset >= 16 {
            &ciphertext[offset - 16..offset]
        } else {
            iv
        };

        cleartext.extend(block
            .iter()
            .zip(previous_block.iter())
            .map(|(a, b)| a ^ b));
    }

    cleartext
}

#[cfg(test)]
fn pkcs7_pad<const N: usize>(bytes: &[u8]) -> [u8; N] {
    if bytes.len() > N {
        panic!("Oversized block");
    }

    let mut block = [(N - bytes.len()) as u8; N];
    block[..bytes.len()].clone_from_slice(bytes);

    block
}

#[cfg(test)]
mod test {
    use rand::RngCore;
    use crate::{aes_decrypt_with_cbc, aes_encrypt_with_cbc};

    #[test]
    fn test_encrypt_decrypt() {
        let original_cleartext = {
            let mut original_cleartext = [0; 256];
            rand::thread_rng().fill_bytes(&mut original_cleartext);

            original_cleartext
        };

        let iv = {
            let mut iv = [0; 16];
            rand::thread_rng().fill_bytes(&mut iv);

            iv
        };

        let key = {
            let mut key = [0; 16];
            rand::thread_rng().fill_bytes(&mut key);

            key
        };

        let ciphertext = aes_encrypt_with_cbc(&original_cleartext, &key, &iv);
        assert_ne!(&original_cleartext, ciphertext.as_slice());

        let decrypted_cleartext = aes_decrypt_with_cbc(&ciphertext, &key, &iv);
        assert_eq!(&original_cleartext, decrypted_cleartext.as_slice());
    }
}
