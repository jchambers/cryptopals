use aes::Aes128;
use aes::cipher::generic_array::GenericArray;
use aes::cipher::{BlockDecrypt, BlockEncrypt, KeyInit};
use crate::pkcs7::pkcs7_pad;

const BLOCK_SIZE: usize = 16;

pub fn aes_ecb_encrypt(cleartext: &[u8], key: &[u8]) -> Vec<u8> {
    let cipher = Aes128::new_from_slice(key).unwrap();
    let mut ciphertext = Vec::with_capacity(cleartext.len());

    cleartext.chunks(16)
        .map(pkcs7_pad::<16>)
        .for_each(|block| {
            let mut block = GenericArray::from(block);
            cipher.encrypt_block(&mut block);

            ciphertext.extend_from_slice(block.as_slice());
        });

    ciphertext
}

pub fn aes_ecb_decrypt(ciphertext: &[u8], key: &[u8]) -> Vec<u8> {
    let cipher = Aes128::new_from_slice(key).unwrap();
    let mut cleartext = Vec::with_capacity(ciphertext.len());

    ciphertext.chunks(BLOCK_SIZE)
        .for_each(|block| {
            let block: [u8; BLOCK_SIZE] = block.try_into().unwrap();
            let mut block = GenericArray::from(block);
            cipher.decrypt_block(&mut block);

            cleartext.extend_from_slice(&block);
        });

    crate::pkcs7::pkcs7_strip(&cleartext)
}

pub fn aes_cbc_encrypt(cleartext: &[u8], key: &[u8], iv: &[u8]) -> Vec<u8> {
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

pub fn aes_cbc_decrypt(ciphertext: &[u8], key: &[u8], iv: &[u8]) -> Vec<u8> {
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

    crate::pkcs7::pkcs7_strip(&cleartext)
}

#[cfg(test)]
mod test {
    use rand::RngCore;
    use crate::aes::{aes_cbc_decrypt, aes_cbc_encrypt};

    #[test]
    fn test_encrypt_decrypt_cbc() {
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

        let ciphertext = aes_cbc_encrypt(&original_cleartext, &key, &iv);
        assert_ne!(&original_cleartext, ciphertext.as_slice());

        let decrypted_cleartext = aes_cbc_decrypt(&ciphertext, &key, &iv);
        assert_eq!(&original_cleartext, decrypted_cleartext.as_slice());
    }
}
