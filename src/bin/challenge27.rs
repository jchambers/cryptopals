use rand::RngCore;

const BLOCK_LENGTH: usize = 16;

const PREFIX: &str = "comment1=cooking%20MCs;userdata=";
const SUFFIX: &str = ";comment2=%20like%20a%20pound%20of%20bacon";

fn main() {
    let key = {
        let mut key = [0; BLOCK_LENGTH];
        rand::thread_rng().fill_bytes(&mut key);

        key
    };

    let ciphertext = encrypt_cookie("OH NO", &key);
    assert!(ciphertext.len() >= 3 * BLOCK_LENGTH);

    let mut malicious_ciphertext = Vec::with_capacity(3 * BLOCK_LENGTH);
    malicious_ciphertext.extend_from_slice(&ciphertext[0..BLOCK_LENGTH]);
    malicious_ciphertext.extend_from_slice(&[0; BLOCK_LENGTH]);
    malicious_ciphertext.extend_from_slice(&ciphertext[0..BLOCK_LENGTH]);

    if let Err(plaintext) = check_cookie(&malicious_ciphertext, &key) {
        let recovered_key: Vec<u8> = plaintext[0..BLOCK_LENGTH].iter()
            .zip(plaintext[2 * BLOCK_LENGTH..3 * BLOCK_LENGTH].iter())
            .map(|(a, b)| a ^ b)
            .collect();

        // Why does this work? We have three blocks of recovered plaintext:
        //
        // 1. key ^ [plaintext 1]
        // 2. [ciphertext 1] ^ [plaintext 2]
        // 3. ([ciphertext 2] = 0) ^ [plaintext 1] == [plaintext 1]
        //
        // So that means if we XOR the first and third blocks, we're doing:
        //
        // (key ^ [plaintext 1]) ^ [plaintext 1] = key
        assert_eq!(&key, recovered_key.as_slice());
    } else {
        panic!();
    }
}

fn encrypt_cookie(user_data: &str, key: &[u8]) -> Vec<u8> {
    let user_data = user_data.replace(";", "%3B")
        .replace("=", "%3D");

    let mut cookie_string = String::from(PREFIX);
    cookie_string.push_str(&user_data);
    cookie_string.push_str(SUFFIX);

    cryptopals::aes::aes_cbc_encrypt(cookie_string.as_bytes(), key, key)
}

fn check_cookie(ciphertext: &[u8], key: &[u8]) -> Result<(), Vec<u8>> {
    let cleartext = cryptopals::aes::aes_cbc_decrypt(ciphertext, key, key);

    if cleartext.iter().all(|b| b & 0b10000000 == 0) {
        Ok(())
    } else {
        Err(cleartext)
    }
}
