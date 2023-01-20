use rand::RngCore;

const PREFIX: &str = "comment1=cooking%20MCs;userdata=";
const SUFFIX: &str = ";comment2=%20like%20a%20pound%20of%20bacon";

fn main() {
    let key = {
        let mut key = [0; 16];
        rand::thread_rng().fill_bytes(&mut key);

        key
    };

    let nonce = rand::thread_rng().next_u64();

    // See challenge 16 for character substitutions
    let mut cookie_ciphertext = encrypt_cookie(":admin<true", &key, nonce);
    cookie_ciphertext[32] ^= 1;
    cookie_ciphertext[32 + ";admin".len()] ^= 1;

    assert!(encrypted_cookie_contains_admin_tuple(&cookie_ciphertext, &key, nonce));
}

fn encrypt_cookie(user_data: &str, key: &[u8], nonce: u64) -> Vec<u8> {
    let user_data = user_data.replace(";", "%3B")
        .replace("=", "%3D");

    let mut cookie_string = String::from(PREFIX);
    cookie_string.push_str(&user_data);
    cookie_string.push_str(SUFFIX);

    cryptopals::aes::aes_ctr_transform(cookie_string.as_bytes(), key, nonce)
}

fn encrypted_cookie_contains_admin_tuple(ciphertext: &[u8], key: &[u8], nonce: u64) -> bool {
    let cleartext = unsafe {
        String::from_utf8_unchecked(cryptopals::aes::aes_ctr_transform(ciphertext, key, nonce))
    };

    cookie_contains_admin_tuple(&cleartext)
}

fn cookie_contains_admin_tuple(cookie: &str) -> bool {
    cookie
        .split(';')
        .any(|pair| pair == "admin=true")
}
