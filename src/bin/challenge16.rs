use rand::RngCore;

const PREFIX: &str = "comment1=cooking%20MCs;userdata=";
const SUFFIX: &str = ";comment2=%20like%20a%20pound%20of%20bacon";

fn main() {
    let key = {
        let mut key = [0; 16];
        rand::thread_rng().fill_bytes(&mut key);

        key
    };

    let iv = {
        let mut iv = [0; 16];
        rand::thread_rng().fill_bytes(&mut iv);

        iv
    };

    // Conveniently, PREFIX is block-aligned, so our user data will appear right at the start of the
    // second block. We want to choose a user data string that we can mutate into something with a
    // valid admin=true tuple. We want to do a single bit flip to change some character to '='.
    //
    // Printable characters that are one bit away from '=' (00111101):
    //
    // - '<' (0b00111100)
    // - '?' (0b00111111)
    // - '9' (0b00111001)
    // - '5' (0b00110101)
    // - '-' (0b00101101)
    // - '}' (0b01111101)
    //
    // So let's roll with '<' and try to flip the lowest bit to turn it into an '='. The other thing
    // here is that the entire first block will get scrambled; I THINK that's okay and within the
    // spirit of the problem (which seems to assume a crappy parser that won't complain about the
    // janky first block?).
    let mut cookie_ciphertext = encrypt_cookie("admin<true", &key, &iv);
    cookie_ciphertext[16 + "admin".len()] ^= 1;

    assert!(encrypted_cookie_contains_admin_tuple(&cookie_ciphertext, &key, &iv));
}

fn encrypt_cookie(user_data: &str, key: &[u8], iv: &[u8]) -> Vec<u8> {
    let user_data = user_data.replace(";", "%3B")
        .replace("=", "%3D");

    let mut cookie_string = String::from(PREFIX);
    cookie_string.push_str(&user_data);
    cookie_string.push_str(SUFFIX);

    cryptopals::aes::aes_cbc_encrypt(cookie_string.as_bytes(), key, iv)
}

fn encrypted_cookie_contains_admin_tuple(ciphertext: &[u8], key: &[u8], iv: &[u8]) -> bool {
    let cleartext = unsafe {
        String::from_utf8_unchecked(cryptopals::aes::aes_cbc_decrypt(ciphertext, key, iv))
    };

    println!("{}", cleartext);

    cookie_contains_admin_tuple(&cleartext)
}

fn cookie_contains_admin_tuple(cookie: &str) -> bool {
    cookie
        .split(';')
        .any(|pair| pair == "admin=true")
}

fn _dump_bit_flipped_alternatives(c: char) {
    for i in 0..8 {
        let alternative = c as u8 ^ (1 << i);
        println!("- '{}' ({:#010b})", alternative as char, alternative);
    }
}

#[cfg(test)]
mod test {
    use rand::RngCore;
    use crate::{cookie_contains_admin_tuple, encrypt_cookie, encrypted_cookie_contains_admin_tuple};
    
    #[test]
    fn test_escape() {
        let key = {
            let mut key = [0; 16];
            rand::thread_rng().fill_bytes(&mut key);

            key
        };

        let iv = {
            let mut iv = [0; 16];
            rand::thread_rng().fill_bytes(&mut iv);

            iv
        };

        let cookie_ciphertext = encrypt_cookie(";admin=true", &key, &iv);

        // We should NOT find an admin tuple in here because `encrypt_cookie` should escape the ';'
        // and '=' characters
        assert!(!encrypted_cookie_contains_admin_tuple(&cookie_ciphertext, &key, &iv));
    }

    #[test]
    fn test_cookie_contains_admin_tuple() {
        assert!(cookie_contains_admin_tuple("shoe_size=12;admin=true;serious=lion"));
        assert!(!cookie_contains_admin_tuple("shoe_size=12;admin=false;serious=lion"));
        assert!(!cookie_contains_admin_tuple("shoe_size=12;serious=lion"));
    }
}