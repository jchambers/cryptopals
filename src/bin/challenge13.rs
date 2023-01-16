use std::collections::{HashMap, HashSet};
use std::error::Error;
use rand::RngCore;

fn main() {
    let key = {
        let mut key = [0; 16];
        rand::thread_rng().fill_bytes(&mut key);

        key
    };

    // As before, start by finding the block length (even though we already know it)
    let block_length = (2usize..=1024usize)
        .find(|block_length| {
            let email = " ".repeat(block_length * 3);
            let ciphertext = encrypted_profile_for(&email, &key);

            let mut blocks = HashSet::new();

            ciphertext.chunks_exact(*block_length)
                .any(|block| !blocks.insert(block))
        })
        .unwrap();

    assert_eq!(16, block_length);

    // First, generate a three-block ciphertext that has just the word "admin" followed by valid
    // PKCS#7 padding in the second block.
    let admin_block = {
        // email=foo@bar.com&uid=10&role=user
        let mut email = " ".repeat(block_length - "email=".len());
        email.push_str("admin");

        let padding = block_length - "admin".len();

        for _ in 0..padding {
            email.push((padding as u8) as char);
        }

        let ciphertext = encrypted_profile_for(&email, &key);

        assert!(ciphertext.len() / block_length > 2);
        Vec::from(&ciphertext[block_length..block_length * 2])
    };

    assert_eq!(block_length, admin_block.len());

    // Next, we just need to choose an email such that "role=" falls right at the end of a block;
    // in this case, we're aiming for the end of block 2.
    let mut conveniently_aligned_ciphertext = encrypted_profile_for("foo12@bar.com", &key);
    assert_eq!(3, conveniently_aligned_ciphertext.len() / block_length);

    // …and, finally, we replace the last block that currently says "user" with our block from
    // earlier that says "admin"
    conveniently_aligned_ciphertext.splice(block_length * 2.., admin_block);

    assert_eq!(3, conveniently_aligned_ciphertext.len() / block_length);

    assert_eq!(
        HashMap::from([
            ("email".to_string(), "foo12@bar.com".to_string()),
            ("uid".to_string(), "10".to_string()),
            ("role".to_string(), "admin".to_string()),
        ]),
        parse_encrypted_profile(&conveniently_aligned_ciphertext, &key).unwrap()
    );
}

fn encrypted_profile_for(email: &str, key: &[u8]) -> Vec<u8> {
    cryptopals::aes::aes_ecb_encrypt(profile_for(email).as_bytes(), key)
}

fn parse_encrypted_profile(ciphertext: &[u8], key: &[u8]) -> Result<HashMap<String, String>, Box<dyn Error>> {
    let cleartext = String::from_utf8(cryptopals::pkcs7::pkcs7_strip(&cryptopals::aes::aes_ecb_decrypt(ciphertext, key)))?;
    parse_kv_string(&cleartext)
}

fn profile_for(email: &str) -> String {
    encode_kv_pairs(&[
        ("email", email),
        ("uid", "10"),
        ("role", "user"),
    ])
}

fn parse_kv_string(string: &str) -> Result<HashMap<String, String>, Box<dyn Error>> {
    string.split('&')
        .map(|pair| {
            if let &[key, value] = pair.split('=').collect::<Vec<&str>>().as_slice() {
                Ok((key.to_string(), value.to_string()))
            } else {
                Err("Could not parse key/value pair".into())
            }
        })
        .collect::<Result<_, _>>()
}

fn encode_kv_pairs(pairs: &[(&str, &str)]) -> String {
    pairs.iter()
        .map(|(key, value)| {
            let mut key = key.to_string();
            let mut value = value.to_string();

            key.retain(|c| c != '&' && c != '=');
            value.retain(|c| c != '&' && c != '=');

            format!("{}={}", key, value)
        })
        .collect::<Vec<String>>()
        .join("&")
}

#[cfg(test)]
mod test {
    use std::collections::HashMap;
    use crate::{encode_kv_pairs, parse_kv_string};

    #[test]
    fn test_parse_kv_pair() {
        assert_eq!(
            HashMap::from([
                ("foo".to_string(), "bar".to_string()),
                ("baz".to_string(), "qux".to_string()),
                ("zap".to_string(), "zazzle".to_string()),
            ]),
            parse_kv_string("foo=bar&baz=qux&zap=zazzle").unwrap()
        );
    }

    #[test]
    fn test_encode_kv_pairs() {
        let pairs = [
            ("foo", "bar"),
            ("baz", "qux"),
            ("zap", "zazzle"),
        ];

        let expected: HashMap<String, String> = pairs.iter()
            .map(|(key, value)| {
                (key.to_string(), value.to_string())
            })
            .collect();

        assert_eq!(expected, parse_kv_string(&encode_kv_pairs(&pairs)).unwrap());
    }
}