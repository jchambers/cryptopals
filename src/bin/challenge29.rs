use cryptopals::sha1::Sha1;

fn main() {
    const MALICIOUS_SUFFIX: &str = ";admin=true";

    let cookie_api = CookieApi::new();
    let (cookie, mac) = cookie_api.generate_signed_cookie();

    for key_length in 1..32 {
        let padding = Sha1::padding(key_length + cookie.len());

        let forged_mac = {
            let mut sha1 = Sha1::with_initial_state(&mac, key_length + cookie.len() + padding.len());

            sha1.update(MALICIOUS_SUFFIX.as_bytes());
            sha1.finish()
        };

        let mut malicious_cookie_bytes = Vec::from(cookie.as_bytes());
        malicious_cookie_bytes.extend_from_slice(&padding);
        malicious_cookie_bytes.extend_from_slice(MALICIOUS_SUFFIX.as_bytes());

        let malicious_cookie = unsafe {
            String::from_utf8_unchecked(malicious_cookie_bytes)
        };

        if cookie_api.validate_cookie(&malicious_cookie, &forged_mac) {
            assert_eq!(cookie_api.key.len(), key_length);
            println!("Key length = {}", key_length);
            break;
        }
    }
}

struct CookieApi {
    key: String,
}

impl CookieApi {
    fn new() -> Self {
        Self { key: cryptopals::text::random_word() }
    }

    fn generate_signed_cookie(&self) -> (String, Vec<u8>) {
        const COOKIE_TEXT: &str =
            "comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon";

        let mut sha1 = Sha1::default();
        sha1.update(self.key.as_bytes());
        sha1.update(COOKIE_TEXT.as_bytes());

        (COOKIE_TEXT.to_string(), sha1.finish())
    }

    fn validate_cookie(&self, cookie: &str, mac: &[u8]) -> bool {
        let mut sha1 = Sha1::default();
        sha1.update(self.key.as_bytes());
        sha1.update(cookie.as_bytes());

        // I think it's within the spirit of the challenge to (a) acknowledge that this is not a
        // constant-time operation, but (b) recognize that's not The Point™ this time around
        sha1.finish() == mac
    }
}

#[cfg(test)]
mod test {
    use crate::CookieApi;

    #[test]
    fn test_validate_cookie() {
        let cookie_api = CookieApi::new();
        let (cookie, mut mac) = cookie_api.generate_signed_cookie();

        assert!(cookie_api.validate_cookie(&cookie, &mac));
        assert!(!cookie_api.validate_cookie("A different cookie", &mac));

        mac[0] = mac[0].wrapping_add(1);

        assert!(!cookie_api.validate_cookie(&cookie, &mac));
    }
}
