use crypto::digest::Digest;
use crypto::sha1::Sha1;
use rand::RngCore;

fn main() {
    let key = {
        let mut key = [0; 16];
        rand::thread_rng().fill_bytes(&mut key);

        key
    };

    assert_ne!(
        secret_prefix_mac(b"Message 1", &key),
        secret_prefix_mac(b"Message 2", &key)
    );
}

fn secret_prefix_mac(message: &[u8], key: &[u8]) -> Vec<u8> {
    let mut sha1 = Sha1::new();
    sha1.input(key);
    sha1.input(message);

    let mut mac = vec![0; sha1.output_bytes()];

    sha1.result(&mut mac);

    mac
}