fn main() {
    assert_eq!(
        b"YELLOW SUBMARINE\x04\x04\x04\x04",
        cryptopals::pkcs7::pkcs7_pad::<20>(b"YELLOW SUBMARINE").as_slice()
    );
}

