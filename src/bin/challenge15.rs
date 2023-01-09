fn main() {
    assert_eq!(
        b"ICE ICE BABY",
        cryptopals::pkcs7::try_pkcs7_strip(b"ICE ICE BABY\x04\x04\x04\x04").unwrap().as_slice()
    );

    assert!(cryptopals::pkcs7::try_pkcs7_strip(b"ICE ICE BABY\x05\x05\x05\x05").is_err());
    assert!(cryptopals::pkcs7::try_pkcs7_strip(b"ICE ICE BABY\x01\x02\x03\x04").is_err());
}
