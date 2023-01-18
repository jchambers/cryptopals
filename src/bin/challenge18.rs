const CIPHERTEXT: &str = "L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ==";

fn main() {
    let ciphertext = radix64::STD.decode(CIPHERTEXT).unwrap();
    let cleartext = String::from_utf8(cryptopals::aes::aes_ctr_transform(
        &ciphertext,
        b"YELLOW SUBMARINE",
        0,
    ))
    .unwrap();

    println!("{}", cleartext);
}
