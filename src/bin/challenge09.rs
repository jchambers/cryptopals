fn main() {
    assert_eq!(
        b"YELLOW SUBMARINE\x04\x04\x04\x04",
        pkcs7_pad::<20>(b"YELLOW SUBMARINE").as_slice()
    );
}

fn pkcs7_pad<const N: usize>(bytes: &[u8]) -> [u8; N] {
    if bytes.len() > N {
        panic!("Oversized block");
    }

    let mut block = [(N - bytes.len()) as u8; N];
    block[..bytes.len()].clone_from_slice(bytes);

    block
}
