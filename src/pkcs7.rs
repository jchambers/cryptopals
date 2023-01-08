pub fn pkcs7_pad<const N: usize>(bytes: &[u8]) -> [u8; N] {
    assert!(bytes.len() <= N);

    let mut block = [(N - bytes.len()) as u8; N];
    block[..bytes.len()].clone_from_slice(bytes);

    block
}
