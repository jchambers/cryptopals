fn main() {
    assert_eq!(
        b"YELLOW SUBMARINE\x04\x04\x04\x04",
        pkcs7_pad(b"YELLOW SUBMARINE", 20).as_slice()
    );
}

fn pkcs7_pad(block: &[u8], block_size: u8) -> Vec<u8> {
    if block.len() > block_size as usize {
        panic!("Oversized block");
    }

    let mut padded = Vec::with_capacity(block_size as usize);
    padded.extend_from_slice(block);

    let padding = block_size - block.len() as u8;

    for _ in 0..padding {
        padded.push(padding);
    }

    padded
}
